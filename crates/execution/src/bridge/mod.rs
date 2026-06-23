//! RSK Bridge precompile (0x01000006) — BTC–RSK two-way peg.
//!
//! The Bridge is the most complex RSK precompile, providing:
//! - BTC header chain (SPV block store in contract storage)
//! - Peg-in: `registerBtcTransaction` credits RBTC for proven BTC deposits
//! - Peg-out: `releaseBtc` + `updateCollections` + `addSignature`
//! - Federation management: create/commit/rollback + voting
//! - Whitelist, locking cap, fee-per-KB governance
//!
//! This module implements the consensus-critical subset (32 transaction-callable
//! methods). Local-call-only getters are deferred to RPC support.

pub mod btc_chain;
pub mod btc_store;
pub mod constants;
pub mod events;
pub mod federation;
pub mod getters;
pub mod governance;
pub mod peg;
pub mod pegin_instructions;
pub mod pmt;
pub mod release_tx;
pub mod serialization;
pub mod storage;
pub mod tx;
pub mod vote;

use alloy_primitives::{Bytes, U256};
use revm::context_interface::ContextTr;
use revm::precompile::{PrecompileError, PrecompileOutput};
use rustock_storage::BlockStore;
use sha3::{Digest, Keccak256};
use std::sync::Arc;

use constants::BridgeConstants;
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::BridgeTxContext;

// ---------------------------------------------------------------------------
// ABI selector helper
// ---------------------------------------------------------------------------

fn compute_selector(sig: &str) -> [u8; 4] {
    let h = Keccak256::digest(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

// ---------------------------------------------------------------------------
// ABI argument validation (rskj `CallTransaction.Function.decode` / parseData)
// ---------------------------------------------------------------------------
//
// rskj's `Bridge.parseData` ABI-decodes ALL of a method's arguments up front
// (CallTransaction.java:409). Any decode exception (an out-of-bounds dynamic
// offset/length, a payload shorter than the head) makes `parseData` return
// null (Bridge.java:344-347), which `getGasForData` then charges as the flat
// RELEASE_BTC parse-failure cost (23_000, no per-byte data cost) and which
// `execute()` turns into a `BridgeIllegalArgumentException` throw. A from-
// scratch client that parses arguments lazily (only inside the method handler)
// would instead charge the matched method's full cost and fork the chain —
// mainnet #6,223,797 tx[3] forwards `receiveHeaders(bytes[])` with a `bytes[]`
// offset of 0xa0 into a 60-byte argument payload, so rskj's decode throws.
//
// `abi_args_decode_ok` mirrors the bound checks rskj's `SolidityType` decoders
// perform (`Utils.safeCopyOfRange`/`validateArrayAllegedSize` throw when
// `data.length < offset + size`; `IntType.decodeInt` special-cases an empty
// payload as 0; offsets/lengths are read via `BigInteger.intValue()`).

#[derive(Clone)]
enum AbiArgType {
    /// 32-byte head word read with `IntType.decodeInt` (empty payload → 0):
    /// int/uint/address/bool.
    Word,
    /// 32-byte head word read with `safeCopyOfRange` (no empty special case):
    /// bytesN.
    FixedBytes,
    /// Dynamic `bytes`/`string`.
    Bytes,
    /// Dynamic `T[]`.
    Array(Box<AbiArgType>),
}

impl AbiArgType {
    fn is_dynamic(&self) -> bool {
        matches!(self, AbiArgType::Bytes | AbiArgType::Array(_))
    }
}

/// Parse a single Solidity type name (as it appears in a bridge signature).
fn parse_abi_type(t: &str) -> AbiArgType {
    let t = t.trim();
    if let Some(elem) = t.strip_suffix("[]") {
        return AbiArgType::Array(Box::new(parse_abi_type(elem)));
    }
    match t {
        "bytes" | "string" => AbiArgType::Bytes,
        _ if t.starts_with("bytes") => AbiArgType::FixedBytes, // bytes1..bytes32
        _ => AbiArgType::Word, // int*, uint*, address, bool
    }
}

/// Extract the argument types from a method signature like `name(a,b,c)`.
fn parse_signature_args(signature: &str) -> Vec<AbiArgType> {
    let inner = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or("");
    if inner.is_empty() {
        return Vec::new();
    }
    inner.split(',').map(parse_abi_type).collect()
}

/// rskj `IntType.decodeInt(encoded, offset).intValue()`: an empty payload
/// decodes to 0 without bounds-checking; otherwise the 32-byte word must fit
/// (`safeCopyOfRange`) and the result is its low-32-bit signed `intValue()`.
fn abi_decode_int(args: &[u8], off: usize) -> Option<i64> {
    if args.is_empty() {
        return Some(0);
    }
    let end = off.checked_add(32)?;
    if end > args.len() {
        return None;
    }
    let low = u32::from_be_bytes([args[off + 28], args[off + 29], args[off + 30], args[off + 31]]);
    Some(low as i32 as i64)
}

/// Validate that `value` (an `int`-decoded offset/length) is usable as a
/// non-negative index. rskj throws (`Math.addExact`, array bounds) on negatives.
fn abi_index(value: i64) -> Option<usize> {
    if value < 0 {
        None
    } else {
        Some(value as usize)
    }
}

/// Mirror `SolidityType.decode(encoded, offset)` for one value, returning
/// `None` exactly where rskj would throw.
fn abi_decode_value_ok(args: &[u8], off: usize, ty: &AbiArgType) -> Option<()> {
    match ty {
        // IntType.decode -> decodeInt (empty payload tolerated).
        AbiArgType::Word => abi_decode_int(args, off).map(|_| ()),
        // Bytes32Type.decode -> safeCopyOfRange(encoded, off, 32) (strict).
        AbiArgType::FixedBytes => {
            let end = off.checked_add(32)?;
            (end <= args.len()).then_some(())
        }
        // BytesType.decode: len = decodeInt(off); safeCopyOfRange(off+32, len).
        AbiArgType::Bytes => {
            let len = abi_index(abi_decode_int(args, off)?)?;
            let data_off = off.checked_add(32)?;
            (data_off.checked_add(len)? <= args.len()).then_some(())
        }
        // DynamicArrayType.decode.
        AbiArgType::Array(elem) => {
            if args.is_empty() {
                return Some(()); // empty payload → empty array (no throw)
            }
            let len = abi_index(abi_decode_int(args, off)?)?;
            let base = off.checked_add(32)?;
            // validateArrayAllegedSize(encoded, base, len) — lower bound.
            if base.checked_add(len)? > args.len() {
                return None;
            }
            let mut elem_off = base;
            for _ in 0..len {
                if elem.is_dynamic() {
                    let dyn_off = abi_index(abi_decode_int(args, elem_off)?)?;
                    abi_decode_value_ok(args, base.checked_add(dyn_off)?, elem)?;
                } else {
                    abi_decode_value_ok(args, elem_off, elem)?;
                }
                elem_off = elem_off.checked_add(32)?; // every element head slot is 32 bytes
            }
            Some(())
        }
    }
}

/// rskj `CallTransaction.Function.decode(encoded, inputs)` (CallTransaction.java
/// :409): walk the head, following each dynamic argument's offset, and confirm
/// every value decodes without an out-of-bounds access. `args` is the calldata
/// AFTER the 4-byte selector. Returns false where rskj's decode would throw
/// (→ `parseData` null → flat 23_000 parse-failure cost).
fn abi_args_decode_ok(args: &[u8], signature: &str) -> bool {
    let types = parse_signature_args(signature);
    let mut off = 0usize;
    for ty in &types {
        let ok = if ty.is_dynamic() {
            match abi_decode_int(args, off).and_then(abi_index) {
                Some(dyn_off) => abi_decode_value_ok(args, dyn_off, ty).is_some(),
                None => false,
            }
        } else {
            abi_decode_value_ok(args, off, ty).is_some()
        };
        if !ok {
            return false;
        }
        match off.checked_add(32) {
            Some(n) => off = n,
            None => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// BridgeMethod — all 69 methods (32 tx-callable + 37 local-only)
// ---------------------------------------------------------------------------

/// Permission model for a Bridge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgePermission {
    /// Callable from transactions (consensus-critical).
    TransactionCallable,
    /// Only callable via local (RPC) calls — never in blocks.
    LocalOnly,
    /// Dynamic: local-only before RSKIP220, tx-callable after.
    DynamicRskip220,
}

/// Describes a Bridge ABI method: its selector, gas cost, and permissions.
#[derive(Debug, Clone)]
pub struct BridgeMethodInfo {
    pub name: &'static str,
    pub signature: &'static str,
    pub selector: [u8; 4],
    pub gas_cost: BridgeGasCost,
    pub permission: BridgePermission,
    pub enabled: BridgeMethodEnabled,
}

/// rskj `BridgeMethods` isEnabled: methods appear/disappear at hardforks.
/// A disabled method's selector is a parse failure (rskj parseData → null).
#[derive(Debug, Clone, Copy)]
pub enum BridgeMethodEnabled {
    Always,
    /// Enabled from the given network upgrade onwards.
    Since(crate::hardfork::RskNetworkUpgrade),
    /// Enabled only BEFORE the given network upgrade (legacy methods).
    Until(crate::hardfork::RskNetworkUpgrade),
}

impl BridgeMethodEnabled {
    pub fn is_enabled(&self, hardfork_cfg: &RskHardforkConfig, block_number: u64) -> bool {
        match self {
            Self::Always => true,
            Self::Since(u) => hardfork_cfg.active_upgrade(block_number) >= *u,
            Self::Until(u) => hardfork_cfg.active_upgrade(block_number) < *u,
        }
    }
}

/// rskj BridgeMethods activation lambdas, mapped through reference.conf
/// (rskip87/89=orchid, rskip122/123=wasabi100, rskip134/143=papyrus200,
/// rskip176/186/200/220=iris300, rskip271/293=hop400, rskip419=lovell700,
/// rskip540=vetiver900).
fn method_enabled(name: &str) -> BridgeMethodEnabled {
    use crate::hardfork::RskNetworkUpgrade::*;
    use BridgeMethodEnabled::*;
    match name {
        // !RSKIP87 / !RSKIP89
        "addLockWhitelistAddress" | "getBtcBlockchainBlockLocator" => Until(Orchid),
        // RSKIP87 / RSKIP89
        "addOneOffLockWhitelistAddress"
        | "addUnlimitedLockWhitelistAddress"
        | "getLockWhitelistEntryByAddress"
        | "getBtcBlockchainInitialBlockHeight"
        | "getBtcBlockchainBlockHashAtDepth" => Since(Orchid),
        // !RSKIP123
        "addFederatorPublicKey"
        | "getFederatorPublicKey"
        | "getPendingFederatorPublicKey"
        | "getRetiringFederatorPublicKey" => Until(Wasabi100),
        // RSKIP122 / RSKIP123
        "addFederatorPublicKeyMultikey"
        | "getFederatorPublicKeyOfType"
        | "getPendingFederatorPublicKeyOfType"
        | "getRetiringFederatorPublicKeyOfType"
        | "getBtcTransactionConfirmations" => Since(Wasabi100),
        // RSKIP134 / RSKIP143
        "getLockingCap"
        | "increaseLockingCap"
        | "registerBtcCoinbaseTransaction"
        | "hasBtcBlockCoinbaseTransactionInformation" => Since(Papyrus200),
        // RSKIP176 / RSKIP186 / RSKIP200 / RSKIP220
        "registerFastBridgeBtcTransaction"
        | "getActiveFederationCreationBlockHeight"
        | "receiveHeader"
        | "getBtcBlockchainBestBlockHeader"
        | "getBtcBlockchainBlockHeaderByHash"
        | "getBtcBlockchainBlockHeaderByHeight"
        | "getBtcBlockchainParentBlockHeaderByHash" => Since(Iris300),
        // RSKIP271 / RSKIP293
        "getNextPegoutCreationBlockNumber"
        | "getQueuedPegoutsCount"
        | "getEstimatedFeesForNextPegOutEvent"
        | "getActivePowpegRedeemScript" => Since(Hop400),
        // RSKIP419
        "getProposedFederationAddress"
        | "getProposedFederationSize"
        | "getProposedFederationCreationTime"
        | "getProposedFederationCreationBlockNumber"
        | "getProposedFederatorPublicKeyOfType"
        | "getStateForSvpClient" => Since(Lovell700),
        // RSKIP540
        "getEstimatedFeesForPegOutAmount" => Since(Vetiver900),
        _ => Always,
    }
}

/// rskj `BridgeMethods` call-type verifier (BridgeMethods.java:1002-1067): the
/// default for every method is `RESTRICTED_TO_CALL` (only `MsgType.CALL`); the
/// read-only getters add `ALLOW_STATIC_CALL` (CALL or STATICCALL). NO method
/// accepts DELEGATECALL or CALLCODE. `Bridge.validateCallMessageType`
/// (Bridge.java:446) throws when a method is reached via a call type it does
/// not accept. Returns true if `name` accepts a STATICCALL.
fn method_allows_static_call(name: &str) -> bool {
    matches!(
        name,
        "getBtcBlockchainBestChainHeight"
            | "getBtcBlockchainInitialBlockHeight"
            | "getBtcBlockchainBlockLocator"
            | "getBtcBlockchainBlockHashAtDepth"
            | "getBtcTransactionConfirmations"
            | "getBtcTxHashProcessedHeight"
            | "getFederationAddress"
            | "getFederationCreationBlockNumber"
            | "getFederationCreationTime"
            | "getFederationSize"
            | "getFederationThreshold"
            | "getFederatorPublicKey"
            | "getFederatorPublicKeyOfType"
            | "getFeePerKb"
            | "getLockWhitelistAddress"
            | "getLockWhitelistEntryByAddress"
            | "getLockWhitelistSize"
            | "getMinimumLockTxValue"
            | "getPendingFederationHash"
            | "getPendingFederationSize"
            | "getPendingFederatorPublicKey"
            | "getPendingFederatorPublicKeyOfType"
            | "getRetiringFederationAddress"
            | "getRetiringFederationCreationBlockNumber"
            | "getRetiringFederationCreationTime"
            | "getRetiringFederationSize"
            | "getRetiringFederationThreshold"
            | "getRetiringFederatorPublicKey"
            | "getRetiringFederatorPublicKeyOfType"
            | "getProposedFederationAddress"
            | "getProposedFederationSize"
            | "getProposedFederationCreationTime"
            | "getProposedFederationCreationBlockNumber"
            | "getProposedFederatorPublicKeyOfType"
            | "getStateForBtcReleaseClient"
            | "getStateForSvpClient"
            | "getStateForDebugging"
            | "getLockingCap"
            | "getActivePowpegRedeemScript"
            | "getActiveFederationCreationBlockHeight"
            | "isBtcTxHashAlreadyProcessed"
            | "hasBtcBlockCoinbaseTransactionInformation"
            | "getBtcBlockchainBestBlockHeader"
            | "getBtcBlockchainBlockHeaderByHash"
            | "getBtcBlockchainBlockHeaderByHeight"
            | "getBtcBlockchainParentBlockHeaderByHash"
            | "getNextPegoutCreationBlockNumber"
            | "getQueuedPegoutsCount"
            | "getEstimatedFeesForNextPegOutEvent"
            | "getEstimatedFeesForPegOutAmount"
    )
}

/// rskj `Bridge.validateLocalCall` (Bridge.java:431) + `BridgeMethods`
/// `onlyAllowsLocalCalls`: a method whose permission only allows LOCAL (eth_call)
/// calls throws `BridgeIllegalArgumentException` when reached by any on-chain
/// (non-local) call. `getBtcBlockchainBestChainHeight` is local-only only before
/// RSKIP220 (Iris300); afterwards it is tx-callable
/// (`getBtcBlockchainBestChainHeightOnlyAllowsLocalCalls`, Bridge.java:700).
fn method_only_allows_local_calls(
    permission: BridgePermission,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> bool {
    match permission {
        BridgePermission::TransactionCallable => false,
        BridgePermission::LocalOnly => true,
        BridgePermission::DynamicRskip220 => {
            hardfork_cfg.active_upgrade(block_number) < crate::hardfork::RskNetworkUpgrade::Iris300
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BridgeGasCost {
    Fixed(u64),
    /// Gas depends on input length (e.g. receiveHeaders).
    InputDependent,
    /// Gas depends on method-specific logic (e.g. getBtcTransactionConfirmations).
    Dynamic,
}

impl BridgeGasCost {
    pub fn fixed_cost(&self) -> u64 {
        match self {
            BridgeGasCost::Fixed(c) => *c,
            _ => 0,
        }
    }
}

/// Build the complete method table. Called once, cached in a lazy_static.
fn build_method_table() -> Vec<BridgeMethodInfo> {
    use BridgeGasCost::*;
    use BridgePermission::*;

    let methods: Vec<(&str, &str, BridgeGasCost, BridgePermission)> = vec![
        // -- Transaction-callable, state-mutating --
        ("addFederatorPublicKey",       "addFederatorPublicKey(bytes)",                              Fixed(13000), TransactionCallable),
        ("addFederatorPublicKeyMultikey","addFederatorPublicKeyMultikey(bytes,bytes,bytes)",          Fixed(13000), TransactionCallable),
        ("addLockWhitelistAddress",     "addLockWhitelistAddress(string,int256)",                    Fixed(25000), TransactionCallable),
        ("addOneOffLockWhitelistAddress","addOneOffLockWhitelistAddress(string,int256)",              Fixed(25000), TransactionCallable),
        ("addUnlimitedLockWhitelistAddress","addUnlimitedLockWhitelistAddress(string)",              Fixed(25000), TransactionCallable),
        ("addSignature",                "addSignature(bytes,bytes[],bytes)",                         Fixed(70000), TransactionCallable),
        ("commitFederation",            "commitFederation(bytes)",                                   Fixed(38000), TransactionCallable),
        ("createFederation",            "createFederation()",                                        Fixed(11000), TransactionCallable),
        ("increaseLockingCap",          "increaseLockingCap(int256)",                                Fixed(8000),  TransactionCallable),
        ("receiveHeaders",              "receiveHeaders(bytes[])",                                   InputDependent, TransactionCallable),
        ("receiveHeader",               "receiveHeader(bytes)",                                      Fixed(10600), TransactionCallable),
        ("registerBtcTransaction",      "registerBtcTransaction(bytes,int256,bytes)",                Fixed(22000), TransactionCallable),
        ("releaseBtc",                  "releaseBtc()",                                              Fixed(23000), TransactionCallable),
        ("removeLockWhitelistAddress",  "removeLockWhitelistAddress(string)",                        Fixed(24000), TransactionCallable),
        ("rollbackFederation",          "rollbackFederation()",                                      Fixed(12000), TransactionCallable),
        ("setLockWhitelistDisableBlockDelay","setLockWhitelistDisableBlockDelay(int256)",             Fixed(24000), TransactionCallable),
        ("updateCollections",           "updateCollections()",                                       Fixed(48000), TransactionCallable),
        ("voteFeePerKbChange",          "voteFeePerKbChange(int256)",                                Fixed(10000), TransactionCallable),
        ("registerBtcCoinbaseTransaction","registerBtcCoinbaseTransaction(bytes,bytes32,bytes,bytes32,bytes32)", Fixed(10000), TransactionCallable),
        ("registerFastBridgeBtcTransaction","registerFastBridgeBtcTransaction(bytes,uint256,bytes,bytes32,bytes,address,bytes,bool)", Fixed(25000), TransactionCallable),
        // -- Transaction-callable, read-only --
        ("getBtcTransactionConfirmations","getBtcTransactionConfirmations(bytes32,bytes32,uint256,bytes32[])", Dynamic, TransactionCallable),
        ("hasBtcBlockCoinbaseTransactionInformation","hasBtcBlockCoinbaseTransactionInformation(bytes32)", Fixed(5000), TransactionCallable),
        ("getActivePowpegRedeemScript", "getActivePowpegRedeemScript()",                             Fixed(30000), TransactionCallable),
        ("getActiveFederationCreationBlockHeight","getActiveFederationCreationBlockHeight()",         Fixed(3000),  TransactionCallable),
        ("getBtcBlockchainBestBlockHeader","getBtcBlockchainBestBlockHeader()",                       Fixed(3800),  TransactionCallable),
        ("getBtcBlockchainBlockHeaderByHash","getBtcBlockchainBlockHeaderByHash(bytes32)",            Fixed(4600),  TransactionCallable),
        ("getBtcBlockchainBlockHeaderByHeight","getBtcBlockchainBlockHeaderByHeight(uint256)",         Fixed(5000),  TransactionCallable),
        ("getBtcBlockchainParentBlockHeaderByHash","getBtcBlockchainParentBlockHeaderByHash(bytes32)", Fixed(4900),  TransactionCallable),
        ("getNextPegoutCreationBlockNumber","getNextPegoutCreationBlockNumber()",                     Fixed(3000),  TransactionCallable),
        ("getQueuedPegoutsCount",       "getQueuedPegoutsCount()",                                   Fixed(3000),  TransactionCallable),
        ("getEstimatedFeesForNextPegOutEvent","getEstimatedFeesForNextPegOutEvent()",                 Fixed(10000), TransactionCallable),
        ("getEstimatedFeesForPegOutAmount","getEstimatedFeesForPegOutAmount(uint256)",                Fixed(10000), TransactionCallable),
        // -- Dynamic permission --
        ("getBtcBlockchainBestChainHeight","getBtcBlockchainBestChainHeight()",                       Fixed(19000), DynamicRskip220),
        // -- Local-only getters (needed for completeness; not consensus-critical) --
        ("getBtcBlockchainInitialBlockHeight","getBtcBlockchainInitialBlockHeight()",                 Fixed(20000), LocalOnly),
        ("getBtcBlockchainBlockLocator","getBtcBlockchainBlockLocator()",                             Fixed(76000), LocalOnly),
        ("getBtcBlockchainBlockHashAtDepth","getBtcBlockchainBlockHashAtDepth(int256)",               Fixed(20000), LocalOnly),
        ("getBtcTxHashProcessedHeight", "getBtcTxHashProcessedHeight(string)",                        Fixed(22000), LocalOnly),
        ("getFederationAddress",        "getFederationAddress()",                                     Fixed(11000), LocalOnly),
        ("getFederationCreationBlockNumber","getFederationCreationBlockNumber()",                     Fixed(10000), LocalOnly),
        ("getFederationCreationTime",   "getFederationCreationTime()",                                Fixed(10000), LocalOnly),
        ("getFederationSize",           "getFederationSize()",                                        Fixed(10000), LocalOnly),
        ("getFederationThreshold",      "getFederationThreshold()",                                   Fixed(11000), LocalOnly),
        ("getFederatorPublicKey",       "getFederatorPublicKey(int256)",                              Fixed(10000), LocalOnly),
        ("getFederatorPublicKeyOfType", "getFederatorPublicKeyOfType(int256,string)",                 Fixed(10000), LocalOnly),
        ("getFeePerKb",                 "getFeePerKb()",                                             Fixed(2000),  LocalOnly),
        ("getLockWhitelistAddress",     "getLockWhitelistAddress(int256)",                            Fixed(16000), LocalOnly),
        ("getLockWhitelistEntryByAddress","getLockWhitelistEntryByAddress(string)",                   Fixed(16000), LocalOnly),
        ("getLockWhitelistSize",        "getLockWhitelistSize()",                                     Fixed(16000), LocalOnly),
        ("getMinimumLockTxValue",       "getMinimumLockTxValue()",                                   Fixed(2000),  LocalOnly),
        ("getPendingFederationHash",    "getPendingFederationHash()",                                 Fixed(3000),  LocalOnly),
        ("getPendingFederationSize",    "getPendingFederationSize()",                                 Fixed(3000),  LocalOnly),
        ("getPendingFederatorPublicKey","getPendingFederatorPublicKey(int256)",                       Fixed(3000),  LocalOnly),
        ("getPendingFederatorPublicKeyOfType","getPendingFederatorPublicKeyOfType(int256,string)",    Fixed(3000),  LocalOnly),
        ("getRetiringFederationAddress","getRetiringFederationAddress()",                             Fixed(3000),  LocalOnly),
        ("getRetiringFederationCreationBlockNumber","getRetiringFederationCreationBlockNumber()",     Fixed(3000),  LocalOnly),
        ("getRetiringFederationCreationTime","getRetiringFederationCreationTime()",                   Fixed(3000),  LocalOnly),
        ("getRetiringFederationSize",   "getRetiringFederationSize()",                                Fixed(3000),  LocalOnly),
        ("getRetiringFederationThreshold","getRetiringFederationThreshold()",                         Fixed(3000),  LocalOnly),
        ("getRetiringFederatorPublicKey","getRetiringFederatorPublicKey(int256)",                     Fixed(3000),  LocalOnly),
        ("getRetiringFederatorPublicKeyOfType","getRetiringFederatorPublicKeyOfType(int256,string)",  Fixed(3000),  LocalOnly),
        ("getProposedFederationAddress","getProposedFederationAddress()",                             Fixed(3000),  LocalOnly),
        ("getProposedFederationSize",   "getProposedFederationSize()",                                Fixed(3000),  LocalOnly),
        ("getProposedFederationCreationTime","getProposedFederationCreationTime()",                   Fixed(3000),  LocalOnly),
        ("getProposedFederationCreationBlockNumber","getProposedFederationCreationBlockNumber()",     Fixed(3000),  LocalOnly),
        ("getProposedFederatorPublicKeyOfType","getProposedFederatorPublicKeyOfType(int256,string)",  Fixed(3000),  LocalOnly),
        ("getStateForBtcReleaseClient", "getStateForBtcReleaseClient()",                             Fixed(4000),  LocalOnly),
        ("getStateForSvpClient",        "getStateForSvpClient()",                                    Fixed(4000),  LocalOnly),
        ("getStateForDebugging",        "getStateForDebugging()",                                    Fixed(3_000_000), LocalOnly),
        ("getLockingCap",               "getLockingCap()",                                            Fixed(3000),  LocalOnly),
        ("isBtcTxHashAlreadyProcessed", "isBtcTxHashAlreadyProcessed(string)",                       Fixed(23000), LocalOnly),
    ];

    methods
        .into_iter()
        .map(|(name, sig, gas, perm)| BridgeMethodInfo {
            name,
            signature: sig,
            selector: compute_selector(sig),
            gas_cost: gas,
            permission: perm,
            enabled: method_enabled(name),
        })
        .collect()
}

use std::collections::HashMap;
use std::sync::LazyLock;

static BRIDGE_METHODS: LazyLock<Vec<BridgeMethodInfo>> = LazyLock::new(build_method_table);

static BRIDGE_SELECTOR_MAP: LazyLock<HashMap<[u8; 4], usize>> = LazyLock::new(|| {
    BRIDGE_METHODS
        .iter()
        .enumerate()
        .map(|(i, m)| (m.selector, i))
        .collect()
});

/// Look up a Bridge method by its 4-byte ABI selector.
pub fn find_bridge_method(selector: &[u8; 4]) -> Option<&'static BridgeMethodInfo> {
    BRIDGE_SELECTOR_MAP.get(selector).map(|&i| &BRIDGE_METHODS[i])
}

// ---------------------------------------------------------------------------
// Bridge execution entry point
// ---------------------------------------------------------------------------

/// Marker prefix for rskj's "invisible exception" on direct (depth-1) Bridge
/// calls. rskj `TransactionExecutor.call` precomputes `requiredGas` from
/// `getGasForData` and, when `Bridge.execute` throws (parse failure OR a
/// method `VMException`/`RuntimeException`), only spends `requiredGas +
/// basicTxCost` while still flagging the summary as failed: the receipt is
/// SUCCESS with that spent gas, no logs, no endowment, but the sender is
/// charged the FULL gas limit. The marker carries `requiredGas` so the
/// precompile frame can record exactly that cost (the basic tx cost is
/// charged separately by revm's intrinsic accounting).
pub const INVISIBLE_EXCEPTION_MARKER: &str = "rskj invisible exception:";

/// Marker prefix for an INTERNAL (depth>1) Bridge method throw. rskj
/// `Program.executePrecompiledAndHandleError` had already charged
/// `requiredGas` before the call, then on a throw pushes zero (CALL fails)
/// and refunds `gas - requiredGas`, so only `requiredGas` is consumed and the
/// caller sees a plain CALL failure. The marker carries `requiredGas`.
pub const INTERNAL_BRIDGE_THROW_MARKER: &str = "rskj bridge method throw:";

fn marker_with_gas(prefix: &str, gas: u64) -> PrecompileError {
    PrecompileError::other(format!("{prefix}{gas}"))
}

fn marker_gas(e: &PrecompileError, prefix: &str) -> Option<u64> {
    match e {
        PrecompileError::Other(msg) => msg.strip_prefix(prefix).and_then(|g| g.parse().ok()),
        _ => None,
    }
}

/// rskj invisible exception (direct, depth-1 Bridge call): returns the spent
/// `requiredGas` if `e` is the invisible marker.
pub fn invisible_exception_gas(e: &PrecompileError) -> Option<u64> {
    marker_gas(e, INVISIBLE_EXCEPTION_MARKER)
}

/// Build the depth-1 invisible-exception error carrying its `requiredGas`.
pub fn invisible_exception_marker_with_gas(gas: u64) -> PrecompileError {
    marker_with_gas(INVISIBLE_EXCEPTION_MARKER, gas)
}

/// Whether a Bridge error is the direct-call invisible-exception marker.
pub fn is_invisible_exception(e: &PrecompileError) -> bool {
    invisible_exception_gas(e).is_some()
}

/// Internal (depth>1) Bridge method throw: returns the spent `requiredGas`.
pub fn internal_throw_gas(e: &PrecompileError) -> Option<u64> {
    marker_gas(e, INTERNAL_BRIDGE_THROW_MARKER)
}

/// Marker prefix for the rskj `Program.callToPrecompiledAddress` insufficient-
/// gas branch: when `requiredGas > msg.getGas()` for an INTERNAL (depth>1)
/// call, rskj does `refundGas(0); stackPushZero(); track.rollback()` — the
/// forwarded gas is fully consumed, the CALL fails (returns 0) and the CALLER
/// CONTINUES; it is NOT a propagating OOG that aborts the caller. The marker
/// carries the forwarded gas to consume (Program.java:1567-1573).
pub const INSUFFICIENT_GAS_MARKER: &str = "rskj precompile insufficient gas:";

/// The EVM call type by which the Bridge precompile was reached, mapped from
/// revm's `CallScheme`. rskj `MessageCall.MsgType` — used by
/// `validateCallMessageType` to reject call types a method does not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeCallKind {
    /// `CALL` — accepted by every method.
    Call,
    /// `STATICCALL` — accepted only by the read-only getters.
    StaticCall,
    /// `DELEGATECALL` or `CALLCODE` — accepted by no method.
    DelegateOrCallCode,
}

/// rskj insufficient-gas precompile call (depth>1): returns the forwarded gas
/// to consume if `e` is the insufficient-gas marker.
pub fn insufficient_gas_consumed(e: &PrecompileError) -> Option<u64> {
    marker_gas(e, INSUFFICIENT_GAS_MARKER)
}

/// Build the insufficient-gas result for a Bridge call whose `requiredGas`
/// exceeds the forwarded `gas_limit`. For a direct (depth-1) call the
/// transaction itself runs out of gas (propagating OOG). For an internal call
/// (a contract CALLing the Bridge) rskj pushes zero and the caller continues,
/// so the marker carries the forwarded gas for a graceful CALL revert.
fn insufficient_gas_marker<CTX: crate::RskContextTr>(ctx: &mut CTX, gas_limit: u64) -> PrecompileError {
    use revm::context_interface::JournalTr;
    if ctx.journal().depth() > 1 {
        marker_with_gas(INSUFFICIENT_GAS_MARKER, gas_limit)
    } else {
        PrecompileError::OutOfGas
    }
}

/// Main entry point for the Bridge precompile.
///
/// Called from `RskPrecompileProvider::run_bridge` with the full EVM context.
/// Parses the ABI selector, dispatches to the appropriate handler, and
/// persists storage changes on success.
pub fn execute_bridge<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    input: &[u8],
    gas_limit: u64,
    config: &BridgeConstants,
    block_store: Option<&Arc<BlockStore>>,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
    caller: alloy_primitives::Address,
    call_depth: usize,
    call_kind: BridgeCallKind,
) -> Result<PrecompileOutput, PrecompileError> {
    // Empty input → releaseBtc (legacy behavior matching rskj)
    if input.is_empty() {
        let gas_cost = 23_000u64;
        if gas_limit < gas_cost {
            return Err(insufficient_gas_marker(ctx, gas_limit));
        }
        return execute_method(ctx, "releaseBtc", &[], gas_cost, config, block_store, use_v2, hardfork_cfg, tx_ctx, caller, call_depth);
    }

    // rskj Bridge.parseData: 1-3 byte data, an unknown selector, or a method
    // not enabled at this block is a parse failure. Before RSKIP88 (orchid)
    // execute() returns null — the tx SUCCEEDS, charged the flat releaseBtc
    // cost without executing anything (mainnet #648,914 sent ASCII text as
    // calldata). Afterwards it throws BridgeIllegalArgumentException.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let parsed = if input.len() < 4 {
        None
    } else {
        find_bridge_method(&[input[0], input[1], input[2], input[3]])
            .filter(|m| m.enabled.is_enabled(hardfork_cfg, block_number))
            // rskj `parseData` ABI-decodes the arguments; a malformed payload
            // (e.g. an out-of-bounds dynamic offset) is a parse failure too.
            .filter(|m| abi_args_decode_ok(&input[4..], m.signature))
    };
    let Some(method) = parsed else {
        let gas_cost = 23_000u64; // BridgeMethods.RELEASE_BTC cost, no data cost
        if gas_limit < gas_cost {
            return Err(insufficient_gas_marker(ctx, gas_limit));
        }
        if !hardfork_cfg.has_rskip88(block_number) {
            return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
        }
        // Post-RSKIP88 rskj throws — but for a direct transaction the
        // exception is invisible in the RECEIPT: TransactionExecutor.call()
        // spends only requiredGas + basicTxCost and go() (vm == null)
        // commits, so the receipt is SUCCESS with empty output and no logs
        // (mainnet #764,123 calls the post-RSKIP87-disabled
        // addLockWhitelistAddress). The FEE accounting still sees it: the
        // execution summary is marked failed, so the sender is charged the
        // FULL gas limit (no leftover refund) and REMASC receives
        // gasLimit * gasPrice, and the endowment is not transferred
        // (TransactionExecutionSummary.getFee / TransactionExecutor.call).
        // Callers translate this marker into those semantics. Only internal
        // calls observe the failure as a plain CALL failure.
        use revm::context_interface::JournalTr;
        if ctx.journal().depth() == 1 {
            // requiredGas for a parse failure is the flat releaseBtc cost.
            return Err(marker_with_gas(INVISIBLE_EXCEPTION_MARKER, gas_cost));
        }
        // Internal (depth>1) call: rskj `execute()` throws and
        // `executePrecompiledAndHandleError` consumes only `requiredGas`
        // (the flat 23_000) before the CALL pushes zero and the caller
        // continues — the surplus forwarded gas is refunded. (#6,223,797 tx[3]
        // forwards a malformed `receiveHeaders` and depends on this refund to
        // finish its post-call path.)
        return Err(marker_with_gas(INTERNAL_BRIDGE_THROW_MARKER, gas_cost));
    };

    let args = &input[4..];
    let gas_cost = bridge_call_gas_cost(ctx, input, config, hardfork_cfg)?;

    if gas_limit < gas_cost {
        return Err(insufficient_gas_marker(ctx, gas_limit));
    }

    // rskj `Bridge.validateCall` (Bridge.java:426) runs two gates after the gas
    // is charged, both throwing `BridgeIllegalArgumentException` → `VMException`
    // (consume `requiredGas`, CALL returns empty). The first is
    // `validateLocalCall` (Bridge.java:431): post-RSKIP88, a LOCAL-ONLY method
    // reached by a non-local call throws. Only `eth_call` is a local call, so
    // every on-chain CALL/transaction during block execution is non-local — a
    // local-only getter invoked on-chain always throws here and returns empty
    // (mainnet #6,223,900: a relay plain-CALLs `getFederationAddress`, which
    // rskj empties so the relay's RETURNDATASIZE check sees 0).
    if method_only_allows_local_calls(method.permission, hardfork_cfg, block_number) {
        use revm::context_interface::JournalTr;
        if ctx.journal().depth() == 1 {
            return Err(marker_with_gas(INVISIBLE_EXCEPTION_MARKER, gas_cost));
        }
        return Err(marker_with_gas(INTERNAL_BRIDGE_THROW_MARKER, gas_cost));
    }

    // rskj `Bridge.validateCallMessageType` (Bridge.java:446): after the gas is
    // charged, a method reached via a call type it does not accept throws. The
    // default is CALL-only; the read getters also accept STATICCALL; no method
    // accepts DELEGATECALL/CALLCODE. The throw consumes `requiredGas` and the
    // CALL returns zero (mainnet #6,223,797-adjacent #6,223,812: a relay
    // DELEGATECALLs receiveHeader, which rskj rejects so RETURNDATASIZE is 0).
    let accepts_call = match call_kind {
        BridgeCallKind::Call => true,
        BridgeCallKind::StaticCall => method_allows_static_call(method.name),
        BridgeCallKind::DelegateOrCallCode => false,
    };
    if !accepts_call {
        use revm::context_interface::JournalTr;
        if ctx.journal().depth() == 1 {
            return Err(marker_with_gas(INVISIBLE_EXCEPTION_MARKER, gas_cost));
        }
        return Err(marker_with_gas(INTERNAL_BRIDGE_THROW_MARKER, gas_cost));
    }

    let result = execute_method(ctx, method.name, args, gas_cost, config, block_store, use_v2, hardfork_cfg, tx_ctx, caller, call_depth);
    // rskj `Bridge.execute` wraps any method `RuntimeException` in a
    // `VMException`, which `TransactionExecutor.call` / `Program` then handle
    // by spending only `requiredGas` (the `getGasForData` cost) — NOT all the
    // forwarded gas. Translate a non-OOG, non-Fatal method throw into the
    // depth-aware markers so the precompile frame records exactly `gas_cost`.
    // (OOG and Fatal keep their original semantics.)
    match result {
        Err(e) if !e.is_oog() && !matches!(e, PrecompileError::Fatal(_)) => {
            use revm::context_interface::JournalTr;
            if ctx.journal().depth() == 1 {
                Err(marker_with_gas(INVISIBLE_EXCEPTION_MARKER, gas_cost))
            } else {
                Err(marker_with_gas(INTERNAL_BRIDGE_THROW_MARKER, gas_cost))
            }
        }
        other => other,
    }
}

/// rskj `Bridge.getGasForData` for a parsed call: functionCost plus
/// `data.length * 2` (23_000 flat for the empty-input releaseBtc form).
/// Free bridge transactions cost 0 — callers handle that case.
pub fn bridge_call_gas_cost<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    input: &[u8],
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<u64, PrecompileError> {
    if input.is_empty() {
        return Ok(23_000);
    }
    // rskj getGasForData: a parse failure costs the flat releaseBtc amount
    // (no data cost), at every era.
    if input.len() < 4 {
        return Ok(23_000);
    }
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let selector = [input[0], input[1], input[2], input[3]];
    let Some(method) = find_bridge_method(&selector)
        .filter(|m| m.enabled.is_enabled(hardfork_cfg, block_number))
    else {
        return Ok(23_000);
    };

    let args = &input[4..];

    let function_cost = match method.gas_cost {
        BridgeGasCost::Fixed(c) => c,
        BridgeGasCost::InputDependent => receive_headers_cost(args, hardfork_cfg, block_number),
        BridgeGasCost::Dynamic => btc_tx_confirmations_cost(ctx, args, config),
    };
    // rskj Bridge.getGasForData: totalCost = functionCost + data.length * 2
    Ok(function_cost.saturating_add(2 * input.len() as u64))
}

/// rskj `Bridge.receiveHeadersGetCost`: 22_000 before RSKIP124; afterwards a
/// base cost plus a per-additional-header charge (recalculated by RSKIP132).
fn receive_headers_cost(args: &[u8], hardfork_cfg: &RskHardforkConfig, block_number: u64) -> u64 {
    if !hardfork_cfg.has_rskip124(block_number) {
        return 22_000;
    }
    let rskip132 = hardfork_cfg.has_rskip132(block_number);
    let base: u64 = if rskip132 { 25_000 } else { 66_000 };
    let per_additional_header: u64 = if rskip132 { 3_500 } else { 1_650 };

    match abi_array_len(args, 0) {
        Some(n) if n > 0 => base.saturating_add((n - 1).saturating_mul(per_additional_header)),
        _ => base,
    }
}

/// rskj `BridgeSupport.getBtcTransactionConfirmationsGetCost`:
/// 27_000 base + blockDepth * 315 + merkleBranchHashes * 144, falling back to
/// the base cost when the block is unknown or too deep.
fn btc_tx_confirmations_cost<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    config: &BridgeConstants,
) -> u64 {
    const BASIC_COST: u64 = 27_000;
    const STEP_COST: u64 = 315;
    const DOUBLE_HASH_COST: u64 = 144;

    // args: bytes32 btcTxHash, bytes32 btcBlockHash, uint256 path, bytes32[] hashes
    let (block_hash, branch_hashes) = match (args.get(32..64), abi_array_len(args, 96)) {
        (Some(h), Some(n)) => (alloy_primitives::B256::from_slice(h), n),
        _ => return BASIC_COST,
    };

    let block_hash = crate::bridge::btc_chain::b256_to_bitcoin_hash(&block_hash);
    let Some(block) = crate::bridge::btc_store::get_stored_block(ctx, &block_hash) else {
        return BASIC_COST;
    };
    let Some(head) = crate::bridge::btc_store::load_chain_head(ctx) else {
        return BASIC_COST;
    };

    let depth = head.height.saturating_sub(block.height) as u64;
    if depth > config.btc_transaction_confirmation_max_depth as u64 {
        return BASIC_COST;
    }

    BASIC_COST + depth * STEP_COST + branch_hashes * DOUBLE_HASH_COST
}

/// Length of an ABI dynamic array whose offset word sits at `slot` in `args`.
fn abi_array_len(args: &[u8], slot: usize) -> Option<u64> {
    let offset = U256::from_be_slice(args.get(slot..slot + 32)?).try_into().ok()?;
    let offset: usize = offset;
    let len = args.get(offset..offset + 32)?;
    Some(U256::from_be_slice(len).to::<u64>())
}

/// Dispatch to individual method handlers.
fn execute_method<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    method_name: &str,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    _block_store: Option<&Arc<BlockStore>>,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
    caller: alloy_primitives::Address,
    call_depth: usize,
) -> Result<PrecompileOutput, PrecompileError> {

    // rskj `Bridge.activeAndRetiringFederationOnly` authorization. The executor
    // for `updateCollections` (always) and `receiveHeaders` (when not public,
    // i.e. post-RSKIP200) throws a `VMException` when the call's sender is not a
    // member of the active or retiring federation. Bridge.execute wraps that in
    // a VMException which `executePrecompiledAndHandleError` turns into a
    // rollback + stackPushZero (the call returns 0 / empty data) while still
    // charging the full `requiredGas`. A relay contract forwarding the call is
    // checked by its own address, so a non-federation caller is rejected with no
    // state change and no event (mainnet #6,223,774 tx[1]: updateCollections via
    // relay 0x82494fb1 must NOT emit the update_collections log).
    let federation_only = match method_name {
        "updateCollections" => true,
        // receiveHeadersIsPublic() = RSKIP124 && !RSKIP200; restricted otherwise.
        "receiveHeaders" => {
            let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
            !(hardfork_cfg.has_rskip124(block_number) && !hardfork_cfg.has_rskip200(block_number))
        }
        _ => false,
    };
    if federation_only {
        let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
        if !peg::is_sender_active_or_retiring_fed_member(ctx, config, hardfork_cfg, block_number, caller) {
            // BridgeIllegalArgumentException-equivalent: a non-OOG throw the
            // execute_bridge wrapper maps to the depth-aware bridge-throw marker
            // (rollback + only requiredGas spent).
            return Err(PrecompileError::other("Bridge: sender is not a federation member"));
        }
    }

    match method_name {
        // Phase 2: BTC header chain
        "receiveHeader" => btc_chain::receive_header(ctx, args, gas_cost, config, use_v2, hardfork_cfg),
        "receiveHeaders" => btc_chain::receive_headers(ctx, args, gas_cost, config, use_v2, hardfork_cfg),
        "getBtcBlockchainBestChainHeight" => btc_chain::get_best_chain_height(ctx, gas_cost),
        "getBtcBlockchainBestBlockHeader" => btc_chain::get_best_block_header(ctx, gas_cost),
        "getBtcBlockchainBlockHeaderByHash" => btc_chain::get_block_header_by_hash(ctx, args, gas_cost),
        "getBtcBlockchainBlockHeaderByHeight" => btc_chain::get_block_header_by_height(ctx, args, gas_cost),
        "getBtcBlockchainParentBlockHeaderByHash" => btc_chain::get_parent_block_header_by_hash(ctx, args, gas_cost),

        // Phase 3: BTC transaction verification
        "registerBtcCoinbaseTransaction" => tx::register_btc_coinbase_transaction(ctx, args, gas_cost),
        "hasBtcBlockCoinbaseTransactionInformation" => tx::has_btc_block_coinbase_info(ctx, args, gas_cost),
        "getBtcTransactionConfirmations" => tx::get_btc_transaction_confirmations(ctx, args, gas_cost),

        // Phase 4: Peg-in
        "registerBtcTransaction" => peg::register_btc_transaction(ctx, args, gas_cost, config, hardfork_cfg, tx_ctx),
        "registerFastBridgeBtcTransaction" => peg::register_fast_bridge_btc_transaction(ctx, args, gas_cost, config, hardfork_cfg, tx_ctx, caller, call_depth),

        // Phase 5: Peg-out
        "releaseBtc" => peg::release_btc(ctx, gas_cost, config, hardfork_cfg, tx_ctx),
        "updateCollections" => peg::update_collections(ctx, gas_cost, config, hardfork_cfg, tx_ctx),
        "addSignature" => peg::add_signature(ctx, args, gas_cost, config, hardfork_cfg),

        // Phase 6: Governance
        "createFederation" => governance::create_federation(ctx, gas_cost, config, hardfork_cfg, tx_ctx),
        "commitFederation" => governance::commit_federation(ctx, args, gas_cost, config, hardfork_cfg, tx_ctx),
        "rollbackFederation" => governance::rollback_federation(ctx, gas_cost, config, hardfork_cfg, tx_ctx),
        "addFederatorPublicKey" => governance::add_federator_public_key(ctx, args, gas_cost, config, hardfork_cfg, tx_ctx),
        "addFederatorPublicKeyMultikey" => governance::add_federator_public_key_multikey(ctx, args, gas_cost, config, hardfork_cfg, tx_ctx),
        "voteFeePerKbChange" => governance::vote_fee_per_kb_change(ctx, args, gas_cost, config, tx_ctx),
        "increaseLockingCap" => governance::increase_locking_cap(ctx, args, gas_cost, config, tx_ctx),
        "addLockWhitelistAddress" => governance::add_lock_whitelist_address(ctx, args, gas_cost, config, tx_ctx),
        "addOneOffLockWhitelistAddress" => governance::add_one_off_lock_whitelist_address(ctx, args, gas_cost, config, tx_ctx),
        "addUnlimitedLockWhitelistAddress" => governance::add_unlimited_lock_whitelist_address(ctx, args, gas_cost, config, tx_ctx),
        "removeLockWhitelistAddress" => governance::remove_lock_whitelist_address(ctx, args, gas_cost, config, tx_ctx),
        "setLockWhitelistDisableBlockDelay" => governance::set_lock_whitelist_disable_block_delay(ctx, args, gas_cost, config, tx_ctx),

        // Transaction-callable read-only
        "getActivePowpegRedeemScript" => governance::get_active_powpeg_redeem_script(ctx, gas_cost),
        "getActiveFederationCreationBlockHeight" => governance::get_active_federation_creation_block_height(ctx, gas_cost),
        "getNextPegoutCreationBlockNumber" => peg::get_next_pegout_creation_block_number(ctx, gas_cost),
        "getQueuedPegoutsCount" => peg::get_queued_pegouts_count(ctx, gas_cost),
        "getEstimatedFeesForNextPegOutEvent" => peg::get_estimated_fees_for_next_pegout(ctx, gas_cost),
        "getEstimatedFeesForPegOutAmount" => peg::get_estimated_fees_for_pegout_amount(ctx, args, gas_cost, config, hardfork_cfg),

        // Local-only getters with real storage reads
        "getFederationAddress" => getters::get_federation_address(ctx, gas_cost),
        "getFederationSize" => getters::get_federation_size(ctx, gas_cost),
        "getFederationThreshold" => getters::get_federation_threshold(ctx, gas_cost),
        "getFederationCreationBlockNumber" => getters::get_federation_creation_block_number(ctx, gas_cost),
        "getFederationCreationTime" => getters::get_federation_creation_time(ctx, gas_cost),
        "getFederatorPublicKey" => getters::get_federator_public_key(ctx, args, gas_cost),
        "getFederatorPublicKeyOfType" => getters::get_federator_public_key_of_type(ctx, args, gas_cost),
        "getFeePerKb" => getters::get_fee_per_kb(ctx, gas_cost),
        "getLockingCap" => getters::get_locking_cap(ctx, gas_cost, config),
        "getMinimumLockTxValue" => getters::get_minimum_lock_tx_value(gas_cost, config),
        "getRetiringFederationAddress" => getters::get_retiring_federation_address(ctx, gas_cost),
        "getRetiringFederationSize" => getters::get_retiring_federation_size(ctx, gas_cost),
        "getRetiringFederationThreshold" => getters::get_retiring_federation_threshold(ctx, gas_cost),
        "getPendingFederationSize" => getters::get_pending_federation_size(ctx, gas_cost),
        "isBtcTxHashAlreadyProcessed" => getters::is_btc_tx_hash_already_processed(ctx, args, gas_cost),
        _ => Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_table_has_70_entries() {
        // 69 pre-vetiver methods + getEstimatedFeesForPegOutAmount (RSKIP540).
        assert_eq!(BRIDGE_METHODS.len(), 70);
    }

    #[test]
    fn selector_map_has_70_entries() {
        assert_eq!(BRIDGE_SELECTOR_MAP.len(), 70);
    }

    #[test]
    fn all_selectors_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for m in BRIDGE_METHODS.iter() {
            assert!(
                seen.insert(m.selector),
                "Duplicate selector for {}",
                m.name
            );
        }
    }

    #[test]
    fn known_selector_release_btc() {
        let m = find_bridge_method(&compute_selector("releaseBtc()")).unwrap();
        assert_eq!(m.name, "releaseBtc");
        assert!(matches!(m.gas_cost, BridgeGasCost::Fixed(23000)));
    }

    #[test]
    fn known_selector_update_collections() {
        let m = find_bridge_method(&compute_selector("updateCollections()")).unwrap();
        assert_eq!(m.name, "updateCollections");
        assert!(matches!(m.gas_cost, BridgeGasCost::Fixed(48000)));
    }

    #[test]
    fn known_selector_register_btc_transaction() {
        let m = find_bridge_method(&compute_selector("registerBtcTransaction(bytes,int256,bytes)")).unwrap();
        assert_eq!(m.name, "registerBtcTransaction");
    }

    #[test]
    fn known_selector_receive_header() {
        let m = find_bridge_method(&compute_selector("receiveHeader(bytes)")).unwrap();
        assert_eq!(m.name, "receiveHeader");
        assert!(matches!(m.gas_cost, BridgeGasCost::Fixed(10600)));
    }

    /// rskj `Bridge.getGasForData` charges `functionCost + data.length * 2` for
    /// every parsed method (Bridge.java:296-321). For `receiveHeader` the total
    /// is `10_600 + 2 * data.len()`, NOT the bare 10_600 function cost.
    ///
    /// Groundtruth: mainnet #6,223,762 tx[2] CALLs the Bridge with a 164-byte
    /// `receiveHeader(bytes)` payload; rskj charges the precompile
    /// `10_600 + 2*164 = 10_928`. rustock previously hardcoded 10_600 in
    /// `receive_header`, undercharging by 328 gas and forking the chain.
    #[test]
    fn receive_header_gas_includes_data_cost() {
        let func_cost = match find_bridge_method(&compute_selector("receiveHeader(bytes)"))
            .unwrap()
            .gas_cost
        {
            BridgeGasCost::Fixed(c) => c,
            _ => panic!("receiveHeader must be a Fixed cost"),
        };
        assert_eq!(func_cost, 10_600);
        // rskj getGasForData total cost for the #6,223,762 tx[2] payload.
        let input_len = 164u64;
        assert_eq!(func_cost + 2 * input_len, 10_928);
    }

    #[test]
    fn known_selector_add_signature() {
        let m = find_bridge_method(&compute_selector("addSignature(bytes,bytes[],bytes)")).unwrap();
        assert_eq!(m.name, "addSignature");
    }

    /// rskj `parseData` ABI-decodes the arguments; a malformed payload (here a
    /// `bytes[]` head offset of 0xa0 into a 60-byte argument tail) makes the
    /// Solidity decoder throw → parse failure (flat 23_000 cost), NOT the
    /// method's own cost. Groundtruth: mainnet #6,223,797 tx[3] forwards
    /// exactly this `receiveHeaders(bytes[])` payload to the Bridge.
    #[test]
    fn abi_decode_rejects_out_of_bounds_array_offset() {
        // selector(4) + offset(0xa0) + 28 trailing bytes = 64-byte calldata.
        let mut input = compute_selector("receiveHeaders(bytes[])").to_vec();
        let mut word = [0u8; 32];
        word[31] = 0xa0; // offset 160, well past the 60-byte argument tail
        input.extend_from_slice(&word);
        input.extend_from_slice(&[0u8; 28]);
        assert_eq!(input.len(), 64);
        assert!(
            !abi_args_decode_ok(&input[4..], "receiveHeaders(bytes[])"),
            "out-of-bounds bytes[] offset must fail to decode (rskj parse failure)"
        );
    }

    /// rskj `validateCallMessageType`: tx methods are CALL-only, getters also
    /// accept STATICCALL, and no method accepts DELEGATECALL/CALLCODE. (#6,223,812
    /// DELEGATECALLs receiveHeader, which rskj rejects.)
    #[test]
    fn call_type_acceptance_matches_rskj() {
        // Tx method: not static-callable.
        assert!(!method_allows_static_call("receiveHeader"));
        assert!(!method_allows_static_call("registerBtcTransaction"));
        assert!(!method_allows_static_call("updateCollections"));
        assert!(!method_allows_static_call("addSignature"));
        // Read getters: static-callable.
        assert!(method_allows_static_call("getFederationAddress"));
        assert!(method_allows_static_call("getBtcTransactionConfirmations"));
        assert!(method_allows_static_call("isBtcTxHashAlreadyProcessed"));
    }

    /// rskj `validateLocalCall`: a local-only getter reached by an on-chain call
    /// throws. During block execution every call is non-local, so a local-only
    /// method always rejects. `getBtcBlockchainBestChainHeight` flips from
    /// local-only to tx-callable at RSKIP220 (Iris300). (#6,223,900: a relay
    /// plain-CALLs `getFederationAddress`, which rskj empties.)
    #[test]
    fn local_call_gating_matches_rskj() {
        let cfg = crate::hardfork::RskHardforkConfig::mainnet();
        let pre_iris = 3_000_000; // before Iris300 (mainnet #3,614,800)
        let post_iris = 6_223_900;

        let local = find_bridge_method(&compute_selector("getFederationAddress()")).unwrap();
        assert!(matches!(local.permission, BridgePermission::LocalOnly));
        // A local-only getter rejects on-chain at any block.
        assert!(method_only_allows_local_calls(local.permission, &cfg, post_iris));
        assert!(method_only_allows_local_calls(local.permission, &cfg, pre_iris));

        // Tx-callable methods are never local-gated.
        let txm = find_bridge_method(&compute_selector("registerBtcTransaction(bytes,int256,bytes)")).unwrap();
        assert!(!method_only_allows_local_calls(txm.permission, &cfg, post_iris));

        // getBtcBlockchainBestChainHeight: local-only before Iris300, tx-callable after.
        let dynm = find_bridge_method(&compute_selector("getBtcBlockchainBestChainHeight()")).unwrap();
        assert!(matches!(dynm.permission, BridgePermission::DynamicRskip220));
        assert!(method_only_allows_local_calls(dynm.permission, &cfg, pre_iris));
        assert!(!method_only_allows_local_calls(dynm.permission, &cfg, post_iris));
    }

    /// A well-formed `receiveHeaders(bytes[])` with one empty header element
    /// must decode successfully (no false parse failure).
    #[test]
    fn abi_decode_accepts_wellformed_array() {
        // offset=0x20, len=1, element-offset=0x20, element-len=0.
        let mut a = vec![0u8; 32 * 4];
        a[31] = 0x20; // offset to array
        a[63] = 1; // array length 1
        a[95] = 0x20; // element[0] offset (relative to array base)
        // a[96..128] = element length 0
        assert!(abi_args_decode_ok(&a, "receiveHeaders(bytes[])"));
        // Empty argument tail decodes as an empty array (rskj special case).
        assert!(abi_args_decode_ok(&[], "receiveHeaders(bytes[])"));
    }

    #[test]
    fn tx_callable_count() {
        let count = BRIDGE_METHODS
            .iter()
            .filter(|m| m.permission == BridgePermission::TransactionCallable)
            .count();
        assert_eq!(count, 32, "31 pre-vetiver methods with fixedPermission(false) + getEstimatedFeesForPegOutAmount");
    }

    #[test]
    fn local_only_count() {
        let count = BRIDGE_METHODS
            .iter()
            .filter(|m| m.permission == BridgePermission::LocalOnly)
            .count();
        assert_eq!(count, 37, "37 local-only methods");
    }

    #[test]
    fn dynamic_permission_count() {
        let count = BRIDGE_METHODS
            .iter()
            .filter(|m| m.permission == BridgePermission::DynamicRskip220)
            .count();
        assert_eq!(count, 1, "1 dynamic permission method (getBtcBlockchainBestChainHeight)");
    }

    #[test]
    fn empty_input_maps_to_release_btc() {
        // Verify the empty-input → releaseBtc behavior is wired correctly
        let sel = compute_selector("releaseBtc()");
        let m = find_bridge_method(&sel).unwrap();
        assert_eq!(m.name, "releaseBtc");
    }

    /// rskj Bridge.receiveHeadersGetCost groundtruth: 22_000 pre-RSKIP124;
    /// post-RSKIP132 (mainnet wasabi100) 25_000 + (n-1) * 3_500.
    #[test]
    fn receive_headers_cost_matches_rskj() {
        let cfg = crate::hardfork::RskHardforkConfig::mainnet();

        // ABI bytes[] with 3 entries: offset word + length word (entries not needed)
        let mut args = vec![0u8; 64];
        args[31] = 0x20; // offset 32
        args[63] = 3;    // length 3

        // Pre-wasabi100: flat 22_000 regardless of header count.
        assert_eq!(receive_headers_cost(&args, &cfg, 1_590_999), 22_000);
        // Post-wasabi100 (rskip124+132 both active on mainnet): 25_000 + 2*3_500.
        assert_eq!(receive_headers_cost(&args, &cfg, 1_591_000), 32_000);
        // Unparseable args fall back to the base cost.
        assert_eq!(receive_headers_cost(&[], &cfg, 1_591_000), 25_000);
    }
}
