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
pub mod pmt;
pub mod release_tx;
pub mod serialization;
pub mod storage;
pub mod tx;

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

/// Main entry point for the Bridge precompile.
///
/// Called from `RskPrecompileProvider::run_bridge` with the full EVM context.
/// Parses the ABI selector, dispatches to the appropriate handler, and
/// persists storage changes on success.
pub fn execute_bridge<CTX: ContextTr>(
    ctx: &mut CTX,
    input: &[u8],
    gas_limit: u64,
    config: &BridgeConstants,
    block_store: Option<&Arc<BlockStore>>,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    // Empty input → releaseBtc (legacy behavior matching rskj)
    if input.is_empty() {
        let gas_cost = 23_000u64;
        if gas_limit < gas_cost {
            return Err(PrecompileError::OutOfGas);
        }
        return execute_method(ctx, "releaseBtc", &[], gas_cost, config, block_store, use_v2, hardfork_cfg, tx_ctx);
    }

    // rskj Bridge.parseData: 1-3 byte data or an unknown selector is a parse
    // failure. Before RSKIP88 (orchid) execute() returns null — the tx
    // SUCCEEDS, charged the flat releaseBtc cost without executing anything
    // (mainnet #648,914 sent ASCII text as calldata). Afterwards it throws.
    let parsed = if input.len() < 4 {
        None
    } else {
        find_bridge_method(&[input[0], input[1], input[2], input[3]])
    };
    let Some(method) = parsed else {
        let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
        if !hardfork_cfg.has_rskip88(block_number) {
            let gas_cost = 23_000u64; // BridgeMethods.RELEASE_BTC cost, no data cost
            if gas_limit < gas_cost {
                return Err(PrecompileError::OutOfGas);
            }
            return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
        }
        return Err(PrecompileError::other("Bridge: invalid calldata"));
    };

    let args = &input[4..];
    let gas_cost = bridge_call_gas_cost(ctx, input, config, hardfork_cfg)?;

    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }

    execute_method(ctx, method.name, args, gas_cost, config, block_store, use_v2, hardfork_cfg, tx_ctx)
}

/// rskj `Bridge.getGasForData` for a parsed call: functionCost plus
/// `data.length * 2` (23_000 flat for the empty-input releaseBtc form).
/// Free bridge transactions cost 0 — callers handle that case.
pub fn bridge_call_gas_cost<CTX: ContextTr>(
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
    let selector = [input[0], input[1], input[2], input[3]];
    let Some(method) = find_bridge_method(&selector) else {
        return Ok(23_000);
    };

    let args = &input[4..];
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();

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
fn btc_tx_confirmations_cost<CTX: ContextTr>(
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
fn execute_method<CTX: ContextTr>(
    ctx: &mut CTX,
    method_name: &str,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    _block_store: Option<&Arc<BlockStore>>,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {

    match method_name {
        // Phase 2: BTC header chain
        "receiveHeader" => btc_chain::receive_header(ctx, args, config, use_v2),
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
        "registerBtcTransaction" => peg::register_btc_transaction(ctx, args, gas_cost, config, hardfork_cfg),
        "registerFastBridgeBtcTransaction" => peg::register_fast_bridge_btc_transaction(ctx, args, gas_cost, config),

        // Phase 5: Peg-out
        "releaseBtc" => peg::release_btc(ctx, gas_cost, config, hardfork_cfg, tx_ctx),
        "updateCollections" => peg::update_collections(ctx, gas_cost, config, hardfork_cfg, tx_ctx),
        "addSignature" => peg::add_signature(ctx, args, gas_cost, config, hardfork_cfg),

        // Phase 6: Governance
        "createFederation" => governance::create_federation(ctx, gas_cost),
        "commitFederation" => governance::commit_federation(ctx, args, gas_cost),
        "rollbackFederation" => governance::rollback_federation(ctx, gas_cost),
        "addFederatorPublicKey" => governance::add_federator_public_key(ctx, args, gas_cost),
        "addFederatorPublicKeyMultikey" => governance::add_federator_public_key_multikey(ctx, args, gas_cost),
        "voteFeePerKbChange" => governance::vote_fee_per_kb_change(ctx, args, gas_cost, config, tx_ctx),
        "increaseLockingCap" => governance::increase_locking_cap(ctx, args, gas_cost),
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
        "getLockingCap" => getters::get_locking_cap(ctx, gas_cost),
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
    }

    #[test]
    fn known_selector_add_signature() {
        let m = find_bridge_method(&compute_selector("addSignature(bytes,bytes[],bytes)")).unwrap();
        assert_eq!(m.name, "addSignature");
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
