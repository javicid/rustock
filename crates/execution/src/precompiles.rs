/// RSK precompiled contracts for revm.
///
/// RSK extends Ethereum's standard precompiles (0x01–0x09) with its own
/// native contracts at higher addresses (0x01000006+). This module defines
/// all RSK precompile addresses, implements the RSK-specific ones, and
/// provides a builder that produces the complete `Precompiles` set for a
/// given block height.
///
/// ## Address Layout
///
/// | Range          | Type                | Examples                        |
/// |----------------|---------------------|---------------------------------|
/// | 0x01–0x05      | Ethereum (genesis)  | ECRecover, SHA256, Identity     |
/// | 0x06–0x08      | Ethereum (RSKIP137) | BN128 add/mul/pairing           |
/// | 0x09           | Ethereum (RSKIP153) | Blake2F                         |
/// | 0x01000006     | RSK (genesis)       | Bridge                          |
/// | 0x01000008     | RSK (genesis)       | REMASC                          |
/// | 0x01000009+    | RSK (various)       | HDWalletUtils, BlockHeader, etc |

use alloy_primitives::{Address, Bytes};
use revm::context::{Cfg, LocalContextTr};
use revm::context_interface::{ContextTr, JournalTr};
use revm::handler::PrecompileProvider;
use revm::interpreter::{CallInput, CallInputs, Gas, InstructionResult, InterpreterResult};
use revm::precompile::{
    Precompile, PrecompileId, PrecompileOutput, PrecompileError, Precompiles,
    PrecompileSpecId,
};
use revm::primitives::hardfork::SpecId;

use crate::hardfork::{RskHardforkConfig, RskNetworkUpgrade};

// ---------------------------------------------------------------------------
// RSK-specific precompile addresses
// ---------------------------------------------------------------------------

pub const BRIDGE_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000006"));

pub const REMASC_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000008"));

pub const HD_WALLET_UTILS_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000009"));

pub const BLOCK_HEADER_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000010"));

pub const ENVIRONMENT_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000011"));

pub const SECP256K1_ADD_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000016"));

pub const SECP256K1_MUL_ADDR: Address =
    Address::new(hex_addr("0000000000000000000000000000000001000017"));

/// Returns all RSK precompile addresses (including standard Ethereum ones).
pub fn all_rsk_precompile_addresses() -> Vec<Address> {
    vec![
        BRIDGE_ADDR,
        REMASC_ADDR,
        HD_WALLET_UTILS_ADDR,
        BLOCK_HEADER_ADDR,
        ENVIRONMENT_ADDR,
        SECP256K1_ADD_ADDR,
        SECP256K1_MUL_ADDR,
    ]
}

// ---------------------------------------------------------------------------
// RSK precompile implementations
// ---------------------------------------------------------------------------

/// REMASC: Reward Manager Smart Contract.
/// Called as the last transaction in every block to distribute miner fees.
/// Gas cost: 0 (free). Returns empty output on success.
fn remasc_run(_input: &[u8], _gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    Ok(PrecompileOutput::new(0, Vec::new().into()))
}

/// Bridge: BTC–RSK two-way peg bridge.
/// Full implementation is complex (~60 methods). For now, returns empty output
/// and charges a minimal gas cost. Will be fully implemented in a later phase.
fn bridge_run(_input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 10_000u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    Ok(PrecompileOutput::new(gas_cost, Vec::new().into()))
}

/// HDWalletUtils: BIP32/BIP44 wallet operations.
/// Stub — returns empty with base gas cost.
fn hd_wallet_utils_run(_input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 13_000u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    Ok(PrecompileOutput::new(gas_cost, Vec::new().into()))
}

/// BlockHeaderContract: exposes block header fields to smart contracts.
/// Stub — returns empty with base gas cost.
fn block_header_run(input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 4_000u64 + 2 * input.len() as u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    Ok(PrecompileOutput::new(gas_cost, Vec::new().into()))
}

/// Environment: provides call stack depth.
/// Gas cost: 0.
fn environment_run(_input: &[u8], _gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    Ok(PrecompileOutput::new(0, Vec::new().into()))
}

/// Secp256k1 point addition.
/// Input: up to 128 bytes = [x1(32) | y1(32) | x2(32) | y2(32)], big-endian.
/// Output: 64 bytes = [x(32) | y(32)].
/// (0,0) represents the point at infinity.
/// Gas cost: 150.
fn secp256k1_add_run(input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 150u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    let p1 = parse_secp256k1_point(input, 0)?;
    let p2 = parse_secp256k1_point(input, 64)?;
    let result = p1 + p2;
    Ok(PrecompileOutput::new(gas_cost, encode_secp256k1_point(result).into()))
}

/// Secp256k1 scalar multiplication.
/// Input: up to 96 bytes = [x(32) | y(32) | scalar(32)], big-endian.
/// Output: 64 bytes = [x(32) | y(32)].
/// Gas cost: 3000.
fn secp256k1_mul_run(input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 3_000u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    let point = parse_secp256k1_point(input, 0)?;
    let scalar = parse_word(input, 64);
    let k = <k256::Scalar as k256::elliptic_curve::ops::Reduce<k256::U256>>::reduce(
        k256::U256::from_be_slice(&scalar),
    );
    let result = point * k;
    Ok(PrecompileOutput::new(gas_cost, encode_secp256k1_point(result).into()))
}

/// Read a 32-byte big-endian word from `data` at `offset`, zero-padding
/// if the data is shorter than `offset + 32`.
fn parse_word(data: &[u8], offset: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    if offset < data.len() {
        let end = std::cmp::min(offset + 32, data.len());
        let len = end - offset;
        word[32 - len..].copy_from_slice(&data[offset..end]);
    }
    word
}

/// Parse a secp256k1 affine point from two consecutive 32-byte words at `offset`.
/// (0,0) is treated as the point at infinity.
fn parse_secp256k1_point(
    data: &[u8],
    offset: usize,
) -> Result<k256::ProjectivePoint, PrecompileError> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;

    let x_bytes = parse_word(data, offset);
    let y_bytes = parse_word(data, offset + 32);

    let is_zero = x_bytes.iter().all(|&b| b == 0) && y_bytes.iter().all(|&b| b == 0);
    if is_zero {
        return Ok(k256::ProjectivePoint::IDENTITY);
    }

    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&x_bytes);
    uncompressed[33..65].copy_from_slice(&y_bytes);

    let encoded = k256::EncodedPoint::from_bytes(&uncompressed)
        .map_err(|_| PrecompileError::other("invalid secp256k1 point encoding"))?;

    let affine = k256::AffinePoint::from_encoded_point(&encoded);
    if affine.is_none().into() {
        return Err(PrecompileError::other("point not on secp256k1 curve"));
    }
    Ok(k256::ProjectivePoint::from(affine.unwrap()))
}

/// Encode a projective point as 64 bytes [x(32) | y(32)].
/// The identity (point at infinity) encodes as all zeros.
fn encode_secp256k1_point(point: k256::ProjectivePoint) -> Vec<u8> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let affine = k256::AffinePoint::from(point);
    let encoded = affine.to_encoded_point(false);

    if encoded.is_identity() {
        return vec![0u8; 64];
    }

    let mut out = vec![0u8; 64];
    let x = encoded.x().expect("non-identity point has x");
    let y = encoded.y().expect("non-identity point has y");
    out[..32].copy_from_slice(x);
    out[32..].copy_from_slice(y);
    out
}

// ---------------------------------------------------------------------------
// Precompile set builder
// ---------------------------------------------------------------------------

/// Builds the complete revm `Precompiles` set for an RSK block.
///
/// Starts with the Ethereum precompiles matching the block's SpecId,
/// then adds RSK-specific precompiles gated by their activation RSKIPs.
pub fn rsk_precompiles(hardfork_cfg: &RskHardforkConfig, block_number: u64) -> Precompiles {
    let spec_id = hardfork_cfg.spec_id(block_number);
    let precompile_spec = spec_id_to_precompile_spec(spec_id);

    let mut precompiles = Precompiles::new(precompile_spec).clone();

    let upgrade = hardfork_cfg.active_upgrade(block_number);

    // Genesis precompiles: Bridge, REMASC (always active)
    precompiles.extend([
        Precompile::new(
            PrecompileId::custom("rsk-remasc"),
            REMASC_ADDR,
            remasc_run,
        ),
        Precompile::new(
            PrecompileId::custom("rsk-bridge"),
            BRIDGE_ADDR,
            bridge_run,
        ),
    ]);

    // RSKIP106 (Orchid): HDWalletUtils
    if upgrade >= RskNetworkUpgrade::Orchid {
        precompiles.extend([
            Precompile::new(
                PrecompileId::custom("rsk-hdwallet"),
                HD_WALLET_UTILS_ADDR,
                hd_wallet_utils_run,
            ),
        ]);
    }

    // RSKIP119 (Wasabi100): BlockHeaderContract
    if upgrade >= RskNetworkUpgrade::Wasabi100 {
        precompiles.extend([
            Precompile::new(
                PrecompileId::custom("rsk-blockheader"),
                BLOCK_HEADER_ADDR,
                block_header_run,
            ),
        ]);
    }

    // RSKIP203 (Iris300): Environment
    if upgrade >= RskNetworkUpgrade::Iris300 {
        precompiles.extend([
            Precompile::new(
                PrecompileId::custom("rsk-environment"),
                ENVIRONMENT_ADDR,
                environment_run,
            ),
        ]);
    }

    // RSKIP516 (Reed800): Secp256k1 Addition/Multiplication
    if upgrade >= RskNetworkUpgrade::Reed800 {
        precompiles.extend([
            Precompile::new(
                PrecompileId::custom("rsk-secp256k1-add"),
                SECP256K1_ADD_ADDR,
                secp256k1_add_run,
            ),
            Precompile::new(
                PrecompileId::custom("rsk-secp256k1-mul"),
                SECP256K1_MUL_ADDR,
                secp256k1_mul_run,
            ),
        ]);
    }

    precompiles
}

// ---------------------------------------------------------------------------
// PrecompileProvider implementation for revm integration
// ---------------------------------------------------------------------------

/// Wraps an owned `Precompiles` set to implement revm's `PrecompileProvider`.
///
/// Unlike `EthPrecompiles` which holds a `&'static Precompiles`, this owns the
/// set because RSK precompiles are dynamically built per-block based on which
/// RSKIPs are active.
#[derive(Debug)]
pub struct RskPrecompileProvider {
    precompiles: Precompiles,
    hardfork_cfg: RskHardforkConfig,
    spec: SpecId,
}

/// Addresses handled via the stateful dispatch path (have access to &mut CTX).
const STATEFUL_PRECOMPILES: [Address; 3] = [ENVIRONMENT_ADDR, BLOCK_HEADER_ADDR, REMASC_ADDR];

impl RskPrecompileProvider {
    pub fn new(precompiles: Precompiles, hardfork_cfg: &RskHardforkConfig) -> Self {
        Self {
            precompiles,
            hardfork_cfg: hardfork_cfg.clone(),
            spec: SpecId::default(),
        }
    }

    /// Dispatch stateful RSK precompiles that need access to the execution context.
    ///
    /// Returns `Ok(Some(result))` if the address was handled, `Ok(None)` to
    /// fall through to the generic (pure-function) precompile path.
    fn run_stateful<CTX: ContextTr>(
        &self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        let addr = &inputs.bytecode_address;

        if !STATEFUL_PRECOMPILES.contains(addr) {
            return Ok(None);
        }

        // Copy input to owned bytes so we can pass &mut CTX to the handler
        // without conflicting with the SharedBuffer borrow.
        let input_bytes: Vec<u8> = match &inputs.input {
            CallInput::SharedBuffer(range) => {
                if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                    slice.as_ref().to_vec()
                } else {
                    Vec::new()
                }
            }
            CallInput::Bytes(bytes) => bytes.to_vec(),
        };

        let exec_result = if *addr == ENVIRONMENT_ADDR {
            self.run_environment(context, &input_bytes, inputs.gas_limit)
        } else if *addr == BLOCK_HEADER_ADDR {
            self.run_block_header(context, &input_bytes, inputs.gas_limit)
        } else {
            self.run_remasc(context, &input_bytes, inputs.gas_limit)
        };

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas: Gas::new(inputs.gas_limit),
            output: Bytes::new(),
        };

        match exec_result {
            Ok(output) => {
                result.gas.record_refund(output.gas_refunded);
                let underflow = result.gas.record_cost(output.gas_used);
                assert!(underflow, "Gas underflow is not possible");
                result.result = if output.reverted {
                    InstructionResult::Revert
                } else {
                    InstructionResult::Return
                };
                result.output = output.bytes;
            }
            Err(PrecompileError::Fatal(e)) => return Err(e),
            Err(e) => {
                result.result = if e.is_oog() {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
                if !e.is_oog() && context.journal().depth() == 1 {
                    context
                        .local_mut()
                        .set_precompile_error_context(e.to_string());
                }
            }
        }

        Ok(Some(result))
    }

    /// Environment precompile (0x01000011).
    /// Single method: `getCallStackDepth()` → returns the current call depth.
    /// Gas: 0.
    ///
    /// The depth value matches rskj's `programInvoke.getCallDeep() + 1`:
    /// in revm, `journal().depth()` already includes the precompile's own
    /// call frame, so no adjustment is needed.
    fn run_environment<CTX: ContextTr>(
        &self,
        context: &mut CTX,
        input: &[u8],
        _gas_limit: u64,
    ) -> Result<PrecompileOutput, PrecompileError> {
        // keccak256("getCallStackDepth()")[0:4]
        const GET_CALL_STACK_DEPTH: [u8; 4] = [0xe8, 0xce, 0x22, 0x74];

        if input.len() < 4 {
            return Err(PrecompileError::other(
                "Environment: input too short for method selector",
            ));
        }

        if input[..4] != GET_CALL_STACK_DEPTH {
            return Err(PrecompileError::other(
                "Environment: unknown method selector",
            ));
        }

        let depth = context.journal().depth() as u32;

        // ABI-encode as uint32 (32-byte left-padded big-endian)
        let mut output = vec![0u8; 32];
        output[28..32].copy_from_slice(&depth.to_be_bytes());

        Ok(PrecompileOutput::new(0, output.into()))
    }

    /// BlockHeaderContract precompile (0x01000010).
    /// Exposes block header fields via ABI method dispatch. Gas: 4000 + 2*input.len().
    /// Stub — actual implementation in Stage 4 will use block store lookups.
    fn run_block_header<CTX: ContextTr>(
        &self,
        _context: &mut CTX,
        input: &[u8],
        gas_limit: u64,
    ) -> Result<PrecompileOutput, PrecompileError> {
        let gas_cost = 4_000u64 + 2 * input.len() as u64;
        if gas_limit < gas_cost {
            return Err(PrecompileError::OutOfGas);
        }
        Ok(PrecompileOutput::new(gas_cost, Vec::new().into()))
    }

    /// REMASC precompile (0x01000008).
    /// Distributes miner fees with delayed maturity. Gas: 0.
    /// Stub — actual implementation in Stage 6 will use journal storage.
    fn run_remasc<CTX: ContextTr>(
        &self,
        _context: &mut CTX,
        _input: &[u8],
        _gas_limit: u64,
    ) -> Result<PrecompileOutput, PrecompileError> {
        Ok(PrecompileOutput::new(0, Vec::new().into()))
    }
}

impl Clone for RskPrecompileProvider {
    fn clone(&self) -> Self {
        Self {
            precompiles: self.precompiles.clone(),
            hardfork_cfg: self.hardfork_cfg.clone(),
            spec: self.spec,
        }
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for RskPrecompileProvider {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let spec: SpecId = spec.into();
        if spec == self.spec {
            return false;
        }
        self.spec = spec;
        true
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        // Stateful RSK precompiles are intercepted first — they need &mut CTX
        // for journal depth, block store lookups, or storage access.
        if let Some(result) = self.run_stateful(context, inputs)? {
            return Ok(Some(result));
        }

        let Some(precompile) = self.precompiles.get(&inputs.bytecode_address) else {
            return Ok(None);
        };

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas: Gas::new(inputs.gas_limit),
            output: Bytes::new(),
        };

        let exec_result = {
            let r;
            let input_bytes = match &inputs.input {
                CallInput::SharedBuffer(range) => {
                    if let Some(slice) = context.local().shared_memory_buffer_slice(range.clone()) {
                        r = slice;
                        r.as_ref()
                    } else {
                        &[]
                    }
                }
                CallInput::Bytes(bytes) => bytes.0.iter().as_slice(),
            };
            precompile.execute(input_bytes, inputs.gas_limit)
        };

        match exec_result {
            Ok(output) => {
                result.gas.record_refund(output.gas_refunded);
                let underflow = result.gas.record_cost(output.gas_used);
                assert!(underflow, "Gas underflow is not possible");
                result.result = if output.reverted {
                    InstructionResult::Revert
                } else {
                    InstructionResult::Return
                };
                result.output = output.bytes;
            }
            Err(PrecompileError::Fatal(e)) => return Err(e),
            Err(e) => {
                result.result = if e.is_oog() {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
                if !e.is_oog() && context.journal().depth() == 1 {
                    context
                        .local_mut()
                        .set_precompile_error_context(e.to_string());
                }
            }
        }
        Ok(Some(result))
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        Box::new(self.precompiles.addresses().cloned())
    }

    fn contains(&self, address: &Address) -> bool {
        self.precompiles.contains(address)
    }
}

fn spec_id_to_precompile_spec(spec_id: SpecId) -> PrecompileSpecId {
    match spec_id {
        SpecId::FRONTIER | SpecId::FRONTIER_THAWING | SpecId::HOMESTEAD
        | SpecId::DAO_FORK | SpecId::TANGERINE | SpecId::SPURIOUS_DRAGON => {
            PrecompileSpecId::HOMESTEAD
        }
        SpecId::BYZANTIUM | SpecId::CONSTANTINOPLE | SpecId::PETERSBURG => {
            PrecompileSpecId::BYZANTIUM
        }
        SpecId::ISTANBUL | SpecId::MUIR_GLACIER => PrecompileSpecId::ISTANBUL,
        SpecId::BERLIN | SpecId::LONDON | SpecId::ARROW_GLACIER
        | SpecId::GRAY_GLACIER | SpecId::MERGE => PrecompileSpecId::BERLIN,
        SpecId::SHANGHAI | SpecId::CANCUN => PrecompileSpecId::CANCUN,
        _ => PrecompileSpecId::CANCUN,
    }
}

/// Helper to check if an address is an RSK precompile at a given block.
pub fn is_rsk_precompile(
    address: &Address,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> bool {
    let precompiles = rsk_precompiles(hardfork_cfg, block_number);
    precompiles.contains(address)
}

// ---------------------------------------------------------------------------
// Compile-time hex address helper
// ---------------------------------------------------------------------------

const fn hex_addr(hex: &str) -> [u8; 20] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 40, "hex address must be 40 chars");
    let mut result = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        result[i] = (hex_val(bytes[i * 2]) << 4) | hex_val(bytes[i * 2 + 1]);
        i += 1;
    }
    result
}

const fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex char"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remasc_address() {
        assert_eq!(
            format!("{:x}", REMASC_ADDR),
            "0000000000000000000000000000000001000008"
        );
    }

    #[test]
    fn test_bridge_address() {
        assert_eq!(
            format!("{:x}", BRIDGE_ADDR),
            "0000000000000000000000000000000001000006"
        );
    }

    #[test]
    fn test_genesis_precompiles_always_present() {
        let cfg = RskHardforkConfig::mainnet();
        let precompiles = rsk_precompiles(&cfg, 0);

        assert!(precompiles.contains(&REMASC_ADDR));
        assert!(precompiles.contains(&BRIDGE_ADDR));

        // Standard Ethereum precompiles should also be present
        let ecrecover = Address::new(hex_addr("0000000000000000000000000000000000000001"));
        assert!(precompiles.contains(&ecrecover));
    }

    #[test]
    fn test_hdwallet_not_active_before_orchid() {
        let cfg = RskHardforkConfig::mainnet();
        let precompiles = rsk_precompiles(&cfg, 0);
        assert!(!precompiles.contains(&HD_WALLET_UTILS_ADDR));
    }

    #[test]
    fn test_hdwallet_active_after_orchid() {
        let cfg = RskHardforkConfig::mainnet();
        let precompiles = rsk_precompiles(&cfg, 729_000);
        assert!(precompiles.contains(&HD_WALLET_UTILS_ADDR));
    }

    #[test]
    fn test_blockheader_active_after_wasabi() {
        let cfg = RskHardforkConfig::mainnet();

        let pre = rsk_precompiles(&cfg, 1_590_999);
        assert!(!pre.contains(&BLOCK_HEADER_ADDR));

        let post = rsk_precompiles(&cfg, 1_591_000);
        assert!(post.contains(&BLOCK_HEADER_ADDR));
    }

    #[test]
    fn test_environment_active_after_iris() {
        let cfg = RskHardforkConfig::mainnet();

        let pre = rsk_precompiles(&cfg, 3_614_799);
        assert!(!pre.contains(&ENVIRONMENT_ADDR));

        let post = rsk_precompiles(&cfg, 3_614_800);
        assert!(post.contains(&ENVIRONMENT_ADDR));
    }

    #[test]
    fn test_secp256k1_active_after_reed() {
        let cfg = RskHardforkConfig::mainnet();

        let pre = rsk_precompiles(&cfg, 8_052_199);
        assert!(!pre.contains(&SECP256K1_ADD_ADDR));
        assert!(!pre.contains(&SECP256K1_MUL_ADDR));

        let post = rsk_precompiles(&cfg, 8_052_200);
        assert!(post.contains(&SECP256K1_ADD_ADDR));
        assert!(post.contains(&SECP256K1_MUL_ADDR));
    }

    #[test]
    fn test_all_active_has_everything() {
        let cfg = RskHardforkConfig::all_active(33);
        let precompiles = rsk_precompiles(&cfg, 0);

        assert!(precompiles.contains(&REMASC_ADDR));
        assert!(precompiles.contains(&BRIDGE_ADDR));
        assert!(precompiles.contains(&HD_WALLET_UTILS_ADDR));
        assert!(precompiles.contains(&BLOCK_HEADER_ADDR));
        assert!(precompiles.contains(&ENVIRONMENT_ADDR));
        assert!(precompiles.contains(&SECP256K1_ADD_ADDR));
        assert!(precompiles.contains(&SECP256K1_MUL_ADDR));
    }

    #[test]
    fn test_remasc_zero_gas() {
        let result = remasc_run(&[], 0).unwrap();
        assert_eq!(result.gas_used, 0);
        assert!(result.bytes.is_empty());
    }

    #[test]
    fn test_bridge_charges_gas() {
        let result = bridge_run(&[], 100_000).unwrap();
        assert_eq!(result.gas_used, 10_000);

        let oog = bridge_run(&[], 5_000);
        assert!(matches!(oog, Err(PrecompileError::OutOfGas)));
    }

    #[test]
    fn test_block_header_gas_scales_with_input() {
        let result = block_header_run(&[0u8; 100], 100_000).unwrap();
        assert_eq!(result.gas_used, 4_000 + 200); // 4000 + 2*100
    }

    #[test]
    fn test_secp256k1_gas_costs() {
        let add = secp256k1_add_run(&[], 1_000).unwrap();
        assert_eq!(add.gas_used, 150);

        let mul = secp256k1_mul_run(&[], 10_000).unwrap();
        assert_eq!(mul.gas_used, 3_000);
    }

    // -----------------------------------------------------------------------
    // Secp256k1 add/mul tests ported from rskj Secp256k1ServiceTest.java
    // -----------------------------------------------------------------------

    const V1Y: &str =
        "29896722852569046015560700294576055776214335159245303116488692907525646231534";
    const V1BY2X: &str =
        "90462569716653277674664832038037428010367175520031690655826237506178777087235";
    const V1BY2Y: &str =
        "30122570767565969031174451675354718271714177419582540229636601003470726681395";
    const V1BY9X: &str =
        "46171929588085016379679198610744759757996296651373714437564035753833216770329";
    const V1BY9Y: &str =
        "4076329532618667641907419885981677362511359868272295070859229146922980867493";
    const SECP256K1_P: &str =
        "115792089237316195423570985008687907853269984665640564039457584007908834671663";

    fn decimal_to_32bytes(s: &str) -> [u8; 32] {
        alloy_primitives::U256::from_str_radix(s, 10)
            .expect("valid decimal")
            .to_be_bytes::<32>()
    }

    fn build_add_input(x1: &str, y1: &str, x2: &str, y2: &str) -> Vec<u8> {
        let mut input = vec![0u8; 128];
        input[..32].copy_from_slice(&decimal_to_32bytes(x1));
        input[32..64].copy_from_slice(&decimal_to_32bytes(y1));
        input[64..96].copy_from_slice(&decimal_to_32bytes(x2));
        input[96..128].copy_from_slice(&decimal_to_32bytes(y2));
        input
    }

    fn build_mul_input(x: &str, y: &str, scalar: &str) -> Vec<u8> {
        let mut input = vec![0u8; 96];
        input[..32].copy_from_slice(&decimal_to_32bytes(x));
        input[32..64].copy_from_slice(&decimal_to_32bytes(y));
        input[64..96].copy_from_slice(&decimal_to_32bytes(scalar));
        input
    }

    fn build_output(x: &str, y: &str) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        out[..32].copy_from_slice(&decimal_to_32bytes(x));
        out[32..64].copy_from_slice(&decimal_to_32bytes(y));
        out
    }

    fn negate_field(y: &str) -> String {
        let p = alloy_primitives::U256::from_str_radix(SECP256K1_P, 10).unwrap();
        let val = alloy_primitives::U256::from_str_radix(y, 10).unwrap();
        (p - val).to_string()
    }

    // --- Addition tests ---

    #[test]
    fn test_secp_add_two_identical_points() {
        let input = build_add_input("1", V1Y, "1", V1Y);
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        let expected = build_output(V1BY2X, V1BY2Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_add_zero_points_is_zero() {
        let input = vec![0u8; 128];
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        assert_eq!(result.bytes.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_secp_add_empty_input_is_zero() {
        let result = secp256k1_add_run(&[], 1_000).unwrap();
        assert_eq!(result.bytes.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_secp_add_point_plus_infinity_is_point() {
        let input = build_add_input("1", V1Y, "0", "0");
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        let expected = build_output("1", V1Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_add_infinity_plus_point_is_point() {
        let input = build_add_input("0", "0", "1", V1Y);
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        let expected = build_output("1", V1Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_add_point_not_on_curve_fails() {
        let bad = decimal_to_32bytes(
            "7711111111111111111111111111111111111111111111111111111111111111",
        );
        let mut input = vec![0u8; 128];
        input[..32].copy_from_slice(&bad);
        input[32..64].copy_from_slice(&bad);
        input[64..96].copy_from_slice(&bad);
        input[96..128].copy_from_slice(&bad);
        assert!(secp256k1_add_run(&input, 1_000).is_err());
    }

    #[test]
    fn test_secp_add_inverse_points_is_infinity() {
        let y_str = "21320899557911560362763253855565071047772010424612278905734793689199612115787";
        let neg_y = negate_field(y_str);
        let input = build_add_input("3", y_str, "3", &neg_y);
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        assert_eq!(result.bytes.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_secp_add_two_valid_points() {
        let input = build_add_input(
            "4",
            "40508090799132825824753983223610497876805216745196355809233758402754120847507",
            "1624070059937464756887933993293429854168590106605707304006200119738501412969",
            "48810817106871756219742442189260392858217846784043974224646271552914041676099",
        );
        let result = secp256k1_add_run(&input, 1_000).unwrap();
        let expected = build_output(
            "59470963110652214182270290319243047549711080187995156844066669631124720856270",
            "75549874947483386113764723043915448105868538368156141886808196158351727282824",
        );
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_add_gas_constant_regardless_of_input_length() {
        let r1 = secp256k1_add_run(&[], 1_000).unwrap();
        let r2 = secp256k1_add_run(&[0u8; 64], 1_000).unwrap();
        let r3 = secp256k1_add_run(&[0u8; 128], 1_000).unwrap();
        assert_eq!(r1.gas_used, 150);
        assert_eq!(r2.gas_used, 150);
        assert_eq!(r3.gas_used, 150);
    }

    #[test]
    fn test_secp_add_oog() {
        assert!(matches!(
            secp256k1_add_run(&[], 100),
            Err(PrecompileError::OutOfGas)
        ));
    }

    #[test]
    fn test_secp_add_zero_padded_32_bytes_is_zero() {
        let result = secp256k1_add_run(&[0u8; 32], 1_000).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secp_add_zero_padded_64_bytes_is_zero() {
        let result = secp256k1_add_run(&[0u8; 64], 1_000).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.bytes.iter().all(|&b| b == 0));
    }

    // --- Multiplication tests ---

    #[test]
    fn test_secp_mul_scalar_and_point() {
        let input = build_mul_input(
            "1",
            V1Y,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        );
        let result = secp256k1_mul_run(&input, 10_000).unwrap();
        let expected = build_output(
            "68306631035792818416930554521980007078198693994042647901813352646899028694565",
            "763410389832780290161227297165449309800016629866253823160953352172730927280",
        );
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_mul_identity_when_multiplied_by_one() {
        let input = build_mul_input("1", V1Y, "1");
        let result = secp256k1_mul_run(&input, 10_000).unwrap();
        let expected = build_output("1", V1Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_mul_point_by_scalar_9() {
        let input = build_mul_input("1", V1Y, "9");
        let result = secp256k1_mul_run(&input, 10_000).unwrap();
        let expected = build_output(V1BY9X, V1BY9Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_mul_point_by_scalar_2() {
        let input = build_mul_input("1", V1Y, "2");
        let result = secp256k1_mul_run(&input, 10_000).unwrap();
        let expected = build_output(V1BY2X, V1BY2Y);
        assert_eq!(result.bytes.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_secp_mul_point_not_on_curve_fails() {
        let bad = decimal_to_32bytes(
            "7711111111111111111111111111111111111111111111111111111111111111",
        );
        let mut input = vec![0u8; 96];
        input[..32].copy_from_slice(&bad);
        input[32..64].copy_from_slice(&bad);
        input[64..96].copy_from_slice(&bad);
        assert!(secp256k1_mul_run(&input, 10_000).is_err());
    }

    #[test]
    fn test_secp_mul_empty_input_is_zero() {
        let result = secp256k1_mul_run(&[], 10_000).unwrap();
        assert_eq!(result.bytes.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_secp_mul_gas_constant_regardless_of_input_length() {
        let r1 = secp256k1_mul_run(&[], 10_000).unwrap();
        let r2 = secp256k1_mul_run(&[0u8; 64], 10_000).unwrap();
        let r3 = secp256k1_mul_run(&[0u8; 96], 10_000).unwrap();
        assert_eq!(r1.gas_used, 3_000);
        assert_eq!(r2.gas_used, 3_000);
        assert_eq!(r3.gas_used, 3_000);
    }

    #[test]
    fn test_secp_mul_oog() {
        assert!(matches!(
            secp256k1_mul_run(&[], 2_000),
            Err(PrecompileError::OutOfGas)
        ));
    }

    #[test]
    fn test_secp_mul_zero_padded_32_bytes_is_zero() {
        let result = secp256k1_mul_run(&[0u8; 32], 10_000).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secp_mul_zero_padded_64_bytes_is_zero() {
        let result = secp256k1_mul_run(&[0u8; 64], 10_000).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_precompile_count_at_genesis() {
        let cfg = RskHardforkConfig::mainnet();
        let precompiles = rsk_precompiles(&cfg, 0);

        // Standard Ethereum (Byzantium): 0x01-0x08 = 8
        // RSK genesis: Bridge, REMASC = 2
        // Total = 10
        // Note: exact count depends on revm's Byzantium set
        assert!(precompiles.len() >= 6, "should have at least 6 precompiles at genesis");
    }

    #[test]
    fn test_is_rsk_precompile() {
        let cfg = RskHardforkConfig::all_active(33);
        assert!(is_rsk_precompile(&REMASC_ADDR, &cfg, 0));
        assert!(is_rsk_precompile(&BRIDGE_ADDR, &cfg, 0));
        assert!(!is_rsk_precompile(&Address::repeat_byte(0xFF), &cfg, 0));
    }

    // -----------------------------------------------------------------------
    // Stateful dispatch infrastructure tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stateful_precompiles_list() {
        assert!(STATEFUL_PRECOMPILES.contains(&ENVIRONMENT_ADDR));
        assert!(STATEFUL_PRECOMPILES.contains(&BLOCK_HEADER_ADDR));
        assert!(STATEFUL_PRECOMPILES.contains(&REMASC_ADDR));
        assert!(!STATEFUL_PRECOMPILES.contains(&BRIDGE_ADDR));
        assert!(!STATEFUL_PRECOMPILES.contains(&SECP256K1_ADD_ADDR));
    }

    #[test]
    fn test_stateful_addresses_still_in_precompile_set() {
        let cfg = RskHardforkConfig::all_active(33);
        let precompiles = rsk_precompiles(&cfg, 0);

        assert!(precompiles.contains(&ENVIRONMENT_ADDR));
        assert!(precompiles.contains(&BLOCK_HEADER_ADDR));
        assert!(precompiles.contains(&REMASC_ADDR));
    }

    #[test]
    fn test_provider_contains_stateful_addresses() {
        let cfg = RskHardforkConfig::all_active(33);
        let precompiles = rsk_precompiles(&cfg, 0);
        let provider = RskPrecompileProvider::new(precompiles, &cfg);

        assert!(provider.precompiles.contains(&ENVIRONMENT_ADDR));
        assert!(provider.precompiles.contains(&BLOCK_HEADER_ADDR));
        assert!(provider.precompiles.contains(&REMASC_ADDR));
        assert!(provider.precompiles.contains(&BRIDGE_ADDR));
        assert!(provider.precompiles.contains(&SECP256K1_ADD_ADDR));
    }

    // -----------------------------------------------------------------------
    // Environment precompile tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_environment_selector_is_keccak256() {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(b"getCallStackDepth()");
        assert_eq!(
            &hash[..4],
            &[0xe8, 0xce, 0x22, 0x74],
            "selector should be keccak256('getCallStackDepth()')[0:4]"
        );
    }
}
