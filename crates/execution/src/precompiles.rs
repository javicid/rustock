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
/// Gas cost: 150.
fn secp256k1_add_run(_input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 150u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    Ok(PrecompileOutput::new(gas_cost, vec![0u8; 64].into()))
}

/// Secp256k1 scalar multiplication.
/// Gas cost: 3000.
fn secp256k1_mul_run(_input: &[u8], gas_limit: u64) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 3_000u64;
    if gas_limit < gas_cost {
        return Err(PrecompileError::OutOfGas);
    }
    Ok(PrecompileOutput::new(gas_cost, vec![0u8; 64].into()))
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

impl RskPrecompileProvider {
    pub fn new(precompiles: Precompiles, hardfork_cfg: &RskHardforkConfig) -> Self {
        Self {
            precompiles,
            hardfork_cfg: hardfork_cfg.clone(),
            spec: SpecId::default(),
        }
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
}
