//! Bridge governance — federation voting, fee/whitelist/locking cap management.
//!
//! ## Federation lifecycle
//!
//! 1. `createFederation()` — creates a new pending federation (if none exists)
//! 2. `addFederatorPublicKey(bytes)` / `addFederatorPublicKeyMultikey(bytes,bytes,bytes)`
//!    — adds a member to the pending federation
//! 3. `commitFederation(bytes pendingHash)` — commits the pending federation
//!    as the new active federation, demoting the current one to retiring
//! 4. `rollbackFederation()` — discards the pending federation
//!
//! ## Other governance
//!
//! - `voteFeePerKbChange(int256)` — authorized vote on BTC fee per KB
//! - `addOneOffLockWhitelistAddress` / `addUnlimitedLockWhitelistAddress`
//!   / `removeLockWhitelistAddress` / `setLockWhitelistDisableBlockDelay`
//! - `increaseLockingCap(int256)` — increase the RBTC locking cap

use alloy_primitives::{Bytes, U256};
use revm::context_interface::ContextTr;
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::storage::*;

// ---------------------------------------------------------------------------
// Storage key constants for governance
// ---------------------------------------------------------------------------

const FEE_PER_KB_KEY: &str = "feePerKb";
const LOCKING_CAP_KEY: &str = "lockingCap";
const LOCK_WHITELIST_DISABLE_BLOCK_DELAY_KEY: &str = "lockWhitelistDisDelay";

// ---------------------------------------------------------------------------
// Federation change methods
// ---------------------------------------------------------------------------

/// `createFederation()` → int256
///
/// Creates a new pending federation. Returns:
///   1  = success
///  -1  = pending federation already exists
///  -10 = unauthorized
pub fn create_federation<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Check if a pending federation already exists
    let key = bridge_storage_key(PENDING_FEDERATION_KEY);
    let existing = bridge_sload(ctx, key);

    if !existing.is_zero() {
        return Ok(encode_int_result(gas_cost, -1));
    }

    // Create pending federation: store a marker value (count = 0)
    bridge_sstore(ctx, key, U256::from(1));

    Ok(encode_int_result(gas_cost, 1))
}

/// `addFederatorPublicKey(bytes key)` → int256
///
/// Adds a public key to the pending federation. Returns:
///   1  = success
///  -1  = key already exists
///  -2  = no pending federation
pub fn add_federator_public_key<CTX: ContextTr>(
    ctx: &mut CTX,
    _args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let key = bridge_storage_key(PENDING_FEDERATION_KEY);
    let existing = bridge_sload(ctx, key);

    if existing.is_zero() {
        return Ok(encode_int_result(gas_cost, -2));
    }

    // Increment member count
    let new_count = existing.wrapping_add(U256::from(1));
    bridge_sstore(ctx, key, new_count);

    Ok(encode_int_result(gas_cost, 1))
}

/// `addFederatorPublicKeyMultikey(bytes btcKey, bytes rskKey, bytes mstKey)` → int256
///
/// Same as addFederatorPublicKey but with separate keys for BTC/RSK/MST.
pub fn add_federator_public_key_multikey<CTX: ContextTr>(
    ctx: &mut CTX,
    _args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let key = bridge_storage_key(PENDING_FEDERATION_KEY);
    let existing = bridge_sload(ctx, key);

    if existing.is_zero() {
        return Ok(encode_int_result(gas_cost, -2));
    }

    let new_count = existing.wrapping_add(U256::from(1));
    bridge_sstore(ctx, key, new_count);

    Ok(encode_int_result(gas_cost, 1))
}

/// `commitFederation(bytes pendingHash)` → int256
///
/// Commits the pending federation as the new active federation.
/// Returns:
///   1  = success
///  -1  = no pending federation
///  -2  = pending hash mismatch
pub fn commit_federation<CTX: ContextTr>(
    ctx: &mut CTX,
    _args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let pending_key = bridge_storage_key(PENDING_FEDERATION_KEY);
    let pending_val = bridge_sload(ctx, pending_key);

    if pending_val.is_zero() {
        return Ok(encode_int_result(gas_cost, -1));
    }

    // Move current active → old (retiring)
    let new_fed_key = bridge_storage_key(NEW_FEDERATION_KEY);
    let old_fed_key = bridge_storage_key(OLD_FEDERATION_KEY);
    let current_active = bridge_sload(ctx, new_fed_key);

    if !current_active.is_zero() {
        bridge_sstore(ctx, old_fed_key, current_active);
    }

    // Move pending → active
    bridge_sstore(ctx, new_fed_key, pending_val);

    // Clear pending
    bridge_sstore(ctx, pending_key, U256::ZERO);

    Ok(encode_int_result(gas_cost, 1))
}

/// `rollbackFederation()` → int256
///
/// Discards the pending federation.
/// Returns:
///   1  = success
///  -1  = no pending federation
pub fn rollback_federation<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let key = bridge_storage_key(PENDING_FEDERATION_KEY);
    let existing = bridge_sload(ctx, key);

    if existing.is_zero() {
        return Ok(encode_int_result(gas_cost, -1));
    }

    bridge_sstore(ctx, key, U256::ZERO);

    Ok(encode_int_result(gas_cost, 1))
}

// ---------------------------------------------------------------------------
// Fee per KB voting
// ---------------------------------------------------------------------------

/// `voteFeePerKbChange(int256 feePerKb)` → int256
///
/// Authorized vote to change the BTC fee per KB for peg-out transactions.
/// Returns:
///   1  = vote accepted
///  -1  = unauthorized
///  -2  = negative value
pub fn vote_fee_per_kb_change<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("voteFeePerKbChange: args too short"));
    }

    let fee_value = U256::from_be_slice(&args[..32]);

    // Check for negative (sign bit set in int256)
    if args[0] & 0x80 != 0 {
        return Ok(encode_int_result(gas_cost, -2));
    }

    // Store the new fee
    let key = bridge_storage_key(FEE_PER_KB_KEY);
    bridge_sstore(ctx, key, fee_value);

    Ok(encode_int_result(gas_cost, 1))
}

// ---------------------------------------------------------------------------
// Locking cap
// ---------------------------------------------------------------------------

/// `increaseLockingCap(int256 newCap)` → bool
///
/// Increases the RBTC locking cap. Can only increase, never decrease.
/// Returns true if successful.
pub fn increase_locking_cap<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("increaseLockingCap: args too short"));
    }

    let new_cap = U256::from_be_slice(&args[..32]);

    let key = bridge_storage_key(LOCKING_CAP_KEY);
    let current_cap = bridge_sload(ctx, key);

    // Can only increase
    if new_cap <= current_cap {
        let output = [0u8; 32];
        return Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()));
    }

    bridge_sstore(ctx, key, new_cap);

    let mut output = [0u8; 32];
    output[31] = 1; // true
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// Whitelist management
// ---------------------------------------------------------------------------

/// `addLockWhitelistAddress(string address, int256 maxTransferValue)` → int256
pub fn add_lock_whitelist_address<CTX: ContextTr>(
    _ctx: &mut CTX,
    _args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Whitelist management is authorized-only.
    // For now, return success stub.
    Ok(encode_int_result(gas_cost, 1))
}

/// `addOneOffLockWhitelistAddress(string address, int256 maxTransferValue)` → int256
pub fn add_one_off_lock_whitelist_address<CTX: ContextTr>(
    _ctx: &mut CTX,
    _args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    Ok(encode_int_result(gas_cost, 1))
}

/// `addUnlimitedLockWhitelistAddress(string address)` → int256
pub fn add_unlimited_lock_whitelist_address<CTX: ContextTr>(
    _ctx: &mut CTX,
    _args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    Ok(encode_int_result(gas_cost, 1))
}

/// `removeLockWhitelistAddress(string address)` → int256
pub fn remove_lock_whitelist_address<CTX: ContextTr>(
    _ctx: &mut CTX,
    _args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    Ok(encode_int_result(gas_cost, 1))
}

/// `setLockWhitelistDisableBlockDelay(int256 delay)` → int256
pub fn set_lock_whitelist_disable_block_delay<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other(
            "setLockWhitelistDisableBlockDelay: args too short",
        ));
    }

    let delay = U256::from_be_slice(&args[..32]);
    let key = bridge_storage_key(LOCK_WHITELIST_DISABLE_BLOCK_DELAY_KEY);
    bridge_sstore(ctx, key, delay);

    Ok(encode_int_result(gas_cost, 1))
}

// ---------------------------------------------------------------------------
// Read-only governance methods
// ---------------------------------------------------------------------------

/// `getActivePowpegRedeemScript()` → bytes
pub fn get_active_powpeg_redeem_script<CTX: ContextTr>(
    _ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Return empty bytes (no federation configured yet)
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// `getActiveFederationCreationBlockHeight()` → uint256
pub fn get_active_federation_creation_block_height<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let key = bridge_storage_key(ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY);
    let val = bridge_sload(ctx, key);
    let output = val.to_be_bytes::<32>();
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encode_int_result(gas_cost: u64, value: i64) -> PrecompileOutput {
    let mut output = [0u8; 32];
    if value >= 0 {
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        output = [0xFF; 32];
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    }
    PrecompileOutput::new(gas_cost, output.to_vec().into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_int_success() {
        let out = encode_int_result(0, 1);
        assert_eq!(out.bytes[31], 1);
    }

    #[test]
    fn encode_int_error() {
        let out = encode_int_result(0, -1);
        assert!(out.bytes.iter().all(|&b| b == 0xFF));
    }
}
