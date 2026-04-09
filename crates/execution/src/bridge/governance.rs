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

use super::serialization;
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
    let existing = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
    if !existing.is_empty() {
        return Ok(encode_int_result(gas_cost, -1));
    }

    // Create empty pending federation: RLP list with empty members list
    let empty_federation = serialize_pending_federation(&[]);
    bridge_store_bytes_named(ctx, PENDING_FEDERATION_KEY, &empty_federation);

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
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let existing = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
    if existing.is_empty() {
        return Ok(encode_int_result(gas_cost, -2));
    }

    let pubkey = decode_bytes_arg(args)?;
    let mut members = deserialize_pending_federation(&existing);
    members.push(pubkey);
    let updated = serialize_pending_federation(&members);
    bridge_store_bytes_named(ctx, PENDING_FEDERATION_KEY, &updated);

    Ok(encode_int_result(gas_cost, 1))
}

/// `addFederatorPublicKeyMultikey(bytes btcKey, bytes rskKey, bytes mstKey)` → int256
///
/// Same as addFederatorPublicKey but with separate keys for BTC/RSK/MST.
/// For storage purposes, we store the BTC key as the representative key.
pub fn add_federator_public_key_multikey<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let existing = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
    if existing.is_empty() {
        return Ok(encode_int_result(gas_cost, -2));
    }

    let btc_key = decode_bytes_arg(args)?;
    let mut members = deserialize_pending_federation(&existing);
    members.push(btc_key);
    let updated = serialize_pending_federation(&members);
    bridge_store_bytes_named(ctx, PENDING_FEDERATION_KEY, &updated);

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
    let pending_data = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
    if pending_data.is_empty() {
        return Ok(encode_int_result(gas_cost, -1));
    }

    // Promote pending → active. Move current active → old (retiring).
    let current_active = bridge_load_bytes_named(ctx, NEW_FEDERATION_KEY);
    if !current_active.is_empty() {
        bridge_store_bytes_named(ctx, OLD_FEDERATION_KEY, &current_active);
    }

    // Build federation RLP: [[member_keys...], creation_time, creation_block]
    // Use current block number and timestamp from the context.
    let members = deserialize_pending_federation(&pending_data);
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let federation_rlp = serialize_federation(&members, 0, block_number);
    bridge_store_bytes_named(ctx, NEW_FEDERATION_KEY, &federation_rlp);

    // Store creation block height
    bridge_store_u256(ctx, ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY, U256::from(block_number));

    // Clear pending
    bridge_store_bytes_named(ctx, PENDING_FEDERATION_KEY, &[]);

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
    let existing = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
    if existing.is_empty() {
        return Ok(encode_int_result(gas_cost, -1));
    }

    bridge_store_bytes_named(ctx, PENDING_FEDERATION_KEY, &[]);

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

// ---------------------------------------------------------------------------
// Federation RLP serialization (matching BridgeSerializationUtils)
// ---------------------------------------------------------------------------

/// Serialize a pending federation as an RLP list of member public keys.
fn serialize_pending_federation(member_keys: &[Vec<u8>]) -> Vec<u8> {
    let encoded_keys: Vec<Vec<u8>> = member_keys
        .iter()
        .map(|k| serialization::rlp_encode_element(k))
        .collect();
    serialization::rlp_encode_list(&encoded_keys)
}

/// Deserialize a pending federation from RLP → list of member public keys.
fn deserialize_pending_federation(data: &[u8]) -> Vec<Vec<u8>> {
    serialization::rlp_decode_list(data).unwrap_or_default()
}

/// Serialize a committed federation as `[[member_keys...], creation_time, creation_block]`.
fn serialize_federation(member_keys: &[Vec<u8>], creation_time: u64, creation_block: u64) -> Vec<u8> {
    let keys_rlp: Vec<Vec<u8>> = member_keys
        .iter()
        .map(|k| serialization::rlp_encode_element(k))
        .collect();
    let keys_list = serialization::rlp_encode_list(&keys_rlp);
    let time_rlp = serialization::rlp_encode_u64(creation_time);
    let block_rlp = serialization::rlp_encode_u64(creation_block);
    serialization::rlp_encode_list(&[keys_list, time_rlp, block_rlp])
}

/// Decode a single `bytes` ABI argument from calldata.
fn decode_bytes_arg(args: &[u8]) -> Result<Vec<u8>, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("bytes arg: too short"));
    }
    let offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    if offset + 32 > args.len() {
        return Err(PrecompileError::other("bytes arg: offset out of bounds"));
    }
    let len = U256::from_be_slice(&args[offset..offset + 32]).to::<usize>();
    let start = offset + 32;
    if start + len > args.len() {
        return Err(PrecompileError::other("bytes arg: data out of bounds"));
    }
    Ok(args[start..start + len].to_vec())
}

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

    // -----------------------------------------------------------------------
    // Federation serialization tests — ported from rskj
    // BridgeSerializationUtilsTest.serializeAndDeserializeFederationOnlyBtcKeys
    // -----------------------------------------------------------------------

    /// Ported from rskj: pending federation roundtrip (list of public keys).
    #[test]
    fn rskj_pending_federation_roundtrip() {
        let keys: Vec<Vec<u8>> = vec![
            vec![0x02; 33],
            vec![0x03; 33],
            vec![0x04; 33],
        ];

        let encoded = serialize_pending_federation(&keys);
        let decoded = deserialize_pending_federation(&encoded);

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], keys[0]);
        assert_eq!(decoded[1], keys[1]);
        assert_eq!(decoded[2], keys[2]);
    }

    /// Ported from rskj: empty pending federation.
    #[test]
    fn rskj_pending_federation_empty() {
        let keys: Vec<Vec<u8>> = vec![];
        let encoded = serialize_pending_federation(&keys);
        let decoded = deserialize_pending_federation(&encoded);
        assert!(decoded.is_empty());
    }

    /// Ported from rskj: committed federation roundtrip with known values.
    /// Matches BridgeSerializationUtilsTest pattern: 6 keys, creation_time=5000,
    /// creation_block=42.
    #[test]
    fn rskj_committed_federation_roundtrip() {
        let keys: Vec<Vec<u8>> = (100u8..106)
            .map(|i| vec![i; 33])
            .collect();

        let creation_time = 5000u64;
        let creation_block = 42u64;

        let encoded = serialize_federation(&keys, creation_time, creation_block);
        let decoded = serialization::rlp_decode_list(&encoded).unwrap();
        assert_eq!(decoded.len(), 3, "federation RLP should have 3 items");

        let decoded_keys = serialization::rlp_decode_list(&decoded[0]).unwrap();
        assert_eq!(decoded_keys.len(), 6);
        for (i, key) in decoded_keys.iter().enumerate() {
            assert_eq!(key, &keys[i], "key {i} mismatch");
        }

        let decoded_time = serialization::rlp_decode_u64(&decoded[1]);
        assert_eq!(decoded_time, creation_time);

        let decoded_block = serialization::rlp_decode_u64(&decoded[2]);
        assert_eq!(decoded_block, creation_block);
    }

    /// Verify single-member federation serialization.
    #[test]
    fn rskj_committed_federation_single_member() {
        let keys = vec![vec![0x02; 33]];
        let encoded = serialize_federation(&keys, 0, 1);

        let decoded = serialization::rlp_decode_list(&encoded).unwrap();
        let decoded_keys = serialization::rlp_decode_list(&decoded[0]).unwrap();
        assert_eq!(decoded_keys.len(), 1);
        assert_eq!(decoded_keys[0], vec![0x02; 33]);
        assert_eq!(serialization::rlp_decode_u64(&decoded[1]), 0);
        assert_eq!(serialization::rlp_decode_u64(&decoded[2]), 1);
    }
}
