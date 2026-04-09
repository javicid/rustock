//! Bridge local-only getter implementations.
//!
//! These methods read federation data, fee parameters, and locking cap
//! from Bridge contract storage. They are consensus-safe read-only queries.

use alloy_primitives::{Bytes, U256};
use revm::context_interface::ContextTr;
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::constants::BridgeConstants;
use super::serialization;
use super::storage::*;

/// `getFederationAddress()` → string (ABI-encoded)
pub fn get_federation_address<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, NEW_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }
    // The federation address is derived from the serialized federation data.
    // For now, return the raw federation data as-is (the caller can decode it).
    // A full implementation would compute the P2SH address from member keys.
    let output = abi_encode_bytes(&fed_data);
    Ok(PrecompileOutput::new(gas_cost, output.into()))
}

/// `getFederationSize()` → int256
pub fn get_federation_size<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, NEW_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(0)));
    }
    let size = decode_federation_size(&fed_data);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(size as i64)))
}

/// `getFederationThreshold()` → int256
pub fn get_federation_threshold<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, NEW_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(0)));
    }
    let size = decode_federation_size(&fed_data);
    let threshold = (size / 2) + 1;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(threshold as i64)))
}

/// `getFederationCreationBlockNumber()` → int256
pub fn get_federation_creation_block_number<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = bridge_load_u256(ctx, ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_u256(val)))
}

/// `getFederationCreationTime()` → int256
pub fn get_federation_creation_time<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, NEW_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(0)));
    }
    let creation_time = decode_federation_creation_time(&fed_data);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(creation_time as i64)))
}

/// `getFederatorPublicKey(int256 index)` → bytes
pub fn get_federator_public_key<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("getFederatorPublicKey: args too short"));
    }
    let _index = U256::from_be_slice(&args[..32]).to::<usize>();

    let fed_data = bridge_load_bytes_named(ctx, NEW_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    let keys = decode_federation_keys(&fed_data);
    if _index < keys.len() {
        let output = abi_encode_bytes(&keys[_index]);
        Ok(PrecompileOutput::new(gas_cost, output.into()))
    } else {
        Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
    }
}

/// `getFederatorPublicKeyOfType(int256 index, string keyType)` → bytes
pub fn get_federator_public_key_of_type<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Simplified: delegates to get_federator_public_key (BTC key)
    get_federator_public_key(ctx, args, gas_cost)
}

/// `getFeePerKb()` → int256
pub fn get_fee_per_kb<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = bridge_load_u256(ctx, "feePerKb");
    Ok(PrecompileOutput::new(gas_cost, abi_encode_u256(val)))
}

/// `getLockingCap()` → int256
pub fn get_locking_cap<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = bridge_load_u256(ctx, "lockingCap");
    Ok(PrecompileOutput::new(gas_cost, abi_encode_u256(val)))
}

/// `getMinimumLockTxValue()` → int256
pub fn get_minimum_lock_tx_value(
    gas_cost: u64,
    config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    let satoshi_value = config.minimum_pegin_tx_value;
    let wei = U256::from(satoshi_value) * U256::from(10_000_000_000u64);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_u256(wei)))
}

/// `getRetiringFederationAddress()` → string
pub fn get_retiring_federation_address<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, OLD_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(-1)));
    }
    let output = abi_encode_bytes(&fed_data);
    Ok(PrecompileOutput::new(gas_cost, output.into()))
}

/// `getRetiringFederationSize()` → int256
pub fn get_retiring_federation_size<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, OLD_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(-1)));
    }
    let size = decode_federation_size(&fed_data);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(size as i64)))
}

/// `getRetiringFederationThreshold()` → int256
pub fn get_retiring_federation_threshold<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, OLD_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(-1)));
    }
    let size = decode_federation_size(&fed_data);
    let threshold = (size / 2) + 1;
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(threshold as i64)))
}

/// `getPendingFederationSize()` → int256
pub fn get_pending_federation_size<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let fed_data = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_int(-1)));
    }
    let size = decode_federation_size(&fed_data);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_int(size as i64)))
}

/// `isBtcTxHashAlreadyProcessed(string hash)` → bool
pub fn is_btc_tx_hash_already_processed<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 64 {
        return Err(PrecompileError::other("isBtcTxHashAlreadyProcessed: args too short"));
    }
    let offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    if offset + 32 > args.len() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_bool(false)));
    }
    let len = U256::from_be_slice(&args[offset..offset + 32]).to::<usize>();
    if offset + 32 + len > args.len() {
        return Ok(PrecompileOutput::new(gas_cost, abi_encode_bool(false)));
    }
    let hash_str = &args[offset + 32..offset + 32 + len];
    let hash_hex = String::from_utf8_lossy(hash_str);
    let key = compound_key(BTC_TX_HASH_AP_KEY, "-", &hash_hex);
    let val = bridge_sload(ctx, key);
    Ok(PrecompileOutput::new(gas_cost, abi_encode_bool(!val.is_zero())))
}

// ---------------------------------------------------------------------------
// ABI encoding helpers
// ---------------------------------------------------------------------------

fn abi_encode_int(value: i64) -> Bytes {
    let mut output = [0u8; 32];
    if value >= 0 {
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        output = [0xFF; 32];
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    }
    Bytes::copy_from_slice(&output)
}

fn abi_encode_u256(value: U256) -> Bytes {
    Bytes::copy_from_slice(&value.to_be_bytes::<32>())
}

fn abi_encode_bool(value: bool) -> Bytes {
    let mut output = [0u8; 32];
    if value {
        output[31] = 1;
    }
    Bytes::copy_from_slice(&output)
}

fn abi_encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(64 + ((data.len() + 31) / 32) * 32);
    // offset to data (always 32 for single bytes param)
    let mut offset = [0u8; 32];
    offset[28..32].copy_from_slice(&32u32.to_be_bytes());
    output.extend_from_slice(&offset);
    // length
    let mut len_word = [0u8; 32];
    len_word[28..32].copy_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(&len_word);
    // data (padded to 32 bytes)
    output.extend_from_slice(data);
    let padding = (32 - (data.len() % 32)) % 32;
    output.extend(std::iter::repeat(0u8).take(padding));
    output
}

// ---------------------------------------------------------------------------
// Federation data decoding (from RLP-serialized format)
// ---------------------------------------------------------------------------

/// Decode the number of members from serialized federation data.
fn decode_federation_size(data: &[u8]) -> usize {
    if let Some(items) = serialization::rlp_decode_list(data) {
        // Federation RLP: [[member_keys...], creation_time, creation_block]
        if let Some(first) = items.first() {
            if let Some(members) = serialization::rlp_decode_list(first) {
                return members.len();
            }
        }
    }
    0
}

/// Decode the creation time from serialized federation data.
fn decode_federation_creation_time(data: &[u8]) -> u64 {
    if let Some(items) = serialization::rlp_decode_list(data) {
        if items.len() >= 2 {
            let time_bytes = &items[1];
            if time_bytes.is_empty() {
                return 0;
            }
            let mut padded = [0u8; 8];
            let start = 8usize.saturating_sub(time_bytes.len());
            let copy_len = time_bytes.len().min(8);
            padded[start..start + copy_len].copy_from_slice(&time_bytes[..copy_len]);
            return u64::from_be_bytes(padded);
        }
    }
    0
}

/// Decode the BTC public keys from serialized federation data.
fn decode_federation_keys(data: &[u8]) -> Vec<Vec<u8>> {
    if let Some(items) = serialization::rlp_decode_list(data) {
        if let Some(first) = items.first() {
            if let Some(members) = serialization::rlp_decode_list(first) {
                return members;
            }
        }
    }
    Vec::new()
}
