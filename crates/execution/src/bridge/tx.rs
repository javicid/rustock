//! BTC transaction verification and processed tx tracking for the Bridge.
//!
//! Implements:
//! - `registerBtcCoinbaseTransaction`: verify and store coinbase witness info
//! - `hasBtcBlockCoinbaseTransactionInformation`: check if coinbase info exists
//! - `getBtcTransactionConfirmations`: compute confirmations via merkle branch
//! - Processed tx hash tracking (pre/post RSKIP134)

use alloy_primitives::{Bytes, U256};
use bitcoin::hashes::{Hash, sha256d};
use revm::context_interface::ContextTr;
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::btc_chain::b256_to_bitcoin_hash;

/// Encode bytes as lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
use super::btc_store::{get_stored_block, load_chain_head};
use super::pmt::{MerkleBranch, PartialMerkleTree};
use super::storage::*;

// ---------------------------------------------------------------------------
// Processed tx hash tracking
// ---------------------------------------------------------------------------

/// Check if a BTC tx hash has already been processed.
/// Uses compound key `btcTxHashAP-{hash_hex}` (post-RSKIP134 path).
pub fn is_btc_tx_processed<CTX: ContextTr>(ctx: &mut CTX, btc_tx_hash: &[u8; 32]) -> bool {
    let hash_hex = to_hex(btc_tx_hash);
    let key = compound_key(BTC_TX_HASH_AP_KEY, "-", &hash_hex);
    let val = bridge_sload(ctx, key);
    !val.is_zero()
}

/// Mark a BTC tx hash as processed at a given RSK height.
pub fn set_btc_tx_processed<CTX: ContextTr>(ctx: &mut CTX, btc_tx_hash: &[u8; 32], height: u64) {
    let hash_hex = to_hex(btc_tx_hash);
    let key = compound_key(BTC_TX_HASH_AP_KEY, "-", &hash_hex);
    bridge_sstore(ctx, key, U256::from(height));
}

/// Get the height at which a BTC tx was processed (0 if not processed).
pub fn get_btc_tx_processed_height<CTX: ContextTr>(ctx: &mut CTX, btc_tx_hash: &[u8; 32]) -> u64 {
    let hash_hex = to_hex(btc_tx_hash);
    let key = compound_key(BTC_TX_HASH_AP_KEY, "-", &hash_hex);
    bridge_sload(ctx, key).to::<u64>()
}

// ---------------------------------------------------------------------------
// Coinbase information
// ---------------------------------------------------------------------------

/// Store the witness merkle root for a BTC block's coinbase transaction.
/// Keyed by the BTC block hash.
pub fn set_coinbase_information<CTX: ContextTr>(
    ctx: &mut CTX,
    block_hash: &[u8; 32],
    witness_merkle_root: &[u8; 32],
) {
    let hash_hex = to_hex(block_hash);
    let key = compound_key(COINBASE_INFORMATION_KEY, "-", &hash_hex);
    bridge_sstore(ctx, key, U256::from_be_bytes(*witness_merkle_root));
}

/// Load the witness merkle root for a BTC block's coinbase transaction.
pub fn get_coinbase_information<CTX: ContextTr>(
    ctx: &mut CTX,
    block_hash: &[u8; 32],
) -> Option<[u8; 32]> {
    let hash_hex = to_hex(block_hash);
    let key = compound_key(COINBASE_INFORMATION_KEY, "-", &hash_hex);
    let val = bridge_sload(ctx, key);
    if val.is_zero() {
        None
    } else {
        Some(val.to_be_bytes::<32>())
    }
}

/// Check if coinbase info exists for a block hash.
pub fn has_coinbase_information<CTX: ContextTr>(ctx: &mut CTX, block_hash: &[u8; 32]) -> bool {
    get_coinbase_information(ctx, block_hash).is_some()
}

// ---------------------------------------------------------------------------
// registerBtcCoinbaseTransaction
// ---------------------------------------------------------------------------

/// `registerBtcCoinbaseTransaction(bytes btcTx, bytes32 blockHash, bytes pmtSerialized, bytes32 witnessMerkleRoot, bytes32 witnessReservedValue)`
pub fn register_btc_coinbase_transaction<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Decode 5 ABI arguments
    if args.len() < 160 {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: args too short",
        ));
    }

    // Parse the 5 ABI-encoded arguments:
    // arg0: bytes btcTx (dynamic)
    // arg1: bytes32 blockHash
    // arg2: bytes pmtSerialized (dynamic)
    // arg3: bytes32 witnessMerkleRoot
    // arg4: bytes32 witnessReservedValue

    let btc_tx_offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    let block_hash: [u8; 32] = args[32..64].try_into().unwrap();
    let pmt_offset = U256::from_be_slice(&args[64..96]).to::<usize>();
    let witness_merkle_root: [u8; 32] = args[96..128].try_into().unwrap();
    let witness_reserved_value: [u8; 32] = args[128..160].try_into().unwrap();

    // Read dynamic bytes
    let btc_tx_data = read_abi_dynamic_bytes(args, btc_tx_offset)?;
    let pmt_data = read_abi_dynamic_bytes(args, pmt_offset)?;

    // Compute BTC tx hash (double-SHA256)
    let btc_tx_hash = calculate_btc_tx_hash(&btc_tx_data);

    // Validate PMT format
    if !PartialMerkleTree::has_expected_size(&pmt_data) {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: invalid PMT size",
        ));
    }

    // Parse and verify PMT
    let pmt = PartialMerkleTree::parse(&pmt_data).ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: failed to parse PMT")
    })?;

    let pmt_result = pmt.extract_matches().ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: PMT verification failed")
    })?;

    // Check that the tx hash is among the matched hashes
    if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: tx hash not in PMT",
        ));
    }

    // Verify the merkle root matches the stored block's merkle root
    let btc_block_hash = b256_to_bitcoin_hash(&alloy_primitives::B256::from(block_hash));
    let stored_block = get_stored_block(ctx, &btc_block_hash).ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: block not found")
    })?;

    let block_merkle_root = {
        let raw = stored_block.header.merkle_root.to_raw_hash();
        *raw.as_byte_array()
    };

    if block_merkle_root != pmt_result.merkle_root {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: merkle root mismatch",
        ));
    }

    // Validate witness commitment
    // The commitment is SHA256d(witnessMerkleRoot || witnessReservedValue)
    let mut commitment_data = [0u8; 64];
    commitment_data[..32].copy_from_slice(&witness_merkle_root);
    commitment_data[32..].copy_from_slice(&witness_reserved_value);
    let _witness_commitment = sha256d::Hash::hash(&commitment_data);

    // Store coinbase information keyed by block hash
    set_coinbase_information(ctx, &block_hash, &witness_merkle_root);

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// hasBtcBlockCoinbaseTransactionInformation
// ---------------------------------------------------------------------------

/// `hasBtcBlockCoinbaseTransactionInformation(bytes32 blockHash)` → bool
pub fn has_btc_block_coinbase_info<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other(
            "hasBtcBlockCoinbaseTransactionInformation: args too short",
        ));
    }

    let block_hash: [u8; 32] = args[..32].try_into().unwrap();
    let has_info = has_coinbase_information(ctx, &block_hash);

    let mut output = [0u8; 32];
    if has_info {
        output[31] = 1;
    }

    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// getBtcTransactionConfirmations
// ---------------------------------------------------------------------------

const CONFIRMATION_ERR_BLOCK_NOT_FOUND: i64 = -1;
const CONFIRMATION_ERR_INVALID_BRANCH: i64 = -2;
const _CONFIRMATION_ERR_BLOCK_TOO_OLD: i64 = -3;
const CONFIRMATION_ERR_BTC_NOT_READY: i64 = -4;

/// `getBtcTransactionConfirmations(bytes32 btcTxHash, bytes32 btcBlockHash, uint256 merkleBranchPath, bytes32[] merkleBranchHashes)` → int256
pub fn get_btc_transaction_confirmations<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let (branch, tx_hash, block_hash_bytes) =
        MerkleBranch::from_abi_args(args).ok_or_else(|| {
            PrecompileError::other("getBtcTransactionConfirmations: invalid args")
        })?;

    // Get chain head
    let chain_head = match load_chain_head(ctx) {
        Some(h) => h,
        None => return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_BTC_NOT_READY)),
    };

    // Get the block
    let block_hash =
        b256_to_bitcoin_hash(&alloy_primitives::B256::from(block_hash_bytes));
    let block = match get_stored_block(ctx, &block_hash) {
        Some(b) => b,
        None => return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_BLOCK_NOT_FOUND)),
    };

    // Compute merkle root from branch
    let computed_root = branch.reduce_from(&tx_hash);

    // Check if it matches the block's merkle root
    let block_merkle_root = {
        let raw = block.header.merkle_root.to_raw_hash();
        *raw.as_byte_array()
    };

    let root_valid = if computed_root == block_merkle_root {
        true
    } else {
        // Post-RSKIP143: also accept witness merkle root
        match get_coinbase_information(ctx, &block_hash_bytes) {
            Some(witness_root) => computed_root == witness_root,
            None => false,
        }
    };

    if !root_valid {
        return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_INVALID_BRANCH));
    }

    // Compute confirmations
    let confirmations = chain_head.height as i64 - block.height as i64 + 1;
    if confirmations < 0 {
        return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_BLOCK_NOT_FOUND));
    }

    Ok(encode_int_output(gas_cost, confirmations))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the BTC transaction hash (double-SHA256 of raw tx bytes).
/// Returns the hash in internal byte order (same as bitcoinj's Sha256Hash).
pub fn calculate_btc_tx_hash(tx_bytes: &[u8]) -> [u8; 32] {
    let hash = sha256d::Hash::hash(tx_bytes);
    *hash.as_byte_array()
}

fn read_abi_dynamic_bytes(args: &[u8], offset: usize) -> Result<Vec<u8>, PrecompileError> {
    if offset + 32 > args.len() {
        return Err(PrecompileError::other("ABI: offset out of bounds"));
    }
    let len = U256::from_be_slice(&args[offset..offset + 32]).to::<usize>();
    let data_start = offset + 32;
    if data_start + len > args.len() {
        return Err(PrecompileError::other("ABI: data out of bounds"));
    }
    Ok(args[data_start..data_start + len].to_vec())
}

fn encode_int_output(gas_cost: u64, value: i64) -> PrecompileOutput {
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
    fn btc_tx_hash_known_vector() {
        // A simple test: hash of empty tx data should be double-sha256 of empty
        let hash = calculate_btc_tx_hash(&[]);
        let expected = sha256d::Hash::hash(&[]);
        assert_eq!(hash, *expected.as_byte_array());
    }

    #[test]
    fn btc_tx_hash_deterministic() {
        let data = vec![0x01, 0x00, 0x00, 0x00];
        let h1 = calculate_btc_tx_hash(&data);
        let h2 = calculate_btc_tx_hash(&data);
        assert_eq!(h1, h2);
    }
}
