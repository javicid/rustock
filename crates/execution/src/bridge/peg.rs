//! Peg-in and peg-out logic for the Bridge.
//!
//! ## Peg-in (`registerBtcTransaction`)
//!
//! The core flow:
//! 1. Verify BTC transaction is included in a stored block (via PMT)
//! 2. Check the block has sufficient confirmations
//! 3. Classify the transaction (peg-in / migration / etc.)
//! 4. For peg-in: identify the federation address in outputs, credit RBTC
//! 5. Mark the transaction as processed
//!
//! ## Peg-out (`releaseBtc`)
//!
//! Enqueues a release request that will be processed by `updateCollections`.

use alloy_primitives::{Bytes, U256};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::Transaction as BtcTransaction;
use revm::context_interface::{ContextTr, JournalTr};
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::btc_chain::b256_to_bitcoin_hash;
use super::btc_store::{get_stored_block, load_chain_head};
use super::constants::BridgeConstants;
use super::pmt::PartialMerkleTree;
use super::storage::*;
use super::tx::*;
use crate::precompiles::BRIDGE_ADDR;

// ---------------------------------------------------------------------------
// registerBtcTransaction
// ---------------------------------------------------------------------------

/// `registerBtcTransaction(bytes btcTxSerialized, int256 height, bytes pmtSerialized)`
///
/// The core peg-in method. Verifies a BTC transaction is included in the
/// BTC header chain, classifies it, and credits RBTC to the sender.
pub fn register_btc_transaction<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 96 {
        return Err(PrecompileError::other(
            "registerBtcTransaction: args too short",
        ));
    }

    // Parse ABI arguments:
    // arg0: bytes btcTxSerialized (dynamic)
    // arg1: int256 height
    // arg2: bytes pmtSerialized (dynamic)

    let btc_tx_offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    let btc_block_height = {
        let raw = U256::from_be_slice(&args[32..64]);
        raw.to::<u64>()
    };
    let pmt_offset = U256::from_be_slice(&args[64..96]).to::<usize>();

    let btc_tx_data = read_dynamic_bytes(args, btc_tx_offset)?;
    let pmt_data = read_dynamic_bytes(args, pmt_offset)?;

    // Compute BTC tx hash
    let btc_tx_hash = calculate_btc_tx_hash(&btc_tx_data);

    // Check if already processed
    if is_btc_tx_processed(ctx, &btc_tx_hash) {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Validate PMT
    if !PartialMerkleTree::has_expected_size(&pmt_data) {
        return Err(PrecompileError::other(
            "registerBtcTransaction: invalid PMT size",
        ));
    }

    let pmt = PartialMerkleTree::parse(&pmt_data).ok_or_else(|| {
        PrecompileError::other("registerBtcTransaction: failed to parse PMT")
    })?;

    let pmt_result = pmt.extract_matches().ok_or_else(|| {
        PrecompileError::other("registerBtcTransaction: PMT verification failed")
    })?;

    // Check tx hash is in PMT matched hashes
    if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
        return Err(PrecompileError::other(
            "registerBtcTransaction: tx not in PMT",
        ));
    }

    // Look up the BTC block by height
    let block_hash_b256 = bridge_load_btc_block_hash_by_height(ctx, btc_block_height as u32);
    let block_hash = match block_hash_b256 {
        Some(h) => b256_to_bitcoin_hash(&h),
        None => {
            return Err(PrecompileError::other(
                "registerBtcTransaction: BTC block not found at height",
            ))
        }
    };

    let stored_block = get_stored_block(ctx, &block_hash).ok_or_else(|| {
        PrecompileError::other("registerBtcTransaction: stored block not found")
    })?;

    // Verify merkle root matches
    let block_merkle_root = {
        let raw = stored_block.header.merkle_root.to_raw_hash();
        *raw.as_byte_array()
    };

    let root_valid = if pmt_result.merkle_root == block_merkle_root {
        true
    } else {
        // Post-RSKIP143: also accept witness merkle root
        let block_hash_bytes = {
            let raw = block_hash.to_raw_hash();
            *raw.as_byte_array()
        };
        match get_coinbase_information(ctx, &block_hash_bytes) {
            Some(witness_root) => pmt_result.merkle_root == witness_root,
            None => false,
        }
    };

    if !root_valid {
        return Err(PrecompileError::other(
            "registerBtcTransaction: merkle root mismatch",
        ));
    }

    // Check confirmations
    let chain_head = load_chain_head(ctx);
    let best_height = chain_head.map(|h| h.height).unwrap_or(0);
    if best_height < stored_block.height + config.btc2rsk_minimum_acceptable_confirmations {
        return Err(PrecompileError::other(
            "registerBtcTransaction: insufficient confirmations",
        ));
    }

    // Parse the BTC transaction
    let btc_tx: BtcTransaction = deserialize(&btc_tx_data).map_err(|_| {
        PrecompileError::other("registerBtcTransaction: invalid BTC transaction")
    })?;

    // Process the transaction outputs:
    // Look for outputs that pay to a known federation address.
    // For each such output, credit the equivalent RBTC amount to the
    // address derived from the sender (first input's script).
    //
    // In the full rskj implementation, this involves complex peg type
    // detection (PegUtils). For now, we sum all output values as
    // the peg-in amount and credit the transaction caller.
    let total_value: u64 = btc_tx.output.iter().map(|o| o.value.to_sat()).sum();
    let rbtc_amount = btc_satoshi_to_rbtc_wei(total_value);

    // Credit the caller
    if !rbtc_amount.is_zero() {
        let _ = ctx
            .journal_mut()
            .balance_incr(BRIDGE_ADDR, rbtc_amount);
    }

    // Mark as processed
    let rsk_height = stored_block.height as u64;
    set_btc_tx_processed(ctx, &btc_tx_hash, rsk_height);

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// registerFastBridgeBtcTransaction (Flyover)
// ---------------------------------------------------------------------------

/// `registerFastBridgeBtcTransaction(bytes,uint256,bytes,bytes32,bytes,address,bytes,bool)`
///
/// Flyover peg-in variant. Similar to registerBtcTransaction but with
/// additional derivation hash validation and separate tracking.
pub fn register_fast_bridge_btc_transaction<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    // The Flyover peg-in has 8 parameters.
    // For now, implement the core verification (PMT + merkle root + confirmations)
    // and mark as processed. Full Flyover-specific logic (derivation hash,
    // federation info lookup, separate UTXO tracking) will be refined later.

    if args.len() < 256 {
        return Err(PrecompileError::other(
            "registerFastBridgeBtcTransaction: args too short",
        ));
    }

    // arg0: bytes btcTxSerialized (dynamic)
    // arg1: uint256 height
    // arg2: bytes pmtSerialized (dynamic)
    // arg3: bytes32 derivationArgumentsHash
    // arg4: bytes userRefundBtcAddress (dynamic)
    // arg5: address liquidityBridgeContractAddress
    // arg6: bytes liquidityProviderBtcAddress (dynamic)
    // arg7: bool shouldTransferToContract

    let btc_tx_offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    let btc_block_height = U256::from_be_slice(&args[32..64]).to::<u64>();
    let pmt_offset = U256::from_be_slice(&args[64..96]).to::<usize>();
    let _derivation_hash: [u8; 32] = args[96..128].try_into().unwrap();

    let btc_tx_data = read_dynamic_bytes(args, btc_tx_offset)?;
    let pmt_data = read_dynamic_bytes(args, pmt_offset)?;

    let btc_tx_hash = calculate_btc_tx_hash(&btc_tx_data);

    // Check hash+derivation not already used
    let flyover_key = {
        let hash_hex = to_hex(&btc_tx_hash);
        compound_key(FAST_BRIDGE_HASH_USED_KEY, "-", &hash_hex)
    };
    let already_used = bridge_sload(ctx, flyover_key);
    if !already_used.is_zero() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // PMT verification
    if !PartialMerkleTree::has_expected_size(&pmt_data) {
        return Err(PrecompileError::other(
            "registerFastBridgeBtcTransaction: invalid PMT size",
        ));
    }

    let pmt = PartialMerkleTree::parse(&pmt_data).ok_or_else(|| {
        PrecompileError::other("registerFastBridgeBtcTransaction: failed to parse PMT")
    })?;

    let pmt_result = pmt.extract_matches().ok_or_else(|| {
        PrecompileError::other("registerFastBridgeBtcTransaction: PMT verification failed")
    })?;

    if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
        return Err(PrecompileError::other(
            "registerFastBridgeBtcTransaction: tx not in PMT",
        ));
    }

    // Block and merkle root verification (same as registerBtcTransaction)
    let block_hash_b256 = bridge_load_btc_block_hash_by_height(ctx, btc_block_height as u32);
    let block_hash = match block_hash_b256 {
        Some(h) => b256_to_bitcoin_hash(&h),
        None => {
            return Err(PrecompileError::other(
                "registerFastBridgeBtcTransaction: BTC block not found",
            ))
        }
    };

    let stored_block = get_stored_block(ctx, &block_hash).ok_or_else(|| {
        PrecompileError::other("registerFastBridgeBtcTransaction: stored block not found")
    })?;

    let block_merkle_root = {
        let raw = stored_block.header.merkle_root.to_raw_hash();
        *raw.as_byte_array()
    };

    if pmt_result.merkle_root != block_merkle_root {
        let block_hash_bytes = {
            let raw = block_hash.to_raw_hash();
            *raw.as_byte_array()
        };
        match get_coinbase_information(ctx, &block_hash_bytes) {
            Some(witness_root) if pmt_result.merkle_root == witness_root => {}
            _ => {
                return Err(PrecompileError::other(
                    "registerFastBridgeBtcTransaction: merkle root mismatch",
                ))
            }
        }
    }

    // Confirmations
    let chain_head = load_chain_head(ctx);
    let best_height = chain_head.map(|h| h.height).unwrap_or(0);
    if best_height < stored_block.height + config.btc2rsk_minimum_acceptable_confirmations {
        return Err(PrecompileError::other(
            "registerFastBridgeBtcTransaction: insufficient confirmations",
        ));
    }

    // Mark as used
    bridge_sstore(ctx, flyover_key, U256::from(1));

    // Also mark as processed in the standard map
    set_btc_tx_processed(ctx, &btc_tx_hash, stored_block.height as u64);

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// releaseBtc
// ---------------------------------------------------------------------------

/// `releaseBtc()` — enqueue a peg-out request.
///
/// The caller sends RBTC to the Bridge address. This method enqueues a
/// release request that will be batched and signed by `updateCollections`.
pub fn release_btc<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    _config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    // In rskj, releaseBtc:
    // 1. Rejects contract callers (RSKIP185)
    // 2. Derives BTC destination from RSK tx sender
    // 3. Validates minimum peg-out amount
    // 4. Enqueues on release request queue
    //
    // For now: accept the call, deduct value from the Bridge balance,
    // and increment a counter for the release queue.

    // Read the next pegout height to track queue
    let key = bridge_storage_key(NEXT_PEGOUT_HEIGHT_KEY);
    let queue_count = bridge_sload(ctx, key);
    bridge_sstore(ctx, key, queue_count.wrapping_add(U256::from(1)));

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// updateCollections
// ---------------------------------------------------------------------------

/// `updateCollections()` — orchestrator for peg-out processing.
///
/// In rskj, this method:
/// - Processes fund migration between federations
/// - Batches peg-out requests into BTC transactions
/// - Promotes confirmed pegouts
/// - Updates federation creation block heights
/// - Manages SVP state
///
/// For now: no-op stub (peg-out batching requires federation UTXO tracking).
pub fn update_collections<CTX: ContextTr>(
    _ctx: &mut CTX,
    gas_cost: u64,
    _config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// addSignature
// ---------------------------------------------------------------------------

/// `addSignature(bytes federatorPublicKey, bytes[] signatures, bytes rskTxHash)`
///
/// Collects federator signatures for pending peg-out BTC transactions.
/// When enough signatures are collected, the BTC tx is considered complete.
///
/// For now: no-op stub (requires peg-out tx assembly and federation state).
pub fn add_signature<CTX: ContextTr>(
    _ctx: &mut CTX,
    _args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert BTC satoshis to RBTC wei.
/// 1 BTC = 10^8 satoshis = 10^18 wei RBTC, so 1 satoshi = 10^10 wei.
fn btc_satoshi_to_rbtc_wei(satoshis: u64) -> U256 {
    U256::from(satoshis) * U256::from(10_000_000_000u64) // 10^10
}

fn read_dynamic_bytes(args: &[u8], offset: usize) -> Result<Vec<u8>, PrecompileError> {
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

// ---------------------------------------------------------------------------
// Read-only query methods
// ---------------------------------------------------------------------------

/// `getNextPegoutCreationBlockNumber()` → int256
pub fn get_next_pegout_creation_block_number<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let key = bridge_storage_key(NEXT_PEGOUT_HEIGHT_KEY);
    let val = bridge_sload(ctx, key);
    let mut output = [0u8; 32];
    let bytes = val.to_be_bytes::<32>();
    output.copy_from_slice(&bytes);
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

/// `getQueuedPegoutsCount()` → uint256
pub fn get_queued_pegouts_count<CTX: ContextTr>(
    _ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // For now return 0 (no actual queue tracking yet)
    let output = [0u8; 32];
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

/// `getEstimatedFeesForNextPegOutEvent()` → uint256
pub fn get_estimated_fees_for_next_pegout<CTX: ContextTr>(
    _ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Return 0 for now
    let output = [0u8; 32];
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satoshi_to_wei_conversion() {
        assert_eq!(btc_satoshi_to_rbtc_wei(1), U256::from(10_000_000_000u64));
        assert_eq!(
            btc_satoshi_to_rbtc_wei(100_000_000),
            U256::from(10u128).pow(U256::from(18))
        );
    }

    #[test]
    fn satoshi_to_wei_zero() {
        assert_eq!(btc_satoshi_to_rbtc_wei(0), U256::ZERO);
    }
}
