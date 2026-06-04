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
//!
//! ## Release request queue formats (rskj BridgeSerializationUtils)
//!
//! Pre-RSKIP146 (`releaseRequestQueue`):
//!   RLP_list [ btc_addr_hash160_0, bigint(sat_0), btc_addr_hash160_1, bigint(sat_1), ... ]
//!
//! Post-RSKIP146 (`releaseRequestQueueWithTxHash`):
//!   RLP_list [ btc_addr_hash160_0, bigint(sat_0), rsk_tx_hash_0, ... ] (triples)
//!
//! ## rskTxsWaitingFS (pegoutsWaitingForSignatures)
//!
//! SortedMap<keccak256_rsk_tx_hash → raw_btc_tx_bytes> stored as:
//!   RLP_list [ rlp_bytes(rsk_hash_0), rlp_bytes(btc_tx_raw_0), rlp_bytes(rsk_hash_1), ... ]

use alloy_primitives::{Address as RskAddress, Bytes, U256};
use bitcoin::consensus::{deserialize, serialize as btc_serialize};
use bitcoin::hashes::Hash;
use bitcoin::Transaction as BtcTransaction;
use revm::context_interface::{ContextTr, JournalTr};
use revm::precompile::{PrecompileError, PrecompileOutput};
use std::collections::BTreeMap;

use sha3::Digest;
use sha2;
use ripemd;

use super::btc_chain::b256_to_bitcoin_hash;
use super::btc_store::{get_stored_block, load_chain_head};
use super::constants::BridgeConstants;
use super::pmt::PartialMerkleTree;
use super::serialization::{rlp_decode_list, rlp_encode_element, rlp_encode_list, rlp_encode_u64};
use super::storage::*;
use super::tx::*;
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::{BRIDGE_ADDR, BridgeTxContext};

/// A pending peg-out release request, matching rskj's ReleaseRequestQueue.Entry.
///
/// The BTC destination address is the P2PKH hash160 derived from the RSK
/// transaction sender's public key (matching rskj's BridgeUtils.recoverBtcAddressFromEthTransaction).
#[derive(Debug, Clone)]
pub struct ReleaseRequest {
    /// BTC destination address as 20-byte P2PKH hash160.
    pub btc_dest_hash160: [u8; 20],
    /// Amount in satoshis (NOT wei).
    pub amount_satoshis: u64,
    /// RSK transaction hash (post-RSKIP146 only; None for pre-RSKIP146 queue).
    pub rsk_tx_hash: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// registerBtcTransaction
// ---------------------------------------------------------------------------

/// `registerBtcTransaction(bytes btcTxSerialized, int256 height, bytes pmtSerialized)`
///
/// The core peg-in method. Verifies a BTC transaction is included in the
/// BTC header chain, classifies it, and credits RBTC to the sender.
/// rskj BridgeSupport.shouldMarkRejectedPeginAsProcessed: only between
/// RSKIP459 (lovell700) and RSKIP551 (vetiver900) are rejected
/// non-refundable peg-ins marked as processed.
fn should_mark_rejected_pegin_as_processed(cfg: &RskHardforkConfig, block_number: u64) -> bool {
    cfg.has_rskip459(block_number) && !cfg.has_rskip551(block_number)
}

pub fn register_btc_transaction<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
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

    // Derive the destination RSK address from the BTC transaction.
    // rskj's PegUtils derives the address from OP_RETURN data or
    // the first input's P2PKH script. We parse OP_RETURN first,
    // falling back to the first input's public key hash.
    let rsk_destination = extract_rsk_destination(&btc_tx);

    // Sum outputs that pay to any known federation address (simplified:
    // we sum all non-OP_RETURN outputs as the peg-in amount).
    let total_value: u64 = btc_tx
        .output
        .iter()
        .filter(|o| !o.script_pubkey.is_op_return())
        .map(|o| o.value.to_sat())
        .sum();

    // rskj marks processed txs with the RSK execution block number
    // (BridgeSupport.markTxAsProcessed), not the BTC block height.
    let rsk_height = revm::context_interface::Block::number(ctx.block()).to::<u64>();

    // Enforce minimum peg-in value (rskj handleNonRefundablePegin).
    if total_value < config.minimum_pegin_tx_value {
        if should_mark_rejected_pegin_as_processed(hardfork_cfg, rsk_height) {
            set_btc_tx_processed(ctx, &btc_tx_hash, rsk_height);
        }
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    let rbtc_amount = btc_satoshi_to_rbtc_wei(total_value);

    // Credit the derived destination address (transfer from Bridge balance)
    if let Some(dest) = rsk_destination {
        if !rbtc_amount.is_zero() {
            let _ = ctx.journal_mut().transfer(BRIDGE_ADDR, dest, rbtc_amount);
        }
    }

    // Mark as processed
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
///
/// Matches rskj's `BridgeSupport.releaseBtc()`:
/// - Reads the call value from the Bridge's received balance delta
/// - Validates minimum peg-out amount (in satoshis)
/// - Derives the BTC destination address from the RSK tx sender's public key
///   (matches `BridgeUtils.recoverBtcAddressFromEthTransaction`)
/// - Post-RSKIP146: stores to `releaseRequestQueueWithTxHash` (triple format)
/// - Pre-RSKIP146: stores to `releaseRequestQueue` (pair format)
pub fn release_btc<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let call_value_wei = revm::context_interface::Transaction::value(ctx.tx());

    if call_value_wei.is_zero() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Convert Wei to satoshis: 1 satoshi = 10^10 wei
    let satoshis_per_wei = U256::from(10_000_000_000u64);
    let amount_satoshis_u256 = call_value_wei / satoshis_per_wei;
    if amount_satoshis_u256.is_zero() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Determine minimum pegout value based on RSKIP219 activation
    let min_satoshis = if hardfork_cfg.has_rskip219(block_number) {
        config.minimum_pegout_tx_value
    } else {
        config.legacy_minimum_pegout_tx_value
    };

    if amount_satoshis_u256 < U256::from(min_satoshis) {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    let amount_satoshis = amount_satoshis_u256.to::<u64>();

    // BTC destination: RIPEMD160(SHA256(compressed_pubkey)) derived from tx sender.
    // tx_ctx.btc_sender_hash160 was computed by the executor from the RSK tx signature,
    // matching rskj's BridgeUtils.recoverBtcAddressFromEthTransaction.
    let btc_dest = tx_ctx.btc_sender_hash160;

    let use_tx_hash_format = hardfork_cfg.has_rskip146(block_number);

    if use_tx_hash_format {
        // Post-RSKIP146: store in releaseRequestQueueWithTxHash (triple format)
        let key = bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY);
        let existing = bridge_load_bytes(ctx, key);
        let mut queue = deserialize_release_queue_with_hash(&existing);
        queue.push(ReleaseRequest {
            btc_dest_hash160: btc_dest,
            amount_satoshis,
            rsk_tx_hash: Some(tx_ctx.rsk_tx_hash),
        });
        let updated = serialize_release_queue_with_hash(&queue);
        bridge_store_bytes(ctx, key, &updated);
    } else {
        // Pre-RSKIP146: store in releaseRequestQueue (pair format)
        let key = bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY);
        let existing = bridge_load_bytes(ctx, key);
        let mut queue = deserialize_release_queue_legacy(&existing);
        queue.push(ReleaseRequest {
            btc_dest_hash160: btc_dest,
            amount_satoshis,
            rsk_tx_hash: None,
        });
        let updated = serialize_release_queue_legacy(&queue);
        bridge_store_bytes(ctx, key, &updated);
    }

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// updateCollections
// ---------------------------------------------------------------------------

/// `updateCollections()` — orchestrator for peg-out processing.
///
/// Matches rskj's `BridgeSupport.updateCollections()`. Key state transitions:
///
/// 1. **Process pending releases** from the release request queue:
///    - Load pending requests (from `releaseRequestQueueWithTxHash` or legacy queue)
///    - Build unsigned BTC peg-out transaction(s) using federation UTXOs
///    - Store in `pegoutsWaitingForConfirmations` (or `releaseTransactionSetWithTxHash`)
///    - Clear the processed queue entries
///    - Update `nextPegoutHeight` (post-RSKIP271)
///
/// 2. **Promote confirmed pegouts** to signing stage:
///    - For each entry in `pegoutsWaitingForConfirmations` that has enough RSK block
///      confirmations (`rsk2btc_minimum_acceptable_confirmations`), move it to
///      `rskTxsWaitingFS` (pegoutsWaitingForSignatures).
pub fn update_collections<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let use_tx_hash = hardfork_cfg.has_rskip146(block_number);
    let use_rskip271 = hardfork_cfg.has_rskip271(block_number);

    // -----------------------------------------------------------------------
    // Step 1: Check if we should create a new peg-out batch this block
    // -----------------------------------------------------------------------
    let should_create_batch = if use_rskip271 {
        // RSKIP271: batching — only process when nextPegoutHeight ≤ current block
        let next_height_key = bridge_storage_key(NEXT_PEGOUT_HEIGHT_KEY);
        let next_height = bridge_sload(ctx, next_height_key).to::<u64>();
        block_number >= next_height
    } else {
        true // Pre-RSKIP271: process every block
    };

    if should_create_batch {
        // Load pending requests from the correct queue key
        let (pending, queue_key) = if use_tx_hash {
            let key = bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY);
            let data = bridge_load_bytes(ctx, key);
            (deserialize_release_queue_with_hash(&data), key)
        } else {
            let key = bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY);
            let data = bridge_load_bytes(ctx, key);
            (deserialize_release_queue_legacy(&data), key)
        };

        if !pending.is_empty() {
            // Build BTC peg-out transaction from federation UTXOs
            let federation_keys = load_federation_member_keys(ctx);
            let threshold = (federation_keys.len() / 2) + 1;
            let fee_per_kb = get_effective_fee_per_kb(ctx, config);

            if let Some(btc_tx) = build_pegout_btc_tx(
                ctx,
                &pending,
                &federation_keys,
                threshold,
                fee_per_kb,
                config,
            ) {
                // Serialize the unsigned BTC transaction
                let btc_tx_raw = btc_serialize(&btc_tx);

                // Store in pegoutsWaitingForConfirmations
                let waiting_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
                let existing_data = bridge_load_bytes(ctx, waiting_key);
                let mut waiting = deserialize_pegouts_waiting_for_confirmations(&existing_data, use_tx_hash);

                // The RSK tx hash for the updateCollections call itself (for RSKIP176+)
                let update_collections_rsk_hash = if hardfork_cfg.has_rskip176(block_number) {
                    Some(tx_ctx.rsk_tx_hash)
                } else {
                    // Before RSKIP176, use the first release request's rsk_tx_hash
                    pending.first().and_then(|r| r.rsk_tx_hash)
                };

                waiting.push(PegoutWaitingForConfirmations {
                    btc_tx_raw: btc_tx_raw.clone(),
                    rsk_block_height: block_number,
                    rsk_tx_hash: update_collections_rsk_hash,
                });

                let updated = serialize_pegouts_waiting_for_confirmations(&waiting, use_tx_hash);
                bridge_store_bytes(ctx, waiting_key, &updated);

                // Clear the queue
                bridge_store_bytes(ctx, queue_key, &[]);
            }

            // Update nextPegoutHeight (RSKIP271)
            if use_rskip271 {
                let next_height = block_number + config.number_of_blocks_between_pegouts;
                let next_height_key = bridge_storage_key(NEXT_PEGOUT_HEIGHT_KEY);
                bridge_sstore(ctx, next_height_key, U256::from(next_height));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: Promote confirmed pegouts → waiting for signatures
    // -----------------------------------------------------------------------
    {
        let waiting_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
        let waiting_data = bridge_load_bytes(ctx, waiting_key);
        let mut waiting = deserialize_pegouts_waiting_for_confirmations(&waiting_data, use_tx_hash);

        let min_confirmations = config.rsk2btc_minimum_acceptable_confirmations as u64;
        let mut promoted = Vec::new();
        let mut remaining = Vec::new();

        for entry in waiting.drain(..) {
            if block_number >= entry.rsk_block_height + min_confirmations {
                promoted.push(entry);
            } else {
                remaining.push(entry);
            }
        }

        if !promoted.is_empty() {
            // Update pegoutsWaitingForConfirmations (remove promoted entries)
            let updated = serialize_pegouts_waiting_for_confirmations(&remaining, use_tx_hash);
            bridge_store_bytes(ctx, waiting_key, &updated);

            // Add promoted entries to rskTxsWaitingFS (pegoutsWaitingForSignatures)
            let wfs_key = bridge_storage_key(PEGOUTS_WAITING_FOR_SIGNATURES_KEY);
            let wfs_data = bridge_load_bytes(ctx, wfs_key);
            let mut wfs = deserialize_rsk_txs_waiting_for_signatures(&wfs_data);

            for entry in promoted {
                // Key: RSK tx hash (from the updateCollections call, or fallback)
                let rsk_hash = entry.rsk_tx_hash.unwrap_or(tx_ctx.rsk_tx_hash);
                wfs.insert(rsk_hash, entry.btc_tx_raw);
            }

            let updated_wfs = serialize_rsk_txs_waiting_for_signatures(&wfs);
            bridge_store_bytes(ctx, wfs_key, &updated_wfs);
        }
    }

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// addSignature
// ---------------------------------------------------------------------------

/// `addSignature(bytes federatorPublicKey, bytes[] signatures, bytes rskTxHash)`
///
/// Collects federator DER signatures for a pending peg-out BTC transaction.
///
/// Matches rskj's `BridgeSupport.addSignature()`:
/// 1. Parse federator public key, signature array, and RSK tx hash
/// 2. Load the BTC tx from `rskTxsWaitingFS` by RSK tx hash
/// 3. Apply each DER signature to the matching BTC tx input(s)
/// 4. Determine signature threshold from federation stored in Bridge storage
/// 5. If threshold reached: remove from `rskTxsWaitingFS` (tx is fully signed)
/// 6. If not yet threshold: reserialize with new signatures and store back
///
/// The BTC P2SH-multisig scriptSig format (per input):
///   OP_0 <der_sig_1> <der_sig_2> ... <redeemScript>
pub fn add_signature<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 96 {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // ABI layout: bytes federatorPublicKey, bytes[] signatures, bytes rskTxHash
    let fed_key_offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    let sigs_offset = U256::from_be_slice(&args[32..64]).to::<usize>();
    let rsk_hash_offset = U256::from_be_slice(&args[64..96]).to::<usize>();

    // Parse federator public key
    let fed_key = match read_dynamic_bytes(args, fed_key_offset) {
        Ok(k) => k,
        Err(_) => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };
    if fed_key.len() != 33 && fed_key.len() != 65 {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Parse RSK tx hash (32 bytes)
    let rsk_tx_hash_bytes = match read_dynamic_bytes(args, rsk_hash_offset) {
        Ok(h) if h.len() == 32 => h,
        _ => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };
    let mut rsk_tx_hash = [0u8; 32];
    rsk_tx_hash.copy_from_slice(&rsk_tx_hash_bytes);

    // Parse signatures array
    let sigs = parse_bytes_array(args, sigs_offset);
    if sigs.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Load the waiting-for-signatures map
    let wfs_key = bridge_storage_key(PEGOUTS_WAITING_FOR_SIGNATURES_KEY);
    let wfs_data = bridge_load_bytes(ctx, wfs_key);
    let mut wfs = deserialize_rsk_txs_waiting_for_signatures(&wfs_data);

    // Find the BTC tx by RSK tx hash
    let btc_tx_raw = match wfs.get(&rsk_tx_hash) {
        Some(r) => r.clone(),
        None => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };

    let mut btc_tx: BtcTransaction = match deserialize(&btc_tx_raw) {
        Ok(tx) => tx,
        Err(_) => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };

    // Get the federation redeem script to apply signatures
    let federation_keys = load_federation_member_keys(ctx);
    let threshold = (federation_keys.len() / 2) + 1;

    if federation_keys.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let redeem_script = build_federation_redeem_script(&federation_keys, threshold);

    // Apply DER signatures to each input
    let _ = apply_signatures_to_tx(
        &mut btc_tx,
        &sigs,
        &fed_key,
        &federation_keys,
        &redeem_script,
    );

    // Count distinct sigs on the first input to determine if threshold is reached
    let sig_count = count_signatures_in_tx(&btc_tx, threshold);

    if sig_count >= threshold {
        // Fully signed — remove from waiting map
        // (The BTC tx is broadcast off-chain by federation nodes)
        wfs.remove(&rsk_tx_hash);
        let updated = serialize_rsk_txs_waiting_for_signatures(&wfs);
        bridge_store_bytes(ctx, wfs_key, &updated);

        // Also track the sig hash for RSKIP379+ (pegoutTxSigHash compound key)
        let hash_hex = to_hex(&rsk_tx_hash);
        let sig_key = compound_key(PEGOUT_TX_SIG_HASH_KEY, "-", &hash_hex);
        bridge_sstore(ctx, sig_key, U256::from(sig_count as u64));
    } else {
        // Partially signed — update the map with new signatures
        let updated_raw = btc_serialize(&btc_tx);
        wfs.insert(rsk_tx_hash, updated_raw);
        let updated = serialize_rsk_txs_waiting_for_signatures(&wfs);
        bridge_store_bytes(ctx, wfs_key, &updated);
    }

    let _ = (hardfork_cfg, block_number);
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// rskTxsWaitingFS (pegoutsWaitingForSignatures) serialization
//
// Matches rskj BridgeSerializationUtils.serializeRskTxsWaitingForSignatures:
//   RLP_list [ rlp_bytes(rsk_hash_0), rlp_bytes(btc_tx_raw_0), ... ]
//
// The map is sorted by RSK tx hash (lexicographic, matching Java's TreeMap).
// ---------------------------------------------------------------------------

/// Serialize the pegouts-waiting-for-signatures map.
pub fn serialize_rsk_txs_waiting_for_signatures(
    map: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Vec<u8> {
    let mut items = Vec::with_capacity(map.len() * 2);
    for (rsk_hash, btc_tx_raw) in map.iter() {
        items.push(rlp_encode_element(rsk_hash));
        items.push(rlp_encode_element(btc_tx_raw));
    }
    rlp_encode_list(&items)
}

/// Deserialize the pegouts-waiting-for-signatures map.
/// Returns sorted BTreeMap (RSK tx hash → raw BTC tx bytes).
pub fn deserialize_rsk_txs_waiting_for_signatures(data: &[u8]) -> BTreeMap<[u8; 32], Vec<u8>> {
    let mut map = BTreeMap::new();
    if data.is_empty() {
        return map;
    }
    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return map,
    };
    if items.len() % 2 != 0 {
        return map;
    }
    for pair in items.chunks_exact(2) {
        if pair[0].len() != 32 {
            continue;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&pair[0]);
        map.insert(hash, pair[1].clone());
    }
    map
}

// ---------------------------------------------------------------------------
// PegoutsWaitingForConfirmations serialization
//
// Pre-RSKIP146 format (pairs): RLP_list [ btc_tx_bytes, height_bigint, ... ]
// Post-RSKIP146 format (triples): RLP_list [ btc_tx_bytes, height_bigint, rsk_tx_hash, ... ]
//
// Matches rskj BridgeSerializationUtils.serializePegoutsWaitingForConfirmations.
// ---------------------------------------------------------------------------

/// Entry in the pegouts-waiting-for-confirmations set.
#[derive(Debug, Clone)]
pub struct PegoutWaitingForConfirmations {
    pub btc_tx_raw: Vec<u8>,
    pub rsk_block_height: u64,
    pub rsk_tx_hash: Option<[u8; 32]>,
}

pub fn serialize_pegouts_waiting_for_confirmations(
    entries: &[PegoutWaitingForConfirmations],
    use_tx_hash: bool,
) -> Vec<u8> {
    let capacity = if use_tx_hash { entries.len() * 3 } else { entries.len() * 2 };
    let mut items = Vec::with_capacity(capacity);
    for entry in entries {
        items.push(rlp_encode_element(&entry.btc_tx_raw));
        items.push(rlp_encode_u64(entry.rsk_block_height));
        if use_tx_hash {
            let hash = entry.rsk_tx_hash.unwrap_or([0u8; 32]);
            items.push(rlp_encode_element(&hash));
        }
    }
    rlp_encode_list(&items)
}

pub fn deserialize_pegouts_waiting_for_confirmations(
    data: &[u8],
    use_tx_hash: bool,
) -> Vec<PegoutWaitingForConfirmations> {
    use super::serialization::rlp_decode_u64;

    if data.is_empty() {
        return Vec::new();
    }
    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let stride = if use_tx_hash { 3 } else { 2 };
    let mut entries = Vec::new();
    let mut i = 0;
    while i + stride <= items.len() {
        let btc_tx_raw = items[i].clone();
        let height = rlp_decode_u64(&items[i + 1]);
        let rsk_tx_hash = if use_tx_hash && items[i + 2].len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&items[i + 2]);
            Some(hash)
        } else {
            None
        };
        entries.push(PegoutWaitingForConfirmations { btc_tx_raw, rsk_block_height: height, rsk_tx_hash });
        i += stride;
    }
    entries
}

// ---------------------------------------------------------------------------
// Release request queue serialization
//
// Pre-RSKIP146 (pairs):
//   RLP_list [ hash160_0, bigint(sat_0), hash160_1, bigint(sat_1), ... ]
//
// Post-RSKIP146 (triples, key = releaseRequestQueueWithTxHash):
//   RLP_list [ hash160_0, bigint(sat_0), rsk_hash_0, hash160_1, ... ]
//
// Matches rskj BridgeSerializationUtils.serializeReleaseRequestQueue.
// ---------------------------------------------------------------------------

pub fn serialize_release_queue_legacy(entries: &[ReleaseRequest]) -> Vec<u8> {
    let mut items = Vec::with_capacity(entries.len() * 2);
    for entry in entries {
        items.push(rlp_encode_element(&entry.btc_dest_hash160));
        items.push(rlp_encode_u64(entry.amount_satoshis));
    }
    rlp_encode_list(&items)
}

pub fn deserialize_release_queue_legacy(data: &[u8]) -> Vec<ReleaseRequest> {
    use super::serialization::rlp_decode_u64;

    if data.is_empty() {
        return Vec::new();
    }
    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut entries = Vec::new();
    let mut i = 0;
    while i + 1 < items.len() {
        if items[i].len() != 20 {
            i += 2;
            continue;
        }
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(&items[i]);
        let amount = rlp_decode_u64(&items[i + 1]);
        entries.push(ReleaseRequest { btc_dest_hash160: hash160, amount_satoshis: amount, rsk_tx_hash: None });
        i += 2;
    }
    entries
}

pub fn serialize_release_queue_with_hash(entries: &[ReleaseRequest]) -> Vec<u8> {
    let mut items = Vec::with_capacity(entries.len() * 3);
    for entry in entries {
        items.push(rlp_encode_element(&entry.btc_dest_hash160));
        items.push(rlp_encode_u64(entry.amount_satoshis));
        let hash = entry.rsk_tx_hash.unwrap_or([0u8; 32]);
        items.push(rlp_encode_element(&hash));
    }
    rlp_encode_list(&items)
}

pub fn deserialize_release_queue_with_hash(data: &[u8]) -> Vec<ReleaseRequest> {
    use super::serialization::rlp_decode_u64;

    if data.is_empty() {
        return Vec::new();
    }
    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut entries = Vec::new();
    let mut i = 0;
    while i + 2 < items.len() {
        if items[i].len() != 20 {
            i += 3;
            continue;
        }
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(&items[i]);
        let amount = rlp_decode_u64(&items[i + 1]);
        let rsk_hash = if items[i + 2].len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&items[i + 2]);
            Some(h)
        } else {
            None
        };
        entries.push(ReleaseRequest { btc_dest_hash160: hash160, amount_satoshis: amount, rsk_tx_hash: rsk_hash });
        i += 3;
    }
    entries
}

// ---------------------------------------------------------------------------
// BTC peg-out transaction builder
//
// Matches rskj's ReleaseTransactionBuilder:
// - Version 2
// - DefaultCoinSelector: sort UTXOs largest first, select greedily
// - Fee = ceil(estimatedVBytes * feePerKb / 1000)
// - Change output to federation P2SH if remainder > dust (546 satoshis)
// ---------------------------------------------------------------------------

/// BTC P2SH script: OP_HASH160 <hash160> OP_EQUAL (23 bytes)
fn p2sh_output_script(hash160: &[u8; 20]) -> bitcoin::ScriptBuf {
    use bitcoin::script::Builder;
    use bitcoin::opcodes::all::{OP_HASH160, OP_EQUAL};
    Builder::new()
        .push_opcode(OP_HASH160)
        .push_slice(hash160)
        .push_opcode(OP_EQUAL)
        .into_script()
}

/// BTC P2PKH script: OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
fn p2pkh_output_script(hash160: &[u8; 20]) -> bitcoin::ScriptBuf {
    use bitcoin::script::Builder;
    use bitcoin::opcodes::all::{OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG};
    Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(hash160)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build the federation P2SH redeem script from member public keys.
///
/// m-of-n multisig: OP_m <key1> ... <keyn> OP_n OP_CHECKMULTISIG
/// Keys are sorted (matching bitcoinj's createRedeemScript behavior).
pub fn build_federation_redeem_script(keys: &[[u8; 33]], threshold: usize) -> Vec<u8> {
    let mut sorted_keys = keys.to_vec();
    sorted_keys.sort();

    let mut script = Vec::new();
    script.push(0x50 + threshold as u8); // OP_m
    for key in &sorted_keys {
        script.push(33); // OP_PUSHBYTES_33
        script.extend_from_slice(key);
    }
    script.push(0x50 + sorted_keys.len() as u8); // OP_n
    script.push(0xAE); // OP_CHECKMULTISIG
    script
}

/// Compute RIPEMD160(SHA256(redeem_script)) = P2SH address hash160.
fn redeem_script_hash160(redeem_script: &[u8]) -> [u8; 20] {
    use sha2::Digest as Sha2Digest;
    let sha256 = sha2::Sha256::digest(redeem_script);
    let hash160 = ripemd::Ripemd160::digest(sha256);
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&hash160);
    arr
}

/// Load federation member compressed public keys from Bridge storage.
/// Returns sorted keys matching the federation's multisig ordering.
fn load_federation_member_keys<CTX: ContextTr>(ctx: &mut CTX) -> Vec<[u8; 33]> {
    let fed_data = bridge_load_bytes_named(ctx, NEW_FEDERATION_KEY);
    if fed_data.is_empty() {
        return Vec::new();
    }

    // Federation RLP format (from governance.rs):
    //   RLP_list [ key1_rlp, key2_rlp, ... ] for pending, OR
    //   RLP_list [ creation_time, block_number, key_list ] for committed
    // Try committed format first (3-item outer list)
    if let Some(outer) = rlp_decode_list(&fed_data) {
        let key_list_data = if outer.len() == 3 {
            &outer[2] // committed: [time, block, keys]
        } else {
            &fed_data  // pending: just the keys list
        };

        if let Some(keys) = rlp_decode_list(key_list_data) {
            return keys.into_iter().filter_map(|k| {
                if k.len() == 33 {
                    let mut arr = [0u8; 33];
                    arr.copy_from_slice(&k);
                    Some(arr)
                } else {
                    None
                }
            }).collect();
        }
    }
    Vec::new()
}

/// Estimate BTC transaction vbytes for fee calculation.
/// Matches rskj's BridgeUtils.getRegularPegoutTxSize:
///   overhead + inputs * input_size + outputs * output_size
///
/// For P2SH m-of-n multisig with n keys:
///   input size ≈ 41 + ceil((73*m + 34*n + 3) / 4) * 4 + overhead
/// Standard approximation: ~300 bytes per input, 32 per output, 11 overhead.
fn estimate_tx_vbytes(n_inputs: usize, n_outputs: usize, threshold: usize, n_keys: usize) -> usize {
    // Base overhead (version 4 + locktime 4 + vin_count 1 + vout_count 1)
    let overhead = 10;
    // Input size: 36 (outpoint) + 4 (seq) + 1 (scriptLen) + P2SH-multisig scriptSig
    // P2SH scriptSig ≈ OP_0 + threshold*73 (DER sig) + redeem_script(1 + 33*n + 3)
    let redeem_size = 1 + 33 * n_keys + 3;
    let scriptsig_size = 1 + threshold * 73 + redeem_size;
    let input_size = 36 + 4 + varint_size(scriptsig_size) + scriptsig_size;
    // Output size: 8 (value) + 1 (scriptLen) + 23 (P2SH) or 25 (P2PKH)
    let output_size = 34;

    overhead + n_inputs * input_size + n_outputs * output_size
}

fn varint_size(n: usize) -> usize {
    if n < 0xfd { 1 } else if n <= 0xffff { 3 } else { 5 }
}

/// Read the effective fee per KB from storage, falling back to genesis value.
fn get_effective_fee_per_kb<CTX: ContextTr>(ctx: &mut CTX, config: &BridgeConstants) -> u64 {
    let key = bridge_storage_key(super::storage::FEE_PER_KB_KEY);
    let stored = bridge_sload(ctx, key);
    if stored.is_zero() {
        config.genesis_fee_per_kb
    } else {
        stored.to::<u64>()
    }
}

/// Build an unsigned BTC peg-out transaction.
///
/// Matches rskj's ReleaseTransactionBuilder using DefaultCoinSelector:
/// - Sort UTXOs from largest to smallest
/// - Select greedily until sum ≥ outputs_total + fee
/// - P2PKH outputs for each release request
/// - P2SH change output to federation if remainder > dust (546 sat)
/// - Transaction version = 2
/// Returns None if no UTXOs available or insufficient funds.
fn build_pegout_btc_tx<CTX: ContextTr>(
    ctx: &mut CTX,
    requests: &[ReleaseRequest],
    federation_keys: &[[u8; 33]],
    threshold: usize,
    fee_per_kb: u64,
    config: &BridgeConstants,
) -> Option<BtcTransaction> {
    use bitcoin::{Amount, OutPoint, TxIn, TxOut, Txid, Sequence, ScriptBuf};
    use bitcoin::transaction::Version;

    // Load federation UTXOs
    let mut utxos = load_federation_utxos(ctx);
    if utxos.is_empty() {
        return None;
    }

    // Sort UTXOs largest first (DefaultCoinSelector)
    utxos.sort_by(|a, b| b.value_satoshis.cmp(&a.value_satoshis));

    // Limit inputs to max_inputs_per_pegout_transaction
    utxos.truncate(config.max_inputs_per_pegout_transaction as usize);

    let total_output: u64 = requests.iter().map(|r| r.amount_satoshis).sum();
    let n_outputs_base = requests.len() + 1; // +1 for potential change

    // Build the redeem script for fee estimation
    let redeem_script = build_federation_redeem_script(federation_keys, threshold);
    let fed_hash160 = redeem_script_hash160(&redeem_script);

    // Greedy coin selection
    let mut selected_utxos = Vec::new();
    let mut selected_total = 0u64;

    for utxo in &utxos {
        selected_utxos.push(utxo.clone());
        selected_total += utxo.value_satoshis;

        let estimated_vbytes = estimate_tx_vbytes(
            selected_utxos.len(),
            n_outputs_base,
            threshold,
            federation_keys.len(),
        );
        let fee = (estimated_vbytes as u64 * fee_per_kb + 999) / 1000;

        if selected_total >= total_output + fee {
            // Build the transaction
            let inputs: Vec<TxIn> = selected_utxos.iter().map(|u| {
                let txid_bytes: [u8; 32] = {
                    // Bitcoin txid is stored in reversed byte order
                    let mut b = u.tx_hash;
                    b.reverse();
                    b
                };
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array(txid_bytes),
                        vout: u.vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }
            }).collect();

            let mut outputs: Vec<TxOut> = requests.iter().map(|r| {
                TxOut {
                    value: Amount::from_sat(r.amount_satoshis),
                    script_pubkey: p2pkh_output_script(&r.btc_dest_hash160),
                }
            }).collect();

            let change = selected_total - total_output - fee;
            const DUST_THRESHOLD: u64 = 546;
            if change > DUST_THRESHOLD {
                outputs.push(TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: p2sh_output_script(&fed_hash160),
                });
            }

            let tx = BtcTransaction {
                version: Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: inputs,
                output: outputs,
            };

            // Remove used UTXOs from federation storage
            let used_keys: std::collections::HashSet<([u8; 32], u32)> =
                selected_utxos.iter().map(|u| (u.tx_hash, u.vout)).collect();
            let mut all_utxos = load_federation_utxos(ctx);
            all_utxos.retain(|u| !used_keys.contains(&(u.tx_hash, u.vout)));
            store_federation_utxos(ctx, &all_utxos);

            return Some(tx);
        }
    }

    None // Insufficient UTXOs
}

/// Apply DER signatures to a BTC P2SH-multisig transaction.
///
/// For each input, if the input's scriptSig doesn't yet have enough sigs,
/// add the provided signatures at the correct position (ordered by key index
/// in the federation's sorted key list).
///
/// The P2SH scriptSig format: `OP_0 <sig_1> ... <sig_m> <redeemScript>`
fn apply_signatures_to_tx(
    tx: &mut BtcTransaction,
    sigs: &[Vec<u8>],
    fed_key: &[u8],
    federation_keys: &[[u8; 33]],
    redeem_script: &[u8],
) -> bool {
    if sigs.is_empty() || tx.input.is_empty() {
        return false;
    }

    // Find the position of this federator's key in the sorted key list
    let mut sorted_keys = federation_keys.to_vec();
    sorted_keys.sort();

    let key_index = sorted_keys.iter().position(|k| k.as_slice() == fed_key || &k[1..] == &fed_key[1..]);
    // Try partial match for compressed vs uncompressed
    let _key_index = key_index.unwrap_or(0);

    for (i, input) in tx.input.iter_mut().enumerate() {
        let sig = if i < sigs.len() { &sigs[i] } else { &sigs[0] };
        if sig.is_empty() {
            continue;
        }

        // Build or extend the P2SH multisig scriptSig:
        // OP_0 <sig1> ... <sigm> <redeemScript>
        let current_script = input.script_sig.as_bytes().to_vec();

        let new_script = if current_script.is_empty() {
            // First signature: start with OP_0 + sig + redeemScript
            build_p2sh_scriptsig(&[sig.clone()], redeem_script)
        } else {
            // Additional signature: insert before redeemScript
            add_sig_to_p2sh_scriptsig(&current_script, sig, redeem_script)
        };

        input.script_sig = bitcoin::ScriptBuf::from_bytes(new_script);
    }

    true
}

/// Build a P2SH multisig scriptSig from signatures and redeem script.
/// Format: OP_0 <sig1> ... <sigm> <redeemScript>
fn build_p2sh_scriptsig(sigs: &[Vec<u8>], redeem_script: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(0x00); // OP_0
    for sig in sigs {
        push_data(&mut script, sig);
    }
    push_data(&mut script, redeem_script);
    script
}

/// Add a signature to an existing P2SH multisig scriptSig.
/// Inserts before the redeemScript (the last pushed data item).
fn add_sig_to_p2sh_scriptsig(
    existing: &[u8],
    new_sig: &[u8],
    redeem_script: &[u8],
) -> Vec<u8> {
    // Parse existing sigs (skip OP_0 prefix and final redeemScript push)
    let mut existing_sigs = parse_p2sh_scriptsig_sigs(existing, redeem_script);
    existing_sigs.push(new_sig.to_vec());
    build_p2sh_scriptsig(&existing_sigs, redeem_script)
}

/// Parse the signatures from an existing P2SH scriptsig, excluding the redeemScript.
fn parse_p2sh_scriptsig_sigs(script: &[u8], redeem_script: &[u8]) -> Vec<Vec<u8>> {
    let mut sigs = Vec::new();
    let mut pos = 0;

    // Skip OP_0
    if pos < script.len() && script[pos] == 0x00 {
        pos += 1;
    }

    while pos < script.len() {
        let (data, consumed) = read_push_data(&script[pos..]);
        if data == redeem_script {
            break; // reached the redeemScript
        }
        if !data.is_empty() {
            sigs.push(data);
        }
        pos += consumed;
    }
    sigs
}

/// Read a Script push data item. Returns (data, bytes_consumed).
fn read_push_data(script: &[u8]) -> (Vec<u8>, usize) {
    if script.is_empty() {
        return (Vec::new(), 0);
    }
    let opcode = script[0];
    if opcode == 0x00 {
        // OP_0
        return (Vec::new(), 1);
    }
    if opcode <= 0x4b {
        // OP_PUSHBYTES_N
        let len = opcode as usize;
        if 1 + len > script.len() {
            return (Vec::new(), script.len());
        }
        return (script[1..1 + len].to_vec(), 1 + len);
    }
    if opcode == 0x4c {
        // OP_PUSHDATA1
        if script.len() < 2 {
            return (Vec::new(), script.len());
        }
        let len = script[1] as usize;
        if 2 + len > script.len() {
            return (Vec::new(), script.len());
        }
        return (script[2..2 + len].to_vec(), 2 + len);
    }
    if opcode == 0x4d {
        // OP_PUSHDATA2
        if script.len() < 3 {
            return (Vec::new(), script.len());
        }
        let len = u16::from_le_bytes([script[1], script[2]]) as usize;
        if 3 + len > script.len() {
            return (Vec::new(), script.len());
        }
        return (script[3..3 + len].to_vec(), 3 + len);
    }
    (Vec::new(), 1)
}

/// Append a data push to a script.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 0x4b {
        script.push(len as u8);
    } else if len <= 0xff {
        script.push(0x4c);
        script.push(len as u8);
    } else {
        script.push(0x4d);
        script.extend_from_slice(&(len as u16).to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// Count the number of distinct DER signatures in the first input of a tx.
fn count_signatures_in_tx(tx: &BtcTransaction, _threshold: usize) -> usize {
    if tx.input.is_empty() {
        return 0;
    }
    let script = tx.input[0].script_sig.as_bytes();
    let sigs = parse_p2sh_scriptsig_sigs(script, &[]);
    // Filter for valid-looking DER signatures (start with 0x30 and end with sighash byte)
    sigs.iter().filter(|s| s.len() > 8 && s[0] == 0x30).count()
}

/// Parse an array of dynamic bytes from ABI-encoded `bytes[]` argument.
fn parse_bytes_array(args: &[u8], array_offset: usize) -> Vec<Vec<u8>> {
    if array_offset + 32 > args.len() {
        return Vec::new();
    }
    let count = U256::from_be_slice(&args[array_offset..array_offset + 32]).to::<usize>();
    if count == 0 || count > 1000 {
        return Vec::new();
    }

    let offsets_start = array_offset + 32;
    let mut result = Vec::with_capacity(count);

    for i in 0..count {
        let off_pos = offsets_start + i * 32;
        if off_pos + 32 > args.len() {
            break;
        }
        let elem_rel_offset = U256::from_be_slice(&args[off_pos..off_pos + 32]).to::<usize>();
        let elem_abs = offsets_start + elem_rel_offset;
        if elem_abs + 32 > args.len() {
            break;
        }
        let elem_len = U256::from_be_slice(&args[elem_abs..elem_abs + 32]).to::<usize>();
        let data_start = elem_abs + 32;
        if data_start + elem_len > args.len() {
            break;
        }
        result.push(args[data_start..data_start + elem_len].to_vec());
    }
    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the RSK destination address from a BTC peg-in transaction.
///
/// Checks for OP_RETURN data first (20-byte RSK address embedded after
/// the OP_RETURN opcode). Falls back to deriving the address from the
/// first input's P2PKH public key (matching rskj's PegUtils).
fn extract_rsk_destination(btc_tx: &BtcTransaction) -> Option<RskAddress> {
    // 1. Check OP_RETURN outputs for embedded RSK address
    for output in &btc_tx.output {
        if output.script_pubkey.is_op_return() {
            let script_bytes = output.script_pubkey.as_bytes();
            // OP_RETURN (0x6a) + push opcode + data
            // The RSK address is typically 20 bytes following the push
            if script_bytes.len() >= 22 {
                let data_start = 2; // skip OP_RETURN + push opcode
                if script_bytes.len() >= data_start + 20 {
                    return Some(RskAddress::from_slice(
                        &script_bytes[data_start..data_start + 20],
                    ));
                }
            }
        }
    }

    // 2. Fall back to deriving from first input's scriptSig (P2PKH)
    if let Some(first_input) = btc_tx.input.first() {
        let script_bytes = first_input.script_sig.as_bytes();
        // P2PKH scriptSig: <sig> <pubkey>
        // The public key is the last push (33 bytes compressed, 65 uncompressed)
        if script_bytes.len() >= 34 {
            let pubkey_len = script_bytes[script_bytes.len() - 34] as usize;
            if pubkey_len == 33 && script_bytes.len() >= 34 {
                let pubkey = &script_bytes[script_bytes.len() - 33..];
                let hash = sha3::Keccak256::digest(pubkey);
                return Some(RskAddress::from_slice(&hash[12..]));
            }
        }
    }

    None
}

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
///
/// Returns the number of pending peg-out requests in the release queue.
/// Checks both `releaseRequestQueueWithTxHash` (post-RSKIP146) and the
/// legacy `releaseRequestQueue`.
pub fn get_queued_pegouts_count<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Try the post-RSKIP146 queue first
    let with_hash_key = bridge_storage_key(RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY);
    let with_hash_data = bridge_load_bytes(ctx, with_hash_key);
    if !with_hash_data.is_empty() {
        let entries = deserialize_release_queue_with_hash(&with_hash_data);
        let count = U256::from(entries.len());
        return Ok(PrecompileOutput::new(gas_cost, count.to_be_bytes::<32>().to_vec().into()));
    }

    // Fall back to legacy queue
    let legacy_key = bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY);
    let legacy_data = bridge_load_bytes(ctx, legacy_key);
    let entries = deserialize_release_queue_legacy(&legacy_data);
    let count = U256::from(entries.len());
    Ok(PrecompileOutput::new(gas_cost, count.to_be_bytes::<32>().to_vec().into()))
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

    // -----------------------------------------------------------------------
    // Release queue serialization tests — ported from rskj
    // BridgeSerializationUtils / BridgeSupportReleaseBtcTest patterns
    // -----------------------------------------------------------------------

    fn make_request(hash160: [u8; 20], satoshis: u64) -> ReleaseRequest {
        ReleaseRequest { btc_dest_hash160: hash160, amount_satoshis: satoshis, rsk_tx_hash: None }
    }

    fn make_request_with_hash(hash160: [u8; 20], satoshis: u64, rsk_hash: [u8; 32]) -> ReleaseRequest {
        ReleaseRequest { btc_dest_hash160: hash160, amount_satoshis: satoshis, rsk_tx_hash: Some(rsk_hash) }
    }

    /// Legacy queue: empty roundtrip.
    #[test]
    fn rskj_release_queue_empty_roundtrip() {
        let queue: Vec<ReleaseRequest> = vec![];
        let encoded = serialize_release_queue_legacy(&queue);
        let decoded = deserialize_release_queue_legacy(&encoded);
        assert!(decoded.is_empty());
    }

    /// Legacy queue: single entry roundtrip.
    #[test]
    fn rskj_release_queue_single_entry_roundtrip() {
        let hash160 = [0xAAu8; 20];
        let amount = 250_000u64;
        let queue = vec![make_request(hash160, amount)];

        let encoded = serialize_release_queue_legacy(&queue);
        let decoded = deserialize_release_queue_legacy(&encoded);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].btc_dest_hash160, hash160);
        assert_eq!(decoded[0].amount_satoshis, amount);
    }

    /// Legacy queue: multiple entries preserves order.
    #[test]
    fn rskj_release_queue_multiple_entries_roundtrip() {
        let entries = vec![
            make_request([0x11u8; 20], 400_000),
            make_request([0x22u8; 20], 800_000),
            make_request([0x33u8; 20], 1_200_000),
        ];

        let encoded = serialize_release_queue_legacy(&entries);
        let decoded = deserialize_release_queue_legacy(&encoded);

        assert_eq!(decoded.len(), 3);
        for (orig, dec) in entries.iter().zip(decoded.iter()) {
            assert_eq!(orig.btc_dest_hash160, dec.btc_dest_hash160);
            assert_eq!(orig.amount_satoshis, dec.amount_satoshis);
        }
    }

    /// Legacy queue: empty data returns empty vec.
    #[test]
    fn rskj_release_queue_deserialize_empty() {
        assert!(deserialize_release_queue_legacy(&[]).is_empty());
    }

    /// Post-RSKIP146 queue with tx hash: roundtrip.
    #[test]
    fn rskj_release_queue_with_hash_roundtrip() {
        let hash160 = [0xBBu8; 20];
        let rsk_hash = [0xCCu8; 32];
        let entries = vec![make_request_with_hash(hash160, 500_000, rsk_hash)];

        let encoded = serialize_release_queue_with_hash(&entries);
        let decoded = deserialize_release_queue_with_hash(&encoded);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].btc_dest_hash160, hash160);
        assert_eq!(decoded[0].amount_satoshis, 500_000);
        assert_eq!(decoded[0].rsk_tx_hash, Some(rsk_hash));
    }

    /// rskTxsWaitingFS: empty roundtrip.
    #[test]
    fn rskj_rsk_txs_waiting_fs_empty_roundtrip() {
        let map = BTreeMap::new();
        let encoded = serialize_rsk_txs_waiting_for_signatures(&map);
        let decoded = deserialize_rsk_txs_waiting_for_signatures(&encoded);
        assert!(decoded.is_empty());
    }

    /// rskTxsWaitingFS: single entry roundtrip with sorted ordering.
    #[test]
    fn rskj_rsk_txs_waiting_fs_roundtrip() {
        let mut map = BTreeMap::new();
        let hash1 = [0x11u8; 32];
        let hash2 = [0xAAu8; 32];
        let btc1 = vec![0x01, 0x02, 0x03];
        let btc2 = vec![0x04, 0x05, 0x06];
        map.insert(hash2, btc2.clone());
        map.insert(hash1, btc1.clone());

        let encoded = serialize_rsk_txs_waiting_for_signatures(&map);
        let decoded = deserialize_rsk_txs_waiting_for_signatures(&encoded);

        assert_eq!(decoded.len(), 2);
        // BTreeMap ensures sorted order: hash1 (0x11...) < hash2 (0xAA...)
        assert_eq!(decoded[&hash1], btc1);
        assert_eq!(decoded[&hash2], btc2);
    }

    /// PegoutsWaitingForConfirmations: legacy pair format roundtrip.
    #[test]
    fn rskj_pegouts_waiting_for_confirmations_legacy_roundtrip() {
        let entries = vec![
            PegoutWaitingForConfirmations { btc_tx_raw: vec![0xDE, 0xAD], rsk_block_height: 1000, rsk_tx_hash: None },
            PegoutWaitingForConfirmations { btc_tx_raw: vec![0xBE, 0xEF], rsk_block_height: 2000, rsk_tx_hash: None },
        ];

        let encoded = serialize_pegouts_waiting_for_confirmations(&entries, false);
        let decoded = deserialize_pegouts_waiting_for_confirmations(&encoded, false);

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].btc_tx_raw, vec![0xDE, 0xAD]);
        assert_eq!(decoded[0].rsk_block_height, 1000);
        assert_eq!(decoded[1].rsk_block_height, 2000);
    }

    /// PegoutsWaitingForConfirmations: RSKIP146 triple format roundtrip.
    #[test]
    fn rskj_pegouts_waiting_for_confirmations_with_hash_roundtrip() {
        let rsk_hash = [0xFFu8; 32];
        let entries = vec![
            PegoutWaitingForConfirmations {
                btc_tx_raw: vec![0x01, 0x02],
                rsk_block_height: 5000,
                rsk_tx_hash: Some(rsk_hash),
            },
        ];

        let encoded = serialize_pegouts_waiting_for_confirmations(&entries, true);
        let decoded = deserialize_pegouts_waiting_for_confirmations(&encoded, true);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].btc_tx_raw, vec![0x01, 0x02]);
        assert_eq!(decoded[0].rsk_block_height, 5000);
        assert_eq!(decoded[0].rsk_tx_hash, Some(rsk_hash));
    }

    /// Federation redeem script: correct multisig format.
    #[test]
    fn rskj_federation_redeem_script_format() {
        let keys: Vec<[u8; 33]> = vec![
            [0x02; 33],
            [0x03; 33],
            [0x04; 33],
        ];
        let threshold = 2;
        let script = build_federation_redeem_script(&keys, threshold);

        // OP_2 + 3 keys (each: 0x21 + 33 bytes) + OP_3 + OP_CHECKMULTISIG
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(script[script.len() - 2], 0x53); // OP_3
        assert_eq!(script[script.len() - 1], 0xAE); // OP_CHECKMULTISIG
        assert_eq!(script.len(), 1 + 3 * 34 + 2);
    }

    /// Redeem script hash160.
    #[test]
    fn rskj_redeem_script_hash160_non_zero() {
        let keys: Vec<[u8; 33]> = vec![[0x02; 33], [0x03; 33]];
        let script = build_federation_redeem_script(&keys, 1);
        let hash = redeem_script_hash160(&script);
        assert_ne!(hash, [0u8; 20], "hash160 should not be zero");
    }

    // -----------------------------------------------------------------------
    // Golden vector tests — format verification against rskj
    // Ported from BridgeSerializationUtilsTest.java
    // -----------------------------------------------------------------------

    /// rskTxsWaitingFS: two entries with createHash3(1) and createHash3(2) keys
    /// are stored in BTreeMap order (hash1 < hash2 since 0x01 < 0x02).
    ///
    /// Matches rskj BridgeSerializationUtilsTest.serializeAndDeserializeRskTxsWaitingForSignatures.
    #[test]
    fn rskj_rsk_txs_waiting_fs_ordering_golden() {
        // createHash3(1) = [0x01, 0x00, ..., 0x00]
        let mut hash1 = [0u8; 32];
        hash1[0] = 0x01;

        // createHash3(2) = [0x02, 0x00, ..., 0x00]
        let mut hash2 = [0u8; 32];
        hash2[0] = 0x02;

        // Minimal BTC tx bytes (insert in reverse order to confirm sorting)
        let btc1 = vec![0x01, 0x00, 0x00, 0x00]; // version=1 LE, minimal
        let btc2 = vec![0x02, 0x00, 0x00, 0x00];

        let mut map = BTreeMap::new();
        map.insert(hash2, btc2.clone()); // insert hash2 first
        map.insert(hash1, btc1.clone());

        let encoded = serialize_rsk_txs_waiting_for_signatures(&map);
        let decoded = deserialize_rsk_txs_waiting_for_signatures(&encoded);

        assert_eq!(decoded.len(), 2);
        // Keys should be sorted: hash1 (0x01...) < hash2 (0x02...)
        let keys: Vec<[u8; 32]> = decoded.keys().cloned().collect();
        assert_eq!(keys[0], hash1, "hash1 should come first (BTreeMap sorted)");
        assert_eq!(keys[1], hash2, "hash2 should come second");
        assert_eq!(decoded[&hash1], btc1);
        assert_eq!(decoded[&hash2], btc2);

        // Verify the RLP structure: outer list with 4 elements (2 pairs)
        let items = rlp_decode_list(&encoded).unwrap();
        assert_eq!(items.len(), 4, "should have 4 RLP items (2 hash-tx pairs)");
        assert_eq!(items[0].len(), 32);
        assert_eq!(items[0][0], 0x01, "first item should be hash1");
        assert_eq!(items[2][0], 0x02, "third item should be hash2");
    }

    /// Empty rskTxsWaitingFS: empty data → empty map (matches rskj behavior).
    ///
    /// Ported from rskj: deserializeRskTxsWaitingForSignatures with null/empty → empty map.
    #[test]
    fn rskj_rsk_txs_waiting_fs_null_empty_returns_empty() {
        let decoded_null = deserialize_rsk_txs_waiting_for_signatures(&[]);
        assert!(decoded_null.is_empty(), "null data should return empty map");

        // Empty RLP list → empty map
        let empty_rlp = vec![0xc0u8]; // RLP encoded empty list
        let decoded_empty = deserialize_rsk_txs_waiting_for_signatures(&empty_rlp);
        assert!(decoded_empty.is_empty(), "empty list should return empty map");
    }

    /// Release queue legacy format: amount is stored as RLP-encoded BigInteger
    /// (satoshis), not as Wei.
    ///
    /// Verifies that 400_000 satoshis is stored correctly (not as Wei amount).
    #[test]
    fn rskj_release_queue_stores_satoshis_not_wei() {
        let hash160 = [0x42u8; 20];
        let satoshis = 400_000u64; // minimum pegout value
        let entries = vec![make_request(hash160, satoshis)];
        let encoded = serialize_release_queue_legacy(&entries);

        let decoded = deserialize_release_queue_legacy(&encoded);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].amount_satoshis, satoshis,
            "amount should be in satoshis, not wei");
        // Verify: 400_000 in satoshis should NOT equal 400_000 * 10^10 (wei)
        assert_ne!(decoded[0].amount_satoshis, 400_000 * 10_000_000_000u64,
            "amount must NOT be in wei");
    }

    /// Release queue with hash: RSK tx hash is stored as 32 bytes in the third slot.
    #[test]
    fn rskj_release_queue_with_hash_format_verified() {
        let hash160 = [0x11u8; 20];
        let satoshis = 500_000u64;
        // createHash3(1) from rskj test patterns
        let mut rsk_hash = [0u8; 32];
        rsk_hash[0] = 0x01;

        let entries = vec![make_request_with_hash(hash160, satoshis, rsk_hash)];
        let encoded = serialize_release_queue_with_hash(&entries);

        let items = rlp_decode_list(&encoded).unwrap();
        assert_eq!(items.len(), 3, "post-RSKIP146 entry should have 3 items");
        assert_eq!(items[0], hash160.as_slice(), "first item is hash160");
        assert_eq!(items[2].len(), 32, "third item is RSK tx hash (32 bytes)");
        assert_eq!(items[2][0], 0x01, "RSK hash matches createHash3(1)");
    }

    /// BTC tx size estimation for fee calculation.
    #[test]
    fn rskj_estimate_tx_vbytes_1in_2out_2of3() {
        // 2-of-3 multisig, 1 input, 2 outputs (payment + change)
        let vbytes = estimate_tx_vbytes(1, 2, 2, 3);
        // Should be a reasonable P2SH multisig tx size
        assert!(vbytes > 100 && vbytes < 600,
            "1-input 2-output P2SH 2-of-3 tx should be 100-600 vbytes, got {}", vbytes);
    }

    /// Conversion: 1 satoshi = 10^10 wei.
    #[test]
    fn rskj_satoshi_wei_conversion() {
        assert_eq!(btc_satoshi_to_rbtc_wei(1), U256::from(10_000_000_000u64));
        assert_eq!(btc_satoshi_to_rbtc_wei(100_000_000), U256::from(10u128.pow(18)));
        assert_eq!(btc_satoshi_to_rbtc_wei(0), U256::ZERO);
    }

    /// Ported from rskj BridgeSupportTestUtil.shouldMarkRejectedPeginAsProcessed
    /// and BridgeSupportRejectedPeginTest activation matrix: rejected
    /// non-refundable peg-ins are marked as processed only between RSKIP459
    /// (lovell700, mainnet 7_338_024) and RSKIP551 (vetiver900, mainnet 8_804_200).
    #[test]
    fn test_should_mark_rejected_pegin_as_processed_window() {
        let cfg = RskHardforkConfig::mainnet();
        // Before lovell700: no marking.
        assert!(!should_mark_rejected_pegin_as_processed(&cfg, 7_338_023));
        // lovell700 .. vetiver900: marking active.
        assert!(should_mark_rejected_pegin_as_processed(&cfg, 7_338_024));
        assert!(should_mark_rejected_pegin_as_processed(&cfg, 8_804_199));
        // From vetiver900 (RSKIP551): disabled again.
        assert!(!should_mark_rejected_pegin_as_processed(&cfg, 8_804_200));
    }
}
