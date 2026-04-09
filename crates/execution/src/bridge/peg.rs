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

use alloy_primitives::{Address as RskAddress, Bytes, U256};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::Transaction as BtcTransaction;
use revm::context_interface::{ContextTr, JournalTr};
use revm::precompile::{PrecompileError, PrecompileOutput};

use sha3::Digest;

use super::btc_chain::b256_to_bitcoin_hash;
use super::btc_store::{get_stored_block, load_chain_head};
use super::constants::BridgeConstants;
use super::pmt::PartialMerkleTree;
use super::storage::*;
use super::tx::*;
use crate::precompiles::BRIDGE_ADDR;

/// A pending peg-out release request.
#[derive(Debug, Clone)]
pub struct ReleaseRequest {
    pub rsk_address: RskAddress,
    pub amount: U256,
}

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

    // Enforce minimum peg-in value
    if total_value < config.minimum_pegin_tx_value {
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
///
/// Matches rskj's `BridgeSupport.releaseBtc()`:
/// - Reads the call value from the Bridge's received balance delta
/// - Validates minimum peg-out amount
/// - Queues the release request with (rskAddress, amount)
/// - The queue is serialized as RLP and stored in multi-slot Bridge storage
pub fn release_btc<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    // Read the call value from the transaction environment.
    // In the precompile context, msg.value has already been transferred
    // to the Bridge address by revm. We read it from the tx env.
    let call_value = revm::context_interface::Transaction::value(ctx.tx());

    if call_value.is_zero() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Enforce minimum pegout value (convert satoshis to wei)
    let min_value_wei = U256::from(config.minimum_pegout_tx_value) * U256::from(10_000_000_000u64);
    if call_value < min_value_wei {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Get the caller (msg.sender) for the release request
    let caller = revm::context_interface::Transaction::caller(ctx.tx());

    // Load existing queue, append new entry, store back
    let queue_key = bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY);
    let existing_data = bridge_load_bytes(ctx, queue_key);
    let mut queue = deserialize_release_queue(&existing_data);
    queue.push(ReleaseRequest {
        rsk_address: caller,
        amount: call_value,
    });
    let updated = serialize_release_queue(&queue);
    bridge_store_bytes(ctx, queue_key, &updated);

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
/// This implementation reads the release request queue from multi-slot
/// storage and processes any pending entries by moving them to the
/// waiting-for-confirmations set. Full BTC transaction construction
/// and UTXO management are deferred.
pub fn update_collections<CTX: ContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    _config: &BridgeConstants,
) -> Result<PrecompileOutput, PrecompileError> {
    let queue_key = bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY);
    let queue_data = bridge_load_bytes(ctx, queue_key);

    if !queue_data.is_empty() {
        // Move pending entries to "waiting for confirmations"
        let waiting_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
        let mut existing_waiting = bridge_load_bytes(ctx, waiting_key);
        existing_waiting.extend_from_slice(&queue_data);
        bridge_store_bytes(ctx, waiting_key, &existing_waiting);

        // Clear the release queue
        bridge_store_bytes(ctx, queue_key, &[]);
    }

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
/// Parses the arguments and stores the signature. Full signature threshold
/// checking and BTC tx finalization require federation key management.
pub fn add_signature<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 96 {
        return Err(PrecompileError::other("addSignature: args too short"));
    }

    // arg0: bytes federatorPublicKey (dynamic)
    // arg1: bytes[] signatures (dynamic array)
    // arg2: bytes rskTxHash (dynamic)
    let _fed_key_offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    let _sigs_offset = U256::from_be_slice(&args[32..64]).to::<usize>();
    let rsk_tx_hash_offset = U256::from_be_slice(&args[64..96]).to::<usize>();

    // Read the RSK tx hash
    if rsk_tx_hash_offset + 32 <= args.len() {
        let len = U256::from_be_slice(&args[rsk_tx_hash_offset..rsk_tx_hash_offset + 32]).to::<usize>();
        if len == 32 && rsk_tx_hash_offset + 64 <= args.len() {
            let mut rsk_tx_hash = [0u8; 32];
            rsk_tx_hash.copy_from_slice(&args[rsk_tx_hash_offset + 32..rsk_tx_hash_offset + 64]);
            // Track that a signature was added for this tx
            let hash_hex = to_hex(&rsk_tx_hash);
            let sig_key = compound_key(PEGOUT_TX_SIG_HASH_KEY, "-", &hash_hex);
            let count = bridge_sload(ctx, sig_key);
            bridge_sstore(ctx, sig_key, count.wrapping_add(U256::from(1)));
        }
    }

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
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

/// Serialize the release request queue as an RLP list.
/// Each entry: RLP([rskAddress(20 bytes), amount(BE trimmed bytes)]).
fn serialize_release_queue(entries: &[ReleaseRequest]) -> Vec<u8> {
    use super::serialization::{rlp_encode_element, rlp_encode_list};

    let mut items = Vec::new();
    for entry in entries {
        let amount_bytes = u256_to_trimmed_be(&entry.amount);
        let entry_items = vec![
            rlp_encode_element(entry.rsk_address.as_slice()),
            rlp_encode_element(&amount_bytes),
        ];
        items.push(rlp_encode_list(&entry_items));
    }
    rlp_encode_list(&items)
}

/// Deserialize the release request queue from RLP.
fn deserialize_release_queue(data: &[u8]) -> Vec<ReleaseRequest> {
    use super::serialization::rlp_decode_list;

    if data.is_empty() {
        return Vec::new();
    }

    let outer = match rlp_decode_list(data) {
        Some(items) => items,
        None => return Vec::new(),
    };

    let mut entries = Vec::new();
    for entry_rlp in &outer {
        let fields = match rlp_decode_list(entry_rlp) {
            Some(f) => f,
            None => continue,
        };
        if fields.len() < 2 { continue; }

        let addr = if fields[0].len() == 20 {
            RskAddress::from_slice(&fields[0])
        } else {
            continue;
        };

        let amount = if fields[1].is_empty() {
            U256::ZERO
        } else {
            U256::from_be_slice(&fields[1])
        };

        entries.push(ReleaseRequest {
            rsk_address: addr,
            amount,
        });
    }
    entries
}

/// Trim leading zero bytes from a U256's big-endian representation.
fn u256_to_trimmed_be(val: &U256) -> Vec<u8> {
    let bytes = val.to_be_bytes::<32>();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    bytes[start..].to_vec()
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

    // -----------------------------------------------------------------------
    // Release queue serialization tests — ported from rskj
    // BridgeSerializationUtilsTest / BridgeSupportReleaseBtcTest patterns
    // -----------------------------------------------------------------------

    /// Roundtrip: serialize → deserialize an empty release queue.
    #[test]
    fn rskj_release_queue_empty_roundtrip() {
        let queue: Vec<ReleaseRequest> = vec![];
        let encoded = serialize_release_queue(&queue);
        let decoded = deserialize_release_queue(&encoded);
        assert!(decoded.is_empty());
    }

    /// Roundtrip: single entry in release queue.
    #[test]
    fn rskj_release_queue_single_entry_roundtrip() {
        let addr = RskAddress::repeat_byte(0xAA);
        let amount = U256::from(250_000u64) * U256::from(10_000_000_000u64); // min pegout in wei
        let queue = vec![ReleaseRequest { rsk_address: addr, amount }];

        let encoded = serialize_release_queue(&queue);
        let decoded = deserialize_release_queue(&encoded);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rsk_address, addr);
        assert_eq!(decoded[0].amount, amount);
    }

    /// Roundtrip: multiple entries preserves order.
    #[test]
    fn rskj_release_queue_multiple_entries_roundtrip() {
        let entries = vec![
            ReleaseRequest {
                rsk_address: RskAddress::repeat_byte(0x11),
                amount: U256::from(1_000_000u64),
            },
            ReleaseRequest {
                rsk_address: RskAddress::repeat_byte(0x22),
                amount: U256::from(2_000_000u64),
            },
            ReleaseRequest {
                rsk_address: RskAddress::repeat_byte(0x33),
                amount: U256::from(3_000_000u64),
            },
        ];

        let encoded = serialize_release_queue(&entries);
        let decoded = deserialize_release_queue(&encoded);

        assert_eq!(decoded.len(), 3);
        for (orig, dec) in entries.iter().zip(decoded.iter()) {
            assert_eq!(orig.rsk_address, dec.rsk_address);
            assert_eq!(orig.amount, dec.amount);
        }
    }

    /// Deserializing empty/null data yields empty queue (matching rskj behavior).
    #[test]
    fn rskj_release_queue_deserialize_empty() {
        assert!(deserialize_release_queue(&[]).is_empty());
    }

    /// Verify U256 trimming: large values preserve full precision.
    #[test]
    fn rskj_release_queue_large_amount_roundtrip() {
        let amount = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));
        let queue = vec![ReleaseRequest {
            rsk_address: RskAddress::repeat_byte(0xFF),
            amount,
        }];

        let encoded = serialize_release_queue(&queue);
        let decoded = deserialize_release_queue(&encoded);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].amount, amount, "21M RBTC should survive roundtrip");
    }
}
