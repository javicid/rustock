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

    // A fresh bridge BTC store must be seeded with the rskj checkpoint
    // before any chain lookups.
    {
        let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
        let use_v2 = hardfork_cfg.has_stored_block_v2(block_number);
        super::btc_chain::ensure_btc_chain_seeded(ctx, config, use_v2);
    }

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

    // Check confirmations (rskj BridgeUtils.validateHeightAndConfirmations:
    // the block itself counts as one confirmation, and the CALLER-supplied
    // height is what gets validated).
    let chain_head = load_chain_head(ctx);
    let best_height = chain_head.map(|h| h.height).unwrap_or(0);
    let confirmations = best_height as i64 - btc_block_height as i64 + 1;
    if confirmations < config.btc2rsk_minimum_acceptable_confirmations as i64 {
        return Err(PrecompileError::other(
            "registerBtcTransaction: insufficient confirmations",
        ));
    }

    // Parse the BTC transaction
    let btc_tx: BtcTransaction = deserialize(&btc_tx_data).map_err(|_| {
        PrecompileError::other("registerBtcTransaction: invalid BTC transaction")
    })?;

    // The active federation's P2SH script identifies which outputs are
    // peg-ins and which inputs make the tx a peg-out.
    let federation_keys = federation_keys_or_genesis(ctx, config);
    let threshold = (federation_keys.len() / 2) + 1;
    let fed_redeem = build_federation_redeem_script(&federation_keys, threshold);
    let fed_script = p2sh_output_script(&redeem_script_hash160(&fed_redeem));

    // rskj marks processed txs with the RSK execution block number
    // (BridgeSupport.markTxAsProcessed), not the BTC block height.
    let rsk_height = revm::context_interface::Block::number(ctx.block()).to::<u64>();

    // rskj BridgeUtils.isPegOutTx: an input spends the federation's P2SH
    // (its scriptSig carries the federation redeem script). Peg-outs are
    // registered to reclaim the change UTXOs; nothing is credited.
    let is_pegout = btc_tx.input.iter().any(|i| {
        super::release_tx::extract_redeem_script(i.script_sig.as_bytes())
            .is_some_and(|r| r == fed_redeem)
    });
    if is_pegout {
        register_new_utxos(ctx, &btc_tx, &fed_script);
        set_btc_tx_processed(ctx, &btc_tx_hash, rsk_height);
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Peg-in value: only the outputs paying the federation
    // (rskj computeTotalAmountSent over the federation wallet).
    let total_value: u64 = btc_tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == fed_script)
        .map(|o| o.value.to_sat())
        .sum();
    if total_value == 0 {
        // Neither a peg-in nor a peg-out for the active federation: ignore
        // without marking as processed (rskj logs and returns).
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Enforce minimum peg-in value (legacy minimum until RSKIP219,
    // strictly-below comparison per PegUtilsLegacy.isValidPegInTx).
    let min_pegin = if hardfork_cfg.has_rskip219(rsk_height) {
        config.minimum_pegin_tx_value
    } else {
        config.legacy_minimum_pegin_tx_value
    };
    if total_value < min_pegin {
        if should_mark_rejected_pegin_as_processed(hardfork_cfg, rsk_height) {
            set_btc_tx_processed(ctx, &btc_tx_hash, rsk_height);
        }
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Legacy (protocol v0) peg-ins require a P2PKH sender; without one the
    // sender is undetermined and rskj aborts without marking as processed.
    let Some(sender_pubkey) = btc_sender_pubkey(&btc_tx) else {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    };
    let sender_hash160 = pubkey_hash160(&sender_pubkey);

    // Lock whitelist gate (rskj verifyLockSenderIsWhitelisted): the matching
    // one-off entry is consumed on success; rejection generates a refund
    // peg-out back to the sender (generateRejectionRelease).
    let wl_allowed = whitelist_allows_and_consume(ctx, &sender_hash160, total_value, btc_block_height);
    tracing::debug!(
        "pegin whitelist check: sender {} amount {} btc_height {} -> {}",
        to_hex(&sender_hash160),
        total_value,
        btc_block_height,
        wl_allowed
    );
    if !wl_allowed {
        let pegin_utxos: Vec<BridgeUtxo> = btc_tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey == fed_script)
            .map(|(index, o)| BridgeUtxo {
                tx_hash: btc_txid_event_bytes(&btc_tx),
                vout: index as u32,
                value_satoshis: o.value.to_sat(),
                height: 0,
                script: o.script_pubkey.to_bytes(),
                coinbase: btc_tx.is_coinbase(),
            })
            .collect();
        let fee_per_kb = get_effective_fee_per_kb(ctx, config);
        let tx_version = if hardfork_cfg.has_rskip201(rsk_height) { 2 } else { 1 };
        let refund_script = p2pkh_output_script(&sender_hash160);
        let built = super::release_tx::build_empty_wallet_to(
            &pegin_utxos,
            &refund_script,
            &fed_redeem,
            fee_per_kb,
            tx_version,
        );
        tracing::debug!(
            "pegin rejection release: utxos {} fee_per_kb {} built {:?}",
            pegin_utxos.len(),
            fee_per_kb,
            built.as_ref().map(|b| b.tx.compute_txid().to_string())
        );
        if let Some(built) = built {
            let use_tx_hash = hardfork_cfg.has_rskip146(rsk_height);
            let waiting_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
            let existing = bridge_load_bytes(ctx, waiting_key);
            let mut waiting = deserialize_pegouts_waiting_for_confirmations(&existing, use_tx_hash);
            waiting.push(PegoutWaitingForConfirmations {
                btc_tx_raw: btc_serialize(&built.tx),
                rsk_block_height: rsk_height,
                // TODO(rustock): post-RSKIP146 the rejection is keyed by the
                // registerBtcTransaction RSK tx hash and logs
                // release_requested; wire the tx context when sync nears
                // papyrus200 rejections.
                rsk_tx_hash: None,
            });
            let updated = serialize_pegouts_waiting_for_confirmations(&waiting, use_tx_hash);
            bridge_store_bytes(ctx, waiting_key, &updated);
        }
        set_btc_tx_processed(ctx, &btc_tx_hash, rsk_height);
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    let rbtc_amount = btc_satoshi_to_rbtc_wei(total_value);

    // RSK destination: rskj's legacy peg-in credits the address derived from
    // the sender's public key (ethereumj ECKey.getAddress over the
    // UNCOMPRESSED point — mainnet #267,460 used a 65-byte pubkey).
    // OP_RETURN-embedded destinations are pegin v1, RSKIP170+.
    let rsk_destination = if hardfork_cfg.has_rskip170(rsk_height) {
        extract_rsk_destination(&btc_tx)
            .or_else(|| super::federation::rsk_address_from_public_key(&sender_pubkey))
    } else {
        super::federation::rsk_address_from_public_key(&sender_pubkey)
    };

    // Credit the derived destination address (transfer from Bridge balance)
    if let Some(dest) = rsk_destination {
        if !rbtc_amount.is_zero() {
            let _ = ctx.journal_mut().transfer(BRIDGE_ADDR, dest, rbtc_amount);
        }

        // Peg-in events: lock_btc from RSKIP146, pegin_btc from RSKIP170.
        let txid_bytes = btc_txid_event_bytes(&btc_tx);
        if hardfork_cfg.has_rskip170(rsk_height) {
            let protocol_version = if has_op_return_destination(&btc_tx) { 1 } else { 0 };
            super::events::log_pegin_btc(ctx, dest, &txid_bytes, total_value, protocol_version);
        } else if hardfork_cfg.has_rskip146(rsk_height) {
            let sender = btc_sender_base58(&btc_tx, config).unwrap_or_default();
            super::events::log_lock_btc(ctx, dest, &txid_bytes, &sender, total_value);
        }
    }

    // rskj registerNewUtxos: the outputs paying the federation become
    // spendable federation UTXOs for future peg-outs.
    register_new_utxos(ctx, &btc_tx, &fed_script);

    // Mark as processed
    set_btc_tx_processed(ctx, &btc_tx_hash, rsk_height);

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// The peg-in sender's public key from the first input's P2PKH scriptSig
/// (`<sig> <pubkey>`, compressed or uncompressed) — rskj BtcLockSender.
fn btc_sender_pubkey(tx: &BtcTransaction) -> Option<Vec<u8>> {
    let script = tx.input.first()?.script_sig.as_bytes();
    let chunks = super::release_tx::parse_chunks(script)?;
    match chunks.as_slice() {
        [super::release_tx::Chunk::Data(_sig), super::release_tx::Chunk::Data(pubkey)]
            if pubkey.len() == 33 || pubkey.len() == 65 =>
        {
            Some(pubkey.clone())
        }
        _ => None,
    }
}

/// rskj `LockWhitelist.isWhitelistedFor` + `consume`: returns whether the
/// sender may peg in `amount` at BTC height `height`, consuming the matching
/// one-off entry. A height past the disable height turns the whitelist off
/// (but a matching one-off entry is still consumed).
fn whitelist_allows_and_consume<CTX: ContextTr>(
    ctx: &mut CTX,
    sender_hash160: &[u8; 20],
    amount: u64,
    height: u64,
) -> bool {
    let (mut one_off, disable_h) = load_one_off_whitelist(ctx);
    let disabled = (height as i64) > (disable_h as i64);

    if let Some(pos) = one_off.iter().position(|(h, _)| h == sender_hash160) {
        let allowed = disabled || amount <= one_off[pos].1;
        if allowed {
            one_off.remove(pos);
            store_one_off_whitelist(ctx, &one_off, disable_h);
        }
        return allowed;
    }
    if disabled {
        return true;
    }
    load_unlimited_whitelist(ctx).contains(sender_hash160)
}

/// rskj `BridgeSupport.registerNewUtxos`: register every output paying the
/// active federation as a federation UTXO (height 0, original scriptPubKey).
fn register_new_utxos<CTX: ContextTr>(
    ctx: &mut CTX,
    btc_tx: &BtcTransaction,
    fed_script: &bitcoin::ScriptBuf,
) {
    let new_utxos: Vec<BridgeUtxo> = btc_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_pubkey == *fed_script)
        .map(|(index, o)| BridgeUtxo {
            tx_hash: btc_txid_event_bytes(btc_tx),
            vout: index as u32,
            value_satoshis: o.value.to_sat(),
            height: 0,
            script: o.script_pubkey.to_bytes(),
            coinbase: btc_tx.is_coinbase(),
        })
        .collect();
    if new_utxos.is_empty() {
        return;
    }
    let mut utxos = load_federation_utxos(ctx);
    utxos.extend(new_utxos);
    store_federation_utxos(ctx, &utxos);
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

    // rskj requestRelease: post-RSKIP219 the minimum is inclusive (and also
    // bounded by a fee-based estimate — TODO before iris300); the legacy rule
    // is EXCLUSIVE: value must be strictly greater than the legacy minimum.
    let rejected = if hardfork_cfg.has_rskip219(block_number) {
        amount_satoshis_u256 < U256::from(config.minimum_pegout_tx_value)
    } else {
        amount_satoshis_u256 <= U256::from(config.legacy_minimum_pegout_tx_value)
    };
    if rejected {
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

    // rskj BridgeSupport.updateCollections logs an update_collections event;
    // the single-topic legacy format applies before RSKIP146, the Solidity
    // format afterwards.
    if use_tx_hash {
        super::events::log_solidity_update_collections(ctx, tx_ctx.rsk_sender);
    } else {
        super::events::log_legacy_update_collections(ctx, tx_ctx.rsk_sender);
    }

    // -----------------------------------------------------------------------
    // Step 1: Process peg-out requests (rskj processPegoutRequests)
    // -----------------------------------------------------------------------
    let should_process_requests = if use_rskip271 {
        // RSKIP271: batching — only process when nextPegoutHeight ≤ current block
        let next_height_key = bridge_storage_key(NEXT_PEGOUT_HEIGHT_KEY);
        let next_height = bridge_sload(ctx, next_height_key).to::<u64>();
        block_number >= next_height
    } else {
        true // Pre-RSKIP271: process every block
    };

    if should_process_requests {
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
            let federation_keys = federation_keys_or_genesis(ctx, config);
            if !federation_keys.is_empty() {
                let threshold = (federation_keys.len() / 2) + 1;
                let redeem_script = build_federation_redeem_script(&federation_keys, threshold);
                let change_script = p2sh_output_script(&redeem_script_hash160(&redeem_script));
                let fee_per_kb = get_effective_fee_per_kb(ctx, config);
                let tx_version = if hardfork_cfg.has_rskip201(block_number) { 2 } else { 1 };

                let mut available = load_federation_utxos(ctx);
                let waiting_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
                let existing_data = bridge_load_bytes(ctx, waiting_key);
                let mut waiting =
                    deserialize_pegouts_waiting_for_confirmations(&existing_data, use_tx_hash);
                let mut created_any = false;

                // Settle one successfully built peg-out: remove the spent
                // UTXOs, queue it for confirmations, and (RSKIP146+) log
                // release_requested with the creation RSK tx hash.
                let settle = |ctx: &mut CTX,
                                  built: super::release_tx::BuiltPegout,
                                  rsk_tx_hash: Option<[u8; 32]>,
                                  amount: u64,
                                  available: &mut Vec<BridgeUtxo>,
                                  waiting: &mut Vec<PegoutWaitingForConfirmations>| {
                    available.retain(|u| {
                        !built
                            .used_utxos
                            .iter()
                            .any(|s| s.tx_hash == u.tx_hash && s.vout == u.vout)
                    });
                    waiting.push(PegoutWaitingForConfirmations {
                        btc_tx_raw: btc_serialize(&built.tx),
                        rsk_block_height: block_number,
                        rsk_tx_hash: if use_tx_hash { rsk_tx_hash } else { None },
                    });
                    if use_tx_hash {
                        if let Some(hash) = rsk_tx_hash {
                            super::events::log_release_requested(
                                ctx,
                                &hash,
                                &btc_txid_event_bytes(&built.tx),
                                amount,
                            );
                        }
                    }
                };

                if !use_rskip271 {
                    // Pre-RSKIP271 (processPegoutsIndividually): one BTC tx
                    // per request, up to MAX_RELEASE_ITERATIONS(30) per call;
                    // failed builds are re-appended at the end of the queue.
                    const MAX_RELEASE_ITERATIONS: usize = 30;
                    let mut kept = Vec::new();
                    let mut to_retry = Vec::new();
                    for (i, request) in pending.iter().enumerate() {
                        if i >= MAX_RELEASE_ITERATIONS {
                            kept.push(request.clone());
                            continue;
                        }
                        let outputs = [super::release_tx::PegoutOutput {
                            script: p2pkh_output_script(&request.btc_dest_hash160),
                            amount_satoshis: request.amount_satoshis,
                        }];
                        match super::release_tx::complete_pegout_tx(
                            &available,
                            &outputs,
                            &change_script,
                            &redeem_script,
                            fee_per_kb,
                            tx_version,
                        ) {
                            Some(built) => {
                                settle(
                                    ctx,
                                    built,
                                    request.rsk_tx_hash,
                                    request.amount_satoshis,
                                    &mut available,
                                    &mut waiting,
                                );
                                created_any = true;
                            }
                            None => to_retry.push(request.clone()),
                        }
                    }
                    kept.extend(to_retry);
                    let updated_queue = if use_tx_hash {
                        serialize_release_queue_with_hash(&kept)
                    } else {
                        serialize_release_queue_legacy(&kept)
                    };
                    bridge_store_bytes(ctx, queue_key, &updated_queue);
                } else {
                    // RSKIP271+ (processPegoutsInBatch): one batched BTC tx
                    // for the whole queue, keyed by this updateCollections
                    // call's tx hash.
                    let outputs: Vec<super::release_tx::PegoutOutput> = pending
                        .iter()
                        .map(|r| super::release_tx::PegoutOutput {
                            script: p2pkh_output_script(&r.btc_dest_hash160),
                            amount_satoshis: r.amount_satoshis,
                        })
                        .collect();
                    if let Some(built) = super::release_tx::complete_pegout_tx(
                        &available,
                        &outputs,
                        &change_script,
                        &redeem_script,
                        fee_per_kb,
                        tx_version,
                    ) {
                        let total: u64 = pending.iter().map(|r| r.amount_satoshis).sum();
                        settle(
                            ctx,
                            built,
                            Some(tx_ctx.rsk_tx_hash),
                            total,
                            &mut available,
                            &mut waiting,
                        );
                        created_any = true;
                        bridge_store_bytes(ctx, queue_key, &[]);
                    }

                    // Update nextPegoutHeight (RSKIP271)
                    let next_height = block_number + config.number_of_blocks_between_pegouts;
                    let next_height_key = bridge_storage_key(NEXT_PEGOUT_HEIGHT_KEY);
                    bridge_sstore(ctx, next_height_key, U256::from(next_height));
                }

                if created_any {
                    let updated =
                        serialize_pegouts_waiting_for_confirmations(&waiting, use_tx_hash);
                    bridge_store_bytes(ctx, waiting_key, &updated);
                    store_federation_utxos(ctx, &available);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: Promote ONE confirmed pegout → waiting for signatures
    // (rskj processConfirmedPegouts: getNextPegoutWithEnoughConfirmations
    // promotes a single entry per updateCollections call)
    // -----------------------------------------------------------------------
    {
        let waiting_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
        let waiting_data = bridge_load_bytes(ctx, waiting_key);
        let mut waiting = deserialize_pegouts_waiting_for_confirmations(&waiting_data, use_tx_hash);
        let min_confirmations = config.rsk2btc_minimum_acceptable_confirmations as u64;
        let confirmed_pos = waiting.iter().position(|e| {
            block_number
                .checked_sub(e.rsk_block_height)
                .is_some_and(|d| d >= min_confirmations)
        });

        if let Some(pos) = confirmed_pos {
            let entry = waiting.remove(pos);
            tracing::debug!(
                "promoting confirmed pegout created at #{} ({} bytes) into WFS",
                entry.rsk_block_height,
                entry.btc_tx_raw.len()
            );
            let updated = serialize_pegouts_waiting_for_confirmations(&waiting, use_tx_hash);
            bridge_store_bytes(ctx, waiting_key, &updated);

            // rskj getPegoutWaitingForSignatureKey:
            // - RSKIP375+: the pegout creation RSK tx hash
            // - RSKIP146..RSKIP176: creation hash, falling back to this tx
            // - otherwise (incl. pre-RSKIP146): this updateCollections tx hash
            let rsk_hash = if hardfork_cfg.has_rskip375(block_number) {
                entry.rsk_tx_hash.unwrap_or(tx_ctx.rsk_tx_hash)
            } else if use_tx_hash && !hardfork_cfg.has_rskip176(block_number) {
                entry.rsk_tx_hash.unwrap_or(tx_ctx.rsk_tx_hash)
            } else {
                tx_ctx.rsk_tx_hash
            };

            let wfs_key = bridge_storage_key(PEGOUTS_WAITING_FOR_SIGNATURES_KEY);
            let wfs_data = bridge_load_bytes(ctx, wfs_key);
            let mut wfs = deserialize_rsk_txs_waiting_for_signatures(&wfs_data);
            wfs.insert(rsk_hash, entry.btc_tx_raw);
            let updated_wfs = serialize_rsk_txs_waiting_for_signatures(&wfs);
            bridge_store_bytes(ctx, wfs_key, &updated_wfs);
        }
    }

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// Active federation member keys: the committed federation from storage, or
/// the genesis federation from the network constants when none was ever
/// stored (rskj `FederationSupport.getActiveFederation` fallback).
pub(crate) fn federation_keys_or_genesis<CTX: ContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
) -> Vec<[u8; 33]> {
    let stored = load_federation_member_keys(ctx);
    if !stored.is_empty() {
        return stored;
    }
    config
        .genesis_federation_public_keys
        .iter()
        .filter_map(|hex| {
            let bytes = alloy_primitives::hex::decode(hex).ok()?;
            bytes.try_into().ok()
        })
        .collect()
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
    config: &BridgeConstants,
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
        None => {
            // Temporary diagnostics for the #272,850 pipeline debug: show how
            // far the peg-out pipeline progressed when the lookup misses.
            let queue_len = {
                let key = bridge_storage_key(RELEASE_REQUEST_QUEUE_KEY);
                deserialize_release_queue_legacy(&bridge_load_bytes(ctx, key)).len()
            };
            let wfc_len = {
                let key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
                deserialize_pegouts_waiting_for_confirmations(&bridge_load_bytes(ctx, key), false)
                    .len()
            };
            let utxo_count = load_federation_utxos(ctx).len();
            let wfc_raw_len = {
                let key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
                bridge_load_bytes(ctx, key).len()
            };
            let wfs_raw_len = bridge_load_bytes(ctx, wfs_key).len();
            let fee_per_kb = get_effective_fee_per_kb(ctx, config);
            let stored_fed = load_federation_member_keys(ctx).len();
            tracing::debug!(
                "WFS raw {} bytes, WFC raw {} bytes, fee_per_kb {}, stored fed keys {}",
                wfs_raw_len,
                wfc_raw_len,
                fee_per_kb,
                stored_fed
            );
            let (one_off, disable_h) = load_one_off_whitelist(ctx);
            tracing::debug!(
                "addSignature: WFS miss for {} (wfs keys: {:?}; queue {} entries, wfc {} entries, {} federation utxos; whitelist {:?} disable={} unlimited={})",
                to_hex(&rsk_tx_hash),
                wfs.keys().map(|k| to_hex(&k[..4])).collect::<Vec<_>>(),
                queue_len,
                wfc_len,
                utxo_count,
                one_off
                    .iter()
                    .map(|(h, v)| format!("{}:{}", to_hex(h), v))
                    .collect::<Vec<_>>(),
                disable_h,
                load_unlimited_whitelist(ctx).len()
            );
            return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
        }
    };

    let mut btc_tx: BtcTransaction = match deserialize(&btc_tx_raw) {
        Ok(tx) => tx,
        Err(_) => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };

    // rskj areSignaturesEnoughToSignAllTxInputs: one signature per input.
    if sigs.len() != btc_tx.input.len() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Membership check against the active federation (genesis fallback).
    // TODO(rustock): rskj also accepts retiring-federation members.
    let federation_keys = federation_keys_or_genesis(ctx, config);
    if federation_keys.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }
    let Some(compressed_key) = compress_pubkey(&fed_key) else {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    };
    if !federation_keys.contains(&compressed_key) {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();

    // rskj logs an add_signature event for a federation member: before
    // RSKIP326 it fires BEFORE the signatures are verified and applied;
    // afterwards only when a signature was actually applied. The format is
    // legacy single-topic before RSKIP146 and Solidity afterwards.
    let legacy_events = !hardfork_cfg.has_rskip146(block_number);
    let log_only_when_applied = hardfork_cfg.has_rskip326(block_number);
    let emit_add_signature = |ctx: &mut CTX, btc_tx: &BtcTransaction| {
        if legacy_events {
            let txid = btc_tx.compute_txid().to_string();
            super::events::log_legacy_add_signature(
                ctx,
                &txid,
                &pubkey_hash160(&compressed_key),
                &rsk_tx_hash,
            );
        } else {
            // Pre-RSKIP415 the federator's RSK address derives from its BTC key.
            if let Some(addr) = super::federation::rsk_address_from_public_key(&fed_key) {
                super::events::log_solidity_add_signature(ctx, &rsk_tx_hash, addr, &fed_key);
            }
        }
    };
    if !log_only_when_applied {
        emit_add_signature(ctx, &btc_tx);
    }

    // rskj processSigning: verify every provided signature against its
    // input's sighash before applying any, then insert each at the position
    // determined by the key order in the redeem script.
    let applied = apply_signatures_to_tx(&mut btc_tx, &sigs, &compressed_key);
    if log_only_when_applied && applied {
        emit_add_signature(ctx, &btc_tx);
    }

    if super::release_tx::has_enough_signatures(&btc_tx) {
        // Fully signed: rskj logs release_btc with the signed transaction
        // and removes it from the waiting map (the BTC tx is broadcast
        // off-chain by the federation nodes).
        if legacy_events {
            let txid = btc_tx.compute_txid().to_string();
            super::events::log_legacy_release_btc(ctx, &txid, &btc_serialize(&btc_tx));
        } else {
            super::events::log_solidity_release_btc(ctx, &rsk_tx_hash, &btc_serialize(&btc_tx));
        }
        wfs.remove(&rsk_tx_hash);
        let updated = serialize_rsk_txs_waiting_for_signatures(&wfs);
        bridge_store_bytes(ctx, wfs_key, &updated);
    } else if applied {
        // Partially signed — update the map with the new signatures.
        let updated_raw = btc_serialize(&btc_tx);
        wfs.insert(rsk_tx_hash, updated_raw);
        let updated = serialize_rsk_txs_waiting_for_signatures(&wfs);
        bridge_store_bytes(ctx, wfs_key, &updated);
    }

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// BTC txid in rskj event byte order: bitcoinj `Sha256Hash.getBytes()` keeps
/// the display (big-endian) order, the reverse of rust-bitcoin's internal one.
fn btc_txid_event_bytes(tx: &BtcTransaction) -> [u8; 32] {
    let mut bytes = *tx.compute_txid().to_raw_hash().as_byte_array();
    bytes.reverse();
    bytes
}

/// Whether the peg-in carries an OP_RETURN destination (protocol v1).
fn has_op_return_destination(tx: &BtcTransaction) -> bool {
    tx.output.iter().any(|o| o.script_pubkey.is_op_return())
}

/// Base58Check P2PKH address of the peg-in sender (first input's public key).
fn btc_sender_base58(tx: &BtcTransaction, config: &BridgeConstants) -> Option<String> {
    let first_input = tx.input.first()?;
    let script_bytes = first_input.script_sig.as_bytes();
    if script_bytes.len() < 34 {
        return None;
    }
    let pubkey_len = script_bytes[script_bytes.len() - 34] as usize;
    if pubkey_len != 33 {
        return None;
    }
    let pubkey = &script_bytes[script_bytes.len() - 33..];
    let network = match config.btc_network {
        super::constants::BtcNetwork::Mainnet => bitcoin::Network::Bitcoin,
        super::constants::BtcNetwork::Testnet => bitcoin::Network::Testnet,
        super::constants::BtcNetwork::Regtest => bitcoin::Network::Regtest,
    };
    let key = bitcoin::PublicKey::from_slice(pubkey).ok()?;
    Some(bitcoin::Address::p2pkh(key.pubkey_hash(), network).to_string())
}

/// Compress a SEC1 public key (33- or 65-byte) to its 33-byte form.
fn compress_pubkey(key: &[u8]) -> Option<[u8; 33]> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let parsed = k256::PublicKey::from_sec1_bytes(key).ok()?;
    let point = parsed.to_encoded_point(true);
    point.as_bytes().try_into().ok()
}

/// RIPEMD160(SHA256(pubkey)) — bitcoinj `ECKey.getPubKeyHash` over the key
/// bytes as provided.
fn pubkey_hash160(key: &[u8]) -> [u8; 20] {
    use sha2::Digest as Sha2Digest;
    let sha256 = sha2::Sha256::digest(key);
    let hash160 = ripemd::Ripemd160::digest(sha256);
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&hash160);
    arr
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
    // rskj sorts entries by the serialized BTC transaction bytes
    // (PegoutsWaitingForConfirmations.Entry.BTC_TX_COMPARATOR).
    let mut entries: Vec<&PegoutWaitingForConfirmations> = entries.iter().collect();
    entries.sort_by(|a, b| a.btc_tx_raw.cmp(&b.btc_tx_raw));

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
pub(crate) fn load_federation_member_keys<CTX: ContextTr>(ctx: &mut CTX) -> Vec<[u8; 33]> {
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

/// Apply a federator's DER signatures to a peg-out BTC transaction
/// (rskj `BridgeSupport.processSigning` + `sign`).
///
/// All provided signatures are verified against their input's legacy
/// SIGHASH_ALL hash (over the redeem script extracted from the placeholder
/// scriptSig) before any is applied; a single invalid signature aborts the
/// call. Each valid signature is then inserted at the position dictated by
/// the key order in the redeem script, consuming one OP_0 placeholder.
/// Returns whether at least one signature was applied.
fn apply_signatures_to_tx(
    tx: &mut BtcTransaction,
    sigs: &[Vec<u8>],
    fed_key: &[u8; 33],
) -> bool {
    use super::release_tx::{
        extract_redeem_script, input_signed_by, legacy_sighash_all, sig_insertion_index,
        update_script_with_signature, verify_der_signature,
    };

    let n = tx.input.len();
    let mut redeems = Vec::with_capacity(n);
    let mut sighashes = Vec::with_capacity(n);
    for i in 0..n {
        let Some(redeem) = extract_redeem_script(tx.input[i].script_sig.as_bytes()) else {
            return false;
        };
        sighashes.push(legacy_sighash_all(tx, i, &redeem));
        redeems.push(redeem);
    }

    // getTransactionSignatures: any malformed or non-verifying signature
    // aborts without applying anything.
    for (sig, sighash) in sigs.iter().zip(&sighashes) {
        if !verify_der_signature(sig, sighash, fed_key) {
            return false;
        }
    }

    // sign(): stop at the first input already signed by this federator.
    let mut signed = false;
    for i in 0..n {
        if input_signed_by(tx, i, fed_key, &sighashes[i]) {
            break;
        }
        let mut encoded = sigs[i].clone();
        encoded.push(0x01); // SIGHASH_ALL
        let script_sig = tx.input[i].script_sig.as_bytes().to_vec();
        let index = sig_insertion_index(&script_sig, &sighashes[i], fed_key, &redeems[i]);
        let Some(updated) = update_script_with_signature(&script_sig, &encoded, index) else {
            return false; // no placeholder left (bitcoinj throws)
        };
        tx.input[i].script_sig = bitcoin::ScriptBuf::from_bytes(updated);
        signed = true;
    }
    signed
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

    // 2. Fall back to deriving from the first input's P2PKH public key
    // (compressed or uncompressed).
    btc_sender_pubkey(btc_tx)
        .and_then(|pk| super::federation::rsk_address_from_public_key(&pk))
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

/// `getEstimatedFeesForPegOutAmount(uint256 pegoutAmountInWeis)` → uint256
///
/// Enabled by RSKIP540 (Vetiver900). Validates the amount against the
/// minimum peg-out value like rskj BridgeSupport.getEstimatedFeesForPegOutAmount;
/// the fee simulation itself shares getEstimatedFeesForNextPegOutEvent's
/// (stub) fidelity.
pub fn get_estimated_fees_for_pegout_amount<CTX: ContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    if !hardfork_cfg.has_rskip540(block_number) {
        return Err(PrecompileError::other(
            "getEstimatedFeesForPegOutAmount: method not enabled",
        ));
    }
    if args.len() < 32 {
        return Err(PrecompileError::other(
            "getEstimatedFeesForPegOutAmount: args too short",
        ));
    }

    // co.rsk.core.Coin (wei) -> bitcoin Coin (satoshi): / 10^10
    let wei = U256::from_be_slice(&args[0..32]);
    let satoshis = wei / U256::from(10_000_000_000u64);
    if satoshis < U256::from(config.minimum_pegout_tx_value) {
        return Err(PrecompileError::other(
            "getEstimatedFeesForPegOutAmount: peg-out amount is below the minimum peg-out value",
        ));
    }

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
        // rskj sorts entries by serialized BTC tx bytes (BTC_TX_COMPARATOR):
        // 0xBEEF < 0xDEAD.
        assert_eq!(decoded[0].btc_tx_raw, vec![0xBE, 0xEF]);
        assert_eq!(decoded[0].rsk_block_height, 2000);
        assert_eq!(decoded[1].btc_tx_raw, vec![0xDE, 0xAD]);
        assert_eq!(decoded[1].rsk_block_height, 1000);
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

    /// Mainnet #267,460: a peg-in from an UNCOMPRESSED-pubkey sender credits
    /// the RSK address of the uncompressed point (ethereumj ECKey.getAddress).
    /// Our 33-byte-only parser missed it, leaving the recipient at balance 0
    /// until their first spend failed at #400,982.
    #[test]
    fn rskj_pegin_destination_from_uncompressed_pubkey() {
        let pubkey = alloy_primitives::hex::decode(
            "04869eeeb358fa4e76da63b1596a38305bdc1007b981b6d5c59f54156678280cc6120605a7c8492adb33ab50f529162c9554f5f9491faba644719517e36d12d64c",
        )
        .unwrap();
        let addr = crate::bridge::federation::rsk_address_from_public_key(&pubkey).unwrap();
        assert_eq!(
            alloy_primitives::hex::encode(addr),
            "95bf476114e3241b808e81144228fe833fd38887"
        );

        // And through the scriptSig parser: <72-byte sig> <65-byte pubkey>.
        let mut script = vec![71u8];
        script.extend_from_slice(&[0x30; 71]);
        script.push(65);
        script.extend_from_slice(&pubkey);
        let tx = BtcTransaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: Default::default(),
                script_sig: bitcoin::ScriptBuf::from_bytes(script),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        assert_eq!(btc_sender_pubkey(&tx), Some(pubkey));
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
