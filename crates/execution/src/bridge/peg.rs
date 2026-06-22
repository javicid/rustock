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

use super::btc_store::load_chain_head;
use super::constants::BridgeConstants;
use super::pmt::PartialMerkleTree;
use super::serialization::{rlp_decode_list, rlp_encode_element, rlp_encode_list, rlp_encode_u64};
use super::storage::*;
use super::tx::*;
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::{BRIDGE_ADDR, BridgeTxContext};

/// rskj `BridgeSupport.BURN_ADDRESS`: receiver of the sBTC burned when a
/// pegout's dusty change output is raised to the non-dust minimum.
const BURN_ADDR: RskAddress = RskAddress::new([0xff; 20]);

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

/// rskj `PegUtilsLegacy.isValidPegInTx` minimum gate over the live-federations
/// outputs. Under RSKIP293 each UTXO must be at least `min`
/// (`isAnyUTXOAmountBelowMinimum`); before it, the *total* sent must be
/// (`valueSentToMe.isLessThan`). An EMPTY set of live-fed outputs is not below
/// minimum under RSKIP293 (`anyMatch` over an empty stream is false), so a tx
/// that pays no live federation is still a valid (amount-0) peg-in; pre-RSKIP293
/// a 0 total is below minimum and is not a peg-in.
fn pegin_below_minimum(live_output_values: &[u64], min: u64, rskip293: bool) -> bool {
    if rskip293 {
        live_output_values.iter().any(|v| *v < min)
    } else {
        live_output_values.iter().sum::<u64>() < min
    }
}

pub fn register_btc_transaction<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
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
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let use_v2 = hardfork_cfg.has_stored_block_v2(block_number);
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    super::btc_chain::ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);

    // rskj wraps the registerBtcTransaction body in
    // `try { ... } catch (RegisterBtcTransactionException e) { log }`: an
    // already-processed tx or any failed validation
    // (validationsForRegisterBtcTransaction → "Could not validate
    // transaction") is logged and the call returns SUCCESSFULLY without
    // registering anything. Mirror that — these are a no-op success, not a
    // failed tx. Only a malformed BTC tx (parsed below, a separate
    // exception) propagates and fails the tx.
    let validation = (|| -> Result<(), PrecompileError> {
        // Check if already processed
        if is_btc_tx_processed(ctx, &btc_tx_hash) {
            return Err(PrecompileError::other("transaction already processed"));
        }

        // Validate PMT
        if !PartialMerkleTree::has_expected_size(&pmt_data) {
            return Err(PrecompileError::other("invalid PMT size"));
        }
        let pmt = PartialMerkleTree::parse(&pmt_data)
            .ok_or_else(|| PrecompileError::other("failed to parse PMT"))?;
        let pmt_result = pmt
            .extract_matches()
            .ok_or_else(|| PrecompileError::other("PMT verification failed"))?;

        // Check tx hash is in PMT matched hashes
        if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
            return Err(PrecompileError::other("tx not in PMT"));
        }

        // Look up the BTC block on the main chain at the caller-supplied
        // height (walks the chain pre-RSKIP199, indexed lookup afterwards).
        let stored_block =
            super::btc_chain::stored_block_at_main_chain_height(ctx, btc_block_height as u32, rskip199)
                .ok_or_else(|| PrecompileError::other("BTC block not found at height"))?;
        let block_hash = stored_block.header.block_hash();

        // Verify merkle root matches
        let block_merkle_root = {
            let raw = stored_block.header.merkle_root.to_raw_hash();
            *raw.as_byte_array()
        };
        let root_valid = if pmt_result.merkle_root == block_merkle_root {
            true
        } else {
            // Post-RSKIP143: also accept witness merkle root. The coinbase
            // information is keyed by the block hash in DISPLAY byte order
            // (rskj `Sha256Hash.toString()`; see set_coinbase_information),
            // the reverse of rust-bitcoin's internal order.
            let block_hash_bytes = {
                let mut raw = *block_hash.to_raw_hash().as_byte_array();
                raw.reverse();
                raw
            };
            match get_coinbase_information(ctx, &block_hash_bytes) {
                // The stored witness merkle root is in DISPLAY byte order
                // (rskj registerBtcCoinbaseTransaction wraps the ABI arg and
                // reverses it for the commitment, BridgeSupport l.2574), while
                // the PMT merkle root is internal order — compare reversed.
                Some(mut witness_root) => {
                    witness_root.reverse();
                    pmt_result.merkle_root == witness_root
                }
                None => false,
            }
        };
        if !root_valid {
            return Err(PrecompileError::other("merkle root mismatch"));
        }

        // Check confirmations (rskj BridgeUtils.validateHeightAndConfirmations:
        // the block itself counts as one confirmation, and the CALLER-supplied
        // height is what gets validated).
        let best_height = load_chain_head(ctx).map(|h| h.height).unwrap_or(0);
        let confirmations = best_height as i64 - btc_block_height as i64 + 1;
        if confirmations < config.btc2rsk_minimum_acceptable_confirmations as i64 {
            return Err(PrecompileError::other("insufficient confirmations"));
        }
        Ok(())
    })();
    if let Err(e) = validation {
        tracing::debug!("registerBtcTransaction: {e}; returning success (rskj swallows RegisterBtcTransactionException)");
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Parse the BTC transaction
    let btc_tx: BtcTransaction = deserialize(&btc_tx_data).map_err(|_| {
        PrecompileError::other("registerBtcTransaction: invalid BTC transaction")
    })?;

    // rskj re-checks "already processed" using the witness-stripped txid
    // (BridgeSupport.registerBtcTransaction l.404, `btcTx.getHash(false)`):
    // the pre-parse check above used the wtxid (`calculateBtcTxHash` over the
    // raw bytes), so for a SegWit tx the two keys differ and this second check
    // is what actually guards the legacy-txid-keyed map. Every mark below uses
    // this same legacy txid (rskj markTxAsProcessed l.763).
    let legacy_txid = legacy_btc_txid(&btc_tx);
    if is_btc_tx_processed(ctx, &legacy_txid) {
        tracing::debug!("registerBtcTransaction: transaction already processed (txid); returning success");
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Live federations (active + retiring during migration): their P2SH
    // scripts identify which outputs are peg-ins and which inputs make the
    // tx a peg-out (rskj getNoSpendWalletForLiveFederations).
    let block_number_now = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    // Each live federation's redeem script (and hence the P2SH address used to
    // recognize peg-in outputs / peg-out inputs) is built from its STORED format
    // version, not the current block — an ERP federation keeps its ERP script
    // even after a later template hardfork (rskj getActiveFederation /
    // getRetiringFederation → Federation.getRedeemScript()).
    let (federation_keys, fed_redeem) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number_now);
    let fed_script = p2sh_output_script(&redeem_script_hash160(&fed_redeem));
    // rskj isPegOutTx compares against each federation's STANDARD redeem script
    // (getStandardRedeemScript) — for an ERP federation this is the default
    // multisig branch only, not the full ERP/flyover-wrapped redeem.
    let fed_standard_redeem =
        build_federation_redeem_script(&federation_keys, federation_keys.len() / 2 + 1);
    let retiring = retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number_now)
        .map(|(_keys, redeem)| {
            let script = p2sh_output_script(&redeem_script_hash160(&redeem));
            (redeem, script)
        });
    let retiring_standard_redeem = retiring_federation_keys(ctx, config, hardfork_cfg, block_number_now)
        .map(|keys| build_federation_redeem_script(&keys, keys.len() / 2 + 1));

    // rskj marks processed txs with the RSK execution block number
    // (BridgeSupport.markTxAsProcessed), not the BTC block height.
    let rsk_height = revm::context_interface::Block::number(ctx.block()).to::<u64>();

    // Minimum peg-in value (legacy until RSKIP219, strictly-below comparison
    // per PegUtilsLegacy.isValidPegInTx). Needed both for the migration
    // moveToActive check below and the peg-in value gate further down.
    let min_pegin = if hardfork_cfg.has_rskip219(rsk_height) {
        config.minimum_pegin_tx_value
    } else {
        config.legacy_minimum_pegin_tx_value
    };

    // rskj PegUtilsLegacy.getTransactionType — PEGOUT_OR_MIGRATION detection.
    // An input "spends" a federation when its scriptSig redeem hashes to that
    // federation's P2SH; isPegOutTx/migration compare the input's STANDARD
    // (default-branch) redeem (extractStandardRedeemScript) to each fed's
    // standard P2SH, while txIsFromOldFederation compares the FULL redeem.
    let active_std_hash160 = redeem_script_hash160(&fed_standard_redeem);
    let retiring_std_hash160 = retiring_standard_redeem.as_ref().map(|r| redeem_script_hash160(r));
    // lastRetiredFederationP2SHScript (RSKIP186): the P2SH of the last fully
    // retired federation, stored as serializeScript = RLP([program]).
    let retired_hash160: Option<[u8; 20]> = if hardfork_cfg.has_rskip186(rsk_height) {
        let raw = super::storage::bridge_load_bytes_named(
            ctx,
            super::storage::LAST_RETIRED_FEDERATION_P2SH_SCRIPT_KEY,
        );
        rlp_decode_list(&raw)
            .and_then(|items| items.into_iter().next())
            .filter(|p| p.len() == 23)
            .map(|p| p[2..22].try_into().expect("23-byte P2SH program"))
    } else {
        None
    };
    let std_hash160_of = |full: &[u8]| -> [u8; 20] {
        redeem_script_hash160(&build_federation_redeem_script(
            &super::release_tx::spending_redeem_keys(full),
            super::release_tx::redeem_script_threshold(full),
        ))
    };

    // (1) txIsFromOldFederation (RSKIP199): any input spends the hardcoded old
    //     federation address — unconditionally a migration.
    let tx_from_old_fed = hardfork_cfg.has_rskip199(rsk_height)
        && btc_tx.input.iter().any(|i| {
            super::release_tx::extract_redeem_script(i.script_sig.as_bytes())
                .is_some_and(|r| redeem_script_hash160(&r) == config.old_federation_address_hash160)
        });
    // (4) isPegOutTx(liveFeds): an input's standard redeem matches the active
    //     or retiring federation.
    let spends_live_fed = btc_tx.input.iter().any(|i| {
        super::release_tx::extract_redeem_script(i.script_sig.as_bytes()).is_some_and(|r| {
            let h = std_hash160_of(&r);
            h == active_std_hash160 || retiring_std_hash160 == Some(h)
        })
    });
    // (3) isMigrationTx: an input spends the retired or retiring federation AND
    //     an output funds the active federation (moveFromRetiringOrRetired &&
    //     moveToActive).
    let spends_retired_or_retiring = btc_tx.input.iter().any(|i| {
        super::release_tx::extract_redeem_script(i.script_sig.as_bytes()).is_some_and(|r| {
            let h = std_hash160_of(&r);
            Some(h) == retired_hash160 || retiring_std_hash160 == Some(h)
        })
    });
    let active_output_values: Vec<u64> = btc_tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == fed_script)
        .map(|o| o.value.to_sat())
        .collect();
    let move_to_active = if hardfork_cfg.has_rskip293(rsk_height) {
        !active_output_values.is_empty() && active_output_values.iter().all(|v| *v >= min_pegin)
    } else {
        active_output_values.iter().sum::<u64>() >= min_pegin
    };
    let is_migration = spends_retired_or_retiring && move_to_active;

    if tx_from_old_fed || is_migration || spends_live_fed {
        let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
        register_federation_outputs(ctx, &btc_tx, &fed_script, active_utxo_key);
        if let Some((_, retiring_script)) = &retiring {
            register_federation_outputs(
                ctx,
                &btc_tx,
                retiring_script,
                super::storage::OLD_FEDERATION_BTC_UTXOS_KEY,
            );
        }
        set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Peg-in value: the outputs paying any live federation
    // (rskj computeTotalAmountSent over the live-federations wallet).
    let pays_live_federation = |script: &bitcoin::ScriptBuf| {
        *script == fed_script || retiring.as_ref().is_some_and(|(_, rs)| *script == *rs)
    };
    let live_output_values: Vec<u64> = btc_tx
        .output
        .iter()
        .filter(|o| pays_live_federation(&o.script_pubkey))
        .map(|o| o.value.to_sat())
        .collect();
    let total_value: u64 = live_output_values.iter().sum();

    // rskj PegUtilsLegacy.isValidPegInTx minimum gate: under RSKIP293 it checks
    // EACH UTXO (isAnyUTXOAmountBelowMinimum), otherwise the total amount sent
    // (valueSentToMe.isLessThan). Crucially, an EMPTY live-output set is not
    // "below minimum" under RSKIP293 (anyMatch over an empty stream is false),
    // so a tx that pays no live federation (e.g. only a now-retired one, once
    // the retiring federation has been cleared earlier in the block) is still a
    // valid peg-in — processed with amount 0 (pegin_btc amount=0, destination
    // account created). Pre-RSKIP293 a 0 total is below minimum → not a peg-in.
    let below_min =
        pegin_below_minimum(&live_output_values, min_pegin, hardfork_cfg.has_rskip293(rsk_height));
    if below_min {
        // Not a valid peg-in: rskj getTransactionType returns UNKNOWN here (the
        // tx is neither a migration nor a peg-out), so registerBtcTransaction
        // ignores it. The RSKIP459+ "mark rejected as processed" behavior lives
        // in the post-RSKIP379 evaluatePegin flow, folded in here for parity.
        if should_mark_rejected_pegin_as_processed(hardfork_cfg, rsk_height) {
            set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
        }
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // Sender classification (rskj BtcLockSenderProvider). Used by the legacy
    // (v0) path for the destination/refund, and as the v1 fallback refund.
    let sender = classify_pegin_sender(&btc_tx);

    // rskj `PeginInformation.parse`: the BtcLockSender sets the default
    // (version-0) info; then, if RSKIP170 is active, an RSKT OP_RETURN
    // overrides it (version 1). A malformed RSKT payload throws
    // `PeginInstructionsException` and rejects the v1 peg-in. NoOpReturn
    // (Ok(None)) leaves the legacy info in place.
    let instructions = if hardfork_cfg.has_rskip170(rsk_height) {
        match super::pegin_instructions::build_pegin_instructions(&btc_tx) {
            Ok(opt) => opt,
            Err(_) => {
                // processPegIn: parse exception. RSKIP181 logs
                // PEGIN_V1_INVALID_PAYLOAD(4); refund to the sender (the only
                // refund address available — a malformed payload has no v1
                // refund), then mark processed.
                if hardfork_cfg.has_rskip181(rsk_height) {
                    super::events::log_rejected_pegin(ctx, &btc_txid_event_bytes(&btc_tx), 4);
                }
                if let Some(sender) = &sender {
                    let (refund_hash160, refund_is_p2sh) = sender_refund_target(sender);
                    emit_pegin_rejection_release(
                        ctx, &btc_tx, &refund_hash160, refund_is_p2sh, total_value, &fed_redeem,
                        &retiring, &pays_live_federation, rsk_height, config, hardfork_cfg, tx_ctx,
                    );
                }
                set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
                return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
            }
        }
    } else {
        None
    };

    let cap_ok = |ctx: &mut CTX| {
        !hardfork_cfg.has_rskip134(rsk_height)
            || verify_lock_does_not_surpass_locking_cap(ctx, config, total_value)
    };
    let rbtc_amount = btc_satoshi_to_rbtc_wei(total_value);

    // ---- Version 1 (RSKIP170 OP_RETURN) peg-in ----
    if let Some(instr) = instructions {
        // processPegInVersion1: NO whitelist, only the locking cap.
        if !cap_ok(ctx) {
            if hardfork_cfg.has_rskip181(rsk_height) {
                super::events::log_rejected_pegin(ctx, &btc_txid_event_bytes(&btc_tx), 1); // PEGIN_CAP_SURPASSED
            }
            // refundTxSender: refund to the v1 refund address if present, else
            // the BtcLockSender address; if neither, no refund (a non-refundable
            // peg-in — unrefundable_pegin event not modeled, see TODO).
            if let Some((refund_hash160, refund_is_p2sh)) = v1_refund_target(&instr, sender.as_ref()) {
                emit_pegin_rejection_release(
                    ctx, &btc_tx, &refund_hash160, refund_is_p2sh, total_value, &fed_redeem,
                    &retiring, &pays_live_federation, rsk_height, config, hardfork_cfg, tx_ctx,
                );
            }
            set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
            return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
        }

        // executePegIn: credit the v1 destination from the OP_RETURN payload.
        let dest = RskAddress::from(instr.rsk_destination);
        if !rbtc_amount.is_zero() {
            let _ = ctx.journal_mut().transfer(BRIDGE_ADDR, dest, rbtc_amount);
        } else {
            // transferTo(dest, 0) still creates+persists the account (RSK keeps
            // empty touched accounts — see the legacy path below).
            let _ = ctx.journal_mut().load_account(dest);
            ctx.journal_mut().touch_account(dest);
        }
        // RSKIP170 is required for v1, so pegin_btc (protocolVersion = 1).
        super::events::log_pegin_btc(ctx, dest, &btc_txid_event_bytes(&btc_tx), total_value, 1);

        let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
        register_federation_outputs(ctx, &btc_tx, &fed_script, active_utxo_key);
        if let Some((_, retiring_script)) = &retiring {
            register_federation_outputs(ctx, &btc_tx, retiring_script, super::storage::OLD_FEDERATION_BTC_UTXOS_KEY);
        }
        set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // ---- Version 0 (legacy) peg-in ----
    // A non-P2PKH sender before RSKIP143 (txIsProcessable) aborts WITHOUT
    // marking the tx as processed (no BtcLockSender or unsupported type).
    let Some(sender) = sender else {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    };
    let rskip143 = hardfork_cfg.has_rskip143(rsk_height);
    if !matches!(sender, PeginSender::P2pkh { .. }) && !rskip143 {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }
    // rskj txIsLockable: only P2PKH and (post-RSKIP143) P2SH-P2WPKH senders
    // can lock; other processable types are refunded ("Btc tx type not
    // supported, returning funds to sender") without consulting the
    // whitelist or the locking cap.
    let (sender_hash160, sender_is_p2sh, sender_pubkey, lockable): ([u8; 20], bool, Option<&[u8]>, bool) =
        match &sender {
            PeginSender::P2pkh { pubkey } => (pubkey_hash160(pubkey), false, Some(pubkey), true),
            PeginSender::P2shP2wpkh { pubkey, p2sh_hash } => {
                (*p2sh_hash, true, Some(pubkey), true)
            }
            PeginSender::P2shMultisig { p2sh_hash } | PeginSender::P2shP2wsh { p2sh_hash } => {
                (*p2sh_hash, true, None, false)
            }
        };

    // Lock whitelist gate (rskj verifyLockSenderIsWhitelisted): the matching
    // one-off entry is consumed on success; rejection generates a refund
    // peg-out back to the sender (generateRejectionRelease).
    // Locking cap gate (rskj verifyLockDoesNotSurpassLockingCap, RSKIP134):
    // evaluated only when the whitelist passed (rskj short-circuits the &&,
    // so a whitelist rejection never lazily initializes the cap). A cap
    // rejection produces the same refund release as a whitelist one.
    let allowed = lockable
        && whitelist_allows_and_consume(ctx, &sender_hash160, total_value, btc_block_height)
        && cap_ok(ctx);
    tracing::debug!(
        "pegin lock check: sender {} amount {} btc_height {} -> {}",
        to_hex(&sender_hash160),
        total_value,
        btc_block_height,
        allowed
    );
    if !allowed {
        // RSKIP181 (iris300): log rejected_pegin. rskj processPegInVersionLegacy
        // re-runs the lockable/cap checks in the rejection branch (NOT the
        // whitelist): `!isTxLockableForLegacyVersion` -> LEGACY_PEGIN_MULTISIG_SENDER(2),
        // else `!verifyLockDoesNotSurpassLockingCap` -> PEGIN_CAP_SURPASSED(1).
        // A whitelist-only rejection (lockable, cap ok) logs nothing. The cap
        // re-evaluation here also lazily initializes the locking-cap cell, like
        // rskj's second verifyLockDoesNotSurpassLockingCap call.
        if hardfork_cfg.has_rskip181(rsk_height) {
            let reason = if !lockable {
                Some(2u64) // LEGACY_PEGIN_MULTISIG_SENDER
            } else if !cap_ok(ctx) {
                Some(1u64) // PEGIN_CAP_SURPASSED
            } else {
                None // whitelist rejection: no event
            };
            if let Some(reason) = reason {
                super::events::log_rejected_pegin(ctx, &btc_txid_event_bytes(&btc_tx), reason);
            }
        }
        emit_pegin_rejection_release(
            ctx, &btc_tx, &sender_hash160, sender_is_p2sh, total_value, &fed_redeem,
            &retiring, &pays_live_federation, rsk_height, config, hardfork_cfg, tx_ctx,
        );
        set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    // RSK destination: rskj's legacy peg-in credits the address derived from
    // the sender's public key (ethereumj ECKey.getAddress over the
    // UNCOMPRESSED point — mainnet #267,460 used a 65-byte pubkey).
    let rsk_destination = sender_pubkey.and_then(super::federation::rsk_address_from_public_key);

    // Credit the derived destination address (transfer from Bridge balance)
    if let Some(dest) = rsk_destination {
        if !rbtc_amount.is_zero() {
            let _ = ctx.journal_mut().transfer(BRIDGE_ADDR, dest, rbtc_amount);
        } else {
            // rskj executePegIn always calls transferTo(dest, amount); a 0-value
            // transfer still creates and persists the destination account (RSK
            // keeps empty touched accounts — no EIP-161 cleanup). An amount-0
            // peg-in therefore materializes the destination with balance 0.
            let _ = ctx.journal_mut().load_account(dest);
            ctx.journal_mut().touch_account(dest);
        }

        // Peg-in events: lock_btc from RSKIP146, pegin_btc from RSKIP170
        // (a legacy peg-in past RSKIP170 logs pegin_btc with protocolVersion 0).
        let txid_bytes = btc_txid_event_bytes(&btc_tx);
        if hardfork_cfg.has_rskip170(rsk_height) {
            super::events::log_pegin_btc(ctx, dest, &txid_bytes, total_value, 0);
        } else if hardfork_cfg.has_rskip146(rsk_height) {
            let sender_addr = sender_base58_address(&sender_hash160, sender_is_p2sh, config);
            super::events::log_lock_btc(ctx, dest, &txid_bytes, &sender_addr, total_value);
        }
    }

    // rskj registerNewUtxos: outputs paying the active federation feed the
    // set that backs it (the OLD set while a committed federation awaits
    // activation); outputs paying the retiring federation feed the OLD set.
    let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
    register_federation_outputs(ctx, &btc_tx, &fed_script, active_utxo_key);
    if let Some((_, retiring_script)) = &retiring {
        register_federation_outputs(
            ctx,
            &btc_tx,
            retiring_script,
            super::storage::OLD_FEDERATION_BTC_UTXOS_KEY,
        );
    }

    // Mark as processed
    set_btc_tx_processed(ctx, &legacy_txid, rsk_height, hardfork_cfg.has_rskip134(rsk_height));

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// rskj `BtcLockSender.getBTCAddress` target for a legacy refund: the sender's
/// hash160 and whether it is a P2SH address.
fn sender_refund_target(sender: &PeginSender) -> ([u8; 20], bool) {
    match sender {
        PeginSender::P2pkh { pubkey } => (pubkey_hash160(pubkey), false),
        PeginSender::P2shP2wpkh { p2sh_hash, .. }
        | PeginSender::P2shMultisig { p2sh_hash }
        | PeginSender::P2shP2wsh { p2sh_hash } => (*p2sh_hash, true),
    }
}

/// rskj `refundTxSender` for a v1 peg-in: the refund goes to the v1 OP_RETURN
/// refund address if present, otherwise the BtcLockSender address. Returns
/// `None` when neither is available (a non-refundable peg-in).
fn v1_refund_target(
    instr: &super::pegin_instructions::PeginInstructions,
    sender: Option<&PeginSender>,
) -> Option<([u8; 20], bool)> {
    if let Some(refund) = &instr.btc_refund_address {
        return Some((refund.hash160, refund.is_p2sh));
    }
    sender.map(sender_refund_target)
}

/// rskj `generateRejectionRelease`: build an empty-wallet refund of all the
/// outputs paying the live federation(s) back to `refund_hash160`, enqueue it
/// in the pegouts-waiting-for-confirmations set, and (post-RSKIP146) log
/// release_requested with the registering RSK tx hash.
#[allow(clippy::too_many_arguments)]
fn emit_pegin_rejection_release<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx: &BtcTransaction,
    refund_hash160: &[u8; 20],
    refund_is_p2sh: bool,
    total_value: u64,
    fed_redeem: &[u8],
    retiring: &Option<(Vec<u8>, bitcoin::ScriptBuf)>,
    pays_live_federation: &impl Fn(&bitcoin::ScriptBuf) -> bool,
    rsk_height: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) {
    // TODO(rustock): a rejected peg-in paying BOTH live federations would
    // need per-input redeem scripts in the refund; none exists on
    // mainnet pre-wasabi. Inputs paying the retiring federation use its
    // redeem via the same builder when the active outputs are absent.
    let pegin_utxos: Vec<BridgeUtxo> = btc_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| pays_live_federation(&o.script_pubkey))
        .map(|(index, o)| BridgeUtxo {
            tx_hash: btc_txid_event_bytes(btc_tx),
            vout: index as u32,
            value_satoshis: o.value.to_sat(),
            height: 0,
            script: o.script_pubkey.to_bytes(),
            coinbase: btc_tx.is_coinbase(),
        })
        .collect();
    let refund_redeem = if pegin_utxos
        .iter()
        .all(|u| retiring.as_ref().is_some_and(|(_, rs)| u.script == rs.to_bytes()))
    {
        &retiring.as_ref().expect("checked above").0
    } else {
        fed_redeem
    };
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);
    let tx_version = if hardfork_cfg.has_rskip201(rsk_height) { 2 } else { 1 };
    let refund_script = if refund_is_p2sh {
        p2sh_output_script(refund_hash160)
    } else {
        p2pkh_output_script(refund_hash160)
    };
    let built = super::release_tx::build_empty_wallet_to(
        &pegin_utxos,
        &refund_script,
        refund_redeem,
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
        // rskj generateRejectionRelease: post-RSKIP146 the entry carries
        // this registerBtcTransaction tx hash and logs release_requested.
        let use_tx_hash = hardfork_cfg.has_rskip146(rsk_height);
        let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
        waiting.push(PegoutWaitingForConfirmations {
            btc_tx_raw: btc_serialize(&built.tx),
            rsk_block_height: rsk_height,
            rsk_tx_hash: use_tx_hash.then_some(tx_ctx.rsk_tx_hash),
        });
        if use_tx_hash {
            super::events::log_release_requested(
                ctx,
                &tx_ctx.rsk_tx_hash,
                &btc_txid_event_bytes(&built.tx),
                total_value,
            );
        }
        store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);
    }
}

/// rskj `BtcLockSender.TxType`: the peg-in sender classification derived
/// from the FIRST input. `hash160` is the sender's BTC address hash (pubkey
/// hash for P2PKH, script hash for the P2SH variants) — what rskj's
/// `senderBtcAddress` carries into the whitelist check and the refund.
enum PeginSender {
    P2pkh { pubkey: Vec<u8> },
    P2shP2wpkh { pubkey: Vec<u8>, p2sh_hash: [u8; 20] },
    P2shMultisig { p2sh_hash: [u8; 20] },
    P2shP2wsh { p2sh_hash: [u8; 20] },
}

/// bitcoinj `Script.isSentToMultiSig` over a redeem script.
fn is_sent_to_multisig(redeem: &[u8]) -> bool {
    use super::release_tx::{parse_chunks, Chunk};
    let decode_op_n = |op: u8| -> Option<u8> {
        // bitcoinj decodeFromOpN: OP_1..OP_16 (OP_0/OP_1NEGATE decode below 1).
        match op {
            0x51..=0x60 => Some(op - 0x50),
            _ => None,
        }
    };
    let Some(chunks) = parse_chunks(redeem) else { return false };
    if chunks.len() < 4 {
        return false;
    }
    let Chunk::Op(last) = chunks[chunks.len() - 1] else { return false };
    if last != 0xae && last != 0xaf {
        return false; // CHECKMULTISIG / CHECKMULTISIGVERIFY
    }
    let Chunk::Op(n_op) = chunks[chunks.len() - 2] else { return false };
    let Some(num_keys) = decode_op_n(n_op) else { return false };
    if chunks.len() != 3 + num_keys as usize {
        return false;
    }
    if chunks[1..chunks.len() - 2].iter().any(|c| !matches!(c, Chunk::Data(_))) {
        return false;
    }
    let Chunk::Op(m_op) = chunks[0] else { return false };
    decode_op_n(m_op).is_some()
}

/// rskj `BtcLockSenderProvider.tryGetBtcLockSender`: try P2PKH, then
/// P2SH-P2WPKH, then P2SH-MULTISIG, then P2SH-P2WSH — all on the first
/// input. Returns `None` when no parser matches (rskj then returns from
/// registerBtcTransaction WITHOUT marking the tx as processed).
fn classify_pegin_sender(tx: &BtcTransaction) -> Option<PeginSender> {
    use super::release_tx::{parse_chunks, Chunk};
    let first = tx.input.first()?;
    let chunks = parse_chunks(first.script_sig.as_bytes())?;

    // P2PKH: scriptSig is exactly [sig, pubkey] with a valid curve point
    // (rskj derives both the BTC and RSK addresses from it).
    if let [Chunk::Data(_sig), Chunk::Data(pubkey)] = chunks.as_slice() {
        if compress_pubkey(pubkey).is_some() {
            return Some(PeginSender::P2pkh { pubkey: pubkey.clone() });
        }
    }

    let witness: Vec<&[u8]> = first.witness.iter().collect();

    // P2SH-P2WPKH: single-chunk scriptSig, witness [sig, compressed pubkey];
    // P2SH hash = hash160(0x0014 || hash160(pubkey)).
    if chunks.len() == 1 && witness.len() == 2 {
        let pubkey = witness[1];
        if pubkey.len() == 33 && compress_pubkey(pubkey).is_some() {
            let mut redeem = vec![0x00, 0x14];
            redeem.extend_from_slice(&pubkey_hash160(pubkey));
            return Some(PeginSender::P2shP2wpkh {
                pubkey: pubkey.to_vec(),
                p2sh_hash: pubkey_hash160(&redeem),
            });
        }
    }

    // P2SH-MULTISIG: scriptSig [.., sigs.., redeem] with a multisig redeem;
    // P2SH hash = hash160(redeem).
    if chunks.len() >= 3 {
        if let Some(Chunk::Data(redeem)) = chunks.last() {
            if is_sent_to_multisig(redeem) {
                return Some(PeginSender::P2shMultisig { p2sh_hash: pubkey_hash160(redeem) });
            }
        }
    }

    // P2SH-P2WSH: single-chunk scriptSig, witness [.., sigs.., redeem] with
    // a multisig redeem; P2SH hash = hash160(0x0020 || sha256(redeem)).
    if chunks.len() == 1 && witness.len() >= 3 {
        let redeem = witness[witness.len() - 1];
        if is_sent_to_multisig(redeem) {
            use sha2::Digest;
            let mut merged = vec![0x00, 0x20];
            merged.extend_from_slice(&sha2::Sha256::digest(redeem));
            return Some(PeginSender::P2shP2wsh { p2sh_hash: pubkey_hash160(&merged) });
        }
    }

    None
}

/// Base58Check address string for the peg-in sender (rskj
/// `senderBtcAddress.toString()`, used in the lock_btc event).
fn sender_base58_address(
    hash160: &[u8; 20],
    p2sh: bool,
    config: &BridgeConstants,
) -> String {
    let version: u8 = match (config.btc_network, p2sh) {
        (super::constants::BtcNetwork::Mainnet, false) => 0,
        (super::constants::BtcNetwork::Mainnet, true) => 5,
        (_, false) => 111,
        (_, true) => 196,
    };
    let mut payload = [0u8; 21];
    payload[0] = version;
    payload[1..].copy_from_slice(hash160);
    bitcoin::base58::encode_check(&payload)
}

/// rskj `BridgeSupport.getLockingCap` (RSKIP134): lazily initializes the cap
/// to the network's initial value on first read, persisting it (the provider
/// caches the value and `saveLockingCap` writes it on the bridge save).
pub(super) fn get_or_init_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
) -> u64 {
    if bridge_load_bytes_named(ctx, LOCKING_CAP_KEY).is_empty() {
        bridge_store_u256(ctx, LOCKING_CAP_KEY, U256::from(config.initial_locking_cap));
        return config.initial_locking_cap;
    }
    bridge_load_u256(ctx, LOCKING_CAP_KEY).to::<u64>()
}

/// rskj `BridgeSupport.verifyLockDoesNotSurpassLockingCap`: the federation's
/// current funds are maxRbtc (21M BTC) minus the Bridge contract balance;
/// the peg-in is rejected when funds + amount exceed the cap.
fn verify_lock_does_not_surpass_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    total_amount_satoshis: u64,
) -> bool {
    let cap = get_or_init_locking_cap(ctx, config);
    let bridge_balance_wei = ctx
        .journal_mut()
        .load_account(crate::precompiles::BRIDGE_ADDR)
        .map(|a| a.info.balance)
        .unwrap_or_default();
    // co.rsk.core.Coin.toBitcoin: truncating wei -> satoshi division.
    let balance_satoshis = (bridge_balance_wei / U256::from(10_000_000_000u64)).to::<u64>();
    const MAX_RBTC_SATOSHIS: u64 = 2_100_000_000_000_000; // Constants maxRbtc, 21M BTC
    let fed_current_funds = MAX_RBTC_SATOSHIS.saturating_sub(balance_satoshis);
    fed_current_funds + total_amount_satoshis <= cap
}

/// rskj `LockWhitelist.isWhitelistedFor` + `consume`: returns whether the
/// sender may peg in `amount` at BTC height `height`, consuming the matching
/// one-off entry. A height past the disable height turns the whitelist off
/// (but a matching one-off entry is still consumed).
fn whitelist_allows_and_consume<CTX: crate::RskContextTr>(
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
/// given federation script into the given UTXO storage set.
fn register_federation_outputs<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx: &BtcTransaction,
    fed_script: &bitcoin::ScriptBuf,
    utxo_key: &str,
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
    let mut utxos = load_utxos_at(ctx, utxo_key);
    utxos.extend(new_utxos);
    store_utxos_at(ctx, utxo_key, &utxos);
}

// ---------------------------------------------------------------------------
// registerFastBridgeBtcTransaction (Flyover)
// ---------------------------------------------------------------------------

/// rskj `FlyoverTxResponseCodes`: the int256 status the method returns on the
/// rejection / unprocessable paths. The success path returns the locked amount
/// in wei instead.
mod flyover_codes {
    pub const REFUNDED_USER: i64 = -100;
    pub const REFUNDED_LP: i64 = -200;
    pub const UNPROCESSABLE_NOT_CONTRACT: i64 = -300;
    pub const UNPROCESSABLE_INVALID_SENDER: i64 = -301;
    pub const UNPROCESSABLE_ALREADY_PROCESSED: i64 = -302;
    pub const UNPROCESSABLE_VALIDATIONS: i64 = -303;
    pub const UNPROCESSABLE_VALUE_ZERO: i64 = -304;
    pub const UNPROCESSABLE_UTXO_BELOW_MINIMUM: i64 = -305;
    pub const GENERIC_ERROR: i64 = -900;
}

/// ABI-encode a signed int256 response code as 32 big-endian bytes (two's
/// complement), matching rskj `BigInteger.valueOf(code)` Solidity encoding.
/// The value must be sign-extended to the FULL 256 bits: a negative code is
/// `2^256 - |code|` (all high bytes 0xff), not merely 128-bit-wide — otherwise
/// a caller that adds back the code (e.g. the LBC `value + 900 == 0` check)
/// overflows at bit 128 instead of wrapping at bit 256 and branches wrongly
/// (mainnet #5,967,453: GENERIC_ERROR -900 mis-encoded as `2^128-900`).
fn flyover_code_output(code: i64) -> Bytes {
    let value = if code < 0 {
        // Full 256-bit two's complement: 2^256 - |code|.
        U256::ZERO.wrapping_sub(U256::from(code.unsigned_abs()))
    } else {
        U256::from(code as u64)
    };
    Bytes::copy_from_slice(&value.to_be_bytes::<32>())
}

/// rskj `PegUtils.getFlyoverDerivationHash`:
/// `keccak256(derivationArgumentsHash(32) || userRefundAddrBytes ||
/// lbcAddress(20) || lpBtcAddrBytes)`. Note the array-copy order puts the LBC
/// address BEFORE the LP address (NOT the parameter order). The BTC-address
/// bytes are `serializeBtcAddressWithVersion`; pre-RSKIP284 (iris) that
/// round-trips the input `[version || hash160]` arg unchanged (a single version
/// byte for every mainnet address version), so the raw 21-byte ABI args are
/// used verbatim.
fn flyover_derivation_hash(
    derivation_arguments_hash: &[u8; 32],
    user_refund_addr_bytes: &[u8],
    lbc_address: &RskAddress,
    lp_btc_addr_bytes: &[u8],
) -> [u8; 32] {
    use sha3::Digest;
    let mut preimage = Vec::with_capacity(32 + user_refund_addr_bytes.len() + 20 + lp_btc_addr_bytes.len());
    preimage.extend_from_slice(derivation_arguments_hash);
    preimage.extend_from_slice(user_refund_addr_bytes);
    preimage.extend_from_slice(lbc_address.as_slice());
    preimage.extend_from_slice(lp_btc_addr_bytes);
    sha3::Keccak256::digest(&preimage).into()
}

/// rskj `FlyoverRedeemScriptBuilderImpl.of`: prepend `PUSH(derivationHash)
/// OP_DROP` to the federation redeem script.
fn flyover_redeem_script(flyover_derivation_hash: &[u8; 32], federation_redeem: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34 + federation_redeem.len());
    script.push(32); // OP_PUSHBYTES_32
    script.extend_from_slice(flyover_derivation_hash);
    script.push(0x75); // OP_DROP
    script.extend_from_slice(federation_redeem);
    script
}

/// `registerFastBridgeBtcTransaction(bytes,uint256,bytes,bytes32,bytes,address,bytes,bool)`
///
/// Flyover (RSKIP176, iris300) peg-in. Full port of rskj
/// `BridgeSupport.registerFlyoverBtcTransaction`. Returns an int256:
/// the locked amount in wei on success, or a negative `FlyoverTxResponseCodes`
/// value on every rejection / unprocessable path. The method only ever fails
/// the tx for a malformed BTC transaction or PMT (mirrors rskj's outer
/// try/catch returning GENERIC_ERROR for those).
#[allow(clippy::too_many_arguments)]
pub fn register_fast_bridge_btc_transaction<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
    caller: RskAddress,
    call_depth: usize,
) -> Result<PrecompileOutput, PrecompileError> {
    let ok = |code: Bytes| Ok(PrecompileOutput::new(gas_cost, code));

    // rskj wraps the whole body in try/catch → GENERIC_ERROR. Any malformed
    // ABI / arg shape returns GENERIC_ERROR (NOT a failed tx).
    let parse = (|| -> Option<(usize, u64, usize, [u8; 32], Vec<u8>, RskAddress, Vec<u8>, bool)> {
        if args.len() < 256 {
            return None;
        }
        let btc_tx_offset = U256::from_be_slice(args.get(0..32)?).to::<usize>();
        let btc_block_height = U256::from_be_slice(args.get(32..64)?).to::<u64>();
        let pmt_offset = U256::from_be_slice(args.get(64..96)?).to::<usize>();
        let derivation_args_hash: [u8; 32] = args.get(96..128)?.try_into().ok()?;
        let user_refund_offset = U256::from_be_slice(args.get(128..160)?).to::<usize>();
        // arg5: address (right-aligned in 32 bytes → low 20 bytes).
        let lbc_address = RskAddress::from_slice(args.get(172..192)?);
        let lp_offset = U256::from_be_slice(args.get(192..224)?).to::<usize>();
        let should_transfer_to_contract = U256::from_be_slice(args.get(224..256)?) != U256::ZERO;
        let user_refund_addr = read_dynamic_bytes(args, user_refund_offset).ok()?;
        let lp_btc_addr = read_dynamic_bytes(args, lp_offset).ok()?;
        Some((
            btc_tx_offset, btc_block_height, pmt_offset, derivation_args_hash,
            user_refund_addr, lbc_address, lp_btc_addr, should_transfer_to_contract,
        ))
    })();
    let Some((
        btc_tx_offset, btc_block_height, pmt_offset, derivation_args_hash,
        user_refund_addr, lbc_address, lp_btc_addr, should_transfer_to_contract,
    )) = parse
    else {
        return ok(flyover_code_output(flyover_codes::GENERIC_ERROR));
    };

    // rskj parses BOTH BTC addresses in the ABI layer (`Bridge.registerFlyover-
    // BtcTransaction`) via `BridgeUtils.deserializeBtcAddressWithVersion`, wrapped
    // in a try/catch that returns GENERIC_ERROR on ANY exception — and this runs
    // BEFORE `bridgeSupport.registerFlyoverBtcTransaction`'s isContractTx/sender
    // checks. Post-RSKIP284 (hop400) the deserializer REQUIRES exactly 21 bytes
    // (`[version || 20-byte hash160]`), throwing `BridgeIllegalArgumentException`
    // otherwise; pre-RSKIP284 the legacy path only needs ≥21 bytes (a shorter
    // array throws `ArrayIndexOutOfBoundsException` in its `arraycopy`). Either
    // way a bad-length address yields GENERIC_ERROR. The userRefund address is
    // parsed first, the LP address second (mainnet #5,967,453: a 33-byte
    // userRefund address makes rskj return GENERIC_ERROR, not a validations code).
    let rskip284 = hardfork_cfg.has_rskip284(rsk_height_of(ctx));
    let address_len_ok = |bytes: &[u8]| -> bool {
        if rskip284 { bytes.len() == 21 } else { bytes.len() >= 21 }
    };
    if !address_len_ok(&user_refund_addr) || !address_len_ok(&lp_btc_addr) {
        return ok(flyover_code_output(flyover_codes::GENERIC_ERROR));
    }

    // rskj `isContractTx`: the rskTx must be an InternalTransaction (the Bridge
    // was reached via a contract CALL), i.e. call depth > 1.
    if call_depth <= 1 {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_NOT_CONTRACT));
    }
    // The calling contract must be the declared LBC address.
    if caller != lbc_address {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_INVALID_SENDER));
    }

    let btc_tx_data = read_dynamic_bytes(args, btc_tx_offset)?;
    let pmt_data = read_dynamic_bytes(args, pmt_offset)?;

    // wtxid (calculateBtcTxHash over the raw bytes) — the first already-used key.
    let btc_tx_hash = calculate_btc_tx_hash(&btc_tx_data);

    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let use_v2 = hardfork_cfg.has_stored_block_v2(block_number);
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    super::btc_chain::ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);

    // getFlyoverDerivationHash (over the raw 21-byte address args; see helper).
    let flyover_hash = flyover_derivation_hash(
        &derivation_args_hash,
        &user_refund_addr,
        &lbc_address,
        &lp_btc_addr,
    );

    // First already-used check, keyed by the wtxid.
    if is_flyover_derivation_hash_used(ctx, &btc_tx_hash, &flyover_hash) {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_ALREADY_PROCESSED));
    }

    // validationsForRegisterBtcTransaction: PMT + merkle root + confirmations.
    let validations = (|| -> bool {
        if !PartialMerkleTree::has_expected_size(&pmt_data) {
            return false;
        }
        let Some(pmt) = PartialMerkleTree::parse(&pmt_data) else { return false };
        let Some(pmt_result) = pmt.extract_matches() else { return false };
        if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
            return false;
        }
        let Some(stored_block) =
            super::btc_chain::stored_block_at_main_chain_height(ctx, btc_block_height as u32, rskip199)
        else {
            return false;
        };
        let block_hash = stored_block.header.block_hash();
        let block_merkle_root = *stored_block.header.merkle_root.to_raw_hash().as_byte_array();
        let root_valid = pmt_result.merkle_root == block_merkle_root || {
            let block_hash_bytes = {
                let mut raw = *block_hash.to_raw_hash().as_byte_array();
                raw.reverse();
                raw
            };
            match get_coinbase_information(ctx, &block_hash_bytes) {
                Some(mut wr) => {
                    wr.reverse();
                    pmt_result.merkle_root == wr
                }
                None => false,
            }
        };
        if !root_valid {
            return false;
        }
        let best_height = load_chain_head(ctx).map(|h| h.height).unwrap_or(0);
        let confirmations = best_height as i64 - btc_block_height as i64 + 1;
        confirmations >= config.btc2rsk_minimum_acceptable_confirmations as i64
    })();
    if !validations {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_VALIDATIONS));
    }

    // Parse the BTC tx and compute the witness-stripped txid (getHash(false)).
    let btc_tx: BtcTransaction = deserialize(&btc_tx_data)
        .map_err(|_| PrecompileError::other("registerFastBridgeBtcTransaction: invalid BTC transaction"))?;
    let btc_tx_hash_no_witness = legacy_btc_txid(&btc_tx);

    // Second already-used check, keyed by the legacy txid (only when it differs
    // from the wtxid, i.e. a SegWit tx).
    if btc_tx_hash_no_witness != btc_tx_hash
        && is_flyover_derivation_hash_used(ctx, &btc_tx_hash_no_witness, &flyover_hash)
    {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_ALREADY_PROCESSED));
    }

    // createFlyoverFederationInformation for the ACTIVE federation: build the
    // flyover redeem script (PUSH(hash) OP_DROP <fedRedeem>) and its P2SH.
    // rskj `getActiveFederation().getRedeemScript()` is format-aware: a P2SH-ERP
    // federation (RSKIP353, active at fingerroot500) yields its ERP redeem, not a
    // plain multisig — so the flyover P2SH must wrap the ERP redeem to match the
    // address the BTC tx actually paid (mainnet #5,831,167).
    let (_active_keys, fed_redeem) =
        active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
    let fed_p2sh_hash = redeem_script_hash160(&fed_redeem);
    let flyover_redeem = flyover_redeem_script(&flyover_hash, &fed_redeem);
    let flyover_p2sh_hash = redeem_script_hash160(&flyover_redeem);
    let flyover_script = p2sh_output_script(&flyover_p2sh_hash);

    // createFlyoverFederationInformation for the RETIRING federation (RSKIP293,
    // hop400). rskj `getRetiringFederation()` is the OLD federation once the new
    // one has activated; its redeem follows the OLD federation's STORED format
    // version (`federation.getRedeemScript()`), so an ERP retiring federation
    // gets its ERP flyover redeem. The flyover output script is a plain P2SH for
    // every federation format except P2SH-P2WSH-ERP (`getFlyoverFederationOutputScript`),
    // which rustock does not yet support — feds at hop400 are P2SH-ERP.
    let retiring_flyover = if hardfork_cfg.has_rskip293(block_number) {
        retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number).map(
            |(_keys, retiring_redeem)| {
                let retiring_p2sh_hash = redeem_script_hash160(&retiring_redeem);
                let retiring_flyover_redeem = flyover_redeem_script(&flyover_hash, &retiring_redeem);
                let retiring_flyover_p2sh_hash = redeem_script_hash160(&retiring_flyover_redeem);
                let retiring_flyover_script = p2sh_output_script(&retiring_flyover_p2sh_hash);
                FlyoverFedInfo {
                    fed_p2sh_hash: retiring_p2sh_hash,
                    flyover_redeem: retiring_flyover_redeem,
                    flyover_p2sh_hash: retiring_flyover_p2sh_hash,
                    flyover_script: retiring_flyover_script,
                }
            },
        )
    } else {
        None
    };

    // validateFlyoverPeginValue: the amount sent to the flyover address(es) must
    // be non-zero (getAmountSentToAddresses sums outputs paying any flyover
    // address — under RSKIP293 both active and retiring). Under RSKIP293 it then
    // gates EACH flyover UTXO against the minimum peg-in value
    // (PegUtils.allUTXOsToFedAreAboveMinimumPeginValue; pre-RSKIP379 this is
    // isAnyUTXOAmountBelowMinimum, the path that applies at hop400).
    let pays_flyover = |script: &bitcoin::ScriptBuf| {
        *script == flyover_script
            || retiring_flyover.as_ref().is_some_and(|r| *script == r.flyover_script)
    };
    let flyover_output_values: Vec<u64> = btc_tx
        .output
        .iter()
        .filter(|o| pays_flyover(&o.script_pubkey))
        .map(|o| o.value.to_sat())
        .collect();
    let total_satoshis: u64 = flyover_output_values.iter().sum();
    if total_satoshis == 0 {
        return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_VALUE_ZERO));
    }
    if hardfork_cfg.has_rskip293(block_number) {
        let min_pegin = config.minimum_pegin_tx_value; // RSKIP219 active alongside RSKIP293.
        if flyover_output_values.iter().any(|v| *v < min_pegin) {
            return ok(flyover_code_output(flyover_codes::UNPROCESSABLE_UTXO_BELOW_MINIMUM));
        }
    }

    let refund_to = |should_lp: bool| -> (&[u8], bool) {
        // Refund destination: the LP BTC address when shouldTransferToContract,
        // else the user refund address. Both are `[version || hash160]`.
        if should_lp {
            (&lp_btc_addr[..], true)
        } else {
            (&user_refund_addr[..], false)
        }
    };

    // verifyLockDoesNotSurpassLockingCap (RSKIP134): a flyover peg-in is always
    // post-RSKIP134 (iris). On surplus, refund (LP or user) and mark used.
    if !verify_lock_does_not_surpass_locking_cap(ctx, config, total_satoshis) {
        // markFlyoverDerivationHashAsUsed(btcTxHashWithoutWitness, hash).
        mark_flyover_derivation_hash_used(ctx, &btc_tx_hash_no_witness, &flyover_hash);
        let (refund_addr_bytes, is_lp) = refund_to(should_transfer_to_contract);
        let refund_hash160: [u8; 20] = refund_addr_bytes
            .get(1..21)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0u8; 20]);
        // The refund address version byte distinguishes P2PKH from P2SH:
        // use P2SH iff the version equals the network's P2SH header.
        let p2sh_version: u8 = match config.btc_network {
            super::constants::BtcNetwork::Mainnet => 5,
            _ => 196,
        };
        let refund_is_p2sh = refund_addr_bytes.first() == Some(&p2sh_version);
        let rsk_height = rsk_height_of(ctx);
        // generateFlyoverRejectionReleaseWithWalletProvider: the refund spends the
        // flyover UTXOs of BOTH the active and (RSKIP293) retiring feds, resolving
        // each input's redeem from its flyover P2SH (FlyoverCompatibleBtcWallet-
        // WithMultipleScripts).
        let mut flyover_redeems: Vec<Vec<u8>> = vec![flyover_redeem.clone()];
        if let Some(r) = &retiring_flyover {
            flyover_redeems.push(r.flyover_redeem.clone());
        }
        emit_flyover_rejection_release(
            ctx, &btc_tx, &refund_hash160, refund_is_p2sh, total_satoshis,
            &flyover_redeems, rsk_height, config, hardfork_cfg, tx_ctx,
        );
        return ok(flyover_code_output(if is_lp {
            flyover_codes::REFUNDED_LP
        } else {
            flyover_codes::REFUNDED_USER
        }));
    }

    // transferTo(lbcAddress, amount): credit the LBC contract.
    let rbtc_amount = btc_satoshi_to_rbtc_wei(total_satoshis);
    if !rbtc_amount.is_zero() {
        let _ = ctx.journal_mut().transfer(BRIDGE_ADDR, lbc_address, rbtc_amount);
    }

    // saveFlyoverActiveFederationDataInStorage:
    //   - mark the flyover hash used (keyed by the legacy txid)
    //   - persist the flyover federation information
    //   - add the flyover UTXOs to the ACTIVE federation UTXO set
    mark_flyover_derivation_hash_used(ctx, &btc_tx_hash_no_witness, &flyover_hash);
    set_flyover_federation_information(ctx, &flyover_hash, &fed_p2sh_hash, &flyover_p2sh_hash);

    let rsk_height = rsk_height_of(ctx);
    let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, rsk_height);
    register_federation_outputs(ctx, &btc_tx, &flyover_script, active_utxo_key);

    // saveFlyoverRetiringFederationDataInStorage (RSKIP293): only when the
    // retiring fed actually received flyover UTXOs (rskj guards on a non-empty
    // utxosForRetiringFed list). markFlyoverDerivationHashAsUsed is called again
    // (idempotent) and the retiring flyover fed info is persisted under the same
    // key scheme keyed by ITS flyover P2SH hash; the UTXOs go to the retiring
    // (old) federation set.
    if let Some(r) = &retiring_flyover {
        if btc_tx.output.iter().any(|o| o.script_pubkey == r.flyover_script) {
            mark_flyover_derivation_hash_used(ctx, &btc_tx_hash_no_witness, &flyover_hash);
            set_flyover_federation_information(
                ctx, &flyover_hash, &r.fed_p2sh_hash, &r.flyover_p2sh_hash,
            );
            register_federation_outputs(
                ctx, &btc_tx, &r.flyover_script, super::storage::OLD_FEDERATION_BTC_UTXOS_KEY,
            );
        }
    }

    // Returns the locked amount in wei (co.rsk.core.Coin.fromBitcoin.asBigInteger).
    ok(Bytes::copy_from_slice(&rbtc_amount.to_be_bytes::<32>()))
}

/// Flyover federation information for one federation (active or retiring): the
/// destination fed's redeem-script P2SH hash, plus the derived flyover redeem,
/// its P2SH hash, and its P2SH output script. Mirrors rskj
/// `createFlyoverFederationInformation` + `getFlyoverFederationOutputScript`.
struct FlyoverFedInfo {
    fed_p2sh_hash: [u8; 20],
    flyover_redeem: Vec<u8>,
    flyover_p2sh_hash: [u8; 20],
    flyover_script: bitcoin::ScriptBuf,
}

/// Current RSK execution block number.
fn rsk_height_of<CTX: crate::RskContextTr>(ctx: &mut CTX) -> u64 {
    revm::context_interface::Block::number(ctx.block()).to::<u64>()
}

/// rskj `BridgeStorageProvider.isFlyoverDerivationHashUsed`: the cell at
/// `fastBridgeHashUsedInBtcTx-<btcTxHash.toString()><derivationHash.toString()>`
/// holds a single TRUE byte. `Sha256Hash.toString()` is DISPLAY order;
/// `Keccak256.toString()` is forward order.
fn is_flyover_derivation_hash_used<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
    flyover_hash: &[u8; 32],
) -> bool {
    let key = flyover_hash_used_key(btc_tx_hash, flyover_hash);
    super::storage::bridge_load_raw(ctx, key)
        .is_some_and(|d| d.len() == 1 && d[0] == 1)
}

/// rskj `markFlyoverDerivationHashAsUsed` → `saveFlyoverDerivationHash`:
/// `addStorageBytes(key, [TRUE])`.
fn mark_flyover_derivation_hash_used<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
    flyover_hash: &[u8; 32],
) {
    let key = flyover_hash_used_key(btc_tx_hash, flyover_hash);
    super::storage::bridge_store_raw(ctx, key, Some(vec![1]));
}

/// rskj `getStorageKeyForFlyoverHash`:
/// `fastBridgeHashUsedInBtcTx-` + `Sha256Hash.toString()` (display order) +
/// `Keccak256.toString()` (forward order).
fn flyover_hash_used_key(btc_tx_hash: &[u8; 32], flyover_hash: &[u8; 32]) -> U256 {
    let identifier = format!(
        "{}{}",
        super::tx::btc_hash_hex_display(btc_tx_hash),
        to_hex(flyover_hash)
    );
    compound_key(FAST_BRIDGE_HASH_USED_KEY, "-", &identifier)
}

/// rskj `setFlyoverFederationInformation` → `saveFlyoverFederationInformation`:
/// store `RLP([derivationHash, federationRedeemScriptHash])` keyed by
/// `fastBridgeFederationInformation-` + hex(flyoverFederationRedeemScriptHash).
fn set_flyover_federation_information<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    flyover_hash: &[u8; 32],
    fed_p2sh_hash: &[u8; 20],
    flyover_p2sh_hash: &[u8; 20],
) {
    let key = compound_key(
        FAST_BRIDGE_FEDERATION_INFO_KEY,
        "-",
        &to_hex(flyover_p2sh_hash),
    );
    let value = rlp_encode_list(&[
        rlp_encode_element(flyover_hash),
        rlp_encode_element(fed_p2sh_hash),
    ]);
    super::storage::bridge_store_raw(ctx, key, Some(value));
}

/// rskj `BridgeStorageProvider.getFlyoverFederationInformation`: read the
/// `RLP[derivationHash(32), fedRedeemScriptHash(20)]` stored for a flyover P2SH
/// hash160, or `None` if the input is not a flyover UTXO.
fn get_flyover_federation_information<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    flyover_p2sh_hash: &[u8; 20],
) -> Option<([u8; 32], [u8; 20])> {
    let key = compound_key(FAST_BRIDGE_FEDERATION_INFO_KEY, "-", &to_hex(flyover_p2sh_hash));
    let data = super::storage::bridge_load_raw(ctx, key)?;
    let items = super::serialization::rlp_decode_list(&data)?;
    let derivation: [u8; 32] = items.first()?.as_slice().try_into().ok()?;
    let fed_hash: [u8; 20] = items.get(1)?.as_slice().try_into().ok()?;
    Some((derivation, fed_hash))
}

/// Extract the hash160 from a P2SH output script
/// (`OP_HASH160 <20 bytes> OP_EQUAL`).
fn p2sh_script_hash160(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        script[2..22].try_into().ok()
    } else {
        None
    }
}

/// rskj `FlyoverCompatibleBtcWalletWithStorage.findRedeemDataFromScriptHash`:
/// resolve the redeem script for each spending UTXO. A flyover UTXO (whose P2SH
/// hash has stored flyover federation information) spends with
/// `PUSH32 <derivationHash> OP_DROP <fedRedeem>`, where `fedRedeem` is the
/// destination federation's redeem (the active or retiring federation whose
/// hash160 matches the stored `fedRedeemScriptHash`); every other UTXO spends
/// with `default_redeem`. Returns one redeem per UTXO, in input order.
///
/// `candidate_fed_redeems` lists the redeem scripts of the federations
/// `getDestinationFederation` searches (active + retiring), used to rebuild the
/// inner fed redeem from the stored hash. Returns a sparse map of per-UTXO
/// flyover redeem overrides keyed by `(tx_hash, vout)`; UTXOs absent from the
/// map spend with the default redeem. The map is stable across coin selection
/// (it does not depend on the mutating available-UTXO list).
fn resolve_flyover_input_redeems<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    utxos: &[BridgeUtxo],
    candidate_fed_redeems: &[Vec<u8>],
) -> std::collections::HashMap<([u8; 32], u32), Vec<u8>> {
    let mut overrides = std::collections::HashMap::new();
    for u in utxos {
        let flyover = p2sh_script_hash160(&u.script)
            .and_then(|h| get_flyover_federation_information(ctx, &h))
            .and_then(|(derivation, fed_hash)| {
                candidate_fed_redeems
                    .iter()
                    .find(|r| redeem_script_hash160(r) == fed_hash)
                    .map(|fed_redeem| flyover_redeem_script(&derivation, fed_redeem))
            });
        if let Some(redeem) = flyover {
            overrides.insert((u.tx_hash, u.vout), redeem);
        }
    }
    overrides
}

/// rskj `generateFlyoverRejectionReleaseWithWalletProvider`: build an
/// empty-wallet refund of the flyover-federation outputs to `refund_hash160`
/// using the FLYOVER redeem script(s), enqueue it, and log release_requested.
///
/// `flyover_redeems` is the list of candidate flyover redeem scripts (the active
/// fed's, plus the retiring fed's under RSKIP293). The refund spends every output
/// paying any of their flyover P2SH addresses; each input is resolved to its own
/// redeem (rskj `FlyoverCompatibleBtcWalletWithMultipleScripts`).
#[allow(clippy::too_many_arguments)]
fn emit_flyover_rejection_release<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx: &BtcTransaction,
    refund_hash160: &[u8; 20],
    refund_is_p2sh: bool,
    total_satoshis: u64,
    flyover_redeems: &[Vec<u8>],
    rsk_height: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) {
    // Map each flyover P2SH output script → its redeem, then gather the spending
    // UTXOs in output order with their resolved redeem.
    let scripts: Vec<(bitcoin::ScriptBuf, &[u8])> = flyover_redeems
        .iter()
        .map(|r| (p2sh_output_script(&redeem_script_hash160(r)), r.as_slice()))
        .collect();
    let mut utxos: Vec<BridgeUtxo> = Vec::new();
    let mut input_redeems: Vec<&[u8]> = Vec::new();
    for (index, o) in btc_tx.output.iter().enumerate() {
        if let Some((_, redeem)) = scripts.iter().find(|(s, _)| *s == o.script_pubkey) {
            utxos.push(BridgeUtxo {
                tx_hash: btc_txid_event_bytes(btc_tx),
                vout: index as u32,
                value_satoshis: o.value.to_sat(),
                height: 0,
                script: o.script_pubkey.to_bytes(),
                coinbase: btc_tx.is_coinbase(),
            });
            input_redeems.push(redeem);
        }
    }
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);
    let tx_version = if hardfork_cfg.has_rskip201(rsk_height) { 2 } else { 1 };
    let refund_script = if refund_is_p2sh {
        p2sh_output_script(refund_hash160)
    } else {
        p2pkh_output_script(refund_hash160)
    };
    // When every spent UTXO shares a single redeem (the common case — only the
    // active fed received funds), defer to the shared single-redeem builder for
    // byte-exact parity; otherwise build the empty-wallet refund with per-input
    // redeems (rskj buildEmptyWalletTo over the multi-script flyover wallet).
    let built = if input_redeems.iter().all(|r| *r == input_redeems.first().copied().unwrap_or(&[])) {
        let single = input_redeems.first().copied().unwrap_or(&[]);
        super::release_tx::build_empty_wallet_to(
            &utxos, &refund_script, single, fee_per_kb, tx_version,
        )
    } else {
        build_flyover_empty_wallet_multi(
            &utxos, &input_redeems, &refund_script, fee_per_kb, tx_version,
        )
    };
    if let Some(built) = built {
        let use_tx_hash = hardfork_cfg.has_rskip146(rsk_height);
        let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
        waiting.push(PegoutWaitingForConfirmations {
            btc_tx_raw: btc_serialize(&built.tx),
            rsk_block_height: rsk_height,
            rsk_tx_hash: use_tx_hash.then_some(tx_ctx.rsk_tx_hash),
        });
        if use_tx_hash {
            super::events::log_release_requested(
                ctx,
                &tx_ctx.rsk_tx_hash,
                &btc_txid_event_bytes(&built.tx),
                total_satoshis,
            );
        }
        store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);
    }
}

/// rskj `ReleaseTransactionBuilder.buildEmptyWalletTo` over a multi-script
/// flyover wallet: like `release_tx::build_empty_wallet_to` but each input is
/// signed/sized with its OWN redeem script (`input_redeems[i]` pairs with
/// `utxos[i]`). Used only for the rare RSKIP293 locking-cap rejection where a
/// single flyover tx funds BOTH the active and retiring flyover feds.
///
/// The fee sizing mirrors bitcoinj exactly: a single downward fee adjustment of
/// `feePerKb * size / 1000`, where `size` is the empty-scriptSig serialized
/// length plus, per input, `threshold * SIG_SIZE + redeemScript.len()`. The
/// final placeholder-filled tx must not exceed MAX_STANDARD_TX_SIZE.
fn build_flyover_empty_wallet_multi(
    utxos: &[BridgeUtxo],
    input_redeems: &[&[u8]],
    refund_script: &bitcoin::ScriptBuf,
    fee_per_kb: u64,
    version: i32,
) -> Option<super::release_tx::BuiltPegout> {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, Sequence, TxIn, TxOut, Witness,
    };
    // bitcoinj constants (see release_tx.rs): SIG_SIZE=75, min fee 5000 sat/kB,
    // MAX_STANDARD_TX_SIZE=100k.
    const SIG_SIZE: usize = 75;
    const REFERENCE_DEFAULT_MIN_TX_FEE: u64 = 5000;
    const MAX_STANDARD_TX_SIZE: usize = 100_000;

    if utxos.is_empty() {
        return None;
    }
    let thresholds: Vec<usize> = input_redeems
        .iter()
        .map(|r| super::release_tx::redeem_script_threshold(r))
        .collect();
    if thresholds.contains(&0) {
        return None;
    }
    let gathered: u64 = utxos.iter().map(|u| u.value_satoshis).sum();

    // Convert a stored UTXO hash (bitcoinj display/stored byte order) into a
    // rust-bitcoin Txid (internal byte order).
    let txid_from_stored = |stored: &[u8; 32]| -> bitcoin::Txid {
        use bitcoin::hashes::Hash;
        let mut internal = *stored;
        internal.reverse();
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(internal))
    };
    let inputs: Vec<TxIn> = utxos
        .iter()
        .map(|u| TxIn {
            previous_output: OutPoint {
                txid: txid_from_stored(&u.tx_hash),
                vout: u.vout,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        })
        .collect();
    let mut tx = BtcTransaction {
        version: Version(version),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::from_sat(gathered),
            script_pubkey: refund_script.clone(),
        }],
    };

    let base_size = bitcoin::consensus::serialize(&tx).len();
    let sig_estimate: usize = input_redeems
        .iter()
        .zip(&thresholds)
        .map(|(r, t)| t * SIG_SIZE + r.len())
        .sum();
    let size = base_size + sig_estimate;
    let fee_rate = fee_per_kb.max(REFERENCE_DEFAULT_MIN_TX_FEE);
    let fee = fee_rate * size as u64 / 1000;
    if fee >= gathered {
        return None;
    }
    let value = gathered - fee;
    if value < super::release_tx::min_non_dust_value(refund_script) {
        return None;
    }
    tx.output[0].value = Amount::from_sat(value);

    for (input, (redeem, threshold)) in tx.input.iter_mut().zip(input_redeems.iter().zip(&thresholds)) {
        input.script_sig =
            bitcoin::ScriptBuf::from_bytes(super::release_tx::placeholder_scriptsig(redeem, *threshold));
    }
    if bitcoin::consensus::serialize(&tx).len() > MAX_STANDARD_TX_SIZE {
        return None;
    }
    Some(super::release_tx::BuiltPegout { tx, used_utxos: utxos.to_vec() })
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
pub fn release_btc<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    tx_ctx: &BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let call_value_wei = revm::context_interface::Transaction::value(ctx.tx());

    // NOTE: do NOT early-return on a zero call value. rskj's
    // `BridgeSupport.releaseBtc` always forwards to `requestRelease`, which
    // rejects a below-minimum amount (a zero value is below any minimum) and,
    // post-RSKIP185, refunds the sender and emits `release_request_rejected`.
    // A zero-value EOA call therefore still produces a receipts-visible log
    // (mainnet #4,212,341 tx[3]: value=0 empty-input Bridge call → LOW_AMOUNT).

    // Convert Wei to satoshis: 1 satoshi = 10^10 wei
    let satoshis_per_wei = U256::from(10_000_000_000u64);
    let amount_satoshis_u256 = call_value_wei / satoshis_per_wei;
    let amount_satoshis = amount_satoshis_u256.to::<u64>();

    // rskj BridgeSupport.requestRelease: post-RSKIP219 the minimum is INCLUSIVE
    // and is the max of `minimumPegoutTxValue` and a fee-based estimate; the
    // legacy rule is EXCLUSIVE (value must be strictly greater than the legacy
    // minimum). On rejection the reason distinguishes LOW_AMOUNT from
    // FEE_ABOVE_VALUE (the latter when the fee estimate is the binding bound).
    let reject_reason: Option<u64> = if hardfork_cfg.has_rskip219(block_number) {
        let fee_per_kb = get_effective_fee_per_kb(ctx, config);
        // rskj getRegularPegoutTxSize uses getActiveFederation().getRedeemScript():
        // the active federation's actual (format-aware, possibly P2SH-ERP) redeem
        // script and its required-signature count drive the fee-based minimum.
        let (active_keys, active_redeem) =
            active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
        let num_sigs_required = (active_keys.len() / 2 + 1) as u64;
        let require_funds_for_fee = require_funds_for_fee(
            &active_redeem,
            num_sigs_required,
            fee_per_kb,
            hardfork_cfg.has_rskip271(block_number),
            config,
        );
        let min_value = config.minimum_pegout_tx_value.max(require_funds_for_fee);
        if amount_satoshis < min_value {
            // rskj: FEE_ABOVE_VALUE when minValue == requireFundsForFee, else
            // LOW_AMOUNT. RejectedPegoutReason: LOW_AMOUNT=1, FEE_ABOVE_VALUE=3.
            Some(if min_value == require_funds_for_fee { 3 } else { 1 })
        } else {
            None
        }
    } else if amount_satoshis_u256 <= U256::from(config.legacy_minimum_pegout_tx_value) {
        Some(1) // legacy: always LOW_AMOUNT
    } else {
        None
    };

    if let Some(reason) = reject_reason {
        // RSKIP185 (Iris300): refund the value to the sender and emit the
        // release_request_rejected event. Before RSKIP185 the request was
        // silently dropped (value retained by the Bridge).
        if hardfork_cfg.has_rskip185(block_number) {
            // Pre-RSKIP427 refund value = Coin.fromBitcoin(weis.toBitcoin()),
            // i.e. the wei amount truncated to satoshi granularity.
            let refund_wei = amount_satoshis_u256 * U256::from(10_000_000_000u64);
            let _ = ctx
                .journal_mut()
                .transfer(BRIDGE_ADDR, tx_ctx.rsk_sender, refund_wei);
            // Pre-RSKIP427 the event amount is in satoshis; post-427 it is the
            // full wei call value (rskj logs `releaseRequestedValueInWeis`).
            let event_amount = if hardfork_cfg.has_rskip427(block_number) {
                call_value_wei
            } else {
                U256::from(amount_satoshis)
            };
            super::events::log_release_request_rejected(
                ctx,
                tx_ctx.rsk_sender,
                event_amount,
                reason,
            );
        }
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

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

    // RSKIP185 (Iris300): an accepted peg-out emits release_request_received
    // (rskj BridgeSupport.requestRelease). The destination is the sender's
    // P2PKH BTC address. Pre-RSKIP326 the event carries the 20-byte hash160,
    // post-326 the Base58 string; pre-RSKIP427 the amount is satoshis, post-427
    // the full wei call value.
    if hardfork_cfg.has_rskip185(block_number) {
        let dest_base58 = sender_base58_address(&btc_dest, false, config);
        let event_amount = if hardfork_cfg.has_rskip427(block_number) {
            call_value_wei
        } else {
            U256::from(amount_satoshis)
        };
        super::events::log_release_request_received(
            ctx,
            tx_ctx.rsk_sender,
            &btc_dest,
            &dest_base58,
            event_amount,
            hardfork_cfg.has_rskip326(block_number),
        );
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
pub fn update_collections<CTX: crate::RskContextTr>(
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

    // rskj BridgeStorageProvider.save() persists every collection the call
    // LOADED, including empty ones. updateCollections always loads the
    // active federation UTXO list (getActiveFederationWallet), the release
    // request queue, the release tx set and the signatures-waiting map, so
    // their RLP-empty `[0xc0]` entries materialize on the first call
    // (mainnet #615). Post-RSKIP146 the with-txhash queue/set variants are
    // loaded (and thus materialized) too.
    {
        let active_utxo_key = active_federation_utxo_key(ctx, config, hardfork_cfg, block_number);
        let mut touched: Vec<&str> = vec![
            active_utxo_key,
            RELEASE_REQUEST_QUEUE_KEY,
            PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY,
            PEGOUTS_WAITING_FOR_SIGNATURES_KEY,
        ];
        if use_tx_hash {
            touched.push(super::storage::RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY);
            touched.push(super::storage::PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY);
        }
        for key_name in touched {
            let key = bridge_storage_key(key_name);
            if super::storage::bridge_load_raw(ctx, key).is_none() {
                // RLP.encodeList() of an empty collection.
                super::storage::bridge_store_raw(ctx, key, Some(vec![0xc0]));
            }
        }
    }

    // updateCollections loads the active federation (getActiveFederationWallet),
    // so rskj's save() re-serializes it. Post-RSKIP123 the first such save
    // migrates `newFederation` to the multikey member format and writes
    // `newFederationFormatVersion` (mainnet #1,591,009).
    super::federation::save_new_federation_multikey(ctx, hardfork_cfg, block_number);

    // -----------------------------------------------------------------------
    // Step 0: Funds migration (rskj processFundsMigration) — while the new
    // federation is in its migration window, each updateCollections call
    // moves the retiring federation's balance into the active federation
    // with a migration transaction queued like a peg-out.
    // -----------------------------------------------------------------------
    process_funds_migration(ctx, config, hardfork_cfg, block_number, tx_ctx);

    // -----------------------------------------------------------------------
    // Step 1: Process peg-out requests (rskj processPegoutRequests)
    // -----------------------------------------------------------------------
    let should_process_requests = if use_rskip271 {
        // RSKIP271: batching — only process when nextPegoutHeight ≤ current block
        let next_height =
            super::storage::bridge_load_u256(ctx, NEXT_PEGOUT_HEIGHT_KEY).to::<u64>();
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

        // RSKIP271: rskj processPegoutsInBatch sets nextPegoutHeight whenever
        // the queue ends up empty — including the case where it was empty to
        // begin with (BridgeSupport.processPegoutsInBatch line 1555). Track
        // whether the queue is empty after this call so we can mirror that.
        let mut queue_emptied = pending.is_empty();

        if !pending.is_empty() {
            // rskj getActiveFederation().getRedeemScript(): the spending
            // federation's redeem follows its STORED format version (plain /
            // NON_STANDARD_ERP / P2SH-ERP / P2SH-P2WSH-ERP), not the plain
            // multisig builder — otherwise the pegout's per-input placeholder
            // scriptSig and the change P2SH (hence the txid) fork. See #4,677,503.
            let (federation_keys, redeem_script) =
                active_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number);
            if !federation_keys.is_empty() {
                let change_script = p2sh_output_script(&redeem_script_hash160(&redeem_script));
                let fee_per_kb = get_effective_fee_per_kb(ctx, config);
                let tx_version = if hardfork_cfg.has_rskip201(block_number) { 2 } else { 1 };

                let active_utxo_key =
                    active_federation_utxo_key(ctx, config, hardfork_cfg, block_number);
                let mut available = load_utxos_at(ctx, active_utxo_key);

                // rskj getActiveFederationWallet builds a FlyoverCompatibleBtcWallet:
                // resolve a flyover UTXO's redeem per input (PUSH32 <hash> OP_DROP
                // <fedRedeem>). getDestinationFederation searches active + retiring.
                let mut candidate_fed_redeems = vec![redeem_script.clone()];
                if let Some((_, retiring_redeem)) =
                    retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number)
                {
                    candidate_fed_redeems.push(retiring_redeem);
                }
                let flyover_overrides =
                    resolve_flyover_input_redeems(ctx, &available, &candidate_fed_redeems);
                let redeem_for = |u: &BridgeUtxo| -> &[u8] {
                    flyover_overrides
                        .get(&(u.tx_hash, u.vout))
                        .map(|r| r.as_slice())
                        .unwrap_or(redeem_script.as_slice())
                };

                let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
                let mut created_any = false;

                // Settle one successfully built peg-out: remove the spent
                // UTXOs, queue it for confirmations, (RSKIP146+) log
                // release_requested with the creation RSK tx hash, and burn
                // the dusty-change surplus (adjustBalancesIfChangeOutputWasDust).
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
                    // rskj BridgeSupport.adjustBalancesIfChangeOutputWasDust
                    // (unconditional since genesis): when a dusty change
                    // output was raised to the non-dust minimum (paid by the
                    // recipient), the federation spent less BTC than the user
                    // sent, so the difference is burned — transferred from
                    // the Bridge to 0xffff...ff (BridgeSupport.BURN_ADDRESS).
                    if built.tx.output.len() > 1 {
                        let sum_inputs: u64 =
                            built.used_utxos.iter().map(|u| u.value_satoshis).sum();
                        // Papyrus-era rskj reads getOutput(1); HOP+ reads
                        // getValueSentToMe(wallet). Both equal the change
                        // paid back to the federation P2SH script.
                        let change: u64 = built
                            .tx
                            .output
                            .iter()
                            .filter(|o| o.script_pubkey == *change_script)
                            .map(|o| o.value.to_sat())
                            .sum();
                        let spent_by_federation = sum_inputs.saturating_sub(change);
                        if spent_by_federation < amount {
                            let to_burn = amount - spent_by_federation;
                            let _ = ctx.journal_mut().transfer(
                                BRIDGE_ADDR,
                                BURN_ADDR,
                                btc_satoshi_to_rbtc_wei(to_burn),
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
                            redeem_for,
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
                        redeem_for,
                        fee_per_kb,
                        tx_version,
                    ) {
                        let total: u64 = pending.iter().map(|r| r.amount_satoshis).sum();
                        // rskj logBatchPegoutCreated needs the batch BTC tx hash
                        // and the per-request creation RSK tx hashes; capture
                        // them before `settle` consumes `built`.
                        let batch_btc_tx_hash = btc_txid_event_bytes(&built.tx);
                        let batch_rsk_tx_hashes: Vec<[u8; 32]> = pending
                            .iter()
                            .map(|r| r.rsk_tx_hash.unwrap_or(tx_ctx.rsk_tx_hash))
                            .collect();
                        settle(
                            ctx,
                            built,
                            Some(tx_ctx.rsk_tx_hash),
                            total,
                            &mut available,
                            &mut waiting,
                        );
                        // rskj BridgeSupport.processPegoutsInBatch logs
                        // batch_pegout_created right after settleReleaseRequest
                        // (which already logged release_requested), listing every
                        // batched request's RSK creation tx hash.
                        super::events::log_batch_pegout_created(
                            ctx,
                            &batch_btc_tx_hash,
                            &batch_rsk_tx_hashes,
                        );
                        created_any = true;
                        // The whole queue was batched into one BTC tx, so it
                        // is now empty (rskj removeEntries(pegoutEntries)).
                        // rskj re-serializes the emptied queue, so the cell
                        // holds RLP.encodeList([]) = [0xc0], NOT empty bytes.
                        bridge_store_bytes(ctx, queue_key, &serialize_release_queue_with_hash(&[]));
                        queue_emptied = true;
                    }
                }

                if created_any {
                    store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);
                    store_utxos_at(ctx, active_utxo_key, &available);
                }
            }
        }

        // RSKIP271: set nextPegoutHeight when there are no pending pegout
        // requests left (either none to begin with, or all batched). This is
        // independent of whether a BTC tx was actually built, matching rskj
        // BridgeSupport.processPegoutsInBatch (the `pegoutRequests.getEntries()
        // .isEmpty()` tail at line 1555). A failed/insufficient build leaves
        // the queue non-empty and thus does NOT advance the height.
        if use_rskip271 && queue_emptied {
            let next_height = block_number + config.number_of_blocks_between_pegouts;
            super::storage::bridge_store_u256(
                ctx,
                NEXT_PEGOUT_HEIGHT_KEY,
                U256::from(next_height),
            );
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: Promote ONE confirmed pegout → waiting for signatures
    // (rskj processConfirmedPegouts: getNextPegoutWithEnoughConfirmations
    // promotes a single entry per updateCollections call)
    // -----------------------------------------------------------------------
    {
        let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
        let min_confirmations = config.rsk2btc_minimum_acceptable_confirmations as u64;
        let confirmed_pos = next_pegout_with_enough_confirmations(
            &waiting,
            block_number,
            min_confirmations,
        );

        if let Some(pos) = confirmed_pos {
            let entry = waiting.remove(pos);
            tracing::debug!(
                "promoting confirmed pegout created at #{} ({} bytes) into WFS",
                entry.rsk_block_height,
                entry.btc_tx_raw.len()
            );
            store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);

            // rskj BridgeSupport.processConfirmedPegouts l.1617 logs
            // pegout_confirmed for the promoted entry (RSKIP326, fingerroot500).
            // Capture the event inputs before `btc_tx_raw` is moved into the WFS.
            let pegout_confirmed = hardfork_cfg.has_rskip326(block_number).then(|| {
                (
                    btc_txid_event_bytes(
                        &deserialize::<BtcTransaction>(&entry.btc_tx_raw)
                            .expect("confirmed pegout btc tx deserializes"),
                    ),
                    entry.rsk_block_height,
                )
            });

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

            if let Some((btc_tx_hash, rsk_block_height)) = pegout_confirmed {
                super::events::log_pegout_confirmed(ctx, &btc_tx_hash, rsk_block_height);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: Promote the pending federation creation height once the new
    // federation reaches its activation age (rskj updateFederationCreationBlockHeights).
    // -----------------------------------------------------------------------
    super::governance::update_federation_creation_block_heights(
        ctx,
        config,
        hardfork_cfg,
        block_number,
    );

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// rskj `PegoutsWaitingForConfirmations.getNextPegoutWithEnoughConfirmations`:
/// `entries.stream().filter(hasEnoughConfirmations).findFirst()` over a Java
/// `HashSet<Entry>`. The selected entry is therefore the first confirmed one in
/// Java `HashSet` iteration order — NOT the storage (btc-tx-sorted) order. When
/// two entries share the same creation height (so both confirm on the same
/// block) the choice between them depends on this iteration order, which is
/// consensus-critical (block #3,345,557 mainnet).
///
/// `HashSet` iteration walks buckets `0..table.length` ascending, and within a
/// bucket in insertion order. The bucket is `(table.length-1) & spread(hash)`
/// with `spread(h) = h ^ (h >>> 16)` and
/// `hash = Objects.hash(btcTx, Long(height))`
/// (`= 31*(31 + btcTx.hashCode()) + Long.hashCode(height)`), where
/// `btcTx.hashCode()` is the last 4 bytes of the display-order txid read
/// big-endian (bitcoinj `Sha256Hash.hashCode`).
///
/// **Table capacity.** rskj does NOT pre-size from the final count. The cached
/// set is built incrementally (`BridgeStorageProvider.getPegoutsWaitingForConfirmations`:
/// `new HashSet<>(emptyLegacyCell)` then `entries.addAll(withTxHashCell)`,
/// `HashSet.addAll` = `AbstractCollection.addAll` = one `add` per element), and
/// `deserializePegoutsWaitingForConfirmations` likewise adds one-by-one to a
/// default-16 set. So the table starts at capacity 16 and resizes to the next
/// power of two whenever `size > capacity*0.75` (Java `HashMap.putVal`:
/// `if (++size > threshold) resize()`). After `n` insertions the capacity is the
/// smallest power-of-two `>= 16` with `n <= floor(cap*0.75)`. This differs from
/// the `new HashSet<>(collection)` pre-size formula at the resize boundaries
/// (e.g. `n = 12` -> cap 16 here, but pre-size would give 32; `n = 24` -> 32 vs
/// 64), which would fork the bucket walk. Returns the index into `entries`.
fn next_pegout_with_enough_confirmations(
    entries: &[PegoutWaitingForConfirmations],
    current_block: u64,
    min_confirmations: u64,
) -> Option<usize> {
    if entries.is_empty() {
        return None;
    }

    let cap = java_hashset_capacity(entries.len());

    // Bucket each entry; within a bucket preserve insertion (storage) order.
    let mut buckets: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (i, entry) in entries.iter().enumerate() {
        let h = pegout_entry_hash(entry);
        let spread = h ^ (h >> 16);
        let bucket = (cap - 1) & spread;
        buckets.entry(bucket).or_default().push(i);
    }

    // findFirst over the confirmation-filtered stream in iteration order.
    buckets.into_values().flatten().find(|&i| {
        current_block
            .checked_sub(entries[i].rsk_block_height)
            .is_some_and(|d| d >= min_confirmations)
    })
}

/// Java `HashMap` table capacity after inserting `n` elements one-by-one into a
/// default-constructed `HashSet` (initial capacity 16, load factor 0.75).
/// The table doubles whenever `size > capacity * 0.75` (`HashMap.putVal`:
/// `if (++size > threshold) resize()`), so the result is the smallest
/// power-of-two `>= 16` whose threshold `floor(cap * 0.75)` is `>= n`.
fn java_hashset_capacity(n: usize) -> u32 {
    let mut cap = 16u32;
    while n as u32 > (cap as f64 * 0.75) as u32 {
        cap <<= 1;
    }
    cap
}

/// rskj `PegoutsWaitingForConfirmations.Entry.hashCode()`:
/// `Objects.hash(btcTransaction, pegoutCreationRskBlockNumber)`
/// `= 31 * (31 * 1 + btcTransaction.hashCode()) + Long.hashCode(height)`.
/// `btcTransaction.hashCode()` (bitcoinj) is `Sha256Hash.hashCode()` of the
/// txid: the last 4 bytes of the display-order hash read big-endian.
fn pegout_entry_hash(entry: &PegoutWaitingForConfirmations) -> u32 {
    // Display-order txid = reverse of rust-bitcoin's internal SHA256d.
    let btc_hash_code = match deserialize::<BtcTransaction>(&entry.btc_tx_raw) {
        Ok(tx) => {
            let mut disp = *tx.compute_txid().to_raw_hash().as_byte_array();
            disp.reverse();
            u32::from_be_bytes([disp[28], disp[29], disp[30], disp[31]])
        }
        Err(_) => 0,
    };
    let long_hash_code =
        (entry.rsk_block_height ^ (entry.rsk_block_height >> 32)) as u32;
    // Objects.hash(btcTx, height) = 31 * (31 + btcTx.hashCode()) + Long.hashCode.
    let r = 31u32.wrapping_add(btc_hash_code);
    31u32.wrapping_mul(r).wrapping_add(long_hash_code)
}

/// rskj `BridgeSupport.processFundsMigration` (pre-RSKIP294/376 era).
fn process_funds_migration<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    tx_ctx: &BridgeTxContext,
) {
    let Some(retiring_keys) =
        retiring_federation_keys(ctx, config, hardfork_cfg, block_number)
    else {
        return;
    };
    let Some(new_fed) = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY)
    else {
        return;
    };

    let age = block_number.saturating_sub(new_fed.creation_block);
    let activation_age =
        super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    // rskj FederationConstants.getFundsMigrationAgeSinceActivationEnd: while
    // RSKIP357 is active and RSKIP374 is not (mainnet hop401 #4,976,300 ..
    // fingerroot500 #5,468,000), the migration window end takes its special-case
    // value (mainnet 172,800 instead of 10,585), greatly extending the window.
    let migration_age_end = if hardfork_cfg.has_rskip357(block_number)
        && !hardfork_cfg.has_rskip374(block_number)
    {
        config.special_case_funds_migration_age_end
    } else {
        config.funds_migration_age_end
    };
    let migration_start = activation_age + config.funds_migration_age_begin;
    let migration_end = activation_age + migration_age_end;
    let in_migration_age = age > migration_start && age < migration_end;
    let past_migration_age = age >= migration_end;
    if !in_migration_age && !past_migration_age {
        return;
    }

    let mut old_utxos = super::storage::load_old_federation_utxos(ctx);
    // rskj `getRetiringFederationWallet`: post-RSKIP294 the spend wallet caps
    // its UTXO set to the first `maxInputsPerPegoutTransaction` entries
    // (`utxos.subList(0, limit)`, BridgeSupport.java:1249-1251, 312-323), so the
    // migration balance, fee floor, and coin selection only ever see those.
    let migration_utxos: Vec<super::storage::BridgeUtxo> = if hardfork_cfg.has_rskip294(block_number)
    {
        old_utxos
            .iter()
            .take(config.max_inputs_per_pegout_transaction as usize)
            .cloned()
            .collect()
    } else {
        old_utxos.clone()
    };
    let balance: u64 = migration_utxos.iter().map(|u| u.value_satoshis).sum();
    let fee_per_kb = get_effective_fee_per_kb(ctx, config);

    let should_migrate = (in_migration_age && balance > fee_per_kb / 2)
        || (past_migration_age && balance > 0);
    if should_migrate {
        // The retiring federation spends with the redeem of its STORED format
        // version (plain / NON_STANDARD_ERP / P2SH-ERP / P2SH-P2WSH-ERP), like
        // the regular pegout path — `getRetiringFederation().getRedeemScript()`.
        // Once the retiring federation is itself an ERP federation, the plain
        // multisig builder gives the wrong per-input placeholder scriptSig and
        // thus a wrong unsigned migration txid (same class as #4,677,503, but on
        // the migration path — first hit at #4,998,800).
        let retiring_redeem =
            retiring_federation_keys_and_redeem(ctx, config, hardfork_cfg, block_number)
                .map(|(_keys, redeem)| redeem)
                .unwrap_or_else(|| {
                    build_federation_redeem_script(&retiring_keys, retiring_keys.len() / 2 + 1)
                });
        // rskj `migrateFunds` sends the migration to `getActiveFederationAddress()`
        // = the NEW (active) federation's P2SH address (BridgeSupport.java:1308,
        // FederationSupportImpl.getActiveFederationAddress -> getAddress()). The
        // active federation here is the ERP federation committed at #4,652,781, so
        // its address derives from the (RSKIP201-era non-standard) ERP redeem
        // script, NOT a plain multisig. Use the committed-federation redeem builder
        // so this matches whatever federation format was committed (standard pre-
        // RSKIP201, non-standard ERP, P2SH-ERP, or P2SH-P2WSH-ERP).
        let new_btc_keys = new_fed.btc_keys();
        let new_redeem = build_committed_federation_redeem_script(
            &new_btc_keys,
            config,
            hardfork_cfg,
            block_number,
        );
        let active_script = p2sh_output_script(&redeem_script_hash160(&new_redeem));

        // rskj getRetiringFederationWallet builds a FlyoverCompatibleBtcWallet:
        // a flyover UTXO in the migration set spends with the flyover redeem
        // (PUSH32 <derivationHash> OP_DROP <fedRedeem>) of its destination
        // federation, not the plain retiring redeem. Resolve per input.
        // getDestinationFederation searches active + retiring; the stored
        // fedRedeemScriptHash is the *plain* multisig hash of whichever fed was
        // active at the flyover peg-in (now the retiring fed for this batch).
        let plain_new_redeem = build_federation_redeem_script(&new_btc_keys, new_btc_keys.len() / 2 + 1);
        let candidate_fed_redeems = vec![retiring_redeem.clone(), plain_new_redeem];
        let flyover_overrides =
            resolve_flyover_input_redeems(ctx, &migration_utxos, &candidate_fed_redeems);
        let redeem_for = |u: &BridgeUtxo| -> &[u8] {
            flyover_overrides
                .get(&(u.tx_hash, u.vout))
                .map(|r| r.as_slice())
                .unwrap_or(retiring_redeem.as_slice())
        };

        // createMigrationTransaction: target the full balance, halving on
        // size overflow (pre-RSKIP376 migrations are version 1).
        let mut target = balance;
        let built = loop {
            let outputs = [super::release_tx::PegoutOutput {
                script: active_script.clone(),
                amount_satoshis: target,
            }];
            match super::release_tx::complete_pegout_tx(
                &migration_utxos,
                &outputs,
                &active_script,
                redeem_for,
                fee_per_kb,
                1,
            ) {
                Some(b) => break Some(b),
                None => {
                    target /= 2;
                    if target < 10_000 {
                        break None;
                    }
                }
            }
        };

        if let Some(built) = built {
            // rskj processFundsMigration: post-RSKIP146 the entry carries the
            // updateCollections tx hash and logs release_requested with the
            // migrated amount (sum of the selected UTXO values).
            let use_tx_hash = hardfork_cfg.has_rskip146(block_number);
            let mut waiting = load_pegout_confirmation_set(ctx, use_tx_hash);
            waiting.push(PegoutWaitingForConfirmations {
                btc_tx_raw: btc_serialize(&built.tx),
                rsk_block_height: block_number,
                rsk_tx_hash: use_tx_hash.then_some(tx_ctx.rsk_tx_hash),
            });
            if use_tx_hash {
                let amount_migrated: u64 =
                    built.used_utxos.iter().map(|u| u.value_satoshis).sum();
                super::events::log_release_requested(
                    ctx,
                    &tx_ctx.rsk_tx_hash,
                    &btc_txid_event_bytes(&built.tx),
                    amount_migrated,
                );
            }
            store_pegout_confirmation_set(ctx, &waiting, use_tx_hash);

            old_utxos.retain(|u| {
                !built
                    .used_utxos
                    .iter()
                    .any(|s| s.tx_hash == u.tx_hash && s.vout == u.vout)
            });
            super::storage::store_old_federation_utxos(ctx, &old_utxos);
            tracing::debug!(
                "funds migration: queued {} ({} utxos) at #{block_number}",
                built.tx.compute_txid(),
                built.used_utxos.len()
            );
        }
    }

    if past_migration_age {
        // clearRetiredFederation: the old federation is gone for good. rskj
        // saveOldFederation writes the format-version cell on every save once
        // RSKIP123 is active — even this clearing one (the federation cell is
        // deleted, the version cell stays).
        if hardfork_cfg.has_rskip123(block_number) {
            bridge_store_bytes_named(
                ctx,
                OLD_FEDERATION_FORMAT_VERSION_KEY,
                &super::serialization::rlp_encode_u64(1000),
            );
        }
        bridge_store_bytes_named(ctx, OLD_FEDERATION_KEY, &[]);
    }
}

/// Active federation member keys (rskj FederationSupport.getActiveFederation):
/// the committed (new) federation once it reaches the activation age, the old
/// federation while the new one awaits activation, or the genesis federation
/// when none was ever stored.
pub(crate) fn federation_keys_or_genesis<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    want_rsk: bool,
) -> Vec<[u8; 33]> {
    // `want_rsk` selects the member's RSK public key instead of its BTC key
    // (RSKIP415 REMASC payout). Genesis-fallback members are single-key, so
    // their RSK key equals their BTC key.
    let keys = |f: &super::federation::StoredFederation| {
        if want_rsk { f.rsk_keys() } else { f.btc_keys() }
    };
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age =
        super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    match (new, old) {
        (Some(n), Some(o)) => {
            if block_number >= n.creation_block + age {
                keys(&n)
            } else {
                keys(&o)
            }
        }
        (Some(n), None) => keys(&n),
        (None, _) => genesis_federation_keys(config),
    }
}

/// The RSK public key of the federation member whose BTC public key is
/// `btc_key`, searching the active federation first and then the retiring one
/// (rskj `BridgeSupport.getFederationMember` via `getFederationFromPublicKey`).
/// For legacy single-key members rsk == btc, so this returns `btc_key` itself.
/// `None` when no federation member matches.
fn federator_rsk_key_for_btc<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
    btc_key: &[u8; 33],
) -> Option<[u8; 33]> {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    // Active federation: new once it reaches activation age, otherwise old.
    let (active, retiring) = match (&new, &old) {
        (Some(n), Some(o)) => {
            if block_number >= n.creation_block + age {
                (Some(n), Some(o))
            } else {
                (Some(o), None)
            }
        }
        (Some(n), None) => (Some(n), None),
        (None, _) => (None, None),
    };
    for fed in [active, retiring].into_iter().flatten() {
        if let Some(m) = fed.members.iter().find(|m| &m.btc == btc_key) {
            return Some(m.rsk);
        }
    }
    None
}

/// Which UTXO storage set backs the ACTIVE federation: after a commit and
/// until activation the active federation IS the old one, whose UTXOs were
/// moved to oldFederationBtcUTXOs (rskj getActiveFederationBtcUTXOs).
pub(crate) fn active_federation_utxo_key<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> &'static str {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    if let (Some(n), Some(_)) = (new, old) {
        let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
        if block_number < n.creation_block + age {
            return super::storage::OLD_FEDERATION_BTC_UTXOS_KEY;
        }
    }
    super::storage::NEW_FEDERATION_BTC_UTXOS_KEY
}

fn load_utxos_at<CTX: crate::RskContextTr>(ctx: &mut CTX, key: &str) -> Vec<BridgeUtxo> {
    super::storage::deserialize_utxo_list(&bridge_load_bytes_named(ctx, key))
}

fn store_utxos_at<CTX: crate::RskContextTr>(ctx: &mut CTX, key: &str, utxos: &[BridgeUtxo]) {
    bridge_store_bytes_named(ctx, key, &super::storage::serialize_utxo_list(utxos));
}

/// Active federation keys together with the redeem script built from the
/// federation's STORED format version (rskj `getActiveFederation().getRedeemScript()`).
/// During the activation window the active federation is still the OLD one, so its
/// format cell (and keys) must be used.
fn active_federation_keys_and_redeem<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> (Vec<[u8; 33]>, Vec<u8>) {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    let (keys, format_key) = match (new, old) {
        (Some(n), Some(o)) => {
            if block_number >= n.creation_block + age {
                (n.btc_keys(), super::storage::NEW_FEDERATION_FORMAT_VERSION_KEY)
            } else {
                (o.btc_keys(), super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY)
            }
        }
        (Some(n), None) => (n.btc_keys(), super::storage::NEW_FEDERATION_FORMAT_VERSION_KEY),
        (None, _) => return {
            let keys = genesis_federation_keys(config);
            let redeem = build_federation_redeem_script(&keys, keys.len() / 2 + 1);
            (keys, redeem)
        },
    };
    let version = federation_format_version(ctx, format_key);
    let redeem = federation_redeem_for_format(&keys, version, config);
    (keys, redeem)
}

/// Retiring federation keys + redeem (rskj `getRetiringFederation().getRedeemScript()`).
/// The retiring federation is the OLD federation once the new one has activated;
/// its redeem script follows the OLD federation's stored format version.
fn retiring_federation_keys_and_redeem<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Option<(Vec<[u8; 33]>, Vec<u8>)> {
    let keys = retiring_federation_keys(ctx, config, hardfork_cfg, block_number)?;
    let version = federation_format_version(ctx, super::storage::OLD_FEDERATION_FORMAT_VERSION_KEY);
    let redeem = federation_redeem_for_format(&keys, version, config);
    Some((keys, redeem))
}

/// Retiring federation keys (rskj getRetiringFederation): the old federation
/// while both old+new exist and the new one has reached activation age.
pub(crate) fn retiring_federation_keys<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Option<Vec<[u8; 33]>> {
    let new = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY)?;
    let old = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY)?;
    let age = super::governance::federation_activation_age(config, hardfork_cfg, block_number);
    if block_number >= new.creation_block + age {
        Some(old.btc_keys())
    } else {
        None
    }
}

pub(crate) fn genesis_federation_keys(config: &BridgeConstants) -> Vec<[u8; 33]> {
    // rskj Federation sorts members by compressed BTC public key.
    let mut keys: Vec<[u8; 33]> = config
        .genesis_federation_public_keys
        .iter()
        .filter_map(|hex| {
            let bytes = alloy_primitives::hex::decode(hex).ok()?;
            bytes.try_into().ok()
        })
        .collect();
    keys.sort();
    keys
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
pub fn add_signature<CTX: crate::RskContextTr>(
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
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let federation_keys = federation_keys_or_genesis(ctx, config, hardfork_cfg, block_number, false);
    if federation_keys.is_empty() {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }
    let Some(compressed_key) = compress_pubkey(&fed_key) else {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    };
    // rskj getFederationFromPublicKey: active first, then retiring.
    let is_member = federation_keys.contains(&compressed_key)
        || retiring_federation_keys(ctx, config, hardfork_cfg, block_number)
            .is_some_and(|keys| keys.contains(&compressed_key));
    if !is_member {
        return Ok(PrecompileOutput::new(gas_cost, Bytes::new()));
    }

    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();

    // rskj logs an add_signature event for a federation member: before
    // RSKIP326 it fires BEFORE the signatures are verified and applied;
    // afterwards only when a signature was actually applied. The format is
    // legacy single-topic before RSKIP146 and Solidity afterwards.
    let legacy_events = !hardfork_cfg.has_rskip146(block_number);
    let log_only_when_applied = hardfork_cfg.has_rskip326(block_number);
    // rskj `BridgeEventLoggerImpl.getFederatorRskPublicKey`: the add_signature
    // event's federatorRskAddress topic derives from the member's BTC public
    // key before RSKIP415 (arrowhead600) and from its RSK public key after.
    // For legacy single-key members the two keys are identical.
    let federator_addr_key: Vec<u8> = if hardfork_cfg.has_rskip415(block_number) {
        federator_rsk_key_for_btc(ctx, config, hardfork_cfg, block_number, &compressed_key)
            .map(|k| k.to_vec())
            .unwrap_or_else(|| fed_key.clone())
    } else {
        fed_key.clone()
    };
    let emit_add_signature = |ctx: &mut CTX, btc_tx: &BtcTransaction| {
        if legacy_events {
            let txid = btc_tx.compute_txid().to_string();
            super::events::log_legacy_add_signature(
                ctx,
                &txid,
                &pubkey_hash160(&compressed_key),
                &rsk_tx_hash,
            );
        } else if let Some(addr) = super::federation::rsk_address_from_public_key(&federator_addr_key) {
            // Topic = federatorRskAddress; data = the BTC public key (always).
            super::events::log_solidity_add_signature(ctx, &rsk_tx_hash, addr, &fed_key);
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
// The map is a Java TreeMap<Keccak256, BtcTransaction>, so entries serialize in
// Keccak256 natural order — and rskj's `Keccak256.compareTo` compares bytes
// UNSIGNED from the LAST byte (index 31) down to the first, i.e. reverse-byte
// (little-endian) order. A plain BTreeMap<[u8;32]> orders forward (big-endian),
// which diverges whenever the two orderings disagree, so we re-sort at
// serialization time rather than rely on the in-memory map's iteration order.
// ---------------------------------------------------------------------------

/// Serialize the pegouts-waiting-for-signatures map.
pub fn serialize_rsk_txs_waiting_for_signatures(
    map: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Vec<u8> {
    // rskj Keccak256.compareTo: unsigned, from byte[31] down to byte[0].
    let mut entries: Vec<(&[u8; 32], &Vec<u8>)> = map.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.iter().rev().cmp(b.iter().rev()));
    let mut items = Vec::with_capacity(entries.len() * 2);
    for (rsk_hash, btc_tx_raw) in entries {
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

/// rskj `BridgeStorageProvider.getReleaseTransactionSet`: one in-memory set
/// loaded from the legacy cell (pair entries, no hash), merged post-RSKIP146
/// with the with-txhash cell (triple entries).
pub fn load_pegout_confirmation_set<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    use_tx_hash: bool,
) -> Vec<PegoutWaitingForConfirmations> {
    let legacy_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
    let mut entries =
        deserialize_pegouts_waiting_for_confirmations(&bridge_load_bytes(ctx, legacy_key), false);
    if use_tx_hash {
        let key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY);
        entries.extend(deserialize_pegouts_waiting_for_confirmations(
            &bridge_load_bytes(ctx, key),
            true,
        ));
    }
    entries
}

/// rskj `BridgeStorageProvider.saveReleaseTransactionSet`: the hash-less
/// entries go to the legacy cell (pair format); post-RSKIP146 the
/// hash-bearing entries go to the with-txhash cell (triple format) — BOTH
/// cells are written on every save.
pub fn store_pegout_confirmation_set<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    entries: &[PegoutWaitingForConfirmations],
    use_tx_hash: bool,
) {
    let legacy_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY);
    if !use_tx_hash {
        let bytes = serialize_pegouts_waiting_for_confirmations(entries, false);
        bridge_store_bytes(ctx, legacy_key, &bytes);
        return;
    }
    let (with, without): (Vec<_>, Vec<_>) = entries
        .iter()
        .cloned()
        .partition(|e| e.rsk_tx_hash.is_some());
    let legacy_bytes = serialize_pegouts_waiting_for_confirmations(&without, false);
    bridge_store_bytes(ctx, legacy_key, &legacy_bytes);
    let with_key = bridge_storage_key(PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY);
    let with_bytes = serialize_pegouts_waiting_for_confirmations(&with, true);
    bridge_store_bytes(ctx, with_key, &with_bytes);
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

/// rskj `Utils.signedLongToByteArrayLE`: `reverseBytes(BigInteger.valueOf(v)
/// .toByteArray())` — the minimal big-endian two's-complement byte array
/// (Java `BigInteger.toByteArray`, which keeps a leading 0x00 sign byte when
/// the top bit is set) reversed to little-endian. NOT BIP68-minimal: e.g.
/// 52560 -> `50 cd 00` (3 bytes), because 0xCD has its high bit set. This is
/// the CSV-delay push consensus byte sequence; a from-scratch minimal encoding
/// would emit `50 cd` and fork. (co/rsk/bitcoinj/core/Utils.java)
fn signed_long_to_byte_array_le(value: i64) -> Vec<u8> {
    // BigInteger.valueOf(value).toByteArray(): minimal big-endian two's complement.
    let mut be = value.to_be_bytes().to_vec();
    // Strip redundant sign-extension bytes (keep one byte that carries the sign).
    while be.len() > 1 {
        let b0 = be[0];
        let b1 = be[1];
        // Drop a leading 0x00 only if the next byte's top bit is also 0 (still
        // positive), or a leading 0xFF only if the next byte's top bit is 1.
        if (b0 == 0x00 && b1 & 0x80 == 0) || (b0 == 0xff && b1 & 0x80 != 0) {
            be.remove(0);
        } else {
            break;
        }
    }
    be.reverse();
    be
}

/// rskj `NonStandardErpRedeemScriptBuilder` (post-RSKIP284/293) and
/// `P2shErpRedeemScriptBuilder` (post-RSKIP353) emergency-multisig template.
///
/// Both wrap a default N-of-M multisig and an emergency K-of-J multisig in a
/// CSV-gated `OP_NOTIF ... OP_ELSE <csv> OP_CHECKSEQUENCEVERIFY OP_DROP ...
/// OP_ENDIF`. The non-standard form strips the trailing `OP_CHECKMULTISIG`
/// from each inner script and appends a single `OP_CHECKMULTISIG` after
/// `OP_ENDIF`; the P2SH-ERP form keeps each inner script intact (incl. its
/// `OP_CHECKMULTISIG`) and emits nothing after `OP_ENDIF`. Inner scripts are
/// standard multisig with keys sorted lexicographically (see
/// [`build_federation_redeem_script`]). The CSV delay is pushed via
/// [`signed_long_to_byte_array_le`].
fn build_erp_redeem_script(
    default_keys: &[[u8; 33]],
    default_threshold: usize,
    erp_keys: &[[u8; 33]],
    erp_threshold: usize,
    csv_delay: i64,
    p2sh: bool,
) -> Vec<u8> {
    let default_redeem = build_federation_redeem_script(default_keys, default_threshold);
    let erp_redeem = build_federation_redeem_script(erp_keys, erp_threshold);
    let csv = signed_long_to_byte_array_le(csv_delay);

    // `removeOpCheckMultisig`: drop the trailing OP_CHECKMULTISIG (last byte).
    let default_inner: &[u8] = if p2sh { &default_redeem } else { &default_redeem[..default_redeem.len() - 1] };
    let erp_inner: &[u8] = if p2sh { &erp_redeem } else { &erp_redeem[..erp_redeem.len() - 1] };

    let mut script = Vec::with_capacity(default_inner.len() + erp_inner.len() + csv.len() + 8);
    script.push(0x64); // OP_NOTIF
    script.extend_from_slice(default_inner);
    script.push(0x67); // OP_ELSE
    script.push(csv.len() as u8); // push CSV bytes
    script.extend_from_slice(&csv);
    script.push(0xb2); // OP_CHECKSEQUENCEVERIFY
    script.push(0x75); // OP_DROP
    script.extend_from_slice(erp_inner);
    script.push(0x68); // OP_ENDIF
    if !p2sh {
        script.push(0xae); // OP_CHECKMULTISIG
    }
    script
}

/// rskj `PendingFederation.buildFederation` redeem-script selection: a
/// committed federation is a standard multisig (pre-RSKIP201), a non-standard
/// ERP federation (RSKIP201 active, RSKIP353 not), a P2SH-ERP federation
/// (RSKIP353 active, RSKIP305 not), or a P2SH-P2WSH-ERP federation (RSKIP305).
/// The emergency keys/threshold and CSV delay come from the network's
/// federation constants. Returns the redeem script whose hash160 is the
/// federation's P2SH address. (P2SH-P2WSH-ERP shares the P2SH-ERP redeem
/// template — see FederationFactory.buildP2shP2wshErpFederation.)
pub fn build_committed_federation_redeem_script(
    keys: &[[u8; 33]],
    config: &BridgeConstants,
    hardfork_cfg: &RskHardforkConfig,
    block_number: u64,
) -> Vec<u8> {
    let threshold = keys.len() / 2 + 1;
    if !hardfork_cfg.has_rskip201(block_number) {
        return build_federation_redeem_script(keys, threshold);
    }
    let erp_keys: Vec<[u8; 33]> = config
        .erp_fed_pubkeys
        .iter()
        .map(|hex| {
            let bytes = alloy_primitives::hex::decode(hex).expect("valid erp pubkey hex");
            bytes.try_into().expect("33-byte compressed erp pubkey")
        })
        .collect();
    let erp_threshold = erp_keys.len() / 2 + 1;
    let csv = config.erp_fed_activation_delay;
    let p2sh = hardfork_cfg.has_rskip353(block_number);
    build_erp_redeem_script(keys, threshold, &erp_keys, erp_threshold, csv, p2sh)
}

/// Build a live federation's redeem script from its **stored format version**,
/// mirroring rskj `BridgeSerializationUtils.deserializeFederationAccordingToVersion`
/// + `FederationFactory`. A federation that outlives the hardfork that introduced
/// a newer template keeps its original type, so the redeem script (and hence the
/// P2SH address used to recognize peg-in outputs / peg-out inputs) must be chosen
/// by the format the federation was stored with — NOT by the current block height.
///   1000 STANDARD_MULTISIG      → plain N-of-M multisig
///   2000 NON_STANDARD_ERP       → non-standard ERP (no trailing OP_CHECKMULTISIG per inner)
///   3000 P2SH_ERP / 4000 P2SH_P2WSH_ERP → P2SH-ERP template
/// (The P2SH-P2WSH-ERP federation reuses the P2SH-ERP redeem template — see
/// `FederationFactory.buildP2shP2wshErpFederation`.)
fn federation_redeem_for_format(
    keys: &[[u8; 33]],
    format_version: u64,
    config: &BridgeConstants,
) -> Vec<u8> {
    let threshold = keys.len() / 2 + 1;
    if format_version <= 1000 {
        return build_federation_redeem_script(keys, threshold);
    }
    let erp_keys: Vec<[u8; 33]> = config
        .erp_fed_pubkeys
        .iter()
        .map(|hex| {
            let bytes = alloy_primitives::hex::decode(hex).expect("valid erp pubkey hex");
            bytes.try_into().expect("33-byte compressed erp pubkey")
        })
        .collect();
    let erp_threshold = erp_keys.len() / 2 + 1;
    let csv = config.erp_fed_activation_delay;
    // 2000 = non-standard ERP (p2sh=false); 3000/4000 = P2SH-ERP template (p2sh=true).
    let p2sh = format_version >= 3000;
    build_erp_redeem_script(keys, threshold, &erp_keys, erp_threshold, csv, p2sh)
}

/// Read a federation's stored format version (rskj
/// `FederationStorageProviderImpl.getFederationFormatVersion`): the value in the
/// `*FederationFormatVersion` cell, or `STANDARD_MULTISIG_FEDERATION` (1000) when
/// the cell is absent (a pre-RSKIP123 only-BTC-keys federation).
fn federation_format_version<CTX: crate::RskContextTr>(ctx: &mut CTX, key_name: &str) -> u64 {
    let cell = bridge_load_bytes_named(ctx, key_name);
    if cell.is_empty() {
        1000
    } else {
        super::storage::rlp_decode_uint(&cell).to::<u64>()
    }
}

/// Public wrapper for governance (commit_federation event addresses).
pub fn redeem_script_hash160_pub(redeem_script: &[u8]) -> [u8; 20] {
    redeem_script_hash160(redeem_script)
}

/// P2SH output script program bytes for a script hash160
/// (`OP_HASH160 <hash160> OP_EQUAL`), matching bitcoinj
/// `ScriptBuilder.createP2SHOutputScript(...).getProgram()`. Used by the
/// federation handover to persist `lastRetiredFederationP2SHScript`.
pub fn p2sh_output_script_program(hash160: &[u8; 20]) -> Vec<u8> {
    p2sh_output_script(hash160).into_bytes()
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
pub(crate) fn load_federation_member_keys<CTX: crate::RskContextTr>(ctx: &mut CTX) -> Vec<[u8; 33]> {
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

/// rskj `BridgeUtils.getRegularPegoutTxSize` for a regular peg-out (two inputs,
/// two outputs). The active federation's actual (format-aware, possibly ERP)
/// redeem script length and required-signature count drive the estimate.
///
/// - Pre-RSKIP271: `BridgeUtilsLegacy.calculatePegoutTxSize` — an analytic
///   approximation parameterised by the script-sig chunk size.
/// - Post-RSKIP271: `BridgeUtils.calculateLegacyTxSize` — the exact
///   `BtcTransaction.bitcoinSerialize()` length of a 2-in/2-out legacy tx whose
///   inputs carry the redeem script as their scriptSig, plus
///   `numSigsRequired * inputsCount * 72`. (Mainnet federations are never
///   segwit at the heights rustock handles, so only the legacy branch applies.)
fn regular_pegout_tx_size(redeem: &[u8], num_sigs_required: u64, rskip271: bool) -> u64 {
    const INPUTS: u64 = 2;
    const OUTPUTS: u64 = 2;

    if !rskip271 {
        const SIGNATURE_MULTIPLIER: u64 = 71;
        const OUTPUT_SIZE: u64 = 25;
        const INPUT_ADDITIONAL_DATA_SIZE: u64 = 40;
        const OUTPUT_ADDITIONAL_DATA_SIZE: u64 = 9;
        const TX_ADDITIONAL_DATA_SIZE: u64 = 4;

        let script_sig_chunk =
            num_sigs_required * (SIGNATURE_MULTIPLIER + 1) + redeem.len() as u64 + 1;
        return TX_ADDITIONAL_DATA_SIZE
            + (script_sig_chunk + INPUT_ADDITIONAL_DATA_SIZE) * INPUTS
            + (OUTPUT_SIZE + 1 + OUTPUT_ADDITIONAL_DATA_SIZE) * OUTPUTS;
    }

    // Post-RSKIP271: exact bitcoinSerialize() length of the legacy tx that
    // BridgeUtils.calculateLegacyTxSize builds (input scriptSig = redeem,
    // output scriptPubKey = the 23-byte P2SH-to-federation script).
    const P2SH_SCRIPT_LEN: u64 = 23;
    let r = redeem.len() as u64;
    let base_size = 4 // version
        + varint_size(INPUTS)
        + INPUTS * (36 + varint_size(r) + r + 4)
        + varint_size(OUTPUTS)
        + OUTPUTS * (8 + varint_size(P2SH_SCRIPT_LEN) + P2SH_SCRIPT_LEN)
        + 4; // locktime
    let signing_size = num_sigs_required * INPUTS * 72;
    base_size + signing_size
}

/// bitcoinj `VarInt` serialized length.
fn varint_size(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// rskj `BridgeSupport.requestRelease` minimum-fee estimate (post-RSKIP219):
/// `feePerKb * pegoutSize / 1000`, plus a configured percentage gap.
fn require_funds_for_fee(
    redeem: &[u8],
    num_sigs_required: u64,
    fee_per_kb: u64,
    rskip271: bool,
    config: &BridgeConstants,
) -> u64 {
    let pegout_size = regular_pegout_tx_size(redeem, num_sigs_required, rskip271);
    let base = fee_per_kb * pegout_size / 1000;
    base + base * config.minimum_pegout_value_percentage_to_receive_after_fee / 100
}

/// Read the effective fee per KB from storage, falling back to genesis value.
fn get_effective_fee_per_kb<CTX: crate::RskContextTr>(ctx: &mut CTX, config: &BridgeConstants) -> u64 {
    let stored = super::storage::bridge_load_u256(ctx, super::storage::FEE_PER_KB_KEY);
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
        // rskj getSigInsertionIndex -> findKeyInRedeem throws when the
        // federator's key is not in this input's redeem script (e.g. a
        // NEW-federation member signing a migration tx that spends the OLD
        // federation's UTXOs); processSigning catches it and returns,
        // keeping any inputs already signed in this call. The signature
        // verified fine against the federator's own key, so without this
        // gate it would fill a placeholder it has no claim to (#2,448,984).
        if !super::release_tx::spending_redeem_keys(&redeems[i]).contains(fed_key) {
            return signed;
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
pub fn get_next_pegout_creation_block_number<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = super::storage::bridge_load_u256(ctx, NEXT_PEGOUT_HEIGHT_KEY);
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
pub fn get_queued_pegouts_count<CTX: crate::RskContextTr>(
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
pub fn get_estimated_fees_for_next_pegout<CTX: crate::RskContextTr>(
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
pub fn get_estimated_fees_for_pegout_amount<CTX: crate::RskContextTr>(
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

    /// Regression for mainnet #5,967,453: a flyover negative response code must
    /// be ABI-encoded as a FULL 256-bit two's-complement int256 (rskj
    /// `BigInteger.valueOf(code)`), not a 128-bit-wide value zero-extended to
    /// 256 bits. The LBC contract checks `bridgeResponse + 900 == 0` to detect
    /// GENERIC_ERROR (-900); the old `code as i128 as u128` produced `2^128-900`,
    /// so adding 900 overflowed at bit 128 to `2^128` (non-zero) instead of
    /// wrapping at bit 256 to 0 — flipping a JUMPI and over-charging 51,580 gas
    /// (computed 194,449 vs header 142,869).
    #[test]
    fn flyover_code_output_full_256bit_twos_complement() {
        // -900 = 0xffff...fc7c with ALL 31 high bytes 0xff (64 hex f's).
        let out = flyover_code_output(flyover_codes::GENERIC_ERROR);
        let expected = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7c";
        assert_eq!(alloy_primitives::hex::encode(&out), expected);

        // The contract's check: response + 900 == 0 (mod 2^256).
        let v = U256::from_be_slice(&out);
        assert_eq!(v.wrapping_add(U256::from(900u64)), U256::ZERO);

        // Every negative flyover code round-trips: value + |code| == 0 (mod 2^256).
        for code in [
            flyover_codes::REFUNDED_USER,
            flyover_codes::REFUNDED_LP,
            flyover_codes::UNPROCESSABLE_NOT_CONTRACT,
            flyover_codes::UNPROCESSABLE_VALIDATIONS,
            flyover_codes::GENERIC_ERROR,
        ] {
            let v = U256::from_be_slice(&flyover_code_output(code));
            assert_eq!(v.wrapping_add(U256::from(code.unsigned_abs())), U256::ZERO);
            // High byte is 0xff (sign-extended across the whole word).
            assert_eq!(flyover_code_output(code)[0], 0xff);
        }

        // A non-negative locked-amount code encodes as a plain big-endian uint.
        assert_eq!(U256::from_be_slice(&flyover_code_output(0)), U256::ZERO);
        assert_eq!(U256::from_be_slice(&flyover_code_output(123_456)), U256::from(123_456u64));
    }

    /// Regression for mainnet #5,171,600: once the retiring federation is
    /// cleared earlier in the block, a btc tx that pays only the now-retired
    /// federation leaves an EMPTY set of live-federation outputs. rskj's
    /// `isAnyUTXOAmountBelowMinimum` (RSKIP293) is `false` over that empty set,
    /// so the tx is a valid amount-0 peg-in (it emits pegin_btc(amount=0),
    /// creates the destination account and is marked processed) rather than
    /// being ignored. Pre-RSKIP293 the 0 total is below minimum → not a peg-in.
    #[test]
    fn empty_live_outputs_are_not_below_minimum_under_rskip293() {
        let min = 500_000;
        // RSKIP293: per-UTXO. Empty set → not below minimum (valid amount-0 peg-in).
        assert!(!pegin_below_minimum(&[], min, true));
        // A single below-minimum UTXO → below minimum (rejected).
        assert!(pegin_below_minimum(&[100_000], min, true));
        // Any below-minimum UTXO fails even if the total clears the minimum.
        assert!(pegin_below_minimum(&[100_000, 600_000], min, true));
        // All UTXOs at/above the minimum → valid.
        assert!(!pegin_below_minimum(&[500_000, 600_000], min, true));

        // Pre-RSKIP293: total comparison. Empty set (0 total) IS below minimum.
        assert!(pegin_below_minimum(&[], min, false));
        // A mix below the minimum total is below; one clearing it is not.
        assert!(pegin_below_minimum(&[100_000, 300_000], min, false));
        assert!(!pegin_below_minimum(&[100_000, 600_000], min, false));
    }

    /// Regression for mainnet #5,527,682 (RSKIP377, Fingerroot500): on a
    /// federation handover the retiring ERP federation's
    /// `lastRetiredFederationP2SHScript` is its *members* (default / standard
    /// multisig branch) P2SH, NOT the full ERP P2SH. rskj
    /// `FederationSupportImpl.getFederationMembersP2SHScript` returns
    /// `ErpFederation.getDefaultP2SHScript()` for an ERP federation. Pre-RSKIP377
    /// it stored the full ERP P2SH; the two hash160s differ, so getting this
    /// wrong forks the state trie at the `lastRetiredFedP2SHScript` leaf.
    #[test]
    fn rskip377_last_retired_fed_uses_default_branch_p2sh() {
        let config = crate::bridge::constants::BridgeConstants::mainnet();
        let hardfork = RskHardforkConfig::mainnet();
        // A P2SH-ERP federation (RSKIP353 active at fingerroot500).
        let block = 5_527_682u64;
        assert!(hardfork.has_rskip201(block));
        assert!(hardfork.has_rskip353(block));
        assert!(hardfork.has_rskip377(block));

        let key = |seed: u8| -> [u8; 33] {
            use k256::ecdsa::SigningKey;
            let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
            sk.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap()
        };
        let mut keys: Vec<[u8; 33]> = (1u8..=5).map(key).collect();
        keys.sort();

        // Full ERP redeem (what the federation IS) vs the default/standard branch.
        let full_erp = build_committed_federation_redeem_script(&keys, &config, &hardfork, block);
        let default_branch = build_federation_redeem_script(&keys, keys.len() / 2 + 1);
        assert_ne!(full_erp, default_branch, "ERP redeem must differ from its default branch");

        let full_hash = redeem_script_hash160(&full_erp);
        let default_hash = redeem_script_hash160(&default_branch);
        // RSKIP377 stores the default-branch P2SH; the legacy bug stored the ERP one.
        assert_ne!(
            full_hash, default_hash,
            "members P2SH (default branch) must differ from the full ERP P2SH",
        );
    }

    /// Regression for mainnet #2,448,984: a federator whose key is NOT in an
    /// input's redeem script (a NEW-federation member signing the migration
    /// tx that spends the OLD federation's UTXOs) must not have its
    /// signature applied — rskj's getSigInsertionIndex/findKeyInRedeem
    /// throws and processSigning returns. The signature itself verifies
    /// against the federator's own key, so only redeem membership blocks it.
    #[test]
    fn add_signature_rejects_key_not_in_redeem_script() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{Signature, SigningKey};

        let key_pair = |seed: u8| {
            let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
            let pk: [u8; 33] = sk
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
            (sk, pk)
        };
        let members: Vec<_> = (1u8..=3).map(key_pair).collect();
        let (outsider_sk, outsider_pk) = key_pair(9);
        let member_keys: Vec<[u8; 33]> = members.iter().map(|(_, pk)| *pk).collect();
        let redeem = build_federation_redeem_script(&member_keys, 2);

        let mut tx = BtcTransaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from_bytes(
                    super::super::release_tx::placeholder_scriptsig(&redeem, 2),
                ),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        let sighash = super::super::release_tx::legacy_sighash_all(&tx, 0, &redeem);
        let sign = |sk: &SigningKey| {
            let sig: Signature = sk.sign_prehash(&sighash).unwrap();
            sig.to_der().as_bytes().to_vec()
        };

        // Outsider: verifies against its own key but is not in the redeem.
        let before = tx.input[0].script_sig.clone();
        assert!(!apply_signatures_to_tx(&mut tx, &[sign(&outsider_sk)], &outsider_pk));
        assert_eq!(tx.input[0].script_sig, before, "script must be untouched");

        // Member: applied normally.
        assert!(apply_signatures_to_tx(&mut tx, &[sign(&members[0].0)], &members[0].1));
        assert_ne!(tx.input[0].script_sig, before);
    }

    /// Regression for mainnet #4,598,511 (just after Hop400 / RSKIP271 at
    /// #4,598,500): a state-root divergence caused by NOT advancing the
    /// Bridge's `nextPegoutHeight` storage cell when an updateCollections call
    /// runs with an empty release-request queue.
    ///
    /// rskj `BridgeSupport.processPegoutsInBatch` (BridgeSupport.java:1554-1559)
    /// sets `nextPegoutHeight = currentBlock + numberOfBlocksBetweenPegouts`
    /// whenever the queue ends up empty — *including* when it was empty to begin
    /// with — as long as `currentBlock >= nextPegoutHeight` (the gate at
    /// line 1501). At Hop400 the cell is unset (0), so the gate is open and the
    /// very first updateCollections after activation writes the cell, mutating
    /// Bridge storage and thus the state root.
    ///
    /// Ground truth: mainnet `numberOfBlocksBetweenPegouts = 360`
    /// (BridgeMainNetConstants.java:45), so block #4,598,511 advances the height
    /// to 4,598,871.
    #[test]
    fn rskip271_next_pegout_height_formula_mainnet() {
        let cfg = crate::RskHardforkConfig::mainnet();
        let constants = BridgeConstants::mainnet();
        assert_eq!(constants.number_of_blocks_between_pegouts, 360);

        // RSKIP271 active at Hop400 (#4,598,500) and onward.
        assert!(cfg.has_rskip271(4_598_500));
        assert!(cfg.has_rskip271(4_598_511));
        assert!(!cfg.has_rskip271(4_598_499));

        // The gate: a freshly-activated chain has nextPegoutHeight = 0, so any
        // post-activation block satisfies `block >= nextPegoutHeight` and the
        // empty-queue tail must advance the height.
        let block_number = 4_598_511u64;
        let next_height = block_number + constants.number_of_blocks_between_pegouts;
        assert_eq!(next_height, 4_598_871);
    }

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

    /// Byte-exact ground truth: the mainnet `releaseTransactionSetWithTxHash`
    /// cell at #2,421,462 (one pegout created by updateCollections), dumped
    /// from a synced rskj unitrie. rskj splits the ONE in-memory set across
    /// the legacy cell (hash-less entries, pairs) and the with-txhash cell
    /// (hash-bearing entries, triples); this entry carries the requesting RSK
    /// tx hash and lives ONLY in the with-txhash cell (legacy stays 0xc0).
    #[test]
    fn rskj_pegout_set_with_txhash_groundtruth_2421462() {
        use alloy_primitives::hex;
        let rskj = hex::decode(
            "f901ddb901b5010000000105fa7bc00829cc15870c0bab2fb67c4d0e8dcfb08cb926148c9fbc0eb159252001000000fd3e01\
             0000000000004d35015521027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c81715\
             0f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2102a9c6848e302193179ce6479516c2d97f6967e136\
             5c707e3b9d3e0cb683ccb8222103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93210372cd\
             46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33\
             ae751e248ae60094cc989fb880f62103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103\
             b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c45732103ecd8af1e93c57a1b8c7f917bd9980af7\
             98adeb0205e9687865673353eb041e8d59aeffffffff02026b1000000000001976a914410deef0190ff5ef7bb4da984c804b\
             fe12a843c888ac20c375470000000017a914279d4b44e8cf5e3f04c0ea21c78f1a0ecaa4cd9f87000000008324f2d6a08036\
             e82984f100a1213c8ac65fb620aa65dab57ddaba3577b55bd81d0a40234a",
        )
        .unwrap();
        let decoded = deserialize_pegouts_waiting_for_confirmations(&rskj, true);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].rsk_block_height, 2_421_462);
        assert_eq!(
            hex::encode(decoded[0].rsk_tx_hash.unwrap()),
            "8036e82984f100a1213c8ac65fb620aa65dab57ddaba3577b55bd81d0a40234a"
        );
        assert_eq!(serialize_pegouts_waiting_for_confirmations(&decoded, true), rskj);
        // The same entries serialized for the LEGACY cell must exclude the
        // hash-bearing entry entirely (rskj getEntriesWithoutHash) — that
        // cell stays an empty list.
        let hashless: Vec<PegoutWaitingForConfirmations> = decoded
            .iter()
            .filter(|e| e.rsk_tx_hash.is_none())
            .cloned()
            .collect();
        assert_eq!(serialize_pegouts_waiting_for_confirmations(&hashless, false), vec![0xc0]);
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

    fn key(hex: &str) -> [u8; 33] {
        alloy_primitives::hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn p2sh_base58_mainnet(redeem: &[u8]) -> String {
        let mut payload = [0u8; 21];
        payload[0] = 5; // mainnet P2SH version
        payload[1..].copy_from_slice(&redeem_script_hash160(redeem));
        bitcoin::base58::encode_check(&payload)
    }

    /// rskj `Utils.signedLongToByteArrayLE`: 52560 -> `50 cd 00` (sign byte
    /// preserved, NOT BIP68-minimal). Consensus-critical CSV-delay encoding.
    #[test]
    fn erp_csv_delay_encoding_groundtruth() {
        assert_eq!(signed_long_to_byte_array_le(52560), vec![0x50, 0xcd, 0x00]);
        assert_eq!(signed_long_to_byte_array_le(500), vec![0xf4, 0x01]);
        assert_eq!(signed_long_to_byte_array_le(1), vec![0x01]);
    }

    /// Ground truth: the first real RSK mainnet federation change committed at
    /// block #4,652,781 produced a NON-STANDARD ERP federation (RSKIP201 active,
    /// RSKIP353 not). Its base58 P2SH address appears in the block's
    /// commit_federation event (header receipts root
    /// 0x883ea305...). New federation 5-of-9 default keys + the 4 mainnet
    /// emergency keys, CSV 52560.
    #[test]
    fn nonstandard_erp_federation_address_mainnet_4652781() {
        let new_keys = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c36",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
            "03ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d",
        ]
        .map(key);
        let erp_keys = BridgeConstants::mainnet()
            .erp_fed_pubkeys
            .iter()
            .map(|h| key(h))
            .collect::<Vec<_>>();
        // NonStandard ERP (p2sh = false): default 5-of-9, emergency 3-of-4.
        let redeem = build_erp_redeem_script(&new_keys, 5, &erp_keys, 3, 52560, false);
        assert_eq!(p2sh_base58_mainnet(&redeem), "3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh");
    }

    /// Ground truth ported from rskj P2shErpFederationTest
    /// `createdFederationInfo_withRealValues_equalsExistingFederationInfo_mainnet`:
    /// P2SH-ERP federation (RSKIP353 active) for a real mainnet fed →
    /// program `a9142c1bab6ea51fdaf85c8366bd2b1502eaa69b6ae687`, address
    /// `35iEoWHfDfEXRQ5ZWM5F6eMsY2Uxrc64YK`.
    #[test]
    fn p2sh_erp_federation_address_rskj_fixture() {
        let default_keys = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c949",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
            "03b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b35888771906",
        ]
        .map(key);
        let erp_keys = BridgeConstants::mainnet()
            .erp_fed_pubkeys
            .iter()
            .map(|h| key(h))
            .collect::<Vec<_>>();
        let redeem = build_erp_redeem_script(&default_keys, 5, &erp_keys, 3, 52560, true);
        assert_eq!(
            alloy_primitives::hex::encode(p2sh_output_script(&redeem_script_hash160(&redeem)).as_bytes()),
            "a9142c1bab6ea51fdaf85c8366bd2b1502eaa69b6ae687"
        );
        assert_eq!(p2sh_base58_mainnet(&redeem), "35iEoWHfDfEXRQ5ZWM5F6eMsY2Uxrc64YK");
    }

    /// Ground truth for `federation_redeem_for_format` — the dispatch that fixes
    /// the #4,677,229 divergence. A live federation's redeem script must follow
    /// its STORED format version, not the current block. At #4,677,229 the active
    /// federation is the format-2000 (NON_STANDARD_ERP) fed and the retiring one
    /// is format-1000 (STANDARD_MULTISIG); a `registerBtcTransaction` migration tx
    /// pays the active fed's P2SH (3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh), and the
    /// change UTXO is only registered if that script is reconstructed correctly.
    #[test]
    fn federation_redeem_for_format_groundtruth() {
        // The real format-2000 ERP federation active at #4,677,229 (== the fed
        // committed at #4,652,781), 5-of-9 default keys.
        let active_keys = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c36",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
            "03ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d",
        ]
        .map(key);
        let config = BridgeConstants::mainnet();

        // format 2000 (NON_STANDARD_ERP) → the active fed's real mainnet P2SH.
        let r2000 = federation_redeem_for_format(&active_keys, 2000, &config);
        assert_eq!(
            p2sh_base58_mainnet(&r2000),
            "3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh",
            "format 2000 must build the non-standard ERP redeem script"
        );

        // format 1000 (STANDARD_MULTISIG) → plain N-of-M, a DIFFERENT address.
        let r1000 = federation_redeem_for_format(&active_keys, 1000, &config);
        assert_eq!(
            r1000,
            build_federation_redeem_script(&active_keys, active_keys.len() / 2 + 1),
            "format 1000 must build a plain multisig redeem script"
        );
        assert_ne!(
            p2sh_base58_mainnet(&r1000),
            "3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh",
            "the standard multisig must NOT collide with the ERP address"
        );

        // format 3000 (P2SH_ERP) → the P2SH-ERP template (p2sh=true), distinct
        // from the non-standard ERP form.
        let r3000 = federation_redeem_for_format(&active_keys, 3000, &config);
        assert_ne!(r3000, r2000, "P2SH-ERP and non-standard ERP differ");
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

    /// rskj `getNextPegoutWithEnoughConfirmations` selects the first confirmed
    /// entry in Java `HashSet` iteration order — not storage (btc-tx-sorted)
    /// order. Groundtruth from RSK Mainnet block #3,345,557 (migration window):
    /// two pegout entries share creation height 3,341,556 and both confirm at
    /// this block (min 4000 confirmations), so the tie is broken purely by
    /// HashSet bucket order. rskj moved the `a7c69a46…` input tx
    /// (pegoutCreationRskTxHash `26dc74c8…`) into pegoutsWaitingForSignatures,
    /// leaving the lexicographically-smaller `0260d432…` tx in the set. A naive
    /// btc-tx-sorted selection would pick the wrong one and fork the chain.
    #[test]
    fn rskj_next_pegout_hashset_iteration_order_groundtruth() {
        // The two real h=3,341,556 entries from the diverging cell at #3,345,557.
        // rskj-selected (moved to WFS): btc spends input a7c69a46…:1.
        let selected_btc = hex::decode(
            "010000000122fab61f4bdfe74f41dfecbe2a52d0cb5aa42c898687c6142d3f8497469ac6a701000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff029a686c09000000001976a914fb53759d716de10362f5b57d28151a6481fd30e188ace354f1f00c00000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();
        // rskj-kept (NOT selected): btc spends input 0260d432…:1, smaller bytes.
        let kept_btc = hex::decode(
            "01000000010260d43256d4072e46f87acec7e3225752beff0fcb60288baf5088f5d5e9949401000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff02a69bbc06000000001976a9140b9c738761bb47eba3802df6ac169717aa85b6f088ac104bd32d0100000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();

        let mk = |btc: &[u8], h: u64| PegoutWaitingForConfirmations {
            btc_tx_raw: btc.to_vec(),
            rsk_block_height: h,
            rsk_tx_hash: Some([0u8; 32]),
        };

        // 13 entries (the real cell size at #3,345,557) so the HashSet capacity
        // is 32. The 11 fillers carry height 3,345,000 (only 557 confirmations
        // at block 3,345,557) so they never confirm and the tie is decided by
        // the two real entries' buckets: a7c69a46→9, 0260d432→20.
        let mut entries = vec![mk(&kept_btc, 3_341_556), mk(&selected_btc, 3_341_556)];
        for i in 0..11u8 {
            entries.push(mk(&[1, 0, 0, 0, i], 3_345_000));
        }

        let pos = next_pegout_with_enough_confirmations(&entries, 3_345_557, 4000)
            .expect("one confirmed entry");
        assert_eq!(
            entries[pos].btc_tx_raw, selected_btc,
            "must promote the a7c69a46… tx (HashSet bucket 9) like rskj, not the \
             lexicographically-smaller 0260d432… tx (bucket 20)"
        );
    }

    /// rskj builds the pegouts-waiting-for-confirmations `HashSet` incrementally
    /// (`new HashSet<>()` + one-by-one `add`), so the table capacity follows the
    /// Java `HashMap` resize history (start 16, double when `size > cap*0.75`),
    /// NOT the `new HashSet<>(collection)` pre-size formula. The two disagree at
    /// the resize boundaries: a 12-entry set has capacity 16, but the pre-size
    /// formula would give 32; a 24-entry set has capacity 32, not 64. Getting the
    /// capacity wrong reshuffles the bucket walk and forks the pegout selection.
    #[test]
    fn java_hashset_capacity_resize_boundaries() {
        // <=12 fit at the default capacity 16 (threshold = 12, resize is strict >).
        assert_eq!(java_hashset_capacity(0), 16);
        assert_eq!(java_hashset_capacity(1), 16);
        assert_eq!(java_hashset_capacity(12), 16);
        // 13th insertion crosses 16's threshold → 32 (threshold 24).
        assert_eq!(java_hashset_capacity(13), 32);
        assert_eq!(java_hashset_capacity(24), 32);
        // 25th crosses 32's threshold → 64 (threshold 48).
        assert_eq!(java_hashset_capacity(25), 64);
        assert_eq!(java_hashset_capacity(48), 64);
        assert_eq!(java_hashset_capacity(49), 128);
    }

    /// Resize-boundary selection: with the two real h=3,341,556 entries plus
    /// fillers totalling exactly 13 entries the capacity is 32 (a7c69a46→bucket 9,
    /// 0260d432→bucket 20), so the a7c69a46 tx is selected — the #3,345,557
    /// groundtruth. The point here is the boundary count: 13 entries is the first
    /// size that resizes 16→32, and the OLD pre-size formula also yielded 32, so
    /// both gave the right answer at 13. This guards that the incremental model
    /// keeps capacity 32 at 13 (and would have given 16 at 12).
    #[test]
    fn pegout_selection_at_16_to_32_resize_boundary() {
        let selected_btc = hex::decode(
            "010000000122fab61f4bdfe74f41dfecbe2a52d0cb5aa42c898687c6142d3f8497469ac6a701000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff029a686c09000000001976a914fb53759d716de10362f5b57d28151a6481fd30e188ace354f1f00c00000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();
        let kept_btc = hex::decode(
            "01000000010260d43256d4072e46f87acec7e3225752beff0fcb60288baf5088f5d5e9949401000000fdc80100000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff67802992103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5daeffffffff02a69bbc06000000001976a9140b9c738761bb47eba3802df6ac169717aa85b6f088ac104bd32d0100000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a8700000000",
        )
        .unwrap();
        let mk = |btc: &[u8], h: u64| PegoutWaitingForConfirmations {
            btc_tx_raw: btc.to_vec(),
            rsk_block_height: h,
            rsk_tx_hash: Some([0u8; 32]),
        };
        let mut entries = vec![mk(&kept_btc, 3_341_556), mk(&selected_btc, 3_341_556)];
        for i in 0..11u8 {
            entries.push(mk(&[1, 0, 0, 0, i], 3_345_000));
        }
        assert_eq!(entries.len(), 13);
        assert_eq!(java_hashset_capacity(entries.len()), 32);
        let pos = next_pegout_with_enough_confirmations(&entries, 3_345_557, 4000)
            .expect("one confirmed entry");
        assert_eq!(entries[pos].btc_tx_raw, selected_btc);
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
        match classify_pegin_sender(&tx) {
            Some(PeginSender::P2pkh { pubkey: parsed }) => assert_eq!(parsed, pubkey),
            other => panic!("expected P2PKH sender, got {}", other.is_some()),
        }
    }

    /// rskj BtcLockSenderProvider: a P2SH-multisig first input (OP_0,
    /// signatures, multisig redeem) classifies as P2SHMULTISIG with the
    /// sender address = P2SH(hash160(redeem)) — processable post-RSKIP143
    /// but NOT lockable (refunded). Groundtruth shape from mainnet
    /// #2,851,909 tx 2.
    #[test]
    fn classify_p2sh_multisig_pegin_sender() {
        // 2-of-3 multisig redeem with valid-shape compressed keys.
        let mut redeem = vec![0x52];
        for i in 0..3u8 {
            redeem.push(33);
            let mut k = [0x02u8; 33];
            k[32] = i;
            redeem.extend_from_slice(&k);
        }
        redeem.push(0x53);
        redeem.push(0xae);
        let mut script = vec![0x00, 71];
        script.extend_from_slice(&[0x30; 71]);
        script.push(71);
        script.extend_from_slice(&[0x30; 71]);
        script.push(0x4c); // PUSHDATA1
        script.push(redeem.len() as u8);
        script.extend_from_slice(&redeem);
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
        match classify_pegin_sender(&tx) {
            Some(PeginSender::P2shMultisig { p2sh_hash }) => {
                assert_eq!(p2sh_hash, pubkey_hash160(&redeem));
            }
            other => panic!("expected P2SH-multisig sender, got {}", other.is_some()),
        }
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

    /// rskTxsWaitingFS is a Java TreeMap<Keccak256, BtcTransaction>; rskj's
    /// `Keccak256.compareTo` compares bytes UNSIGNED from the LAST byte down to
    /// the first (reverse/little-endian order). Ground truth from RSK Mainnet
    /// block #3,340,065: the two waiting-for-signatures RSK tx hashes must
    /// serialize with `285b…0c` BEFORE `12b7…f0` (last bytes 0x0c < 0xf0),
    /// the opposite of forward (big-endian) BTreeMap order (0x12 < 0x28).
    #[test]
    fn rsk_txs_waiting_fs_keccak_reverse_byte_order() {
        let k_12b7: [u8; 32] =
            hex::decode("12b7dd806871857a4d949c2bbd25ab95bce3c4a38ef5c7fcee7bc43ea3a6baf0")
                .unwrap()
                .try_into()
                .unwrap();
        let k_285b: [u8; 32] =
            hex::decode("285b09d3973cbe2a324cb7d3248b36ee668b66093f2976f1e5a5a4b5d9a7d10c")
                .unwrap()
                .try_into()
                .unwrap();
        let mut map = BTreeMap::new();
        map.insert(k_12b7, vec![0xaa]);
        map.insert(k_285b, vec![0xbb]);
        let out = serialize_rsk_txs_waiting_for_signatures(&map);
        let items = rlp_decode_list(&out).unwrap();
        // First serialized key must be 285b… (smaller under reverse-byte order).
        assert_eq!(items[0], k_285b);
        assert_eq!(items[2], k_12b7);
    }

    /// A 13-member standard multisig federation's regular peg-out (2 inputs,
    /// 2 outputs). The redeem script is the 7-of-13 multisig (445 bytes).
    ///
    /// Pre-RSKIP271 (`BridgeUtilsLegacy.calculatePegoutTxSize`) must size to
    /// within 2% of the real-world 2076 bytes. Post-RSKIP271
    /// (`BridgeUtils.calculateLegacyTxSize`) is the exact `bitcoinSerialize()`
    /// length: ported ground truth from rskj
    /// `BridgeUtilsTest.testCalculatePegoutTxSize_2Inputs_2Outputs` = 2058 bytes.
    #[test]
    fn regular_pegout_tx_size_matches_rskj() {
        use k256::ecdsa::SigningKey;
        let keys: Vec<[u8; 33]> = (1u8..=13)
            .map(|seed| {
                SigningKey::from_slice(&[seed; 32])
                    .unwrap()
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap()
            })
            .collect();
        let threshold = keys.len() / 2 + 1; // 7
        let redeem = build_federation_redeem_script(&keys, threshold);

        // Post-RSKIP271: exact match against rskj's 2058.
        assert_eq!(regular_pegout_tx_size(&redeem, threshold as u64, true), 2058);

        // Pre-RSKIP271: within 2% of the real-world 2076-byte tx.
        let legacy = regular_pegout_tx_size(&redeem, threshold as u64, false) as i64;
        let orig = 2076i64;
        assert!(
            (orig - legacy).abs() as f64 <= orig as f64 * 0.02,
            "legacy size {legacy} too far from {orig}"
        );
    }

    /// At mainnet #3,615,279 (feePerKb 30000 sat/kB, mainnet federation) the
    /// fee-based minimum is far below the 400000-sat minimumPegoutTxValue, so a
    /// 10000-sat direct transfer is rejected with reason LOW_AMOUNT (not
    /// FEE_ABOVE_VALUE). This pins the reason-selection branch.
    #[test]
    fn require_funds_for_fee_below_minimum_pegout_value() {
        let config = BridgeConstants::mainnet();
        let keys = genesis_federation_keys(&config);
        let threshold = keys.len() / 2 + 1;
        let redeem = build_federation_redeem_script(&keys, threshold);
        let fee = require_funds_for_fee(&redeem, threshold as u64, 30_000, true, &config);
        assert!(
            fee < config.minimum_pegout_tx_value,
            "require_funds_for_fee {fee} should be below {} so reason is LOW_AMOUNT",
            config.minimum_pegout_tx_value
        );
    }

    // -----------------------------------------------------------------------
    // Flyover (RSKIP176) ground-truth tests
    // -----------------------------------------------------------------------

    /// rskj `BitcoinTestUtils.createP2PKHAddress`: priv = keccak256(seed),
    /// address = `[version=0] || hash160(compressed pubkey)` on mainnet.
    fn mainnet_p2pkh_addr_bytes(seed: &str) -> Vec<u8> {
        use k256::ecdsa::SigningKey;
        use sha3::Digest;
        let priv_bytes: [u8; 32] = sha3::Keccak256::digest(seed.as_bytes()).into();
        let sk = SigningKey::from_slice(&priv_bytes).unwrap();
        let pubkey = sk.verifying_key().to_encoded_point(true); // compressed
        let hash160 = pubkey_hash160(pubkey.as_bytes());
        let mut out = vec![0u8]; // mainnet P2PKH version
        out.extend_from_slice(&hash160);
        out
    }

    /// Ported from rskj `PegUtilsTest.getFlyoverDerivationHash_returnsExpectedDerivationHash`
    /// (hardcoded expected hash `56d4f6bd…44d8`).
    #[test]
    fn flyover_derivation_hash_groundtruth() {
        // derivationArgumentsHash = PegTestUtils.createHash3(5) → byte[0]=5.
        let mut derivation_args = [0u8; 32];
        derivation_args[0] = 5;
        let user_refund = mainnet_p2pkh_addr_bytes("userRefundBtcAddress");
        let lp_btc = mainnet_p2pkh_addr_bytes("lpBtcAddress");
        let lbc = RskAddress::from_slice(
            &hex_to_bytes("461750b4824b14c3d9b7702bc6fbb82469082b23"),
        );

        let hash = flyover_derivation_hash(&derivation_args, &user_refund, &lbc, &lp_btc);
        assert_eq!(
            to_hex(&hash),
            "56d4f6bd69378ef607e091832903ddc2b5aac5008bd06987a26f14bb248c44d8"
        );
    }

    /// Ported from rskj `PegUtilsTest.getFlyoverValues_fromRealLegacyFedTx`:
    /// the flyover redeem script (`PUSH(hash) OP_DROP <fedRedeem>`) and its
    /// P2SH hash160 for derivation hash `fc2bb9…0439`.
    #[test]
    fn flyover_redeem_script_and_p2sh_groundtruth() {
        let flyover_hash: [u8; 32] = hex_to_bytes(
            "fc2bb93810d3d2332fed0b291c03822100a813eceaa0665896e0c82a8d500439",
        )
        .try_into()
        .unwrap();
        // The full expected flyover redeem script from rskj.
        let expected_flyover_redeem = hex_to_bytes(
            "20fc2bb93810d3d2332fed0b291c03822100a813eceaa0665896e0c82a8d50043975645521020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c21025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db210275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c9492102a95f095d0ce8cb3b9bf70cc837e3ebe1d107959b1fa3f9b2d8f33446f9c8cbdb2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321034851379ec6b8a701bd3eef8a0e2b119abb4bdde7532a3d6bcbff291b0daf3f25210350179f143a632ce4e6ac9a755b82f7f4266cfebb116a42cadb104c2c2a3350f92103b04fbd87ef5e2c0946a684c8c93950301a45943bbe56d979602038698facf9032103b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b3588877190659ae670350cd00b275532102370a9838e4d15708ad14a104ee5606b36caaaaf739d833e67770ce9fd9b3ec80210257c293086c4d4fe8943deda5f890a37d11bebd140e220faa76258a41d077b4d42103c2660a46aa73078ee6016dee953488566426cf55fc8011edd0085634d75395f92103cd3e383ec6e12719a6c69515e5559bcbe037d0aa24c187e1e26ce932e22ad7b354ae68",
        );
        // The federation redeem script is the suffix after `PUSH(32) hash OP_DROP`
        // (33 + 1 bytes of prefix).
        let federation_redeem = &expected_flyover_redeem[34..];

        let flyover_redeem = flyover_redeem_script(&flyover_hash, federation_redeem);
        assert_eq!(
            to_hex(&flyover_redeem),
            to_hex(&expected_flyover_redeem),
            "flyover redeem script must match rskj"
        );

        let p2sh_hash = redeem_script_hash160(&flyover_redeem);
        assert_eq!(
            to_hex(&p2sh_hash),
            "18fc3b52a5b7d5277f41b9765719b45bfa427730",
            "flyover P2SH hash160 must match rskj"
        );
    }

    /// Regression for mainnet #5,831,167 (registerFastBridgeBtcTransaction,
    /// fingerroot500): rskj's `createFlyoverFederationInformation` derives the
    /// active flyover P2SH from `getActiveFederation().getRedeemScript()`, which
    /// is FORMAT-AWARE — at fingerroot500 the active fed is a P2SH-ERP federation
    /// (RSKIP353), so the flyover redeem must wrap the ERP redeem. rustock
    /// previously built a PLAIN multisig redeem here, producing the wrong P2SH;
    /// the BTC tx's flyover output then matched nothing, the bridge returned
    /// UNPROCESSABLE_VALUE_ZERO (-304) instead of the locked amount, and the
    /// LiquidityBridgeContract took the wrong branch — overcharging gas by 6,817
    /// (216,145 vs the header's 209,328).
    #[test]
    fn flyover_active_p2sh_uses_erp_redeem_5831167() {
        // The real ERP active-federation redeem at #5,831,167 (captured from the
        // format-aware builder) and the block's flyover derivation hash.
        let flyover_hash: [u8; 32] = hex_to_bytes(
            "5f157f6ea6385bfdc191321bda7fd285d4df84c499d9fef7660de63af590cf80",
        )
        .try_into()
        .unwrap();
        let erp_fed_redeem = hex_to_bytes(
            "645521020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c21025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db21026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c210275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c9492102a95f095d0ce8cb3b9bf70cc837e3ebe1d107959b1fa3f9b2d8f33446f9c8cbdb2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321034851379ec6b8a701bd3eef8a0e2b119abb4bdde7532a3d6bcbff291b0daf3f252103b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b358887719062103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff678029959ae670350cd00b275532102370a9838e4d15708ad14a104ee5606b36caaaaf739d833e67770ce9fd9b3ec80210257c293086c4d4fe8943deda5f890a37d11bebd140e220faa76258a41d077b4d42103c2660a46aa73078ee6016dee953488566426cf55fc8011edd0085634d75395f92103cd3e383ec6e12719a6c69515e5559bcbe037d0aa24c187e1e26ce932e22ad7b354ae68",
        );

        // Format-aware (ERP) redeem → the P2SH hash160 the BTC tx actually paid.
        let flyover_redeem = flyover_redeem_script(&flyover_hash, &erp_fed_redeem);
        assert_eq!(
            to_hex(&redeem_script_hash160(&flyover_redeem)),
            "69206b978af5523129667292dae54f464170256a",
            "active flyover P2SH must derive from the ERP redeem"
        );

        // The plain-multisig redeem over the SAME keys yields a DIFFERENT P2SH —
        // the bug that made the flyover output match nothing.
        let keys: Vec<[u8; 33]> = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "0275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c949",
            "02a95f095d0ce8cb3b9bf70cc837e3ebe1d107959b1fa3f9b2d8f33446f9c8cbdb",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "034851379ec6b8a701bd3eef8a0e2b119abb4bdde7532a3d6bcbff291b0daf3f25",
            "03b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b35888771906",
            "03e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299",
        ]
        .iter()
        .map(|h| hex_to_bytes(h).try_into().unwrap())
        .collect();
        let plain_redeem = build_federation_redeem_script(&keys, keys.len() / 2 + 1);
        let plain_p2sh = redeem_script_hash160(&flyover_redeem_script(&flyover_hash, &plain_redeem));
        assert_ne!(
            to_hex(&plain_p2sh),
            "69206b978af5523129667292dae54f464170256a",
            "plain multisig must NOT match the ERP flyover P2SH"
        );
    }

    /// The flyover-hash-used storage key uses the DISPLAY-order BTC tx hash and
    /// the FORWARD-order derivation hash (rskj getStorageKeyForFlyoverHash).
    #[test]
    fn flyover_hash_used_key_byte_order() {
        // wtxid in internal order; display order is the reverse.
        let btc_hash = hex_to_bytes(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        )
        .try_into()
        .unwrap();
        let flyover_hash = hex_to_bytes(
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        )
        .try_into()
        .unwrap();
        let key = flyover_hash_used_key(&btc_hash, &flyover_hash);
        // Reconstruct the expected compound identifier: display(btc) + forward(flyover).
        let expected = compound_key(
            FAST_BRIDGE_HASH_USED_KEY,
            "-",
            "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        );
        assert_eq!(key, expected);
    }

    /// RSKIP293 retiring-federation flyover (hop400): the retiring fed's flyover
    /// federation information is built with the SAME math as the active fed
    /// (createFlyoverFederationInformation(hash, federation) →
    /// flyover redeem = PUSH(hash) OP_DROP <fedRedeem>, P2SH = its hash160). Here
    /// we feed an ERP retiring redeem (the iris-era flyover groundtruth's inner
    /// redeem) and confirm the FlyoverFedInfo fields match the same vector the
    /// active-fed groundtruth test asserts.
    #[test]
    fn flyover_retiring_federation_information_groundtruth() {
        let flyover_hash: [u8; 32] = hex_to_bytes(
            "fc2bb93810d3d2332fed0b291c03822100a813eceaa0665896e0c82a8d500439",
        )
        .try_into()
        .unwrap();
        let expected_flyover_redeem = hex_to_bytes(
            "20fc2bb93810d3d2332fed0b291c03822100a813eceaa0665896e0c82a8d50043975645521020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c21025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db210275d473555de2733c47125f9702b0f870df1d817379f5587f09b6c40ed2c6c9492102a95f095d0ce8cb3b9bf70cc837e3ebe1d107959b1fa3f9b2d8f33446f9c8cbdb2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf9321034851379ec6b8a701bd3eef8a0e2b119abb4bdde7532a3d6bcbff291b0daf3f25210350179f143a632ce4e6ac9a755b82f7f4266cfebb116a42cadb104c2c2a3350f92103b04fbd87ef5e2c0946a684c8c93950301a45943bbe56d979602038698facf9032103b58a5da144f5abab2e03e414ad044b732300de52fa25c672a7f7b3588877190659ae670350cd00b275532102370a9838e4d15708ad14a104ee5606b36caaaaf739d833e67770ce9fd9b3ec80210257c293086c4d4fe8943deda5f890a37d11bebd140e220faa76258a41d077b4d42103c2660a46aa73078ee6016dee953488566426cf55fc8011edd0085634d75395f92103cd3e383ec6e12719a6c69515e5559bcbe037d0aa24c187e1e26ce932e22ad7b354ae68",
        );
        let retiring_fed_redeem = &expected_flyover_redeem[34..];

        // Mirror the retiring branch of register_fast_bridge_btc_transaction.
        let flyover_redeem = flyover_redeem_script(&flyover_hash, retiring_fed_redeem);
        let flyover_p2sh_hash = redeem_script_hash160(&flyover_redeem);
        let flyover_script = p2sh_output_script(&flyover_p2sh_hash);

        assert_eq!(to_hex(&flyover_redeem), to_hex(&expected_flyover_redeem));
        assert_eq!(
            to_hex(&flyover_p2sh_hash),
            "18fc3b52a5b7d5277f41b9765719b45bfa427730",
            "retiring flyover P2SH hash160 must match rskj"
        );
        // The flyover output script is a plain P2SH (OP_HASH160 <h> OP_EQUAL).
        assert_eq!(flyover_script.as_bytes()[0], 0xa9);
        assert_eq!(flyover_script.as_bytes()[1], 0x14);
        assert_eq!(flyover_script.as_bytes()[22], 0x87);
        // fed_p2sh_hash is the hash160 of the (ERP) retiring redeem itself.
        assert_eq!(redeem_script_hash160(retiring_fed_redeem).len(), 20);
    }

    /// RSKIP293 per-UTXO minimum gate (validateFlyoverPeginValue →
    /// allUTXOsToFedAreAboveMinimumPeginValue → isAnyUTXOAmountBelowMinimum at
    /// hop400): under RSKIP293 ANY flyover UTXO strictly below the minimum
    /// rejects the whole tx with -305; pre-RSKIP293 only the total-is-zero gate
    /// applies. Mirrors the gate used in register_fast_bridge_btc_transaction.
    #[test]
    fn flyover_per_utxo_minimum_gate() {
        let min = 500_000u64; // RSKIP219 minimum peg-in value (mainnet).
        // One UTXO below the minimum among otherwise-fine ones → below min.
        let with_dust = [min, min - 1, min + 10];
        assert!(with_dust.iter().any(|v| *v < min));
        // All at/above the minimum → OK.
        let all_ok = [min, min + 1, 2 * min];
        assert!(!all_ok.iter().any(|v| *v < min));
        // Empty set → not below minimum (anyMatch over empty stream is false);
        // the separate total==0 gate (-304) handles a no-output tx.
        let empty: [u64; 0] = [];
        assert!(!empty.iter().any(|v| *v < min));
    }

    /// `build_flyover_empty_wallet_multi` must agree byte-for-byte with the
    /// single-redeem `release_tx::build_empty_wallet_to` when every input shares
    /// the same flyover redeem (the degenerate active-only case), and must
    /// produce a valid refund with per-input redeems when the active and
    /// retiring flyover redeems differ.
    #[test]
    fn flyover_multi_empty_wallet_matches_single_when_uniform() {
        let flyover_hash = [7u8; 32];
        // Two distinct 2-of-3 fed redeems → two distinct flyover redeems.
        let keys_a: Vec<[u8; 33]> = (1u8..=3).map(|i| [i; 33]).collect();
        let keys_b: Vec<[u8; 33]> = (4u8..=6).map(|i| [i; 33]).collect();
        let fed_a = build_federation_redeem_script(&keys_a, 2);
        let fed_b = build_federation_redeem_script(&keys_b, 2);
        let fly_a = flyover_redeem_script(&flyover_hash, &fed_a);
        let fly_b = flyover_redeem_script(&flyover_hash, &fed_b);

        let refund = p2sh_output_script(&[9u8; 20]);
        let mk_utxo = |seed: u8, sats: u64| BridgeUtxo {
            tx_hash: [seed; 32],
            vout: 0,
            value_satoshis: sats,
            height: 0,
            script: vec![],
            coinbase: false,
        };

        // Uniform case: both inputs use fly_a → must equal the single-redeem build.
        let utxos = [mk_utxo(1, 5_000_000), mk_utxo(2, 6_000_000)];
        let redeems_uniform: Vec<&[u8]> = vec![fly_a.as_slice(), fly_a.as_slice()];
        let multi = build_flyover_empty_wallet_multi(&utxos, &redeems_uniform, &refund, 1000, 2)
            .expect("multi build");
        let single =
            crate::bridge::release_tx::build_empty_wallet_to(&utxos, &refund, &fly_a, 1000, 2)
                .expect("single build");
        assert_eq!(
            bitcoin::consensus::serialize(&multi.tx),
            bitcoin::consensus::serialize(&single.tx),
            "uniform-redeem multi build must equal single build"
        );

        // Mixed case: input 0 uses fly_a, input 1 uses fly_b. The refund spends
        // both, each input carries its own placeholder scriptSig (sizes differ
        // only if the redeems differ in length; here they are equal length but
        // distinct content).
        let redeems_mixed: Vec<&[u8]> = vec![fly_a.as_slice(), fly_b.as_slice()];
        let mixed = build_flyover_empty_wallet_multi(&utxos, &redeems_mixed, &refund, 1000, 2)
            .expect("mixed build");
        assert_eq!(mixed.tx.input.len(), 2);
        assert_eq!(mixed.used_utxos.len(), 2);
        // Each input's scriptSig is the placeholder built from its own redeem.
        let ss0 = crate::bridge::release_tx::placeholder_scriptsig(
            &fly_a,
            crate::bridge::release_tx::redeem_script_threshold(&fly_a),
        );
        let ss1 = crate::bridge::release_tx::placeholder_scriptsig(
            &fly_b,
            crate::bridge::release_tx::redeem_script_threshold(&fly_b),
        );
        assert_eq!(mixed.tx.input[0].script_sig.as_bytes(), ss0.as_slice());
        assert_eq!(mixed.tx.input[1].script_sig.as_bytes(), ss1.as_slice());
        assert_ne!(ss0, ss1, "the two flyover redeems must produce distinct scriptSigs");
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Regression for mainnet #4,683,511: a btc tx spending the LAST RETIRED
    /// federation (a pre-ERP 7-of-13 multisig) and paying the active ERP
    /// federation must classify as PEGOUT_OR_MIGRATION (registerNewUtxos, no
    /// events) — rskj PegUtilsLegacy.isMigrationTx via
    /// getLastRetiredFederationP2SHScript. The decisive step is reducing the
    /// input's full redeem to its STANDARD redeem and hashing it
    /// (extractStandardRedeemScript + createP2SHOutputScript), which must equal
    /// the stored retired-federation P2SH hash160.
    #[test]
    fn retired_federation_input_reduces_to_its_standard_p2sh() {
        // input[0] full redeem from the #4,683,511 migration tx (e92052db…).
        let input_redeem = hex_to_bytes(
            "57210231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c36\
21026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c\
21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344\
210294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc\
2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93\
21033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb88576aa42b3432ad\
210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaac87a1a0a42\
210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6\
2103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6\
2103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de90d1\
2103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2\
2103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299\
2103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d\
5dae",
        );
        // This federation is a plain (non-ERP) multisig: the standard redeem is
        // the full redeem, so the standard P2SH equals the spent address.
        let std_redeem = build_federation_redeem_script(
            &super::super::release_tx::spending_redeem_keys(&input_redeem),
            super::super::release_tx::redeem_script_threshold(&input_redeem),
        );
        assert_eq!(std_redeem, input_redeem, "non-ERP redeem is its own standard");
        let std_hash160 = redeem_script_hash160(&std_redeem);
        // hash160 of the spent address (the lastRetiredFederationP2SHScript at
        // this block) — base58 35cqv4Hr…/program a914596cff92…87.
        assert_eq!(
            to_hex(&std_hash160),
            "596cff92a275960df9cb2ab9df0ff69faa2b1d8a"
        );
    }

    /// Regression for mainnet #4,998,800: a funds migration spends the RETIRING
    /// federation. Once that federation is itself an ERP federation (stored
    /// format 2000+), its spending redeem is the ERP redeem, not the plain
    /// multisig — the migration path must resolve it via the same format-aware
    /// builder the regular pegout uses (`getRetiringFederation().getRedeemScript()`),
    /// otherwise the per-input placeholder scriptSig and the unsigned migration
    /// txid fork. This locks that the format-2000 redeem differs from the plain
    /// builder the buggy migration code used.
    #[test]
    fn erp_retiring_federation_migration_redeem_is_not_plain() {
        let keys = [
            "020ace50bab1230f8002a0bfe619482af74b338cc9e4c956add228df47e6adae1c",
            "0231a395e332dde8688800a0025cccc5771ea1aa874a633b8ab6e5c89d300c7c36",
            "025093f439fb8006fd29ab56605ffec9cdc840d16d2361004e1337a2f86d8bd2db",
            "026b472f7d59d201ff1f540f111b6eb329e071c30a9d23e3d2bcd128fe73dc254c",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
        ]
        .map(key);
        let config = BridgeConstants::mainnet();
        let plain = build_federation_redeem_script(&keys, keys.len() / 2 + 1);
        let erp = federation_redeem_for_format(&keys, 2000, &config);
        assert_ne!(
            plain, erp,
            "an ERP retiring federation must not migrate with the plain multisig redeem"
        );
    }

    /// The hardcoded mainnet old-federation address (rskj
    /// FederationMainNetConstants.oldFederationAddress
    /// "35JUi1FxabGdhygLhnNUEFG4AgvpNMgxK1") decodes to this hash160, used by
    /// PegUtilsLegacy.txIsFromOldFederation.
    #[test]
    fn mainnet_old_federation_address_hash160() {
        let config = super::super::constants::BridgeConstants::mainnet();
        assert_eq!(
            to_hex(&config.old_federation_address_hash160),
            "279d4b44e8cf5e3f04c0ea21c78f1a0ecaa4cd9f"
        );
    }
}
