//! Byte-exact replica of bitcoinj-thin's `Wallet.completeTx` and P2SH
//! multisig scriptSig handling, as used by rskj's `ReleaseTransactionBuilder`
//! and `BridgeSupport.addSignature`/`processSigning`.
//!
//! The unsigned peg-out transaction produced here is stored in Bridge storage
//! and its txid is embedded in bridge events (`add_signature_topic`,
//! `release_btc_topic`), so every byte must match bitcoinj-thin
//! (v0.14.4-rsk-18) exactly:
//!
//! - Coin selection: `RskAllowUnconfirmedCoinSelector` — candidates sorted by
//!   parent tx hash (interpreted as a big-endian integer over bitcoinj's
//!   stored/display byte order) then output index, selected greedily until
//!   the target is reached.
//! - Fee: `recipientsPayFees = true` loop — the fee is subtracted equally
//!   from the recipient outputs (the first also pays the remainder), the
//!   selection target stays at the original total.
//! - Dust: `minNonDustValue = 3 * 5000 * (serializedOutputLen + 148) / 1000`.
//!   Dusty recipient outputs abort the build; a dusty change output is raised
//!   to the minimum, deducting the difference from the first recipient.
//! - scriptSigs: `MissingSigsMode.USE_OP_ZERO` placeholders,
//!   `OP_0 <OP_0 x threshold> <redeemScript>` per input.
//! - Size: fee sizing uses the empty-scriptSig serialization plus
//!   `threshold * SIG_SIZE(75) + redeemScript.len()` per input; the final
//!   placeholder-filled tx must not exceed `MAX_STANDARD_TX_SIZE` (100k).

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction as BtcTransaction, TxIn, TxOut, Txid,
    Witness,
};

use super::storage::BridgeUtxo;

/// bitcoinj `Script.SIG_SIZE`: maximum DER signature size used for fee sizing.
const SIG_SIZE: usize = 75;
/// bitcoinj `BtcTransaction.REFERENCE_DEFAULT_MIN_TX_FEE` (satoshis/kB).
const REFERENCE_DEFAULT_MIN_TX_FEE: u64 = 5000;
/// bitcoinj `BtcTransaction.MAX_STANDARD_TX_SIZE`.
const MAX_STANDARD_TX_SIZE: usize = 100_000;

/// A recipient output for a peg-out transaction.
pub struct PegoutOutput {
    pub script: ScriptBuf,
    pub amount_satoshis: u64,
}

/// A successfully built peg-out transaction plus the UTXOs it spends.
pub struct BuiltPegout {
    pub tx: BtcTransaction,
    pub used_utxos: Vec<BridgeUtxo>,
}

/// bitcoinj `TransactionOutput.getMinNonDustValue()`: 3 * minTxFee(5000) per
/// kB over the serialized output size plus 148 bytes of spending input.
pub fn min_non_dust_value(script: &ScriptBuf) -> u64 {
    let serialized_len = 8 + varint_len(script.len()) + script.len();
    (serialized_len as u64 + 148) * 3 * REFERENCE_DEFAULT_MIN_TX_FEE / 1000
}

fn varint_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    }
}

/// Build the placeholder scriptSig bitcoinj produces for an unsigned P2SH
/// multisig input: `OP_0 <OP_0 x threshold> <redeemScript push>`.
pub fn placeholder_scriptsig(redeem_script: &[u8], threshold: usize) -> Vec<u8> {
    let mut script = Vec::with_capacity(2 + threshold + redeem_script.len() + 3);
    script.push(0x00); // OP_0 (CHECKMULTISIG bug workaround)
    for _ in 0..threshold {
        script.push(0x00); // empty signature placeholder == OP_0
    }
    push_data(&mut script, redeem_script);
    script
}

/// Append a minimal data push to a script (bitcoinj `ScriptBuilder.data`).
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(0x00); // OP_0
    } else if len <= 0x4b {
        script.push(len as u8);
    } else if len <= 0xff {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
    } else {
        script.push(0x4d); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
    }
    if len > 0 {
        script.extend_from_slice(data);
    }
}

/// Number of signatures required by an `OP_m ... OP_n OP_CHECKMULTISIG`
/// redeem script (bitcoinj `Script.getNumberOfSignaturesRequiredToSpend`).
pub fn redeem_script_threshold(redeem_script: &[u8]) -> usize {
    match redeem_script.first() {
        Some(op) if (0x51..=0x60).contains(op) => (op - 0x50) as usize,
        _ => 0,
    }
}

/// Replica of `Wallet.completeTx` for the bridge peg-out path
/// (`recipientsPayFees = true`, `shuffleOutputs = false`, legacy P2SH
/// multisig federation, `ensureMinRequiredFee = true`).
///
/// `available_utxos` is the federation UTXO list in storage order;
/// `change_script` is the federation P2SH output script. Returns `None` on
/// any of bitcoinj's build failures (dusty send, insufficient money, could
/// not adjust downwards, exceeded max size).
pub fn complete_pegout_tx(
    available_utxos: &[BridgeUtxo],
    outputs: &[PegoutOutput],
    change_script: &ScriptBuf,
    redeem_script: &[u8],
    fee_per_kb: u64,
    version: i32,
) -> Option<BuiltPegout> {
    if outputs.is_empty() {
        return None;
    }
    let threshold = redeem_script_threshold(redeem_script);
    if threshold == 0 {
        return None;
    }

    // completeTx: dusty sends are rejected up front (DustySendRequested).
    for output in outputs {
        if output.amount_satoshis < min_non_dust_value(&output.script) {
            return None;
        }
    }

    // RskAllowUnconfirmedCoinSelector: sort candidates by parent tx hash
    // (BigInteger over bitcoinj's stored byte order) then output index.
    let mut candidates: Vec<&BridgeUtxo> = available_utxos.iter().collect();
    candidates.sort_by(|a, b| a.tx_hash.cmp(&b.tx_hash).then(a.vout.cmp(&b.vout)));

    let value: u64 = outputs.iter().map(|o| o.amount_satoshis).sum();
    let n_outputs = outputs.len() as u64;

    // calculateFee loop: fee starts at zero and grows until it covers the
    // size-based requirement. recipientsPayFees keeps the selection target at
    // the original total.
    let mut fee: u64 = 0;
    loop {
        // Recipient outputs minus the current fee, split equally; the first
        // recipient also pays the remainder (CouldNotAdjustDownwards when an
        // output falls below its non-dust minimum).
        let mut out_values: Vec<u64> = Vec::with_capacity(outputs.len());
        for (i, output) in outputs.iter().enumerate() {
            let mut v = output.amount_satoshis as i128 - (fee / n_outputs) as i128;
            if i == 0 {
                v -= (fee % n_outputs) as i128;
            }
            if v < min_non_dust_value(&output.script) as i128 {
                return None;
            }
            out_values.push(v as u64);
        }

        // Greedy selection until the target is gathered (InsufficientMoney
        // when the candidates cannot cover it).
        let mut gathered: u64 = 0;
        let mut selected: Vec<&BridgeUtxo> = Vec::new();
        for utxo in &candidates {
            if gathered >= value {
                break;
            }
            selected.push(utxo);
            gathered += utxo.value_satoshis;
        }
        if gathered < value {
            return None;
        }

        let mut tx_outputs: Vec<TxOut> = outputs
            .iter()
            .zip(&out_values)
            .map(|(o, v)| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: o.script.clone(),
            })
            .collect();

        let mut change = gathered - value;
        if change > 0 {
            let min_change = min_non_dust_value(change_script);
            if change < min_change {
                // recipientsPayFees: raise dusty change to the minimum and
                // deduct the difference from the first recipient.
                let missing = min_change - change;
                let first = tx_outputs[0].value.to_sat() as i128 - missing as i128;
                if first < 0 || (first as u64) < min_non_dust_value(&outputs[0].script) {
                    return None;
                }
                tx_outputs[0].value = Amount::from_sat(first as u64);
                change = min_change;
            }
            tx_outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_script.clone(),
            });
        }

        let inputs: Vec<TxIn> = selected
            .iter()
            .map(|u| TxIn {
                previous_output: OutPoint {
                    txid: txid_from_stored_hash(&u.tx_hash),
                    vout: u.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect();

        let mut tx = BtcTransaction {
            version: Version(version),
            lock_time: LockTime::ZERO,
            input: inputs,
            output: tx_outputs,
        };

        // calculateTxSize: empty-scriptSig serialization plus the estimated
        // signing bytes per P2SH input.
        let base_size = bitcoin::consensus::serialize(&tx).len();
        let size = base_size + selected.len() * (threshold * SIG_SIZE + redeem_script.len());

        let fee_rate = fee_per_kb.max(REFERENCE_DEFAULT_MIN_TX_FEE);
        let fee_needed = fee_rate * size as u64 / 1000;

        if fee >= fee_needed {
            // Done: fill in the USE_OP_ZERO placeholder scriptSigs.
            let scriptsig = placeholder_scriptsig(redeem_script, threshold);
            for input in &mut tx.input {
                input.script_sig = ScriptBuf::from_bytes(scriptsig.clone());
            }
            if bitcoin::consensus::serialize(&tx).len() > MAX_STANDARD_TX_SIZE {
                return None;
            }
            let used_utxos = selected.into_iter().cloned().collect();
            return Some(BuiltPegout { tx, used_utxos });
        }
        fee = fee_needed;
    }
}

/// Convert a stored UTXO hash (bitcoinj display/stored byte order) into a
/// rust-bitcoin `Txid` (internal byte order).
fn txid_from_stored_hash(stored: &[u8; 32]) -> Txid {
    use bitcoin::hashes::Hash;
    let mut internal = *stored;
    internal.reverse();
    Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(internal))
}

// ---------------------------------------------------------------------------
// Script chunk handling (bitcoinj Script/ScriptBuilder replicas)
// ---------------------------------------------------------------------------

/// A parsed script chunk: OP_0, a data push, or any other opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    OpZero,
    Data(Vec<u8>),
    Op(u8),
}

/// Parse a script into chunks. Returns `None` on a malformed push.
pub fn parse_chunks(script: &[u8]) -> Option<Vec<Chunk>> {
    let mut chunks = Vec::new();
    let mut pos = 0;
    while pos < script.len() {
        let opcode = script[pos];
        pos += 1;
        match opcode {
            0x00 => chunks.push(Chunk::OpZero),
            1..=0x4b => {
                let len = opcode as usize;
                if pos + len > script.len() {
                    return None;
                }
                chunks.push(Chunk::Data(script[pos..pos + len].to_vec()));
                pos += len;
            }
            0x4c => {
                let len = *script.get(pos)? as usize;
                pos += 1;
                if pos + len > script.len() {
                    return None;
                }
                chunks.push(Chunk::Data(script[pos..pos + len].to_vec()));
                pos += len;
            }
            0x4d => {
                if pos + 2 > script.len() {
                    return None;
                }
                let len = u16::from_le_bytes([script[pos], script[pos + 1]]) as usize;
                pos += 2;
                if pos + len > script.len() {
                    return None;
                }
                chunks.push(Chunk::Data(script[pos..pos + len].to_vec()));
                pos += len;
            }
            other => chunks.push(Chunk::Op(other)),
        }
    }
    Some(chunks)
}

/// Serialize chunks back into script bytes with minimal pushes.
pub fn chunks_to_script(chunks: &[Chunk]) -> Vec<u8> {
    let mut script = Vec::new();
    for chunk in chunks {
        match chunk {
            Chunk::OpZero => script.push(0x00),
            Chunk::Data(d) => push_data(&mut script, d),
            Chunk::Op(op) => script.push(*op),
        }
    }
    script
}

/// Extract the redeem script (last data chunk) from a P2SH input scriptSig.
pub fn extract_redeem_script(script_sig: &[u8]) -> Option<Vec<u8>> {
    match parse_chunks(script_sig)?.last()? {
        Chunk::Data(d) => Some(d.clone()),
        _ => None,
    }
}

/// Parse the compressed public keys out of an `OP_m <keys> OP_n
/// OP_CHECKMULTISIG` redeem script.
pub fn redeem_script_keys(redeem_script: &[u8]) -> Vec<[u8; 33]> {
    let Some(chunks) = parse_chunks(redeem_script) else {
        return Vec::new();
    };
    chunks
        .into_iter()
        .filter_map(|c| match c {
            Chunk::Data(d) if d.len() == 33 => d.try_into().ok(),
            _ => None,
        })
        .collect()
}

/// bitcoinj `ScriptBuilder.updateScriptWithSignature` with `sigsPrefixCount =
/// 1` and `sigsSuffixCount = 1`: insert `signature` at `target_index` among
/// the signature slots, consuming one OP_0 placeholder. Returns `None` when
/// the scriptSig has no remaining placeholder (bitcoinj throws).
pub fn update_script_with_signature(
    script_sig: &[u8],
    signature: &[u8],
    target_index: usize,
) -> Option<Vec<u8>> {
    let chunks = parse_chunks(script_sig)?;
    let total = chunks.len();
    if total < 3 {
        return None;
    }
    // The chunk in the last signature slot must still be a placeholder.
    if chunks[total - 2] != Chunk::OpZero {
        return None;
    }

    let mut result = Vec::with_capacity(total);
    result.push(chunks[0].clone()); // prefix OP_0

    let middle = &chunks[1..total - 1];
    let mut pos = 0;
    for chunk in middle {
        if pos == target_index {
            result.push(Chunk::Data(signature.to_vec()));
            pos += 1;
        }
        if *chunk != Chunk::OpZero {
            result.push(chunk.clone());
            pos += 1;
        }
    }
    while pos < middle.len() {
        if pos == target_index {
            result.push(Chunk::Data(signature.to_vec()));
        } else {
            result.push(Chunk::OpZero);
        }
        pos += 1;
    }

    result.push(chunks[total - 1].clone()); // suffix: redeem script
    Some(chunks_to_script(&result))
}

/// bitcoinj `Script.getSigInsertionIndex`: position for this federator's
/// signature among the existing ones, ordered by key index in the redeem
/// script.
pub fn sig_insertion_index(
    script_sig: &[u8],
    sighash: &[u8; 32],
    signing_key: &[u8; 33],
    redeem_script: &[u8],
) -> usize {
    let keys = redeem_script_keys(redeem_script);
    let my_index = keys
        .iter()
        .position(|k| k == signing_key)
        .unwrap_or(usize::MAX);
    let Some(chunks) = parse_chunks(script_sig) else {
        return 0;
    };
    if chunks.len() < 2 {
        return 0;
    }

    let mut sig_index = 0;
    for chunk in &chunks[1..chunks.len() - 1] {
        if let Chunk::Data(sig) = chunk {
            let sig_key_index = find_sig_key_index(sig, sighash, &keys);
            if my_index < sig_key_index {
                return sig_index;
            }
            sig_index += 1;
        }
    }
    sig_index
}

/// bitcoinj `Script.findSigInRedeem`: index of the redeem-script key that
/// verifies this encoded signature (DER + sighash byte) for `sighash`.
fn find_sig_key_index(sig_with_hashtype: &[u8], sighash: &[u8; 32], keys: &[[u8; 33]]) -> usize {
    if sig_with_hashtype.len() < 2 {
        return keys.len();
    }
    let der = &sig_with_hashtype[..sig_with_hashtype.len() - 1];
    keys.iter()
        .position(|k| verify_der_signature(der, sighash, k))
        .unwrap_or(keys.len())
}

/// Verify a DER-encoded ECDSA signature over a 32-byte message hash against a
/// compressed secp256k1 public key. High-S signatures are accepted, matching
/// bitcoinj's `ECKey.verify`.
pub fn verify_der_signature(der: &[u8], msg32: &[u8; 32], pubkey: &[u8; 33]) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{Signature, VerifyingKey};

    let Ok(key) = VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let Ok(mut sig) = Signature::from_der(der) else {
        return false;
    };
    if let Some(normalized) = sig.normalize_s() {
        sig = normalized;
    }
    key.verify_prehash(msg32, &sig).is_ok()
}

/// Legacy (pre-segwit) BIP-143-less signature hash with the redeem script as
/// the script code, SIGHASH_ALL.
pub fn legacy_sighash_all(tx: &BtcTransaction, input_index: usize, redeem_script: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::Hash;
    let cache = bitcoin::sighash::SighashCache::new(tx);
    let script = ScriptBuf::from_bytes(redeem_script.to_vec());
    let hash = cache
        .legacy_signature_hash(input_index, &script, bitcoin::EcdsaSighashType::All as u32)
        .expect("legacy sighash never fails for valid input index");
    hash.to_byte_array()
}

/// bitcoinj `BridgeUtils.hasEnoughSignatures`: every input's scriptSig has no
/// OP_0 placeholder left in its signature slots.
pub fn has_enough_signatures(tx: &BtcTransaction) -> bool {
    for input in &tx.input {
        let Some(chunks) = parse_chunks(input.script_sig.as_bytes()) else {
            return false;
        };
        if chunks.len() < 3 {
            return false;
        }
        if chunks[1..chunks.len() - 1]
            .iter()
            .any(|c| *c == Chunk::OpZero)
        {
            return false;
        }
    }
    !tx.input.is_empty()
}

/// rskj `BridgeUtils.isInputSignedByThisFederator`: one of the input's
/// signature chunks verifies against this federator's key.
pub fn input_signed_by(
    tx: &BtcTransaction,
    input_index: usize,
    pubkey: &[u8; 33],
    sighash: &[u8; 32],
) -> bool {
    let Some(chunks) = parse_chunks(tx.input[input_index].script_sig.as_bytes()) else {
        return false;
    };
    if chunks.len() < 3 {
        return false;
    }
    chunks[1..chunks.len() - 1].iter().any(|c| match c {
        Chunk::Data(sig) if sig.len() > 1 => {
            verify_der_signature(&sig[..sig.len() - 1], sighash, pubkey)
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utxo(hash_byte: u8, vout: u32, value: u64) -> BridgeUtxo {
        BridgeUtxo {
            tx_hash: [hash_byte; 32],
            vout,
            value_satoshis: value,
            height: 0,
            script: vec![],
            coinbase: false,
        }
    }

    fn p2pkh(script_byte: u8) -> ScriptBuf {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[script_byte; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        ScriptBuf::from_bytes(s)
    }

    fn p2sh(script_byte: u8) -> ScriptBuf {
        let mut s = vec![0xa9, 0x14];
        s.extend_from_slice(&[script_byte; 20]);
        s.push(0x87);
        ScriptBuf::from_bytes(s)
    }

    fn test_redeem(threshold: usize, n: usize) -> Vec<u8> {
        // Deterministic distinct compressed keys (not on curve; fine for
        // structure-only tests).
        let mut script = vec![0x50 + threshold as u8];
        for i in 0..n {
            script.push(33);
            let mut key = [0x02u8; 33];
            key[32] = i as u8;
            script.extend_from_slice(&key);
        }
        script.push(0x50 + n as u8);
        script.push(0xae);
        script
    }

    #[test]
    fn min_non_dust_matches_bitcoinj() {
        // P2PKH output: 34 serialized bytes -> (34+148)*15 = 2730 satoshis.
        assert_eq!(min_non_dust_value(&p2pkh(1)), 2730);
        // P2SH output: 32 serialized bytes -> (32+148)*15 = 2700 satoshis.
        assert_eq!(min_non_dust_value(&p2sh(1)), 2700);
    }

    #[test]
    fn placeholder_scriptsig_layout() {
        let redeem = test_redeem(2, 3);
        let script = placeholder_scriptsig(&redeem, 2);
        // OP_0 + 2 placeholder OP_0s + PUSHDATA1 push of the 105-byte redeem
        assert_eq!(script[0], 0x00);
        assert_eq!(script[1], 0x00);
        assert_eq!(script[2], 0x00);
        assert_eq!(script[3], 0x4c); // OP_PUSHDATA1 (redeem > 75 bytes)
        assert_eq!(script[4] as usize, redeem.len());
        assert_eq!(&script[5..], &redeem[..]);
    }

    #[test]
    fn selector_sorts_by_hash_then_index() {
        let utxos = vec![utxo(9, 0, 50_000), utxo(1, 1, 50_000), utxo(1, 0, 50_000)];
        let redeem = test_redeem(2, 3);
        let built = complete_pegout_tx(
            &utxos,
            &[PegoutOutput { script: p2pkh(7), amount_satoshis: 60_000 }],
            &p2sh(8),
            &redeem,
            5000,
            1,
        )
        .expect("build");
        // Selection order: hash 01 vout 0, hash 01 vout 1 (covers 100k > 60k).
        assert_eq!(built.used_utxos.len(), 2);
        assert_eq!(built.used_utxos[0].tx_hash, [1u8; 32]);
        assert_eq!(built.used_utxos[0].vout, 0);
        assert_eq!(built.used_utxos[1].vout, 1);
        assert_eq!(built.tx.version.0, 1);
    }

    #[test]
    fn recipients_pay_fees_and_change_is_added() {
        let utxos = vec![utxo(1, 0, 1_000_000)];
        let redeem = test_redeem(2, 3);
        let built = complete_pegout_tx(
            &utxos,
            &[PegoutOutput { script: p2pkh(7), amount_satoshis: 200_000 }],
            &p2sh(8),
            &redeem,
            5000,
            1,
        )
        .expect("build");
        let tx = &built.tx;
        assert_eq!(tx.output.len(), 2);
        let recipient = tx.output[0].value.to_sat();
        let change = tx.output[1].value.to_sat();
        let fee = 1_000_000 - recipient - change;
        // Recipient pays the fee: output reduced below the requested amount;
        // change matches the full surplus.
        assert!(recipient < 200_000);
        assert_eq!(fee, 200_000 - recipient);
        assert_eq!(change, 800_000);
        // Fee covers the size-based requirement at 5000 sat/kB.
        let threshold = 2;
        let size_estimate = {
            let mut unsigned = tx.clone();
            for input in &mut unsigned.input {
                input.script_sig = ScriptBuf::new();
            }
            bitcoin::consensus::serialize(&unsigned).len()
                + tx.input.len() * (threshold * SIG_SIZE + redeem.len())
        };
        assert_eq!(fee, 5000 * size_estimate as u64 / 1000);
        // Placeholder scriptSig on the input.
        assert_eq!(
            tx.input[0].script_sig.as_bytes(),
            placeholder_scriptsig(&redeem, threshold).as_slice()
        );
    }

    #[test]
    fn dusty_request_rejected() {
        let utxos = vec![utxo(1, 0, 1_000_000)];
        let redeem = test_redeem(2, 3);
        assert!(complete_pegout_tx(
            &utxos,
            &[PegoutOutput { script: p2pkh(7), amount_satoshis: 2_729 }],
            &p2sh(8),
            &redeem,
            5000,
            1,
        )
        .is_none());
    }

    #[test]
    fn insufficient_money_rejected() {
        let utxos = vec![utxo(1, 0, 10_000)];
        let redeem = test_redeem(2, 3);
        assert!(complete_pegout_tx(
            &utxos,
            &[PegoutOutput { script: p2pkh(7), amount_satoshis: 20_000 }],
            &p2sh(8),
            &redeem,
            5000,
            1,
        )
        .is_none());
    }

    #[test]
    fn dusty_change_raised_from_first_recipient() {
        // Gathered 103_000 vs target 100_000 leaves change 3_000 > 0 but
        // under the 2_700 P2SH minimum? 3_000 >= 2_700, so use 102_000:
        // change 2_000 < 2_700 -> raised to 2_700, recipient pays 700 extra.
        let utxos = vec![utxo(1, 0, 102_000)];
        let redeem = test_redeem(2, 3);
        let built = complete_pegout_tx(
            &utxos,
            &[PegoutOutput { script: p2pkh(7), amount_satoshis: 100_000 }],
            &p2sh(8),
            &redeem,
            5000,
            1,
        )
        .expect("build");
        let tx = &built.tx;
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[1].value.to_sat(), 2700);
    }

    #[test]
    fn update_script_inserts_and_consumes_placeholder() {
        let redeem = test_redeem(2, 3);
        let script = placeholder_scriptsig(&redeem, 2);
        let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];

        let updated = update_script_with_signature(&script, &sig, 0).expect("insert");
        let chunks = parse_chunks(&updated).unwrap();
        assert_eq!(chunks.len(), 4); // OP_0, sig, OP_0, redeem
        assert_eq!(chunks[0], Chunk::OpZero);
        assert_eq!(chunks[1], Chunk::Data(sig.clone()));
        assert_eq!(chunks[2], Chunk::OpZero);

        // Insert a second signature after the first.
        let sig2 = vec![0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x01];
        let updated2 = update_script_with_signature(&updated, &sig2, 1).expect("insert 2");
        let chunks2 = parse_chunks(&updated2).unwrap();
        assert_eq!(chunks2.len(), 4);
        assert_eq!(chunks2[1], Chunk::Data(sig));
        assert_eq!(chunks2[2], Chunk::Data(sig2));

        // Fully signed: no placeholder left to consume.
        assert!(update_script_with_signature(&updated2, &[0x30], 0).is_none());
    }

    #[test]
    fn signing_roundtrip_with_real_keys() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{Signature, SigningKey};

        // Two real keys, 2-of-2 federation.
        let sk1 = SigningKey::from_bytes(&[1u8; 32].into()).unwrap();
        let sk2 = SigningKey::from_bytes(&[2u8; 32].into()).unwrap();
        let mut keys: Vec<[u8; 33]> = [&sk1, &sk2]
            .iter()
            .map(|sk| {
                sk.verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap()
            })
            .collect();
        keys.sort();
        let mut redeem = vec![0x52];
        for k in &keys {
            redeem.push(33);
            redeem.extend_from_slice(k);
        }
        redeem.extend_from_slice(&[0x52, 0xae]);

        // One-input tx with placeholder scriptSig.
        let mut tx = BtcTransaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: txid_from_stored_hash(&[3u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::from_bytes(placeholder_scriptsig(&redeem, 2)),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: p2pkh(7),
            }],
        };

        let sighash = legacy_sighash_all(&tx, 0, &redeem);

        // Sign with the SECOND key in redeem order first.
        let order = |sk: &SigningKey| -> usize {
            let k: [u8; 33] = sk
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
            keys.iter().position(|x| *x == k).unwrap()
        };
        let (first_sk, second_sk) = if order(&sk1) == 1 { (&sk1, &sk2) } else { (&sk2, &sk1) };

        let sign = |sk: &SigningKey| -> Vec<u8> {
            let sig: Signature = sk.sign_prehash(&sighash).unwrap();
            let sig = sig.normalize_s().unwrap_or(sig);
            let mut bytes = sig.to_der().as_bytes().to_vec();
            bytes.push(0x01); // SIGHASH_ALL
            bytes
        };

        // Key with redeem index 1 signs first -> insertion index 0.
        let key1: [u8; 33] = first_sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let idx = sig_insertion_index(tx.input[0].script_sig.as_bytes(), &sighash, &key1, &redeem);
        assert_eq!(idx, 0);
        let updated =
            update_script_with_signature(tx.input[0].script_sig.as_bytes(), &sign(first_sk), idx)
                .unwrap();
        tx.input[0].script_sig = ScriptBuf::from_bytes(updated);
        assert!(!has_enough_signatures(&tx));
        assert!(input_signed_by(&tx, 0, &key1, &sighash));

        // Key with redeem index 0 signs second -> must insert BEFORE -> 0.
        let key0: [u8; 33] = second_sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        assert!(!input_signed_by(&tx, 0, &key0, &sighash));
        let idx0 = sig_insertion_index(tx.input[0].script_sig.as_bytes(), &sighash, &key0, &redeem);
        assert_eq!(idx0, 0);
        let updated0 =
            update_script_with_signature(tx.input[0].script_sig.as_bytes(), &sign(second_sk), idx0)
                .unwrap();
        tx.input[0].script_sig = ScriptBuf::from_bytes(updated0);
        assert!(has_enough_signatures(&tx));

        // Final scriptSig order matches redeem key order.
        let chunks = parse_chunks(tx.input[0].script_sig.as_bytes()).unwrap();
        assert_eq!(chunks.len(), 4);
        let (Chunk::Data(s0), Chunk::Data(s1)) = (&chunks[1], &chunks[2]) else {
            panic!("expected two signatures");
        };
        assert!(verify_der_signature(&s0[..s0.len() - 1], &sighash, &key0));
        assert!(verify_der_signature(&s1[..s1.len() - 1], &sighash, &key1));
    }
}
