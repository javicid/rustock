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

/// bitcoinj `Script.isErpType` / `RedeemScriptParser.hasErpFormat`: an ERP
/// redeem wraps the standard multisig as `OP_NOTIF <default multisig> OP_ELSE
/// <csv> OP_CSV OP_DROP <emergency multisig> OP_ENDIF`. A flyover redeem may
/// prefix it with `PUSH32 <hash> OP_DROP`. Detect by the first real opcode
/// (after an optional flyover prefix) being OP_NOTIF.
pub fn is_erp_redeem(redeem_script: &[u8]) -> bool {
    let Some(chunks) = parse_chunks(redeem_script) else {
        return false;
    };
    let mut chunks = chunks.as_slice();
    // Skip an optional flyover prefix: Data(32) OP_DROP (0x75).
    if let [Chunk::Data(d), Chunk::Op(0x75), rest @ ..] = chunks {
        if d.len() == 32 {
            chunks = rest;
        }
    }
    matches!(chunks.first(), Some(Chunk::Op(0x64))) // OP_NOTIF
}

/// Build the placeholder scriptSig bitcoinj produces for an unsigned P2SH
/// multisig input: `OP_0 <OP_0 x threshold> <redeemScript push>`. For an ERP
/// redeem, bitcoinj `Script.createEmptyInputScript` inserts an extra `OP_0`
/// before the redeem push — the flag that selects the `OP_NOTIF` (default
/// federation) branch — so the unsigned txid matches.
pub fn placeholder_scriptsig(redeem_script: &[u8], threshold: usize) -> Vec<u8> {
    let mut script = Vec::with_capacity(2 + threshold + redeem_script.len() + 3);
    script.push(0x00); // OP_0 (CHECKMULTISIG bug workaround)
    for _ in 0..threshold {
        script.push(0x00); // empty signature placeholder == OP_0
    }
    if is_erp_redeem(redeem_script) {
        script.push(0x00); // OP_0 selecting the OP_NOTIF default branch
    }
    push_data(&mut script, redeem_script);
    script
}

/// rskj `BitcoinUtils.setSpendingBaseScriptSegwit`: for a P2SH-P2WSH ERP input
/// the scriptSig is the witness-program push (`buildSegwitScriptSig` = push of
/// `OP_0 PUSH32 sha256(redeem)`), and the unsigned base witness
/// (`createBaseWitnessThatSpendsFromErpRedeemScript`) carries the CHECKMULTISIG
/// dummy, `threshold` empty signature placeholders, the OP_NOTIF default-branch
/// flag, then the redeem script.
pub fn segwit_base_input(redeem: &[u8], threshold: usize) -> (ScriptBuf, Witness) {
    use sha2::Digest as _;
    let mut program = vec![0x00, 0x20]; // OP_0 PUSH32
    program.extend_from_slice(&sha2::Sha256::digest(redeem));
    let mut script_sig = Vec::with_capacity(1 + program.len());
    push_data(&mut script_sig, &program);

    let mut witness = Witness::new();
    witness.push([] as [u8; 0]); // OP_0 (CHECKMULTISIG bug workaround)
    for _ in 0..threshold {
        witness.push([] as [u8; 0]); // empty signature placeholder
    }
    witness.push([] as [u8; 0]); // OP_NOTIF default-branch flag
    witness.push(redeem);
    (ScriptBuf::from_bytes(script_sig), witness)
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
///
/// Flyover (`PUSH32 <hash> OP_DROP <fedRedeem>`) and ERP redeem scripts wrap a
/// standard multisig: the `OP_m` we need is the first `OP_1..OP_16` opcode in
/// the script, not necessarily the first byte. bitcoinj resolves the inner
/// multisig the same way when sizing/signing a P2SH spend.
pub fn redeem_script_threshold(redeem_script: &[u8]) -> usize {
    parse_chunks(redeem_script)
        .into_iter()
        .flatten()
        .find_map(|c| match c {
            Chunk::Op(op) if (0x51..=0x60).contains(&op) => Some((op - 0x50) as usize),
            _ => None,
        })
        .unwrap_or(0)
}

/// Replica of `Wallet.completeTx` for the bridge peg-out path
/// (`recipientsPayFees = true`, `shuffleOutputs = false`, legacy P2SH
/// multisig federation, `ensureMinRequiredFee = true`).
///
/// `available_utxos` is the federation UTXO list in storage order;
/// `change_script` is the federation P2SH output script. `redeem_for` returns
/// the redeem script bitcoinj's spend wallet uses for a given UTXO — for a
/// flyover UTXO this is the `PUSH32 <derivationHash> OP_DROP <fedRedeem>`
/// wrapper (34 bytes longer than the plain fed redeem), which changes both the
/// USE_OP_ZERO placeholder scriptSig and the per-input fee-sizing estimate.
/// Returns `None` on any of bitcoinj's build failures (dusty send, insufficient
/// money, could not adjust downwards, exceeded max size).
pub fn complete_pegout_tx<'r, F>(
    available_utxos: &[BridgeUtxo],
    outputs: &[PegoutOutput],
    change_script: &ScriptBuf,
    redeem_for: F,
    fee_per_kb: u64,
    version: i32,
    is_segwit: bool,
) -> Option<BuiltPegout>
where
    F: Fn(&BridgeUtxo) -> &'r [u8],
{
    if outputs.is_empty() {
        return None;
    }

    // completeTx: dusty sends are rejected up front (DustySendRequested).
    for output in outputs {
        if output.amount_satoshis < min_non_dust_value(&output.script) {
            return None;
        }
    }

    // RskAllowUnconfirmedCoinSelector: sort candidates by parent tx hash
    // (BigInteger over bitcoinj's stored byte order) then output index. Each
    // candidate carries the redeem script its input must be signed with.
    let mut candidates: Vec<(&BridgeUtxo, &[u8])> =
        available_utxos.iter().map(|u| (u, redeem_for(u))).collect();
    candidates.sort_by(|a, b| a.0.tx_hash.cmp(&b.0.tx_hash).then(a.0.vout.cmp(&b.0.vout)));
    if candidates.iter().any(|(_, r)| redeem_script_threshold(r) == 0) {
        return None;
    }

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
        let mut selected: Vec<(&BridgeUtxo, &[u8])> = Vec::new();
        for &(utxo, redeem) in &candidates {
            if gathered >= value {
                break;
            }
            selected.push((utxo, redeem));
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
            .map(|(u, _)| TxIn {
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

        // calculateTxSize (bitcoinj Wallet): base size = empty-scriptSig
        // serialization (+36 per input for a segwit-compatible tx), plus the
        // estimated signing bytes per P2SH input (this input's own redeem; a
        // flyover input costs 34 extra bytes). A segwit tx is then weighted:
        // vsize = (baseSize + signing + 3*baseSize) / 4.
        let base_size = bitcoin::consensus::serialize(&tx).len()
            + if is_segwit { selected.len() * 36 } else { 0 };
        let signing: usize = selected
            .iter()
            .map(|(_, r)| redeem_script_threshold(r) * SIG_SIZE + r.len())
            .sum();
        let size = if is_segwit {
            (base_size + signing + 3 * base_size) / 4
        } else {
            base_size + signing
        };

        let fee_rate = fee_per_kb.max(REFERENCE_DEFAULT_MIN_TX_FEE);
        let fee_needed = fee_rate * size as u64 / 1000;

        if fee >= fee_needed {
            // Done: fill the per-input spending scripts. A segwit input carries
            // the witness-program scriptSig + base witness; a legacy input the
            // USE_OP_ZERO placeholder scriptSig (per-input redeem, so a flyover
            // input embeds the flyover redeem).
            for (input, (_, redeem)) in tx.input.iter_mut().zip(&selected) {
                let threshold = redeem_script_threshold(redeem);
                if is_segwit {
                    let (script_sig, witness) = segwit_base_input(redeem, threshold);
                    input.script_sig = script_sig;
                    input.witness = witness;
                } else {
                    input.script_sig = ScriptBuf::from_bytes(placeholder_scriptsig(redeem, threshold));
                }
            }
            if bitcoin::consensus::serialize(&tx).len() > MAX_STANDARD_TX_SIZE {
                return None;
            }
            let used_utxos = selected.into_iter().map(|(u, _)| u.clone()).collect();
            return Some(BuiltPegout { tx, used_utxos });
        }
        fee = fee_needed;
    }
}

/// Replica of `Wallet.completeTx` with `SendRequest.recipientsPayFees = false`
/// (rskj's `ReleaseTransactionBuilder.buildSvpFundTransaction`): the recipient
/// outputs are FIXED and the change output to `change_script` (the active
/// federation) absorbs the size-based fee. Selection target is `value + fee`;
/// the fee grows until it covers the tx size. A dusty change output is dropped
/// into the fee (no change output) — bitcoinj `Wallet.completeTx`.
pub fn complete_recipients_dont_pay_fees_tx<'r, F>(
    available_utxos: &[BridgeUtxo],
    outputs: &[PegoutOutput],
    change_script: &ScriptBuf,
    redeem_for: F,
    fee_per_kb: u64,
    version: i32,
) -> Option<BuiltPegout>
where
    F: Fn(&BridgeUtxo) -> &'r [u8],
{
    if outputs.is_empty() {
        return None;
    }
    // completeTx: dusty sends are rejected up front (DustySendRequested).
    for output in outputs {
        if output.amount_satoshis < min_non_dust_value(&output.script) {
            return None;
        }
    }

    // Same RskAllowUnconfirmedCoinSelector ordering as the pegout path.
    let mut candidates: Vec<(&BridgeUtxo, &[u8])> =
        available_utxos.iter().map(|u| (u, redeem_for(u))).collect();
    candidates.sort_by(|a, b| a.0.tx_hash.cmp(&b.0.tx_hash).then(a.0.vout.cmp(&b.0.vout)));
    if candidates.iter().any(|(_, r)| redeem_script_threshold(r) == 0) {
        return None;
    }

    let value: u64 = outputs.iter().map(|o| o.amount_satoshis).sum();
    let mut fee: u64 = 0;
    loop {
        // recipientsPayFees = false: the selection target carries the fee.
        let target = value + fee;
        let mut gathered: u64 = 0;
        let mut selected: Vec<(&BridgeUtxo, &[u8])> = Vec::new();
        for &(utxo, redeem) in &candidates {
            if gathered >= target {
                break;
            }
            selected.push((utxo, redeem));
            gathered += utxo.value_satoshis;
        }
        if gathered < target {
            return None;
        }

        // Recipient outputs are unchanged; the change output absorbs the fee.
        let mut tx_outputs: Vec<TxOut> = outputs
            .iter()
            .map(|o| TxOut {
                value: Amount::from_sat(o.amount_satoshis),
                script_pubkey: o.script.clone(),
            })
            .collect();
        let change = gathered - target;
        if change > 0 && change >= min_non_dust_value(change_script) {
            tx_outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_script.clone(),
            });
        }
        // (A dusty change is dropped into the fee, leaving no change output.)

        let inputs: Vec<TxIn> = selected
            .iter()
            .map(|(u, _)| TxIn {
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

        let base_size = bitcoin::consensus::serialize(&tx).len();
        let signing: usize = selected
            .iter()
            .map(|(_, r)| redeem_script_threshold(r) * SIG_SIZE + r.len())
            .sum();
        let size = base_size + signing;

        let fee_rate = fee_per_kb.max(REFERENCE_DEFAULT_MIN_TX_FEE);
        let fee_needed = fee_rate * size as u64 / 1000;

        if fee >= fee_needed {
            for (input, (_, redeem)) in tx.input.iter_mut().zip(&selected) {
                let scriptsig = placeholder_scriptsig(redeem, redeem_script_threshold(redeem));
                input.script_sig = ScriptBuf::from_bytes(scriptsig);
            }
            if bitcoin::consensus::serialize(&tx).len() > MAX_STANDARD_TX_SIZE {
                return None;
            }
            let used_utxos = selected.into_iter().map(|(u, _)| u.clone()).collect();
            return Some(BuiltPegout { tx, used_utxos });
        }
        fee = fee_needed;
    }
}

/// Replica of `Wallet.completeTx` with `SendRequest.emptyWallet = true`, as
/// used by rskj's `ReleaseTransactionBuilder.buildEmptyWalletTo` for peg-in
/// rejection refunds: spend ALL the given UTXOs (in provider order — the
/// MAX_MONEY selection skips sorting) into a single output to `refund_script`
/// worth the gathered total minus the size-based fee.
pub fn build_empty_wallet_to(
    utxos: &[BridgeUtxo],
    refund_script: &ScriptBuf,
    redeem_script: &[u8],
    fee_per_kb: u64,
    version: i32,
) -> Option<BuiltPegout> {
    if utxos.is_empty() {
        return None;
    }
    let threshold = redeem_script_threshold(redeem_script);
    if threshold == 0 {
        return None;
    }

    let gathered: u64 = utxos.iter().map(|u| u.value_satoshis).sum();

    let inputs: Vec<TxIn> = utxos
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
        output: vec![TxOut {
            value: Amount::from_sat(gathered),
            script_pubkey: refund_script.clone(),
        }],
    };

    // adjustOutputDownwardsForFee: single pass, fee from the empty-scriptSig
    // size plus the signing estimate; the output must stay above dust.
    let base_size = bitcoin::consensus::serialize(&tx).len();
    let size = base_size + utxos.len() * (threshold * SIG_SIZE + redeem_script.len());
    let fee_rate = fee_per_kb.max(REFERENCE_DEFAULT_MIN_TX_FEE);
    let fee = fee_rate * size as u64 / 1000;
    if fee >= gathered {
        return None;
    }
    let value = gathered - fee;
    if value < min_non_dust_value(refund_script) {
        return None;
    }
    tx.output[0].value = Amount::from_sat(value);

    let scriptsig = placeholder_scriptsig(redeem_script, threshold);
    for input in &mut tx.input {
        input.script_sig = ScriptBuf::from_bytes(scriptsig.clone());
    }
    if bitcoin::consensus::serialize(&tx).len() > MAX_STANDARD_TX_SIZE {
        return None;
    }
    Some(BuiltPegout { tx, used_utxos: utxos.to_vec() })
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

/// Public keys bitcoinj's `RedeemScriptParser.getPubKeys()` exposes for SIGNING
/// a P2SH input. For an ERP redeem a normal (`OP_NOTIF` default-branch) spend
/// uses only the DEFAULT-federation multisig, so the emergency keys after
/// `OP_ELSE` must be excluded; otherwise sig insertion indexes against the wrong
/// key set. For a plain (or flyover-plain) redeem this is every 33-byte push.
pub fn spending_redeem_keys(redeem_script: &[u8]) -> Vec<[u8; 33]> {
    let Some(chunks) = parse_chunks(redeem_script) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for c in &chunks {
        match c {
            Chunk::Op(0x67) => break, // OP_ELSE: emergency keys follow
            Chunk::Data(d) if d.len() == 33 => {
                if let Ok(k) = d.as_slice().try_into() {
                    out.push(k);
                }
            }
            _ => {}
        }
    }
    out
}

/// The redeem script of a P2SH input scriptSig (its last data push), and whether
/// it is ERP-typed. Used to size the trailing chunks bitcoinj reserves
/// (`BridgeUtils.countValuesToSubstract`: redeem only, or `OP_NOTIF` flag +
/// redeem for ERP).
fn input_redeem_is_erp(chunks: &[Chunk]) -> bool {
    chunks
        .iter()
        .rev()
        .find_map(|c| match c {
            Chunk::Data(d) => Some(is_erp_redeem(d)),
            _ => None,
        })
        .unwrap_or(false)
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
    // Trailing chunks bitcoinj reserves: the redeem, plus the ERP OP_NOTIF flag.
    let suffix = if input_redeem_is_erp(&chunks) { 2 } else { 1 };
    if total < 2 + suffix {
        return None;
    }
    // The last signature slot (just before the suffix) must still be a placeholder.
    if chunks[total - 1 - suffix] != Chunk::OpZero {
        return None;
    }

    let mut result = Vec::with_capacity(total + 1);
    result.push(chunks[0].clone()); // prefix OP_0

    let middle = &chunks[1..total - suffix];
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

    result.extend_from_slice(&chunks[total - suffix..]); // suffix: [ERP flag] + redeem
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
    let keys = spending_redeem_keys(redeem_script);
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
    // Skip the trailing redeem (and the ERP OP_NOTIF flag) when scanning sigs.
    let suffix = if input_redeem_is_erp(&chunks) { 2 } else { 1 };
    if chunks.len() < 1 + suffix {
        return 0;
    }

    let mut sig_index = 0;
    for chunk in &chunks[1..chunks.len() - suffix] {
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
        // A segwit (P2SH-P2WSH) input carries its signatures in the witness, not
        // the scriptSig (which is just the witness-program push).
        if !input.witness.is_empty() {
            let pushes: Vec<Vec<u8>> = input.witness.iter().map(|p| p.to_vec()).collect();
            if !witness_input_fully_signed(&pushes) {
                return false;
            }
            continue;
        }
        let Some(chunks) = parse_chunks(input.script_sig.as_bytes()) else {
            return false;
        };
        if chunks.len() < 3 {
            return false;
        }
        // rskj BridgeUtils.countValuesToSubstract: skip the redeem (1), plus the
        // OP_NOTIF flag (1 more) for an ERP redeem, when counting missing sigs.
        let suffix = if input_redeem_is_erp(&chunks) { 2 } else { 1 };
        if chunks.len() < 1 + suffix {
            return false;
        }
        if chunks[1..chunks.len() - suffix]
            .iter()
            .any(|c| *c == Chunk::OpZero)
        {
            return false;
        }
    }
    !tx.input.is_empty()
}

/// Witness equivalent of the per-input check in `has_enough_signatures`: every
/// signature slot (between the CHECKMULTISIG dummy and the ERP OP_NOTIF flag +
/// redeem suffix) is filled.
fn witness_input_fully_signed(pushes: &[Vec<u8>]) -> bool {
    let total = pushes.len();
    if total < 3 {
        return false;
    }
    let suffix = if witness_redeem_is_erp(pushes) { 2 } else { 1 };
    if total < 1 + suffix {
        return false;
    }
    !pushes[1..total - suffix].iter().any(|p| p.is_empty())
}

/// Whether a segwit input's redeem (its last witness push) is ERP-typed.
fn witness_redeem_is_erp(pushes: &[Vec<u8>]) -> bool {
    pushes.last().map(|d| is_erp_redeem(d)).unwrap_or(false)
}

/// BIP-143 (segwit v0) signature hash with the redeem script as the witness
/// script, SIGHASH_ALL — rskj `BtcTransaction.hashForWitnessSignature` /
/// `BitcoinUtils.generateSigHashForSegwitTransactionInput`. `value` is the
/// satoshi value of the output being spent (from `releasesOutpointsValues`).
pub fn segwit_sighash_all(
    tx: &BtcTransaction,
    input_index: usize,
    redeem_script: &[u8],
    value: u64,
) -> [u8; 32] {
    use bitcoin::hashes::Hash;
    let mut cache = bitcoin::sighash::SighashCache::new(tx);
    let script = ScriptBuf::from_bytes(redeem_script.to_vec());
    let hash = cache
        .p2wsh_signature_hash(
            input_index,
            &script,
            bitcoin::Amount::from_sat(value),
            bitcoin::EcdsaSighashType::All,
        )
        .expect("p2wsh sighash never fails for valid input index");
    hash.to_byte_array()
}

/// Witness equivalent of `update_script_with_signature`: insert `signature` at
/// `target_index` among the witness signature slots (an empty push is the OP_0
/// placeholder), reserving the redeem (+ ERP OP_NOTIF flag) suffix. Returns
/// `None` when no placeholder is left (bitcoinj throws).
pub fn witness_update_with_signature(
    pushes: &[Vec<u8>],
    signature: &[u8],
    target_index: usize,
) -> Option<Vec<Vec<u8>>> {
    let total = pushes.len();
    let suffix = if witness_redeem_is_erp(pushes) { 2 } else { 1 };
    if total < 2 + suffix {
        return None;
    }
    if !pushes[total - 1 - suffix].is_empty() {
        return None;
    }
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(total + 1);
    result.push(pushes[0].clone()); // CHECKMULTISIG dummy
    let middle = &pushes[1..total - suffix];
    let mut pos = 0;
    for item in middle {
        if pos == target_index {
            result.push(signature.to_vec());
            pos += 1;
        }
        if !item.is_empty() {
            result.push(item.clone());
            pos += 1;
        }
    }
    while pos < middle.len() {
        if pos == target_index {
            result.push(signature.to_vec());
        } else {
            result.push(Vec::new());
        }
        pos += 1;
    }
    result.extend_from_slice(&pushes[total - suffix..]); // [ERP flag] + redeem
    Some(result)
}

/// Witness equivalent of `sig_insertion_index`.
pub fn witness_sig_insertion_index(
    pushes: &[Vec<u8>],
    sighash: &[u8; 32],
    signing_key: &[u8; 33],
    redeem_script: &[u8],
) -> usize {
    let keys = spending_redeem_keys(redeem_script);
    let my_index = keys.iter().position(|k| k == signing_key).unwrap_or(usize::MAX);
    let total = pushes.len();
    let suffix = if witness_redeem_is_erp(pushes) { 2 } else { 1 };
    if total < 1 + suffix {
        return 0;
    }
    let mut sig_index = 0;
    for item in &pushes[1..total - suffix] {
        if !item.is_empty() {
            let sig_key_index = find_sig_key_index(item, sighash, &keys);
            if my_index < sig_key_index {
                return sig_index;
            }
            sig_index += 1;
        }
    }
    sig_index
}

/// Witness equivalent of `input_signed_by`.
pub fn witness_input_signed_by(
    pushes: &[Vec<u8>],
    pubkey: &[u8; 33],
    sighash: &[u8; 32],
) -> bool {
    let total = pushes.len();
    if total < 3 {
        return false;
    }
    pushes[1..total - 1].iter().any(|sig| {
        sig.len() > 1 && verify_der_signature(&sig[..sig.len() - 1], sighash, pubkey)
    })
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

    /// Ground truth from mainnet #8,117,400 (the first federator signing the
    /// segwit SVP spend tx): inserting one signature into the base ERP witness
    /// [dummy, e×5, flag, redeem] (threshold 5) puts the sig in slot 1 and
    /// leaves the remaining sig slots + the OP_NOTIF flag + redeem suffix.
    #[test]
    fn witness_update_with_signature_erp_first_sig() {
        let redeem = erp_redeem(5, 9);
        let mut pushes: Vec<Vec<u8>> = vec![Vec::new()]; // dummy
        for _ in 0..5 {
            pushes.push(Vec::new()); // empty sig placeholders
        }
        pushes.push(Vec::new()); // OP_NOTIF flag
        pushes.push(redeem.clone());

        let sig = vec![0x30u8, 0x44, 0xAA, 0x01]; // dummy DER-ish + sighash byte
        let updated = witness_update_with_signature(&pushes, &sig, 0).unwrap();
        assert_eq!(updated.len(), 8); // unchanged item count
        assert!(updated[0].is_empty()); // dummy
        assert_eq!(updated[1], sig); // signature in slot 1
        assert!(updated[2..6].iter().all(|p| p.is_empty())); // 4 empty sig slots
        assert!(updated[6].is_empty()); // OP_NOTIF flag
        assert_eq!(updated[7], redeem); // redeem
        assert!(!witness_input_fully_signed(&updated)); // 1/5 signatures
    }

    /// An ERP redeem: `OP_NOTIF <std multisig> OP_ELSE <csv> <emergency
    /// multisig> OP_ENDIF` — enough for `is_erp_redeem` / threshold parsing.
    fn erp_redeem(threshold: usize, n: usize) -> Vec<u8> {
        let mut script = vec![0x64]; // OP_NOTIF
        script.extend_from_slice(&test_redeem(threshold, n));
        script.push(0x67); // OP_ELSE
        script.push(0x68); // OP_ENDIF
        script
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
    fn erp_placeholder_inserts_op0_before_redeem() {
        // Minimal ERP-shaped redeem: OP_NOTIF <m-of-n> OP_ELSE <csv> OP_CSV
        // OP_DROP <m-of-n> OP_ENDIF. Detection only needs the leading OP_NOTIF.
        let inner = test_redeem(2, 3);
        let mut erp = vec![0x64]; // OP_NOTIF
        erp.extend_from_slice(&inner[..inner.len() - 1]); // drop trailing CHECKMULTISIG
        erp.push(0x67); // OP_ELSE
        erp.extend_from_slice(&[0x03, 0x50, 0xcd, 0x00, 0xb2, 0x75]); // push csv, OP_CSV, OP_DROP
        erp.extend_from_slice(&inner[..inner.len() - 1]);
        erp.push(0x68); // OP_ENDIF
        erp.push(0xae); // OP_CHECKMULTISIG

        assert!(is_erp_redeem(&erp));
        assert!(!is_erp_redeem(&test_redeem(2, 3))); // plain multisig

        // Flyover-wrapped ERP and flyover-wrapped plain.
        let mut flyover_erp = vec![0x20];
        flyover_erp.extend_from_slice(&[0xaa; 32]);
        flyover_erp.push(0x75); // OP_DROP
        flyover_erp.extend_from_slice(&erp);
        assert!(is_erp_redeem(&flyover_erp));
        let mut flyover_plain = vec![0x20];
        flyover_plain.extend_from_slice(&[0xbb; 32]);
        flyover_plain.push(0x75);
        flyover_plain.extend_from_slice(&test_redeem(2, 3));
        assert!(!is_erp_redeem(&flyover_plain));

        // ERP placeholder has the extra OP_0 (default-branch flag) before the
        // redeem push: OP_0 + 2 sig placeholders + OP_0(flag) + PUSHDATA2 redeem.
        let erp_ph = placeholder_scriptsig(&erp, 2);
        assert_eq!(&erp_ph[..4], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(erp_ph[4], 0x4c); // OP_PUSHDATA1 (218-byte erp redeem)
        // Plain placeholder has NO extra flag: OP_0 + 2 placeholders + push.
        let plain_ph = placeholder_scriptsig(&test_redeem(2, 3), 2);
        assert_eq!(&plain_ph[..3], &[0x00, 0x00, 0x00]);
        assert_eq!(plain_ph[3], 0x4c); // OP_PUSHDATA1 (105-byte redeem)
    }

    #[test]
    fn erp_signing_ignores_op_notif_flag() {
        // Build a small ERP redeem (default 2-of-3) and its placeholder.
        let inner = test_redeem(2, 3);
        let mut erp = vec![0x64]; // OP_NOTIF
        erp.extend_from_slice(&inner[..inner.len() - 1]);
        erp.push(0x67); // OP_ELSE
        erp.extend_from_slice(&[0x03, 0x50, 0xcd, 0x00, 0xb2, 0x75]);
        erp.extend_from_slice(&inner[..inner.len() - 1]);
        erp.push(0x68); // OP_ENDIF
        erp.push(0xae);
        let ph = placeholder_scriptsig(&erp, 2);

        // A tx whose single input carries the ERP placeholder is NOT fully
        // signed: the trailing OP_NOTIF flag OP_0 must not be counted.
        let mk_tx = |ss: &[u8]| BtcTransaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: txid_from_stored_hash(&[1u8; 32]), vout: 0 },
                script_sig: ScriptBuf::from_bytes(ss.to_vec()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        assert!(!has_enough_signatures(&mk_tx(&ph)));

        // Fill the two real sig slots (inserting before the flag); after both,
        // it is fully signed even though the flag OP_0 remains before the redeem.
        let sig = vec![0x30u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];
        let one = update_script_with_signature(&ph, &sig, 0).expect("first sig");
        assert!(!has_enough_signatures(&mk_tx(&one)));
        let two = update_script_with_signature(&one, &sig, 1).expect("second sig");
        assert!(has_enough_signatures(&mk_tx(&two)));
        // Inserting a third must fail — no placeholder slot left (flag excluded).
        assert!(update_script_with_signature(&two, &sig, 0).is_none());

        // The flag OP_0 is still immediately before the redeem push.
        let chunks = parse_chunks(&two).unwrap();
        assert_eq!(chunks[chunks.len() - 2], Chunk::OpZero);
        assert!(matches!(&chunks[chunks.len() - 1], Chunk::Data(d) if is_erp_redeem(d)));
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
            |_| redeem.as_slice(),
            5000,
            1,
            false,
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
    fn segwit_pegout_uses_witness_inputs_and_smaller_fee() {
        // A P2SH-P2WSH (format ≥ 4000) federation is spent with segwit inputs and
        // a witness-discounted fee. Use an ERP redeem so the base witness has the
        // OP_NOTIF flag (threshold 5 → 8 witness items).
        let redeem = {
            let mut r = vec![0x64u8]; // OP_NOTIF
            r.extend_from_slice(&test_redeem(5, 9));
            r.push(0x67); // OP_ELSE
            r.push(0x68); // OP_ENDIF
            r
        };
        let utxos = vec![utxo(1, 0, 1_000_000)];
        let build = |segwit| {
            complete_pegout_tx(
                &utxos,
                &[PegoutOutput { script: p2pkh(7), amount_satoshis: 200_000 }],
                &p2sh(8),
                |_| redeem.as_slice(),
                100_000,
                2,
                segwit,
            )
            .expect("build")
        };
        let seg = build(true);
        let leg = build(false);

        // Segwit input: scriptSig is the 35-byte witness-program push, the redeem
        // lives in the witness (8 items for threshold 5).
        let sig = seg.tx.input[0].script_sig.as_bytes();
        assert_eq!(sig.len(), 35);
        assert_eq!(&sig[0..3], &[0x22, 0x00, 0x20]);
        assert_eq!(seg.tx.input[0].witness.len(), 8);
        assert_eq!(seg.tx.input[0].witness.iter().last().unwrap(), redeem.as_slice());

        // Witness discount: the segwit fee is strictly smaller, so the recipient
        // keeps more (recipientsPayFees).
        assert!(seg.tx.output[0].value.to_sat() > leg.tx.output[0].value.to_sat());
    }

    #[test]
    fn recipients_pay_fees_and_change_is_added() {
        let utxos = vec![utxo(1, 0, 1_000_000)];
        let redeem = test_redeem(2, 3);
        let built = complete_pegout_tx(
            &utxos,
            &[PegoutOutput { script: p2pkh(7), amount_satoshis: 200_000 }],
            &p2sh(8),
            |_| redeem.as_slice(),
            5000,
            1,
            false,
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
    fn recipients_dont_pay_fees_change_absorbs_fee() {
        // Models the SVP fund tx: two fixed 800k outputs + change to the
        // federation, recipientsPayFees=false. One large UTXO covers it.
        let utxos = vec![utxo(1, 0, 255_336_759_550)];
        let redeem = test_redeem(2, 3);
        let built = complete_recipients_dont_pay_fees_tx(
            &utxos,
            &[
                PegoutOutput { script: p2sh(7), amount_satoshis: 800_000 },
                PegoutOutput { script: p2sh(9), amount_satoshis: 800_000 },
            ],
            &p2sh(8),
            |_| redeem.as_slice(),
            5000,
            2,
        )
        .expect("build");
        let tx = &built.tx;
        assert_eq!(tx.version.0, 2);
        assert_eq!(tx.input.len(), 1);
        // Three outputs: the two FIXED recipients (unchanged) + change.
        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.output[0].value.to_sat(), 800_000);
        assert_eq!(tx.output[1].value.to_sat(), 800_000);
        let change = tx.output[2].value.to_sat();
        let fee = 255_336_759_550 - 1_600_000 - change;
        // The change (not the recipients) carries the size-based fee.
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
    }

    #[test]
    fn dusty_request_rejected() {
        let utxos = vec![utxo(1, 0, 1_000_000)];
        let redeem = test_redeem(2, 3);
        assert!(complete_pegout_tx(
            &utxos,
            &[PegoutOutput { script: p2pkh(7), amount_satoshis: 2_729 }],
            &p2sh(8),
            |_| redeem.as_slice(),
            5000,
            1,
            false,
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
            |_| redeem.as_slice(),
            5000,
            1,
            false,
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
            |_| redeem.as_slice(),
            5000,
            1,
            false,
        )
        .expect("build");
        let tx = &built.tx;
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[1].value.to_sat(), 2700);
    }

    /// A flyover UTXO spends with `PUSH32 <hash> OP_DROP <fedRedeem>` (34 bytes
    /// longer than the plain redeem), which must size its own input and embed
    /// its own placeholder scriptSig — exactly what forked block #4,671,312's
    /// migration tx. Mixing one flyover input with one standard input, the fee
    /// must account for the extra 34 bytes only on the flyover input, and each
    /// input's placeholder scriptSig must carry its own redeem.
    #[test]
    fn flyover_input_sizes_and_signs_with_its_own_redeem() {
        let std_redeem = test_redeem(2, 3);
        let mut flyover_redeem = vec![32u8];
        flyover_redeem.extend_from_slice(&[7u8; 32]); // PUSH32 <derivationHash>
        flyover_redeem.push(0x75); // OP_DROP
        flyover_redeem.extend_from_slice(&std_redeem); // <fedRedeem>
        assert_eq!(flyover_redeem.len(), std_redeem.len() + 34);
        // The inner multisig threshold is still 2.
        assert_eq!(redeem_script_threshold(&flyover_redeem), 2);

        // hash 01 vout 0 = standard input, hash 02 vout 0 = flyover input.
        let utxos = vec![utxo(1, 0, 700_000), utxo(2, 0, 700_000)];
        let redeem_for = |u: &BridgeUtxo| -> &[u8] {
            if u.tx_hash[0] == 2 {
                flyover_redeem.as_slice()
            } else {
                std_redeem.as_slice()
            }
        };
        let built = complete_pegout_tx(
            &utxos,
            &[PegoutOutput { script: p2pkh(7), amount_satoshis: 1_000_000 }],
            &p2sh(8),
            redeem_for,
            5000,
            1,
            false,
        )
        .expect("build");
        let tx = &built.tx;
        assert_eq!(tx.input.len(), 2);

        // Per-input placeholder scriptSigs use each input's own redeem.
        for (input, u) in tx.input.iter().zip(&built.used_utxos) {
            let redeem = redeem_for(u);
            assert_eq!(
                input.script_sig.as_bytes(),
                placeholder_scriptsig(redeem, redeem_script_threshold(redeem)).as_slice()
            );
        }

        // Fee covers base + per-input signing estimate (flyover input +34).
        let recipient = tx.output[0].value.to_sat();
        let change = tx.output[1].value.to_sat();
        let fee = 1_400_000 - recipient - change;
        let size = {
            let mut unsigned = tx.clone();
            for i in &mut unsigned.input {
                i.script_sig = ScriptBuf::new();
            }
            bitcoin::consensus::serialize(&unsigned).len()
                + (2 * SIG_SIZE + std_redeem.len())
                + (2 * SIG_SIZE + flyover_redeem.len())
        };
        assert_eq!(fee, 5000 * size as u64 / 1000);
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

    /// Second mainnet groundtruth: the whitelist-rejected peg-in at RSK
    /// #378,129 (post-RSKIP88) must produce the rejection release whose txid
    /// appears in block #382,134's add_signature events.
    #[test]
    fn mainnet_378129_rejection_release_txid() {
        let pegin_hex = open_pegin_378129();
        let pegin: BtcTransaction =
            bitcoin::consensus::deserialize(&alloy_primitives::hex::decode(pegin_hex).unwrap())
                .unwrap();
        let config = super::super::constants::BridgeConstants::mainnet();
        let keys: Vec<[u8; 33]> = config
            .genesis_federation_public_keys
            .iter()
            .map(|h| alloy_primitives::hex::decode(h).unwrap().try_into().unwrap())
            .collect();
        let redeem = super::super::peg::build_federation_redeem_script(&keys, 8);
        use bitcoin::hashes::Hash as _;
        let h160 = bitcoin::hashes::hash160::Hash::hash(&redeem);
        let mut fed_script = vec![0xa9, 0x14];
        fed_script.extend_from_slice(h160.as_byte_array());
        fed_script.push(0x87);

        let mut txid = *pegin.compute_txid().to_raw_hash().as_byte_array();
        txid.reverse();
        let utxos: Vec<BridgeUtxo> = pegin
            .output
            .iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey.as_bytes() == fed_script.as_slice())
            .map(|(i, o)| BridgeUtxo {
                tx_hash: txid,
                vout: i as u32,
                value_satoshis: o.value.to_sat(),
                height: 0,
                script: o.script_pubkey.to_bytes(),
                coinbase: false,
            })
            .collect();
        assert_eq!(utxos.len(), 1, "one 0.3 BTC federation output");

        let sender_h160 =
            alloy_primitives::hex::decode("6105e0718165a715a644033fea05d12451747ec9").unwrap();
        let mut refund = vec![0x76, 0xa9, 0x14];
        refund.extend_from_slice(&sender_h160);
        refund.extend_from_slice(&[0x88, 0xac]);

        let built = build_empty_wallet_to(
            &utxos,
            &ScriptBuf::from_bytes(refund),
            &redeem,
            500_000,
            1,
        )
        .expect("rejection release builds");
        let mut rid = *built.tx.compute_txid().to_raw_hash().as_byte_array();
        rid.reverse();
        assert_eq!(
            alloy_primitives::hex::encode(rid),
            "3061f2cde3abd19957784734f42ae0744bf4cac1fb82f104920af994f2847a42"
        );
    }

    fn open_pegin_378129() -> &'static str {
        "01000000016d2ddc655238b6f109ecf9c1e7aa6cdd45a4a68f638e8540111194620a24e2ae010000006a473044022078a581ac84297ea831d6a04bab9d7f809c67c88eb385ab924447485f34288b3002200eb6257d2c4618bc3c353463f82b488e39df84f25718cebcdff2e80d0743b0440121027c2a8e9aa95990b704dd104496bcec52c68ec3bc8199ced4ce3885224aded6b5feffffff027cf73001000000001976a9147274e670ad82b15ee0a34b81560d19f1fd9fa6d488ac80c3c9010000000017a91451f103320b435b5fe417b3f3e0f18972ccc710a08711f40700"
    }

    /// Mainnet groundtruth: the whitelist-rejected peg-in
    /// f8cf5d4eb235cdd88afe502047f7cf96212805f1beea18d4328a5668d9a85383
    /// (registered in RSK tx 0x292b8f49... at block #268,846, 0.35 BTC to the
    /// genesis federation) produced the rejection release whose txid appears
    /// in block #272,850's add_signature events.
    #[test]
    fn mainnet_268846_rejection_release_txid() {
        let pegin_hex = "010000000198d97366c38c8013adaaa2929c84f0e7d8fc2e93702a242329134f6880bdd092000000006a47304402206a38b5af9c244904e11afde7995e2ce32a7d7a7a107802aa3619c3ee1f71cad002204a2f112536f5dba011e8527dd344e5aa06e7909a0ff453a3d514c3ac1aec11e4012103e4388dd4e2b53498d8dca313d42453d226828f7da181bf7761029faf06391ceffeffffff02c00e16020000000017a91451f103320b435b5fe417b3f3e0f18972ccc710a087684d7804000000001976a914736b40a8092e2a941ce5b51676df108b380bc33788ac8bd90700";
        let pegin: BtcTransaction =
            bitcoin::consensus::deserialize(&alloy_primitives::hex::decode(pegin_hex).unwrap())
                .unwrap();

        // Genesis federation redeem script (8-of-15) and P2SH script.
        let config = super::super::constants::BridgeConstants::mainnet();
        let keys: Vec<[u8; 33]> = config
            .genesis_federation_public_keys
            .iter()
            .map(|h| alloy_primitives::hex::decode(h).unwrap().try_into().unwrap())
            .collect();
        let redeem = super::super::peg::build_federation_redeem_script(&keys, 8);
        let mut fed_script = vec![0xa9, 0x14];
        use bitcoin::hashes::Hash as _;
        let h160 = bitcoin::hashes::hash160::Hash::hash(&redeem);
        fed_script.extend_from_slice(h160.as_byte_array());
        fed_script.push(0x87);
        assert_eq!(
            h160.as_byte_array().to_vec(),
            alloy_primitives::hex::decode("51f103320b435b5fe417b3f3e0f18972ccc710a0").unwrap(),
            "genesis federation P2SH hash"
        );

        // The peg-in's federation UTXOs (output 0, 0.35 BTC).
        let mut txid = *pegin.compute_txid().to_raw_hash().as_byte_array();
        txid.reverse(); // stored/display order
        let utxos: Vec<BridgeUtxo> = pegin
            .output
            .iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey.as_bytes() == fed_script.as_slice())
            .map(|(i, o)| BridgeUtxo {
                tx_hash: txid,
                vout: i as u32,
                value_satoshis: o.value.to_sat(),
                height: 0,
                script: o.script_pubkey.to_bytes(),
                coinbase: false,
            })
            .collect();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].value_satoshis, 35_000_000);

        // Refund to the sender's P2PKH (pubkey from the first input).
        let sender_pubkey = alloy_primitives::hex::decode(
            "03e4388dd4e2b53498d8dca313d42453d226828f7da181bf7761029faf06391cef",
        )
        .unwrap();
        let sender_h160 = bitcoin::hashes::hash160::Hash::hash(&sender_pubkey);
        let mut refund = vec![0x76, 0xa9, 0x14];
        refund.extend_from_slice(sender_h160.as_byte_array());
        refund.extend_from_slice(&[0x88, 0xac]);

        let built = build_empty_wallet_to(
            &utxos,
            &ScriptBuf::from_bytes(refund),
            &redeem,
            500_000, // mainnet genesis feePerKb
            1,       // pre-RSKIP201
        )
        .expect("rejection release builds");

        // Fee: 500000 sat/kB over 1198 bytes (598 serialized + 8*75+598
        // signing estimate) = 599,000.
        assert_eq!(built.tx.output.len(), 1);
        assert_eq!(built.tx.output[0].value.to_sat(), 35_000_000 - 599_000);

        let mut rid = *built.tx.compute_txid().to_raw_hash().as_byte_array();
        rid.reverse();
        assert_eq!(
            alloy_primitives::hex::encode(rid),
            "5b42e517f17c47b036bee6311a87d3679490f721d99e2811ef9fd2a5b7f5ca11",
            "rejection release txid must match the mainnet add_signature event"
        );
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
