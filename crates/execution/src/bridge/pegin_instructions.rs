//! RSKIP170 peg-in v1 OP_RETURN parser.
//!
//! Port of rskj `co.rsk.peg.pegininstructions.PeginInstructionsProvider`,
//! `PeginInstructionsBase`, and `PeginInstructionsVersion1`.
//!
//! ## OP_RETURN payload layout (the data pushed after the OP_RETURN opcode)
//!
//! ```text
//!   [0..4]   "RSKT" magic (0x52534b54)
//!   [4]      protocol version (u8); v1 is the only supported version
//!   [5..25]  RSK destination address (20 bytes)
//!   -- length 25 stops here (no refund address) --
//!   [25]     BTC refund address type: 1 = P2PKH, 2 = P2SH
//!   [26..46] refund address hash160 (20 bytes)
//! ```
//!
//! Valid payload lengths are exactly **25** or **46**.
//!
//! ## Error semantics (consensus-critical)
//!
//! rskj distinguishes two failure modes, and the peg-in dispatch treats them
//! very differently:
//!
//! * `NoOpReturnException` (no OP_RETURN output carries the RSKT magic) →
//!   `buildPeginInstructions` returns `Optional.empty()` and the peg-in falls
//!   back to **legacy** (version-0) processing. Modeled here as `Ok(None)`.
//! * `PeginInstructionsException` / `PeginInstructionsParseException` (more
//!   than one RSKT OP_RETURN, an unsupported protocol version, a bad data
//!   length, or a bad refund-address type) → the v1 peg-in is **rejected**
//!   (refund + mark processed + `rejected_pegin(PEGIN_V1_INVALID_PAYLOAD)`).
//!   Modeled here as `Err(PeginInstructionsError)`.

use super::release_tx::{parse_chunks, Chunk};
use bitcoin::Transaction as BtcTransaction;

/// `RSKT` in ASCII — the magic prefix of an RSK peg-in OP_RETURN payload.
const RSKT_MAGIC: [u8; 4] = [0x52, 0x53, 0x4b, 0x54];

const P2PKH_ADDRESS_TYPE: u8 = 1;
const P2SH_ADDRESS_TYPE: u8 = 2;

/// A BTC refund address parsed from a v1 payload (`version` byte + 20-byte
/// hash160). The version distinguishes P2PKH from P2SH for the refund script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcRefundAddress {
    /// `true` if the refund address is a P2SH (script hash) address.
    pub is_p2sh: bool,
    /// The 20-byte address hash (pubkey hash for P2PKH, script hash for P2SH).
    pub hash160: [u8; 20],
}

/// Parsed peg-in instructions (rskj `PeginInstructions`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeginInstructions {
    /// Protocol version (always 1 here — the only supported v1 version).
    pub protocol_version: u8,
    /// RSK destination address (20 bytes).
    pub rsk_destination: [u8; 20],
    /// Optional BTC refund address (present only for 46-byte payloads).
    pub btc_refund_address: Option<BtcRefundAddress>,
}

/// rskj `PeginInstructionsException` (and its `PeginInstructionsParseException`
/// subclass): a malformed RSKT OP_RETURN that must REJECT the v1 peg-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeginInstructionsError;

/// rskj `PeginInstructionsProvider.buildPeginInstructions`.
///
/// * `Ok(Some(instructions))` — a single valid RSKT v1 OP_RETURN.
/// * `Ok(None)` — no RSKT OP_RETURN (`NoOpReturnException`): fall back to
///   legacy processing.
/// * `Err(_)` — a malformed RSKT OP_RETURN (`PeginInstructionsException`):
///   reject the v1 peg-in.
pub fn build_pegin_instructions(
    btc_tx: &BtcTransaction,
) -> Result<Option<PeginInstructions>, PeginInstructionsError> {
    let data = match extract_op_return_data(btc_tx)? {
        Some(data) => data,
        None => return Ok(None), // NoOpReturnException → legacy
    };

    // extractProtocolVersion: needs at least 5 bytes (magic + version byte).
    if data.len() < 5 {
        return Err(PeginInstructionsError);
    }
    let protocol_version = data[4];

    match protocol_version {
        1 => parse_version1(&data).map(Some),
        // Any other version (including 0) throws PeginInstructionsException.
        _ => Err(PeginInstructionsError),
    }
}

/// rskj `PeginInstructionsProvider.extractOpReturnData`.
///
/// Scans the outputs for OP_RETURNs whose pushed data starts with the RSKT
/// magic. Returns the payload of the single match (`Ok(Some)`), `Ok(None)` if
/// there is none (`NoOpReturnException`), or `Err` if more than one carries the
/// RSKT magic (`PeginInstructionsException`).
fn extract_op_return_data(
    btc_tx: &BtcTransaction,
) -> Result<Option<Vec<u8>>, PeginInstructionsError> {
    let mut found: Option<Vec<u8>> = None;
    let mut occurrences = 0u32;

    for output in &btc_tx.output {
        if let Some(data) = op_return_rsk_payload(output.script_pubkey.as_bytes()) {
            found = Some(data);
            occurrences += 1;
        }
    }

    if occurrences == 0 {
        return Ok(None); // NoOpReturnException → legacy fallback
    }
    if occurrences > 1 {
        return Err(PeginInstructionsError); // PeginInstructionsException
    }
    Ok(found)
}

/// rskj `PeginInstructionsProvider.hasOpReturnForRsk` combined with the
/// chunk-1 data extraction: an OP_RETURN script whose second chunk is data of
/// length ≥ 4 starting with the RSKT magic. Returns that chunk's data.
fn op_return_rsk_payload(script: &[u8]) -> Option<Vec<u8>> {
    // bitcoinj Script.isOpReturn: first opcode is OP_RETURN (0x6a).
    if script.first() != Some(&0x6a) {
        return None;
    }
    let chunks = parse_chunks(script)?;
    // Need a chunk at index 1 that is data of length >= 4 with the RSKT prefix.
    let Some(Chunk::Data(data)) = chunks.get(1) else {
        return None;
    };
    if data.len() >= 4 && data[0..4] == RSKT_MAGIC {
        Some(data.clone())
    } else {
        None
    }
}

/// rskj `PeginInstructionsVersion1.parse` (via `PeginInstructionsBase.parse`):
/// validate the data length, read the destination, then parse the optional
/// refund address.
fn parse_version1(data: &[u8]) -> Result<PeginInstructions, PeginInstructionsError> {
    // validateDataLength: exactly 25 or 46 bytes.
    if data.len() != 25 && data.len() != 46 {
        return Err(PeginInstructionsError);
    }

    // getRskDestinationAddressFromData: bytes [5..25].
    let mut rsk_destination = [0u8; 20];
    rsk_destination.copy_from_slice(&data[5..25]);

    let btc_refund_address = if data.len() == 25 {
        None
    } else {
        // parseAdditionalData: byte 25 is the address type, [26..46] the hash.
        let addr_type = data[25];
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(&data[26..46]);
        let is_p2sh = match addr_type {
            P2PKH_ADDRESS_TYPE => false,
            P2SH_ADDRESS_TYPE => true,
            _ => return Err(PeginInstructionsError), // invalid btc address type
        };
        Some(BtcRefundAddress { is_p2sh, hash160 })
    };

    Ok(PeginInstructions {
        protocol_version: 1,
        rsk_destination,
        btc_refund_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, TxOut};

    /// Build the OP_RETURN payload exactly like rskj
    /// `PegTestUtils.createOpReturnScriptForRsk`.
    fn rsk_op_return_payload(
        protocol_version: u8,
        rsk_dest: [u8; 20],
        refund: Option<(u8, [u8; 20])>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&RSKT_MAGIC);
        payload.push(protocol_version);
        payload.extend_from_slice(&rsk_dest);
        if let Some((addr_type, hash160)) = refund {
            payload.push(addr_type);
            payload.extend_from_slice(&hash160);
        }
        payload
    }

    /// Wrap an arbitrary payload in an OP_RETURN script (OP_RETURN + push).
    fn op_return_script(payload: &[u8]) -> ScriptBuf {
        let mut script = vec![0x6a];
        super::super::release_tx::push_data(&mut script, payload);
        ScriptBuf::from_bytes(script)
    }

    fn tx_with_outputs(scripts: Vec<ScriptBuf>) -> BtcTransaction {
        BtcTransaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: scripts
                .into_iter()
                .map(|s| TxOut {
                    value: Amount::ZERO,
                    script_pubkey: s,
                })
                .collect(),
        }
    }

    // Ported from rskj PeginInstructionsProviderTest.buildPeginInstructions_nullOpReturnData
    #[test]
    fn no_op_return_data_is_legacy_fallback() {
        // Bare OP_RETURN with no pushdata → not RSK → legacy fallback.
        let tx = tx_with_outputs(vec![ScriptBuf::from_bytes(vec![0x6a])]);
        assert_eq!(build_pegin_instructions(&tx), Ok(None));
    }

    // Ported from PeginInstructionsProviderTest.extractOpReturnData_noOpReturnForRsk
    #[test]
    fn non_rsk_op_return_is_legacy_fallback() {
        let tx = tx_with_outputs(vec![op_return_script(b"some-payload")]);
        assert_eq!(build_pegin_instructions(&tx), Ok(None));
    }

    // Ported from PeginInstructionsProviderTest.buildPeginInstructions_invalidProtocolVersion
    #[test]
    fn invalid_protocol_version_rejects() {
        let payload = rsk_op_return_payload(0, [0u8; 20], None);
        let tx = tx_with_outputs(vec![op_return_script(&payload)]);
        assert_eq!(build_pegin_instructions(&tx), Err(PeginInstructionsError));
    }

    // Ported from PeginInstructionsProviderTest.buildPeginInstructions_v1_dataLengthSmallerThanExpected
    #[test]
    fn v1_data_too_short_rejects() {
        // RSKT + version + 5 custom bytes = 10 bytes (not 25/46).
        let mut payload = Vec::new();
        payload.extend_from_slice(&RSKT_MAGIC);
        payload.push(1);
        payload.extend_from_slice(&[0u8; 5]);
        let tx = tx_with_outputs(vec![op_return_script(&payload)]);
        assert_eq!(build_pegin_instructions(&tx), Err(PeginInstructionsError));
    }

    // Ported from PeginInstructionsProviderTest.buildPeginInstructions_v1_dataLengthDifferentThanSupported
    #[test]
    fn v1_data_wrong_length_rejects() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&RSKT_MAGIC);
        payload.push(1);
        payload.extend_from_slice(&[0u8; 30]); // 35 bytes total
        let tx = tx_with_outputs(vec![op_return_script(&payload)]);
        assert_eq!(build_pegin_instructions(&tx), Err(PeginInstructionsError));
    }

    // Ported from PeginInstructionsProviderTest.buildPeginInstructions_v1_noBtcRefundAddress
    #[test]
    fn v1_no_refund_address() {
        let dest = [0x11u8; 20];
        let payload = rsk_op_return_payload(1, dest, None);
        assert_eq!(payload.len(), 25);
        let tx = tx_with_outputs(vec![op_return_script(&payload)]);
        let instr = build_pegin_instructions(&tx).unwrap().unwrap();
        assert_eq!(instr.protocol_version, 1);
        assert_eq!(instr.rsk_destination, dest);
        assert!(instr.btc_refund_address.is_none());
    }

    // Ported from PeginInstructionsVersion1Test.parseAdditionalData_p2pkhTypeAddress
    #[test]
    fn v1_p2pkh_refund_address() {
        let dest = [0x22u8; 20];
        let refund_hash = [0xABu8; 20];
        let payload = rsk_op_return_payload(1, dest, Some((P2PKH_ADDRESS_TYPE, refund_hash)));
        assert_eq!(payload.len(), 46);
        let tx = tx_with_outputs(vec![op_return_script(&payload)]);
        let instr = build_pegin_instructions(&tx).unwrap().unwrap();
        let refund = instr.btc_refund_address.unwrap();
        assert!(!refund.is_p2sh);
        assert_eq!(refund.hash160, refund_hash);
    }

    // Ported from PeginInstructionsVersion1Test.parseAdditionalData_p2shMultisigAddress
    #[test]
    fn v1_p2sh_refund_address() {
        let dest = [0x22u8; 20];
        let refund_hash = [0xCDu8; 20];
        let payload = rsk_op_return_payload(1, dest, Some((P2SH_ADDRESS_TYPE, refund_hash)));
        let tx = tx_with_outputs(vec![op_return_script(&payload)]);
        let instr = build_pegin_instructions(&tx).unwrap().unwrap();
        let refund = instr.btc_refund_address.unwrap();
        assert!(refund.is_p2sh);
        assert_eq!(refund.hash160, refund_hash);
    }

    // Ported from PeginInstructionsVersion1Test.parseAdditionalData_invalidAddressType
    #[test]
    fn v1_invalid_refund_address_type_rejects() {
        let payload = rsk_op_return_payload(1, [0u8; 20], Some((9, [0u8; 20])));
        let tx = tx_with_outputs(vec![op_return_script(&payload)]);
        assert_eq!(build_pegin_instructions(&tx), Err(PeginInstructionsError));
    }

    // Ported from PeginInstructionsProviderTest.extractOpReturnData_twoOpReturnOutputsForRsk
    #[test]
    fn two_rsk_op_returns_rejects() {
        let payload = rsk_op_return_payload(1, [0u8; 20], None);
        let script = op_return_script(&payload);
        let tx = tx_with_outputs(vec![script.clone(), script]);
        assert_eq!(build_pegin_instructions(&tx), Err(PeginInstructionsError));
    }

    // Ported from PeginInstructionsProviderTest.extractOpReturnData_multipleOpReturnOutpust_oneForRsk
    #[test]
    fn multiple_op_returns_one_for_rsk() {
        let dest = [0x33u8; 20];
        let rsk = op_return_script(&rsk_op_return_payload(1, dest, None));
        let other1 = op_return_script(b"1");
        let other2 = op_return_script(b"some-payload");
        let tx = tx_with_outputs(vec![other1, rsk, other2]);
        let instr = build_pegin_instructions(&tx).unwrap().unwrap();
        assert_eq!(instr.rsk_destination, dest);
    }
}
