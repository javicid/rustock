//! Legacy (pre-RSKIP146) Bridge event emission.
//!
//! Ported from rskj `BrigeEventLoggerLegacyImpl`: a single topic that is the
//! event name as right-aligned ASCII in 32 bytes (`DataWord.fromString`),
//! with RLP-encoded data.

use alloy_primitives::{Address, Bytes, B256};
use alloy_rlp::Encodable;
use revm::context_interface::{ContextTr, JournalTr};
use revm::primitives::Log;

use crate::precompiles::BRIDGE_ADDR;

/// `DataWord.fromString(name)`: ASCII bytes right-aligned in a 32-byte word.
pub(crate) fn legacy_topic(name: &str) -> B256 {
    let bytes = name.as_bytes();
    debug_assert!(bytes.len() <= 32);
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    B256::new(buf)
}

fn emit<CTX: ContextTr>(ctx: &mut CTX, topic: B256, data: Vec<u8>) {
    ctx.journal_mut().log(Log::new_unchecked(
        BRIDGE_ADDR,
        vec![topic],
        Bytes::from(data),
    ));
}

/// rskj `logUpdateCollections`: data = RLP.encodeElement(senderAddress).
pub fn log_legacy_update_collections<CTX: ContextTr>(ctx: &mut CTX, sender: Address) {
    let mut data = Vec::with_capacity(21);
    sender.as_slice().encode(&mut data);
    emit(ctx, legacy_topic("update_collections_topic"), data);
}

/// rskj `logAddSignature`: data = RLP([btcTxHash-as-hex-string,
/// federatorBtcPubKeyHash160, rskTxHash]).
pub fn log_legacy_add_signature<CTX: ContextTr>(
    ctx: &mut CTX,
    btc_tx_hash_hex: &str,
    federator_pubkey_hash160: &[u8; 20],
    rsk_tx_hash: &[u8; 32],
) {
    let mut inner = Vec::new();
    btc_tx_hash_hex.encode(&mut inner);
    federator_pubkey_hash160.as_slice().encode(&mut inner);
    rsk_tx_hash.as_slice().encode(&mut inner);
    let mut data = Vec::with_capacity(inner.len() + 3);
    alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut data);
    data.extend_from_slice(&inner);
    emit(ctx, legacy_topic("add_signature_topic"), data);
}

/// rskj `logReleaseBtc`: data = RLP([btcTxHash-as-hex-string, serializedBtcTx]).
pub fn log_legacy_release_btc<CTX: ContextTr>(
    ctx: &mut CTX,
    btc_tx_hash_hex: &str,
    serialized_btc_tx: &[u8],
) {
    let mut inner = Vec::new();
    btc_tx_hash_hex.encode(&mut inner);
    serialized_btc_tx.encode(&mut inner);
    let mut data = Vec::with_capacity(inner.len() + 3);
    alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut data);
    data.extend_from_slice(&inner);
    emit(ctx, legacy_topic("release_btc_topic"), data);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Groundtruth from mainnet block #615 tx 1 receipt (public-node.rsk.co):
    /// topic 0x00000000000000007570646174655f636f6c6c656374696f6e735f746f706963,
    /// data 0x9432c865f2dbf36ce6f4cfcb624b559ef98b33a2d1.
    #[test]
    fn legacy_update_collections_event_matches_mainnet() {
        let topic = legacy_topic("update_collections_topic");
        assert_eq!(
            hex::encode(topic),
            "00000000000000007570646174655f636f6c6c656374696f6e735f746f706963"
        );

        let sender: Address = "0x32c865f2dbf36ce6f4cfcb624b559ef98b33a2d1".parse().unwrap();
        let mut data = Vec::new();
        sender.as_slice().encode(&mut data);
        assert_eq!(
            hex::encode(&data),
            "9432c865f2dbf36ce6f4cfcb624b559ef98b33a2d1"
        );
    }
}
