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


// ---------------------------------------------------------------------------
// RSKIP146 (Solidity-format) events — rskj BridgeEventLoggerImpl
// ---------------------------------------------------------------------------

/// keccak256 of the Solidity event signature.
fn solidity_topic(signature: &str) -> B256 {
    alloy_primitives::keccak256(signature.as_bytes())
}

fn emit_topics<CTX: ContextTr>(ctx: &mut CTX, topics: Vec<B256>, data: Vec<u8>) {
    ctx.journal_mut().log(Log::new_unchecked(BRIDGE_ADDR, topics, Bytes::from(data)));
}

fn address_word(addr: Address) -> B256 {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr.as_slice());
    B256::new(word)
}

/// ABI head word for a U256 value.
fn u256_word(value: alloy_primitives::U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

/// ABI-encode a single dynamic `bytes`/`string` parameter as event data.
fn abi_single_dynamic(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + data.len().div_ceil(32) * 32);
    out.extend_from_slice(&u256_word(alloy_primitives::U256::from(32u64)));
    out.extend_from_slice(&u256_word(alloy_primitives::U256::from(data.len() as u64)));
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(32).max(64), 0);
    out
}

/// `update_collections(address sender)` — no indexed params.
pub fn log_solidity_update_collections<CTX: ContextTr>(ctx: &mut CTX, sender: Address) {
    emit_topics(
        ctx,
        vec![solidity_topic("update_collections(address)")],
        address_word(sender).as_slice().to_vec(),
    );
}

/// `add_signature(bytes32 indexed releaseRskTxHash, address indexed
/// federatorRskAddress, bytes federatorBtcPublicKey)`.
pub fn log_solidity_add_signature<CTX: ContextTr>(
    ctx: &mut CTX,
    release_rsk_tx_hash: &[u8; 32],
    federator_rsk_address: Address,
    federator_btc_public_key: &[u8],
) {
    emit_topics(
        ctx,
        vec![
            solidity_topic("add_signature(bytes32,address,bytes)"),
            B256::from_slice(release_rsk_tx_hash),
            address_word(federator_rsk_address),
        ],
        abi_single_dynamic(federator_btc_public_key),
    );
}

/// `release_btc(bytes32 indexed releaseRskTxHash, bytes btcRawTransaction)`.
pub fn log_solidity_release_btc<CTX: ContextTr>(
    ctx: &mut CTX,
    release_rsk_tx_hash: &[u8; 32],
    btc_raw_transaction: &[u8],
) {
    emit_topics(
        ctx,
        vec![
            solidity_topic("release_btc(bytes32,bytes)"),
            B256::from_slice(release_rsk_tx_hash),
        ],
        abi_single_dynamic(btc_raw_transaction),
    );
}

/// `lock_btc(address indexed receiver, bytes32 btcTxHash, string
/// senderBtcAddress, int256 amount)` — RSKIP146 peg-in event (until RSKIP170).
pub fn log_lock_btc<CTX: ContextTr>(
    ctx: &mut CTX,
    receiver: Address,
    btc_tx_hash: &[u8; 32],
    sender_btc_address: &str,
    amount_satoshis: u64,
) {
    let mut data = Vec::new();
    data.extend_from_slice(btc_tx_hash);
    data.extend_from_slice(&u256_word(alloy_primitives::U256::from(96u64))); // string offset
    data.extend_from_slice(&u256_word(alloy_primitives::U256::from(amount_satoshis)));
    let s = sender_btc_address.as_bytes();
    data.extend_from_slice(&u256_word(alloy_primitives::U256::from(s.len() as u64)));
    data.extend_from_slice(s);
    data.resize(data.len().next_multiple_of(32), 0);
    emit_topics(
        ctx,
        vec![
            solidity_topic("lock_btc(address,bytes32,string,int256)"),
            address_word(receiver),
        ],
        data,
    );
}

/// `pegin_btc(address indexed receiver, bytes32 indexed btcTxHash, int256
/// amount, int256 protocolVersion)` — replaces lock_btc from RSKIP170.
pub fn log_pegin_btc<CTX: ContextTr>(
    ctx: &mut CTX,
    receiver: Address,
    btc_tx_hash: &[u8; 32],
    amount_satoshis: u64,
    protocol_version: u64,
) {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&u256_word(alloy_primitives::U256::from(amount_satoshis)));
    data.extend_from_slice(&u256_word(alloy_primitives::U256::from(protocol_version)));
    emit_topics(
        ctx,
        vec![
            solidity_topic("pegin_btc(address,bytes32,int256,int256)"),
            address_word(receiver),
            B256::from_slice(btc_tx_hash),
        ],
        data,
    );
}

/// `release_requested(bytes32 indexed rskTxHash, bytes32 indexed btcTxHash,
/// uint256 amount)` — fired when a peg-out BTC transaction is created.
pub fn log_release_requested<CTX: ContextTr>(
    ctx: &mut CTX,
    rsk_tx_hash: &[u8; 32],
    btc_tx_hash: &[u8; 32],
    amount_satoshis: u64,
) {
    emit_topics(
        ctx,
        vec![
            solidity_topic("release_requested(bytes32,bytes32,uint256)"),
            B256::from_slice(rsk_tx_hash),
            B256::from_slice(btc_tx_hash),
        ],
        u256_word(alloy_primitives::U256::from(amount_satoshis)).to_vec(),
    );
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

    /// Groundtruth from the mainnet #2,392,704 updateCollections receipt
    /// (first post-papyrus200 block with one): Solidity-format topic and
    /// ABI-encoded sender data.
    #[test]
    fn solidity_update_collections_matches_mainnet_2392704() {
        assert_eq!(
            hex::encode(solidity_topic("update_collections(address)")),
            "1069152f4f916cbf155ee32a695d92258481944edb5b6fd649718fc1b43e515e"
        );
        let sender: Address = "0x7b197517908e9a434c0c69e8d42e8b74f8b86992".parse().unwrap();
        assert_eq!(
            hex::encode(address_word(sender)),
            "0000000000000000000000007b197517908e9a434c0c69e8d42e8b74f8b86992"
        );
    }

    /// ABI layout of a single dynamic parameter (offset, length, padded data).
    #[test]
    fn abi_single_dynamic_layout() {
        let out = abi_single_dynamic(&[0xAA; 33]);
        assert_eq!(out.len(), 64 + 64);
        assert_eq!(out[31], 32);   // offset
        assert_eq!(out[63], 33);   // length
        assert_eq!(out[64], 0xAA);
        assert_eq!(out[96], 0xAA);
        assert_eq!(out[97], 0x00); // padding
    }
}
