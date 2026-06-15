//! Legacy (pre-RSKIP146) Bridge event emission.
//!
//! Ported from rskj `BrigeEventLoggerLegacyImpl`: a single topic that is the
//! event name as right-aligned ASCII in 32 bytes (`DataWord.fromString`),
//! with RLP-encoded data.

use alloy_primitives::{Address, Bytes, B256};
use alloy_rlp::Encodable;
use revm::context_interface::JournalTr;
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

fn emit<CTX: crate::RskContextTr>(ctx: &mut CTX, topic: B256, data: Vec<u8>) {
    ctx.journal_mut().log(Log::new_unchecked(
        BRIDGE_ADDR,
        vec![topic],
        Bytes::from(data),
    ));
}

/// rskj `logUpdateCollections`: data = RLP.encodeElement(senderAddress).
pub fn log_legacy_update_collections<CTX: crate::RskContextTr>(ctx: &mut CTX, sender: Address) {
    let mut data = Vec::with_capacity(21);
    sender.as_slice().encode(&mut data);
    emit(ctx, legacy_topic("update_collections_topic"), data);
}

/// rskj `logAddSignature`: data = RLP([btcTxHash-as-hex-string,
/// federatorBtcPubKeyHash160, rskTxHash]).
pub fn log_legacy_add_signature<CTX: crate::RskContextTr>(
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
pub fn log_legacy_release_btc<CTX: crate::RskContextTr>(
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


/// Legacy `commit_federation_topic` event
/// (rskj BrigeEventLoggerLegacyImpl.logCommitFederation):
/// data = RLP[ RLP[oldFedAddressHash160, RLP[oldKeys...]],
///             RLP[newFedAddressHash160, RLP[newKeys...]],
///             activationBlockNumber as a DECIMAL ASCII string ].
pub fn log_legacy_commit_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    old_fed_hash160: &[u8; 20],
    old_keys: &[[u8; 33]],
    new_fed_hash160: &[u8; 20],
    new_keys: &[[u8; 33]],
    activation_block: u64,
) {
    use super::serialization::{rlp_encode_element, rlp_encode_list};
    let fed_data = |hash160: &[u8; 20], keys: &[[u8; 33]]| {
        let key_items: Vec<Vec<u8>> = keys.iter().map(|k| rlp_encode_element(k)).collect();
        rlp_encode_list(&[rlp_encode_element(hash160), rlp_encode_list(&key_items)])
    };
    let data = rlp_encode_list(&[
        fed_data(old_fed_hash160, old_keys),
        fed_data(new_fed_hash160, new_keys),
        rlp_encode_element(activation_block.to_string().as_bytes()),
    ]);
    emit(ctx, legacy_topic("commit_federation_topic"), data);
}

// ---------------------------------------------------------------------------
// RSKIP146 (Solidity-format) events — rskj BridgeEventLoggerImpl
// ---------------------------------------------------------------------------

/// keccak256 of the Solidity event signature.
fn solidity_topic(signature: &str) -> B256 {
    alloy_primitives::keccak256(signature.as_bytes())
}

fn emit_topics<CTX: crate::RskContextTr>(ctx: &mut CTX, topics: Vec<B256>, data: Vec<u8>) {
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
pub fn log_solidity_update_collections<CTX: crate::RskContextTr>(ctx: &mut CTX, sender: Address) {
    emit_topics(
        ctx,
        vec![solidity_topic("update_collections(address)")],
        address_word(sender).as_slice().to_vec(),
    );
}

/// `add_signature(bytes32 indexed releaseRskTxHash, address indexed
/// federatorRskAddress, bytes federatorBtcPublicKey)`.
pub fn log_solidity_add_signature<CTX: crate::RskContextTr>(
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
pub fn log_solidity_release_btc<CTX: crate::RskContextTr>(
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

/// `commit_federation(bytes oldFederationBtcPublicKeys, string
/// oldFederationBtcAddress, bytes newFederationBtcPublicKeys, string
/// newFederationBtcAddress, int256 activationHeight)` — RSKIP146 federation
/// commit event (rskj logCommitFederationInSolidityFormat). The key bytes
/// are the federation's sorted compressed BTC pubkeys flat-concatenated;
/// the addresses are Base58Check P2SH strings.
pub fn log_solidity_commit_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    old_keys: &[[u8; 33]],
    old_fed_address: &str,
    new_keys: &[[u8; 33]],
    new_fed_address: &str,
    activation_block: u64,
) {
    emit_topics(
        ctx,
        vec![solidity_topic("commit_federation(bytes,string,bytes,string,int256)")],
        commit_federation_event_data(
            old_keys,
            old_fed_address,
            new_keys,
            new_fed_address,
            activation_block,
        ),
    );
}

fn commit_federation_event_data(
    old_keys: &[[u8; 33]],
    old_fed_address: &str,
    new_keys: &[[u8; 33]],
    new_fed_address: &str,
    activation_block: u64,
) -> Vec<u8> {
    let old_flat = old_keys.concat();
    let new_flat = new_keys.concat();
    let dynamics: [&[u8]; 4] = [
        &old_flat,
        old_fed_address.as_bytes(),
        &new_flat,
        new_fed_address.as_bytes(),
    ];
    let head_len = 5 * 32;
    let mut tail = Vec::new();
    let mut head = Vec::with_capacity(head_len);
    for d in dynamics {
        head.extend_from_slice(&u256_word(alloy_primitives::U256::from(
            (head_len + tail.len()) as u64,
        )));
        tail.extend_from_slice(&u256_word(alloy_primitives::U256::from(d.len() as u64)));
        tail.extend_from_slice(d);
        tail.resize(tail.len().next_multiple_of(32), 0);
    }
    head.extend_from_slice(&u256_word(alloy_primitives::U256::from(activation_block)));
    head.extend_from_slice(&tail);
    head
}

/// `lock_btc(address indexed receiver, bytes32 btcTxHash, string
/// senderBtcAddress, int256 amount)` — RSKIP146 peg-in event (until RSKIP170).
pub fn log_lock_btc<CTX: crate::RskContextTr>(
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
pub fn log_pegin_btc<CTX: crate::RskContextTr>(
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

/// `rejected_pegin(bytes32 indexed btcTxHash, int256 reason)` — rskj
/// `logRejectedPegin` (RSKIP181, iris300). Fired when a peg-in is rejected but
/// the funds are refundable. `reason` is the `RejectedPeginReason` enum value:
/// PEGIN_CAP_SURPASSED=1, LEGACY_PEGIN_MULTISIG_SENDER=2,
/// LEGACY_PEGIN_UNDETERMINED_SENDER=3, PEGIN_V1_INVALID_PAYLOAD=4,
/// INVALID_AMOUNT=5. The topic is `btcTx.getHash().getBytes()` = the legacy
/// (witness-stripped) txid in display order.
pub fn log_rejected_pegin<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
    reason: u64,
) {
    emit_topics(
        ctx,
        vec![
            solidity_topic("rejected_pegin(bytes32,int256)"),
            B256::from_slice(btc_tx_hash),
        ],
        u256_word(alloy_primitives::U256::from(reason)).to_vec(),
    );
}

/// `release_requested(bytes32 indexed rskTxHash, bytes32 indexed btcTxHash,
/// uint256 amount)` — fired when a peg-out BTC transaction is created.
pub fn log_release_requested<CTX: crate::RskContextTr>(
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

/// `batch_pegout_created(bytes32 indexed btcTxHash, bytes releaseRskTxHashes)`
/// — rskj `logBatchPegoutCreated` (RSKIP271, peg-out batching). Fired by
/// `processPegoutsInBatch` when the whole release-request queue is settled into
/// a single batched BTC transaction. `btcTxHash` is the batch BTC tx's
/// `Sha256Hash.getBytes()` (big-endian), and the data field is the raw
/// concatenation of every batched request's 32-byte RSK creation tx hash
/// (`serializeRskTxHashes`), ABI-encoded as a single dynamic `bytes`.
pub fn log_batch_pegout_created<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
    rsk_tx_hashes: &[[u8; 32]],
) {
    let serialized: Vec<u8> = rsk_tx_hashes.iter().flatten().copied().collect();
    emit_topics(
        ctx,
        vec![
            solidity_topic("batch_pegout_created(bytes32,bytes)"),
            B256::from_slice(btc_tx_hash),
        ],
        abi_single_dynamic(&serialized),
    );
}

/// `release_request_rejected(address indexed sender, uint256 amount, int256
/// reason)` — rskj `logReleaseBtcRequestRejected`. The signature is identical in
/// every era; only the `amount` encoding changes: pre-RSKIP427 (lovell700) it is
/// the value in satoshis (`amountInWeis.toBitcoin().getValue()`), post-RSKIP427
/// it is the full value in wei (`amountInWeis.asBigInteger()`). The reason is the
/// `RejectedPegoutReason` enum value (LOW_AMOUNT=1, CALLER_CONTRACT=2,
/// FEE_ABOVE_VALUE=3).
pub fn log_release_request_rejected<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    sender: Address,
    amount: alloy_primitives::U256,
    reason: u64,
) {
    emit_topics(
        ctx,
        vec![
            solidity_topic("release_request_rejected(address,uint256,int256)"),
            address_word(sender),
        ],
        release_request_rejected_data(amount, reason),
    );
}

/// ABI `data` for `release_request_rejected`: `uint256(amount) || int256(reason)`.
fn release_request_rejected_data(amount: alloy_primitives::U256, reason: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&u256_word(amount));
    data.extend_from_slice(&u256_word(alloy_primitives::U256::from(reason)));
    data
}

/// `release_request_received` — rskj `logReleaseBtcRequestReceived`. Emitted when
/// a peg-out is accepted and enqueued (RSKIP185, iris300). The event has TWO
/// destination formats:
///
/// - **Pre-RSKIP326 (fingerroot500)** `RELEASE_REQUEST_RECEIVED_LEGACY`:
///   `release_request_received(address indexed sender, bytes btcDestinationAddress, uint256 amount)`
///   where `btcDestinationAddress` is the 20-byte hash160
///   (`btcDestinationAddress.getHash160()`).
/// - **Post-RSKIP326** `RELEASE_REQUEST_RECEIVED`:
///   `release_request_received(address indexed sender, string btcDestinationAddress, uint256 amount)`
///   where the destination is the Base58 address string
///   (`btcDestinationAddress.toString()`).
///
/// Independently, the `amount` is in satoshis pre-RSKIP427 (lovell700) and in
/// full wei post-RSKIP427.
pub fn log_release_request_received<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    sender: Address,
    btc_dest_hash160: &[u8; 20],
    btc_dest_base58: &str,
    amount: alloy_primitives::U256,
    rskip326: bool,
) {
    let (signature, dynamic): (&str, &[u8]) = if rskip326 {
        ("release_request_received(address,string,uint256)", btc_dest_base58.as_bytes())
    } else {
        ("release_request_received(address,bytes,uint256)", btc_dest_hash160)
    };
    emit_topics(
        ctx,
        vec![solidity_topic(signature), address_word(sender)],
        release_request_received_data(dynamic, amount),
    );
}

/// ABI `data` for `release_request_received`: the dynamic destination field
/// (bytes hash160 pre-326, string base58 post-326) occupies the same head slots
/// — offset word (0x40) + amount word — then the tail (length word + content,
/// right-zero-padded to 32 bytes).
fn release_request_received_data(dynamic: &[u8], amount: alloy_primitives::U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(160);
    data.extend_from_slice(&u256_word(alloy_primitives::U256::from(64u64)));
    data.extend_from_slice(&u256_word(amount));
    data.extend_from_slice(&u256_word(alloy_primitives::U256::from(dynamic.len() as u64)));
    data.extend_from_slice(dynamic);
    data.resize(data.len().next_multiple_of(32), 0);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Groundtruth from mainnet #2,426,478 tx 1 (commitFederation of the 2019
    /// federation change; receipt from public-node.rsk.co): the RSKIP146
    /// Solidity commit_federation event — 9 old keys, 15 new keys, both
    /// federations' Base58 P2SH addresses, activation 2,444,978 (= 2,426,478
    /// + 18,500). Verifies the 5-param ABI layout byte-for-byte.
    #[test]
    fn solidity_commit_federation_event_matches_mainnet_2426478() {
        use alloy_primitives::hex;
        assert_eq!(
            solidity_topic("commit_federation(bytes,string,bytes,string,int256)"),
            B256::from_slice(
                &hex::decode("5b9466a0b50d1cab12eeb0b3b5d387ece7659afcc56bb15704535e6954de8c4e")
                    .unwrap()
            )
        );
        let parse = |hexes: &[&str]| -> Vec<[u8; 33]> {
            hexes
                .iter()
                .map(|h| hex::decode(h).unwrap().try_into().unwrap())
                .collect()
        };
        let old_keys = parse(&[
            "027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344",
            "0294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc",
            "02a9c6848e302193179ce6479516c2d97f6967e1365c707e3b9d3e0cb683ccb822",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
            "03b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573",
            "03ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d",
        ]);
        let new_keys = parse(&[
            "0245ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffeea",
            "024cd9f00935993695af7e6c35165550a79eeac9fdfe95df83c5fdd8692ba2ef9e",
            "027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344",
            "0294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc",
            "02ac1901b6fba2c1dbd47d894d2bd76c8ba1d296d65f6ab47f1c6b22afb53e73eb",
            "02c6018fcbd3e89f3cf9c7f48b3232ea3638eb8bf217e59ee290f5f0cfb2fb9259",
            "031aabbeb9b27258f98c2bf21f36677ae7bae09eb2d8c958ef41a20a6e88626d26",
            "03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93",
            "0340df69f28d69eef60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb44",
            "0372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6",
            "03ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6",
            "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
            "03b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573",
            "03d789669ec532f756461d3d6d83b316ed0c4272d48dc3b60cce0f494e9a09d3e7",
            "03ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d",
        ]);
        let data = commit_federation_event_data(
            &old_keys,
            "35JUi1FxabGdhygLhnNUEFG4AgvpNMgxK1",
            &new_keys,
            "3JYaMbjuKXkURNpLpDDDWMzUcNMt2GreNc",
            2_444_978,
        );
        let expected = hex::decode(
            "00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000\
             000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000260\
             000000000000000000000000000000000000000000000000000000000000048000000000000000000000000000000000\
             00000000000000000000000000254eb20000000000000000000000000000000000000000000000000000000000000129\
             027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc23440294c817150f78607566e961b3c71d\
             f53a22022a80acbb982f83c0c8baac040adc02a9c6848e302193179ce6479516c2d97f6967e1365c707e3b9d3e0cb683\
             ccb82203250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf930372cd46831f3b6afd4c044d\
             160b7667e8ebf659d6cb51a825a3104df6ee0638c603ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094\
             cc989fb880f603b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad203b65cd7c22e70c082\
             3882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c457303ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e968\
             7865673353eb041e8d000000000000000000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000002233354a5569314678616247646879674c686e4e5545464734416776704e4d6778\
             4b3100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000001ef0245ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffe\
             ea024cd9f00935993695af7e6c35165550a79eeac9fdfe95df83c5fdd8692ba2ef9e027319afb15481dbeb3c426bcc37\
             f9a30e7f51ceff586936d85548d9395bcc23440294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8ba\
             ac040adc02ac1901b6fba2c1dbd47d894d2bd76c8ba1d296d65f6ab47f1c6b22afb53e73eb02c6018fcbd3e89f3cf9c7\
             f48b3232ea3638eb8bf217e59ee290f5f0cfb2fb9259031aabbeb9b27258f98c2bf21f36677ae7bae09eb2d8c958ef41\
             a20a6e88626d2603250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf930340df69f28d69ee\
             f60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb440372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51\
             a825a3104df6ee0638c603ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f603b53899c3\
             90573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad203b65cd7c22e70c0823882c6e71ac2c279ed31cb\
             e29cb4a1c00572ce539c0c457303d789669ec532f756461d3d6d83b316ed0c4272d48dc3b60cce0f494e9a09d3e703ec\
             d8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d0000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000022334a59614d626a754b586b55524e704c\
             70444444574d7a55634e4d74324772654e63000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(data, expected);
    }

    /// Groundtruth from mainnet block #4,598,891 tx 2 (updateCollections that
    /// triggered the RSKIP271 batched peg-out): the `batch_pegout_created`
    /// event. topic0 is the event signature, topic1 is the batched BTC tx's
    /// Sha256Hash (big-endian), and the data is the ABI `bytes` holding the two
    /// batched requests' 32-byte RSK creation tx hashes concatenated. Verifies
    /// the signature hash and the `serializeRskTxHashes` + ABI-bytes layout
    /// byte-for-byte.
    #[test]
    fn batch_pegout_created_event_matches_mainnet_4598891() {
        use alloy_primitives::hex;
        assert_eq!(
            solidity_topic("batch_pegout_created(bytes32,bytes)"),
            B256::from_slice(
                &hex::decode("483d0191cc4e784b04a41f6c4801a0766b43b1fdd0b9e3e6bfdca74e5b05c2eb")
                    .unwrap()
            )
        );
        let h0: [u8; 32] =
            hex::decode("61c6130f81c18343e003cbd3f2ea51c6770985a8a52390cb29fe277a73c705c4")
                .unwrap()
                .try_into()
                .unwrap();
        let h1: [u8; 32] =
            hex::decode("0b667320dc677030d0c7314fd3728f60a21fe665befe3105204cebecad3501b4")
                .unwrap()
                .try_into()
                .unwrap();
        let serialized: Vec<u8> = [h0, h1].iter().flatten().copied().collect();
        let data = abi_single_dynamic(&serialized);
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000020\
             0000000000000000000000000000000000000000000000000000000000000040\
             61c6130f81c18343e003cbd3f2ea51c6770985a8a52390cb29fe277a73c705c4\
             0b667320dc677030d0c7314fd3728f60a21fe665befe3105204cebecad3501b4",
        )
        .unwrap();
        assert_eq!(data, expected);
    }

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

    /// Groundtruth from mainnet #3,615,279 tx 9 receipt (public-node.rsk.co):
    /// a direct RBTC transfer to the Bridge below the minimum peg-out value is
    /// rejected with LOW_AMOUNT(1), refunded, and logged. The receipt log:
    ///   topic0 0xb607c3e1fbe6b38cd145b15b837f7b722b199caa60e3057b36c141adee3b75e7
    ///   topic1 0x000000000000000000000000a231da16f77aaefa07427f13c6e03141eb15733a
    ///   data   0x...2710 (10000 sat) ...0001 (reason LOW_AMOUNT)
    #[test]
    fn solidity_release_request_rejected_matches_mainnet_3615279() {
        use alloy_primitives::hex;
        assert_eq!(
            hex::encode(solidity_topic("release_request_rejected(address,uint256,int256)")),
            "b607c3e1fbe6b38cd145b15b837f7b722b199caa60e3057b36c141adee3b75e7"
        );
        let sender: Address = "0xa231da16f77aaefa07427f13c6e03141eb15733a".parse().unwrap();
        assert_eq!(
            hex::encode(address_word(sender)),
            "000000000000000000000000a231da16f77aaefa07427f13c6e03141eb15733a"
        );
        // Pre-RSKIP427: data = uint256(amountSatoshis=10000) || int256(reason=1)
        let data = release_request_rejected_data(alloy_primitives::U256::from(10_000u64), 1);
        assert_eq!(
            hex::encode(&data),
            "0000000000000000000000000000000000000000000000000000000000002710\
             0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    /// Groundtruth from mainnet #4,212,341 tx 3 receipt (public-node.rsk.co):
    /// a value=0, empty-input EOA call to the Bridge is forwarded to
    /// `requestRelease` (NOT silently dropped) — zero is below the minimum
    /// peg-out value, so post-RSKIP185 it is rejected with LOW_AMOUNT(1),
    /// refunded (a no-op for 0 wei), and logged. This was the receipts-root
    /// divergence at #4,212,341: rustock had a `call_value_wei.is_zero()`
    /// early-return in `release_btc` that skipped the event entirely. Receipt:
    ///   topic0 0xb607c3e1fbe6b38cd145b15b837f7b722b199caa60e3057b36c141adee3b75e7
    ///   topic1 0x0000000000000000000000006338723180b802c5a5201f8ed12398eb7da31998
    ///   data   0x...00 (amount 0) ...01 (reason LOW_AMOUNT)
    #[test]
    fn solidity_release_request_rejected_zero_value_mainnet_4212341() {
        use alloy_primitives::hex;
        let sender: Address = "0x6338723180b802c5a5201f8ed12398eb7da31998".parse().unwrap();
        assert_eq!(
            hex::encode(address_word(sender)),
            "0000000000000000000000006338723180b802c5a5201f8ed12398eb7da31998"
        );
        // Pre-RSKIP427: data = uint256(amountSatoshis=0) || int256(reason=1)
        let data = release_request_rejected_data(alloy_primitives::U256::ZERO, 1);
        assert_eq!(
            hex::encode(&data),
            "0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    /// Post-RSKIP427 (lovell700) the `release_request_rejected` amount is the
    /// full wei value, not satoshis. 10,000 sat * 1e10 = 1e14 wei =
    /// 0x5af3107a4000. Signature is unchanged.
    #[test]
    fn release_request_rejected_post_rskip427_amount_is_wei() {
        use alloy_primitives::hex;
        let wei = alloy_primitives::U256::from(10_000u64) * alloy_primitives::U256::from(10_000_000_000u64);
        let data = release_request_rejected_data(wei, 1);
        assert_eq!(
            hex::encode(&data),
            "00000000000000000000000000000000000000000000000000005af3107a4000\
             0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    /// Groundtruth from mainnet #3,615,289 tx 0 receipt (public-node.rsk.co):
    /// a 400,000-sat direct RBTC transfer to the Bridge is ACCEPTED, enqueued,
    /// and logged with release_request_received (legacy variant; pre-RSKIP326
    /// destination = 20-byte hash160, pre-RSKIP427 amount in satoshis). Receipt:
    ///   topic0 0x8e04e2f2c246a91202761c435d6a4971bdc7af0617f0c739d900ecd12a6d7266
    ///   topic1 0x000000000000000000000000a231da16f77aaefa07427f13c6e03141eb15733a
    ///   data   offset(0x40) || 0x061a80 (400000 sat) || len(0x14) || hash160
    #[test]
    fn release_request_received_matches_mainnet_3615289() {
        use alloy_primitives::hex;
        assert_eq!(
            hex::encode(solidity_topic("release_request_received(address,bytes,uint256)")),
            "8e04e2f2c246a91202761c435d6a4971bdc7af0617f0c739d900ecd12a6d7266"
        );
        let sender: Address = "0xa231da16f77aaefa07427f13c6e03141eb15733a".parse().unwrap();
        assert_eq!(
            hex::encode(address_word(sender)),
            "000000000000000000000000a231da16f77aaefa07427f13c6e03141eb15733a"
        );
        let hash160: [u8; 20] =
            hex::decode("79d6308c3be90264f36cfd1457dbea5f4a6a2cce").unwrap().try_into().unwrap();
        // Pre-RSKIP326 dynamic field = the 20-byte hash160; amount = 400000 sat.
        let data = release_request_received_data(&hash160, alloy_primitives::U256::from(400_000u64));
        assert_eq!(
            hex::encode(&data),
            "0000000000000000000000000000000000000000000000000000000000000040\
             0000000000000000000000000000000000000000000000000000000000061a80\
             0000000000000000000000000000000000000000000000000000000000000014\
             79d6308c3be90264f36cfd1457dbea5f4a6a2cce000000000000000000000000"
        );
    }

    /// Post-RSKIP326 (fingerroot500) the `release_request_received` destination
    /// is the Base58 address STRING and the signature switches the second arg
    /// from `bytes` to `string`. Post-RSKIP427 (lovell700) the amount becomes
    /// full wei. This checks the new topic + the string-encoded data layout for
    /// a mainnet P2PKH address (version 0) over hash160 79d6308c…2cce.
    #[test]
    fn release_request_received_post_rskip326_427_string_and_wei() {
        use alloy_primitives::hex;
        // New (post-326) topic differs from the legacy one.
        let topic_326 = hex::encode(solidity_topic("release_request_received(address,string,uint256)"));
        assert_ne!(topic_326, "8e04e2f2c246a91202761c435d6a4971bdc7af0617f0c739d900ecd12a6d7266");
        // Base58 P2PKH of the hash160 (mainnet version 0).
        let mut payload = [0u8; 21];
        payload[1..].copy_from_slice(
            &hex::decode("79d6308c3be90264f36cfd1457dbea5f4a6a2cce").unwrap(),
        );
        let base58 = bitcoin::base58::encode_check(&payload);
        assert!(base58.starts_with('1'), "mainnet P2PKH addresses start with 1");
        // Post-427 amount = 400000 sat * 1e10 wei.
        let wei = alloy_primitives::U256::from(400_000u64) * alloy_primitives::U256::from(10_000_000_000u64);
        let data = release_request_received_data(base58.as_bytes(), wei);
        // Head: offset 0x40, amount, then length-prefixed string padded.
        let len = base58.len();
        assert_eq!(&data[0..32], &u256_word(alloy_primitives::U256::from(64u64)));
        assert_eq!(&data[32..64], &u256_word(wei));
        assert_eq!(&data[64..96], &u256_word(alloy_primitives::U256::from(len as u64)));
        assert_eq!(&data[96..96 + len], base58.as_bytes());
        assert_eq!(data.len(), 96 + len.next_multiple_of(32));
    }

    /// rskj `BridgeEvents.REJECTED_PEGIN` topic0 = keccak256 of the canonical
    /// signature `rejected_pegin(bytes32,int256)` (rskj `BridgeEventLoggerImplTest`
    /// derives the topic the same way). Data = int256(reason). Topic1 (indexed
    /// btcTxHash) = `btcTx.getHash().getBytes()` (display-order legacy txid).
    #[test]
    fn rejected_pegin_topic_and_data() {
        use alloy_primitives::hex;
        assert_eq!(
            hex::encode(solidity_topic("rejected_pegin(bytes32,int256)")),
            "708ce1ead20561c5894a93be3fee64b326b2ad6c198f8253e4bb56f1626053d6"
        );
        // Data is a single int256 word holding the reason enum value
        // (PEGIN_CAP_SURPASSED=1, LEGACY_PEGIN_MULTISIG_SENDER=2, ...).
        assert_eq!(
            hex::encode(u256_word(alloy_primitives::U256::from(1u64))),
            "0000000000000000000000000000000000000000000000000000000000000001"
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
