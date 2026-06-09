//! Bridge storage provider — journal-based read/write for Bridge contract state.
//!
//! Mirrors rskj's `BridgeStorageProvider` and `FederationStorageProvider`.
//! All keys use `DataWord.fromString` encoding (same as REMASC storage keys).
//! Compound keys use `DataWord.fromLongString` (SHA3 of the concatenated string).

use alloy_primitives::{Address, B256, U256};
use revm::context_interface::JournalTr;
use sha3::{Digest, Keccak256};

use crate::precompiles::BRIDGE_ADDR;

// ---------------------------------------------------------------------------
// Key encoding (matches rskj DataWord.fromString / fromLongString)
// ---------------------------------------------------------------------------

/// Encode a short key (≤32 bytes) as rskj's `DataWord.fromString`:
/// UTF-8 bytes right-aligned in a 32-byte big-endian word.
pub fn bridge_storage_key(name: &str) -> U256 {
    let bytes = name.as_bytes();
    debug_assert!(bytes.len() <= 32, "key must be ≤32 bytes");
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    U256::from_be_bytes(buf)
}

/// Encode a long key (>32 bytes or compound) as rskj's `DataWord.fromLongString`:
/// Keccak256 hash of the UTF-8 bytes.
pub fn bridge_storage_key_long(name: &str) -> U256 {
    let hash = Keccak256::digest(name.as_bytes());
    U256::from_be_bytes(hash.into())
}

/// Build a compound key: `base_key + delimiter + identifier`, then hash.
/// Matches rskj's `BridgeStorageIndexKey.getCompoundKey(delimiter, identifier)`.
pub fn compound_key(base: &str, delimiter: &str, identifier: &str) -> U256 {
    let combined = format!("{}{}{}", base, delimiter, identifier);
    if combined.len() <= 32 {
        bridge_storage_key(&combined)
    } else {
        bridge_storage_key_long(&combined)
    }
}

// ---------------------------------------------------------------------------
// Bridge storage index keys (from rskj BridgeStorageIndexKey)
// ---------------------------------------------------------------------------

pub const BTC_TX_HASHES_ALREADY_PROCESSED_KEY: &str = "btcTxHashesAP";
pub const RELEASE_REQUEST_QUEUE_KEY: &str = "releaseRequestQueue";
pub const PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY: &str = "releaseTransactionSet";
pub const RELEASES_OUTPOINTS_VALUES_KEY: &str = "releasesOutpointsValues";
pub const PEGOUTS_WAITING_FOR_SIGNATURES_KEY: &str = "rskTxsWaitingFS";
pub const RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY: &str = "releaseRequestQueueWithTxHash";
pub const PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY: &str = "releaseTransactionSetWithTxHash";
pub const RECEIVE_HEADERS_TIMESTAMP_KEY: &str = "receiveHeadersLastTimestamp";
pub const NEXT_PEGOUT_HEIGHT_KEY: &str = "nextPegoutHeight";

// Compound key bases
pub const BTC_TX_HASH_AP_KEY: &str = "btcTxHashAP";
pub const COINBASE_INFORMATION_KEY: &str = "coinbaseInformation";
pub const BTC_BLOCK_HEIGHT_KEY: &str = "btcBlockHeight";
pub const FAST_BRIDGE_HASH_USED_KEY: &str = "fastBridgeHashUsedInBtcTx";
pub const FAST_BRIDGE_FEDERATION_INFO_KEY: &str = "fastBridgeFederationInformation";
pub const PEGOUT_TX_SIG_HASH_KEY: &str = "pegoutTxSigHash";

// SVP keys
pub const SVP_FUND_TX_HASH_UNSIGNED_KEY: &str = "svpFundTxHashUnsigned";
pub const SVP_FUND_TX_SIGNED_KEY: &str = "svpFundTxSigned";
pub const SVP_SPEND_TX_HASH_UNSIGNED_KEY: &str = "svpSpendTxHashUnsigned";
pub const SVP_SPEND_TX_WAITING_FOR_SIGNATURES_KEY: &str = "svpSpendTxWaitingForSignatures";

// ---------------------------------------------------------------------------
// Whitelist storage keys (from rskj WhitelistStorageIndexKey)
// ---------------------------------------------------------------------------

/// One-off lock whitelist key ("lockWhitelist" = 13 bytes, fromString encoding).
pub const LOCK_WHITELIST_KEY: &str = "lockWhitelist";
/// Unlimited lock whitelist key ("unlimitedLockWhitelist" = 22 bytes, fromString encoding).
/// Active post-RSKIP87 (Orchid).
pub const UNLIMITED_LOCK_WHITELIST_KEY: &str = "unlimitedLockWhitelist";

// BTC block store
pub const BLOCK_STORE_CHAIN_HEAD_KEY: &str = "blockStoreChainHead";

// Fee governance
pub const FEE_PER_KB_KEY: &str = "feePerKb";

// ---------------------------------------------------------------------------
// Federation storage index keys (from rskj FederationStorageIndexKey)
// ---------------------------------------------------------------------------

pub const NEW_FEDERATION_BTC_UTXOS_KEY: &str = "newFederationBtcUTXOs";
pub const NEW_FEDERATION_BTC_UTXOS_TESTNET_PRE_HOP_KEY: &str = "newFederationBtcUTXOsForTestnet";
pub const NEW_FEDERATION_BTC_UTXOS_TESTNET_POST_HOP_KEY: &str = "newFedBtcUTXOsForTestnetPostHop";
pub const OLD_FEDERATION_BTC_UTXOS_KEY: &str = "oldFederationBtcUTXOs";

pub const NEW_FEDERATION_KEY: &str = "newFederation";
pub const OLD_FEDERATION_KEY: &str = "oldFederation";
pub const PENDING_FEDERATION_KEY: &str = "pendingFederation";
pub const PROPOSED_FEDERATION_KEY: &str = "proposedFederation";

pub const FEDERATION_ELECTION_KEY: &str = "federationElection";
pub const ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY: &str = "activeFedCreationBlockHeight";
pub const NEXT_FEDERATION_CREATION_BLOCK_HEIGHT_KEY: &str = "nextFedCreationBlockHeight";
pub const LAST_RETIRED_FEDERATION_P2SH_SCRIPT_KEY: &str = "lastRetiredFedP2SHScript";

// Federation format version keys
pub const NEW_FEDERATION_FORMAT_VERSION_KEY: &str = "newFederationFormatVersion";
pub const OLD_FEDERATION_FORMAT_VERSION_KEY: &str = "oldFederationFormatVersion";
pub const PENDING_FEDERATION_FORMAT_VERSION_KEY: &str = "pendingFederationFormatVersion";
pub const PROPOSED_FEDERATION_FORMAT_VERSION_KEY: &str = "proposedFederationFormatVersion";

// ---------------------------------------------------------------------------
// Raw-bytes read/write helpers (rskj addStorageBytes / getStorageBytes:
// one variable-length value per unitrie key, via the RawStorage overlay)
// ---------------------------------------------------------------------------

/// Read a raw-bytes Bridge storage entry (rskj `getStorageBytes`).
pub fn bridge_load_raw<CTX: crate::RskContextTr>(ctx: &mut CTX, key: U256) -> Option<Vec<u8>> {
    ctx.chain_mut().raw_storage.get(BRIDGE_ADDR, key)
}

/// Write a raw-bytes Bridge storage entry (rskj `addStorageBytes`):
/// `None`/empty deletes the trie node.
pub fn bridge_store_raw<CTX: crate::RskContextTr>(ctx: &mut CTX, key: U256, value: Option<Vec<u8>>) {
    ctx.chain_mut().raw_storage.put(BRIDGE_ADDR, key, value);
}

/// rskj `RLP.encodeBigInteger` for unsigned scalars (the encoding behind
/// BridgeSerializationUtils serializeCoin/serializeLong/serializeInteger):
/// minimal big-endian bytes as an RLP element; zero encodes as `0x80`.
pub fn rlp_encode_uint(value: U256) -> Vec<u8> {
    let be = value.to_be_bytes::<32>();
    let start = be.iter().position(|&b| b != 0).unwrap_or(32);
    super::serialization::rlp_encode_element(&be[start..])
}

/// Inverse of [`rlp_encode_uint`]; empty data is zero.
pub fn rlp_decode_uint(data: &[u8]) -> U256 {
    if data.is_empty() {
        return U256::ZERO;
    }
    if data[0] < 0x80 {
        return U256::from(data[0]);
    }
    let len = (data[0] - 0x80) as usize;
    if len == 0 || len > 32 || data.len() < 1 + len {
        return U256::ZERO;
    }
    let mut buf = [0u8; 32];
    buf[32 - len..].copy_from_slice(&data[1..1 + len]);
    U256::from_be_bytes(buf)
}

/// Read an RLP-encoded unsigned scalar entry (rskj deserializeCoin/Long/Integer).
pub fn bridge_load_u256<CTX: crate::RskContextTr>(ctx: &mut CTX, key_name: &str) -> U256 {
    let key = bridge_storage_key(key_name);
    match bridge_load_raw(ctx, key) {
        Some(data) => rlp_decode_uint(&data),
        None => U256::ZERO,
    }
}

/// Write an RLP-encoded unsigned scalar entry (rskj serializeCoin/Long/Integer).
pub fn bridge_store_u256<CTX: crate::RskContextTr>(ctx: &mut CTX, key_name: &str, value: U256) {
    let key = bridge_storage_key(key_name);
    bridge_store_raw(ctx, key, Some(rlp_encode_uint(value)));
}

/// Read a timestamp (rskj serializeLong -> RLP).
pub fn bridge_load_timestamp<CTX: crate::RskContextTr>(ctx: &mut CTX, key_name: &str) -> u64 {
    bridge_load_u256(ctx, key_name).to::<u64>()
}

/// Write a timestamp (rskj serializeLong -> RLP).
pub fn bridge_store_timestamp<CTX: crate::RskContextTr>(ctx: &mut CTX, key_name: &str, value: u64) {
    bridge_store_u256(ctx, key_name, U256::from(value));
}

/// Read a BTC main-chain block hash by height (RSKIP199 index; rskj
/// `getBtcBestBlockHashByHeight` -- value is `RLP.encodeElement(hash)`).
pub fn bridge_load_btc_block_hash_by_height<CTX: crate::RskContextTr>(ctx: &mut CTX, height: u32) -> Option<B256> {
    let key = compound_key(BTC_BLOCK_HEIGHT_KEY, "-", &format!("{:x}", height));
    let data = bridge_load_raw(ctx, key)?;
    // RLP element: 0xa0 || 32-byte hash
    if data.len() == 33 && data[0] == 0xa0 {
        Some(B256::from_slice(&data[1..]))
    } else {
        None
    }
}

/// Store a BTC main-chain block hash by height (RSKIP199 index; rskj
/// `setBtcBestBlockHashByHeight` -- serializeSha256Hash = RLP element).
pub fn bridge_store_btc_block_hash_by_height<CTX: crate::RskContextTr>(ctx: &mut CTX, height: u32, hash: B256) {
    let key = compound_key(BTC_BLOCK_HEIGHT_KEY, "-", &format!("{:x}", height));
    let value = super::serialization::rlp_encode_element(hash.as_slice());
    bridge_store_raw(ctx, key, Some(value));
}

/// Write a serialized byte-array entry (rskj `addStorageBytes`).
pub fn bridge_store_bytes<CTX: crate::RskContextTr>(ctx: &mut CTX, key: U256, value: &[u8]) {
    bridge_store_raw(ctx, key, Some(value.to_vec()));
}

/// Read a serialized byte-array entry (rskj `getStorageBytes`; absent -> empty).
pub fn bridge_load_bytes<CTX: crate::RskContextTr>(ctx: &mut CTX, key: U256) -> Vec<u8> {
    bridge_load_raw(ctx, key).unwrap_or_default()
}

/// Store a variable-length byte array at a named key.
pub fn bridge_store_bytes_named<CTX: crate::RskContextTr>(ctx: &mut CTX, key_name: &str, value: &[u8]) {
    let key = bridge_storage_key(key_name);
    bridge_store_bytes(ctx, key, value);
}

/// Load a variable-length byte array from a named key.
pub fn bridge_load_bytes_named<CTX: crate::RskContextTr>(ctx: &mut CTX, key_name: &str) -> Vec<u8> {
    let key = bridge_storage_key(key_name);
    bridge_load_bytes(ctx, key)
}

/// Transfer amount from Bridge contract to recipient.
pub fn bridge_transfer<CTX: crate::RskContextTr>(ctx: &mut CTX, recipient: Address, amount: U256) -> bool {
    if amount.is_zero() {
        return true;
    }
    matches!(
        ctx.journal_mut().transfer(BRIDGE_ADDR, recipient, amount),
        Ok(None)
    )
}

// ---------------------------------------------------------------------------
// Whitelist serialization helpers
//
// Format (rskj BridgeSerializationUtils.serializeOneOffLockWhitelist):
//   RLP_list [ hash160_0, bigint(maxVal_0), hash160_1, bigint(maxVal_1), ..., bigint(disableBlockHeight) ]
//
// Format (rskj BridgeSerializationUtils.serializeUnlimitedLockWhitelist):
//   RLP_list [ hash160_0, hash160_1, ... ]
// ---------------------------------------------------------------------------

/// Serialize one-off whitelist entries with disable block height.
///
/// Matches rskj's `BridgeSerializationUtils.serializeOneOffLockWhitelist`.
/// `entries`: (BTC hash160, max transfer value in satoshis); rskj's
/// `LockWhitelist` keeps them in a `TreeMap` ordered by
/// `Address.getHash160()` (`UnsignedBytes.lexicographicalComparator`), so the
/// serialized list is sorted by hash160 ascending — independent of insertion
/// order.
/// `disable_height`: BTC height at which the whitelist turns off
/// (`i32::MAX` = not set, matching rskj's LockWhitelist default).
pub fn serialize_one_off_whitelist(entries: &[([u8; 20], u64)], disable_height: i32) -> Vec<u8> {
    use super::serialization::{rlp_encode_element, rlp_encode_list, rlp_encode_u64};

    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by(|&a, &b| entries[a].0.cmp(&entries[b].0));

    let size = entries.len() * 2 + 1;
    let mut items = Vec::with_capacity(size);

    for &i in &order {
        let (hash160, max_val) = &entries[i];
        items.push(rlp_encode_element(hash160));
        items.push(rlp_encode_u64(*max_val));
    }

    // rskj stores the raw disableBlockHeight int (Integer.MAX_VALUE when
    // never set); it is never negative.
    items.push(rlp_encode_u64(disable_height.max(0) as u64));

    rlp_encode_list(&items)
}

/// Deserialize one-off whitelist entries with disable block height.
///
/// Returns (entries: Vec<(hash160, max_val_satoshis)>, disable_height).
pub fn deserialize_one_off_whitelist(data: &[u8]) -> Option<(Vec<([u8; 20], u64)>, i32)> {
    use super::serialization::{rlp_decode_list, rlp_decode_u64};

    // Missing/empty storage means the whitelist was never written: rskj's
    // LockWhitelist then defaults disableBlockHeight to Integer.MAX_VALUE
    // (whitelist ACTIVE and empty).
    if data.is_empty() {
        return Some((Vec::new(), i32::MAX));
    }

    let items = rlp_decode_list(data)?;
    if items.is_empty() {
        return Some((Vec::new(), i32::MAX));
    }

    // Last item is disable block height; rest are (hash160, max_val) pairs
    let entry_count = (items.len() - 1) / 2;
    let mut entries = Vec::with_capacity(entry_count);

    for i in 0..entry_count {
        let hash_bytes = &items[i * 2];
        let val_bytes = &items[i * 2 + 1];
        if hash_bytes.len() != 20 {
            return None;
        }
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(hash_bytes);
        let max_val = rlp_decode_u64(val_bytes);
        entries.push((hash160, max_val));
    }

    let disable_height = rlp_decode_u64(items.last()?) as i32;

    Some((entries, disable_height))
}

/// Serialize unlimited whitelist entries.
///
/// Matches rskj's `BridgeSerializationUtils.serializeUnlimitedLockWhitelist`.
pub fn serialize_unlimited_whitelist(entries: &[[u8; 20]]) -> Vec<u8> {
    use super::serialization::{rlp_encode_element, rlp_encode_list};

    // rskj's LockWhitelist is a TreeMap keyed by hash160
    // (UnsignedBytes.lexicographicalComparator), so entries serialize sorted
    // by hash160 ascending regardless of insertion order.
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();
    let items: Vec<Vec<u8>> = sorted.iter().map(|h| rlp_encode_element(h)).collect();
    rlp_encode_list(&items)
}

/// Deserialize unlimited whitelist entries.
///
/// Returns Vec of BTC hash160 values.
pub fn deserialize_unlimited_whitelist(data: &[u8]) -> Vec<[u8; 20]> {
    use super::serialization::rlp_decode_list;

    if data.is_empty() {
        return Vec::new();
    }

    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return Vec::new(),
    };

    items
        .into_iter()
        .filter_map(|b| {
            if b.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&b);
                Some(arr)
            } else {
                None
            }
        })
        .collect()
}

/// Load the one-off lock whitelist from Bridge storage.
pub fn load_one_off_whitelist<CTX: crate::RskContextTr>(ctx: &mut CTX) -> (Vec<([u8; 20], u64)>, i32) {
    let data = bridge_load_bytes_named(ctx, LOCK_WHITELIST_KEY);
    // rskj LockWhitelist defaults disableBlockHeight to Integer.MAX_VALUE:
    // an empty whitelist is ACTIVE (every legacy peg-in is rejected).
    deserialize_one_off_whitelist(&data).unwrap_or((Vec::new(), i32::MAX))
}

/// Store the one-off lock whitelist into Bridge storage.
pub fn store_one_off_whitelist<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    entries: &[([u8; 20], u64)],
    disable_height: i32,
) {
    let data = serialize_one_off_whitelist(entries, disable_height);
    bridge_store_bytes_named(ctx, LOCK_WHITELIST_KEY, &data);
}

/// Load the unlimited lock whitelist from Bridge storage.
pub fn load_unlimited_whitelist<CTX: crate::RskContextTr>(ctx: &mut CTX) -> Vec<[u8; 20]> {
    let data = bridge_load_bytes_named(ctx, UNLIMITED_LOCK_WHITELIST_KEY);
    deserialize_unlimited_whitelist(&data)
}

/// Store the unlimited lock whitelist into Bridge storage.
pub fn store_unlimited_whitelist<CTX: crate::RskContextTr>(ctx: &mut CTX, entries: &[[u8; 20]]) {
    let data = serialize_unlimited_whitelist(entries);
    bridge_store_bytes_named(ctx, UNLIMITED_LOCK_WHITELIST_KEY, &data);
}

// ---------------------------------------------------------------------------
// UTXO serialization
//
// Format matches co.rsk.bitcoinj.core.UTXO.serializeToStream:
//   value        (8 bytes, little-endian int64)
//   script_len   (1 byte for scripts ≤ 252 bytes; varint otherwise)
//   script       (N bytes)
//   hash         (32 bytes, as stored — big-endian SHA256d)
//   index        (4 bytes, little-endian uint32)
//   height       (4 bytes, little-endian int32)
//   coinbase     (1 byte, 0 = false)
// ---------------------------------------------------------------------------

/// A Bitcoin UTXO (unspent transaction output) stored in Bridge contract storage.
#[derive(Debug, Clone)]
pub struct BridgeUtxo {
    /// SHA256d hash of the transaction containing this output (big-endian internal bytes).
    pub tx_hash: [u8; 32],
    /// Output index in the transaction.
    pub vout: u32,
    /// Value in satoshis.
    pub value_satoshis: u64,
    /// Height of the block containing this UTXO.
    pub height: u32,
    /// ScriptPubKey of the output.
    pub script: Vec<u8>,
    /// Whether this output is a coinbase output.
    pub coinbase: bool,
}

/// Serialize a UTXO to bytes (bitcoinj `UTXO.serializeToStream` format):
/// value u64 LE | script length u32 LE (fixed width, NOT a varint) | script |
/// tx hash in DISPLAY order (bitcoinj `Sha256Hash` bytes) | index u32 LE |
/// height u32 LE | coinbase u8.
fn serialize_utxo(utxo: &BridgeUtxo) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&utxo.value_satoshis.to_le_bytes());
    buf.extend_from_slice(&(utxo.script.len() as u32).to_le_bytes());
    buf.extend_from_slice(&utxo.script);
    // bitcoinj `Transaction.getHash()` is a `Sha256Hash.wrapReversed(...)`, so
    // `UTXO.serializeToStream` writes `hash.getBytes()` already in display
    // order. `tx_hash` is kept in that same (display) order, so store it as-is
    // — reversing it produced the internal order, byte-diverging the
    // newFederationBtcUTXOs cell from rskj's unitrie.
    buf.extend_from_slice(&utxo.tx_hash);
    buf.extend_from_slice(&utxo.vout.to_le_bytes());
    buf.extend_from_slice(&utxo.height.to_le_bytes());
    buf.push(if utxo.coinbase { 1 } else { 0 });
    buf
}

/// Deserialize a UTXO from bytes.
fn deserialize_utxo(data: &[u8]) -> Option<BridgeUtxo> {
    if data.len() < 8 + 1 + 0 + 32 + 4 + 4 + 1 {
        return None;
    }

    let mut pos = 0;

    // value: 8 bytes LE
    let value_satoshis = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?);
    pos += 8;

    // script length: fixed 4-byte LE (bitcoinj UTXO format)
    if pos + 4 > data.len() { return None; }
    let script_len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;

    if pos + script_len > data.len() { return None; }
    let script = data[pos..pos + script_len].to_vec();
    pos += script_len;

    if pos + 32 > data.len() { return None; }
    let tx_hash: [u8; 32] = data[pos..pos + 32].try_into().ok()?;
    pos += 32;

    if pos + 4 > data.len() { return None; }
    let vout = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
    pos += 4;

    if pos + 4 > data.len() { return None; }
    let height = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
    pos += 4;

    if pos >= data.len() { return None; }
    let coinbase = data[pos] != 0;

    Some(BridgeUtxo { tx_hash, vout, value_satoshis, height, script, coinbase })
}

/// Serialize a list of UTXOs (RLP list of RLP-encoded UTXO blobs).
///
/// Matches rskj's `BridgeSerializationUtils.serializeUTXOList`.
pub fn serialize_utxo_list(utxos: &[BridgeUtxo]) -> Vec<u8> {
    use super::serialization::{rlp_encode_element, rlp_encode_list};

    let items: Vec<Vec<u8>> = utxos
        .iter()
        .map(|u| rlp_encode_element(&serialize_utxo(u)))
        .collect();
    rlp_encode_list(&items)
}

/// Deserialize a list of UTXOs from RLP.
///
/// Matches rskj's `BridgeSerializationUtils.deserializeUTXOList`.
pub fn deserialize_utxo_list(data: &[u8]) -> Vec<BridgeUtxo> {
    use super::serialization::rlp_decode_list;

    if data.is_empty() {
        return Vec::new();
    }

    let items = match rlp_decode_list(data) {
        Some(v) => v,
        None => return Vec::new(),
    };

    items.into_iter().filter_map(|b| deserialize_utxo(&b)).collect()
}

/// Load the active federation's BTC UTXOs from Bridge storage.
pub fn load_federation_utxos<CTX: crate::RskContextTr>(ctx: &mut CTX) -> Vec<BridgeUtxo> {
    let data = bridge_load_bytes_named(ctx, NEW_FEDERATION_BTC_UTXOS_KEY);
    deserialize_utxo_list(&data)
}

/// Store the OLD (retiring) federation's BTC UTXOs into Bridge storage.
pub fn store_old_federation_utxos<CTX: crate::RskContextTr>(ctx: &mut CTX, utxos: &[BridgeUtxo]) {
    let data = serialize_utxo_list(utxos);
    bridge_store_bytes_named(ctx, OLD_FEDERATION_BTC_UTXOS_KEY, &data);
}

/// Load the OLD (retiring) federation's BTC UTXOs.
pub fn load_old_federation_utxos<CTX: crate::RskContextTr>(ctx: &mut CTX) -> Vec<BridgeUtxo> {
    let data = bridge_load_bytes_named(ctx, OLD_FEDERATION_BTC_UTXOS_KEY);
    deserialize_utxo_list(&data)
}

/// Store the active federation's BTC UTXOs into Bridge storage.
pub fn store_federation_utxos<CTX: crate::RskContextTr>(ctx: &mut CTX, utxos: &[BridgeUtxo]) {
    let data = serialize_utxo_list(utxos);
    bridge_store_bytes_named(ctx, NEW_FEDERATION_BTC_UTXOS_KEY, &data);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Groundtruth from mainnet #3304: a second `addLockWhitelistAddress` makes
    /// the one-off whitelist hold two entries, and rskj serializes them in its
    /// `HashMap<Address,_>` iteration order — NOT insertion order. Entries are
    /// inserted [a344… (#3303), 54f6be… (#3304)] but the on-chain bytes put
    /// 54f6be first. Validated by the pre-RSKIP126 (orchid) state root at
    /// #3304 matching the mainnet header.
    #[test]
    fn one_off_whitelist_sorted_by_hash160_3304() {
        let a344 = hex_to_20("a344a19d31b92bd0f0077eb0553e7b48ce738f34");
        let f6be = hex_to_20("54f6be1e1ef1dae347a47972103d1e0f8d235c5b");
        // Inserted [a344, 54f6be] but serialized sorted by hash160 ascending
        // (0x54.. < 0xa3..), max value 1e9, disable = MAX. Groundtruth #3304.
        let out = serialize_one_off_whitelist(&[(a344, 1_000_000_000), (f6be, 1_000_000_000)], i32::MAX);
        assert_eq!(
            alloy_primitives::hex::encode(&out),
            "f8399454f6be1e1ef1dae347a47972103d1e0f8d235c5b843b9aca0094a344a19d31b92bd0f0077eb0553e7b48ce738f34843b9aca00847fffffff"
        );
    }

    /// Byte-exact ground truth: the mainnet one-off `lockWhitelist` cell at
    /// #1,590,999 (7 entries) — dumped from a synced rskj unitrie. Feeding the
    /// entries scrambled must reproduce rskj's bytes (sorted by hash160), which
    /// a Java-HashMap ordering would not for 7 entries.
    #[test]
    fn rskj_one_off_whitelist_sorted_groundtruth_1590999() {
        use alloy_primitives::hex;
        let rskj = hex::decode(
            "f8bb9403c6fea3c7907b95312ef0f426c32fca56caa3e3843b9aca00943cdc5e1928a1efc9\
             4d0c7c39fcc3e7491757b3d9843b9aca00945ca39d0128aca2c6b84529ad27c3f4064d233c60\
             843b9aca0094a7ca049069dfbf48b1d199348385c94dd92dcc6b843b9aca0094b298512d102b\
             4e642c6c511781d9cbf7bf5e3a37843b9aca0094cebb2851a9c7cfe2582c12ecaf7f3ff4383d\
             1dc0843b9aca0094f8bcb4cca48194b12d173e87e1323195ac36b78e843b9aca00847fffffff",
        ).unwrap();
        let (mut entries, disable) = deserialize_one_off_whitelist(&rskj).unwrap();
        assert_eq!(entries.len(), 7);
        assert_eq!(disable, i32::MAX);
        entries.reverse(); // scramble
        assert_eq!(serialize_one_off_whitelist(&entries, disable), rskj);
    }

    /// Byte-exact ground truth: the mainnet `unlimitedLockWhitelist` cell at
    /// #1,590,999 (17 entries). Scrambled input must reproduce rskj's bytes.
    #[test]
    fn rskj_unlimited_whitelist_sorted_groundtruth_1590999() {
        use alloy_primitives::hex;
        let rskj = hex::decode(
            "f901659400cfa4fb2adbef0e3f25af5259b1492f394f073e941a906a2b7f8afbf6a7ebb4c2e\
             4868cdc8008bcb59422843c7a3977c7e1ca2a14cd60bb0b25bedfb851943301648cdf96ebff17\
             81631125828f8fa783e55e948bdfd9f9014183674a3906d085231b856e09a722949d1b66dbad1\
             39fa294c47c83415d302f96ce437694aeac85aa74701e3744fd72bf3d5f7b04aab7111b94b8a9\
             6cc5ce2a670cc0d601bf35e871e69bd5364f94bad8369d720c3d6d3f5ebff8666d786fd317030c\
             94c685d3bc07a5411a9731516e74e082dc7447548294c825a1ecf2a6830c4401620c3a16f19950\
             57c2ab94c83874014a9e10b1533d43f0f485b4dbc45449d394c931202b0968fdbc4030b2abce46\
             e0286530b0c194d1919c38b5613a11d62706029b126dd186c589a294e136bc6703ba25ff58b7ef\
             530d47f5cb9bc4769494e8e0b6af4b0be3212369c382cce3dee39a6fa84c94f5c4d9f264488827\
             3cdc7ef706f81b1def114b95",
        ).unwrap();
        let mut entries = deserialize_unlimited_whitelist(&rskj);
        assert_eq!(entries.len(), 17);
        entries.reverse(); // scramble
        assert_eq!(serialize_unlimited_whitelist(&entries), rskj);
    }

    /// A single entry is order-independent (groundtruth: mainnet #3303 root).
    #[test]
    fn one_off_whitelist_single_entry() {
        let a344 = hex_to_20("a344a19d31b92bd0f0077eb0553e7b48ce738f34");
        let out = serialize_one_off_whitelist(&[(a344, 1_000_000_000)], i32::MAX);
        assert_eq!(
            alloy_primitives::hex::encode(&out),
            "df94a344a19d31b92bd0f0077eb0553e7b48ce738f34843b9aca00847fffffff"
        );
    }

    fn hex_to_20(s: &str) -> [u8; 20] {
        let v = alloy_primitives::hex::decode(s).unwrap();
        let mut a = [0u8; 20];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn storage_key_short() {
        let key = bridge_storage_key("btcTxHashesAP");
        let bytes = key.to_be_bytes::<32>();
        assert_eq!(&bytes[32 - 13..], b"btcTxHashesAP");
        assert_eq!(&bytes[..19], &[0u8; 19]);
    }

    #[test]
    fn storage_key_chain_head() {
        let key = bridge_storage_key(BLOCK_STORE_CHAIN_HEAD_KEY);
        let bytes = key.to_be_bytes::<32>();
        let expected = b"blockStoreChainHead";
        assert_eq!(&bytes[32 - expected.len()..], expected);
    }

    #[test]
    fn compound_key_btc_height() {
        let key = compound_key(BTC_BLOCK_HEIGHT_KEY, "-", "ff");
        // "btcBlockHeight-ff" is 17 bytes, fits in 32, so uses fromString
        let bytes = key.to_be_bytes::<32>();
        assert_eq!(&bytes[32 - 17..], b"btcBlockHeight-ff");
    }

    #[test]
    fn compound_key_long_hashes() {
        // A compound key with a long identifier should use keccak256
        let long_id = "aabbccdd11223344aabbccdd11223344";
        let key = compound_key(BTC_TX_HASH_AP_KEY, "-", long_id);
        // "btcTxHashAP-" + 32 hex chars = 43 bytes > 32, so hashed
        let expected = bridge_storage_key_long(&format!("btcTxHashAP-{}", long_id));
        assert_eq!(key, expected);
    }

    #[test]
    fn all_bridge_keys_are_short_enough() {
        let keys = [
            BTC_TX_HASHES_ALREADY_PROCESSED_KEY,
            RELEASE_REQUEST_QUEUE_KEY,
            PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY,
            RELEASES_OUTPOINTS_VALUES_KEY,
            PEGOUTS_WAITING_FOR_SIGNATURES_KEY,
            RECEIVE_HEADERS_TIMESTAMP_KEY,
            NEXT_PEGOUT_HEIGHT_KEY,
            BLOCK_STORE_CHAIN_HEAD_KEY,
        ];
        for k in &keys {
            assert!(k.len() <= 32, "Key too long: {k}");
        }
    }

    #[test]
    fn all_federation_keys_are_short_enough() {
        let keys = [
            NEW_FEDERATION_BTC_UTXOS_KEY,
            OLD_FEDERATION_BTC_UTXOS_KEY,
            NEW_FEDERATION_KEY,
            OLD_FEDERATION_KEY,
            PENDING_FEDERATION_KEY,
            PROPOSED_FEDERATION_KEY,
            FEDERATION_ELECTION_KEY,
            ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY,
        ];
        for k in &keys {
            assert!(k.len() <= 32, "Key too long: {k}");
        }
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj
    // -----------------------------------------------------------------------

    /// Ported from rskj DataWordTest.testFromString — verifies that a
    /// 32-byte ASCII key is stored as-is (right-aligned, no hashing).
    #[test]
    fn rskj_from_string_32_byte_key() {
        let input = "01234567890123456789012345678901";
        assert_eq!(input.len(), 32);
        let key = bridge_storage_key(input);
        let bytes = key.to_be_bytes::<32>();
        assert_eq!(&bytes, input.as_bytes());
    }

    /// Ported from rskj DataWordTest.testFromString — short keys are
    /// right-aligned with leading zeros.
    #[test]
    fn rskj_from_string_short_key_right_aligned() {
        let input = "hello";
        let key = bridge_storage_key(input);
        let bytes = key.to_be_bytes::<32>();
        assert_eq!(&bytes[27..], b"hello");
        assert_eq!(&bytes[..27], &[0u8; 27]);
    }

    /// Ported from rskj DataWordTest.testFromLongString — verifies that
    /// long keys are Keccak256 hashed.
    #[test]
    fn rskj_from_long_string_is_keccak256() {
        let value = "012345678901234567890123456789012345678901234567890123456789";
        assert!(value.len() > 32);
        let key = bridge_storage_key_long(value);

        let expected_hash = Keccak256::digest(value.as_bytes());
        let expected = U256::from_be_bytes(expected_hash.into());
        assert_eq!(key, expected);
    }

    /// Verify compound_key switches from fromString to fromLongString at
    /// the 32-byte boundary (matching rskj's BridgeStorageIndexKey behavior).
    #[test]
    fn rskj_compound_key_boundary() {
        // Short compound: "btcBlockHeight-ff" = 17 bytes → fromString
        let short = compound_key("btcBlockHeight", "-", "ff");
        let short_bytes = short.to_be_bytes::<32>();
        assert_eq!(&short_bytes[32 - 17..], b"btcBlockHeight-ff");

        // Long compound: key + delimiter + 64-char hash → >32 bytes → keccak256
        let long_id = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
        let long_key = compound_key("btcTxHashAP", "-", long_id);
        let combined = format!("btcTxHashAP-{}", long_id);
        assert!(combined.len() > 32);
        let expected = bridge_storage_key_long(&combined);
        assert_eq!(long_key, expected);
    }

    /// Verify that the chain head key "blockStoreChainHead" produces the
    /// same storage slot as rskj's DataWord.fromString("blockStoreChainHead").
    #[test]
    fn rskj_chain_head_key_matches() {
        let key = bridge_storage_key("blockStoreChainHead");
        let bytes = key.to_be_bytes::<32>();
        // "blockStoreChainHead" = 19 bytes, right-aligned
        assert_eq!(&bytes[13..], b"blockStoreChainHead");
        assert_eq!(&bytes[..13], &[0u8; 13]);
    }

    /// Verify that concrete Bridge storage key names produce consistent
    /// encodings (regression test).
    #[test]
    fn rskj_bridge_storage_keys_deterministic() {
        let keys_and_lengths = [
            ("btcTxHashesAP", 13),
            ("releaseRequestQueue", 19),
            ("releaseTransactionSet", 21),
            ("rskTxsWaitingFS", 15),
            ("receiveHeadersLastTimestamp", 27),
            ("newFederation", 13),
            ("oldFederation", 13),
            ("pendingFederation", 17),
            ("federationElection", 18),
            ("lockWhitelist", 13),
            ("unlimitedLockWhitelist", 22),
        ];
        for (name, expected_len) in &keys_and_lengths {
            assert_eq!(name.len(), *expected_len, "key length mismatch for {name}");
            let key = bridge_storage_key(name);
            let bytes = key.to_be_bytes::<32>();
            assert_eq!(&bytes[32 - expected_len..], name.as_bytes());
            for &b in &bytes[..32 - expected_len] {
                assert_eq!(b, 0, "non-zero leading byte for key {name}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Whitelist serialization tests — ported from rskj
    // WhitelistStorageProviderImplTest.java
    // -----------------------------------------------------------------------

    #[test]
    fn rskj_whitelist_one_off_empty_roundtrip() {
        let data = serialize_one_off_whitelist(&[], 0);
        let (entries, disable_h) = deserialize_one_off_whitelist(&data).unwrap();
        assert!(entries.is_empty());
        assert_eq!(disable_h, 0);
    }

    #[test]
    fn rskj_whitelist_one_off_single_entry_roundtrip() {
        let hash160 = [0x11u8; 20];
        let max_val = 1_000_000u64;
        let disable_h = 42i32;

        let data = serialize_one_off_whitelist(&[(hash160, max_val)], disable_h);
        let (entries, dh) = deserialize_one_off_whitelist(&data).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, hash160);
        assert_eq!(entries[0].1, max_val);
        assert_eq!(dh, disable_h);
    }

    #[test]
    fn rskj_whitelist_one_off_two_entries_roundtrip() {
        let hash1 = [0xAAu8; 20];
        let hash2 = [0xBBu8; 20];
        let entries_in = [(hash1, 500_000u64), (hash2, 2_000_000u64)];
        let disable_h = 100i32;

        let data = serialize_one_off_whitelist(&entries_in, disable_h);
        let (entries_out, dh) = deserialize_one_off_whitelist(&data).unwrap();

        // serialize_one_off_whitelist reorders into Java HashMap iteration
        // order (see java_hashmap_order), so the roundtrip preserves the entry
        // SET and each entry's max value, not insertion order.
        assert_eq!(entries_out.len(), 2);
        assert!(entries_out.contains(&(hash1, 500_000)));
        assert!(entries_out.contains(&(hash2, 2_000_000)));
        assert_eq!(dh, disable_h);
    }

    #[test]
    fn rskj_whitelist_unlimited_empty_roundtrip() {
        let data = serialize_unlimited_whitelist(&[]);
        let entries = deserialize_unlimited_whitelist(&data);
        assert!(entries.is_empty());
    }

    #[test]
    fn rskj_whitelist_unlimited_two_entries_roundtrip() {
        let hash1 = [0xAAu8; 20];
        let hash2 = [0xBBu8; 20];
        let data = serialize_unlimited_whitelist(&[hash1, hash2]);
        let entries = deserialize_unlimited_whitelist(&data);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], hash1);
        assert_eq!(entries[1], hash2);
    }

    #[test]
    fn rskj_whitelist_empty_data() {
        let (entries, _) = deserialize_one_off_whitelist(&[]).unwrap();
        assert!(entries.is_empty());
    }

    // -----------------------------------------------------------------------
    // UTXO serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn rskj_utxo_roundtrip() {
        // P2SH script: OP_HASH160 <20 bytes> OP_EQUAL (23 bytes)
        let mut script = vec![0xa9u8, 0x14];
        script.extend_from_slice(&[0x42u8; 20]);
        script.push(0x87);

        let utxo = BridgeUtxo {
            tx_hash: [0xCCu8; 32],
            vout: 1,
            value_satoshis: 500_000,
            height: 700_000,
            script,
            coinbase: false,
        };

        let encoded = serialize_utxo(&utxo);
        let decoded = deserialize_utxo(&encoded).unwrap();

        assert_eq!(decoded.tx_hash, utxo.tx_hash);
        assert_eq!(decoded.vout, utxo.vout);
        assert_eq!(decoded.value_satoshis, utxo.value_satoshis);
        assert_eq!(decoded.height, utxo.height);
        assert_eq!(decoded.script, utxo.script);
        assert_eq!(decoded.coinbase, utxo.coinbase);
    }

    /// Byte-exact ground truth: the first UTXO blob of the mainnet
    /// `newFederationBtcUTXOs` cell at #1,590,999, dumped from a synced rskj
    /// `~/.rsk/mainnet` unitrie. The BTC tx hash is stored in bitcoinj display
    /// order (`Sha256Hash.getBytes()` of the reversed-wrapped tx hash), NOT
    /// reversed again.
    #[test]
    fn rskj_utxo_groundtruth_hash_order() {
        use alloy_primitives::hex;
        // value=0xed342c1c LE, scriptLen=23 LE, P2SH script, 32-byte hash,
        // vout=1, height=0, coinbase=0.
        let expected = hex::decode(
            "1c2c34ed0000000017000000a914b8e177b09d37441023682cc939767648b0ff4823\
             87073efb7a2a2c7f15c38d24a771ce85e24af772ae035162b9ba349a376a207279\
             010000000000000000",
        ).unwrap();

        let script = hex::decode("a914b8e177b09d37441023682cc939767648b0ff482387").unwrap();
        let tx_hash: [u8; 32] = hex::decode(
            "073efb7a2a2c7f15c38d24a771ce85e24af772ae035162b9ba349a376a207279",
        ).unwrap().try_into().unwrap();
        let utxo = BridgeUtxo {
            tx_hash,
            vout: 1,
            value_satoshis: 0xed34_2c1c,
            height: 0,
            script,
            coinbase: false,
        };
        assert_eq!(serialize_utxo(&utxo), expected, "rskj UTXO byte layout");
        // Round-trips back to the same (display-order) hash.
        assert_eq!(deserialize_utxo(&expected).unwrap().tx_hash, tx_hash);
    }

    #[test]
    fn rskj_utxo_list_roundtrip() {
        let utxos: Vec<BridgeUtxo> = (0..3u8).map(|i| BridgeUtxo {
            tx_hash: [i; 32],
            vout: i as u32,
            value_satoshis: (i as u64 + 1) * 100_000,
            height: 100_000 + i as u32,
            script: vec![0xa9, 0x14, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, 0x87],
            coinbase: false,
        }).collect();

        let data = serialize_utxo_list(&utxos);
        let decoded = deserialize_utxo_list(&data);

        assert_eq!(decoded.len(), 3);
        for (orig, dec) in utxos.iter().zip(decoded.iter()) {
            assert_eq!(dec.tx_hash, orig.tx_hash);
            assert_eq!(dec.vout, orig.vout);
            assert_eq!(dec.value_satoshis, orig.value_satoshis);
        }
    }

    #[test]
    fn rskj_utxo_list_empty_roundtrip() {
        let data = serialize_utxo_list(&[]);
        let decoded = deserialize_utxo_list(&data);
        assert!(decoded.is_empty());
    }
}
