//! Bridge serialization utilities — Ethereum RLP encoding matching rskj.
//!
//! All Bridge data stored via `addStorageBytes`/`getStorageBytes` in rskj uses
//! Ethereum RLP encoding (`org.ethereum.util.RLP`). This module provides the
//! exact same encode/decode functions so that rustock and rskj produce
//! byte-identical storage values.

use alloy_primitives::B256;

// ---------------------------------------------------------------------------
// RLP encoding primitives (matching org.ethereum.util.RLP)
// ---------------------------------------------------------------------------

const OFFSET_SHORT_ITEM: u8 = 0x80;
const OFFSET_SHORT_LIST: u8 = 0xc0;
const SIZE_THRESHOLD: usize = 56;

/// RLP-encode a byte string.
///
/// Matches rskj's `RLP.encodeElement(byte[])`:
/// - null/empty → `[0x80]`
/// - single byte `[0x00]` → `[0x00]`
/// - single byte < 0x80 → the byte itself
/// - 1..55 bytes → `[0x80 + len, data...]`
/// - ≥56 bytes → `[0xb7 + len_of_len, len_bytes..., data...]`
pub fn rlp_encode_element(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![OFFSET_SHORT_ITEM];
    }
    if data.len() == 1 && data[0] < OFFSET_SHORT_ITEM {
        return data.to_vec();
    }
    if data.len() < SIZE_THRESHOLD {
        let mut result = Vec::with_capacity(1 + data.len());
        result.push(OFFSET_SHORT_ITEM + data.len() as u8);
        result.extend_from_slice(data);
        result
    } else {
        let len_bytes = encode_length(data.len());
        let mut result = Vec::with_capacity(1 + len_bytes.len() + data.len());
        result.push(0xb7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(data);
        result
    }
}

/// Decode a single RLP string element (the inverse of [`rlp_encode_element`]):
/// returns the payload bytes. `None` for a list header or malformed input.
pub fn rlp_decode_element(data: &[u8]) -> Option<Vec<u8>> {
    let first = *data.first()?;
    if first < OFFSET_SHORT_ITEM {
        return Some(vec![first]);
    }
    if first < 0xb8 {
        let len = (first - OFFSET_SHORT_ITEM) as usize;
        return data.get(1..1 + len).map(|s| s.to_vec());
    }
    if first < OFFSET_SHORT_LIST {
        let len_len = (first - 0xb7) as usize;
        let len_bytes = data.get(1..1 + len_len)?;
        let len = len_bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
        return data.get(1 + len_len..1 + len_len + len).map(|s| s.to_vec());
    }
    None
}

/// RLP-encode a list of already-encoded items.
///
/// Matches rskj's `RLP.encodeList(byte[]...)`.
pub fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|i| i.len()).sum();

    if payload_len < SIZE_THRESHOLD {
        let mut result = Vec::with_capacity(1 + payload_len);
        result.push(OFFSET_SHORT_LIST + payload_len as u8);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    } else {
        let len_bytes = encode_length(payload_len);
        let mut result = Vec::with_capacity(1 + len_bytes.len() + payload_len);
        result.push(0xf7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    }
}

/// RLP-encode a non-negative integer (matching rskj's `RLP.encodeBigInteger`).
///
/// - 0 → `[0x80]` (RLP empty string, per rskj convention)
/// - 1..127 → `[value]` (single byte)
/// - ≥128 → `rlp_encode_element(minimal big-endian bytes)`
pub fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![OFFSET_SHORT_ITEM];
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(7);
    rlp_encode_element(&be[start..])
}

/// Encode a length as big-endian bytes (no leading zeros).
fn encode_length(len: usize) -> Vec<u8> {
    let be = len.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[start..].to_vec()
}

// ---------------------------------------------------------------------------
// RLP decoding primitives (matching org.ethereum.util.RLP decoding)
// ---------------------------------------------------------------------------

/// Decode a top-level RLP list, returning the raw data of each element.
///
/// Matches rskj's `RLP.decode2(data).get(0)` followed by iterating the
/// `RLPList` and calling `getRLPData()` on each element.
pub fn rlp_decode_list(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < OFFSET_SHORT_LIST {
        return None; // not a list
    }

    let (payload_offset, payload_len) = if first < 0xf8 {
        let len = (first - OFFSET_SHORT_LIST) as usize;
        (1, len)
    } else {
        let len_of_len = (first - 0xf7) as usize;
        if 1 + len_of_len > data.len() {
            return None;
        }
        let len = decode_be_usize(&data[1..1 + len_of_len]);
        (1 + len_of_len, len)
    };

    if payload_offset + payload_len > data.len() {
        return None;
    }

    let payload = &data[payload_offset..payload_offset + payload_len];
    let mut items = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let (item_data, item_total_len) = rlp_decode_item(&payload[offset..])?;
        items.push(item_data);
        offset += item_total_len;
    }

    Some(items)
}

/// Decode a single RLP item, returning (decoded_data, total_consumed_bytes).
///
/// For strings: returns the raw payload bytes.
/// For the special "zero" encoding `[0x80]`: returns empty vec (representing 0/null).
fn rlp_decode_item(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];

    if first < OFFSET_SHORT_ITEM {
        // Single byte [0x00..0x7f]
        Some((vec![first], 1))
    } else if first == OFFSET_SHORT_ITEM {
        // Empty string (represents 0 or null)
        Some((Vec::new(), 1))
    } else if first < 0xb8 {
        // Short string: 1..55 bytes
        let len = (first - OFFSET_SHORT_ITEM) as usize;
        if 1 + len > data.len() {
            return None;
        }
        Some((data[1..1 + len].to_vec(), 1 + len))
    } else if first < OFFSET_SHORT_LIST {
        // Long string: ≥56 bytes
        let len_of_len = (first - 0xb7) as usize;
        if 1 + len_of_len > data.len() {
            return None;
        }
        let len = decode_be_usize(&data[1..1 + len_of_len]);
        let start = 1 + len_of_len;
        if start + len > data.len() {
            return None;
        }
        Some((data[start..start + len].to_vec(), start + len))
    } else {
        // It's a nested list — skip it as a single opaque item.
        let (payload_offset, payload_len) = if first < 0xf8 {
            let len = (first - OFFSET_SHORT_LIST) as usize;
            (1usize, len)
        } else {
            let len_of_len = (first - 0xf7) as usize;
            if 1 + len_of_len > data.len() {
                return None;
            }
            let len = decode_be_usize(&data[1..1 + len_of_len]);
            (1 + len_of_len, len)
        };
        let total = payload_offset + payload_len;
        if total > data.len() {
            return None;
        }
        Some((data[..total].to_vec(), total))
    }
}

/// Decode big-endian unsigned integer from bytes.
fn decode_be_usize(data: &[u8]) -> usize {
    let mut result: usize = 0;
    for &b in data {
        result = (result << 8) | b as usize;
    }
    result
}

/// Decode an RLP-encoded unsigned integer (matching rskj's
/// `BigIntegers.fromUnsignedByteArray(rlpElement.getRLPData())`).
///
/// `[0x80]` (empty data) → 0, otherwise big-endian unsigned bytes.
pub fn rlp_decode_u64(rlp_data: &[u8]) -> u64 {
    if rlp_data.is_empty() {
        return 0;
    }
    if rlp_data.len() > 8 {
        // Truncate to u64 range (matching Java's longValue())
        let start = rlp_data.len() - 8;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&rlp_data[start..]);
        return u64::from_be_bytes(buf);
    }
    let mut buf = [0u8; 8];
    buf[8 - rlp_data.len()..].copy_from_slice(rlp_data);
    u64::from_be_bytes(buf)
}

// ---------------------------------------------------------------------------
// Bridge-specific serialization (matching BridgeSerializationUtils)
// ---------------------------------------------------------------------------

/// Serialize a map of SHA256 hashes to u64 values as an RLP list.
///
/// Matches rskj's `BridgeSerializationUtils.serializeMapOfHashesToLong`:
/// keys sorted lexicographically, encoded as alternating (hash, value) pairs
/// inside an RLP list.
pub fn serialize_map_of_hashes_to_longs(map: &[(B256, u64)]) -> Vec<u8> {
    let mut sorted: Vec<_> = map.to_vec();
    sorted.sort_by_key(|(hash, _)| *hash);

    let mut items = Vec::with_capacity(sorted.len() * 2);
    for (hash, value) in &sorted {
        items.push(rlp_encode_element(hash.as_slice()));
        items.push(rlp_encode_u64(*value));
    }

    rlp_encode_list(&items)
}

/// Deserialize a map of SHA256 hashes to u64 values from an RLP list.
///
/// Matches rskj's `BridgeSerializationUtils.deserializeMapOfHashesToLong`.
pub fn deserialize_map_of_hashes_to_longs(data: &[u8]) -> Option<Vec<(B256, u64)>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    let items = rlp_decode_list(data)?;
    if items.len() % 2 != 0 {
        return None; // odd count = invalid
    }
    let mut result = Vec::with_capacity(items.len() / 2);
    for pair in items.chunks_exact(2) {
        if pair[0].len() != 32 {
            return None;
        }
        let hash = B256::from_slice(&pair[0]);
        let value = rlp_decode_u64(&pair[1]);
        result.push((hash, value));
    }
    Some(result)
}

/// Serialize coinbase information (witness merkle root) as an RLP list.
///
/// Matches rskj's `BridgeSerializationUtils.serializeCoinbaseInformation`.
pub fn serialize_coinbase_information(witness_merkle_root: &B256) -> Vec<u8> {
    let items = vec![rlp_encode_element(witness_merkle_root.as_slice())];
    rlp_encode_list(&items)
}

/// Deserialize coinbase information from an RLP list.
///
/// Matches rskj's `BridgeSerializationUtils.deserializeCoinbaseInformation`.
pub fn deserialize_coinbase_information(data: &[u8]) -> Option<B256> {
    let items = rlp_decode_list(data)?;
    if items.len() != 1 || items[0].len() != 32 {
        return None;
    }
    Some(B256::from_slice(&items[0]))
}

/// Serialize a Sha256Hash as an RLP element.
///
/// Matches rskj's `BridgeSerializationUtils.serializeSha256Hash`.
pub fn serialize_hash(hash: &B256) -> Vec<u8> {
    rlp_encode_element(hash.as_slice())
}

/// Deserialize a Sha256Hash from an RLP element.
///
/// Matches rskj's `BridgeSerializationUtils.deserializeSha256Hash`
/// (uses `RLP.decodeFirstElement`).
pub fn deserialize_hash(data: &[u8]) -> Option<B256> {
    let (item, _) = rlp_decode_item(data)?;
    if item.len() != 32 {
        return None;
    }
    Some(B256::from_slice(&item))
}

/// Serialize a long value as RLP.
///
/// Matches rskj's `BridgeSerializationUtils.serializeLong` which uses
/// `RLP.encodeBigInteger(BigInteger.valueOf(value))`.
pub fn serialize_long(value: u64) -> Vec<u8> {
    rlp_encode_u64(value)
}

/// Deserialize a long value from RLP.
///
/// Matches rskj's `BridgeSerializationUtils.deserializeOptionalLong`.
pub fn deserialize_optional_long(data: &[u8]) -> Option<u64> {
    if data.is_empty() {
        return None;
    }
    let (item, _) = rlp_decode_item(data)?;
    Some(rlp_decode_u64(&item))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.replace(|c: char| c.is_whitespace(), "");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // -----------------------------------------------------------------------
    // RLP primitive tests
    // -----------------------------------------------------------------------

    #[test]
    fn rlp_encode_empty() {
        assert_eq!(rlp_encode_element(&[]), vec![0x80]);
    }

    #[test]
    fn rlp_encode_single_byte_small() {
        assert_eq!(rlp_encode_element(&[0x00]), vec![0x00]);
        assert_eq!(rlp_encode_element(&[0x01]), vec![0x01]);
        assert_eq!(rlp_encode_element(&[0x7f]), vec![0x7f]);
    }

    #[test]
    fn rlp_encode_single_byte_large() {
        assert_eq!(rlp_encode_element(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_element(&[0xff]), vec![0x81, 0xff]);
    }

    #[test]
    fn rlp_encode_32_bytes() {
        let data = [0xAAu8; 32];
        let encoded = rlp_encode_element(&data);
        assert_eq!(encoded[0], 0xa0); // 0x80 + 32
        assert_eq!(&encoded[1..], &data);
        assert_eq!(encoded.len(), 33);
    }

    #[test]
    fn rlp_encode_u64_zero() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
    }

    #[test]
    fn rlp_encode_u64_small() {
        assert_eq!(rlp_encode_u64(1), vec![0x01]);
        assert_eq!(rlp_encode_u64(3), vec![0x03]);
        assert_eq!(rlp_encode_u64(127), vec![0x7f]);
    }

    #[test]
    fn rlp_encode_u64_medium() {
        assert_eq!(rlp_encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_u64(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn rlp_encode_empty_list() {
        assert_eq!(rlp_encode_list(&[]), vec![0xc0]);
    }

    #[test]
    fn rlp_roundtrip_list() {
        let items = vec![
            rlp_encode_element(&[1, 2, 3]),
            rlp_encode_u64(42),
        ];
        let encoded = rlp_encode_list(&items);
        let decoded = rlp_decode_list(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], vec![1, 2, 3]);
        assert_eq!(rlp_decode_u64(&decoded[1]), 42);
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj BridgeSerializationUtilsTest
    // -----------------------------------------------------------------------

    /// Ported from rskj BridgeSerializationUtilsTest.serializeMapOfHashesToLong.
    ///
    /// Input map: key='a'×64 → 3, 'b'×64 → 1, 'c'×64 → 4, 'd'×64 → 2
    /// Expected output: keys sorted a,b,c,d with RLP encoding.
    #[test]
    fn rskj_serialize_map_of_hashes_to_longs() {
        let hash_a = B256::from_slice(&[0xaa; 32]);
        let hash_b = B256::from_slice(&[0xbb; 32]);
        let hash_c = B256::from_slice(&[0xcc; 32]);
        let hash_d = B256::from_slice(&[0xdd; 32]);

        let map = vec![
            (hash_b, 1u64),
            (hash_d, 2u64),
            (hash_a, 3u64),
            (hash_c, 4u64),
        ];

        let result = serialize_map_of_hashes_to_longs(&map);

        // Build expected hex matching rskj test:
        // f888 + a0{aa×32}03 + a0{bb×32}01 + a0{cc×32}04 + a0{dd×32}02
        let mut expected = String::new();
        expected.push_str("f888");
        expected.push_str("a0"); expected.push_str(&"aa".repeat(32)); expected.push_str("03");
        expected.push_str("a0"); expected.push_str(&"bb".repeat(32)); expected.push_str("01");
        expected.push_str("a0"); expected.push_str(&"cc".repeat(32)); expected.push_str("04");
        expected.push_str("a0"); expected.push_str(&"dd".repeat(32)); expected.push_str("02");

        assert_eq!(
            bytes_to_hex(&result),
            expected,
            "serializeMapOfHashesToLong output must match rskj"
        );
    }

    /// Ported from rskj BridgeSerializationUtilsTest.deserializeMapOfHashesToLong_nonEmpty.
    ///
    /// Keys 'b'×64, 'd'×64, 'a'×64 with values 7, 76, 123.
    #[test]
    fn rskj_deserialize_map_of_hashes_to_longs_non_empty() {
        let hash_a = B256::from_slice(&[0xaa; 32]);
        let hash_b = B256::from_slice(&[0xbb; 32]);
        let hash_d = B256::from_slice(&[0xdd; 32]);

        // Build the RLP-encoded input matching what rskj would produce
        let map = vec![
            (hash_b, 7u64),
            (hash_d, 76u64),
            (hash_a, 123u64),
        ];
        let encoded = serialize_map_of_hashes_to_longs(&map);
        let decoded = deserialize_map_of_hashes_to_longs(&encoded).unwrap();

        assert_eq!(decoded.len(), 3);
        // Keys should be sorted: aa, bb, dd
        assert_eq!(decoded[0], (hash_a, 123));
        assert_eq!(decoded[1], (hash_b, 7));
        assert_eq!(decoded[2], (hash_d, 76));
    }

    /// Ported from rskj: deserializeMapOfHashesToLong with null/empty → empty map.
    #[test]
    fn rskj_deserialize_map_empty() {
        let decoded = deserialize_map_of_hashes_to_longs(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    /// Ported from rskj: odd number of RLP items → error.
    #[test]
    fn rskj_deserialize_map_odd_items_rejected() {
        // Build a list with 3 items (odd)
        let items = vec![
            rlp_encode_element(&[0xaa; 32]),
            rlp_encode_u64(1),
            rlp_encode_element(&[0xbb; 32]),
        ];
        let encoded = rlp_encode_list(&items);
        assert!(deserialize_map_of_hashes_to_longs(&encoded).is_none());
    }

    /// Ported from rskj BridgeSerializationUtilsTest — coinbase information
    /// roundtrip.
    #[test]
    fn rskj_coinbase_information_roundtrip() {
        let witness_root = B256::from_slice(&hex_to_bytes(
            "e3d0840a0825fb7d880e5cb8306745352920a8c7e8a30fac882b275e26c6bb65"
        ));

        let serialized = serialize_coinbase_information(&witness_root);
        let deserialized = deserialize_coinbase_information(&serialized).unwrap();
        assert_eq!(deserialized, witness_root);

        // Verify the serialized form is an RLP list with one 32-byte element
        assert_eq!(serialized[0], 0xc0 + 33); // short list, 33 bytes payload
        assert_eq!(serialized[1], 0xa0);       // 32-byte string
        assert_eq!(&serialized[2..34], witness_root.as_slice());
    }

    /// Verify coinbase deserialization rejects wrong list size.
    #[test]
    fn rskj_coinbase_information_wrong_list_size() {
        let items = vec![
            rlp_encode_element(&[0x01; 32]),
            rlp_encode_element(&[0x02; 32]),
        ];
        let encoded = rlp_encode_list(&items);
        assert!(deserialize_coinbase_information(&encoded).is_none());
    }

    /// Verify serialize_hash produces RLP-encoded element.
    #[test]
    fn rskj_serialize_hash_rlp() {
        let hash = B256::from_slice(&[0x42; 32]);
        let encoded = serialize_hash(&hash);
        assert_eq!(encoded[0], 0xa0); // 0x80 + 32
        assert_eq!(&encoded[1..], hash.as_slice());
    }

    /// Verify deserialize_hash reads RLP element.
    #[test]
    fn rskj_deserialize_hash_rlp() {
        let hash = B256::from_slice(&[0x42; 32]);
        let encoded = serialize_hash(&hash);
        let decoded = deserialize_hash(&encoded).unwrap();
        assert_eq!(decoded, hash);
    }

    /// Verify serialize_long matches rskj's RLP.encodeBigInteger.
    #[test]
    fn rskj_serialize_long_rlp() {
        assert_eq!(serialize_long(0), vec![0x80]);
        assert_eq!(serialize_long(1), vec![0x01]);
        assert_eq!(serialize_long(127), vec![0x7f]);
        assert_eq!(serialize_long(128), vec![0x81, 0x80]);
        assert_eq!(serialize_long(5000), vec![0x82, 0x13, 0x88]);
    }

    /// Verify deserialize_optional_long handles empty and RLP-encoded values.
    #[test]
    fn rskj_deserialize_optional_long_rlp() {
        assert_eq!(deserialize_optional_long(&[]), None);
        assert_eq!(deserialize_optional_long(&[0x80]), Some(0));
        assert_eq!(deserialize_optional_long(&[0x01]), Some(1));
        assert_eq!(deserialize_optional_long(&[0x82, 0x13, 0x88]), Some(5000));
    }

    // -----------------------------------------------------------------------
    // Federation RLP golden vectors — ported from rskj
    // BridgeSerializationUtilsTest.deserializeFederationOnlyBtcKeys_ok
    // -----------------------------------------------------------------------

    /// Ported from rskj BridgeSerializationUtilsTest.deserializeFederationOnlyBtcKeys_ok
    ///
    /// Validates that the rskj federation format:
    ///   RLP([creation_time_ms, block_number, [key1, key2, ...]])
    /// decodes correctly to the expected values.
    ///
    /// Input: creation_time=5000ms (0x1388), block_number=42 (0x002a), 6 keys
    #[test]
    fn rskj_federation_rlp_golden_vector_decode() {
        let creation_time_rlp = rlp_encode_element(&[0x13, 0x88]); // 5000
        let block_number_rlp = rlp_encode_element(&[0x00, 0x2a]); // 42

        let dummy_keys: Vec<Vec<u8>> = (0..6).map(|i| vec![0x02 + i; 33]).collect();
        let encoded_keys: Vec<Vec<u8>> = dummy_keys.iter()
            .map(|k| rlp_encode_element(k))
            .collect();
        let keys_list = rlp_encode_list(&encoded_keys);

        let federation_rlp = rlp_encode_list(&[
            creation_time_rlp,
            block_number_rlp,
            keys_list,
        ]);

        let items = rlp_decode_list(&federation_rlp).unwrap();
        assert_eq!(items.len(), 3, "federation should have 3 top-level items");

        let creation_time = rlp_decode_u64(&items[0]);
        assert_eq!(creation_time, 5000, "creation_time should be 5000ms");

        let block_number = rlp_decode_u64(&items[1]);
        assert_eq!(block_number, 42, "block_number should be 42");

        let keys = rlp_decode_list(&items[2]).unwrap();
        assert_eq!(keys.len(), 6, "should have 6 federation member keys");
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(key.len(), 33, "key {i} should be 33 bytes");
        }
    }

    /// Ported from rskj: federation with known creation time hex encoding.
    /// Verifies that 0x1388 round-trips as creation_time=5000 and 0x002a as block=42.
    #[test]
    fn rskj_federation_creation_time_encoding() {
        assert_eq!(rlp_encode_element(&[0x13, 0x88]), vec![0x82, 0x13, 0x88]);
        let decoded = rlp_decode_u64(&[0x13, 0x88]);
        assert_eq!(decoded, 5000);

        assert_eq!(rlp_encode_element(&[0x00, 0x2a]), vec![0x82, 0x00, 0x2a]);
        let decoded = rlp_decode_u64(&[0x00, 0x2a]);
        assert_eq!(decoded, 42);
    }

    /// Ported from rskj: empty federation list should decode cleanly.
    #[test]
    fn rskj_empty_federation_keys_list() {
        let keys_list = rlp_encode_list(&[]);
        let creation_rlp = rlp_encode_u64(0);
        let block_rlp = rlp_encode_u64(0);
        let data = rlp_encode_list(&[creation_rlp, block_rlp, keys_list]);

        let items = rlp_decode_list(&data).unwrap();
        assert_eq!(items.len(), 3);
        let keys = rlp_decode_list(&items[2]).unwrap();
        assert!(keys.is_empty());
    }

    /// Verify the full RLP list prefix for a list with > 55 bytes payload.
    #[test]
    fn rlp_long_list_prefix() {
        // 4 hashes × 33 bytes + 4 values × 1 byte = 136 bytes payload
        // 136 > 55, so prefix = [0xf7 + 1, 0x88] = [0xf8, 0x88]
        let items: Vec<Vec<u8>> = (0..4u8)
            .flat_map(|i| {
                vec![
                    rlp_encode_element(&[0x10 + i; 32]),
                    rlp_encode_u64((i + 1) as u64),
                ]
            })
            .collect();
        let encoded = rlp_encode_list(&items);
        assert_eq!(encoded[0], 0xf8);
        assert_eq!(encoded[1], 136);
    }
}
