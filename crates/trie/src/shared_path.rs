/// Shared path serialization matching rskj's SharedPathSerializer.
///
/// Length prefix encoding:
/// | lshared (bits) | First byte     | Format                       |
/// |----------------|----------------|------------------------------|
/// | 1–32           | lshared - 1    | 1 byte (values 0–31)         |
/// | 160–382        | lshared - 128  | 1 byte (values 32–254)       |
/// | other          | 0xFF           | 1 byte + VarInt(lshared)     |
///
/// Followed by the encoded path bytes (bits packed MSB-first).

use crate::path::{self, TrieKeySlice};
use crate::varint;

/// Serializes a shared path into `out`. Appends nothing if the path is empty.
pub fn serialize(shared_path: &TrieKeySlice, out: &mut Vec<u8>) {
    let lshared = shared_path.length();
    if lshared == 0 {
        return;
    }

    serialize_length(lshared, out);
    out.extend_from_slice(&shared_path.encode());
}

fn serialize_length(lshared: usize, out: &mut Vec<u8>) {
    if (1..=32).contains(&lshared) {
        out.push((lshared - 1) as u8);
    } else if (160..=382).contains(&lshared) {
        out.push((lshared - 128) as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&varint::encode_varint(lshared as u64));
    }
}

/// Returns the total serialized length of the shared path (prefix + encoded bytes).
pub fn serialized_length(lshared: usize) -> usize {
    if lshared == 0 {
        return 0;
    }
    length_prefix_size(lshared) + path::encoded_len(lshared)
}

fn length_prefix_size(lshared: usize) -> usize {
    if (1..=32).contains(&lshared) || (160..=382).contains(&lshared) {
        1
    } else {
        1 + varint::varint_size(lshared as u64)
    }
}

/// Deserializes a shared path from `data` at `pos`. Returns `(TrieKeySlice, bytes_consumed)`.
/// If `present` is false, returns an empty key slice with 0 bytes consumed.
pub fn deserialize(data: &[u8], pos: usize, present: bool) -> (TrieKeySlice, usize) {
    if !present {
        return (TrieKeySlice::empty(), 0);
    }

    let first = data[pos] as usize;
    let (lshared, header_size) = if first <= 31 {
        (first + 1, 1)
    } else if first <= 254 {
        (first + 128, 1)
    } else {
        let (v, vs) = varint::decode_varint(&data[pos + 1..]);
        (v as usize, 1 + vs)
    };

    let encoded_bytes = path::encoded_len(lshared);
    let start = pos + header_size;
    let slice = TrieKeySlice::from_encoded(&data[start..start + encoded_bytes], lshared);
    (slice, header_size + encoded_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_path_roundtrip() {
        // 5 bits: fits in 1..=32 range
        let path = TrieKeySlice::new(vec![1, 0, 1, 1, 0], 0, 5);
        let mut buf = Vec::new();
        serialize(&path, &mut buf);
        // prefix byte = 5 - 1 = 4
        assert_eq!(buf[0], 4);
        let (decoded, consumed) = deserialize(&buf, 0, true);
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.length(), 5);
        assert_eq!(decoded.expand(), path.expand());
    }

    #[test]
    fn test_medium_path_roundtrip() {
        // 200 bits: fits in 160..=382 range
        let expanded: Vec<u8> = (0..200).map(|i| (i % 2) as u8).collect();
        let path = TrieKeySlice::new(expanded, 0, 200);
        let mut buf = Vec::new();
        serialize(&path, &mut buf);
        // prefix byte = 200 - 128 = 72
        assert_eq!(buf[0], 72);
        let (decoded, consumed) = deserialize(&buf, 0, true);
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.length(), 200);
        assert_eq!(decoded.expand(), path.expand());
    }

    #[test]
    fn test_empty_path() {
        let path = TrieKeySlice::empty();
        let mut buf = Vec::new();
        serialize(&path, &mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_not_present() {
        let (decoded, consumed) = deserialize(&[0xFF], 0, false);
        assert_eq!(consumed, 0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_long_path_roundtrip() {
        // 100 bits: doesn't fit 1..=32 or 160..=382, uses 0xFF + VarInt
        let expanded: Vec<u8> = (0..100).map(|i| (i % 2) as u8).collect();
        let path = TrieKeySlice::new(expanded, 0, 100);
        let mut buf = Vec::new();
        serialize(&path, &mut buf);
        assert_eq!(buf[0], 0xFF);
        let (decoded, consumed) = deserialize(&buf, 0, true);
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.length(), 100);
        assert_eq!(decoded.expand(), path.expand());
    }
}
