/// Bit-level path encoding for the binary trie.
///
/// Keys in the Unitrie are byte arrays that get expanded to individual bits.
/// Each bit selects left (0) or right (1) when traversing the trie.
/// Bits are packed MSB-first: bit 0 of the path is the MSB of byte 0.

/// Encodes an expanded path (slice of 0s and 1s) into packed bytes (MSB-first).
pub fn encode(path: &[u8]) -> Vec<u8> {
    let len = encoded_len(path.len());
    let mut out = vec![0u8; len];
    for (k, &bit) in path.iter().enumerate() {
        if bit != 0 {
            out[k / 8] |= 0x80 >> (k % 8);
        }
    }
    out
}

/// Decodes packed bytes into an expanded path of `bit_length` bits (each byte is 0 or 1).
pub fn decode(encoded: &[u8], bit_length: usize) -> Vec<u8> {
    let mut path = vec![0u8; bit_length];
    for k in 0..bit_length {
        if (encoded[k / 8] >> (7 - (k % 8))) & 1 != 0 {
            path[k] = 1;
        }
    }
    path
}

/// Number of bytes needed to pack `bit_count` bits.
pub fn encoded_len(bit_count: usize) -> usize {
    (bit_count + 7) / 8
}

/// An immutable slice of a trie key in expanded (bit-per-byte) form.
/// Sub-slices share the underlying allocation via offset/limit.
#[derive(Clone, Debug)]
pub struct TrieKeySlice {
    expanded: Vec<u8>,
    offset: usize,
    limit: usize,
}

impl TrieKeySlice {
    pub fn new(expanded: Vec<u8>, offset: usize, limit: usize) -> Self {
        debug_assert!(offset <= limit);
        debug_assert!(limit <= expanded.len());
        Self { expanded, offset, limit }
    }

    /// Creates a key slice from a packed byte key (each byte → 8 bits).
    pub fn from_key(key: &[u8]) -> Self {
        let expanded = decode(key, key.len() * 8);
        let len = expanded.len();
        Self { expanded, offset: 0, limit: len }
    }

    /// Creates a key slice from already-encoded bytes with a known bit length.
    pub fn from_encoded(encoded: &[u8], bit_length: usize) -> Self {
        let expanded = decode(encoded, bit_length);
        let len = expanded.len();
        Self { expanded, offset: 0, limit: len }
    }

    pub fn empty() -> Self {
        Self { expanded: Vec::new(), offset: 0, limit: 0 }
    }

    pub fn length(&self) -> usize {
        self.limit - self.offset
    }

    pub fn is_empty(&self) -> bool {
        self.length() == 0
    }

    /// Returns the bit at position `i` (0 or 1).
    pub fn get(&self, i: usize) -> u8 {
        self.expanded[self.offset + i]
    }

    /// Packs this slice back to bytes (MSB-first).
    pub fn encode(&self) -> Vec<u8> {
        encode(&self.expanded[self.offset..self.limit])
    }

    /// Returns a sub-slice `[from..to)` (bit positions relative to this slice).
    pub fn slice(&self, from: usize, to: usize) -> Self {
        debug_assert!(from <= to);
        let new_offset = self.offset + from;
        let new_limit = self.offset + to;
        debug_assert!(new_limit <= self.limit);
        Self {
            expanded: self.expanded.clone(),
            offset: new_offset,
            limit: new_limit,
        }
    }

    /// Returns the longest common prefix between `self` and `other`.
    pub fn common_path(&self, other: &Self) -> Self {
        let max_len = self.length().min(other.length());
        for i in 0..max_len {
            if self.get(i) != other.get(i) {
                return self.slice(0, i);
            }
        }
        self.slice(0, max_len)
    }

    /// Rebuilds a shared path as `[self][implicit_bit][child_shared_path]`.
    /// Used during node coalescing after deletion.
    pub fn rebuild_shared_path(&self, implicit_bit: u8, child: &Self) -> Self {
        let new_len = self.length() + 1 + child.length();
        let mut expanded = Vec::with_capacity(new_len);
        expanded.extend_from_slice(&self.expanded[self.offset..self.limit]);
        expanded.push(implicit_bit);
        expanded.extend_from_slice(&child.expanded[child.offset..child.limit]);
        Self { expanded, offset: 0, limit: new_len }
    }

    /// Returns the expanded bit array for this slice.
    pub fn expand(&self) -> &[u8] {
        &self.expanded[self.offset..self.limit]
    }
}

impl PartialEq for TrieKeySlice {
    fn eq(&self, other: &Self) -> bool {
        self.expand() == other.expand()
    }
}
impl Eq for TrieKeySlice {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let path = vec![1, 0, 1, 1, 0, 0, 0, 1, 1, 1];
        let encoded = encode(&path);
        let decoded = decode(&encoded, path.len());
        assert_eq!(decoded, path);
    }

    #[test]
    fn test_encoded_len() {
        assert_eq!(encoded_len(0), 0);
        assert_eq!(encoded_len(1), 1);
        assert_eq!(encoded_len(8), 1);
        assert_eq!(encoded_len(9), 2);
        assert_eq!(encoded_len(16), 2);
        assert_eq!(encoded_len(248), 31);
    }

    #[test]
    fn test_encode_msb_first() {
        // 10110001 = 0xB1
        let path = vec![1, 0, 1, 1, 0, 0, 0, 1];
        let encoded = encode(&path);
        assert_eq!(encoded, vec![0xB1]);
    }

    #[test]
    fn test_from_key() {
        let key = vec![0xAB]; // 10101011
        let slice = TrieKeySlice::from_key(&key);
        assert_eq!(slice.length(), 8);
        assert_eq!(slice.get(0), 1);
        assert_eq!(slice.get(1), 0);
        assert_eq!(slice.get(2), 1);
        assert_eq!(slice.get(3), 0);
        assert_eq!(slice.get(4), 1);
        assert_eq!(slice.get(5), 0);
        assert_eq!(slice.get(6), 1);
        assert_eq!(slice.get(7), 1);
    }

    #[test]
    fn test_common_path() {
        let a = TrieKeySlice::from_key(&[0xFF]); // 11111111
        let b = TrieKeySlice::from_key(&[0xF0]); // 11110000
        let common = a.common_path(&b);
        assert_eq!(common.length(), 4);
        assert_eq!(common.get(0), 1);
        assert_eq!(common.get(3), 1);
    }

    #[test]
    fn test_slice() {
        let key = TrieKeySlice::from_key(&[0xFF]);
        let sub = key.slice(2, 6);
        assert_eq!(sub.length(), 4);
        for i in 0..4 {
            assert_eq!(sub.get(i), 1);
        }
    }

    #[test]
    fn test_rebuild_shared_path() {
        let parent = TrieKeySlice::new(vec![1, 0], 0, 2);
        let child = TrieKeySlice::new(vec![1, 1], 0, 2);
        let rebuilt = parent.rebuild_shared_path(0, &child);
        assert_eq!(rebuilt.length(), 5);
        assert_eq!(rebuilt.expand(), &[1, 0, 0, 1, 1]);
    }

    #[test]
    fn test_empty() {
        let empty = TrieKeySlice::empty();
        assert_eq!(empty.length(), 0);
        assert!(empty.is_empty());
    }
}
