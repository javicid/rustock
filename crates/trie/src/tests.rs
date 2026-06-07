/// Comprehensive tests for the Unitrie implementation.
///
/// Many tests are ported from rskj's trie test suite to ensure
/// cross-implementation compatibility:
/// - TrieHashTest.java         (hash stability, order independence)
/// - TrieKeyValueTest.java     (put/get/delete)
/// - TrieValueTest.java        (inline vs long values)
/// - TrieDeleteTest.java       (bulk deletion hash equivalence)
/// - delete/TrieHashTest.java  (path coalescing after deletion)
/// - delete/TrieImplKeyValueTest.java (state hash progression)
/// - PathEncoderTest.java      (concrete encode/decode vectors)
/// - TrieTreeSizeTest.java     (children_size values)
/// - TrieKeySliceTest.java     (bit-level key slicing)
#[cfg(test)]
mod unit {
    use std::sync::Arc;

    use alloy_primitives::{Address, B256, U256};

    use crate::account::AccountState;
    use crate::key_mapper;
    use crate::node::{empty_trie_hash, TrieNode};
    use crate::path::{self, TrieKeySlice};
    use crate::store::{MemoryTrieStore, TrieStore};

    /// rskj's TrieValueTest.makeValue(n): byte[k] = (k+1) % 256
    fn make_value(length: usize) -> Vec<u8> {
        (0..length).map(|k| ((k + 1) % 256) as u8).collect()
    }

    // ═══════════════════════════════════════════════════════════════
    // PathEncoder concrete vectors (from rskj PathEncoderTest.java)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rskj_encode_binary_path() {
        let bits = vec![0, 1, 1]; // 3 bits
        let encoded = path::encode(&bits);
        assert_eq!(encoded, vec![0x60]);
    }

    #[test]
    fn test_rskj_encode_binary_path_one_byte() {
        let bits = vec![0, 1, 1, 0, 1, 1, 0, 1]; // 8 bits
        let encoded = path::encode(&bits);
        assert_eq!(encoded, vec![0x6d]);
    }

    #[test]
    fn test_rskj_encode_binary_path_nine_bits() {
        let bits = vec![0, 1, 1, 0, 1, 1, 0, 1, 1]; // 9 bits
        let encoded = path::encode(&bits);
        assert_eq!(encoded, vec![0x6d, 0x80]);
    }

    #[test]
    fn test_rskj_encode_binary_path_twelve_bits() {
        let bits = vec![0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1]; // 12 bits
        let encoded = path::encode(&bits);
        assert_eq!(encoded, vec![0x6d, 0x50]);
    }

    #[test]
    fn test_rskj_decode_binary_path() {
        let decoded = path::decode(&[0x60], 3);
        assert_eq!(decoded, vec![0, 1, 1]);
    }

    #[test]
    fn test_rskj_decode_binary_path_one_byte() {
        let decoded = path::decode(&[0x6d], 8);
        assert_eq!(decoded, vec![0, 1, 1, 0, 1, 1, 0, 1]);
    }

    #[test]
    fn test_rskj_decode_binary_path_nine_bits() {
        let decoded = path::decode(&[0x6d, 0x80], 9);
        assert_eq!(decoded, vec![0, 1, 1, 0, 1, 1, 0, 1, 1]);
    }

    #[test]
    fn test_rskj_decode_binary_path_twelve_bits() {
        let decoded = path::decode(&[0x6d, 0x50], 12);
        assert_eq!(decoded, vec![0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1]);
    }

    // ═══════════════════════════════════════════════════════════════
    // TrieKeySlice tests (from rskj TrieKeySliceTest.java)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rskj_bytes_to_key_0xaa() {
        // 0xAA = 10101010
        let key = TrieKeySlice::from_key(&[0xAA]);
        assert_eq!(key.length(), 8);

        let full_encoded = key.encode();
        let expected = path::encode(&[1, 0, 1, 0, 1, 0, 1, 0]);
        assert_eq!(full_encoded, expected);

        // slice(2, 8) = bits 2..7 = [1, 0, 1, 0, 1, 0]
        let s1 = key.slice(2, 8);
        let expected_s1 = path::encode(&[1, 0, 1, 0, 1, 0]);
        assert_eq!(s1.encode(), expected_s1);

        // slice(0, 6) = bits 0..5 = [1, 0, 1, 0, 1, 0]
        let s2 = key.slice(0, 6);
        assert_eq!(s2.encode(), expected_s1);

        // slice(1, 6) = bits 1..5 = [0, 1, 0, 1, 0]
        let s3 = key.slice(1, 6);
        let expected_s3 = path::encode(&[0, 1, 0, 1, 0]);
        assert_eq!(s3.encode(), expected_s3);
    }

    // ═══════════════════════════════════════════════════════════════
    // Hash stability (from rskj TrieHashTest.java)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rskj_empty_hash_for_empty_trie() {
        let h = empty_trie_hash();
        assert_eq!(
            format!("{h:x}"),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn test_rskj_empty_tries_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty().compute_hash(&store);
        let t2 = TrieNode::empty().compute_hash(&store);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_rskj_non_empty_hash_differs_from_empty() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty().put(&TrieKeySlice::from_key(b"foo"), b"bar", &store);
        assert_ne!(root.compute_hash(&store), empty_trie_hash());
    }

    #[test]
    fn test_rskj_non_empty_hash_with_long_value_differs_from_empty() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty().put(
            &TrieKeySlice::from_key(b"foo"),
            &make_value(100),
            &store,
        );
        assert_ne!(root.compute_hash(&store), empty_trie_hash());
    }

    #[test]
    fn test_rskj_same_key_values_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .put(&TrieKeySlice::from_key(b"bar"), b"baz", &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .put(&TrieKeySlice::from_key(b"bar"), b"baz", &store);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_same_key_values_different_order_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .put(&TrieKeySlice::from_key(b"bar"), b"baz", &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"bar"), b"baz", &store)
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_three_keys_different_order_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .put(&TrieKeySlice::from_key(b"bar"), b"baz", &store)
            .put(&TrieKeySlice::from_key(b"baz"), b"foo", &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"bar"), b"baz", &store)
            .put(&TrieKeySlice::from_key(b"baz"), b"foo", &store)
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store);
        let t3 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"baz"), b"foo", &store)
            .put(&TrieKeySlice::from_key(b"bar"), b"baz", &store)
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
        assert_eq!(t3.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_same_key_long_values_different_order_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), &make_value(100), &store)
            .put(&TrieKeySlice::from_key(b"bar"), &make_value(200), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"bar"), &make_value(200), &store)
            .put(&TrieKeySlice::from_key(b"foo"), &make_value(100), &store);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_three_keys_long_values_different_order_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), &make_value(100), &store)
            .put(&TrieKeySlice::from_key(b"bar"), &make_value(200), &store)
            .put(&TrieKeySlice::from_key(b"baz"), &make_value(300), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"bar"), &make_value(200), &store)
            .put(&TrieKeySlice::from_key(b"baz"), &make_value(300), &store)
            .put(&TrieKeySlice::from_key(b"foo"), &make_value(100), &store);
        let t3 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"baz"), &make_value(300), &store)
            .put(&TrieKeySlice::from_key(b"bar"), &make_value(200), &store)
            .put(&TrieKeySlice::from_key(b"foo"), &make_value(100), &store);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
        assert_eq!(t3.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_different_values_different_hashes() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .put(&TrieKeySlice::from_key(b"bar"), b"42", &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .put(&TrieKeySlice::from_key(b"bar"), b"baz", &store);
        assert_ne!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    // ═══════════════════════════════════════════════════════════════
    // Key/Value tests (from rskj TrieKeyValueTest.java)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rskj_get_null_for_unknown_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        assert_eq!(root.get(&TrieKeySlice::from_key(&[0x01, 0x02, 0x03]), &store), None);
        assert_eq!(root.get(&TrieKeySlice::from_key(b"foo"), &store), None);
    }

    #[test]
    fn test_rskj_put_and_get_key_value() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty().put(&TrieKeySlice::from_key(b"foo"), b"bar", &store);
        assert_eq!(root.get(&TrieKeySlice::from_key(b"foo"), &store), Some(b"bar".to_vec()));
    }

    #[test]
    fn test_rskj_put_and_get_two_key_values() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .put(&TrieKeySlice::from_key(b"bar"), b"foo", &store);
        assert_eq!(root.get(&TrieKeySlice::from_key(b"foo"), &store), Some(b"bar".to_vec()));
        assert_eq!(root.get(&TrieKeySlice::from_key(b"bar"), &store), Some(b"foo".to_vec()));
    }

    #[test]
    fn test_rskj_put_and_get_key_and_sub_key_values() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .put(&TrieKeySlice::from_key(b"f"), b"42", &store);
        assert_eq!(root.get(&TrieKeySlice::from_key(b"foo"), &store), Some(b"bar".to_vec()));
        assert_eq!(root.get(&TrieKeySlice::from_key(b"f"), &store), Some(b"42".to_vec()));
    }

    #[test]
    fn test_rskj_put_and_get_key_and_sub_key_values_inverse() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"f"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"fo"), b"bar", &store);
        assert_eq!(root.get(&TrieKeySlice::from_key(b"fo"), &store), Some(b"bar".to_vec()));
        assert_eq!(root.get(&TrieKeySlice::from_key(b"f"), &store), Some(b"42".to_vec()));
    }

    #[test]
    fn test_rskj_put_and_get_long_value() {
        let store = MemoryTrieStore::new();
        let val = make_value(100);
        let root = TrieNode::empty().put(&TrieKeySlice::from_key(b"foo"), &val, &store);
        assert_eq!(root.get(&TrieKeySlice::from_key(b"foo"), &store), Some(val));
    }

    #[test]
    fn test_rskj_put_key_value_and_delete_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), b"bar", &store)
            .delete(&TrieKeySlice::from_key(b"foo"), &store);
        assert_eq!(root.get(&TrieKeySlice::from_key(b"foo"), &store), None);
    }

    #[test]
    fn test_rskj_put_key_long_value_and_delete_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"foo"), &make_value(100), &store)
            .delete(&TrieKeySlice::from_key(b"foo"), &store);
        assert_eq!(root.get(&TrieKeySlice::from_key(b"foo"), &store), None);
    }

    #[test]
    fn test_rskj_put_and_get_100_key_values() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();
        for k in 0..100 {
            let key_str = format!("{k}");
            root = root.put(&TrieKeySlice::from_key(key_str.as_bytes()), key_str.as_bytes(), &store);
        }
        for k in 0..100 {
            let key_str = format!("{k}");
            assert_eq!(
                root.get(&TrieKeySlice::from_key(key_str.as_bytes()), &store),
                Some(key_str.into_bytes())
            );
        }
    }

    #[test]
    fn test_rskj_put_and_get_100_key_long_values() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();
        for k in 0..100 {
            let key_str = format!("{k}");
            root = root.put(&TrieKeySlice::from_key(key_str.as_bytes()), &make_value(k + 100), &store);
        }
        for k in 0..100 {
            let key_str = format!("{k}");
            assert_eq!(
                root.get(&TrieKeySlice::from_key(key_str.as_bytes()), &store),
                Some(make_value(k + 100))
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Value tests (from rskj TrieValueTest.java)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rskj_no_long_value_with_short_value() {
        let store = MemoryTrieStore::new();
        let value = vec![0x01, 0x02, 0x03];
        let key = TrieKeySlice::from_key(&[0x04, 0x05]);
        let root = TrieNode::empty().put(&key, &value, &store);
        assert!(!root.has_long_value());
        assert_eq!(root.value_length(), 3);
        assert_eq!(root.get(&key, &store), Some(value));
    }

    #[test]
    fn test_rskj_no_long_value_with_32_bytes() {
        let store = MemoryTrieStore::new();
        let value = make_value(32);
        let key = TrieKeySlice::from_key(&[0x04, 0x05]);
        let root = TrieNode::empty().put(&key, &value, &store);
        assert!(!root.has_long_value());
        assert_eq!(root.value_length(), 32);
        assert_eq!(root.get(&key, &store), Some(value));
    }

    #[test]
    fn test_rskj_long_value_with_33_bytes() {
        let store = MemoryTrieStore::new();
        let value = make_value(33);
        let key = TrieKeySlice::from_key(&[0x04, 0x05]);
        let root = TrieNode::empty().put(&key, &value, &store);
        assert!(root.has_long_value());
        assert_eq!(root.get(&key, &store), Some(value));
    }

    // ═══════════════════════════════════════════════════════════════
    // Deletion hash equivalence (from rskj TrieDeleteTest.java)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rskj_delete_value_gives_empty_trie() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"key"), b"value", &store)
            .delete(&TrieKeySlice::from_key(b"key"), &store);
        assert_eq!(root.compute_hash(&store), empty_trie_hash());
    }

    #[test]
    fn test_rskj_delete_one_value_gives_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"key1"), b"value1", &store)
            .put(&TrieKeySlice::from_key(b"key2"), b"value2", &store)
            .delete(&TrieKeySlice::from_key(b"key1"), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"key2"), b"value2", &store);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_delete_one_long_value_gives_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"key1"), &make_value(1024), &store)
            .put(&TrieKeySlice::from_key(b"key2"), b"value2", &store)
            .delete(&TrieKeySlice::from_key(b"key1"), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"key2"), b"value2", &store);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_delete_100_values_gives_same_hash() {
        let store = MemoryTrieStore::new();
        let mut t1 = TrieNode::empty();
        for k in 0..200 {
            let key = format!("key{k}");
            let val = format!("value{k}");
            t1 = t1.put(&TrieKeySlice::from_key(key.as_bytes()), val.as_bytes(), &store);
        }
        for k in (1..200).step_by(2) {
            let key = format!("key{k}");
            t1 = t1.delete(&TrieKeySlice::from_key(key.as_bytes()), &store);
        }

        let mut t2 = TrieNode::empty();
        for k in (0..200).step_by(2) {
            let key = format!("key{k}");
            let val = format!("value{k}");
            t2 = t2.put(&TrieKeySlice::from_key(key.as_bytes()), val.as_bytes(), &store);
        }

        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_delete_100_long_values_gives_same_hash() {
        let store = MemoryTrieStore::new();
        let mut t1 = TrieNode::empty();
        for k in 0..200usize {
            let key = format!("key{k}");
            t1 = t1.put(&TrieKeySlice::from_key(key.as_bytes()), &make_value(k + 100), &store);
        }
        for k in (1..200).step_by(2) {
            let key = format!("key{k}");
            t1 = t1.delete(&TrieKeySlice::from_key(key.as_bytes()), &store);
        }

        let mut t2 = TrieNode::empty();
        for k in (0..200usize).step_by(2) {
            let key = format!("key{k}");
            t2 = t2.put(&TrieKeySlice::from_key(key.as_bytes()), &make_value(k + 100), &store);
        }

        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_delete_200_values_gives_empty_hash() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();
        for k in 0..200 {
            let key = format!("key{k}");
            let val = format!("value{k}");
            root = root.put(&TrieKeySlice::from_key(key.as_bytes()), val.as_bytes(), &store);
        }
        for k in 0..200 {
            let key = format!("key{k}");
            root = root.delete(&TrieKeySlice::from_key(key.as_bytes()), &store);
        }
        assert_eq!(root.compute_hash(&store), empty_trie_hash());
    }

    #[test]
    fn test_rskj_delete_200_long_values_gives_empty_hash() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();
        for k in 0..200usize {
            let key = format!("key{k}");
            root = root.put(&TrieKeySlice::from_key(key.as_bytes()), &make_value(k + 200), &store);
        }
        for k in 0..200 {
            let key = format!("key{k}");
            root = root.delete(&TrieKeySlice::from_key(key.as_bytes()), &store);
        }
        assert_eq!(root.compute_hash(&store), empty_trie_hash());
    }

    #[test]
    fn test_rskj_two_phase_delete_gives_empty_hash() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();
        for k in 0..200 {
            let key = format!("key{k}");
            let val = format!("value{k}");
            root = root.put(&TrieKeySlice::from_key(key.as_bytes()), val.as_bytes(), &store);
        }
        // Delete even keys first
        for k in (0..200).step_by(2) {
            let key = format!("key{k}");
            root = root.delete(&TrieKeySlice::from_key(key.as_bytes()), &store);
        }
        // Then odd keys
        for k in (1..200).step_by(2) {
            let key = format!("key{k}");
            root = root.delete(&TrieKeySlice::from_key(key.as_bytes()), &store);
        }
        assert_eq!(root.compute_hash(&store), empty_trie_hash());
    }

    // ═══════════════════════════════════════════════════════════════
    // Path coalescing after deletion (from rskj delete/TrieHashTest.java)
    // These are the most structurally important tests — they verify
    // that hash(insert+delete) == hash(never_inserted).
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rskj_remove_or_never_insert_same_hash() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roosevalt"),
                 b"So, first of all, let me assert my firm belief that", &store)
            .put(&TrieKeySlice::from_key(b"roosevelt"),
                 b"the only thing we have to fear is... fear itself ", &store)
            .put(&TrieKeySlice::from_key(b"roosevilt"), b"42", &store)
            .delete(&TrieKeySlice::from_key(b"roosevelt"), &store);

        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roosevalt"),
                 b"So, first of all, let me assert my firm belief that", &store)
            .put(&TrieKeySlice::from_key(b"roosevilt"), b"42", &store);

        assert_eq!(
            t1.get(&TrieKeySlice::from_key(b"roosevalt"), &store),
            Some(b"So, first of all, let me assert my firm belief that".to_vec())
        );
        assert_eq!(
            t1.get(&TrieKeySlice::from_key(b"roosevilt"), &store),
            Some(b"42".to_vec())
        );
        assert_eq!(t1.get(&TrieKeySlice::from_key(b"roosevelt"), &store), None);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_coalesce_single_child_no_sibling_base() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt"), b"4243", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"424344", &store)
            .delete(&TrieKeySlice::from_key(b"roosevalt"), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"424344", &store);

        assert_eq!(t1.get(&TrieKeySlice::from_key(b"roose"), &store), Some(b"42".to_vec()));
        assert_eq!(t1.get(&TrieKeySlice::from_key(b"roosevaltroosevalt"), &store), Some(b"424344".to_vec()));
        assert_eq!(t1.get(&TrieKeySlice::from_key(b"roosevalt"), &store), None);
        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_coalesce_single_child_no_sibling_recursion() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"ro"), b"4", &store)
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt"), b"4243", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"424344", &store)
            .delete(&TrieKeySlice::from_key(b"roosevalt"), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"ro"), b"4", &store)
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"424344", &store);

        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_coalesce_single_child_with_subtree_base() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt"), b"4243", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"424344", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevaltroosevaltroosevalt"), b"42434445", &store)
            .delete(&TrieKeySlice::from_key(b"roosevalt"), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"424344", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevaltroosevaltroosevalt"), b"42434445", &store);

        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_coalesce_single_child_with_subtree_recursion() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"ro"), b"4", &store)
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt"), b"4243", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"424344", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevaltroosevaltroosevalt"), b"42434445", &store)
            .delete(&TrieKeySlice::from_key(b"roosevalt"), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"ro"), b"4", &store)
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"424344", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevaltroosevaltroosevalt"), b"42434445", &store);

        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_no_coalesce_two_children_base() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt"), b"4243", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt0oosevalt"), b"424344", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt1oosevalt"), b"42434445", &store)
            .delete(&TrieKeySlice::from_key(b"roosevalt"), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roose"), b"42", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt0oosevalt"), b"424344", &store)
            .put(&TrieKeySlice::from_key(b"roosevalt1oosevalt"), b"42434445", &store);

        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    #[test]
    fn test_rskj_coalesce_with_sibling_base() {
        let store = MemoryTrieStore::new();
        let t1 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"roosevalt"), b"4243", &store)
            .put(&TrieKeySlice::from_key(b"rooseval_"), b"424344", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"42434445", &store)
            .delete(&TrieKeySlice::from_key(b"roosevalt"), &store);
        let t2 = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"rooseval_"), b"424344", &store)
            .put(&TrieKeySlice::from_key(b"roosevaltroosevalt"), b"42434445", &store);

        assert_eq!(t1.compute_hash(&store), t2.compute_hash(&store));
    }

    // ═══════════════════════════════════════════════════════════════
    // State hash progression (from rskj delete/TrieImplKeyValueTest.java)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_rskj_delete_prefix_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"0"), b"So, first of all, let me assert my firm belief that", &store)
            .put(&TrieKeySlice::from_key(b"012345678910"), b"the only thing we have to fear is... fear itself ", &store)
            .delete(&TrieKeySlice::from_key(b"0"), &store);

        assert_eq!(
            root.get(&TrieKeySlice::from_key(b"012345678910"), &store),
            Some(b"the only thing we have to fear is... fear itself ".to_vec())
        );
        assert_eq!(root.get(&TrieKeySlice::from_key(b"0"), &store), None);
    }

    #[test]
    fn test_rskj_delete_longer_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(b"0"), b"So, first of all, let me assert my firm belief that", &store)
            .put(&TrieKeySlice::from_key(b"012345678910"), b"the only thing we have to fear is... fear itself ", &store)
            .delete(&TrieKeySlice::from_key(b"012345678910"), &store);

        assert_eq!(
            root.get(&TrieKeySlice::from_key(b"0"), &store),
            Some(b"So, first of all, let me assert my firm belief that".to_vec())
        );
        assert_eq!(root.get(&TrieKeySlice::from_key(b"012345678910"), &store), None);
    }

    #[test]
    fn test_rskj_state_hash_progression_after_delete() {
        let store = MemoryTrieStore::new();
        let t0 = TrieNode::empty();
        let h0 = t0.compute_hash(&store);

        let t1 = t0.put(&TrieKeySlice::from_key(b"0"), b"zero", &store);
        let h1 = t1.compute_hash(&store);

        let t2 = t1.put(&TrieKeySlice::from_key(b"012345678910"), b"one", &store);
        let h2 = t2.compute_hash(&store);

        let t3 = t2.delete(&TrieKeySlice::from_key(b"012345678910"), &store);
        let h3 = t3.compute_hash(&store);

        assert_eq!(t3.get(&TrieKeySlice::from_key(b"0"), &store), Some(b"zero".to_vec()));
        assert_eq!(t3.get(&TrieKeySlice::from_key(b"012345678910"), &store), None);
        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        assert_eq!(h1, h3); // delete restores hash to state before insert

        // Delete already-deleted key is idempotent
        let t4 = t3.delete(&TrieKeySlice::from_key(b"012345678910"), &store);
        let h4 = t4.compute_hash(&store);
        assert_eq!(h3, h4);
    }

    // ═══════════════════════════════════════════════════════════════
    // TrieKeyMapper + AccountState integration
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_account_in_trie() {
        let store = MemoryTrieStore::new();
        let addr = Address::from([0xAB; 20]);
        let acct = AccountState::new(U256::from(1), U256::from(100));

        let key = TrieKeySlice::from_key(&key_mapper::account_key(&addr));
        let root = TrieNode::empty().put(&key, &acct.encode(), &store);
        let decoded = AccountState::decode(&root.get(&key, &store).unwrap()).unwrap();
        assert_eq!(decoded, acct);
    }

    #[test]
    fn test_code_in_trie() {
        let store = MemoryTrieStore::new();
        let addr = Address::from([0x01; 20]);
        let code = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

        let key = TrieKeySlice::from_key(&key_mapper::code_key(&addr));
        let root = TrieNode::empty().put(&key, &code, &store);
        assert_eq!(root.get(&key, &store), Some(code));
    }

    #[test]
    fn test_storage_in_trie() {
        let store = MemoryTrieStore::new();
        let addr = Address::from([0x02; 20]);
        let slot = B256::ZERO;

        let key = TrieKeySlice::from_key(&key_mapper::storage_key(&addr, &slot));
        let root = TrieNode::empty().put(&key, &[0x01], &store);
        assert_eq!(root.get(&key, &store), Some(vec![0x01]));
    }

    #[test]
    fn test_account_code_storage_coexist() {
        let store = MemoryTrieStore::new();
        let addr = Address::from([0x42; 20]);
        let acct = AccountState::new(U256::from(5), U256::from(1000));

        let acct_key = TrieKeySlice::from_key(&key_mapper::account_key(&addr));
        let code_key = TrieKeySlice::from_key(&key_mapper::code_key(&addr));
        let stor_key = TrieKeySlice::from_key(&key_mapper::storage_key(&addr, &B256::with_last_byte(1)));

        let root = TrieNode::empty()
            .put(&acct_key, &acct.encode(), &store)
            .put(&code_key, &[0x60, 0x00], &store)
            .put(&stor_key, &[0xFF], &store);

        assert_eq!(AccountState::decode(&root.get(&acct_key, &store).unwrap()).unwrap(), acct);
        assert_eq!(root.get(&code_key, &store), Some(vec![0x60, 0x00]));
        assert_eq!(root.get(&stor_key, &store), Some(vec![0xFF]));
    }

    #[test]
    fn test_multiple_accounts() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();
        for i in 0u8..10 {
            let addr = Address::from([i; 20]);
            let acct = AccountState::new(U256::from(i as u64), U256::from(i as u64 * 100));
            let key = TrieKeySlice::from_key(&key_mapper::account_key(&addr));
            root = root.put(&key, &acct.encode(), &store);
        }
        for i in 0u8..10 {
            let addr = Address::from([i; 20]);
            let key = TrieKeySlice::from_key(&key_mapper::account_key(&addr));
            let acct = AccountState::decode(&root.get(&key, &store).unwrap()).unwrap();
            assert_eq!(acct.nonce, U256::from(i as u64));
            assert_eq!(acct.balance, U256::from(i as u64 * 100));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Persistence (save + reload from store)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_save_and_reload_single_key() {
        let store = Arc::new(MemoryTrieStore::new());
        let key = TrieKeySlice::from_key(&[0x01]);
        let mut root = TrieNode::empty().put(&key, b"hello", store.as_ref());
        let hash = root.compute_hash(store.as_ref());
        root.save(store.as_ref(), true);

        let data = store.get(hash.as_slice()).unwrap();
        let reloaded = TrieNode::from_message(&data, store.as_ref());
        assert_eq!(reloaded.get(&key, store.as_ref()), Some(b"hello".to_vec()));
        assert_eq!(reloaded.compute_hash(store.as_ref()), hash);
    }

    #[test]
    fn test_save_and_reload_complex_trie() {
        let store = Arc::new(MemoryTrieStore::new());
        let mut root = TrieNode::empty();
        for i in 0u8..20 {
            let key = TrieKeySlice::from_key(&[i, i.wrapping_mul(7)]);
            root = root.put(&key, &[i; 5], store.as_ref());
        }

        let hash = root.compute_hash(store.as_ref());
        root.save(store.as_ref(), true);

        let data = store.get(hash.as_slice()).unwrap();
        let reloaded = TrieNode::from_message(&data, store.as_ref());
        assert_eq!(reloaded.compute_hash(store.as_ref()), hash);
        for i in 0u8..20 {
            let key = TrieKeySlice::from_key(&[i, i.wrapping_mul(7)]);
            assert_eq!(reloaded.get(&key, store.as_ref()), Some(vec![i; 5]));
        }
    }

    #[test]
    fn test_save_and_reload_large_value() {
        let store = Arc::new(MemoryTrieStore::new());
        let key = TrieKeySlice::from_key(&[0x01]);
        let large = vec![0xCC; 1000];
        let mut root = TrieNode::empty().put(&key, &large, store.as_ref());
        let hash = root.compute_hash(store.as_ref());
        root.save(store.as_ref(), true);

        let data = store.get(hash.as_slice()).unwrap();
        let reloaded = TrieNode::from_message(&data, store.as_ref());
        assert_eq!(reloaded.get(&key, store.as_ref()), Some(large));
    }

    #[test]
    fn test_save_and_reload_50_keys() {
        let store = Arc::new(MemoryTrieStore::new());
        let mut root = TrieNode::empty();
        for i in 0u8..50 {
            let key = TrieKeySlice::from_key(&[i]);
            root = root.put(&key, &[i], store.as_ref());
        }

        let hash = root.compute_hash(store.as_ref());
        root.save(store.as_ref(), true);

        let data = store.get(hash.as_slice()).expect("root should be saved");
        let reloaded = TrieNode::from_message(&data, store.as_ref());
        for i in 0u8..50 {
            let key = TrieKeySlice::from_key(&[i]);
            assert_eq!(reloaded.get(&key, store.as_ref()), Some(vec![i]));
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Embeddability
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_small_terminal_node_is_embeddable() {
        let store = MemoryTrieStore::new();
        let node = TrieNode::new_leaf(TrieKeySlice::new(vec![1], 0, 1), vec![0xAB]);
        assert!(node.is_terminal());
        assert!(node.is_embeddable(&store));
    }

    #[test]
    fn test_node_with_children_not_embeddable() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(&[0x00]), b"a", &store)
            .put(&TrieKeySlice::from_key(&[0x80]), b"b", &store);
        assert!(!root.is_terminal());
        assert!(!root.is_embeddable(&store));
    }

    // ═══════════════════════════════════════════════════════════════
    // Orchid (pre-RSKIP107) serialization — ported from rskj
    // TrieOrchidMessageTest groundtruth
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn orchid_empty_trie_to_message() {
        let store = MemoryTrieStore::new();
        let msg = TrieNode::empty().to_message_orchid(false, &store);
        assert_eq!(msg, vec![2, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn orchid_empty_trie_to_message_secure() {
        let store = MemoryTrieStore::new();
        let msg = TrieNode::empty().to_message_orchid(true, &store);
        assert_eq!(msg, vec![2, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn orchid_trie_with_value_to_message() {
        let store = MemoryTrieStore::new();
        let trie = TrieNode::empty().put(&TrieKeySlice::from_key(&[]), &[1, 2, 3, 4], &store);
        let msg = trie.to_message_orchid(false, &store);
        assert_eq!(msg, vec![2, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
    }

    #[test]
    fn orchid_trie_with_long_value_to_message() {
        use sha3::{Digest, Keccak256};
        let store = MemoryTrieStore::new();
        let value = make_value(33);
        let trie = TrieNode::empty().put(&TrieKeySlice::from_key(&[]), &value, &store);
        let msg = trie.to_message_orchid(false, &store);
        assert_eq!(msg.len(), 38);
        assert_eq!(&msg[..6], &[2, 2, 0, 0, 0, 0]); // flags bit 2 = long value
        let value_hash: [u8; 32] = Keccak256::digest(&value).into();
        assert_eq!(&msg[6..38], &value_hash);
    }

    #[test]
    fn orchid_trie_with_subtrie_and_no_value_to_message() {
        let store = MemoryTrieStore::new();
        let trie = TrieNode::empty().put(&TrieKeySlice::from_key(&[0x02]), &[1, 2, 3, 4], &store);
        let msg = trie.to_message_orchid(false, &store);
        assert_eq!(msg, vec![2, 0, 0, 0, 0, 8, 2, 1, 2, 3, 4]);
    }

    #[test]
    fn orchid_trie_with_subtries_and_no_value_to_message() {
        let store = MemoryTrieStore::new();
        let trie = TrieNode::empty()
            .put(&TrieKeySlice::from_key(&[0x02]), &[1, 2, 3, 4], &store)
            .put(&TrieKeySlice::from_key(&[0x12]), &[1, 2, 3, 4], &store);
        let msg = trie.to_message_orchid(false, &store);
        assert_eq!(msg.len(), 6 + 1 + 2 * 32);
        // arity, flags, child bits = 3 (both), lshared = 3 bits, path byte 0
        assert_eq!(&msg[..7], &[2, 0, 0, 3, 0, 3, 0]);
    }

    #[test]
    fn orchid_empty_trie_hash_is_keccak_rlp_empty() {
        let store = MemoryTrieStore::new();
        assert_eq!(TrieNode::empty().compute_hash_orchid(false, &store), empty_trie_hash());
    }
}

#[cfg(test)]
mod delete_recursive_tests {
    use crate::{MemoryTrieStore, TrieKeySlice, TrieNode};

    #[test]
    fn delete_recursive_removes_whole_subtree() {
        let store = MemoryTrieStore::new();
        // Account-style layout: a prefix key with value plus descendants.
        let acct = [0xAB, 0xCD];
        let mut child_a = acct.to_vec();
        child_a.push(0x00); // "storage prefix"
        let mut child_b = acct.to_vec();
        child_b.extend_from_slice(&[0x00, 0x55]); // "storage cell"
        let mut child_c = acct.to_vec();
        child_c.push(0x80); // "code"
        let other = [0xAB, 0x00]; // sibling outside the subtree

        let root = TrieNode::empty()
            .put(&TrieKeySlice::from_key(&acct), &[1, 2, 3], &store)
            .put(&TrieKeySlice::from_key(&child_a), &[1], &store)
            .put(&TrieKeySlice::from_key(&child_b), &[9, 9], &store)
            .put(&TrieKeySlice::from_key(&child_c), &[0x60, 0x00], &store)
            .put(&TrieKeySlice::from_key(&other), &[7], &store);

        let new_root = root.delete_recursive(&TrieKeySlice::from_key(&acct), &store);

        assert!(new_root.get(&TrieKeySlice::from_key(&acct), &store).is_none());
        assert!(new_root.get(&TrieKeySlice::from_key(&child_a), &store).is_none());
        assert!(new_root.get(&TrieKeySlice::from_key(&child_b), &store).is_none());
        assert!(new_root.get(&TrieKeySlice::from_key(&child_c), &store).is_none());
        assert_eq!(new_root.get(&TrieKeySlice::from_key(&other), &store), Some(vec![7]));

        // Root hash equals a trie that never contained the subtree.
        let clean = TrieNode::empty().put(&TrieKeySlice::from_key(&other), &[7], &store);
        assert_eq!(new_root.compute_hash(&store), clean.compute_hash(&store));
    }

    #[test]
    fn delete_recursive_on_missing_key_is_noop() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty().put(&TrieKeySlice::from_key(&[0x11]), &[1], &store);
        let new_root = root.delete_recursive(&TrieKeySlice::from_key(&[0x22]), &store);
        assert_eq!(new_root.compute_hash(&store), root.compute_hash(&store));
    }
}

#[cfg(test)]
mod orchid_converter_tests {
    use crate::account::AccountState;
    use crate::key_mapper::{account_key, account_key_from_bytes, code_key, storage_key, storage_prefix_key};
    use crate::{empty_trie_hash, orchid_state_root, MemoryTrieStore, TrieKeySlice, TrieNode};
    use alloy_primitives::{Address, B256, U256};

    fn put(root: TrieNode, store: &MemoryTrieStore, key: &[u8], value: &[u8]) -> TrieNode {
        root.put(&TrieKeySlice::from_key(key), value, store)
    }

    #[test]
    fn orchid_conversion_smoke() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();

        // EOA
        let eoa = Address::repeat_byte(0x11);
        root = put(root, &store, &account_key(&eoa),
            &AccountState::new(U256::from(1), U256::from(1000)).encode());

        // Contract: account + marker + code + 2 storage cells (incl. a
        // leading-zeroes slot, stored stripped in the unitrie).
        let c = Address::repeat_byte(0x22);
        root = put(root, &store, &account_key(&c),
            &AccountState::new(U256::ZERO, U256::from(5)).encode());
        root = put(root, &store, &storage_prefix_key(&c), &[1]);
        root = put(root, &store, &code_key(&c), &[0x60, 0x00, 0x60, 0x00, 0xF3]);
        root = put(root, &store, &storage_key(&c, &B256::from(U256::from(1))), &[42]);
        root = put(root, &store, &storage_key(&c, &B256::repeat_byte(0xCD)), &[1, 2, 3]);

        // REMASC sender account (1-byte address, 12-byte unitrie key).
        root = put(root, &store, &account_key_from_bytes(&[0x00]),
            &AccountState::new(U256::ZERO, U256::from(7)).encode());

        let r1 = orchid_state_root(&root, &store);
        let r2 = orchid_state_root(&root, &store);
        assert_eq!(r1, r2, "deterministic");
        assert_ne!(r1, empty_trie_hash());
    }

    #[test]
    fn orchid_root_ignores_contract_marker() {
        // The storage-prefix marker node exists only in the unitrie; the
        // Orchid storage trie root must be identical with or without it
        // (rskj TrieConverter strips the first storage node's value).
        let store = MemoryTrieStore::new();
        let c = Address::repeat_byte(0x33);
        let base = TrieNode::empty().put(
            &TrieKeySlice::from_key(&account_key(&c)),
            &AccountState::new(U256::ZERO, U256::from(9)).encode(),
            &store,
        );

        let without_marker = orchid_state_root(&base, &store);
        let with_marker = base.put(
            &TrieKeySlice::from_key(&storage_prefix_key(&c)),
            &[1],
            &store,
        );
        let with_marker_root = orchid_state_root(&with_marker, &store);
        assert_eq!(without_marker, with_marker_root);

        // But the unitrie roots DO differ — the marker is consensus-relevant
        // for the wasabi (RSKIP126) state root.
        assert_ne!(
            base.compute_hash(&store),
            with_marker.compute_hash(&store)
        );
    }
}
