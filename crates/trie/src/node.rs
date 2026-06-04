/// RSKIP107-compatible trie node: binary radix-2 trie with path compression.
///
/// Each node has:
/// - `shared_path`: compressed path prefix (bits shared by all keys in this sub-trie)
/// - `left` / `right`: child references (bit 0 / bit 1)
/// - `value`: inline data for this key, or None
/// - `value_hash`: keccak256 of the value
/// - `children_size`: aggregate size of child sub-trees (VarInt-encoded in serialization)
use alloy_primitives::B256;
use sha3::{Digest, Keccak256};
use crate::path::TrieKeySlice;
use crate::shared_path;
use crate::store::TrieStore;
use crate::varint;

const MAX_EMBEDDED_NODE_SIZE: usize = 44;

fn keccak(data: &[u8]) -> B256 {
    B256::from_slice(&Keccak256::digest(data))
}

/// The empty trie hash is `keccak256(RLP(""))` = `keccak256([0x80])`.
pub fn empty_trie_hash() -> B256 {
    keccak(&[0x80])
}

/// Reference to a child node — either in-memory, by hash, or empty.
#[derive(Clone, Debug)]
pub enum NodeRef {
    Empty,
    Hash(B256),
    Node(Box<TrieNode>),
}

impl NodeRef {
    pub fn is_empty(&self) -> bool {
        matches!(self, NodeRef::Empty)
    }

    /// Resolves the node, loading from store if only a hash is available.
    pub fn resolve(&self, store: &dyn TrieStore) -> Option<TrieNode> {
        match self {
            NodeRef::Empty => None,
            NodeRef::Node(n) => Some(*n.clone()),
            NodeRef::Hash(h) => {
                let data = store.get(h.as_slice())?;
                Some(TrieNode::from_message(&data, store))
            }
        }
    }

    pub fn get_hash(&self, store: &dyn TrieStore) -> Option<B256> {
        match self {
            NodeRef::Empty => None,
            NodeRef::Hash(h) => Some(*h),
            NodeRef::Node(n) => Some(n.compute_hash(store)),
        }
    }

    fn is_embeddable(&self, store: &dyn TrieStore) -> bool {
        match self {
            NodeRef::Node(n) => n.is_embeddable(store),
            _ => false,
        }
    }

    fn serialized_length(&self, store: &dyn TrieStore) -> usize {
        if self.is_empty() {
            return 0;
        }
        if self.is_embeddable(store) {
            if let NodeRef::Node(n) = self {
                return 1 + n.message_length(store);
            }
        }
        32 // keccak256 hash
    }

    fn serialize_into(&self, out: &mut Vec<u8>, store: &dyn TrieStore) {
        match self {
            NodeRef::Empty => {}
            NodeRef::Node(n) if n.is_embeddable(store) => {
                let msg = n.to_message(store);
                out.push(msg.len() as u8);
                out.extend_from_slice(&msg);
            }
            _ => {
                if let Some(h) = self.get_hash(store) {
                    out.extend_from_slice(h.as_slice());
                }
            }
        }
    }

    /// The sub-tree size as defined by RSKIP107: serialized node + children_size + external_value_length.
    fn reference_size(&self, store: &dyn TrieStore) -> u64 {
        match self {
            NodeRef::Empty => 0,
            NodeRef::Node(n) => {
                let external_val_len = if n.has_long_value() { n.value_length() as u64 } else { 0 };
                n.children_size + external_val_len + n.message_length(store) as u64
            }
            NodeRef::Hash(h) => {
                if let Some(data) = store.get(h.as_slice()) {
                    let node = TrieNode::from_message(&data, store);
                    let external_val_len = if node.has_long_value() { node.value_length() as u64 } else { 0 };
                    node.children_size + external_val_len + data.len() as u64
                } else {
                    0
                }
            }
        }
    }
}

/// Orchid hash of a child reference (rskj `NodeReference.getHashOrchid`):
/// `None` for empty references.
fn orchid_child_hash(child: &NodeRef, is_secure: bool, store: &dyn TrieStore) -> Option<B256> {
    let node = child.resolve(store)?;
    Some(node.compute_hash_orchid(is_secure, store))
}

#[derive(Clone, Debug)]
pub struct TrieNode {
    pub shared_path: TrieKeySlice,
    pub value: Option<Vec<u8>>,
    pub value_hash: Option<B256>,
    pub left: NodeRef,
    pub right: NodeRef,
    pub children_size: u64,
    saved: bool,
}

impl TrieNode {
    pub fn empty() -> Self {
        Self {
            shared_path: TrieKeySlice::empty(),
            value: None,
            value_hash: None,
            left: NodeRef::Empty,
            right: NodeRef::Empty,
            children_size: 0,
            saved: false,
        }
    }

    pub fn new_leaf(shared_path: TrieKeySlice, value: Vec<u8>) -> Self {
        let value_hash = Some(keccak(&value));
        Self {
            shared_path,
            value: Some(value),
            value_hash,
            left: NodeRef::Empty,
            right: NodeRef::Empty,
            children_size: 0,
            saved: false,
        }
    }

    pub fn is_empty_trie(&self) -> bool {
        self.value.is_none() && self.left.is_empty() && self.right.is_empty()
    }

    pub fn is_terminal(&self) -> bool {
        self.left.is_empty() && self.right.is_empty()
    }

    pub fn value_length(&self) -> usize {
        self.value.as_ref().map_or(0, |v| v.len())
    }

    pub fn has_long_value(&self) -> bool {
        self.value_length() > 32
    }

    fn get_value_hash(&self) -> B256 {
        self.value_hash.unwrap_or_else(|| {
            self.value.as_ref().map_or(B256::ZERO, |v| keccak(v))
        })
    }

    pub fn is_embeddable(&self, store: &dyn TrieStore) -> bool {
        self.is_terminal() && self.message_length(store) <= MAX_EMBEDDED_NODE_SIZE
    }

    pub fn message_length(&self, store: &dyn TrieStore) -> usize {
        let lshared = self.shared_path.length();
        let has_long_val = self.has_long_value();
        let vlen = self.value_length();

        1 // flags
        + shared_path::serialized_length(lshared)
        + self.left.serialized_length(store)
        + self.right.serialized_length(store)
        + if self.is_terminal() { 0 } else { varint::varint_size(self.children_size) }
        + if has_long_val { 32 + 3 } else { vlen }
    }

    /// Serializes this node to the RSKIP107 wire format.
    pub fn to_message(&self, store: &dyn TrieStore) -> Vec<u8> {
        let cap = self.message_length(store);
        let mut out = Vec::with_capacity(cap);

        let has_long_val = self.has_long_value();

        let mut flags: u8 = 0b0100_0000; // version 01
        if has_long_val {
            flags |= 0b0010_0000;
        }
        if !self.shared_path.is_empty() {
            flags |= 0b0001_0000;
        }
        if !self.left.is_empty() {
            flags |= 0b0000_1000;
        }
        if !self.right.is_empty() {
            flags |= 0b0000_0100;
        }
        if self.left.is_embeddable(store) {
            flags |= 0b0000_0010;
        }
        if self.right.is_embeddable(store) {
            flags |= 0b0000_0001;
        }
        out.push(flags);

        shared_path::serialize(&self.shared_path, &mut out);

        self.left.serialize_into(&mut out, store);
        self.right.serialize_into(&mut out, store);

        if !self.is_terminal() {
            out.extend_from_slice(&varint::encode_varint(self.children_size));
        }

        if has_long_val {
            out.extend_from_slice(self.get_value_hash().as_slice());
            let vlen = self.value_length() as u32;
            out.push((vlen >> 16) as u8);
            out.push((vlen >> 8) as u8);
            out.push(vlen as u8);
        } else if let Some(ref v) = self.value {
            out.extend_from_slice(v);
        }

        out
    }

    /// Deserializes a node from the RSKIP107 wire format.
    pub fn from_message(data: &[u8], store: &dyn TrieStore) -> Self {
        let mut pos = 0;

        let flags = data[pos];
        pos += 1;

        let has_long_val = flags & 0b0010_0000 != 0;
        let shared_prefix_present = flags & 0b0001_0000 != 0;
        let left_present = flags & 0b0000_1000 != 0;
        let right_present = flags & 0b0000_0100 != 0;
        let left_embedded = flags & 0b0000_0010 != 0;
        let right_embedded = flags & 0b0000_0001 != 0;

        let (shared_path, sp_consumed) = shared_path::deserialize(data, pos, shared_prefix_present);
        pos += sp_consumed;

        let left = if left_present {
            if left_embedded {
                let len = data[pos] as usize;
                pos += 1;
                let node = TrieNode::from_message(&data[pos..pos + len], store);
                pos += len;
                NodeRef::Node(Box::new(node))
            } else {
                let hash = B256::from_slice(&data[pos..pos + 32]);
                pos += 32;
                NodeRef::Hash(hash)
            }
        } else {
            NodeRef::Empty
        };

        let right = if right_present {
            if right_embedded {
                let len = data[pos] as usize;
                pos += 1;
                let node = TrieNode::from_message(&data[pos..pos + len], store);
                pos += len;
                NodeRef::Node(Box::new(node))
            } else {
                let hash = B256::from_slice(&data[pos..pos + 32]);
                pos += 32;
                NodeRef::Hash(hash)
            }
        } else {
            NodeRef::Empty
        };

        let children_size = if left_present || right_present {
            let (v, vs) = varint::decode_varint(&data[pos..]);
            pos += vs;
            v
        } else {
            0
        };

        let (value, value_hash) = if has_long_val {
            let vh = B256::from_slice(&data[pos..pos + 32]);
            pos += 32;
            let vlen = ((data[pos] as u32) << 16)
                | ((data[pos + 1] as u32) << 8)
                | (data[pos + 2] as u32);
            let val = store.get(vh.as_slice());
            debug_assert!(val.as_ref().is_none_or(|v| v.len() == vlen as usize));
            (val, Some(vh))
        } else {
            let remaining = data.len() - pos;
            if remaining > 0 {
                let v = data[pos..].to_vec();
                let vh = keccak(&v);
                (Some(v), Some(vh))
            } else {
                (None, None)
            }
        };

        Self {
            shared_path,
            value,
            value_hash,
            left,
            right,
            children_size,
            saved: false,
        }
    }

    /// Computes the Keccak-256 hash of this node's serialized message.
    pub fn compute_hash(&self, store: &dyn TrieStore) -> B256 {
        if self.is_empty_trie() {
            return empty_trie_hash();
        }
        keccak(&self.to_message(store))
    }

    /// Serializes this node in the pre-RSKIP107 ("Orchid") wire format
    /// (rskj `Trie.toMessageOrchid`). Used for the tx/receipts trie roots in
    /// block headers before RSKIP126 activated.
    ///
    /// Layout: arity(1) | flags(1) | child-bits(u16 BE) | lshared-in-bits(u16 BE)
    /// | encoded path | left orchid hash | right orchid hash | value-or-valueHash.
    pub fn to_message_orchid(&self, is_secure: bool, store: &dyn TrieStore) -> Vec<u8> {
        let lshared = self.shared_path.length();
        let has_long_val = self.has_long_value();
        let left_hash = orchid_child_hash(&self.left, is_secure, store);
        let right_hash = orchid_child_hash(&self.right, is_secure, store);

        let mut bits = 0u16;
        if left_hash.is_some() {
            bits |= 0b01;
        }
        if right_hash.is_some() {
            bits |= 0b10;
        }

        let mut out = Vec::new();
        out.push(2); // ARITY
        let mut flags = 0u8;
        if is_secure {
            flags |= 1;
        }
        if has_long_val {
            flags |= 2;
        }
        out.push(flags);
        out.extend_from_slice(&bits.to_be_bytes());
        out.extend_from_slice(&(lshared as u16).to_be_bytes());

        if lshared > 0 {
            out.extend_from_slice(&self.shared_path.encode());
        }
        if let Some(h) = left_hash {
            out.extend_from_slice(h.as_slice());
        }
        if let Some(h) = right_hash {
            out.extend_from_slice(h.as_slice());
        }

        if self.value_length() > 0 {
            if has_long_val {
                out.extend_from_slice(self.get_value_hash().as_slice());
            } else if let Some(ref v) = self.value {
                out.extend_from_slice(v);
            }
        }

        out
    }

    /// Keccak-256 of the Orchid serialization (rskj `Trie.getHashOrchid`).
    pub fn compute_hash_orchid(&self, is_secure: bool, store: &dyn TrieStore) -> B256 {
        if self.is_empty_trie() {
            return empty_trie_hash();
        }
        keccak(&self.to_message_orchid(is_secure, store))
    }

    /// Retrieves the value at the given key, or None.
    pub fn get(&self, key: &TrieKeySlice, store: &dyn TrieStore) -> Option<Vec<u8>> {
        let node = self.find(key, store)?;
        node.value.clone()
    }

    fn find(&self, key: &TrieKeySlice, store: &dyn TrieStore) -> Option<TrieNode> {
        if self.shared_path.length() > key.length() {
            return None;
        }

        let common = key.common_path(&self.shared_path);
        if common.length() < self.shared_path.length() {
            return None;
        }

        if common.length() == key.length() {
            return Some(self.clone());
        }

        let bit = key.get(common.length());
        let child_ref = if bit == 0 { &self.left } else { &self.right };
        let child = child_ref.resolve(store)?;
        let sub_key = key.slice(common.length() + 1, key.length());
        child.find(&sub_key, store)
    }

    /// Inserts or updates a value at the given key. Returns the new root node.
    pub fn put(&self, key: &TrieKeySlice, value: &[u8], store: &dyn TrieStore) -> TrieNode {
        let key_slice = key.clone();
        match self.internal_put(&key_slice, Some(value), false, store) {
            Some(node) => node,
            None => TrieNode::empty(),
        }
    }

    /// Deletes the value at the given key. Returns the new root node.
    pub fn delete(&self, key: &TrieKeySlice, store: &dyn TrieStore) -> TrieNode {
        let key_slice = key.clone();
        match self.put_impl(&key_slice, None, false, store) {
            Some(node) => node,
            None => TrieNode::empty(),
        }
    }

    fn put_impl(
        &self,
        key: &TrieKeySlice,
        value: Option<&[u8]>,
        is_recursive_delete: bool,
        store: &dyn TrieStore,
    ) -> Option<TrieNode> {
        let trie = self.internal_put(key, value, is_recursive_delete, store)?;

        // Coalescing: if deleting and result has exactly one child and no value, merge.
        if value.is_some() {
            return Some(trie);
        }

        if trie.is_empty_trie() {
            return None;
        }

        if trie.value.is_some() {
            return Some(trie);
        }

        // both present or both empty → no coalescing
        if trie.left.is_empty() == trie.right.is_empty() {
            return Some(trie);
        }

        let (child, implicit_bit) = if !trie.left.is_empty() {
            (trie.left.resolve(store)?, 0u8)
        } else {
            (trie.right.resolve(store)?, 1u8)
        };

        let new_path = trie.shared_path.rebuild_shared_path(implicit_bit, &child.shared_path);
        Some(TrieNode {
            shared_path: new_path,
            value: child.value,
            value_hash: child.value_hash,
            left: child.left,
            right: child.right,
            children_size: child.children_size,
            saved: false,
        })
    }

    fn internal_put(
        &self,
        key: &TrieKeySlice,
        value: Option<&[u8]>,
        is_recursive_delete: bool,
        store: &dyn TrieStore,
    ) -> Option<TrieNode> {
        // Normalize: empty value = deletion
        let value = match value {
            Some([]) => None,
            other => other,
        };

        let common = key.common_path(&self.shared_path);

        if common.length() < self.shared_path.length() {
            // Path diverges — need to split this node
            if value.is_none() {
                return Some(self.clone()); // deleting non-existent key
            }
            let split = self.split(&common, store);
            return split.put_impl(key, value, is_recursive_delete, store);
        }

        // Shared path is fully consumed
        if self.shared_path.length() >= key.length() {
            // This is the target node
            if self.value.as_deref() == value {
                return Some(self.clone()); // no change
            }

            if is_recursive_delete {
                return Some(TrieNode {
                    shared_path: self.shared_path.clone(),
                    value: None,
                    value_hash: None,
                    left: self.left.clone(),
                    right: self.right.clone(),
                    children_size: self.children_size,
                    saved: false,
                });
            }

            if Self::is_empty_trie_params(value, &self.left, &self.right) {
                return None;
            }

            let vh = value.map(keccak);
            return Some(TrieNode {
                shared_path: self.shared_path.clone(),
                value: value.map(|v| v.to_vec()),
                value_hash: vh,
                left: self.left.clone(),
                right: self.right.clone(),
                children_size: self.children_size,
                saved: false,
            });
        }

        if self.is_empty_trie() {
            // Replace empty trie with a new leaf
            let vh = value.map(keccak);
            return Some(TrieNode {
                shared_path: key.clone(),
                value: value.map(|v| v.to_vec()),
                value_hash: vh,
                left: NodeRef::Empty,
                right: NodeRef::Empty,
                children_size: 0,
                saved: false,
            });
        }

        // Navigate to child
        let bit = key.get(self.shared_path.length());
        let child_ref = if bit == 0 { &self.left } else { &self.right };
        let child = child_ref.resolve(store).unwrap_or_else(TrieNode::empty);

        let sub_key = key.slice(self.shared_path.length() + 1, key.length());
        let new_child_opt = child.put_impl(&sub_key, value, is_recursive_delete, store);

        // None means the child sub-tree was fully deleted
        let new_ref = match new_child_opt {
            Some(c) => NodeRef::Node(Box::new(c)),
            None => NodeRef::Empty,
        };

        let new_cs = self.children_size
            .saturating_sub(child_ref.reference_size(store))
            + new_ref.reference_size(store);

        let (new_left, new_right) = if bit == 0 {
            (new_ref, self.right.clone())
        } else {
            (self.left.clone(), new_ref)
        };

        if Self::is_empty_trie_params(self.value.as_deref(), &new_left, &new_right) {
            return None;
        }

        Some(TrieNode {
            shared_path: self.shared_path.clone(),
            value: self.value.clone(),
            value_hash: self.value_hash,
            left: new_left,
            right: new_right,
            children_size: new_cs,
            saved: false,
        })
    }

    fn split(&self, common_path: &TrieKeySlice, store: &dyn TrieStore) -> TrieNode {
        let common_len = common_path.length();
        let new_child_path = self.shared_path.slice(common_len + 1, self.shared_path.length());
        let new_child = TrieNode {
            shared_path: new_child_path,
            value: self.value.clone(),
            value_hash: self.value_hash,
            left: self.left.clone(),
            right: self.right.clone(),
            children_size: self.children_size,
            saved: false,
        };

        let child_ref = NodeRef::Node(Box::new(new_child));
        let bit = self.shared_path.get(common_len);

        let cs = child_ref.reference_size(store);
        let (new_left, new_right) = if bit == 0 {
            (child_ref, NodeRef::Empty)
        } else {
            (NodeRef::Empty, child_ref)
        };

        TrieNode {
            shared_path: common_path.clone(),
            value: None,
            value_hash: None,
            left: new_left,
            right: new_right,
            children_size: cs,
            saved: false,
        }
    }

    fn is_empty_trie_params(value: Option<&[u8]>, left: &NodeRef, right: &NodeRef) -> bool {
        value.is_none() && left.is_empty() && right.is_empty()
    }

    /// Recursively saves this node (and its children) to the store.
    pub fn save(&mut self, store: &dyn TrieStore, is_root: bool) {
        if self.saved {
            return;
        }

        // Recursively save children if they are in-memory
        if let NodeRef::Node(ref mut child) = self.left {
            child.save(store, false);
        }
        if let NodeRef::Node(ref mut child) = self.right {
            child.save(store, false);
        }

        // Save long values separately
        if self.has_long_value() {
            if let Some(ref v) = self.value {
                let vh = self.get_value_hash();
                store.put(vh.as_slice(), v);
            }
        }

        // Embeddable non-root nodes are not stored independently
        if self.is_embeddable(store) && !is_root {
            self.saved = true;
            return;
        }

        let hash = self.compute_hash(store);
        let msg = self.to_message(store);
        store.put(hash.as_slice(), &msg);
        self.saved = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryTrieStore;
    use std::sync::Arc;

    #[test]
    fn test_empty_trie_hash() {
        let h = empty_trie_hash();
        assert_eq!(
            format!("{h:x}"),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn test_leaf_serialization_roundtrip() {
        let store = MemoryTrieStore::new();
        let path = TrieKeySlice::new(vec![1, 0, 1], 0, 3);
        let node = TrieNode::new_leaf(path.clone(), vec![0xAB, 0xCD]);

        let msg = node.to_message(&store);
        let decoded = TrieNode::from_message(&msg, &store);

        assert_eq!(decoded.shared_path, path);
        assert_eq!(decoded.value, Some(vec![0xAB, 0xCD]));
        assert!(decoded.left.is_empty());
        assert!(decoded.right.is_empty());
    }

    #[test]
    fn test_node_hash_deterministic() {
        let store = MemoryTrieStore::new();
        let node = TrieNode::new_leaf(TrieKeySlice::from_key(&[0x01]), vec![0xFF]);
        let h1 = node.compute_hash(&store);
        let h2 = node.compute_hash(&store);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_put_single_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        let key = TrieKeySlice::from_key(&[0x01]);
        let root = root.put(&key, &[0xAA], &store);

        let val = root.get(&key, &store);
        assert_eq!(val, Some(vec![0xAA]));
    }

    #[test]
    fn test_put_two_diverging_keys() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();

        let k1 = TrieKeySlice::from_key(&[0x00]); // 00000000
        let k2 = TrieKeySlice::from_key(&[0x80]); // 10000000

        let root = root.put(&k1, b"val1", &store);
        let root = root.put(&k2, b"val2", &store);

        assert_eq!(root.get(&k1, &store), Some(b"val1".to_vec()));
        assert_eq!(root.get(&k2, &store), Some(b"val2".to_vec()));
    }

    #[test]
    fn test_put_overwrite() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        let key = TrieKeySlice::from_key(&[0x42]);

        let root = root.put(&key, b"old", &store);
        assert_eq!(root.get(&key, &store), Some(b"old".to_vec()));

        let root = root.put(&key, b"new", &store);
        assert_eq!(root.get(&key, &store), Some(b"new".to_vec()));
    }

    #[test]
    fn test_delete_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();

        let k1 = TrieKeySlice::from_key(&[0x00]);
        let k2 = TrieKeySlice::from_key(&[0x80]);

        let root = root.put(&k1, b"v1", &store);
        let root = root.put(&k2, b"v2", &store);
        let root = root.delete(&k1, &store);

        assert_eq!(root.get(&k1, &store), None);
        assert_eq!(root.get(&k2, &store), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_delete_last_key() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        let key = TrieKeySlice::from_key(&[0x01]);

        let root = root.put(&key, b"val", &store);
        let root = root.delete(&key, &store);

        assert!(root.is_empty_trie());
        assert_eq!(root.compute_hash(&store), empty_trie_hash());
    }

    #[test]
    fn test_save_and_reload() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let k1 = TrieKeySlice::from_key(&[0x01]);
        let k2 = TrieKeySlice::from_key(&[0x02]);

        let root = root.put(&k1, b"a", store.as_ref());
        let mut root = root.put(&k2, b"b", store.as_ref());

        let hash = root.compute_hash(store.as_ref());
        root.save(store.as_ref(), true);

        // Reload from store using only the hash
        let data = store.get(hash.as_slice()).expect("root should be saved");
        let reloaded = TrieNode::from_message(&data, store.as_ref());

        assert_eq!(reloaded.get(&k1, store.as_ref()), Some(b"a".to_vec()));
        assert_eq!(reloaded.get(&k2, store.as_ref()), Some(b"b".to_vec()));
        assert_eq!(reloaded.compute_hash(store.as_ref()), hash);
    }

    #[test]
    fn test_long_value() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let key = TrieKeySlice::from_key(&[0x01]);
        let long_val = vec![0xBB; 100]; // >32 bytes

        let mut root = root.put(&key, &long_val, store.as_ref());
        let hash = root.compute_hash(store.as_ref());
        root.save(store.as_ref(), true);

        let data = store.get(hash.as_slice()).unwrap();
        let reloaded = TrieNode::from_message(&data, store.as_ref());
        assert_eq!(reloaded.get(&key, store.as_ref()), Some(long_val));
    }

    #[test]
    fn test_many_keys() {
        let store = MemoryTrieStore::new();
        let mut root = TrieNode::empty();

        for i in 0u8..50 {
            let key = TrieKeySlice::from_key(&[i]);
            root = root.put(&key, &[i], &store);
        }

        for i in 0u8..50 {
            let key = TrieKeySlice::from_key(&[i]);
            assert_eq!(root.get(&key, &store), Some(vec![i]));
        }

        // Nonexistent key
        let key = TrieKeySlice::from_key(&[200]);
        assert_eq!(root.get(&key, &store), None);
    }

    #[test]
    fn test_hash_changes_on_put() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();
        let k1 = TrieKeySlice::from_key(&[0x01]);

        let root1 = root.put(&k1, b"a", &store);
        let h1 = root1.compute_hash(&store);

        let root2 = root1.put(&k1, b"b", &store);
        let h2 = root2.compute_hash(&store);

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_serialization_with_children() {
        let store = MemoryTrieStore::new();
        let root = TrieNode::empty();

        let k1 = TrieKeySlice::from_key(&[0x00]);
        let k2 = TrieKeySlice::from_key(&[0x80]);
        let k3 = TrieKeySlice::from_key(&[0x40]);

        let root = root.put(&k1, b"a", &store);
        let root = root.put(&k2, b"b", &store);
        let root = root.put(&k3, b"c", &store);

        let msg = root.to_message(&store);
        let decoded = TrieNode::from_message(&msg, &store);
        assert_eq!(decoded.compute_hash(&store), root.compute_hash(&store));
    }
}
