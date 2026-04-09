/// Trie persistence layer.
///
/// The store maps byte keys (typically Keccak-256 hashes) to byte values.
/// Both trie nodes and long values (>32 bytes) share the same key space,
/// matching rskj's TrieStoreImpl behavior.
use std::collections::HashMap;
use std::sync::Mutex;

pub trait TrieStore: Send + Sync {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn put(&self, key: &[u8], value: &[u8]);
    /// Durably flush any buffered writes to the underlying storage.
    /// Default implementation is a no-op (suitable for stores that write synchronously).
    fn flush(&self) {}
}

/// In-memory store for testing.
pub struct MemoryTrieStore {
    data: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryTrieStore {
    pub fn new() -> Self {
        Self { data: Mutex::new(HashMap::new()) }
    }

    pub fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MemoryTrieStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrieStore for MemoryTrieStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.lock().unwrap().get(key).cloned()
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        self.data.lock().unwrap().insert(key.to_vec(), value.to_vec());
    }
}
