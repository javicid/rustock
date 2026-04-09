//! Write-buffered, LRU-cached trie store wrapping RocksDB.
//!
//! Improves on rskj's `DataSourceWithCache` by using RocksDB `WriteBatch`
//! as the write buffer instead of a `HashMap`:
//! - Single contiguous memory buffer (fewer allocations)
//! - Atomic flush via `db.write(batch)` (no partial writes on crash)
//! - One LRU read cache instead of rskj's dual committed/uncommitted caches

use lru::LruCache;
use rocksdb::{DB, WriteBatch};
use rustock_trie::TrieStore;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

const CF_TRIE: &str = "trie_nodes";
const DEFAULT_LRU_CAPACITY: usize = 50_000;
const DEFAULT_AUTO_FLUSH_THRESHOLD: usize = 10_000;

struct Inner {
    batch: WriteBatch,
    pending: HashMap<Vec<u8>, Vec<u8>>,
    cache: LruCache<Vec<u8>, Vec<u8>>,
    pending_count: usize,
    auto_flush_threshold: usize,
    total_flushed: u64,
}

/// A trie store that buffers writes in a RocksDB `WriteBatch` and caches
/// reads in an LRU cache. Writes are only durable after `flush()` is called.
pub struct CachedTrieStore {
    db: Arc<DB>,
    inner: Mutex<Inner>,
}

impl CachedTrieStore {
    pub fn new(db: Arc<DB>, lru_capacity: usize, auto_flush_threshold: usize) -> Self {
        let capacity = NonZeroUsize::new(lru_capacity.max(1)).unwrap();
        Self {
            db,
            inner: Mutex::new(Inner {
                batch: WriteBatch::default(),
                pending: HashMap::new(),
                cache: LruCache::new(capacity),
                pending_count: 0,
                auto_flush_threshold,
                total_flushed: 0,
            }),
        }
    }

    pub fn with_defaults(db: Arc<DB>) -> Self {
        Self::new(db, DEFAULT_LRU_CAPACITY, DEFAULT_AUTO_FLUSH_THRESHOLD)
    }

    fn do_flush(db: &DB, inner: &mut Inner) {
        if inner.pending_count == 0 {
            return;
        }

        let batch = std::mem::take(&mut inner.batch);
        let count = inner.pending_count;

        if let Err(e) = db.write(batch) {
            warn!(target: "rustock::cached_trie", "WriteBatch flush failed: {e}");
            return;
        }

        inner.pending.clear();
        inner.pending_count = 0;
        inner.total_flushed += count as u64;

        debug!(
            target: "rustock::cached_trie",
            "Flushed {count} trie entries (total: {})",
            inner.total_flushed
        );
    }
}

impl TrieStore for CachedTrieStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap();

        if let Some(val) = inner.pending.get(key) {
            return Some(val.clone());
        }

        if let Some(val) = inner.cache.get(key) {
            return Some(val.clone());
        }

        let cf = self.db.cf_handle(CF_TRIE)?;
        match self.db.get_cf(cf, key) {
            Ok(Some(val)) => {
                inner.cache.put(key.to_vec(), val.clone());
                Some(val)
            }
            Ok(None) => None,
            Err(e) => {
                warn!(target: "rustock::cached_trie", "RocksDB get error: {e}");
                None
            }
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        let mut inner = self.inner.lock().unwrap();

        let cf = match self.db.cf_handle(CF_TRIE) {
            Some(cf) => cf,
            None => {
                warn!(target: "rustock::cached_trie", "trie_nodes CF not found");
                return;
            }
        };

        inner.batch.put_cf(&cf, key, value);
        inner.pending.insert(key.to_vec(), value.to_vec());
        inner.cache.put(key.to_vec(), value.to_vec());
        inner.pending_count += 1;

        if inner.pending_count >= inner.auto_flush_threshold {
            debug!(
                target: "rustock::cached_trie",
                "Auto-flushing: pending count {} >= threshold {}",
                inner.pending_count, inner.auto_flush_threshold
            );
            Self::do_flush(&self.db, &mut inner);
        }
    }

    fn flush(&self) {
        let mut inner = self.inner.lock().unwrap();
        Self::do_flush(&self.db, &mut inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::Options;

    fn open_test_db(dir: &std::path::Path) -> Arc<DB> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = vec![rocksdb::ColumnFamilyDescriptor::new(
            CF_TRIE,
            Options::default(),
        )];
        Arc::new(DB::open_cf_descriptors(&opts, dir, cfs).unwrap())
    }

    #[test]
    fn put_get_before_flush() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());
        let store = CachedTrieStore::with_defaults(db);

        store.put(b"key1", b"val1");
        assert_eq!(store.get(b"key1"), Some(b"val1".to_vec()));
    }

    #[test]
    fn get_miss_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());
        let store = CachedTrieStore::with_defaults(db);

        assert_eq!(store.get(b"nonexistent"), None);
    }

    #[test]
    fn flush_persists_to_rocksdb() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());

        {
            let store = CachedTrieStore::with_defaults(db.clone());
            store.put(b"persist_key", b"persist_val");
            store.flush();
        }

        let cf = db.cf_handle(CF_TRIE).unwrap();
        let val = db.get_cf(cf, b"persist_key").unwrap();
        assert_eq!(val, Some(b"persist_val".to_vec()));
    }

    #[test]
    fn unflushed_data_not_in_rocksdb() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());

        {
            let store = CachedTrieStore::with_defaults(db.clone());
            store.put(b"temp_key", b"temp_val");
            // no flush
        }

        let cf = db.cf_handle(CF_TRIE).unwrap();
        let val = db.get_cf(cf, b"temp_key").unwrap();
        assert!(val.is_none(), "unflushed data should not be in RocksDB");
    }

    #[test]
    fn auto_flush_on_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());
        let store = CachedTrieStore::new(db.clone(), 1000, 5);

        for i in 0..5u8 {
            store.put(&[i], &[i + 100]);
        }

        let cf = db.cf_handle(CF_TRIE).unwrap();
        let val = db.get_cf(cf, &[0u8]).unwrap();
        assert_eq!(val, Some(vec![100]), "auto-flush should have written to DB");
    }

    #[test]
    fn lru_cache_serves_reads() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());

        let cf = db.cf_handle(CF_TRIE).unwrap();
        db.put_cf(cf, b"cached_key", b"cached_val").unwrap();

        let store = CachedTrieStore::new(db, 10, 10_000);

        // First read populates LRU
        assert_eq!(store.get(b"cached_key"), Some(b"cached_val".to_vec()));
        // Second read should come from LRU (can't easily verify, but ensures no crash)
        assert_eq!(store.get(b"cached_key"), Some(b"cached_val".to_vec()));
    }

    #[test]
    fn multiple_puts_same_key_uses_latest() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());
        let store = CachedTrieStore::with_defaults(db);

        store.put(b"key", b"first");
        store.put(b"key", b"second");
        store.put(b"key", b"third");

        assert_eq!(store.get(b"key"), Some(b"third".to_vec()));
    }

    #[test]
    fn flush_then_read_from_lru() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());
        let store = CachedTrieStore::with_defaults(db);

        store.put(b"k", b"v");
        store.flush();

        // After flush, pending is cleared but LRU still has the entry
        assert_eq!(store.get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn trie_save_and_reload_through_cache() {
        use rustock_trie::{TrieNode, TrieKeySlice, AccountState, account_key};
        use alloy_primitives::{Address, U256};

        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(dir.path());
        let store = CachedTrieStore::with_defaults(db);

        let addr = Address::repeat_byte(0xBB);
        let acct = AccountState::new(U256::from(7), U256::from(42_000));

        let root = TrieNode::empty();
        let key_bytes = account_key(&addr);
        let key = TrieKeySlice::from_key(&key_bytes);
        let root = root.put(&key, &acct.encode(), &store);

        let mut root = root;
        let hash = root.compute_hash(&store);
        root.save(&store, true);
        store.flush();

        // Reload from store using root hash
        let data = store.get(hash.as_slice()).expect("root should be persisted");
        let reloaded = TrieNode::from_message(&data, &store);

        let val = reloaded.get(&key, &store).unwrap();
        let decoded = AccountState::decode(&val).unwrap();
        assert_eq!(decoded.nonce, U256::from(7));
        assert_eq!(decoded.balance, U256::from(42_000));
        assert_eq!(reloaded.compute_hash(&store), hash);
    }
}
