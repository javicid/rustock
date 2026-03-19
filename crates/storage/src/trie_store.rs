/// RocksDB-backed implementation of the TrieStore trait.
///
/// Persists trie nodes and long values to a dedicated column family,
/// matching rskj's TrieStoreImpl behavior where both node data and
/// externalized values share the same key space (keyed by keccak256 hash).
use rocksdb::{DB, Options, ColumnFamilyDescriptor};
use rustock_trie::TrieStore;
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

const CF_TRIE: &str = "trie_nodes";

/// Persistent trie store backed by RocksDB.
pub struct RocksDbTrieStore {
    db: Arc<DB>,
}

impl RocksDbTrieStore {
    /// Open or create a RocksDB-backed trie store at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_TRIE, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| anyhow::anyhow!("Failed to open trie RocksDB: {e}"))?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Open using an existing RocksDB instance that has a `trie_nodes` CF.
    pub fn from_db(db: Arc<DB>) -> Self {
        Self { db }
    }
}

impl TrieStore for RocksDbTrieStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let cf = self.db.cf_handle(CF_TRIE)?;
        match self.db.get_cf(cf, key) {
            Ok(val) => val,
            Err(e) => {
                warn!(target: "rustock::trie_store", "RocksDB get error: {e}");
                None
            }
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) {
        let cf = match self.db.cf_handle(CF_TRIE) {
            Some(cf) => cf,
            None => {
                warn!(target: "rustock::trie_store", "trie_nodes CF not found");
                return;
            }
        };
        if let Err(e) = self.db.put_cf(cf, key, value) {
            warn!(target: "rustock::trie_store", "RocksDB put error: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustock_trie::{TrieNode, TrieKeySlice, TrieStore, AccountState, account_key};
    use alloy_primitives::{Address, U256};

    #[test]
    fn test_basic_put_get() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbTrieStore::open(dir.path()).unwrap();

        store.put(b"key1", b"value1");
        store.put(b"key2", b"value2");

        assert_eq!(store.get(b"key1"), Some(b"value1".to_vec()));
        assert_eq!(store.get(b"key2"), Some(b"value2".to_vec()));
        assert_eq!(store.get(b"key3"), None);
    }

    #[test]
    fn test_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbTrieStore::open(dir.path()).unwrap();

        store.put(b"key", b"old");
        assert_eq!(store.get(b"key"), Some(b"old".to_vec()));

        store.put(b"key", b"new");
        assert_eq!(store.get(b"key"), Some(b"new".to_vec()));
    }

    #[test]
    fn test_persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();

        {
            let store = RocksDbTrieStore::open(dir.path()).unwrap();
            store.put(b"persistent_key", b"persistent_value");
        }

        {
            let store = RocksDbTrieStore::open(dir.path()).unwrap();
            assert_eq!(
                store.get(b"persistent_key"),
                Some(b"persistent_value".to_vec()),
                "value should survive close and reopen"
            );
        }
    }

    #[test]
    fn test_trie_operations_with_rocksdb_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbTrieStore::open(dir.path()).unwrap();

        let root = TrieNode::empty();
        let addr = Address::repeat_byte(0xAA);
        let key_bytes = account_key(&addr);
        let key = TrieKeySlice::from_key(&key_bytes);

        let acct = AccountState::new(U256::from(42), U256::from(1_000_000));
        let root = root.put(&key, &acct.encode(), &store);

        let retrieved = root.get(&key, &store).unwrap();
        let decoded = AccountState::decode(&retrieved).unwrap();
        assert_eq!(decoded.nonce, U256::from(42));
        assert_eq!(decoded.balance, U256::from(1_000_000));
    }

    #[test]
    fn test_trie_save_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbTrieStore::open(dir.path()).unwrap();

        let addr1 = Address::repeat_byte(0x11);
        let addr2 = Address::repeat_byte(0x22);
        let acct1 = AccountState::new(U256::from(1), U256::from(100));
        let acct2 = AccountState::new(U256::from(2), U256::from(200));

        let root = TrieNode::empty();
        let key1 = TrieKeySlice::from_key(&account_key(&addr1));
        let key2 = TrieKeySlice::from_key(&account_key(&addr2));
        let root = root.put(&key1, &acct1.encode(), &store);
        let root = root.put(&key2, &acct2.encode(), &store);

        let mut root = root;
        root.save(&store, true);
        let root_hash = root.compute_hash(&store);

        // Reload from store using the root hash
        let data = store.get(root_hash.as_slice())
            .expect("root node should be persisted after save");
        let reloaded = TrieNode::from_message(&data, &store);

        let v1 = reloaded.get(&key1, &store).unwrap();
        let d1 = AccountState::decode(&v1).unwrap();
        assert_eq!(d1.nonce, U256::from(1));
        assert_eq!(d1.balance, U256::from(100));

        let v2 = reloaded.get(&key2, &store).unwrap();
        let d2 = AccountState::decode(&v2).unwrap();
        assert_eq!(d2.nonce, U256::from(2));
        assert_eq!(d2.balance, U256::from(200));

        assert_eq!(
            reloaded.compute_hash(&store),
            root_hash,
            "reloaded trie should have the same root hash"
        );
    }

    #[test]
    fn test_empty_value_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbTrieStore::open(dir.path()).unwrap();

        store.put(b"", b"empty_key_value");
        assert_eq!(store.get(b""), Some(b"empty_key_value".to_vec()));

        store.put(b"key", b"");
        assert_eq!(store.get(b"key"), Some(b"".to_vec()));
    }
}
