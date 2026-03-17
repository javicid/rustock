/// revm Database adapter over the RSK Unitrie.
///
/// revm reads account state, code, and storage through the `Database` trait.
/// This adapter translates those queries into Unitrie key lookups using the
/// key_mapper module from rustock-trie.

use alloy_primitives::{Address, B256, U256};
use revm::database_interface::DBErrorMarker;
use revm::database_interface::DatabaseRef;
use revm::bytecode::Bytecode;
use revm::state::AccountInfo;
use rustock_trie::{
    TrieNode, TrieStore, TrieKeySlice,
    account_key, code_key, storage_key,
    AccountState,
};
use rustock_storage::BlockStore;
use std::sync::Arc;
use sha3::{Digest, Keccak256};

#[derive(Debug, thiserror::Error)]
pub enum RskDbError {
    #[error("trie lookup failed: {0}")]
    TrieError(String),
    #[error("RLP decode error: {0}")]
    RlpDecode(String),
    #[error("block store error: {0}")]
    BlockStore(String),
}

impl DBErrorMarker for RskDbError {}

/// Read-only view into the RSK world state at a particular trie root.
pub struct RskDatabase {
    root: TrieNode,
    store: Arc<dyn TrieStore>,
    block_store: Arc<BlockStore>,
}

impl RskDatabase {
    pub fn new(
        root: TrieNode,
        store: Arc<dyn TrieStore>,
        block_store: Arc<BlockStore>,
    ) -> Self {
        Self { root, store, block_store }
    }

    fn trie_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let expanded = TrieKeySlice::from_key(key);
        self.root.get(&expanded, self.store.as_ref())
    }
}

impl DatabaseRef for RskDatabase {
    type Error = RskDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let key = account_key(&address);
        let Some(data) = self.trie_get(&key) else {
            return Ok(None);
        };

        let acct = AccountState::decode(&data)
            .map_err(|e| RskDbError::RlpDecode(e.to_string()))?;

        let code_key = code_key(&address);
        let code = self.trie_get(&code_key);

        let code_hash = match &code {
            Some(c) => B256::from_slice(&Keccak256::digest(c)),
            None => revm::primitives::KECCAK_EMPTY,
        };

        let bytecode = match code {
            Some(c) => Bytecode::new_raw(c.into()),
            None => Bytecode::default(),
        };

        Ok(Some(AccountInfo {
            balance: acct.balance,
            nonce: acct.nonce.to::<u64>(),
            code_hash,
            code: Some(bytecode),
            account_id: None,
        }))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Code is always returned inline via basic_ref, so this is rarely called.
        // If revm does call it, we can't efficiently look up by hash in the Unitrie
        // (the trie is keyed by address, not code hash). Return empty.
        Ok(Bytecode::default())
    }

    fn storage_ref(
        &self,
        address: Address,
        index: U256,
    ) -> Result<U256, Self::Error> {
        let slot = B256::from(index);
        let key = storage_key(&address, &slot);

        match self.trie_get(&key) {
            Some(data) => {
                if data.len() > 32 {
                    return Err(RskDbError::TrieError(
                        format!("storage value too long: {} bytes", data.len()),
                    ));
                }
                let mut padded = [0u8; 32];
                padded[32 - data.len()..].copy_from_slice(&data);
                Ok(U256::from_be_bytes(padded))
            }
            None => Ok(U256::ZERO),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.block_store
            .canonical_hash(number)
            .map_err(|e| RskDbError::BlockStore(e.to_string()))?
            .ok_or_else(|| RskDbError::BlockStore(format!("block {} not found", number)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustock_trie::{MemoryTrieStore, TrieNode, TrieKeySlice};

    fn make_store_and_root() -> (Arc<MemoryTrieStore>, TrieNode) {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        (store, root)
    }

    fn put_account(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        nonce: u64,
        balance: U256,
    ) -> TrieNode {
        let key_bytes = account_key(addr);
        let key = TrieKeySlice::from_key(&key_bytes);
        let acct = AccountState::new(U256::from(nonce), balance);
        root.put(&key, &acct.encode(), store)
    }

    fn put_code(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        code: &[u8],
    ) -> TrieNode {
        let key_bytes = code_key(addr);
        let key = TrieKeySlice::from_key(&key_bytes);
        root.put(&key, code, store)
    }

    fn put_storage(
        root: &TrieNode,
        store: &dyn TrieStore,
        addr: &Address,
        slot: U256,
        value: U256,
    ) -> TrieNode {
        let slot_b256 = B256::from(slot);
        let key_bytes = storage_key(addr, &slot_b256);
        let key = TrieKeySlice::from_key(&key_bytes);
        let val_bytes: Vec<u8> = {
            let be = value.to_be_bytes::<32>();
            let start = be.iter().position(|&b| b != 0).unwrap_or(32);
            be[start..].to_vec()
        };
        if val_bytes.is_empty() {
            root.delete(&key, store)
        } else {
            root.put(&key, &val_bytes, store)
        }
    }

    #[test]
    fn test_basic_account_not_found() {
        let (store, root) = make_store_and_root();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let result = db.basic_ref(Address::ZERO).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_basic_account_found() {
        let (store, root) = make_store_and_root();
        let addr = Address::repeat_byte(0xAA);
        let root = put_account(&root, store.as_ref(), &addr, 42, U256::from(1_000_000));

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_eq!(info.nonce, 42);
        assert_eq!(info.balance, U256::from(1_000_000));
        assert_eq!(info.code_hash, revm::primitives::KECCAK_EMPTY);
    }

    #[test]
    fn test_account_with_code() {
        let (store, root) = make_store_and_root();
        let addr = Address::repeat_byte(0xBB);
        let code = vec![0x60, 0x00, 0x60, 0x00, 0xFD]; // PUSH0 PUSH0 REVERT

        let root = put_account(&root, store.as_ref(), &addr, 0, U256::ZERO);
        let root = put_code(&root, store.as_ref(), &addr, &code);

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let info = db.basic_ref(addr).unwrap().expect("account should exist");
        assert_ne!(info.code_hash, revm::primitives::KECCAK_EMPTY);
        assert!(info.code.is_some());
        assert_eq!(info.code.unwrap().original_bytes().as_ref(), &code);
    }

    #[test]
    fn test_storage_read() {
        let (store, root) = make_store_and_root();
        let addr = Address::repeat_byte(0xCC);
        let root = put_account(&root, store.as_ref(), &addr, 0, U256::ZERO);
        let root = put_storage(&root, store.as_ref(), &addr, U256::from(0), U256::from(42));
        let root = put_storage(&root, store.as_ref(), &addr, U256::from(1), U256::from(100));

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        assert_eq!(db.storage_ref(addr, U256::from(0)).unwrap(), U256::from(42));
        assert_eq!(db.storage_ref(addr, U256::from(1)).unwrap(), U256::from(100));
        assert_eq!(db.storage_ref(addr, U256::from(2)).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_storage_not_found_returns_zero() {
        let (store, root) = make_store_and_root();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let val = db.storage_ref(Address::repeat_byte(0xFF), U256::from(99)).unwrap();
        assert_eq!(val, U256::ZERO);
    }

    #[test]
    fn test_multiple_accounts() {
        let (store, root) = make_store_and_root();
        let addr1 = Address::repeat_byte(0x11);
        let addr2 = Address::repeat_byte(0x22);
        let addr3 = Address::repeat_byte(0x33);

        let root = put_account(&root, store.as_ref(), &addr1, 1, U256::from(100));
        let root = put_account(&root, store.as_ref(), &addr2, 2, U256::from(200));
        let root = put_account(&root, store.as_ref(), &addr3, 3, U256::from(300));

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let db = RskDatabase::new(root, store, block_store);

        let info1 = db.basic_ref(addr1).unwrap().unwrap();
        let info2 = db.basic_ref(addr2).unwrap().unwrap();
        let info3 = db.basic_ref(addr3).unwrap().unwrap();

        assert_eq!(info1.nonce, 1);
        assert_eq!(info2.nonce, 2);
        assert_eq!(info3.nonce, 3);
        assert_eq!(info1.balance, U256::from(100));
        assert_eq!(info2.balance, U256::from(200));
        assert_eq!(info3.balance, U256::from(300));
    }
}
