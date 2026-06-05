/// Applies revm's EvmState changes back to the RSK Unitrie.
///
/// After executing a block through revm, the resulting `EvmState` contains
/// all account, code, and storage modifications. This module translates
/// those changes into Unitrie put/delete operations.
use alloy_primitives::{Address, B256, U256};
use revm::state::{AccountStatus, EvmState};
use rustock_trie::{
    AccountState, TrieKeySlice, TrieNode, TrieStore,
    account_key, code_key, storage_key,
};
use tracing::debug;

/// Apply all state changes from EVM execution to the trie, returning the new root.
pub fn apply_state_changes(
    root: &TrieNode,
    store: &dyn TrieStore,
    state: &EvmState,
) -> TrieNode {
    let mut new_root = root.clone();

    for (addr, account) in state {
        if !account.is_touched() {
            continue;
        }

        if account.status.contains(AccountStatus::SelfDestructed) {
            new_root = delete_account(&new_root, store, addr, account);
            debug!(%addr, "self-destructed account removed from trie");
            continue;
        }

        new_root = put_account_info(&new_root, store, addr, account);

        if account.status.contains(AccountStatus::Created) {
            if let Some(ref code) = account.info.code {
                let code_bytes = code.original_bytes();
                if !code_bytes.is_empty() {
                    let key_bytes = code_key(addr);
                    let key = TrieKeySlice::from_key(&key_bytes);
                    new_root = new_root.put(&key, &code_bytes, store);
                }
            }
        }

        for (slot, storage_slot) in &account.storage {
            // No is_changed() filter: revm's per-transaction journal fold
            // resets a slot's original_value when a LATER transaction in the
            // same block re-reads it, making a genuine first-tx write look
            // unchanged (mainnet #378,129: the rejection release written by
            // registerBtcTransaction vanished because the block's own
            // updateCollections re-read the cells). Writing the present
            // value unconditionally is always correct — a read-only slot
            // holds the same value the trie already has.
            new_root = put_storage_value(&new_root, store, addr, *slot, storage_slot.present_value);
        }
    }

    new_root
}

fn put_account_info(
    root: &TrieNode,
    store: &dyn TrieStore,
    addr: &Address,
    account: &revm::state::Account,
) -> TrieNode {
    let key_bytes = account_key(addr);
    let key = TrieKeySlice::from_key(&key_bytes);
    let acct = AccountState::new(U256::from(account.info.nonce), account.info.balance);
    root.put(&key, &acct.encode(), store)
}

fn put_storage_value(
    root: &TrieNode,
    store: &dyn TrieStore,
    addr: &Address,
    slot: U256,
    value: U256,
) -> TrieNode {
    let slot_b256 = B256::from(slot);
    let key_bytes = storage_key(addr, &slot_b256);
    let key = TrieKeySlice::from_key(&key_bytes);

    if value.is_zero() {
        root.delete(&key, store)
    } else {
        let be = value.to_be_bytes::<32>();
        let start = be.iter().position(|&b| b != 0).unwrap_or(32);
        root.put(&key, &be[start..], store)
    }
}

fn delete_account(
    root: &TrieNode,
    store: &dyn TrieStore,
    addr: &Address,
    account: &revm::state::Account,
) -> TrieNode {
    let mut new_root = root.clone();

    for slot in account.storage.keys() {
        let slot_b256 = B256::from(*slot);
        let key_bytes = storage_key(addr, &slot_b256);
        let key = TrieKeySlice::from_key(&key_bytes);
        new_root = new_root.delete(&key, store);
    }

    let code_key_bytes = code_key(addr);
    let code_trie_key = TrieKeySlice::from_key(&code_key_bytes);
    new_root = new_root.delete(&code_trie_key, store);

    let acct_key_bytes = account_key(addr);
    let acct_trie_key = TrieKeySlice::from_key(&acct_key_bytes);
    new_root.delete(&acct_trie_key, store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use revm::state::{Account, AccountInfo, AccountStatus, EvmStorageSlot, EvmState};
    use rustock_trie::MemoryTrieStore;

    fn empty_trie() -> (MemoryTrieStore, TrieNode) {
        (MemoryTrieStore::new(), TrieNode::empty())
    }

    fn make_account_info(nonce: u64, balance: U256) -> AccountInfo {
        AccountInfo {
            balance,
            nonce,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
            account_id: None,
        }
    }

    fn make_touched_account(nonce: u64, balance: U256) -> Account {
        let info = make_account_info(nonce, balance);
        Account {
            info: info.clone(),
            original_info: Box::new(info),
            transaction_id: 0,
            storage: Default::default(),
            status: AccountStatus::Touched,
        }
    }

    fn read_account(root: &TrieNode, store: &dyn TrieStore, addr: &Address) -> Option<AccountState> {
        let key_bytes = account_key(addr);
        let key = TrieKeySlice::from_key(&key_bytes);
        root.get(&key, store).and_then(|data| AccountState::decode(&data).ok())
    }

    fn read_storage(root: &TrieNode, store: &dyn TrieStore, addr: &Address, slot: U256) -> U256 {
        let slot_b256 = B256::from(slot);
        let key_bytes = storage_key(addr, &slot_b256);
        let key = TrieKeySlice::from_key(&key_bytes);
        match root.get(&key, store) {
            Some(data) => {
                let mut padded = [0u8; 32];
                padded[32 - data.len()..].copy_from_slice(&data);
                U256::from_be_bytes(padded)
            }
            None => U256::ZERO,
        }
    }

    #[test]
    fn test_apply_simple_balance_transfer() {
        let (store, root) = empty_trie();
        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);

        let key_s = TrieKeySlice::from_key(&account_key(&sender));
        let acct_s = AccountState::new(U256::from(0), U256::from(1_000_000));
        let root = root.put(&key_s, &acct_s.encode(), &store);

        let mut state = EvmState::default();
        state.insert(sender, make_touched_account(1, U256::from(979_000)));
        state.insert(recipient, make_touched_account(0, U256::from(1_000)));

        let new_root = apply_state_changes(&root, &store, &state);

        let sender_acct = read_account(&new_root, &store, &sender).unwrap();
        assert_eq!(sender_acct.nonce, U256::from(1));
        assert_eq!(sender_acct.balance, U256::from(979_000));

        let recipient_acct = read_account(&new_root, &store, &recipient).unwrap();
        assert_eq!(recipient_acct.nonce, U256::from(0));
        assert_eq!(recipient_acct.balance, U256::from(1_000));
    }

    #[test]
    fn test_apply_storage_changes() {
        let (store, root) = empty_trie();
        let addr = Address::repeat_byte(0xCC);

        let key_a = TrieKeySlice::from_key(&account_key(&addr));
        let acct = AccountState::new(U256::from(0), U256::ZERO);
        let root = root.put(&key_a, &acct.encode(), &store);

        let mut account = make_touched_account(0, U256::ZERO);
        account.storage.insert(
            U256::from(0),
            EvmStorageSlot::new_changed(U256::ZERO, U256::from(42), 0),
        );
        account.storage.insert(
            U256::from(1),
            EvmStorageSlot::new_changed(U256::ZERO, U256::from(100), 0),
        );

        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state);

        assert_eq!(read_storage(&new_root, &store, &addr, U256::from(0)), U256::from(42));
        assert_eq!(read_storage(&new_root, &store, &addr, U256::from(1)), U256::from(100));
        assert_eq!(read_storage(&new_root, &store, &addr, U256::from(2)), U256::ZERO);
    }

    #[test]
    fn test_apply_storage_clear_zero() {
        let (store, root) = empty_trie();
        let addr = Address::repeat_byte(0xDD);

        let key_a = TrieKeySlice::from_key(&account_key(&addr));
        let acct = AccountState::new(U256::from(0), U256::ZERO);
        let root = root.put(&key_a, &acct.encode(), &store);

        let slot_b256 = B256::from(U256::from(5));
        let slot_key = TrieKeySlice::from_key(&storage_key(&addr, &slot_b256));
        let root = root.put(&slot_key, &[42u8], &store);

        assert_eq!(read_storage(&root, &store, &addr, U256::from(5)), U256::from(42));

        let mut account = make_touched_account(0, U256::ZERO);
        account.storage.insert(
            U256::from(5),
            EvmStorageSlot::new_changed(U256::from(42), U256::ZERO, 0),
        );

        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state);

        assert_eq!(read_storage(&new_root, &store, &addr, U256::from(5)), U256::ZERO);
    }

    #[test]
    fn test_apply_contract_creation_with_code() {
        let (store, root) = empty_trie();
        let addr = Address::repeat_byte(0xEE);
        let code = vec![0x60, 0x00, 0x60, 0x00, 0xF3];

        let info = AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: B256::ZERO,
            code: Some(revm::bytecode::Bytecode::new_raw(code.clone().into())),
            account_id: None,
        };
        let mut account = Account {
            info: info.clone(),
            original_info: Box::new(info),
            transaction_id: 0,
            storage: Default::default(),
            status: AccountStatus::Created | AccountStatus::Touched,
        };
        account.storage.insert(
            U256::from(0),
            EvmStorageSlot::new_changed(U256::ZERO, U256::from(99), 0),
        );

        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state);

        let acct = read_account(&new_root, &store, &addr).unwrap();
        assert_eq!(acct.nonce, U256::from(1));

        let code_key_bytes = code_key(&addr);
        let code_trie_key = TrieKeySlice::from_key(&code_key_bytes);
        let stored_code = new_root.get(&code_trie_key, &store).unwrap();
        assert_eq!(stored_code, code);

        assert_eq!(read_storage(&new_root, &store, &addr, U256::from(0)), U256::from(99));
    }

    #[test]
    fn test_apply_selfdestruct() {
        let (store, root) = empty_trie();
        let addr = Address::repeat_byte(0xFF);

        let key_a = TrieKeySlice::from_key(&account_key(&addr));
        let acct = AccountState::new(U256::from(5), U256::from(1000));
        let root = root.put(&key_a, &acct.encode(), &store);

        let code_key_bytes = code_key(&addr);
        let code_trie_key = TrieKeySlice::from_key(&code_key_bytes);
        let root = root.put(&code_trie_key, &[0x60, 0x00], &store);

        let slot_b256 = B256::from(U256::from(0));
        let slot_key = TrieKeySlice::from_key(&storage_key(&addr, &slot_b256));
        let root = root.put(&slot_key, &[7u8], &store);

        assert!(read_account(&root, &store, &addr).is_some());

        let info = make_account_info(5, U256::ZERO);
        let mut storage_map = revm::state::EvmStorage::default();
        storage_map.insert(U256::from(0), EvmStorageSlot::new_changed(U256::from(7), U256::ZERO, 0));

        let account = Account {
            info: info.clone(),
            original_info: Box::new(info),
            transaction_id: 0,
            storage: storage_map,
            status: AccountStatus::SelfDestructed | AccountStatus::Touched,
        };

        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state);

        assert!(read_account(&new_root, &store, &addr).is_none());
        assert!(new_root.get(&code_trie_key, &store).is_none());
        assert_eq!(read_storage(&new_root, &store, &addr, U256::from(0)), U256::ZERO);
    }

    #[test]
    fn test_untouched_accounts_ignored() {
        let (store, root) = empty_trie();
        let addr = Address::repeat_byte(0xAA);

        let key_a = TrieKeySlice::from_key(&account_key(&addr));
        let acct = AccountState::new(U256::from(0), U256::from(500));
        let root = root.put(&key_a, &acct.encode(), &store);

        let info = make_account_info(99, U256::from(999));
        let account = Account {
            info: info.clone(),
            original_info: Box::new(info),
            transaction_id: 0,
            storage: Default::default(),
            status: AccountStatus::empty(),
        };

        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state);

        let acct_after = read_account(&new_root, &store, &addr).unwrap();
        assert_eq!(acct_after.balance, U256::from(500), "untouched account should be unchanged");
    }

    #[test]
    fn test_apply_preserves_trie_hash_determinism() {
        let (store, root) = empty_trie();
        let addr1 = Address::repeat_byte(0x11);
        let addr2 = Address::repeat_byte(0x22);

        let mut state = EvmState::default();
        state.insert(addr1, make_touched_account(0, U256::from(100)));
        state.insert(addr2, make_touched_account(0, U256::from(200)));

        let root1 = apply_state_changes(&root, &store, &state);
        let root2 = apply_state_changes(&root, &store, &state);

        assert_eq!(
            root1.compute_hash(&store),
            root2.compute_hash(&store),
            "applying same state changes should produce same trie hash"
        );
    }
}
