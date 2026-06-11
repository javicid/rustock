/// Applies revm's EvmState changes back to the RSK Unitrie.
///
/// After executing a block through revm, the resulting `EvmState` contains
/// all account, code, and storage modifications. This module translates
/// those changes into Unitrie put/delete operations.
use alloy_primitives::{Address, B256, U256};
use revm::state::{AccountStatus, EvmState};
use rustock_trie::{
    AccountState, TrieKeySlice, TrieNode, TrieStore,
    account_key, code_key, storage_key, storage_prefix_key,
};
use tracing::debug;

/// Contract storage-prefix marker nodes to write alongside the EVM state
/// (rskj `MutableRepository.setupContract`: `[0x01]` at `account_key || 0x00`).
#[derive(Debug, Default)]
pub struct ContractMarkers {
    /// Created accounts that must NOT get a marker: a top-level CREATE
    /// transaction with empty data creates the account "without code nor
    /// storage. It doesn't even call setupContract()" (rskj
    /// TransactionExecutor.create).
    pub skip_created: Vec<Address>,
    /// Precompiles successfully called during the block; rskj writes their
    /// marker on the first successful call (TransactionExecutor.call /
    /// Program.callToPrecompiledAddress).
    pub precompiles: Vec<Address>,
    /// The REMASC system tx executed: rskj `TransactionExecutor.execute`
    /// increments the sender nonce, and the REMASC tx sender is the special
    /// 1-byte `[0x00]` address (12-byte unitrie key), so its nonce equals the
    /// block height. revm cannot represent the 1-byte address, so the bump is
    /// applied directly to the trie.
    pub bump_remasc_sender: bool,
    /// Raw-bytes storage writes (rskj `addStorageBytes`): one variable-length
    /// value per unitrie storage key, bypassing revm's U256-valued slots.
    /// `None` deletes the entry.
    pub raw_storage: Vec<crate::raw_storage::RawWrite>,
}

/// Apply all state changes from EVM execution to the trie, returning the new root.
pub fn apply_state_changes(
    root: &TrieNode,
    store: &dyn TrieStore,
    state: &EvmState,
    markers: &ContractMarkers,
) -> TrieNode {
    let mut new_root = root.clone();

    for (addr, account) in state {
        if account.status.contains(AccountStatus::SelfDestructed) {
            // rskj `MutableRepository.delete`: the whole account subtree
            // (storage, code, marker) goes away in one recursive delete.
            // rskj deletes at the END of the destroying transaction
            // (TransactionExecutor.finalization), so a LATER tx in the same
            // block can re-create the address as a fresh account (frontier
            // `transfer`/`addBalance(0)`). The executor neutralizes the
            // journal entry once the destroying tx commits (wiping it and
            // clearing the touched flag), so `is_touched()` here means
            // "alive again at block end": fall through and write the fresh
            // account state (mainnet #3173807). Untouched means the
            // destruction was the last word: the delete is everything.
            let key = TrieKeySlice::from_key(&account_key(addr));
            new_root = new_root.delete_recursive(&key, store);
            debug!(%addr, "self-destructed account subtree removed from trie");
        }

        if !account.is_touched() {
            continue;
        }

        new_root = put_account_info(&new_root, store, addr, account);

        if account.status.contains(AccountStatus::Created) {
            // rskj calls `setupContract` (which writes the storage-prefix
            // marker) only for genuine CREATEs — never for an empty account
            // that merely received value. Under RSK's pre-Spurious-Dragon
            // ("frontier forever") account rules, revm's JournalInner::finalize
            // *materializes* every touched, empty, previously-non-existent
            // account by calling `mark_created()` (global `Created` only, no
            // `CreatedLocal`). Treating those as contract creations wrote
            // spurious `account_key || 0x00 = 0x01` cells absent from rskj's
            // unitrie (mainnet: ~20 EOAs that took value, by #1,591,000).
            // A real CREATE goes through `create_account_checkpoint`
            // (`mark_created_locally` → `CreatedLocal`) and deploys code, so
            // gate the marker on having code or being locally created.
            let code_bytes = account.info.code.as_ref().map(|c| c.original_bytes());
            let has_code = code_bytes.as_ref().is_some_and(|c| !c.is_empty());
            if !markers.skip_created.contains(addr) && (has_code || account.is_created_locally()) {
                let key = TrieKeySlice::from_key(&storage_prefix_key(addr));
                new_root = new_root.put(&key, &[1], store);
            }
            if let Some(code_bytes) = code_bytes {
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

    for addr in &markers.precompiles {
        let key = TrieKeySlice::from_key(&storage_prefix_key(addr));
        new_root = new_root.put(&key, &[1], store);
    }

    for (addr, slot, value) in &markers.raw_storage {
        let slot_b256 = B256::from(*slot);
        let key = TrieKeySlice::from_key(&storage_key(addr, &slot_b256));
        new_root = match value {
            Some(bytes) => new_root.put(&key, bytes, store),
            None => new_root.delete(&key, store),
        };
    }

    if markers.bump_remasc_sender {
        let key = TrieKeySlice::from_key(&rustock_trie::account_key_from_bytes(&[0x00]));
        let mut acct = new_root
            .get(&key, store)
            .and_then(|data| AccountState::decode(&data).ok())
            .unwrap_or_default();
        acct.nonce += U256::from(1);
        new_root = new_root.put(&key, &acct.encode(), store);
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

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());

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

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());

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

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());

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

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());

        let acct = read_account(&new_root, &store, &addr).unwrap();
        assert_eq!(acct.nonce, U256::from(1));

        let code_key_bytes = code_key(&addr);
        let code_trie_key = TrieKeySlice::from_key(&code_key_bytes);
        let stored_code = new_root.get(&code_trie_key, &store).unwrap();
        assert_eq!(stored_code, code);

        assert_eq!(read_storage(&new_root, &store, &addr, U256::from(0)), U256::from(99));
    }

    #[test]
    fn test_created_contract_gets_storage_prefix_marker() {
        let (store, root) = empty_trie();
        let addr = Address::repeat_byte(0xEE);

        // A genuine CREATE deploys code; rskj setupContract writes the marker.
        let code = vec![0x60, 0x00];
        let info = AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: B256::ZERO,
            code: Some(revm::bytecode::Bytecode::new_raw(code.into())),
            account_id: None,
        };
        let account = Account {
            info: info.clone(),
            original_info: Box::new(info),
            transaction_id: 0,
            storage: Default::default(),
            status: AccountStatus::Created | AccountStatus::Touched,
        };
        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());
        let marker_key = TrieKeySlice::from_key(&storage_prefix_key(&addr));
        assert_eq!(new_root.get(&marker_key, &store), Some(vec![1]), "rskj setupContract marker");

        // Same account in skip_created (empty-data CREATE tx): no marker.
        let markers = ContractMarkers { skip_created: vec![addr], ..Default::default() };
        let skipped_root = apply_state_changes(&root, &store, &state, &markers);
        assert_eq!(skipped_root.get(&marker_key, &store), None, "empty-data CREATE skips the marker");
    }

    /// rskj does NOT call setupContract for an empty account that merely
    /// received value: revm materializes it under pre-Spurious-Dragon rules
    /// (`Created` set by `mark_created()`, no `CreatedLocal`, no code), and
    /// such accounts must NOT get a storage-prefix marker. Ground truth:
    /// mainnet unitrie at #1,590,999 — rustock previously wrote ~20 spurious
    /// `account_key || 0x00 = 0x01` cells absent from rskj's trie.
    #[test]
    fn materialized_empty_account_gets_no_storage_prefix_marker() {
        let (store, root) = empty_trie();
        let addr = Address::repeat_byte(0xAB);

        // Empty (no code), Created (global) but NOT created-locally — exactly
        // how JournalInner::finalize marks a touched empty new account.
        let info = make_account_info(0, U256::ZERO);
        let account = Account {
            info: info.clone(),
            original_info: Box::new(info),
            transaction_id: 0,
            storage: Default::default(),
            status: AccountStatus::Created | AccountStatus::Touched,
        };
        assert!(!account.is_created_locally());
        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());
        let marker_key = TrieKeySlice::from_key(&storage_prefix_key(&addr));
        assert_eq!(
            new_root.get(&marker_key, &store), None,
            "materialized empty account must not get a storage-prefix marker",
        );
        // The account record itself is still written (frontier-forever).
        assert!(read_account(&new_root, &store, &addr).is_some());
    }

    #[test]
    fn test_precompile_markers_written() {
        let (store, root) = empty_trie();
        let ecrecover = Address::with_last_byte(0x01);

        let markers = ContractMarkers { precompiles: vec![ecrecover], ..Default::default() };
        let new_root = apply_state_changes(&root, &store, &EvmState::default(), &markers);

        let marker_key = TrieKeySlice::from_key(&storage_prefix_key(&ecrecover));
        assert_eq!(new_root.get(&marker_key, &store), Some(vec![1]));
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

        // Marker + a storage slot written in an "earlier block" that revm's
        // per-tx state map does not mention; the recursive delete must remove
        // them anyway (rskj MutableRepository.delete → deleteRecursive).
        let marker_key = TrieKeySlice::from_key(&storage_prefix_key(&addr));
        let root = root.put(&marker_key, &[1u8], &store);
        let old_slot = B256::from(U256::from(77));
        let old_slot_key = TrieKeySlice::from_key(&storage_key(&addr, &old_slot));
        let root = root.put(&old_slot_key, &[0xAAu8], &store);

        assert!(read_account(&root, &store, &addr).is_some());

        // The executor neutralizes a destroyed account when its tx commits:
        // info/storage wiped, Touched cleared. SelfDestructed without Touched
        // means the destruction was the last word in the block.
        let account = Account {
            info: AccountInfo::default(),
            original_info: Box::new(AccountInfo::default()),
            transaction_id: 0,
            storage: Default::default(),
            status: AccountStatus::SelfDestructed,
        };

        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());

        assert!(read_account(&new_root, &store, &addr).is_none());
        assert!(new_root.get(&code_trie_key, &store).is_none());
        assert_eq!(read_storage(&new_root, &store, &addr, U256::from(0)), U256::ZERO);
        let marker_key = TrieKeySlice::from_key(&storage_prefix_key(&addr));
        assert!(new_root.get(&marker_key, &store).is_none(), "marker removed");
        assert_eq!(
            read_storage(&new_root, &store, &addr, U256::from(77)),
            U256::ZERO,
            "storage from earlier blocks removed by the recursive delete"
        );
        assert!(new_root.is_empty_trie(), "nothing else was in the trie");
    }

    /// Mainnet #3173807: an account selfdestructed by one tx and re-created
    /// by a later tx in the same block arrives here as SelfDestructed AND
    /// Touched (the executor clears Touched when the destroying tx commits;
    /// only a later re-creation re-marks it). The old subtree must be deleted
    /// and the fresh account written.
    #[test]
    fn test_selfdestructed_then_recreated_account_rewritten_fresh() {
        let (store, root) = empty_trie();
        let addr = Address::repeat_byte(0xFF);

        // Old incarnation: account, code, marker, storage slot.
        let key_a = TrieKeySlice::from_key(&account_key(&addr));
        let root = root.put(&key_a, &AccountState::new(U256::from(5), U256::from(1000)).encode(), &store);
        let code_trie_key = TrieKeySlice::from_key(&code_key(&addr));
        let root = root.put(&code_trie_key, &[0x60, 0x00], &store);
        let marker_key = TrieKeySlice::from_key(&storage_prefix_key(&addr));
        let root = root.put(&marker_key, &[1u8], &store);
        let slot_b256 = B256::from(U256::from(7));
        let slot_key = TrieKeySlice::from_key(&storage_key(&addr, &slot_b256));
        let root = root.put(&slot_key, &[0xAAu8], &store);

        // Re-created incarnation: fresh (0, 42) info, wiped storage/code.
        let info = make_account_info(0, U256::from(42));
        let account = Account {
            info: info.clone(),
            original_info: Box::new(info),
            transaction_id: 0,
            storage: Default::default(),
            status: AccountStatus::SelfDestructed | AccountStatus::Touched,
        };
        let mut state = EvmState::default();
        state.insert(addr, account);

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());

        let acct = read_account(&new_root, &store, &addr).expect("fresh account node");
        assert_eq!(acct.nonce, U256::ZERO, "old nonce gone");
        assert_eq!(acct.balance, U256::from(42), "fresh balance");
        assert!(new_root.get(&code_trie_key, &store).is_none(), "old code deleted");
        assert!(new_root.get(&marker_key, &store).is_none(), "old marker deleted");
        assert!(new_root.get(&slot_key, &store).is_none(), "old storage deleted");
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

        let new_root = apply_state_changes(&root, &store, &state, &ContractMarkers::default());

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

        let root1 = apply_state_changes(&root, &store, &state, &ContractMarkers::default());
        let root2 = apply_state_changes(&root, &store, &state, &ContractMarkers::default());

        assert_eq!(
            root1.compute_hash(&store),
            root2.compute_hash(&store),
            "applying same state changes should produce same trie hash"
        );
    }
}
