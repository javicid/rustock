//! Raw-bytes contract storage, mirroring rskj `Repository.addStorageBytes`.
//!
//! rskj stores precompile byte-array entries (Bridge state, REMASC siblings)
//! as a single variable-length value at one unitrie key. revm storage slots
//! only hold `U256`, so these entries bypass the revm journal entirely:
//! writes accumulate here and are projected into the unitrie by
//! `apply_state_changes`; reads fall through to the parent block's trie.
//!
//! The overlay travels in the revm `Context`'s chain slot (`RskChainExt`), so
//! every bridge/remasc function reaches it through `ctx.chain_mut()`.
//!
//! Commit discipline mirrors rskj's repository tracks:
//! - per precompile call: `commit_call` on method success, `discard_call` on
//!   failure (rskj commits the call's child track only on success);
//! - per transaction: `begin_tx` / `discard_tx` (a failed tx reverts all of
//!   its calls' committed writes).
//!
//! Known limitation (consciously accepted): if a contract internally calls a
//! state-writing bridge method, the bridge call succeeds, and the CALLER
//! frame later reverts, rskj rolls the bridge writes back with the parent
//! track while this overlay keeps them. No pre-wasabi mainnet block does
//! this; the per-block orchid state-root check would halt right at such a
//! block if one existed.
use alloy_primitives::{Address, B256, U256};
use rustock_trie::{storage_key, TrieKeySlice, TrieNode, TrieStore};
use std::sync::Arc;

/// One raw storage write: `None` deletes the trie node (rskj
/// `addStorageBytes` with a null/empty value).
pub type RawWrite = (Address, U256, Option<Vec<u8>>);

/// revm `Context` chain-slot extension carrying RSK-specific execution state.
#[derive(Default)]
pub struct RskChainExt {
    pub raw_storage: RawStorage,
}

/// Raw-bytes storage overlay for the block being executed.
#[derive(Default)]
pub struct RawStorage {
    /// Writes committed by successful precompile calls, in write order.
    committed: Vec<RawWrite>,
    /// Writes of the in-flight precompile call.
    pending: Vec<RawWrite>,
    /// `committed` length when the current transaction started.
    tx_start: usize,
    /// Read-through to the parent block's state.
    reader: Option<(Arc<dyn TrieStore>, TrieNode)>,
}

impl RawStorage {
    /// Install the parent-state read-through (block start).
    pub fn set_reader(&mut self, store: Arc<dyn TrieStore>, root: TrieNode) {
        self.reader = Some((store, root));
    }

    /// Read the raw bytes at `(addr, key)`: pending call writes first, then
    /// writes committed earlier in the block, then the parent trie.
    pub fn get(&self, addr: Address, key: U256) -> Option<Vec<u8>> {
        for (a, k, v) in self.pending.iter().rev().chain(self.committed.iter().rev()) {
            if *a == addr && *k == key {
                return v.clone();
            }
        }
        let (store, root) = self.reader.as_ref()?;
        let trie_key = storage_key(&addr, &B256::from(key));
        root.get(&TrieKeySlice::from_key(&trie_key), store.as_ref())
    }

    /// Write raw bytes at `(addr, key)`. Empty bytes delete the entry
    /// (rskj `MutableRepository.addStorageBytes`).
    pub fn put(&mut self, addr: Address, key: U256, value: Option<Vec<u8>>) {
        let value = value.filter(|v| !v.is_empty());
        self.pending.push((addr, key, value));
    }

    /// Promote the in-flight call's writes (precompile method succeeded).
    pub fn commit_call(&mut self) {
        self.committed.append(&mut self.pending);
    }

    /// Drop the in-flight call's writes (precompile method failed).
    pub fn discard_call(&mut self) {
        self.pending.clear();
    }

    /// Mark the start of a transaction.
    pub fn begin_tx(&mut self) {
        debug_assert!(self.pending.is_empty());
        self.tx_start = self.committed.len();
    }

    /// Revert every write of the current transaction (tx failed).
    pub fn discard_tx(&mut self) {
        self.committed.truncate(self.tx_start);
        self.pending.clear();
    }

    /// Take all committed writes for trie projection (block end).
    pub fn drain(&mut self) -> Vec<RawWrite> {
        self.pending.clear();
        self.tx_start = 0;
        std::mem::take(&mut self.committed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustock_trie::MemoryTrieStore;

    const ADDR: Address = Address::new([0xBB; 20]);

    fn key(n: u64) -> U256 {
        U256::from(n)
    }

    #[test]
    fn pending_read_back_and_call_commit() {
        let mut raw = RawStorage::default();
        raw.put(ADDR, key(1), Some(vec![1, 2, 3]));
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1, 2, 3]));
        raw.commit_call();
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1, 2, 3]));
        assert_eq!(raw.drain().len(), 1);
    }

    #[test]
    fn discard_call_drops_pending_only() {
        let mut raw = RawStorage::default();
        raw.put(ADDR, key(1), Some(vec![1]));
        raw.commit_call();
        raw.put(ADDR, key(1), Some(vec![2]));
        raw.discard_call();
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1]));
    }

    #[test]
    fn discard_tx_reverts_committed_calls() {
        let mut raw = RawStorage::default();
        raw.put(ADDR, key(1), Some(vec![1]));
        raw.commit_call();
        raw.begin_tx();
        raw.put(ADDR, key(2), Some(vec![2]));
        raw.commit_call();
        raw.discard_tx();
        assert_eq!(raw.get(ADDR, key(1)), Some(vec![1]));
        assert_eq!(raw.get(ADDR, key(2)), None);
    }

    #[test]
    fn empty_value_means_delete() {
        let mut raw = RawStorage::default();
        raw.put(ADDR, key(1), Some(vec![1]));
        raw.commit_call();
        raw.put(ADDR, key(1), Some(vec![]));
        raw.commit_call();
        assert_eq!(raw.get(ADDR, key(1)), None);
        let writes = raw.drain();
        assert_eq!(writes[1].2, None);
    }

    #[test]
    fn reader_fallthrough_to_trie() {
        let store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());
        let trie_key = storage_key(&ADDR, &B256::from(key(7)));
        let root = TrieNode::empty().put(
            &TrieKeySlice::from_key(&trie_key),
            &[9, 9, 9],
            store.as_ref(),
        );
        let mut raw = RawStorage::default();
        raw.set_reader(store, root);
        assert_eq!(raw.get(ADDR, key(7)), Some(vec![9, 9, 9]));
        // An overlay delete shadows the trie value.
        raw.put(ADDR, key(7), None);
        assert_eq!(raw.get(ADDR, key(7)), None);
    }
}
