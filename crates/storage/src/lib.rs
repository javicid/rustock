pub mod trie_store;
pub mod cached_trie_store;
pub use trie_store::RocksDbTrieStore;
pub use cached_trie_store::CachedTrieStore;

use rocksdb::{DB, Options, ColumnFamilyDescriptor};
use rustock_core::{Block, Header, Receipt, Transaction};
use alloy_primitives::{B256, U256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};
use anyhow::{Result, Context, anyhow};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, warn};

const CF_HEADERS: &str = "headers";
const CF_NUMBERS: &str = "block_numbers";
const CF_TD: &str = "total_difficulty";
const CF_BODIES: &str = "block_bodies";
const CF_RECEIPTS: &str = "receipts";
const CF_TX_INDEX: &str = "tx_index";
const KEY_HEAD: &[u8] = b"head";
const KEY_EXEC_HEAD: &[u8] = b"exec_head";

/// Safety limit: refuse to reorg deeper than this many blocks.
const MAX_REORG_DEPTH: u64 = 1000;

/// Manages storage of blockchain data using RocksDB.
/// 
/// Data is organized into Column Families:
/// - `headers`: Hash -> RLP(Header)
/// - `block_numbers`: BlockNumber (u64 BE) -> Hash
/// - `total_difficulty`: Hash -> RLP(TotalDifficulty)
/// - `block_bodies`: Hash -> RLP([transactions, ommers])
/// - `default`: Metadata like "head" -> Hash
pub struct BlockStore {
    db: Arc<DB>,
}

impl BlockStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_HEADERS, Options::default()),
            ColumnFamilyDescriptor::new(CF_NUMBERS, Options::default()),
            ColumnFamilyDescriptor::new(CF_TD, Options::default()),
            ColumnFamilyDescriptor::new(CF_BODIES, Options::default()),
            ColumnFamilyDescriptor::new(CF_RECEIPTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_TX_INDEX, Options::default()),
            ColumnFamilyDescriptor::new("trie_nodes", Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs).context("Failed to open RocksDB")?;
        Ok(Self { db: Arc::new(db) })
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily> {
        self.db.cf_handle(name)
            .ok_or_else(|| anyhow!("Column family {} not found", name))
    }

    // --- Header Operations ---

    pub fn put_header(&self, header: &Header) -> Result<()> {
        let hash = header.hash();
        self.put_header_with_hash(hash, header)
    }

    /// Stores a header under an explicit hash key (useful for genesis with non-standard RLP).
    pub fn put_header_with_hash(&self, hash: B256, header: &Header) -> Result<()> {
        let mut buf = Vec::new();
        header.encode(&mut buf);
        
        self.db.put_cf(self.cf(CF_HEADERS)?, hash.as_slice(), &buf)
            .context("Failed to write header")
    }

    pub fn header(&self, hash: B256) -> Result<Option<Header>> {
        let bytes = self.db.get_cf(self.cf(CF_HEADERS)?, hash.as_slice())
            .context("Failed to read header")?;
        bytes.map(|b| Header::decode(&mut b.as_slice()).map_err(Into::into)).transpose()
    }

    // --- Canonical Chain Operations ---

    pub fn put_canonical_hash(&self, number: u64, hash: B256) -> Result<()> {
        self.db.put_cf(self.cf(CF_NUMBERS)?, number.to_be_bytes(), hash.as_slice())
            .context("Failed to map number to hash")
    }

    pub fn canonical_hash(&self, number: u64) -> Result<Option<B256>> {
        let bytes = self.db.get_cf(self.cf(CF_NUMBERS)?, number.to_be_bytes())
            .context("Failed to read canonical hash")?;

        Ok(bytes.map(|b| B256::from_slice(&b)))
    }

    /// Removes the canonical `number → hash` mapping for a block height.
    pub fn delete_canonical_hash(&self, number: u64) -> Result<()> {
        self.db.delete_cf(self.cf(CF_NUMBERS)?, number.to_be_bytes())
            .context("Failed to delete canonical hash")
    }

    // --- Total Difficulty Operations ---

    pub fn put_total_difficulty(&self, hash: B256, td: U256) -> Result<()> {
        let mut buf = Vec::new();
        td.encode(&mut buf);
        
        self.db.put_cf(self.cf(CF_TD)?, hash.as_slice(), &buf)
            .context("Failed to write total difficulty")
    }

    pub fn total_difficulty(&self, hash: B256) -> Result<Option<U256>> {
        let bytes = self.db.get_cf(self.cf(CF_TD)?, hash.as_slice())
            .context("Failed to read total difficulty")?;
        bytes.map(|b| U256::decode(&mut b.as_slice()).map_err(Into::into)).transpose()
    }

    /// Checks if a block header exists in the store by hash.
    pub fn has_block(&self, hash: B256) -> Result<bool> {
        Ok(self.db.get_cf(self.cf(CF_HEADERS)?, hash.as_slice())
            .context("Failed to check header existence")?
            .is_some())
    }

    // --- Head Operations ---

    pub fn set_head(&self, hash: B256) -> Result<()> {
        self.db.put(KEY_HEAD, hash.as_slice())
            .context("Failed to set head")
    }

    pub fn head(&self) -> Result<Option<B256>> {
        let bytes = self.db.get(KEY_HEAD)
            .context("Failed to read head")?;

        Ok(bytes.map(|b| B256::from_slice(&b)))
    }

    /// Records the last EXECUTED block (hash) and its post-execution Unitrie
    /// state root. Distinct from `head`, which tracks the best downloaded
    /// block; the executed head is where block execution must resume.
    pub fn set_exec_head(&self, hash: B256, state_root: B256) -> Result<()> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(hash.as_slice());
        buf.extend_from_slice(state_root.as_slice());
        self.db.put(KEY_EXEC_HEAD, &buf)
            .context("Failed to set exec head")
    }

    /// Clears the executed-head marker so the node replays execution from
    /// genesis on next start, reusing already-downloaded headers and bodies
    /// instead of re-fetching them from peers.
    pub fn clear_exec_head(&self) -> Result<()> {
        self.db.delete(KEY_EXEC_HEAD)
            .context("Failed to clear exec head")
    }

    /// Returns the last executed block hash and its Unitrie state root.
    pub fn exec_head(&self) -> Result<Option<(B256, B256)>> {
        let bytes = self.db.get(KEY_EXEC_HEAD)
            .context("Failed to read exec head")?;
        Ok(bytes.filter(|b| b.len() == 64).map(|b| {
            (B256::from_slice(&b[..32]), B256::from_slice(&b[32..]))
        }))
    }

    // --- Batch / High Level Operations ---

    /// Updates the chain head and canonical mapping for a new best block.
    pub fn update_head(&self, header: &Header, td: U256) -> Result<()> {
        let hash = header.hash();

        self.put_header(header)?;
        self.put_total_difficulty(hash, td)?;
        self.put_canonical_hash(header.number, hash)?;
        self.set_head(hash)?;

        Ok(())
    }

    /// Atomically stores a batch of validated headers along with their total
    /// difficulties, then updates the canonical chain if the head changed.
    ///
    /// Headers and TDs are always stored (keyed by hash, safe for forks).
    /// Canonical `number → hash` mappings are only updated for blocks on the
    /// winning chain, preventing fork headers from corrupting the canonical
    /// pointers.
    ///
    /// Returns the hash of the new head (if it changed) or the existing head.
    pub fn store_headers_batch(
        &self,
        entries: &[(&Header, U256)],
        current_head_hash: Option<B256>,
        current_td: U256,
    ) -> Result<Option<B256>> {
        use rocksdb::WriteBatch;

        if entries.is_empty() {
            return Ok(current_head_hash);
        }

        let cf_headers = self.cf(CF_HEADERS)?;
        let cf_td = self.cf(CF_TD)?;

        let mut batch = WriteBatch::default();
        let mut best_hash = current_head_hash;
        let mut best_td = current_td;

        for &(header, td) in entries {
            let hash = header.hash();

            let mut header_buf = Vec::new();
            header.encode(&mut header_buf);
            batch.put_cf(cf_headers, hash.as_slice(), &header_buf);

            let mut td_buf = Vec::new();
            td.encode(&mut td_buf);
            batch.put_cf(cf_td, hash.as_slice(), &td_buf);

            if td > best_td {
                best_td = td;
                best_hash = Some(hash);
            }
        }

        // Commit headers + TDs first so update_canonical_chain can read them.
        self.db.write(batch).context("Failed to write header batch")?;

        // Update canonical chain only if the head actually changed.
        if best_hash != current_head_hash {
            if let Some(new_head) = best_hash {
                self.update_canonical_chain(new_head)?;
            }
        }

        Ok(best_hash)
    }

    /// Walks backward from `new_head` using `parent_hash` links, updating
    /// canonical `number → hash` mappings until the chain below is already
    /// consistent (the fork point).  Also sets `KEY_HEAD`.
    ///
    /// Handles both direct extensions (walk stops after 1 step) and reorgs
    /// (walk continues through the fork chain to the common ancestor).
    ///
    /// Stopping at the first already-canonical block is *not* sufficient: a
    /// prior walk truncated by a not-yet-downloaded parent header can leave a
    /// lower block stale while this one is canonical (skeleton sync delivers
    /// headers out of order). The canonical pointer at #N-1 would then keep
    /// naming an orphan even though #N points at the new fork — an internally
    /// inconsistent chain that wedges execution. So only stop once the
    /// canonical block at the parent's height actually *is* this block's
    /// parent; otherwise keep walking to repair the hole.
    pub fn update_canonical_chain(&self, new_head: B256) -> Result<()> {
        let depth = self.ensure_canonical_lineage(new_head)?;
        self.set_head(new_head)?;

        if depth > 1 {
            debug!(
                target: "rustock::storage",
                "Updated canonical chain ({} blocks rewritten)",
                depth
            );
        }

        Ok(())
    }

    /// Repair canonical `number → hash` pointers by walking back from `hash`
    /// (via `parent_hash`) until the chain below is already consistent, WITHOUT
    /// touching the head. Returns the number of pointers rewritten.
    ///
    /// Used both by `update_canonical_chain` (for a new head) and to repair a
    /// buried hole left by an earlier walk that truncated at a then-missing
    /// parent header — a tip-extension's walk stops at the top and never
    /// revisits such a hole, so it must be repaired explicitly at the block
    /// that exposes it.
    pub fn ensure_canonical_lineage(&self, hash: B256) -> Result<u64> {
        let mut hash = hash;
        let mut depth: u64 = 0;

        loop {
            let header = match self.header(hash)? {
                Some(h) => h,
                None => break, // parent not in store (e.g. pruned or pre-genesis)
            };

            let already_canonical = self.canonical_hash(header.number)? == Some(hash);
            if !already_canonical {
                self.put_canonical_hash(header.number, hash)?;
            }

            if header.number == 0 {
                break;
            }

            // Stop only when the chain below is already consistent: this block
            // is canonical AND #N-1's canonical hash is this block's parent.
            if already_canonical
                && self.canonical_hash(header.number - 1)? == Some(header.parent_hash)
            {
                break;
            }

            depth += 1;
            if depth >= MAX_REORG_DEPTH {
                warn!(
                    target: "rustock::storage",
                    "Canonical chain update reached MAX_REORG_DEPTH ({}) at block #{}",
                    MAX_REORG_DEPTH, header.number
                );
                break;
            }

            hash = header.parent_hash;
        }

        Ok(depth)
    }
}

impl BlockStore {
    /// Stores a block body (transactions + ommers) keyed by block hash.
    /// Uses the original peer-received RLP when available to preserve Java's
    /// non-canonical encoding (leading zeros in BigIntegers).
    pub fn put_body(
        &self,
        hash: B256,
        transactions: &[Transaction],
        ommers: &[Header],
    ) -> Result<()> {
        let mut txs_payload = Vec::new();
        for tx in transactions {
            txs_payload.extend_from_slice(&tx.rlp_for_trie());
        }
        let mut ommers_payload = Vec::new();
        for uncle in ommers {
            uncle.encode(&mut ommers_payload);
        }

        let body_len = RlpHeader { list: true, payload_length: txs_payload.len() }.length()
            + txs_payload.len()
            + RlpHeader { list: true, payload_length: ommers_payload.len() }.length()
            + ommers_payload.len();

        let mut buf = Vec::with_capacity(body_len + 5);
        RlpHeader { list: true, payload_length: body_len }.encode(&mut buf);
        RlpHeader { list: true, payload_length: txs_payload.len() }.encode(&mut buf);
        buf.extend_from_slice(&txs_payload);
        RlpHeader { list: true, payload_length: ommers_payload.len() }.encode(&mut buf);
        buf.extend_from_slice(&ommers_payload);

        self.db
            .put_cf(self.cf(CF_BODIES)?, hash.as_slice(), &buf)
            .context("Failed to write block body")
    }

    /// Reads a block body (transactions + ommers) by hash.
    pub fn body(&self, hash: B256) -> Result<Option<(Vec<Transaction>, Vec<Header>)>> {
        let bytes = self.db
            .get_cf(self.cf(CF_BODIES)?, hash.as_slice())
            .context("Failed to read block body")?;
        match bytes {
            None => Ok(None),
            Some(b) => {
                let mut buf = b.as_slice();
                let outer = RlpHeader::decode(&mut buf)?;
                let mut body = &buf[..outer.payload_length];

                let txs_h = RlpHeader::decode(&mut body)?;
                let mut txs_buf = &body[..txs_h.payload_length];
                body = &body[txs_h.payload_length..];
                let mut transactions = Vec::new();
                while !txs_buf.is_empty() {
                    transactions.push(Transaction::decode(&mut txs_buf)?);
                }

                let ommers_h = RlpHeader::decode(&mut body)?;
                let mut ommers_buf = &body[..ommers_h.payload_length];
                let mut ommers = Vec::new();
                while !ommers_buf.is_empty() {
                    ommers.push(Header::decode(&mut ommers_buf)?);
                }

                Ok(Some((transactions, ommers)))
            }
        }
    }

    /// Stores a full block (header + body).
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let hash = block.hash();
        self.put_header(&block.header)?;
        self.put_body(hash, &block.transactions, &block.ommers)?;
        self.put_canonical_hash(block.header.number, hash)
    }

    /// Returns a full block (header + body) by hash.
    /// If only the header is stored (no body), returns a header-only block
    /// with empty transactions and ommers.
    pub fn block(&self, hash: B256) -> Result<Option<Block>> {
        let header = match self.header(hash)? {
            Some(h) => h,
            None => return Ok(None),
        };

        let (transactions, ommers) = self.body(hash)?
            .unwrap_or_default();

        Ok(Some(Block { header, transactions, ommers }))
    }
}

impl BlockStore {
    /// Stores receipts for a block, keyed by block hash.
    pub fn put_receipts(&self, hash: B256, receipts: &[Receipt]) -> Result<()> {
        let mut payload = Vec::new();
        for r in receipts {
            r.encode(&mut payload);
        }
        let mut buf = Vec::with_capacity(payload.len() + 5);
        RlpHeader { list: true, payload_length: payload.len() }.encode(&mut buf);
        buf.extend_from_slice(&payload);

        self.db
            .put_cf(self.cf(CF_RECEIPTS)?, hash.as_slice(), &buf)
            .context("Failed to write receipts")
    }

    /// Reads receipts for a block by hash.
    pub fn receipts(&self, hash: B256) -> Result<Option<Vec<Receipt>>> {
        let bytes = self.db
            .get_cf(self.cf(CF_RECEIPTS)?, hash.as_slice())
            .context("Failed to read receipts")?;
        match bytes {
            None => Ok(None),
            Some(b) => {
                let mut buf = b.as_slice();
                let header = RlpHeader::decode(&mut buf)?;
                let mut data = &buf[..header.payload_length];
                let mut receipts = Vec::new();
                while !data.is_empty() {
                    receipts.push(Receipt::decode(&mut data)?);
                }
                Ok(Some(receipts))
            }
        }
    }
}

impl BlockStore {
    /// Stores a transaction index entry: tx_hash -> (block_hash, tx_index).
    pub fn put_tx_index(&self, tx_hash: B256, block_hash: B256, tx_index: u32) -> Result<()> {
        let mut val = [0u8; 36];
        val[..32].copy_from_slice(block_hash.as_slice());
        val[32..].copy_from_slice(&tx_index.to_be_bytes());
        self.db
            .put_cf(self.cf(CF_TX_INDEX)?, tx_hash.as_slice(), val)
            .context("Failed to write tx index")
    }

    /// Looks up which block contains a transaction and at what index.
    pub fn tx_location(&self, tx_hash: B256) -> Result<Option<(B256, u32)>> {
        let bytes = self.db
            .get_cf(self.cf(CF_TX_INDEX)?, tx_hash.as_slice())
            .context("Failed to read tx index")?;
        match bytes {
            None => Ok(None),
            Some(b) => {
                if b.len() < 36 {
                    return Err(anyhow!("corrupt tx index entry: {} bytes", b.len()));
                }
                let block_hash = B256::from_slice(&b[..32]);
                let tx_index = u32::from_be_bytes([b[32], b[33], b[34], b[35]]);
                Ok(Some((block_hash, tx_index)))
            }
        }
    }

    /// Indexes all transactions in a block body for fast lookup by tx hash.
    /// Computes each transaction's hash from its RLP encoding.
    pub fn index_block_transactions(&self, block_hash: B256, transactions: &[Transaction]) -> Result<()> {
        use sha3::{Digest, Keccak256};

        for (i, tx) in transactions.iter().enumerate() {
            let mut buf = Vec::new();
            tx.encode(&mut buf);
            let tx_hash = B256::from_slice(&Keccak256::digest(&buf));
            self.put_tx_index(tx_hash, block_hash, i as u32)?;
        }
        Ok(())
    }

    /// Returns a reference to the underlying RocksDB instance.
    pub fn db(&self) -> &Arc<DB> {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustock_core::{Header, Transaction};
    use alloy_primitives::{Address, B256, U256, Bytes};
    use tempfile::tempdir;

    fn dummy_tx(nonce: u64) -> Transaction {
        Transaction {
            nonce,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0x12; 20]),
            value: U256::from(1_000_000u64),
            input: Bytes::default(),
            v: 27,
            r: U256::from(nonce + 100),
            s: U256::from(nonce + 200),
            cached_rlp: None,
        }
    }

    fn dummy_header(number: u64) -> Header {
        Header {
            number,
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::ZERO,
            gas_limit: U256::ZERO,
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    #[test]
    fn test_header_flow() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(1);
        let hash = header.hash();

        // 1. Store Header
        store.put_header(&header).unwrap();
        
        // 2. Retrieve Header
        let retrieved = store.header(hash).unwrap().unwrap();
        assert_eq!(header, retrieved);

        // 3. Set Canonical
        store.put_canonical_hash(1, hash).unwrap();
        assert_eq!(store.canonical_hash(1).unwrap(), Some(hash));

        // 4. Set Head
        store.set_head(hash).unwrap();
        assert_eq!(store.head().unwrap(), Some(hash));

        // 5. Total Difficulty
        store.put_total_difficulty(hash, U256::from(100)).unwrap();
        assert_eq!(store.total_difficulty(hash).unwrap(), Some(U256::from(100)));

        // 6. Executed head (hash + unitrie state root), independent of head
        assert_eq!(store.exec_head().unwrap(), None);
        let state_root = B256::repeat_byte(0x42);
        store.set_exec_head(hash, state_root).unwrap();
        assert_eq!(store.exec_head().unwrap(), Some((hash, state_root)));
        assert_eq!(store.head().unwrap(), Some(hash)); // unchanged
    }

    #[test]
    fn test_update_head_flow() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(100);
        let hash = header.hash();
        let td = U256::from(500);

        store.update_head(&header, td).unwrap();

        // Verify everything was set
        assert_eq!(store.header(hash).unwrap().unwrap(), header);
        assert_eq!(store.canonical_hash(100).unwrap(), Some(hash));
        assert_eq!(store.total_difficulty(hash).unwrap(), Some(td));
        assert_eq!(store.head().unwrap(), Some(hash));
    }

    #[test]
    fn test_put_header_with_hash() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(1);
        let custom_hash = B256::repeat_byte(0xAA);

        store.put_header_with_hash(custom_hash, &header).unwrap();

        assert!(store.header(custom_hash).unwrap().is_some());
        assert!(store.header(header.hash()).unwrap().is_none());
    }

    #[test]
    fn test_has_block() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(1);
        store.put_header(&header).unwrap();

        assert!(store.has_block(header.hash()).unwrap());
        assert!(!store.has_block(B256::repeat_byte(0xFF)).unwrap());
    }

    #[test]
    fn test_put_header_with_hash_for_genesis() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let genesis = dummy_header(0);
        let known_hash = B256::repeat_byte(0x42);
        let td = U256::from(1000);

        store.put_header_with_hash(known_hash, &genesis).unwrap();
        store.put_total_difficulty(known_hash, td).unwrap();

        assert_eq!(store.header(known_hash).unwrap().unwrap(), genesis);
        assert_eq!(store.total_difficulty(known_hash).unwrap(), Some(td));
    }

    // --- store_headers_batch tests ---

    fn dummy_header_with_difficulty(number: u64, difficulty: u64) -> Header {
        let mut h = dummy_header(number);
        h.difficulty = U256::from(difficulty);
        h
    }

    #[test]
    fn test_store_headers_batch_empty() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let result = store
            .store_headers_batch(&[], None, U256::ZERO)
            .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_store_headers_batch_single_entry() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let h = dummy_header_with_difficulty(1, 10);
        let td = U256::from(10);
        let entries = vec![(&h, td)];

        let new_head = store
            .store_headers_batch(&entries, None, U256::ZERO)
            .unwrap();

        // TD(10) > current TD(0), so head should be updated
        assert_eq!(new_head, Some(h.hash()));
        assert!(store.header(h.hash()).unwrap().is_some());
        assert_eq!(store.total_difficulty(h.hash()).unwrap(), Some(td));
        assert_eq!(store.head().unwrap(), Some(h.hash()));
        assert_eq!(store.canonical_hash(1).unwrap(), Some(h.hash()));
    }

    #[test]
    fn test_store_headers_batch_multiple_ascending_td() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let h1 = dummy_header_with_difficulty(1, 5);
        let h2 = dummy_header_with_difficulty(2, 5);
        let h3 = dummy_header_with_difficulty(3, 5);
        let entries = vec![
            (&h1, U256::from(5)),
            (&h2, U256::from(10)),
            (&h3, U256::from(15)),
        ];

        let new_head = store
            .store_headers_batch(&entries, None, U256::ZERO)
            .unwrap();

        // h3 has the highest TD, so it should be the head
        assert_eq!(new_head, Some(h3.hash()));
        assert_eq!(store.head().unwrap(), Some(h3.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(h3.hash()));

        // All headers should be retrievable
        assert!(store.header(h1.hash()).unwrap().is_some());
        assert!(store.header(h2.hash()).unwrap().is_some());
        assert!(store.header(h3.hash()).unwrap().is_some());

        // All TDs should be stored
        assert_eq!(store.total_difficulty(h1.hash()).unwrap(), Some(U256::from(5)));
        assert_eq!(store.total_difficulty(h3.hash()).unwrap(), Some(U256::from(15)));
    }

    #[test]
    fn test_store_headers_batch_does_not_lower_head() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Set up existing head with TD=100
        let existing = dummy_header_with_difficulty(50, 100);
        store.update_head(&existing, U256::from(100)).unwrap();
        let existing_hash = existing.hash();

        // Batch with lower TD should not change head
        let h = dummy_header_with_difficulty(1, 5);
        let entries = vec![(&h, U256::from(5))];

        let result = store
            .store_headers_batch(&entries, Some(existing_hash), U256::from(100))
            .unwrap();

        // Head should remain unchanged
        assert_eq!(result, Some(existing_hash));
        assert_eq!(store.head().unwrap(), Some(existing_hash));

        // But the header should still be stored
        assert!(store.header(h.hash()).unwrap().is_some());
        assert_eq!(store.total_difficulty(h.hash()).unwrap(), Some(U256::from(5)));
    }

    // --- Reorg / canonical chain tests ---

    fn make_chain_header(number: u64, parent_hash: B256, difficulty: u64, nonce: u8) -> Header {
        let mut h = dummy_header(number);
        h.parent_hash = parent_hash;
        h.difficulty = U256::from(difficulty);
        // Use extra_data to differentiate forks at the same height
        h.extra_data = Bytes::from(vec![nonce]);
        h
    }

    /// Build a chain of headers and store them as the canonical chain.
    /// Returns (headers, cumulative TDs) for each block.
    fn build_and_store_chain(
        store: &BlockStore,
        count: usize,
        difficulty: u64,
        nonce: u8,
    ) -> Vec<(Header, U256)> {
        let mut chain = Vec::new();
        let mut parent_hash = B256::ZERO;
        let mut td = U256::ZERO;

        for i in 0..count {
            let h = make_chain_header(i as u64, parent_hash, difficulty, nonce);
            let hash = h.hash();
            td += h.difficulty;
            store.put_header(&h).unwrap();
            store.put_total_difficulty(hash, td).unwrap();
            store.put_canonical_hash(i as u64, hash).unwrap();
            parent_hash = hash;
            chain.push((h, td));
        }
        if let Some((last, _)) = chain.last() {
            store.set_head(last.hash()).unwrap();
        }
        chain
    }

    #[test]
    fn test_reorg_to_higher_td_fork() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Main chain: genesis -> 1A -> 2A -> 3A (difficulty 10 each, TD: 10, 20, 30, 40)
        let chain_a = build_and_store_chain(&store, 4, 10, 0xAA);
        let head_a = chain_a.last().unwrap().0.hash();
        assert_eq!(store.head().unwrap(), Some(head_a));

        // Fork chain: same genesis -> 1B -> 2B -> 3B (difficulty 20 each, higher TD)
        let genesis = &chain_a[0];
        let b1 = make_chain_header(1, genesis.0.hash(), 20, 0xBB);
        let b2 = make_chain_header(2, b1.hash(), 20, 0xBB);
        let b3 = make_chain_header(3, b2.hash(), 20, 0xBB);

        let td_b1 = genesis.1 + b1.difficulty; // 10 + 20 = 30
        let td_b2 = td_b1 + b2.difficulty;     // 30 + 20 = 50
        let td_b3 = td_b2 + b3.difficulty;     // 50 + 20 = 70

        let entries = vec![
            (&b1, td_b1),
            (&b2, td_b2),
            (&b3, td_b3),
        ];

        let result = store
            .store_headers_batch(&entries, Some(head_a), chain_a.last().unwrap().1)
            .unwrap();

        // Fork B has higher TD (70 vs 40), so head should switch
        assert_eq!(result, Some(b3.hash()));
        assert_eq!(store.head().unwrap(), Some(b3.hash()));

        // Canonical chain should now point to fork B
        assert_eq!(store.canonical_hash(0).unwrap(), Some(genesis.0.hash())); // common ancestor
        assert_eq!(store.canonical_hash(1).unwrap(), Some(b1.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(b2.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));

        // Old fork A headers should still be retrievable by hash
        assert!(store.header(chain_a[1].0.hash()).unwrap().is_some());
        assert!(store.header(chain_a[2].0.hash()).unwrap().is_some());
    }

    #[test]
    fn test_delete_canonical_hash() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let h = B256::repeat_byte(0x7);
        store.put_canonical_hash(42, h).unwrap();
        assert_eq!(store.canonical_hash(42).unwrap(), Some(h));
        store.delete_canonical_hash(42).unwrap();
        assert_eq!(store.canonical_hash(42).unwrap(), None);
        // Deleting an absent mapping is a no-op.
        store.delete_canonical_hash(42).unwrap();
    }

    #[test]
    fn test_canonical_walk_repairs_truncated_reorg_hole() {
        // Reproduces a real wedge: skeleton sync delivers a fork's child header
        // before the fork block itself, so an earlier canonical walk truncates
        // at the missing parent and leaves a hole (canonical #2 still names the
        // orphan while #3 builds on the fork). A later head update must repair
        // the hole, not stop at the first already-canonical block.
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Canonical chain A: genesis(#0) <- a1(#1) <- a2(#2).
        let chain_a = build_and_store_chain(&store, 3, 10, 0xAA);
        let a1_hash = chain_a[1].0.hash();
        let a2_hash = chain_a[2].0.hash();

        // Fork B at #2: b2 <- b3 <- b4, all built on a1.
        let b2 = make_chain_header(2, a1_hash, 20, 0xBB);
        let b3 = make_chain_header(3, b2.hash(), 20, 0xBB);
        let b4 = make_chain_header(4, b3.hash(), 20, 0xBB);
        for h in [&b2, &b3, &b4] {
            store.put_header(h).unwrap();
            store.put_total_difficulty(h.hash(), U256::from(100)).unwrap();
        }

        // Simulate the truncated walk: #3 was made canonical (and head), but
        // #2 was never repaired — it still names the orphan a2.
        store.put_canonical_hash(3, b3.hash()).unwrap();
        store.set_head(b3.hash()).unwrap();
        assert_eq!(store.canonical_hash(2).unwrap(), Some(a2_hash), "hole precondition");
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));

        // A new head (b4) triggers a canonical update. The walk must continue
        // past the already-canonical #3 to repair stale #2.
        store.update_canonical_chain(b4.hash()).unwrap();

        assert_eq!(store.canonical_hash(4).unwrap(), Some(b4.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(b2.hash()),
            "hole at #2 must be repaired to the fork block");
        assert_eq!(store.canonical_hash(1).unwrap(), Some(a1_hash), "common ancestor intact");
        // Chain is now internally consistent: each canonical child's parent is
        // the canonical block below it.
        let c3 = store.header(store.canonical_hash(3).unwrap().unwrap()).unwrap().unwrap();
        assert_eq!(c3.parent_hash, store.canonical_hash(2).unwrap().unwrap());
    }

    #[test]
    fn test_lower_td_fork_does_not_corrupt_canonical() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Main chain: genesis -> 1A -> 2A -> 3A (difficulty 20 each)
        let chain_a = build_and_store_chain(&store, 4, 20, 0xAA);
        let head_a = chain_a.last().unwrap().0.hash();

        // Fork chain with lower TD (difficulty 5 each)
        let genesis = &chain_a[0];
        let b1 = make_chain_header(1, genesis.0.hash(), 5, 0xBB);
        let b2 = make_chain_header(2, b1.hash(), 5, 0xBB);
        let b3 = make_chain_header(3, b2.hash(), 5, 0xBB);

        let td_b1 = genesis.1 + b1.difficulty;
        let td_b2 = td_b1 + b2.difficulty;
        let td_b3 = td_b2 + b3.difficulty;

        let entries = vec![(&b1, td_b1), (&b2, td_b2), (&b3, td_b3)];

        let result = store
            .store_headers_batch(&entries, Some(head_a), chain_a.last().unwrap().1)
            .unwrap();

        // Head should NOT change (fork B has lower TD)
        assert_eq!(result, Some(head_a));
        assert_eq!(store.head().unwrap(), Some(head_a));

        // Canonical chain must still point to fork A
        assert_eq!(store.canonical_hash(1).unwrap(), Some(chain_a[1].0.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(chain_a[2].0.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(chain_a[3].0.hash()));

        // Fork B headers should still be stored (keyed by hash)
        assert!(store.header(b1.hash()).unwrap().is_some());
        assert!(store.header(b2.hash()).unwrap().is_some());
        assert!(store.header(b3.hash()).unwrap().is_some());
    }

    #[test]
    fn test_direct_extension_updates_canonical() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Build a chain of 3 blocks
        let chain = build_and_store_chain(&store, 3, 10, 0xAA);
        let head = chain.last().unwrap();
        let head_hash = head.0.hash();
        let head_td = head.1;

        // Extend with block 3 (direct child of block 2)
        let b3 = make_chain_header(3, head_hash, 10, 0xAA);
        let td_b3 = head_td + b3.difficulty;
        let entries = vec![(&b3, td_b3)];

        let result = store
            .store_headers_batch(&entries, Some(head_hash), head_td)
            .unwrap();

        // Head should advance
        assert_eq!(result, Some(b3.hash()));
        assert_eq!(store.head().unwrap(), Some(b3.hash()));

        // All canonical pointers should be correct
        assert_eq!(store.canonical_hash(0).unwrap(), Some(chain[0].0.hash()));
        assert_eq!(store.canonical_hash(1).unwrap(), Some(chain[1].0.hash()));
        assert_eq!(store.canonical_hash(2).unwrap(), Some(chain[2].0.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));
    }

    #[test]
    fn test_update_canonical_chain_direct() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let chain = build_and_store_chain(&store, 3, 10, 0xAA);
        let head = chain.last().unwrap();

        // Add block 3 manually (simulating a new block)
        let b3 = make_chain_header(3, head.0.hash(), 10, 0xAA);
        store.put_header(&b3).unwrap();

        // update_canonical_chain should write canonical for block 3 and stop
        store.update_canonical_chain(b3.hash()).unwrap();

        assert_eq!(store.head().unwrap(), Some(b3.hash()));
        assert_eq!(store.canonical_hash(3).unwrap(), Some(b3.hash()));
        // Previous canonical entries untouched
        assert_eq!(store.canonical_hash(2).unwrap(), Some(head.0.hash()));
    }

    #[test]
    fn test_reorg_longer_fork() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        // Main chain: 5 blocks, difficulty 10
        let chain_a = build_and_store_chain(&store, 5, 10, 0xAA);
        let head_a = chain_a.last().unwrap();

        // Fork from block 2, with 5 more blocks (longer chain, higher TD)
        let fork_base = &chain_a[2]; // block #2
        let mut parent = fork_base.0.hash();
        let mut fork_entries = Vec::new();
        let mut td = fork_base.1;

        for i in 3..8u64 {
            let h = make_chain_header(i, parent, 15, 0xBB);
            td += h.difficulty;
            fork_entries.push((h.clone(), td));
            parent = h.hash();
        }

        let refs: Vec<(&Header, U256)> = fork_entries.iter().map(|(h, td)| (h, *td)).collect();
        let result = store
            .store_headers_batch(&refs, Some(head_a.0.hash()), head_a.1)
            .unwrap();

        let fork_head = fork_entries.last().unwrap();
        assert_eq!(result, Some(fork_head.0.hash()));
        assert_eq!(store.head().unwrap(), Some(fork_head.0.hash()));

        // Canonical should follow fork B from block 3 onward
        assert_eq!(store.canonical_hash(2).unwrap(), Some(chain_a[2].0.hash())); // common ancestor
        assert_eq!(store.canonical_hash(3).unwrap(), Some(fork_entries[0].0.hash()));
        assert_eq!(store.canonical_hash(7).unwrap(), Some(fork_entries[4].0.hash()));
    }

    // --- Body storage tests ---

    #[test]
    fn test_put_and_get_body() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xAA);

        let txs = vec![dummy_tx(0), dummy_tx(1), dummy_tx(2)];
        let ommers = vec![dummy_header(99)];

        store.put_body(hash, &txs, &ommers).unwrap();

        let (retrieved_txs, retrieved_ommers) = store.body(hash).unwrap().unwrap();
        assert_eq!(retrieved_txs.len(), 3);
        assert_eq!(retrieved_ommers.len(), 1);
        assert_eq!(retrieved_txs[0].nonce, 0);
        assert_eq!(retrieved_txs[2].nonce, 2);
        assert_eq!(retrieved_ommers[0].number, 99);
    }

    #[test]
    fn test_body_not_found() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        assert!(store.body(B256::repeat_byte(0xFF)).unwrap().is_none());
    }

    #[test]
    fn test_put_and_get_body_empty() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xBB);

        store.put_body(hash, &[], &[]).unwrap();

        let (txs, ommers) = store.body(hash).unwrap().unwrap();
        assert!(txs.is_empty());
        assert!(ommers.is_empty());
    }

    #[test]
    fn test_put_block_stores_header_and_body() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let header = dummy_header(5);
        let txs = vec![dummy_tx(0), dummy_tx(1)];
        let block = Block {
            header: header.clone(),
            transactions: txs.clone(),
            ommers: vec![],
        };
        let hash = block.hash();

        store.put_block(&block).unwrap();

        // Header should be stored
        let h = store.header(hash).unwrap().unwrap();
        assert_eq!(h.number, 5);

        // Body should be stored
        let (retrieved_txs, retrieved_ommers) = store.body(hash).unwrap().unwrap();
        assert_eq!(retrieved_txs.len(), 2);
        assert!(retrieved_ommers.is_empty());

        // Full block retrieval
        let full_block = store.block(hash).unwrap().unwrap();
        assert_eq!(full_block.header.number, 5);
        assert_eq!(full_block.transactions.len(), 2);
        assert_eq!(full_block.transactions[0].nonce, 0);
    }

    #[test]
    fn test_block_returns_header_only_when_no_body() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let header = dummy_header(10);
        let hash = header.hash();

        store.put_header(&header).unwrap();

        let block = store.block(hash).unwrap().unwrap();
        assert_eq!(block.header.number, 10);
        assert!(block.transactions.is_empty());
        assert!(block.ommers.is_empty());
    }

    #[test]
    fn test_put_body_with_many_txs_and_ommers() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xCC);

        let txs: Vec<Transaction> = (0..10).map(dummy_tx).collect();
        let ommers: Vec<Header> = (100..109).map(dummy_header).collect();

        store.put_body(hash, &txs, &ommers).unwrap();

        let (ret_txs, ret_ommers) = store.body(hash).unwrap().unwrap();
        assert_eq!(ret_txs.len(), 10);
        assert_eq!(ret_ommers.len(), 9);

        for (i, tx) in ret_txs.iter().enumerate() {
            assert_eq!(tx.nonce, i as u64, "tx {i} nonce mismatch");
        }
        for (i, uncle) in ret_ommers.iter().enumerate() {
            assert_eq!(uncle.number, (100 + i) as u64, "uncle {i} number mismatch");
        }
    }

    #[test]
    fn test_put_body_overwrite() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xDD);

        store.put_body(hash, &[dummy_tx(0)], &[]).unwrap();
        let (txs, _) = store.body(hash).unwrap().unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].nonce, 0);

        store.put_body(hash, &[dummy_tx(5), dummy_tx(6)], &[]).unwrap();
        let (txs, _) = store.body(hash).unwrap().unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].nonce, 5);
        assert_eq!(txs[1].nonce, 6);
    }

    #[test]
    fn test_put_block_full_roundtrip() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let header = dummy_header(42);
        let txs = vec![dummy_tx(0), dummy_tx(1), dummy_tx(2)];
        let ommers = vec![dummy_header(40), dummy_header(41)];
        let block = Block {
            header: header.clone(),
            transactions: txs.clone(),
            ommers: ommers.clone(),
        };
        let hash = block.hash();

        store.put_block(&block).unwrap();

        let full = store.block(hash).unwrap().unwrap();
        assert_eq!(full.header.number, 42);
        assert_eq!(full.transactions.len(), 3);
        assert_eq!(full.ommers.len(), 2);
        assert_eq!(full.ommers[0].number, 40);
        assert_eq!(full.ommers[1].number, 41);

        for (i, tx) in full.transactions.iter().enumerate() {
            assert_eq!(tx.nonce, i as u64);
        }
    }

    #[test]
    fn test_body_storage_rlp_stability() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let hash = B256::repeat_byte(0xEE);

        let txs = vec![dummy_tx(7)];
        let ommers = vec![dummy_header(99)];

        store.put_body(hash, &txs, &ommers).unwrap();

        // Read raw bytes and re-decode to verify RLP stability
        let raw = store.db.get_cf(store.cf(CF_BODIES).unwrap(), hash.as_slice())
            .unwrap().unwrap();

        // Decode the raw bytes manually
        let mut cursor = raw.as_slice();
        let outer = alloy_rlp::Header::decode(&mut cursor).unwrap();
        assert!(outer.list);

        let txs_header = alloy_rlp::Header::decode(&mut cursor).unwrap();
        assert!(txs_header.list);

        let tx = Transaction::decode(&mut cursor).unwrap();
        assert_eq!(tx.nonce, 7);

        let ommers_header = alloy_rlp::Header::decode(&mut cursor).unwrap();
        assert!(ommers_header.list);

        let uncle = Header::decode(&mut cursor).unwrap();
        assert_eq!(uncle.number, 99);
    }

    // --- Transaction Index tests ---

    #[test]
    fn test_tx_index_put_and_get() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let tx_hash = B256::repeat_byte(0x11);
        let block_hash = B256::repeat_byte(0x22);
        let tx_index = 5u32;

        store.put_tx_index(tx_hash, block_hash, tx_index).unwrap();

        let (found_block, found_idx) = store.tx_location(tx_hash).unwrap().unwrap();
        assert_eq!(found_block, block_hash);
        assert_eq!(found_idx, tx_index);
    }

    #[test]
    fn test_tx_index_not_found() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        assert!(store.tx_location(B256::repeat_byte(0xFF)).unwrap().is_none());
    }

    #[test]
    fn test_index_block_transactions() {
        use sha3::{Digest, Keccak256};

        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let block_hash = B256::repeat_byte(0x33);
        let txs = vec![dummy_tx(0), dummy_tx(1), dummy_tx(2)];

        store.index_block_transactions(block_hash, &txs).unwrap();

        for (i, tx) in txs.iter().enumerate() {
            let mut buf = Vec::new();
            tx.encode(&mut buf);
            let tx_hash = B256::from_slice(&Keccak256::digest(&buf));

            let (found_block, found_idx) = store.tx_location(tx_hash).unwrap().unwrap();
            assert_eq!(found_block, block_hash);
            assert_eq!(found_idx, i as u32);
        }
    }

    #[test]
    fn test_tx_index_overwrite() {
        let dir = tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();

        let tx_hash = B256::repeat_byte(0x44);
        let block_a = B256::repeat_byte(0xAA);
        let block_b = B256::repeat_byte(0xBB);

        store.put_tx_index(tx_hash, block_a, 0).unwrap();
        store.put_tx_index(tx_hash, block_b, 3).unwrap();

        let (found_block, found_idx) = store.tx_location(tx_hash).unwrap().unwrap();
        assert_eq!(found_block, block_b);
        assert_eq!(found_idx, 3);
    }
}
