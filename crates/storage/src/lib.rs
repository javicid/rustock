use rocksdb::{DB, Options, ColumnFamilyDescriptor};
use rustock_core::{Block, Header};
use alloy_primitives::{B256, U256};
use alloy_rlp::{Decodable, Encodable};
use anyhow::{Result, Context, anyhow};
use std::path::Path;
use std::sync::Arc;

const CF_HEADERS: &str = "headers";
const CF_NUMBERS: &str = "block_numbers";
const CF_TD: &str = "total_difficulty"; // Total Difficulty
const KEY_HEAD: &[u8] = b"head";

/// Manages storage of blockchain data using RocksDB.
/// 
/// Data is organized into Column Families:
/// - `headers`: Hash -> RLP(Header)
/// - `block_numbers`: BlockNumber (u64 BE) -> Hash
/// - `total_difficulty`: Hash -> RLP(TotalDifficulty)
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

    pub fn get_header(&self, hash: B256) -> Result<Option<Header>> {
        let bytes = self.db.get_cf(self.cf(CF_HEADERS)?, hash.as_slice())
            .context("Failed to read header")?;
            
        match bytes {
            Some(bytes) => Ok(Some(Header::decode(&mut bytes.as_slice())?)),
            None => Ok(None),
        }
    }

    // --- Canonical Chain Operations ---

    pub fn put_canonical_hash(&self, number: u64, hash: B256) -> Result<()> {
        self.db.put_cf(self.cf(CF_NUMBERS)?, number.to_be_bytes(), hash.as_slice())
            .context("Failed to map number to hash")
    }

    pub fn get_canonical_hash(&self, number: u64) -> Result<Option<B256>> {
        let bytes = self.db.get_cf(self.cf(CF_NUMBERS)?, number.to_be_bytes())
            .context("Failed to read canonical hash")?;
            
        Ok(bytes.map(|b| B256::from_slice(&b)))
    }

    // --- Total Difficulty Operations ---

    pub fn put_total_difficulty(&self, hash: B256, td: U256) -> Result<()> {
        let mut buf = Vec::new();
        td.encode(&mut buf);
        
        self.db.put_cf(self.cf(CF_TD)?, hash.as_slice(), &buf)
            .context("Failed to write total difficulty")
    }

    pub fn get_total_difficulty(&self, hash: B256) -> Result<Option<U256>> {
        let bytes = self.db.get_cf(self.cf(CF_TD)?, hash.as_slice())
            .context("Failed to read total difficulty")?;
            
        match bytes {
            Some(bytes) => Ok(Some(U256::decode(&mut bytes.as_slice())?)),
            None => Ok(None),
        }
    }

    // --- Head Operations ---

    pub fn set_head(&self, hash: B256) -> Result<()> {
        self.db.put(KEY_HEAD, hash.as_slice())
            .context("Failed to set head")
    }

    pub fn get_head(&self) -> Result<Option<B256>> {
        let bytes = self.db.get(KEY_HEAD)
            .context("Failed to read head")?;
            
        Ok(bytes.map(|b| B256::from_slice(&b)))
    }

    // --- Batch / High Level Operations ---

    /// Updates the chain head and canonical mapping for a new best block.
    pub fn update_head(&self, header: &Header, td: U256) -> Result<()> {
        let hash = header.hash();
        
        // 1. Store the header itself
        self.put_header(header)?;
        
        // 2. Update Total Difficulty
        self.put_total_difficulty(hash, td)?;

        // 3. Update Head
        self.set_head(hash)?;

        // 4. Update Canonical Chain
        // Note: In a full implementation with reorgs, this would be more complex.
        // For linear sync, we just set it.
        self.put_canonical_hash(header.number, hash)?;
        
        Ok(())
    }
}

// Keeping basic Block support for backward compatibility/future use
impl BlockStore {
    pub fn put_block(&self, block: &Block) -> Result<()> {
        // For now, we just store the header. 
        // In a real full node, we'd store the body (txs, ommers) in a separate CF.
        self.put_header(&block.header)?;
        self.put_canonical_hash(block.header.number, block.hash())
    }

    pub fn get_block(&self, hash: B256) -> Result<Option<Block>> {
        // Reconstruct basic block from header (body missing)
        // TODO: Implement body storage
        self.get_header(hash).map(|opt| opt.map(|header| Block {
            header,
            transactions: vec![],
            ommers: vec![],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustock_core::Header;
    use alloy_primitives::{Address, B256, U256, Bytes};
    use tempfile::tempdir;

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
        let retrieved = store.get_header(hash).unwrap().unwrap();
        assert_eq!(header, retrieved);

        // 3. Set Canonical
        store.put_canonical_hash(1, hash).unwrap();
        assert_eq!(store.get_canonical_hash(1).unwrap(), Some(hash));

        // 4. Set Head
        store.set_head(hash).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(hash));

        // 5. Total Difficulty
        store.put_total_difficulty(hash, U256::from(100)).unwrap();
        assert_eq!(store.get_total_difficulty(hash).unwrap(), Some(U256::from(100)));
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
        assert_eq!(store.get_header(hash).unwrap().unwrap(), header);
        assert_eq!(store.get_canonical_hash(100).unwrap(), Some(hash));
        assert_eq!(store.get_total_difficulty(hash).unwrap(), Some(td));
        assert_eq!(store.get_head().unwrap(), Some(hash));
    }
}
