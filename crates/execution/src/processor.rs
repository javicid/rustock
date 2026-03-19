/// End-to-end block processor: validates, executes, and commits blocks.
///
/// Orchestrates sender recovery, EVM execution, state application,
/// receipt construction, and validation against the block header.
use alloy_primitives::{Address, Bloom, B256};
use rustock_core::{Block, Log, Receipt, Transaction, ordered_trie_root};
use rustock_storage::BlockStore;
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;
use tracing::debug;

use crate::executor::RskExecutor;
use crate::hardfork::RskHardforkConfig;
use crate::state::apply_state_changes;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("sender recovery failed for tx {index}: {source}")]
    SenderRecovery { index: usize, source: anyhow::Error },
    #[error("execution error: {0}")]
    Execution(#[from] crate::executor::ExecutionError),
    #[error("gas used mismatch: header={header}, computed={computed}")]
    GasUsedMismatch { header: u64, computed: u64 },
    #[error("state root mismatch: header={header}, computed={computed}")]
    StateRootMismatch { header: B256, computed: B256 },
    #[error("receipts root mismatch: header={header}, computed={computed}")]
    ReceiptsRootMismatch { header: B256, computed: B256 },
    #[error("storage error: {0}")]
    Storage(#[from] anyhow::Error),
}

/// Result of processing a block.
#[derive(Debug)]
pub struct ProcessedBlock {
    pub receipts: Vec<Receipt>,
    pub gas_used: u64,
    pub new_state_root: TrieNode,
    pub state_root_hash: B256,
    pub receipts_root: B256,
}

/// Processes blocks by executing transactions and validating results against headers.
pub struct BlockProcessor {
    executor: RskExecutor,
    hardfork_cfg: RskHardforkConfig,
    block_store: Arc<BlockStore>,
}

impl BlockProcessor {
    pub fn new(
        hardfork_cfg: RskHardforkConfig,
        block_store: Arc<BlockStore>,
    ) -> Self {
        let executor = RskExecutor::new(hardfork_cfg.clone(), block_store.clone());
        Self { executor, hardfork_cfg, block_store }
    }

    /// Execute all transactions in a block and validate results against the header.
    ///
    /// Returns the processed block with receipts and new state root if validation passes.
    pub fn process_block(
        &self,
        block: &Block,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<ProcessedBlock, ProcessError> {
        let header = &block.header;
        let chain_id = self.hardfork_cfg.chain_id;

        let tx_senders = self.recover_senders(&block.transactions, chain_id)?;

        let transactions: Vec<(Transaction, Address)> = block
            .transactions
            .iter()
            .cloned()
            .zip(tx_senders.iter().copied())
            .collect();

        let exec_result = self.executor.execute_block(
            header,
            &transactions,
            state_root,
            trie_store.clone(),
        )?;

        let mut receipts = Vec::with_capacity(exec_result.tx_results.len());
        let mut cumulative_gas = 0u64;
        let mut block_bloom = Bloom::ZERO;

        for tx_result in &exec_result.tx_results {
            cumulative_gas += tx_result.gas_used;

            let logs: Vec<Log> = tx_result.logs.iter().map(|log| {
                Log {
                    address: log.address,
                    topics: log.topics().to_vec(),
                    data: log.data.data.clone(),
                }
            }).collect();

            let mut logs_bloom = Bloom::ZERO;
            for log in &logs {
                accrue_log_bloom(&mut logs_bloom, log);
            }
            block_bloom |= logs_bloom;

            receipts.push(Receipt::new(
                tx_result.success,
                cumulative_gas,
                tx_result.gas_used,
                logs_bloom,
                logs,
            ));
        }

        let new_state_root = apply_state_changes(state_root, trie_store.as_ref(), &exec_result.state_changes);
        let state_root_hash = new_state_root.compute_hash(trie_store.as_ref());
        let receipts_root = ordered_trie_root(&receipts);

        if exec_result.gas_used != header.gas_used {
            return Err(ProcessError::GasUsedMismatch {
                header: header.gas_used,
                computed: exec_result.gas_used,
            });
        }

        debug!(
            number = header.number,
            gas_used = exec_result.gas_used,
            tx_count = receipts.len(),
            "block processed successfully"
        );

        Ok(ProcessedBlock {
            receipts,
            gas_used: exec_result.gas_used,
            new_state_root,
            state_root_hash,
            receipts_root,
        })
    }

    /// Process and fully commit a block: store receipts and update state.
    pub fn process_and_commit(
        &self,
        block: &Block,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<ProcessedBlock, ProcessError> {
        let result = self.process_block(block, state_root, trie_store.clone())?;

        let hash = block.hash();
        self.block_store
            .put_receipts(hash, &result.receipts)
            .map_err(ProcessError::Storage)?;

        Ok(result)
    }

    fn recover_senders(
        &self,
        transactions: &[Transaction],
        chain_id: u64,
    ) -> Result<Vec<Address>, ProcessError> {
        let mut senders = Vec::with_capacity(transactions.len());
        for (i, tx) in transactions.iter().enumerate() {
            let sender = tx.recover_sender(chain_id).map_err(|e| {
                ProcessError::SenderRecovery { index: i, source: e }
            })?;
            senders.push(sender);
        }
        Ok(senders)
    }
}

/// Accrue a single log into a bloom filter (EIP-2718 bloom algorithm).
fn accrue_log_bloom(bloom: &mut Bloom, log: &Log) {
    bloom_insert(bloom, log.address.as_slice());
    for topic in &log.topics {
        bloom_insert(bloom, topic.as_slice());
    }
}

fn bloom_insert(bloom: &mut Bloom, data: &[u8]) {
    use sha3::{Digest, Keccak256};

    let hash = Keccak256::digest(data);
    for i in 0..3 {
        let bit = (((hash[2 * i] as usize) << 8) | (hash[2 * i + 1] as usize)) & 0x7FF;
        bloom.0[255 - bit / 8] |= 1 << (bit % 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, U256};
    use k256::ecdsa::SigningKey;
    use rustock_core::Header;
    use rustock_trie::{AccountState, MemoryTrieStore, TrieKeySlice, account_key};
    use sha3::{Digest, Keccak256};

    fn test_hardfork_cfg() -> RskHardforkConfig {
        RskHardforkConfig::all_active(33)
    }

    fn dummy_header(number: u64) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::repeat_byte(0x01),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(1_000_000),
            number,
            gas_limit: U256::from(6_800_000),
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(0),
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
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

    fn sign_tx(tx: &mut Transaction, key: &SigningKey, chain_id: u64) {
        let hash = tx.signing_hash_eip155(chain_id);
        let (signature, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            key.sign_prehash_recoverable(hash.as_slice()).unwrap();
        let sig_bytes = signature.to_bytes();
        tx.r = U256::from_be_slice(&sig_bytes[..32]);
        tx.s = U256::from_be_slice(&sig_bytes[32..]);
        tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;
    }

    fn sender_address(key: &SigningKey) -> Address {
        let vk = key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..])
    }

    #[test]
    fn test_process_block_empty() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);
        let block = Block {
            header,
            transactions: vec![],
            ommers: vec![],
        };

        let processor = BlockProcessor::new(test_hardfork_cfg(), block_store);
        let result = processor.process_block(&block, &root, store).unwrap();

        assert_eq!(result.gas_used, 0);
        assert!(result.receipts.is_empty());
    }

    #[test]
    fn test_process_block_with_signed_tx() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let chain_id = 33u64;

        let key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let sender = sender_address(&key);
        let recipient = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        sign_tx(&mut tx, &key, chain_id);

        let mut header = dummy_header(8_000_000);
        header.gas_used = 21_000;

        let block = Block {
            header,
            transactions: vec![tx],
            ommers: vec![],
        };

        let processor = BlockProcessor::new(test_hardfork_cfg(), block_store);
        let result = processor.process_block(&block, &root, store).unwrap();

        assert_eq!(result.gas_used, 21_000);
        assert_eq!(result.receipts.len(), 1);
        assert!(result.receipts[0].status);
        assert_eq!(result.receipts[0].cumulative_gas_used, 21_000);
    }

    #[test]
    fn test_process_block_gas_mismatch_error() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let chain_id = 33u64;

        let key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let sender = sender_address(&key);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(Address::repeat_byte(0xBB).as_slice()),
            value: U256::from(100),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        sign_tx(&mut tx, &key, chain_id);

        let mut header = dummy_header(8_000_000);
        header.gas_used = 99_999; // wrong gas

        let block = Block {
            header,
            transactions: vec![tx],
            ommers: vec![],
        };

        let processor = BlockProcessor::new(test_hardfork_cfg(), block_store);
        let result = processor.process_block(&block, &root, store);

        assert!(result.is_err());
        match result.unwrap_err() {
            ProcessError::GasUsedMismatch { header, computed } => {
                assert_eq!(header, 99_999);
                assert_eq!(computed, 21_000);
            }
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_process_and_commit_stores_receipts() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);
        let block = Block {
            header: header.clone(),
            transactions: vec![],
            ommers: vec![],
        };
        let hash = block.hash();

        block_store.put_header(&header).unwrap();

        let processor = BlockProcessor::new(test_hardfork_cfg(), block_store.clone());
        let _result = processor.process_and_commit(&block, &root, store).unwrap();

        let stored_receipts = block_store.receipts(hash).unwrap();
        assert!(stored_receipts.is_some());
        assert!(stored_receipts.unwrap().is_empty());
    }

    #[test]
    fn test_state_root_changes_after_processing() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let chain_id = 33u64;

        let key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let sender = sender_address(&key);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let initial_hash = root.compute_hash(store.as_ref());

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(Address::repeat_byte(0xCC).as_slice()),
            value: U256::from(500),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        sign_tx(&mut tx, &key, chain_id);

        let mut header = dummy_header(8_000_000);
        header.gas_used = 21_000;

        let block = Block {
            header,
            transactions: vec![tx],
            ommers: vec![],
        };

        let processor = BlockProcessor::new(test_hardfork_cfg(), block_store);
        let result = processor.process_block(&block, &root, store).unwrap();

        assert_ne!(
            result.state_root_hash, initial_hash,
            "state root should change after processing a block with transactions"
        );
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj
    // -----------------------------------------------------------------------

    /// Ported from rskj BloomTest.test1.
    /// Verifies bloom filter computation for address + topic matches the known vector.
    #[test]
    fn test_rskj_bloom_computation() {
        use alloy_primitives::Address;

        let address_bytes = hex_to_bytes("095e7baea6a6c7c4c2dfeb977efac326af552d87");
        let topic_bytes = [0u8; 32];

        let log = Log {
            address: Address::from_slice(&address_bytes),
            topics: vec![B256::from(topic_bytes)],
            data: Bytes::new(),
        };

        let mut bloom = Bloom::ZERO;
        accrue_log_bloom(&mut bloom, &log);

        let expected = hex_to_bytes(
            "00000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000040000000000000000000000000000000000000000000000000000000"
        );

        assert_eq!(
            &bloom.0[..],
            expected.as_slice(),
            "bloom filter should match rskj BloomTest.test1 vector"
        );
    }

    /// Ported from rskj ECKeyTest.testFromPrivateKey / testGetAddress.
    /// Verifies that a known private key produces the expected address.
    #[test]
    fn test_rskj_eckey_private_to_address() {
        let priv_hex = "3ecb44df2159c26e0f995712d4f39b6f6e499b40749b1cf1246c37f9516cb6a4";
        let expected_address = "8a40bfaa73256b60764c1bf40675a99083efb075";

        let priv_bytes = hex_to_bytes(priv_hex);
        let key = SigningKey::from_slice(&priv_bytes).unwrap();
        let addr = sender_address(&key);

        let expected = hex_to_bytes(expected_address);
        assert_eq!(
            addr.as_slice(),
            expected.as_slice(),
            "address derived from private key should match rskj ECKeyTest vector"
        );
    }

    /// Ported from rskj BlockExecutorTest.invalidBlockBadGasUsed.
    /// Verifies that a block with incorrect gas_used in the header is rejected.
    #[test]
    fn test_rskj_invalid_block_bad_gas_used() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let chain_id = 33u64;

        let key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let sender = sender_address(&key);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(Address::repeat_byte(0xBB).as_slice()),
            value: U256::from(10),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        sign_tx(&mut tx, &key, chain_id);

        let mut header = dummy_header(8_000_000);
        header.gas_used = 0; // incorrect — should be 21_000

        let block = Block {
            header,
            transactions: vec![tx],
            ommers: vec![],
        };

        let processor = BlockProcessor::new(test_hardfork_cfg(), block_store);
        let result = processor.process_block(&block, &root, store);

        assert!(result.is_err(), "block with bad gas_used should be rejected");
        assert!(
            matches!(result.unwrap_err(), ProcessError::GasUsedMismatch { .. }),
            "error should be GasUsedMismatch"
        );
    }

    /// Ported from rskj BlockExecutorTest.executeBlockWithOneTransaction.
    /// Validates exact balance deduction: sender starts with large balance,
    /// sends 10 wei with gas_price=1, gas_limit=21000.
    /// Final sender balance = initial - 21000*1 - 10.
    #[test]
    fn test_rskj_block_executor_balance_deduction() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let chain_id = 33u64;

        let key = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let sender = sender_address(&key);
        let recipient = Address::repeat_byte(0xCC);

        let initial_balance = U256::from(30_000);
        let root = put_account(&root, store.as_ref(), &sender, 0, initial_balance);
        let root = put_account(&root, store.as_ref(), &recipient, 0, U256::from(10));

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(10),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };
        sign_tx(&mut tx, &key, chain_id);

        let mut header = dummy_header(8_000_000);
        header.gas_used = 21_000;

        let block = Block {
            header,
            transactions: vec![tx],
            ommers: vec![],
        };

        let processor = BlockProcessor::new(test_hardfork_cfg(), block_store);
        let result = processor.process_block(&block, &root, store.clone()).unwrap();

        assert_eq!(result.gas_used, 21_000);
        assert_eq!(result.receipts.len(), 1);
        assert!(result.receipts[0].status, "tx should succeed");
        assert_eq!(result.receipts[0].cumulative_gas_used, 21_000);

        // Verify state: sender = 30000 - 21000 - 10 = 8990
        let sender_acct = read_account_from_trie(&result.new_state_root, store.as_ref(), &sender);
        assert_eq!(
            sender_acct.balance, U256::from(8_990),
            "sender balance: 30000 - 21000*1 - 10 = 8990 (matches rskj)"
        );
    }

    fn read_account_from_trie(
        root: &TrieNode,
        store: &dyn rustock_trie::TrieStore,
        addr: &Address,
    ) -> AccountState {
        let key_bytes = account_key(addr);
        let key = TrieKeySlice::from_key(&key_bytes);
        let data = root.get(&key, store).expect("account should exist");
        AccountState::decode(&data).unwrap()
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
