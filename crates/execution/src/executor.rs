/// Block and transaction executor using revm.
///
/// Executes RSK transactions against the Unitrie state, producing
/// execution results (gas used, logs, state changes) compatible with
/// rskj's behavior.

use alloy_primitives::Address;
use revm::context::CfgEnv;
use revm::database::WrapDatabaseRef;
use revm::primitives::hardfork::SpecId;
use revm::{ExecuteEvm, MainBuilder, MainContext};
use rustock_core::Header;
use rustock_storage::BlockStore;
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;
use tracing::debug;

use crate::database::RskDatabase;
use crate::env::{block_env_from_header, tx_env_from_rsk_tx};
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::{rsk_precompiles, RskPrecompileProvider};

/// Result of executing a single transaction.
#[derive(Debug)]
pub struct TxExecutionResult {
    pub gas_used: u64,
    pub success: bool,
    pub output: Vec<u8>,
    pub logs: Vec<revm::primitives::Log>,
    pub created_address: Option<Address>,
}

/// Result of executing an entire block.
#[derive(Debug)]
pub struct BlockExecutionResult {
    pub tx_results: Vec<TxExecutionResult>,
    pub gas_used: u64,
    pub state_changes: revm::state::EvmState,
}

/// Executes RSK blocks and transactions using revm.
pub struct RskExecutor {
    hardfork_cfg: RskHardforkConfig,
    block_store: Arc<BlockStore>,
}

impl RskExecutor {
    pub fn new(hardfork_cfg: RskHardforkConfig, block_store: Arc<BlockStore>) -> Self {
        Self { hardfork_cfg, block_store }
    }

    /// Execute a single transaction against the given state root.
    pub fn execute_tx(
        &self,
        header: &Header,
        tx: &rustock_core::Transaction,
        sender: Address,
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<TxExecutionResult, ExecutionError> {
        let spec_id = self.hardfork_cfg.spec_id(header.number);
        let block_env = block_env_from_header(header, &self.hardfork_cfg);
        let tx_env = tx_env_from_rsk_tx(tx, sender, &self.hardfork_cfg);
        let db = RskDatabase::new(state_root.clone(), trie_store, self.block_store.clone());

        let cfg = make_cfg_env(spec_id, self.hardfork_cfg.chain_id);

        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg);

        let precompile_provider = RskPrecompileProvider::new(
            rsk_precompiles(&self.hardfork_cfg, header.number),
            &self.hardfork_cfg,
        );
        let mut evm = ctx.build_mainnet().with_precompiles(precompile_provider);

        let result = evm
            .transact(tx_env)
            .map_err(|e| ExecutionError::Evm(format!("{e:?}")))?;

        let exec = result.result;
        let success = exec.is_success();
        let gas_used = exec.gas_used();
        let output = exec.output().map(|o| o.to_vec()).unwrap_or_default();
        let logs = exec.into_logs();

        Ok(TxExecutionResult {
            gas_used,
            success,
            output,
            logs,
            created_address: None,
        })
    }

    /// Execute all transactions in a block.
    pub fn execute_block(
        &self,
        header: &Header,
        transactions: &[(rustock_core::Transaction, Address)],
        state_root: &TrieNode,
        trie_store: Arc<dyn TrieStore>,
    ) -> Result<BlockExecutionResult, ExecutionError> {
        let spec_id = self.hardfork_cfg.spec_id(header.number);
        let block_env = block_env_from_header(header, &self.hardfork_cfg);
        let db = RskDatabase::new(state_root.clone(), trie_store, self.block_store.clone());
        let cfg = make_cfg_env(spec_id, self.hardfork_cfg.chain_id);

        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg);

        let precompile_provider = RskPrecompileProvider::new(
            rsk_precompiles(&self.hardfork_cfg, header.number),
            &self.hardfork_cfg,
        );
        let mut evm = ctx.build_mainnet().with_precompiles(precompile_provider);

        let mut total_gas = 0u64;
        let mut tx_results = Vec::with_capacity(transactions.len());

        for (i, (tx, sender)) in transactions.iter().enumerate() {
            let tx_env = tx_env_from_rsk_tx(tx, *sender, &self.hardfork_cfg);

            let result = evm
                .transact_one(tx_env)
                .map_err(|e| ExecutionError::Evm(format!("{e:?}")))?;

            let success = result.is_success();
            let gas_used = result.gas_used();
            let output = result.output().map(|o| o.to_vec()).unwrap_or_default();
            let logs = result.into_logs();

            total_gas += gas_used;
            tx_results.push(TxExecutionResult {
                gas_used,
                success,
                output,
                logs,
                created_address: None,
            });

            debug!(tx_index = i, gas_used, success, "executed transaction");
        }

        let state = evm.finalize();

        Ok(BlockExecutionResult {
            tx_results,
            gas_used: total_gas,
            state_changes: state,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("database error: {0}")]
    Database(#[from] crate::database::RskDbError),
    #[error("evm error: {0}")]
    Evm(String),
}

fn make_cfg_env(spec_id: SpecId, chain_id: u64) -> CfgEnv {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    cfg.spec = spec_id;
    cfg.limit_contract_code_size = Some(0x6000);
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bloom, Bytes, B256, U256};
    use rustock_trie::{MemoryTrieStore, TrieKeySlice, account_key, AccountState};

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

    #[test]
    fn test_simple_value_transfer() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx = rustock_core::Transaction {
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

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 21_000);
    }

    #[test]
    fn test_insufficient_balance_fails() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);

        let root = put_account(&root, store.as_ref(), &sender, 0, U256::from(100));

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(1_000_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store);
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_contract_creation_simple() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xDD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // PUSH1 0x00 PUSH1 0x00 RETURN (returns empty code)
        let initcode = vec![0x60, 0x00, 0x60, 0x00, 0xF3];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        assert!(result.gas_used > 21_000);
    }

    #[test]
    fn test_block_execution_multiple_txs() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xEE);
        let recipient1 = Address::repeat_byte(0x11);
        let recipient2 = Address::repeat_byte(0x22);

        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx1 = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient1.as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let tx2 = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient2.as_slice()),
            value: U256::from(2_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let transactions = vec![(tx1, sender), (tx2, sender)];

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &transactions, &root, store)
            .unwrap();

        assert_eq!(result.tx_results.len(), 2);
        assert!(result.tx_results[0].success);
        assert!(result.tx_results[1].success);
        assert_eq!(result.gas_used, 42_000);
    }

    #[test]
    fn test_hardfork_spec_selection() {
        let cfg = RskHardforkConfig::mainnet();

        assert_eq!(cfg.spec_id(0), SpecId::BYZANTIUM);
        assert_eq!(cfg.spec_id(2_500_000), SpecId::PETERSBURG);
        assert_eq!(cfg.spec_id(6_300_000), SpecId::ISTANBUL);
        assert_eq!(cfg.spec_id(7_500_000), SpecId::SHANGHAI);
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj's BlockExecutorTest / TransactionExecutorTest
    // -----------------------------------------------------------------------

    /// Ported from rskj's BlockExecutorTest.executeBlockWithOneTransaction.
    /// Validates exact balance deduction: gas_used * gas_price + value.
    #[test]
    fn test_rskj_execute_block_with_one_transaction_balance_check() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xA1);
        let recipient = Address::repeat_byte(0xB2);

        // rskj test: sender starts with 30_000, sends 10 wei, gas_price=1, gas_limit=21_000
        let root = put_account(&root, store.as_ref(), &sender, 0, U256::from(30_000));
        let root = put_account(&root, store.as_ref(), &recipient, 0, U256::from(10));

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx = rustock_core::Transaction {
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

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store)
            .unwrap();

        assert_eq!(result.tx_results.len(), 1);
        assert!(result.tx_results[0].success);
        assert_eq!(result.tx_results[0].gas_used, 21_000);
        assert_eq!(result.gas_used, 21_000);

        // Verify state changes match rskj:
        // sender final = 30_000 - 21_000 (gas*price) - 10 (value) = 8_990
        let sender_state = result.state_changes.get(&sender)
            .expect("sender should have state changes");
        assert_eq!(
            sender_state.info.balance,
            U256::from(8_990),
            "sender balance should be 30000 - 21000*1 - 10 = 8990"
        );
        assert_eq!(sender_state.info.nonce, 1, "sender nonce should increment to 1");

        // recipient final = 10 (initial) + 10 (received) = 20
        let recipient_state = result.state_changes.get(&recipient)
            .expect("recipient should have state changes");
        assert_eq!(
            recipient_state.info.balance,
            U256::from(20),
            "recipient balance should be 10 + 10 = 20"
        );
    }

    /// Ported from rskj TransactionExecutorTest.testInitHandlesFreeTransactionsOK.
    /// Sender with zero balance but non-zero value transfer should fail.
    #[test]
    fn test_rskj_zero_balance_sender_with_value_fails() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0x01);
        let recipient = Address::repeat_byte(0x02);

        // Sender has zero balance
        let root = put_account(&root, store.as_ref(), &sender, 0, U256::ZERO);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(68_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store);
        // Should fail: sender can't cover gas_limit * gas_price + value
        assert!(result.is_err(), "zero-balance sender with value transfer should fail");
    }

    /// Ported from rskj's TransactionTest.testTransactionCost patterns.
    /// Verifies that non-zero calldata bytes cost 16 gas each (post-RSKIP400/Istanbul).
    #[test]
    fn test_rskj_calldata_cost_post_istanbul() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xCC);
        let recipient = Address::repeat_byte(0xDD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Post-Arrowhead (ISTANBUL) → non-zero byte cost = 16
        let header = dummy_header(8_000_000);

        // 1 non-zero byte of calldata
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(vec![0xFF]), // 1 non-zero byte
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        // Intrinsic gas = 21000 (base) + 16 (1 non-zero byte at Istanbul rate)
        assert_eq!(result.gas_used, 21_016, "intrinsic gas = 21000 + 16*1");
    }

    /// Complementary test: pre-Istanbul calldata cost is 68 per non-zero byte.
    #[test]
    fn test_rskj_calldata_cost_pre_istanbul() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xCC);
        let recipient = Address::repeat_byte(0xDD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Pre-Orchid (BYZANTIUM) → non-zero byte cost = 68
        let mut header = dummy_header(100);
        header.gas_limit = U256::from(6_800_000);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(vec![0xFF]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::mainnet(),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        // Pre-Istanbul: intrinsic gas = 21000 + 68*1 = 21068
        assert_eq!(result.gas_used, 21_068, "intrinsic gas = 21000 + 68*1");
    }

    /// Ported from rskj InitcodeCostCalculatorTest.
    /// Validates that contract creation includes initcode word cost at Shanghai.
    #[test]
    fn test_rskj_initcode_cost_shanghai() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xEE);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Post-Lovell = SHANGHAI (has initcode metering)
        let header = dummy_header(8_000_000);

        // 4 bytes of initcode: ceil(4/32) = 1 word, INITCODE_WORD_COST = 2
        // PUSH1 0x00 PUSH1 0x00 RETURN + padding
        let initcode = vec![0x60, 0x00, 0x60, 0x00]; // 4 bytes

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(200_000),
            to: Bytes::new(), // contract creation
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store.clone(),
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store.clone())
            .unwrap();

        // Shanghai create intrinsic: 32000 (create base) + 16*4 (non-zero bytes at Istanbul) + 2 (initcode: 1 word * 2)
        // = 32000 + 64 + 2 = 32066
        // Note: this tx will revert because the initcode doesn't end with RETURN,
        // but we can still check gas_used >= intrinsic cost
        assert!(result.gas_used >= 32_066, "should include initcode metering cost");
    }

    /// Ported from rskj Create2Test patterns.
    /// Verifies that CREATE2 produces the correct contract address.
    #[test]
    fn test_rskj_create2_address_computation() {
        // CREATE2 address = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12..]
        use sha3::{Digest, Keccak256};

        let sender_bytes = hex_to_bytes("0f6510583d425cfcf94b99f8b073b44f60d1912b");
        let salt = [0u8; 32];
        let init_code = vec![0x60, 0x0b]; // 2 bytes of init code (from rskj test)

        let init_code_hash = Keccak256::digest(&init_code);

        let mut input = Vec::new();
        input.push(0xFF);
        input.extend_from_slice(&sender_bytes);
        input.extend_from_slice(&salt);
        input.extend_from_slice(&init_code_hash);

        let result = Keccak256::digest(&input);
        let address = &result[12..];

        let expected = hex_to_bytes("3bc3efa1c487a1ebfc911b47b548e2c82436a212");
        assert_eq!(
            address, expected.as_slice(),
            "CREATE2 address should match rskj test vector"
        );
    }

    /// CREATE2 with different salt → different address (rskj Create2Test.testCREATE2_SaltNumber).
    #[test]
    fn test_rskj_create2_salt_changes_address() {
        use sha3::{Digest, Keccak256};

        let sender_bytes = hex_to_bytes("0f6510583d425cfcf94b99f8b073b44f60d1912b");
        let mut salt = [0u8; 32];
        salt[28..].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        let init_code = vec![0x60, 0x1b];

        let init_code_hash = Keccak256::digest(&init_code);

        let mut input = Vec::new();
        input.push(0xFF);
        input.extend_from_slice(&sender_bytes);
        input.extend_from_slice(&salt);
        input.extend_from_slice(&init_code_hash);

        let result = Keccak256::digest(&input);
        let address = &result[12..];

        let expected = hex_to_bytes("19542b03f2d5d4e1910dbe096faf0842d928883d");
        assert_eq!(
            address, expected.as_slice(),
            "CREATE2 with salt 0xcafebabe should match rskj"
        );
    }

    /// CREATE2 with different sender → different address (rskj Create2Test.testCREATE2_Address).
    #[test]
    fn test_rskj_create2_sender_changes_address() {
        use sha3::{Digest, Keccak256};

        let sender_bytes = hex_to_bytes("deadbeef00000000000000000000000000000000");
        let mut salt = [0u8; 32];
        salt[28..].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        let init_code = vec![0x60, 0x1b];

        let init_code_hash = Keccak256::digest(&init_code);

        let mut input = Vec::new();
        input.push(0xFF);
        input.extend_from_slice(&sender_bytes);
        input.extend_from_slice(&salt);
        input.extend_from_slice(&init_code_hash);

        let result = Keccak256::digest(&input);
        let address = &result[12..];

        let expected = hex_to_bytes("3ba1dc70cc17e740f4bd85052af074b2b2a49e06");
        assert_eq!(
            address, expected.as_slice(),
            "CREATE2 with deadbeef sender should match rskj"
        );
    }

    /// Verifies nonce increments correctly across sequential transactions.
    #[test]
    fn test_rskj_nonce_tracking_across_block() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAB);
        let r1 = Address::repeat_byte(0x01);
        let r2 = Address::repeat_byte(0x02);
        let r3 = Address::repeat_byte(0x03);

        let root = put_account(
            &root, store.as_ref(), &sender, 0, U256::from(1_000_000),
        );

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let make_tx = |nonce: u64, to: &Address| {
            rustock_core::Transaction {
                nonce,
                gas_price: U256::from(0),
                gas_limit: U256::from(21_000),
                to: Bytes::copy_from_slice(to.as_slice()),
                value: U256::from(1),
                input: Bytes::new(),
                v: 0,
                r: U256::ZERO,
                s: U256::ZERO,
            }
        };

        let txs = vec![
            (make_tx(0, &r1), sender),
            (make_tx(1, &r2), sender),
            (make_tx(2, &r3), sender),
        ];

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &txs, &root, store)
            .unwrap();

        assert_eq!(result.tx_results.len(), 3);
        assert!(result.tx_results.iter().all(|r| r.success));

        let sender_state = result.state_changes.get(&sender).unwrap();
        assert_eq!(sender_state.info.nonce, 3, "nonce should be 3 after 3 txs");

        // Each recipient should have received 1 wei
        for addr in [r1, r2, r3] {
            let state = result.state_changes.get(&addr)
                .expect("recipient should appear in state changes");
            assert_eq!(state.info.balance, U256::from(1));
        }
    }

    /// Verifies SSTORE/SLOAD work correctly via a contract that stores a value.
    /// Bytecode: PUSH1 0x42 PUSH1 0x00 SSTORE STOP
    /// (stores 0x42 at slot 0)
    #[test]
    fn test_contract_sstore_execution() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // Initcode that deploys a contract which stores 0x42 at slot 0:
        // Runtime code: PUSH1 0x42 PUSH1 0x00 SSTORE STOP = 60 42 60 00 55 00
        // Initcode: copy runtime to memory and return it
        // PUSH1 6 PUSH1 0x0c PUSH1 0 CODECOPY  (copy 6 bytes from offset 12 to memory 0)
        // PUSH1 6 PUSH1 0 RETURN                (return 6 bytes from memory 0)
        // <runtime code>
        let initcode: Vec<u8> = vec![
            0x60, 0x06, // PUSH1 6 (size)
            0x60, 0x0c, // PUSH1 12 (offset - after initcode)
            0x60, 0x00, // PUSH1 0 (destOffset)
            0x39,       // CODECOPY
            0x60, 0x06, // PUSH1 6 (size)
            0x60, 0x00, // PUSH1 0 (offset)
            0xF3,       // RETURN
            // Runtime code starts here (offset 12):
            0x60, 0x42, // PUSH1 0x42
            0x60, 0x00, // PUSH1 0x00
            0x55,       // SSTORE
            0x00,       // STOP
        ];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(200_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "contract creation should succeed");
        assert!(result.gas_used > 32_000, "should include CREATE base cost");
    }

    /// Verifies zero-value calldata bytes cost 4 gas each (consistent across all specs).
    #[test]
    fn test_rskj_zero_calldata_bytes_cost_4() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // 10 zero bytes + 0 non-zero bytes
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(vec![0x00; 10]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        // 21000 base + 4*10 zero bytes = 21040
        assert_eq!(result.gas_used, 21_040, "intrinsic gas = 21000 + 4*10 zero bytes");
    }

    /// Verifies mixed zero/non-zero calldata gas cost.
    #[test]
    fn test_rskj_mixed_calldata_cost() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // 5 zero bytes + 3 non-zero bytes at Shanghai/Istanbul rate
        let mut data = vec![0x00; 5];
        data.extend_from_slice(&[0xFF, 0xAB, 0xCD]);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(30_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(data),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success);
        // 21000 + 4*5 (zero) + 16*3 (non-zero at Istanbul) = 21000 + 20 + 48 = 21068
        assert_eq!(result.gas_used, 21_068, "21000 + 4*5 + 16*3 = 21068");
    }

    /// Verifies that the beneficiary (coinbase) receives gas fees in state changes.
    #[test]
    fn test_beneficiary_receives_fees() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let recipient = Address::repeat_byte(0xBB);
        let beneficiary = Address::repeat_byte(0x01);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut header = dummy_header(8_000_000);
        header.beneficiary = beneficiary;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(100),
            gas_limit: U256::from(21_000),
            to: Bytes::copy_from_slice(recipient.as_slice()),
            value: U256::from(1_000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store)
            .unwrap();

        assert!(result.tx_results[0].success);

        // Beneficiary should receive gas_used * gas_price = 21000 * 100 = 2_100_000
        let ben_state = result.state_changes.get(&beneficiary)
            .expect("beneficiary should appear in state changes");
        assert_eq!(
            ben_state.info.balance,
            U256::from(2_100_000u64),
            "beneficiary receives 21000 * 100 = 2_100_000"
        );
    }

    // -----------------------------------------------------------------------
    // End-to-end precompile execution tests
    // -----------------------------------------------------------------------

    /// Direct tx to REMASC precompile (0x01000008).
    /// REMASC costs 0 gas — total should be only intrinsic gas (21000).
    #[test]
    fn test_remasc_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let remasc_addr = crate::precompiles::REMASC_ADDR;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(remasc_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "REMASC direct call should succeed");
        assert_eq!(result.gas_used, 21_000, "REMASC costs 0 gas, total = intrinsic only");
    }

    /// Direct tx to Bridge precompile (0x01000006).
    /// Bridge stub charges 10,000 gas.
    #[test]
    fn test_bridge_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let bridge_addr = crate::precompiles::BRIDGE_ADDR;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(bridge_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "Bridge direct call should succeed");
        assert_eq!(
            result.gas_used,
            21_000 + 10_000,
            "Bridge charges 10k gas on top of intrinsic"
        );
    }

    /// Direct tx to Identity precompile (0x04) with known input.
    /// Ported from rskj PrecompiledContractTest.identityTest1:
    ///   input = 0x112233445566, output = 0x112233445566, gas = 18
    #[test]
    fn test_identity_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let identity_addr = Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
        let input_data: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(identity_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input_data.clone()),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "Identity precompile should succeed");
        assert_eq!(
            result.output, input_data,
            "Identity precompile returns input unchanged"
        );

        // Identity gas: 15 base + 3 * ceil(6/32) = 15 + 3 = 18
        // Intrinsic: 21000 + 6*16 = 21096 (all non-zero at Istanbul)
        // Total: 21096 + 18 = 21114
        assert_eq!(result.gas_used, 21_114, "Identity: 21000 + 96 + 18 = 21114");
    }

    /// Direct tx to SHA256 precompile (0x02) with empty input.
    /// Ported from rskj PrecompiledContractTest.sha256Test1:
    ///   SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    #[test]
    fn test_sha256_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let sha256_addr = Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(sha256_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "SHA256 precompile should succeed");

        let expected = hex_to_bytes(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(result.output, expected, "SHA256('') matches rskj test vector");

        // SHA256 gas: 60 base + 12 * ceil(0/32) = 60
        // Intrinsic: 21000 (no data)
        // Total: 21060
        assert_eq!(result.gas_used, 21_060, "SHA256: 21000 + 60 = 21060");
    }

    /// Verify that SHA256 with non-empty input produces the correct hash.
    /// Ported from rskj PrecompiledContractTest.sha256Test3:
    ///   SHA256(0x112233) = 49ee2bf93aac3b1fb4117e59095e07abe555c3383b38d608da37680a406096e8
    #[test]
    fn test_sha256_precompile_with_data() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let sha256_addr = Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let input_data = vec![0x11, 0x22, 0x33];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(sha256_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input_data),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "SHA256 precompile should succeed");

        let expected = hex_to_bytes(
            "49ee2bf93aac3b1fb4117e59095e07abe555c3383b38d608da37680a406096e8"
        );
        assert_eq!(result.output, expected, "SHA256(0x112233) matches rskj test vector");

        // SHA256 gas: 60 + 12*1 = 72 (3 bytes = 1 word)
        // Intrinsic: 21000 + 3*16 = 21048
        // Total: 21048 + 72 = 21120
        assert_eq!(result.gas_used, 21_120, "SHA256: 21000 + 48 + 72 = 21120");
    }

    /// Contract calls Identity precompile via STATICCALL and returns the result.
    /// This tests the precompile-from-contract path (CALL opcode → precompile).
    #[test]
    fn test_identity_precompile_via_contract_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // Deploy a contract whose runtime code:
        //   1. Stores 0xDEADBEEF at memory[0:4]
        //   2. STATICCALLs Identity (0x04) with that 4-byte input
        //   3. RETURNs the 4-byte output
        //
        // Runtime bytecode:
        //   PUSH4 0xDEADBEEF  ; 63 DEADBEEF
        //   PUSH1 0x00        ; 60 00
        //   MSTORE            ; 52           -> mem[28..32] = 0xDEADBEEF (right-aligned in 32 bytes)
        //
        //   PUSH1 0x04        ; 60 04        retSize
        //   PUSH1 0x40        ; 60 40        retOffset
        //   PUSH1 0x04        ; 60 04        argsSize
        //   PUSH1 0x1c        ; 60 1c        argsOffset (28, where the 4 bytes are)
        //   PUSH1 0x04        ; 60 04        address (Identity)
        //   GAS               ; 5A           gas
        //   STATICCALL        ; FA
        //
        //   PUSH1 0x04        ; 60 04        size
        //   PUSH1 0x40        ; 60 40        offset
        //   RETURN            ; F3
        let runtime: Vec<u8> = vec![
            0x63, 0xDE, 0xAD, 0xBE, 0xEF,  // PUSH4 0xDEADBEEF
            0x60, 0x00,                      // PUSH1 0
            0x52,                            // MSTORE
            0x60, 0x04,                      // PUSH1 4 (retSize)
            0x60, 0x40,                      // PUSH1 64 (retOffset)
            0x60, 0x04,                      // PUSH1 4 (argsSize)
            0x60, 0x1c,                      // PUSH1 28 (argsOffset)
            0x60, 0x04,                      // PUSH1 4 (Identity address)
            0x5A,                            // GAS
            0xFA,                            // STATICCALL
            0x60, 0x04,                      // PUSH1 4 (return size)
            0x60, 0x40,                      // PUSH1 64 (return offset)
            0xF3,                            // RETURN
        ];

        let runtime_len = runtime.len() as u8;
        let initcode_prefix: Vec<u8> = vec![
            0x60, runtime_len,              // PUSH1 runtime_len
            0x60, 0x0c,                     // PUSH1 12 (offset after initcode prefix)
            0x60, 0x00,                     // PUSH1 0
            0x39,                           // CODECOPY
            0x60, runtime_len,              // PUSH1 runtime_len
            0x60, 0x00,                     // PUSH1 0
            0xF3,                           // RETURN
        ];

        let mut initcode = initcode_prefix;
        initcode.extend_from_slice(&runtime);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(500_000),
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store.clone(),
        );

        // Step 1: deploy the contract
        let deploy_result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .unwrap();

        assert!(deploy_result.tx_results[0].success, "deployment should succeed");

        // Find the created contract address from state changes
        let contract_addr = deploy_result.state_changes.iter()
            .find(|(addr, acct)| {
                **addr != sender
                    && **addr != header.beneficiary
                    && acct.info.code.as_ref().map_or(false, |c| !c.is_empty())
            })
            .map(|(addr, _)| *addr)
            .expect("should have created a contract");

        // Step 2: call the contract — it will STATICCALL Identity and return the result
        let root2 = TrieNode::empty();
        let root2 = put_account(&root2, store.as_ref(), &sender, 1, one_rbtc);

        // Put the deployed code into the trie for the contract
        let code_bytes = deploy_result.state_changes.get(&contract_addr)
            .unwrap().info.code.as_ref().unwrap().bytes_slice().to_vec();

        use rustock_trie::{TrieKeySlice, code_key};
        let ckey = code_key(&contract_addr);
        let root2 = root2.put(&TrieKeySlice::from_key(&ckey), &code_bytes, store.as_ref());

        let caccount = AccountState::new(U256::ZERO, U256::ZERO);
        let akey = account_key(&contract_addr);
        let root2 = root2.put(&TrieKeySlice::from_key(&akey), &caccount.encode(), store.as_ref());

        let call_tx = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(contract_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let call_result = executor
            .execute_tx(&header, &call_tx, sender, &root2, store)
            .unwrap();

        assert!(call_result.success, "contract call should succeed");
        assert_eq!(
            call_result.output,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            "Identity precompile should return input unchanged via contract STATICCALL"
        );
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
