/// Block and transaction executor using revm.
///
/// Executes RSK transactions against the Unitrie state, producing
/// execution results (gas used, logs, state changes) compatible with
/// rskj's behavior.
use alloy_primitives::{Address, U256};
use revm::context::CfgEnv;
use revm::database::WrapDatabaseRef;
use revm::primitives::hardfork::SpecId;
use revm::{ExecuteEvm, MainBuilder, MainContext};
use sha3::Digest as _;
use rustock_core::Header;
use rustock_storage::BlockStore;
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;
use tracing::debug;

use crate::database::RskDatabase;
use crate::env::{block_env_from_header, tx_env_from_rsk_tx};
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::{rsk_precompiles, BridgeTxContext, RskPrecompileProvider, REMASC_ADDR};

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
    remasc_config: crate::remasc::RemascConfig,
    bridge_constants: crate::bridge::constants::BridgeConstants,
    /// RSK addresses allowed to send free bridge txs (genesis federation +
    /// authorizers), derived from the bridge constants' public keys.
    free_bridge_senders: Vec<Address>,
}

impl RskExecutor {
    pub fn new(hardfork_cfg: RskHardforkConfig, block_store: Arc<BlockStore>) -> Self {
        let remasc_config = crate::remasc::RemascConfig::mainnet();
        let bridge_constants = match hardfork_cfg.chain_id {
            crate::hardfork::RSK_TESTNET_CHAIN_ID => crate::bridge::constants::BridgeConstants::testnet(),
            crate::hardfork::RSK_MAINNET_CHAIN_ID => crate::bridge::constants::BridgeConstants::mainnet(),
            _ => crate::bridge::constants::BridgeConstants::regtest(),
        };
        let free_bridge_senders = bridge_constants
            .genesis_federation_public_keys
            .iter()
            .chain(bridge_constants.authorized_free_tx_keys.iter())
            .filter_map(|hex| rsk_address_from_pubkey_hex(hex))
            .collect();
        Self { hardfork_cfg, block_store, remasc_config, bridge_constants, free_bridge_senders }
    }

    pub fn with_remasc_config(mut self, config: crate::remasc::RemascConfig) -> Self {
        self.remasc_config = config;
        self
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

        let cfg = make_cfg_env(spec_id, self.hardfork_cfg.chain_id, self.hardfork_cfg.has_rskip544(header.number));

        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg);

        let precompile_provider = RskPrecompileProvider::new(
            rsk_precompiles(&self.hardfork_cfg, header.number),
            &self.hardfork_cfg,
            Some(self.block_store.clone()),
            self.remasc_config.clone(),
        );
        let mut evm = ctx.build_mainnet().with_precompiles(precompile_provider);
        crate::rsk_instructions::install(&mut evm.instruction);

        let exec_out = {
            use revm::context::ContextSetters;
            use revm::handler::Handler;
            evm.ctx.set_tx(tx_env);
            let mut handler = crate::rsk_handler::RskHandler::default();
            let out = handler
                .run(&mut evm)
                .map_err(|e: revm::context::result::EVMError<_>| {
                    ExecutionError::Evm(format!("{e:?}"))
                })?;
            out
        };
        let state = {
            use revm::context_interface::{ContextTr, JournalTr};
            evm.ctx.journal_mut().finalize()
        };
        let result = revm::context::result::ExecResultAndState::new(exec_out, state);

        let exec = result.result;
        let success = exec.is_success();
        let gas_used = exec.gas_used();
        let output = exec.output().map(|o| o.to_vec()).unwrap_or_default();
        let logs = exec.into_logs();

        let created_address = Self::extract_created_address(tx, &success);

        Ok(TxExecutionResult {
            gas_used,
            success,
            output,
            logs,
            created_address,
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
        let cfg = make_cfg_env(spec_id, self.hardfork_cfg.chain_id, self.hardfork_cfg.has_rskip544(header.number));

        let ctx = revm::Context::mainnet()
            .with_db(WrapDatabaseRef(db))
            .with_block(block_env)
            .with_cfg(cfg);

        let precompile_provider = RskPrecompileProvider::new(
            rsk_precompiles(&self.hardfork_cfg, header.number),
            &self.hardfork_cfg,
            Some(self.block_store.clone()),
            self.remasc_config.clone(),
        );
        // Shared slot for per-transaction Bridge context (tx hash + BTC destination).
        // We clone the Arc before moving the provider into the EVM so we can update
        // it between transactions.
        let bridge_ctx_slot = precompile_provider.bridge_tx_context_slot();
        let mut evm = ctx.build_mainnet().with_precompiles(precompile_provider);
        crate::rsk_instructions::install(&mut evm.instruction);

        let mut total_gas = 0u64;
        let mut tx_results = Vec::with_capacity(transactions.len());

        for (i, (tx, sender)) in transactions.iter().enumerate() {
            if Self::is_remasc_tx(tx) {
                debug!(tx_index = i, "executing REMASC system call");
                // Warm the REMASC account: outside revm's transact flow the
                // journal rejects storage ops on accounts it has not loaded.
                {
                    use revm::context_interface::{ContextTr, JournalTr};
                    let _ = evm.ctx.journal_mut().load_account(REMASC_ADDR);
                }
                crate::remasc::process_miners_fees(
                    &mut evm.ctx,
                    &self.remasc_config,
                    &self.bridge_constants,
                    &self.hardfork_cfg,
                    Some(&self.block_store),
                )
                .map_err(|e| ExecutionError::Evm(format!("REMASC: {e:?}")))?;

                // Drain the mining_fee_topic logs into the receipt.
                let logs = {
                    use revm::context_interface::{ContextTr, JournalTr};
                    evm.ctx.journal_mut().take_logs()
                };

                tx_results.push(TxExecutionResult {
                    gas_used: 0,
                    success: true,
                    output: Vec::new(),
                    logs,
                    created_address: None,
                });
                continue;
            }

            // Update per-transaction Bridge context before execution.
            // This provides the Bridge precompile with:
            //   - rsk_tx_hash: used for RSKIP146 release queue entries
            //   - btc_sender_hash160: used as BTC peg-out destination (matches rskj's
            //     BridgeUtils.recoverBtcAddressFromEthTransaction)
            {
                let rsk_tx_hash: [u8; 32] = {
                    let rlp = tx.rlp_for_trie();
                    sha3::Keccak256::digest(&rlp).into()
                };
                let btc_sender_hash160 = tx
                    .btc_sender_hash160(self.hardfork_cfg.chain_id)
                    .unwrap_or([0u8; 20]);
                if let Ok(mut guard) = bridge_ctx_slot.lock() {
                    *guard = BridgeTxContext { rsk_tx_hash, btc_sender_hash160, rsk_sender: *sender };
                }
            }

            // Direct Bridge calls that revm's gas validation cannot model:
            // - free bridge transactions (pre-areBridgeTxsPaid): gas_limit 0,
            //   nothing charged (Transaction.transactionCost == 0,
            //   Bridge.getGasForData == 0);
            // - paid calls before RSKIP136 (bahamas): rskj checked the limit
            //   against the precompile cost ALONE and recorded
            //   gasUsed = precompileCost + intrinsicCost, possibly above the
            //   tx gas limit (mainnet #3307: 31280 used with a 30000 limit).
            let is_free = self.is_free_bridge_tx(tx, *sender, header.number);
            let is_pre136_bridge = !self.hardfork_cfg.has_rskip136(header.number)
                && tx.to.len() == 20
                && tx.to.as_ref() == crate::precompiles::BRIDGE_ADDR.as_slice();
            if is_free || is_pre136_bridge {
                debug!(tx_index = i, is_free, "executing direct bridge call");
                use revm::context_interface::journaled_state::account::JournaledAccountTr;
                use revm::context_interface::{ContextTr, JournalTr};
                // rskj increments the sender nonce in init(), outside the
                // execution rollback scope.
                {
                    let mut acc = evm.ctx.journal_mut().load_account_mut(*sender)
                        .map_err(|e| ExecutionError::Evm(format!("{e:?}")))?;
                    acc.data.bump_nonce();
                }

                // Warm the Bridge account: outside revm's transact flow the
                // precompile warm-set is not populated and journal sloads on
                // a cold account fail.
                let _ = evm.ctx.journal_mut()
                    .load_account(crate::precompiles::BRIDGE_ADDR);

                // Pre-RSKIP136 gas accounting (rskj TransactionExecutor.call).
                let (gas_used, enough_gas) = if is_free {
                    (0u64, true)
                } else {
                    let required = crate::bridge::bridge_call_gas_cost(
                        &mut evm.ctx,
                        tx.input.as_ref(),
                        &self.bridge_constants,
                        &self.hardfork_cfg,
                    )
                    .unwrap_or(0);
                    let basic: u64 = 21_000
                        + tx.input.iter()
                            .map(|b| if *b == 0 { 4u64 } else { 68 })
                            .sum::<u64>();
                    let limit = tx.gas_limit.to::<u64>();
                    if limit >= required {
                        // gasUsed may exceed the limit; that is consensus here.
                        (required.saturating_add(basic), true)
                    } else {
                        // rskj execError: all gas consumed, nothing executed.
                        (limit, false)
                    }
                };

                let (success, output, logs) = if enough_gas {
                    let tx_ctx = bridge_ctx_slot.lock().map(|g| g.clone()).unwrap_or_default();
                    let use_v2 = self.hardfork_cfg.has_stored_block_v2(header.number);
                    let checkpoint = evm.ctx.journal_mut().checkpoint();
                    let outcome = crate::bridge::execute_bridge(
                        &mut evm.ctx,
                        tx.input.as_ref(),
                        u64::MAX, // cost already accounted above
                        &self.bridge_constants,
                        Some(&self.block_store),
                        use_v2,
                        &self.hardfork_cfg,
                        &tx_ctx,
                    );
                    match outcome {
                        Ok(out) => {
                            evm.ctx.journal_mut().checkpoint_commit();
                            // Drain bridge events into the receipt like revm
                            // does for normal transactions.
                            let logs = evm.ctx.journal_mut().take_logs();
                            (true, out.bytes.to_vec(), logs)
                        }
                        Err(e) => {
                            evm.ctx.journal_mut().checkpoint_revert(checkpoint);
                            debug!(tx_index = i, error = %e, "direct bridge call failed");
                            (false, Vec::new(), Vec::new())
                        }
                    }
                } else {
                    (false, Vec::new(), Vec::new())
                };

                // Fees go to REMASC like the revm path (block beneficiary).
                let fee = U256::from(gas_used) * tx.gas_price;
                if !fee.is_zero() {
                    let _ = evm.ctx.journal_mut().transfer(
                        *sender,
                        crate::precompiles::REMASC_ADDR,
                        fee,
                    );
                }

                total_gas += gas_used;
                tx_results.push(TxExecutionResult {
                    gas_used,
                    success,
                    output,
                    logs,
                    created_address: None,
                });
                continue;
            }

            let tx_env = tx_env_from_rsk_tx(tx, *sender, &self.hardfork_cfg);

            let result = {
                use revm::context::ContextSetters;
                use revm::handler::Handler;
                evm.ctx.set_tx(tx_env);
                let mut handler = crate::rsk_handler::RskHandler::default();
                handler
                    .run(&mut evm)
                    .map_err(|e: revm::context::result::EVMError<_>| {
                        ExecutionError::Evm(format!("{e:?}"))
                    })?
            };

            let success = result.is_success();
            let gas_used = result.gas_used();
            let output = result.output().map(|o| o.to_vec()).unwrap_or_default();
            let logs = result.into_logs();
            let created_address = Self::extract_created_address(tx, &success);

            total_gas += gas_used;
            tx_results.push(TxExecutionResult {
                gas_used,
                success,
                output,
                logs,
                created_address,
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

    /// rskj BridgeUtils.isFreeBridgeTx: before areBridgeTxsPaid activates,
    /// transactions to the Bridge from the genesis federation or an
    /// authorized sender execute for free (zero gas).
    fn is_free_bridge_tx(&self, tx: &rustock_core::Transaction, sender: Address, block_number: u64) -> bool {
        tx.to.len() == 20
            && tx.to.as_ref() == crate::precompiles::BRIDGE_ADDR.as_slice()
            && !self.hardfork_cfg.has_are_bridge_txs_paid(block_number)
            && self.free_bridge_senders.contains(&sender)
    }

    /// Detect the REMASC synthetic transaction: v=0, r=0, s=0, gas_limit=0,
    /// to=REMASC_ADDR. The gas_limit=0 check distinguishes real REMASC system
    /// calls from normal transactions that happen to call REMASC with valid gas.
    fn is_remasc_tx(tx: &rustock_core::Transaction) -> bool {
        if tx.v != 0 || !tx.r.is_zero() || !tx.s.is_zero() {
            return false;
        }
        if !tx.gas_limit.is_zero() {
            return false;
        }
        tx.to.len() == 20 && tx.to.as_ref() == REMASC_ADDR.as_slice()
    }

    /// For contract creation transactions, compute the created address from
    /// sender + nonce (matching CREATE opcode address derivation).
    fn extract_created_address(
        tx: &rustock_core::Transaction,
        success: &bool,
    ) -> Option<Address> {
        if !success || !tx.to.is_empty() {
            return None;
        }
        // Contract creation transactions don't report the address in
        // revm's transact_one result. In RSK the address follows the
        // standard CREATE scheme, but we'd need the sender here to
        // compute it. Return None for now — the receipt data is still
        // correct for consensus since RSK doesn't include
        // created_address in the receipt RLP.
        None
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("database error: {0}")]
    Database(#[from] crate::database::RskDbError),
    #[error("evm error: {0}")]
    Evm(String),
}

/// Derives an RSK address from a secp256k1 public key in SEC1 hex
/// (compressed or uncompressed): keccak256 of the uncompressed point's
/// 64 coordinate bytes, last 20 bytes (rskj ECKey.getAddress).
fn rsk_address_from_pubkey_hex(hex: &str) -> Option<Address> {
    let bytes = alloy_primitives::hex::decode(hex).ok()?;
    crate::bridge::federation::rsk_address_from_public_key(&bytes)
}

fn make_cfg_env(spec_id: SpecId, chain_id: u64, eip3541_active: bool) -> CfgEnv {
    let mut cfg = CfgEnv::default();
    cfg.chain_id = chain_id;
    // Gas params are spec-dependent: assigning `spec` alone keeps the
    // default (latest-fork) table and mis-prices historical opcodes —
    // e.g. SSTORE reset was charged 2900 instead of 5000 at mainnet #1713.
    cfg.set_spec_and_mainnet_gas_params(spec_id);
    // rskj never adopted EIP-150's 63/64 gas retention: CREATE forwards ALL
    // remaining gas to the child (Program.createContract spends
    // getRemainingGas()). A u64::MAX divisor makes the retention zero. The
    // CALL family is fully replaced by rsk_instructions.
    cfg.gas_params.override_gas([(
        revm::context_interface::cfg::GasId::call_stipend_reduction(),
        u64::MAX,
    )]);
    cfg.limit_contract_code_size = Some(0x6000);
    // RSKIP544 (Vetiver900): rskj only rejects new contract code starting
    // with 0xEF from vetiver900, while revm bundles EIP-3541 into LONDON+.
    cfg.disable_eip3541 = !eip3541_active;
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

    /// Regression for mainnet block #356,285 (gas used mismatch 65,024 vs
    /// 62,724): rskj charges the 2,300 CALL stipend to the caller
    /// (calleeGas = min(remaining, requested + stipend)), while canonical
    /// EVM conjures it for free — making a `transfer()` to an EOA 2,300
    /// cheaper. The contract performs CALL(gas=0, eoa, value=1) and stops:
    ///   21,000 intrinsic + 21 (7 pushes) + 700 CALL + 9,000 VT = 30,721
    /// (the charged stipend returns as the EOA child's unused gas).
    #[test]
    fn test_rskj_call_stipend_is_charged_to_caller() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xCC);
        let eoa = Address::repeat_byte(0xBB);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));

        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &eoa, 1, U256::from(5));
        let root = put_account(&root, store.as_ref(), &contract, 1, U256::from(1_000));
        // PUSH1 0 x4 (ret/args) PUSH1 1 (value) PUSH20 eoa PUSH1 0 (gas) CALL STOP
        let mut code = vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // out/in offsets+sizes
            0x60, 0x01, // value 1
            0x73, // PUSH20
        ];
        code.extend_from_slice(eoa.as_slice());
        code.extend_from_slice(&[0x60, 0x00, 0xF1, 0x00]); // gas 0, CALL, STOP
        let code_key_bytes = rustock_trie::code_key(&contract);
        let root = root.put(
            &TrieKeySlice::from_key(&code_key_bytes),
            &code,
            store.as_ref(),
        );

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(356_285);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(600_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .expect("execution succeeds");
        assert!(result.success);
        assert_eq!(
            result.gas_used, 30_721,
            "rskj charges the stipend through calleeGas; canonical EVM would yield 28,421"
        );
    }

    /// Regression for mainnet block #1713 (gas used mismatch 26656 vs 24556):
    /// cfg.spec alone leaves the latest-fork gas table in place; the params
    /// must be derived per spec. Pre-Istanbul SSTORE: the 5000 reset cost is
    /// fully carried by the static charge.
    #[test]
    fn test_cfg_env_gas_params_follow_spec() {
        let byz = make_cfg_env(SpecId::BYZANTIUM, 30, false);
        assert_eq!(byz.gas_params.sstore_static_gas(), 5000);
        assert_eq!(byz.gas_params.sstore_reset_without_cold_load_cost(), 0);
        assert_eq!(byz.gas_params.sstore_set_without_load_cost(), 15_000);

        // Istanbul-mapped heights use EIP-2200 metering (static = 800).
        let ist = make_cfg_env(SpecId::ISTANBUL, 30, false);
        assert_eq!(ist.gas_params.sstore_static_gas(), 800);
        assert_eq!(ist.gas_params.sstore_reset_without_cold_load_cost(), 4_200);
    }

    /// Regression for mainnet #466,503: rskj charges NEW_ACCT_CALL (25,000)
    /// on trie EXISTENCE — the first-ever internal call to a precompile
    /// creates its account node (zero-value transfer), so the charge applies
    /// once per address in the chain's lifetime, not once per call. The same
    /// ecrecover call in the next block must cost exactly 25,000 less.
    #[test]
    fn test_precompile_new_account_charged_only_once_across_blocks() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let contract = Address::repeat_byte(0xCC);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let root = put_account(&root, store.as_ref(), &contract, 1, U256::ZERO);

        // PUSH1 0 x4 (ret/args) PUSH1 0 (value) PUSH20 0x..01 PUSH2 3000 CALL STOP
        let mut code = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x73];
        let mut ecrecover = [0u8; 20];
        ecrecover[19] = 0x01;
        code.extend_from_slice(&ecrecover);
        code.extend_from_slice(&[0x61, 0x0b, 0xb8, 0xf1, 0x00]); // PUSH2 3000, CALL, STOP
        let code_key_bytes = rustock_trie::code_key(&contract);
        let root = root.put(
            &TrieKeySlice::from_key(&code_key_bytes),
            &code,
            store.as_ref(),
        );

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);

        let call_tx = |nonce: u64| rustock_core::Transaction {
            nonce,
            gas_price: U256::from(0),
            gas_limit: U256::from(200_000),
            to: Bytes::copy_from_slice(contract.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let header = dummy_header(466_503);
        let r1 = executor
            .execute_block(&header, &[(call_tx(0), sender)], &root, store.clone())
            .expect("block 1");
        assert!(r1.tx_results[0].success);

        // Apply to the trie: the ecrecover account node must now exist.
        let root2 =
            crate::state::apply_state_changes(&root, store.as_ref(), &r1.state_changes);

        let header2 = dummy_header(466_504);
        let r2 = executor
            .execute_block(&header2, &[(call_tx(1), sender)], &root2, store.clone())
            .expect("block 2");
        assert!(r2.tx_results[0].success);

        let g1 = r1.tx_results[0].gas_used;
        let g2 = r2.tx_results[0].gas_used;
        assert_eq!(
            g1 - g2,
            25_000,
            "first call pays NEW_ACCT_CALL once (got {g1} then {g2})"
        );
    }

    /// Multi-tx version of the #382,134 regression: a later transaction in
    /// the SAME block re-reads (and possibly same-value re-writes) the bridge
    /// slots written by an earlier one — the slots must still reach the trie.
    /// Mirrors #378,129: registerBtcTransaction writes the rejection release,
    /// the block's own updateCollections reads it, REMASC closes the block.
    #[test]
    fn test_paid_bridge_storage_survives_same_block_reread() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let caller2 = Address::repeat_byte(0xCD);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc * U256::from(2));
        let root = put_account(&root, store.as_ref(), &caller2, 0, one_rbtc);

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(8_000_000);

        // tx1: releaseBtc (writes the release request queue blob)
        let tx1 = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: one_rbtc,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        // tx2: updateCollections (reads the queue; building fails without
        // UTXOs so the queue is re-stored byte-identical)
        let tx2 = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from_static(&[0x0c, 0x5a, 0x99, 0x90]),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_block(
                &header,
                &[(tx1, sender), (tx2, caller2)],
                &root,
                store.clone(),
            )
            .expect("block executes");
        assert!(result.tx_results[0].success, "releaseBtc succeeds");
        assert!(result.tx_results[1].success, "updateCollections succeeds");

        // Apply to the trie and read the queue back through a fresh root,
        // exactly like the next block would.
        let new_root =
            crate::state::apply_state_changes(&root, store.as_ref(), &result.state_changes);
        let queue_key = {
            use sha3::{Digest, Keccak256};
            let mut padded = [0u8; 32];
            let name = b"releaseRequestQueueWithTxHash";
            padded[32 - name.len()..].copy_from_slice(name);
            let _ = Keccak256::digest(name); // (key is ascii-padded, not hashed)
            padded
        };
        let slot_b256 = B256::from(queue_key);
        let key_bytes = rustock_trie::storage_key(&crate::precompiles::BRIDGE_ADDR, &slot_b256);
        let key = rustock_trie::TrieKeySlice::from_key(&key_bytes);
        let stored = new_root.get(&key, store.as_ref());
        assert!(
            stored.is_some(),
            "queue length cell must survive into the trie after a same-block re-read"
        );
    }

    /// Regression for mainnet #382,134: bridge storage written by a PAID
    /// bridge transaction (post-RSKIP88, revm path) must survive into the
    /// block's state changes. A paid releaseBtc enqueues a release request
    /// (a multi-slot blob under the Bridge account).
    #[test]
    fn test_paid_bridge_tx_persists_bridge_storage() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc * U256::from(2));

        let block_store =
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(8_000_000); // paid bridge era

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: one_rbtc, // 1 RBTC -> well above the pegout minimum
            input: Bytes::new(), // empty input = releaseBtc
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store)
            .expect("block executes");
        assert!(result.tx_results[0].success, "releaseBtc succeeds");

        let bridge_state = result
            .state_changes
            .get(&crate::precompiles::BRIDGE_ADDR)
            .expect("bridge account in state changes");
        let written_slots = bridge_state
            .storage
            .iter()
            .filter(|(_, slot)| slot.present_value != slot.original_value())
            .count();
        assert!(
            written_slots >= 2,
            "releaseBtc must persist the release request queue blob, got {written_slots} changed slots"
        );
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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

    /// Runs a contract-creation tx with the given initcode at the given mainnet height.
    fn run_create_at(initcode: Vec<u8>, block_number: u64, gas_limit: u64) -> TxExecutionResult {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xEE);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(block_number);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(gas_limit),
            to: Bytes::new(), // contract creation
            value: U256::ZERO,
            input: Bytes::from(initcode),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        executor.execute_tx(&header, &tx, sender, &root, store).unwrap()
    }

    /// Ported from rskj ContractCodePrefixDslTest
    /// (dsl/contract_code_prefix_rskip544/create_fails_with_ef_byte_activated.txt):
    /// after RSKIP544 (vetiver900), creating a contract whose code starts with
    /// 0xEF fails and burns all gas.
    #[test]
    fn test_rskip544_create_ef_code_fails_after_vetiver900() {
        // PUSH1 0xEF, PUSH1 0, MSTORE8, PUSH1 1, PUSH1 0, RETURN -> code = [0xEF]
        let initcode = hex::decode("60ef60005360016000f3").unwrap();
        let result = run_create_at(initcode, 8_804_200, 300_000);
        assert!(!result.success, "0xEF-prefixed code must be rejected post-vetiver900");
        assert_eq!(result.gas_used, 300_000, "all gas is consumed (rskj DSL groundtruth)");
    }

    /// Ported from rskj ContractCodePrefixDslTest
    /// (testCreateSucceedsWithEFByteBeforeRSKIP544Activation): before vetiver900,
    /// 0xEF-prefixed code is accepted — rskj only enforces EIP-3541 from RSKIP544.
    #[test]
    fn test_rskip544_create_ef_code_succeeds_before_vetiver900() {
        let initcode = hex::decode("60ef60005360016000f3").unwrap();
        let result = run_create_at(initcode, 8_804_199, 300_000);
        assert!(result.success, "0xEF-prefixed code must be accepted pre-vetiver900");
        assert!(result.gas_used > 21_000 && result.gas_used < 300_000);
    }

    /// Ported from rskj ContractCodePrefixDslTest (create_succeeds_with_fe_byte.txt):
    /// 0xFE-prefixed code is fine even after RSKIP544.
    #[test]
    fn test_rskip544_create_fe_code_succeeds_after_vetiver900() {
        let initcode = hex::decode("60fe60005360016000f3").unwrap();
        let result = run_create_at(initcode, 8_804_200, 300_000);
        assert!(result.success);
        assert!(result.gas_used > 21_000 && result.gas_used < 300_000);
    }

    /// Ported from rskj ContractCodePrefixDslTest (create_succeeds_with_empty_code.txt):
    /// empty contract code is allowed after RSKIP544.
    #[test]
    fn test_rskip544_create_empty_code_succeeds_after_vetiver900() {
        let initcode = hex::decode("60006000f3").unwrap();
        let result = run_create_at(initcode, 8_804_200, 300_000);
        assert!(result.success);
        assert!(result.gas_used > 21_000 && result.gas_used < 300_000);
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
                cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
    fn test_fees_routed_to_remasc() {
        use crate::precompiles::REMASC_ADDR;

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
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_block(&header, &[(tx, sender)], &root, store)
            .unwrap();

        assert!(result.tx_results[0].success);

        // Fees are routed to REMASC, not the miner. gas_used * gas_price = 21000 * 100
        let remasc_state = result.state_changes.get(&REMASC_ADDR)
            .expect("REMASC should appear in state changes");
        assert_eq!(
            remasc_state.info.balance,
            U256::from(2_100_000u64),
            "REMASC receives 21000 * 100 = 2_100_000"
        );

        // The miner (header.beneficiary) should NOT receive fees directly
        assert!(
            result.state_changes.get(&beneficiary).is_none(),
            "miner should not receive fees directly; REMASC distributes later"
        );
    }

    // -----------------------------------------------------------------------
    // End-to-end precompile execution tests
    // -----------------------------------------------------------------------

    /// Direct tx to REMASC precompile (0x01000008).
    /// REMASC costs 0 gas — total should be only intrinsic gas (21000).
    /// Uses a low block number (below maturity) so process_miners_fees is a no-op.
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

        // Block 100 is below mainnet maturity (4000), so REMASC is a no-op
        let header = dummy_header(100);

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
            cached_rlp: None,
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
            cached_rlp: None,
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
            21_000 + 23_000,
            "Empty Bridge call dispatches releaseBtc (23k gas) on top of intrinsic"
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
            cached_rlp: None,
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
                    && acct.info.code.as_ref().is_some_and(|c| !c.is_empty())
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
            cached_rlp: None,
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

    /// Direct tx to Environment precompile (0x01000011) with getCallStackDepth() selector.
    /// Ported from rskj EnvironmentTest.getCallStackDepth:
    ///   selector = 0x80af2871, returns depth as uint32.
    ///   Direct tx call → depth = 1 (matching rskj's getCallDeep()==0 + 1).
    #[test]
    fn test_environment_precompile_direct_call() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let env_addr = crate::precompiles::ENVIRONMENT_ADDR;
        let selector = vec![0xe8, 0xce, 0x22, 0x74]; // keccak256("getCallStackDepth()")[0:4]

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(env_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(selector),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "Environment direct call should succeed");

        // Output: uint32 ABI-encoded as 32-byte big-endian
        assert_eq!(result.output.len(), 32);
        let depth = u32::from_be_bytes([
            result.output[28],
            result.output[29],
            result.output[30],
            result.output[31],
        ]);
        assert_eq!(depth, 1, "direct tx call depth should be 1 (matching rskj)");

        // Gas: 0 for Environment + intrinsic cost
        // Intrinsic: 21000 base + 16*4 (4 non-zero selector bytes at Istanbul rate) = 21064
        assert_eq!(result.gas_used, 21_064, "Environment costs 0 gas, total = intrinsic only");
    }

    /// Environment precompile with unknown selector should fail.
    #[test]
    fn test_environment_precompile_unknown_selector() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        let env_addr = crate::precompiles::ENVIRONMENT_ADDR;
        let bad_selector = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(env_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(bad_selector),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(!result.success, "unknown selector should fail");
    }

    /// Environment precompile called via contract STATICCALL should return
    /// depth > 1 (one extra level for the contract frame).
    #[test]
    fn test_environment_precompile_via_contract() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(8_000_000);

        // Runtime code:
        //   Store selector 0xe8ce2274 at memory[0..4]
        //   STATICCALL Environment precompile (0x01000011)
        //   Return 32 bytes of output
        //
        // PUSH4 0xe8ce2274    ; 63 e8ce2274
        // PUSH1 0x00          ; 60 00
        // MSTORE              ; 52       -> mem[28..32] = 0xe8ce2274
        //
        // PUSH1 0x20          ; 60 20    retSize (32)
        // PUSH1 0x40          ; 60 40    retOffset
        // PUSH1 0x04          ; 60 04    argsSize (4)
        // PUSH1 0x1c          ; 60 1c    argsOffset (28)
        // PUSH4 0x01000011    ; 63 01000011   address (4 bytes)
        // GAS                 ; 5A
        // STATICCALL          ; FA
        //
        // PUSH1 0x20          ; 60 20    size
        // PUSH1 0x40          ; 60 40    offset
        // RETURN              ; F3
        let runtime: Vec<u8> = vec![
            0x63, 0xe8, 0xce, 0x22, 0x74,  // PUSH4 0xe8ce2274
            0x60, 0x00,                      // PUSH1 0
            0x52,                            // MSTORE
            0x60, 0x20,                      // PUSH1 32 (retSize)
            0x60, 0x40,                      // PUSH1 64 (retOffset)
            0x60, 0x04,                      // PUSH1 4 (argsSize)
            0x60, 0x1c,                      // PUSH1 28 (argsOffset)
            0x63, 0x01, 0x00, 0x00, 0x11,   // PUSH4 0x01000011 (Environment addr)
            0x5A,                            // GAS
            0xFA,                            // STATICCALL
            0x60, 0x20,                      // PUSH1 32 (return size)
            0x60, 0x40,                      // PUSH1 64 (return offset)
            0xF3,                            // RETURN
        ];

        let runtime_len = runtime.len() as u8;
        let mut initcode: Vec<u8> = vec![
            0x60, runtime_len,
            0x60, 0x0c,
            0x60, 0x00,
            0x39,
            0x60, runtime_len,
            0x60, 0x00,
            0xF3,
        ];
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
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store.clone(),
        );

        // Deploy
        let deploy_result = executor
            .execute_block(&header, &[(tx, sender)], &root, store.clone())
            .unwrap();

        assert!(deploy_result.tx_results[0].success, "deployment should succeed");

        let contract_addr = deploy_result.state_changes.iter()
            .find(|(addr, acct)| {
                **addr != sender
                    && **addr != header.beneficiary
                    && acct.info.code.as_ref().is_some_and(|c| !c.is_empty())
            })
            .map(|(addr, _)| *addr)
            .expect("should have created a contract");

        // Set up state for calling the contract
        let root2 = TrieNode::empty();
        let root2 = put_account(&root2, store.as_ref(), &sender, 1, one_rbtc);

        let code_bytes = deploy_result.state_changes.get(&contract_addr)
            .unwrap().info.code.as_ref().unwrap().bytes_slice().to_vec();

        use rustock_trie::{TrieKeySlice, code_key, AccountState};
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
            cached_rlp: None,
        };

        let call_result = executor
            .execute_tx(&header, &call_tx, sender, &root2, store)
            .unwrap();

        assert!(call_result.success, "contract call should succeed");
        assert_eq!(call_result.output.len(), 32, "should return 32-byte ABI-encoded uint32");

        let depth = u32::from_be_bytes([
            call_result.output[28],
            call_result.output[29],
            call_result.output[30],
            call_result.output[31],
        ]);

        assert!(
            depth >= 2,
            "depth via contract call should be >= 2 (tx frame + contract frame), got {}",
            depth
        );
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // -----------------------------------------------------------------------
    // BlockHeaderContract integration tests
    // -----------------------------------------------------------------------

    fn block_header_selector(sig: &str) -> [u8; 4] {
        use sha3::{Digest, Keccak256};
        let h = Keccak256::digest(sig.as_bytes());
        [h[0], h[1], h[2], h[3]]
    }

    /// Build ABI-encoded input for a single-param BlockHeaderContract call:
    /// 4-byte selector + 32-byte ABI-encoded int256.
    fn bh_input(sig: &str, depth: i64) -> Vec<u8> {
        let sel = block_header_selector(sig);
        let mut input = vec![0u8; 36];
        input[..4].copy_from_slice(&sel);
        if depth >= 0 {
            let be = (depth as u64).to_be_bytes();
            input[28..36].copy_from_slice(&be);
        } else {
            // Negative int256: sign-extend with 0xFF
            input[4..36].fill(0xFF);
            let be = depth.to_be_bytes();
            input[28..36].copy_from_slice(&be);
        }
        input
    }

    /// Decode an ABI-encoded `bytes` return value.
    fn decode_abi_bytes(output: &[u8]) -> Vec<u8> {
        if output.len() < 64 {
            return Vec::new();
        }
        let len = u64::from_be_bytes(output[56..64].try_into().unwrap()) as usize;
        if 64 + len > output.len() {
            return Vec::new();
        }
        output[64..64 + len].to_vec()
    }

    /// Direct tx to BlockHeaderContract with getCoinbaseAddress(0).
    /// Sets up a two-block chain and queries the parent's coinbase.
    #[test]
    fn test_block_header_get_coinbase_address() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Store a parent block (number 99) with a known coinbase
        let parent_coinbase = Address::repeat_byte(0xCC);
        let mut parent_header = dummy_header(99);
        parent_header.beneficiary = parent_coinbase;
        let parent_hash = parent_header.hash();
        block_store.put_header(&parent_header).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        // Current block is 100, parent_hash points to block 99
        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getCoinbaseAddress(int256)", 0);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor
            .execute_tx(&header, &tx, sender, &root, store)
            .unwrap();

        assert!(result.success, "getCoinbaseAddress should succeed");

        let decoded = decode_abi_bytes(&result.output);
        assert_eq!(decoded.len(), 20, "coinbase address should be 20 bytes");
        assert_eq!(decoded, parent_coinbase.as_slice());
    }

    /// Shared fixture for RSKIP536 tests: parent block #99 with difficulty 1,
    /// two uncles of difficulty 1 each, and a stored total difficulty.
    /// Mirrors rskj BlockHeaderContractTest (RSK_BLOCK_DIFFICULTY = 1,
    /// RSK_BLOCK_WITH_UNCLES_DIFFICULTY = 3).
    fn rskip536_call(sig: &str, cfg: RskHardforkConfig, current_number: u64) -> TxExecutionResult {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());

        let parent_number = current_number - 1;
        let mut parent_header = dummy_header(parent_number);
        parent_header.difficulty = U256::from(1);
        let parent_hash = parent_header.hash();
        block_store.put_header(&parent_header).unwrap();
        block_store.put_canonical_hash(parent_number, parent_hash).unwrap();

        let mut uncle1 = dummy_header(parent_number - 1);
        uncle1.difficulty = U256::from(1);
        uncle1.beneficiary = Address::repeat_byte(0xD1);
        let mut uncle2 = dummy_header(parent_number - 1);
        uncle2.difficulty = U256::from(1);
        uncle2.beneficiary = Address::repeat_byte(0xD2);
        block_store.put_body(parent_hash, &[], &[uncle1, uncle2]).unwrap();
        block_store.put_total_difficulty(parent_hash, U256::from(11_996)).unwrap();

        let mut header = dummy_header(current_number);
        header.parent_hash = parent_hash;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(bh_input(sig, 0)),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(cfg, block_store);
        executor.execute_tx(&header, &tx, sender, &root, store).unwrap()
    }

    /// Ported from rskj BlockHeaderContractTest.getDifficultyWithUnclesDifficulty:
    /// difficulty 1 + two uncles of difficulty 1 = 3.
    #[test]
    fn test_rskip536_get_difficulty_with_uncles() {
        let result = rskip536_call(
            "getDifficultyWithUncles(int256)",
            RskHardforkConfig::all_active(33),
            100,
        );
        assert!(result.success);
        assert_eq!(decode_abi_bytes(&result.output), vec![3u8]);
    }

    /// Ported from rskj BlockHeaderContractTest.getCumulativeWork: returns the
    /// block store's total difficulty for the block hash.
    #[test]
    fn test_rskip536_get_cumulative_work() {
        let result = rskip536_call(
            "getCumulativeWork(int256)",
            RskHardforkConfig::all_active(33),
            100,
        );
        assert!(result.success);
        assert_eq!(decode_abi_bytes(&result.output), vec![0x2e, 0xdc]); // 11996
    }

    /// Ported from rskj BlockHeaderContractTest.*_whenMethodDisabled_shouldThrowVME:
    /// both methods fail before RSKIP536 activates (mainnet vetiver900).
    #[test]
    fn test_rskip536_methods_disabled_before_activation() {
        for sig in ["getDifficultyWithUncles(int256)", "getCumulativeWork(int256)"] {
            let result = rskip536_call(sig, RskHardforkConfig::mainnet(), 8_804_199);
            assert!(!result.success, "{sig} must fail before vetiver900");
        }
    }

    /// Both methods work at the vetiver900 boundary on mainnet.
    #[test]
    fn test_rskip536_methods_enabled_at_vetiver900() {
        for sig in ["getDifficultyWithUncles(int256)", "getCumulativeWork(int256)"] {
            let result = rskip536_call(sig, RskHardforkConfig::mainnet(), 8_804_200);
            assert!(result.success, "{sig} must work from vetiver900");
        }
    }

    /// Calls the Bridge's getEstimatedFeesForPegOutAmount(uint256) at the
    /// given mainnet height with the given amount in weis.
    fn call_estimated_fees_for_pegout_amount(block_number: u64, wei: U256) -> TxExecutionResult {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(block_number);

        let mut input = vec![0u8; 36];
        input[..4].copy_from_slice(&block_header_selector("getEstimatedFeesForPegOutAmount(uint256)"));
        input[4..36].copy_from_slice(&wei.to_be_bytes::<32>());

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        executor.execute_tx(&header, &tx, sender, &root, store).unwrap()
    }

    /// Ported from rskj BridgeTest.getEstimatedFeesForPegOutAmount_preRSKIP540__shouldThrowVMException.
    #[test]
    fn test_rskip540_estimated_fees_for_pegout_amount_disabled_before_vetiver900() {
        // 0.004 BTC (mainnet minimum) in wei — valid amount, but method not enabled yet.
        let amount = U256::from(400_000u64) * U256::from(10_000_000_000u64);
        let result = call_estimated_fees_for_pegout_amount(8_804_199, amount);
        assert!(!result.success, "method must not exist before vetiver900");
    }

    /// Ported from rskj BridgeTest.getEstimatedFeesForPegOutAmount_afterRSKIP540_shouldExecute.
    #[test]
    fn test_rskip540_estimated_fees_for_pegout_amount_executes_after_vetiver900() {
        let amount = U256::from(400_000u64) * U256::from(10_000_000_000u64);
        let result = call_estimated_fees_for_pegout_amount(8_804_200, amount);
        assert!(result.success, "method must execute from vetiver900");
    }

    /// Ported from rskj BridgeTest.getEstimatedFeesForPegOutAmount_withAmountBelowMinimum_*:
    /// amounts below the 0.004 BTC mainnet minimum are rejected.
    #[test]
    fn test_rskip540_estimated_fees_for_pegout_amount_below_minimum_fails() {
        let result = call_estimated_fees_for_pegout_amount(8_804_200, U256::from(1));
        assert!(!result.success, "below-minimum amount must be rejected");
    }

    /// Regression for mainnet block #2646 (gas used mismatch 31280 vs 31272):
    /// rskj Bridge.getGasForData charges functionCost + data.length * 2.
    /// getNextPegoutCreationBlockNumber: 21000 + 4*68 + 3000 + 4*2 = 24280.
    #[test]
    fn test_bridge_call_charges_rskj_data_cost() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(2_646);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(block_header_selector("getNextPegoutCreationBlockNumber()").to_vec()),
            v: 28, r: U256::from(1), s: U256::from(1), cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 24_280, "functionCost 3000 + data cost 4*2");
    }

    // -----------------------------------------------------------------------
    // Free bridge transactions (rskj BridgeUtils.isFreeBridgeTx)
    // -----------------------------------------------------------------------

    /// Known vector: the address of private key 0x01. Its public key is
    /// 0479be667e...f81798 / 483ada77...10d4b8 and the derived address is
    /// 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf.
    #[test]
    fn test_rsk_address_from_pubkey_hex() {
        let uncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        let compressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let expected: Address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".parse().unwrap();
        assert_eq!(rsk_address_from_pubkey_hex(uncompressed), Some(expected));
        assert_eq!(rsk_address_from_pubkey_hex(compressed), Some(expected));
        assert_eq!(rsk_address_from_pubkey_hex("zz"), None);
    }

    /// All mainnet free-bridge sender keys (15 federators + 7 authorizers)
    /// derive to distinct addresses.
    #[test]
    fn test_mainnet_free_bridge_senders_derive() {
        let executor = RskExecutor::new(
            RskHardforkConfig::mainnet(),
            Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap()),
        );
        let senders = &executor.free_bridge_senders;
        assert_eq!(senders.len(), 22);
        let unique: std::collections::HashSet<_> = senders.iter().collect();
        assert_eq!(unique.len(), 22);
    }

    /// Runs a gas_limit-0 tx to the Bridge through execute_block at the
    /// given mainnet height from the given sender.
    fn run_bridge_tx_gas0(block_number: u64, sender: Address) -> Result<crate::executor::BlockExecutionResult, ExecutionError> {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let root = put_account(&root, store.as_ref(), &sender, 0, U256::ZERO);
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(block_number);

        // updateCollections() selector
        let input = block_header_selector("updateCollections()").to_vec();
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(0),
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 28, // free bridge txs are real signed txs, not remasc
            r: U256::from(1),
            s: U256::from(1),
            cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        executor.execute_block(&header, &[(tx, sender)], &root, store)
    }

    /// Before areBridgeTxsPaid (mainnet 370_000), a genesis federator's
    /// gas_limit-0 bridge tx executes for free: receipt gas_used 0.
    #[test]
    fn test_free_bridge_tx_executes_with_zero_gas() {
        let federator = rsk_address_from_pubkey_hex(
            "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
        )
        .unwrap();
        let result = run_bridge_tx_gas0(457, federator).expect("free bridge tx must execute");
        assert_eq!(result.tx_results.len(), 1);
        assert_eq!(result.tx_results[0].gas_used, 0);
        assert_eq!(result.gas_used, 0);
    }

    /// From areBridgeTxsPaid on, the same tx goes through normal gas
    /// validation and is rejected (gas_limit 0 < intrinsic cost).
    #[test]
    fn test_bridge_tx_gas0_rejected_after_are_bridge_txs_paid() {
        let federator = rsk_address_from_pubkey_hex(
            "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
        )
        .unwrap();
        assert!(run_bridge_tx_gas0(370_000, federator).is_err());
    }

    /// A non-federation sender never gets the free path. Pre-RSKIP136 the
    /// call is still included: rskj execError (insufficient limit for the
    /// precompile cost) yields a failed receipt consuming the (zero) limit.
    #[test]
    fn test_bridge_tx_gas0_fails_for_unknown_sender() {
        let result = run_bridge_tx_gas0(457, Address::repeat_byte(0xEE))
            .expect("pre-RSKIP136 direct bridge call is included, not rejected");
        assert!(!result.tx_results[0].success);
        assert_eq!(result.tx_results[0].gas_used, 0, "all of the zero gas limit consumed");
    }

    /// Regression for the silent stall at mainnet #4001: the REMASC maturity
    /// is 4_000 blocks, so #4001 is the FIRST block whose system call touches
    /// REMASC storage — on a journal that never loaded the account, the sload
    /// panicked (ColdLoadSkipped) and killed the sync task.
    #[test]
    fn test_remasc_system_call_past_maturity_on_fresh_journal() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());

        // The processing block (#1) whose fees REMASC distributes at #4001.
        let processing = dummy_header(1);
        let processing_hash = processing.hash();
        block_store.put_header(&processing).unwrap();
        block_store.put_canonical_hash(1, processing_hash).unwrap();

        let header = dummy_header(4_001);
        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::copy_from_slice(crate::precompiles::REMASC_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor
            .execute_block(&header, &[(remasc_tx, Address::ZERO)], &root, store)
            .expect("REMASC past maturity must execute on a fresh journal");
        assert!(result.tx_results[0].success);
        assert_eq!(result.gas_used, 0);
    }

    /// Regression for mainnet block #3307: before RSKIP136 (bahamas, 3_397)
    /// rskj checks the limit against the precompile cost alone and records
    /// gasUsed = precompileCost + intrinsicCost — above the 30_000 limit.
    /// getNextPegoutCreationBlockNumber: 21272 + 3000 + 8 = 24280 with a
    /// 23_000 limit (>= required 3008, < total).
    #[test]
    fn test_pre_rskip136_bridge_gas_exceeds_limit() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAB);
        let root = put_account(&root, store.as_ref(), &sender, 0, U256::from(10u64).pow(U256::from(18)));
        let block_store = Arc::new(BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap());
        let header = dummy_header(3_307);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(23_000), // below total 24_280, above required 3_008
            to: Bytes::copy_from_slice(crate::precompiles::BRIDGE_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(block_header_selector("getNextPegoutCreationBlockNumber()").to_vec()),
            v: 28, r: U256::from(1), s: U256::from(1), cached_rlp: None,
        };

        let executor = RskExecutor::new(RskHardforkConfig::mainnet(), block_store);
        let result = executor.execute_block(&header, &[(tx, sender)], &root, store).unwrap();
        assert!(result.tx_results[0].success);
        assert_eq!(result.tx_results[0].gas_used, 24_280, "gasUsed exceeds the tx gas limit pre-RSKIP136");
    }

    /// getCoinbaseAddress at depth 1 returns the grandparent's coinbase.
    #[test]
    fn test_block_header_get_coinbase_depth_1() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let grandparent_coinbase = Address::repeat_byte(0xDD);
        let mut gp = dummy_header(98);
        gp.beneficiary = grandparent_coinbase;
        let gp_hash = gp.hash();
        block_store.put_header(&gp).unwrap();
        block_store.put_canonical_hash(98, gp_hash).unwrap();

        let mut parent = dummy_header(99);
        parent.parent_hash = gp_hash;
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getCoinbaseAddress(int256)", 1);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        assert_eq!(decoded, grandparent_coinbase.as_slice());
    }

    /// getBlockHash returns the correct block hash.
    #[test]
    fn test_block_header_get_block_hash() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let parent = dummy_header(99);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getBlockHash(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, parent_hash.as_slice());
    }

    /// getDifficulty returns the parent block's difficulty.
    #[test]
    fn test_block_header_get_difficulty() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.difficulty = U256::from(1_234_567u64);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getDifficulty(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // 1_234_567 = 0x12D687 → Java BigInteger bytes = [0x12, 0xD6, 0x87]
        assert_eq!(decoded, vec![0x12, 0xD6, 0x87]);
    }

    /// getGasUsed returns ABI-encoded gas used (Java BigInteger format).
    #[test]
    fn test_block_header_get_gas_used() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.gas_used = 21_000;
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getGasUsed(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // 21000 = 0x5208
        assert_eq!(decoded, vec![0x52, 0x08]);
    }

    /// Depth beyond MAX_BLOCK_DEPTH (4000) returns empty bytes.
    #[test]
    fn test_block_header_depth_beyond_max_returns_empty() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(5000);

        // depth 4000 → >= MAX_BLOCK_DEPTH → empty
        let mut input = vec![0u8; 36];
        input[..4].copy_from_slice(&block_header_selector("getDifficulty(int256)"));
        // 4000 = 0x0FA0
        input[34] = 0x0F;
        input[35] = 0xA0;

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success, "depth beyond MAX should succeed with empty");

        let decoded = decode_abi_bytes(&result.output);
        assert!(decoded.is_empty(), "should return empty bytes for depth >= 4000");
    }

    /// Negative depth should fail (rskj throws VMException).
    #[test]
    fn test_block_header_negative_depth_fails() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(100);

        let input = bh_input("getCoinbaseAddress(int256)", -1);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(!result.success, "negative depth should fail");
    }

    /// Block not found at depth returns empty bytes.
    #[test]
    fn test_block_header_block_not_found_returns_empty() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Block 100 executing, no blocks stored → depth 0 will find nothing
        let header = dummy_header(100);

        let input = bh_input("getCoinbaseAddress(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success, "missing block should succeed with empty result");

        let decoded = decode_abi_bytes(&result.output);
        assert!(decoded.is_empty());
    }

    /// Gas cost is 4000 + 2*input.len() (on top of intrinsic).
    #[test]
    fn test_block_header_gas_cost() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let header = dummy_header(100);

        // 36 bytes input (4 selector + 32 depth)
        // Precompile gas: 4000 + 2*36 = 4072
        let input = bh_input("getDifficulty(int256)", 0);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        // Intrinsic: 21000 base + (4 non-zero selector bytes * 16) + (some zero/non-zero depth bytes * 4 or 16)
        // Precompile: 4000 + 72 = 4072
        // Total should be > 21000 + 4000
        assert!(result.gas_used > 25_000, "should include precompile gas");
    }

    /// getMinGasPrice returns the parent's minimum gas price.
    #[test]
    fn test_block_header_get_min_gas_price() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.minimum_gas_price = U256::from(59_240_000u64);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getMinGasPrice(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // 59_240_000 = 0x387_EE40 → Java BigInteger: [0x03, 0x87, 0xEE, 0x40]
        assert_eq!(decoded, vec![0x03, 0x87, 0xEE, 0x40]);
    }

    /// getGasLimit returns the parent's gas limit.
    #[test]
    fn test_block_header_get_gas_limit() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.gas_limit = U256::from(6_800_000u64);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getGasLimit(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // 6_800_000 = 0x67C280 → Java BigInteger: [0x67, 0xC2, 0x80]
        assert_eq!(decoded, vec![0x67, 0xC2, 0x80]);
    }

    // -----------------------------------------------------------------------
    // Ported from rskj BlockHeaderContractTest
    // -----------------------------------------------------------------------

    /// Ported from rskj BlockHeaderContractTest.getGasUsed:
    ///   GAS_USED = 0 → BigInteger(0).toByteArray() = [0]
    #[test]
    fn test_rskj_block_header_gas_used_zero() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let mut parent = dummy_header(99);
        parent.gas_used = 0;
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getGasUsed(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success);

        let decoded = decode_abi_bytes(&result.output);
        // BigInteger.valueOf(0).toByteArray() = [0]
        assert_eq!(decoded, vec![0x00], "gas_used=0 should return [0] (Java BigInteger)");
    }

    /// Ported from rskj BlockHeaderContractTest.getUncleCoinbaseAddress:
    ///   Tests uncle index 0, 1 (valid), and 2 (out of range → empty).
    #[test]
    fn test_rskj_block_header_uncle_coinbase() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Create parent with two uncles
        let uncle0_coinbase = Address::repeat_byte(0x11);
        let uncle1_coinbase = Address::repeat_byte(0x22);

        let mut uncle0 = dummy_header(98);
        uncle0.beneficiary = uncle0_coinbase;
        let mut uncle1 = dummy_header(98);
        uncle1.beneficiary = uncle1_coinbase;

        let parent = dummy_header(99);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();
        block_store
            .put_body(parent_hash, &[], &[uncle0, uncle1])
            .unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        // Uncle index 0 → uncle0_coinbase
        let mut input = vec![0u8; 68];
        input[..4].copy_from_slice(&block_header_selector("getUncleCoinbaseAddress(int256,int256)"));
        // blockDepth = 0
        // uncleIndex = 0 (already zero)
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input.clone()),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let result = executor.execute_tx(&header, &tx, sender, &root, store.clone()).unwrap();
        assert!(result.success, "uncle index 0 should succeed");
        let decoded = decode_abi_bytes(&result.output);
        assert_eq!(decoded, uncle0_coinbase.as_slice(), "uncle 0 coinbase");

        // Uncle index 1 → uncle1_coinbase
        let mut input1 = vec![0u8; 68];
        input1[..4].copy_from_slice(&block_header_selector("getUncleCoinbaseAddress(int256,int256)"));
        input1[67] = 1; // uncleIndex = 1
        let tx1 = rustock_core::Transaction {
            nonce: 1,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input1),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let root1 = put_account(&TrieNode::empty(), store.as_ref(), &sender, 1, one_rbtc);
        let result1 = executor.execute_tx(&header, &tx1, sender, &root1, store.clone()).unwrap();
        assert!(result1.success, "uncle index 1 should succeed");
        let decoded1 = decode_abi_bytes(&result1.output);
        assert_eq!(decoded1, uncle1_coinbase.as_slice(), "uncle 1 coinbase");

        // Uncle index 2 → out of range → empty
        let mut input2 = vec![0u8; 68];
        input2[..4].copy_from_slice(&block_header_selector("getUncleCoinbaseAddress(int256,int256)"));
        input2[67] = 2; // uncleIndex = 2
        let tx2 = rustock_core::Transaction {
            nonce: 2,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input2),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };
        let root2 = put_account(&TrieNode::empty(), store.as_ref(), &sender, 2, one_rbtc);
        let result2 = executor.execute_tx(&header, &tx2, sender, &root2, store.clone()).unwrap();
        assert!(result2.success, "uncle index 2 (out of range) should succeed with empty");
        let decoded2 = decode_abi_bytes(&result2.output);
        assert!(decoded2.is_empty(), "uncle index 2 should return empty (only 2 uncles)");
    }

    /// Ported from rskj BlockHeaderContractTest.negativeUncleIndex:
    ///   Negative uncle index should fail.
    #[test]
    fn test_rskj_block_header_negative_uncle_index() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        let parent = dummy_header(99);
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();
        block_store.put_body(parent_hash, &[], &[]).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        // blockDepth=0, uncleIndex=-1
        let mut input = vec![0u8; 68];
        input[..4].copy_from_slice(&block_header_selector("getUncleCoinbaseAddress(int256,int256)"));
        // uncleIndex = -1 → all 0xFF in the second int256
        input[36..68].fill(0xFF);

        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(!result.success, "negative uncle index should fail");
    }

    /// Ported from rskj BlockHeaderContractTest.getEmptyMergedMiningTags:
    ///   When parent has no bitcoin_merged_mining_coinbase_transaction,
    ///   getMergedMiningTags returns empty bytes.
    #[test]
    fn test_rskj_block_header_empty_merged_mining_tags() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Parent with no merged mining data at all
        let parent = dummy_header(99);
        assert!(parent.bitcoin_merged_mining_coinbase_transaction.is_none());
        let parent_hash = parent.hash();
        block_store.put_header(&parent).unwrap();
        block_store.put_canonical_hash(99, parent_hash).unwrap();

        let mut header = dummy_header(100);
        header.parent_hash = parent_hash;

        let input = bh_input("getMergedMiningTags(int256)", 0);
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success, "empty merged mining should succeed");

        let decoded = decode_abi_bytes(&result.output);
        assert!(decoded.is_empty(), "no coinbase tx → empty merged mining tags");
    }

    /// Ported from rskj BlockHeaderContractTest.invalidBlockDepth:
    ///   Chain of 300 blocks, query at depth 500 → block not found → empty.
    #[test]
    fn test_rskj_block_header_depth_exceeds_chain_length() {
        let store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, store.as_ref(), &sender, 0, one_rbtc);

        let block_store = Arc::new(
            BlockStore::open(tempfile::tempdir().unwrap().path()).unwrap(),
        );

        // Store a small chain: blocks 0 through 9
        for i in 0..10 {
            let mut h = dummy_header(i);
            if i > 0 {
                let prev_hash = block_store.canonical_hash(i - 1).unwrap().unwrap();
                h.parent_hash = prev_hash;
            }
            let hash = h.hash();
            block_store.put_header(&h).unwrap();
            block_store.put_canonical_hash(i, hash).unwrap();
        }

        // Execute at block 10, parent is block 9
        let parent_hash = block_store.canonical_hash(9).unwrap().unwrap();
        let mut header = dummy_header(10);
        header.parent_hash = parent_hash;

        // depth 500 → target = 10 - 1 - 500 = underflow → empty
        let mut input = vec![0u8; 36];
        input[..4].copy_from_slice(&block_header_selector("getCoinbaseAddress(int256)"));
        input[34] = 0x01; // depth = 256+244=500
        input[35] = 0xF4;
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(crate::precompiles::BLOCK_HEADER_ADDR.as_slice()),
            value: U256::ZERO,
            input: Bytes::from(input),
            v: 0, r: U256::ZERO, s: U256::ZERO, cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store,
        );

        let result = executor.execute_tx(&header, &tx, sender, &root, store).unwrap();
        assert!(result.success, "depth exceeding chain length should succeed with empty");
        let decoded = decode_abi_bytes(&result.output);
        assert!(decoded.is_empty(), "depth 500 in 10-block chain → empty");
    }

    // -----------------------------------------------------------------------
    // REMASC fee distribution tests (Stage 6b)
    //
    // Port of rskj's RemascProcessMinerFeesTest using regtest config:
    //   maturity=10, syntheticSpan=5, rskLabsDivisor=5,
    //   federationDivisor=100, punishmentDivisor=10
    // -----------------------------------------------------------------------

    /// Helper: build a block store populated with a chain of headers.
    /// Each header at height `i` has parent_hash pointing to the previous hash.
    /// Returns (block_store, hashes) where hashes[i] is the canonical hash at block i.
    fn build_chain_store(
        count: u64,
        miner: Address,
        paid_fees_at: &[(u64, U256)],
    ) -> (Arc<BlockStore>, Vec<B256>) {
        let dir = tempfile::tempdir().unwrap();
        let bs = Arc::new(BlockStore::open(dir.path()).unwrap());

        let mut hashes = Vec::new();
        let mut parent_hash = B256::ZERO;

        for i in 0..count {
            let mut h = dummy_header(i);
            h.beneficiary = miner;
            h.parent_hash = parent_hash;
            // Set paid_fees for specified blocks
            for &(block, ref fees) in paid_fees_at {
                if block == i {
                    h.paid_fees = *fees;
                }
            }
            let hash = h.hash();
            bs.put_header_with_hash(hash, &h).unwrap();
            bs.put_canonical_hash(i, hash).unwrap();
            hashes.push(hash);
            parent_hash = hash;
        }

        (bs, hashes)
    }

    /// Helper: execute a REMASC call at the given block height and return state changes.
    /// `remasc_balance` simulates the fees already accumulated in REMASC from prior blocks.
    fn execute_remasc_at(
        block_store: &Arc<BlockStore>,
        block_number: u64,
        sender_balance: U256,
        remasc_config: crate::remasc::RemascConfig,
    ) -> crate::executor::BlockExecutionResult {
        execute_remasc_at_with_balance(block_store, block_number, sender_balance, remasc_config, U256::ZERO)
    }

    fn execute_remasc_at_with_balance(
        block_store: &Arc<BlockStore>,
        block_number: u64,
        sender_balance: U256,
        remasc_config: crate::remasc::RemascConfig,
        remasc_balance: U256,
    ) -> crate::executor::BlockExecutionResult {
        let trie_store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let root = put_account(&root, trie_store.as_ref(), &sender, 0, sender_balance);

        let remasc_addr = crate::precompiles::REMASC_ADDR;

        // Pre-seed REMASC with accumulated fees balance
        let root = if !remasc_balance.is_zero() {
            put_account(&root, trie_store.as_ref(), &remasc_addr, 0, remasc_balance)
        } else {
            root
        };

        let mut header = dummy_header(block_number);
        header.beneficiary = Address::repeat_byte(0x99); // actual miner (not used for fee routing)

        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(remasc_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            block_store.clone(),
        ).with_remasc_config(remasc_config);

        executor
            .execute_block(&header, &[(remasc_tx, sender)], &root, trie_store)
            .unwrap()
    }

    /// Before maturity is reached, no distribution should happen.
    /// Matches rskj's `processMinersFeesWithoutRequiredMaturity`.
    #[test]
    fn remasc_no_distribution_before_maturity() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest(); // maturity=10
        let paid_fees = U256::from(21_000);

        // Chain: block 5 has paid_fees=21000, blocks 0..12 exist
        let (bs, _) = build_chain_store(12, miner, &[(5, paid_fees)]);

        // Execute REMASC at block 12 (only 7 blocks since fee block → maturity not reached)
        let result = execute_remasc_at(&bs, 12, U256::from(10u64).pow(U256::from(18)), config);
        assert!(result.tx_results[0].success);

        // Miner should not have received anything
        assert!(
            result.state_changes.get(&miner).is_none(),
            "miner should not be paid before maturity"
        );
    }

    /// After maturity but before syntheticSpan, fees accrue but no payout.
    /// Matches rskj's `processMinersFeesWithoutMinimumSyntheticSpan`.
    #[test]
    fn remasc_fees_accrue_before_synthetic_span() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest(); // maturity=10, syntheticSpan=5
        let paid_fees = U256::from(21_000);

        // Block 3 has paid_fees=21000. Execute REMASC at block 13 (candidateBlock=3, < syntheticSpan=5)
        let (bs, _) = build_chain_store(14, miner, &[(3, paid_fees)]);

        let result = execute_remasc_at(&bs, 13, U256::from(10u64).pow(U256::from(18)), config);
        assert!(result.tx_results[0].success);

        // REMASC storage should have rewardBalance = 21000
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let remasc_state = result.state_changes.get(&remasc_addr);
        assert!(remasc_state.is_some(), "REMASC account should exist in state changes");

        // Check storage: rewardBalance key
        let reward_key = crate::remasc::remasc_storage_key(crate::remasc::REWARD_BALANCE_KEY);
        let reward_slot = remasc_state.unwrap().storage.get(&reward_key);
        assert!(reward_slot.is_some(), "rewardBalance should be set in storage");
        assert_eq!(
            reward_slot.unwrap().present_value,
            paid_fees,
            "rewardBalance should equal the processing block's paid_fees"
        );

        // Miner should NOT be paid (syntheticSpan not reached)
        assert!(
            result.state_changes.get(&miner).is_none(),
            "miner should not be paid before syntheticSpan"
        );
    }

    /// Full distribution with no siblings. Matches rskj's `processMinersFeesWithNoSiblings`.
    ///
    /// regtest: maturity=10, syntheticSpan=5, rskLabsDivisor=5, federationDivisor=100
    /// minerFee=21000 at block 5. Execute REMASC at block 16.
    ///   candidateBlock = 16 - 10 = 6 → but we use block 5 for fees
    ///   Actually: we need candidateBlock = 5, so execution at block 15.
    ///   15 - 10 = 5 ≥ 1 ✓, 5 - 5 = 0 ≥ 0 ✓
    ///
    /// Expected math:
    ///   rewardBalance = 0 + 21000 = 21000
    ///   syntheticReward = 21000 / 5 = 4200
    ///   rewardBalance = 21000 - 4200 = 16800
    ///   rskLabsPay = 4200 / 5 = 840
    ///   remaining = 4200 - 840 = 3360
    ///   federationReward = 3360 / 100 = 33
    ///   remaining = 3360 - 33 = 3327
    ///   miner gets 3327
    #[test]
    fn remasc_basic_distribution_no_siblings() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest();
        let rsk_labs = config.rsk_labs_address;
        let paid_fees = U256::from(21_000);

        // 16 blocks (0..15). Block 5 has paid_fees=21000.
        let (bs, _) = build_chain_store(16, miner, &[(5, paid_fees)]);

        // REMASC has 21000 balance from the fees accumulated when block 5 was executed
        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees,
        );
        assert!(result.tx_results[0].success);

        let remasc_addr = crate::precompiles::REMASC_ADDR;

        // RSK Labs should receive 840
        let labs_state = result.state_changes.get(&rsk_labs)
            .expect("RSK Labs should appear in state changes");
        assert_eq!(
            labs_state.info.balance,
            U256::from(840),
            "RSK Labs receives syntheticReward / rskLabsDivisor = 4200 / 5 = 840"
        );

        // Miner should receive 3327
        let miner_state = result.state_changes.get(&miner)
            .expect("miner should appear in state changes");
        assert_eq!(
            miner_state.info.balance,
            U256::from(3327),
            "miner receives remainder: 4200 - 840 - 33 = 3327"
        );

        // REMASC storage: rewardBalance = 16800
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let reward_key = crate::remasc::remasc_storage_key(crate::remasc::REWARD_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&reward_key).unwrap().present_value,
            U256::from(16_800),
            "rewardBalance = 21000 - 4200 = 16800"
        );

        // Pre-RSKIP85 the federation cut (3360/100 = 33) is paid out to the
        // 15 genesis federators every block, never accrued: the
        // federationBalance cell stays untouched. (The accrual-below-minimum
        // path is groundtruthed by the mainnet #4010 test.)
        let fed_key = crate::remasc::remasc_storage_key(crate::remasc::FEDERATION_BALANCE_KEY);
        let fed_slot = remasc_state.storage.get(&fed_key);
        assert!(
            fed_slot.is_none() || fed_slot.unwrap().present_value.is_zero(),
            "federation cut paid out pre-RSKIP85, not accrued"
        );

        // REMASC storage: burnedBalance = 0
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        let burned_slot = remasc_state.storage.get(&burned_key);
        let burned = burned_slot.map(|s| s.present_value).unwrap_or(U256::ZERO);
        assert_eq!(burned, U256::ZERO, "no burns without broken selection rule");
    }

    /// Distribution with previous broken selection rule should apply punishment burn.
    ///
    /// We pre-seed the brokenSelectionRule storage flag to true, then verify
    /// that `punishment = remaining / punishmentDivisor` is burned.
    ///
    /// With regtest config and 21000 fees:
    ///   remaining (after labs + federation) = 3327
    ///   punishment = 3327 / 10 = 332
    ///   miner gets 3327 - 332 = 2995
    ///   burnedBalance = 332
    #[test]
    fn remasc_distribution_with_broken_selection_punishment() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(21_000);

        let (bs, _) = build_chain_store(16, miner, &[(5, paid_fees)]);

        let trie_store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();

        let sender = Address::repeat_byte(0xAA);
        let one_rbtc = U256::from(10u64).pow(U256::from(18));
        let root = put_account(&root, trie_store.as_ref(), &sender, 0, one_rbtc);

        // Pre-seed brokenSelectionRule = true in REMASC's storage
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let broken_key = crate::remasc::remasc_storage_key(crate::remasc::BROKEN_SELECTION_RULE_KEY);
        let root = {
            use rustock_trie::TrieKeySlice;
            let slot = B256::from(broken_key);
            let storage_key_bytes = rustock_trie::storage_key(&remasc_addr, &slot);
            let key = TrieKeySlice::from_key(&storage_key_bytes);
            let value = U256::from(1);
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&value.to_be_bytes::<32>());
            root.put(&key, &buf, trie_store.as_ref())
        };

        // Pre-seed REMASC with accumulated fees balance (21000 from block 5)
        let root = put_account(&root, trie_store.as_ref(), &remasc_addr, 0, paid_fees);

        let mut header = dummy_header(15);
        header.beneficiary = Address::repeat_byte(0x99);

        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(remasc_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            bs.clone(),
        ).with_remasc_config(config);

        let result = executor
            .execute_block(&header, &[(remasc_tx, sender)], &root, trie_store)
            .unwrap();

        assert!(result.tx_results[0].success);

        // Miner receives 3327 - 332 = 2995
        let miner_state = result.state_changes.get(&miner)
            .expect("miner should appear in state changes");
        assert_eq!(
            miner_state.info.balance,
            U256::from(2995),
            "miner receives 3327 - punishment(332) = 2995"
        );

        // burnedBalance = 332
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&burned_key).unwrap().present_value,
            U256::from(332),
            "burnedBalance = 3327 / 10 = 332"
        );
    }

    // -----------------------------------------------------------------------
    // Stage 6c tests – siblings / uncles
    // -----------------------------------------------------------------------

    struct ChainBlock {
        miner: Address,
        paid_fees: U256,
        uncle_count: u64,
        ommers: Vec<rustock_core::Header>,
    }

    fn build_chain_store_ext(blocks: &[ChainBlock]) -> Arc<BlockStore> {
        let dir = tempfile::tempdir().unwrap();
        let bs = Arc::new(BlockStore::open(dir.path()).unwrap());

        let mut parent_hash = B256::ZERO;

        for (i, cb) in blocks.iter().enumerate() {
            let mut h = dummy_header(i as u64);
            h.beneficiary = cb.miner;
            h.parent_hash = parent_hash;
            h.paid_fees = cb.paid_fees;
            h.uncle_count = cb.uncle_count;

            let hash = h.hash();
            bs.put_header_with_hash(hash, &h).unwrap();
            bs.put_canonical_hash(i as u64, hash).unwrap();

            if !cb.ommers.is_empty() {
                bs.put_body(hash, &[], &cb.ommers).unwrap();
            }

            parent_hash = hash;
        }

        bs
    }

    fn simple_block(miner: Address) -> ChainBlock {
        ChainBlock { miner, paid_fees: U256::ZERO, uncle_count: 0, ommers: vec![] }
    }

    fn make_uncle(number: u64, coinbase: Address, paid_fees: U256, uncle_count: u64) -> rustock_core::Header {
        let mut h = dummy_header(number);
        h.beneficiary = coinbase;
        h.paid_fees = paid_fees;
        h.uncle_count = uncle_count;
        // Give it a distinct extra_data so its hash differs from the canonical block
        h.extra_data = Bytes::copy_from_slice(coinbase.as_slice());
        h
    }

    /// Port of rskj's `processMinersFeesWithOneSibling`.
    ///
    /// Chain (regtest: maturity=10, syntheticSpan=5):
    ///   blocks 0-4: simple
    ///   block 5: coinbaseA, paid_fees=21000
    ///   block 5' (uncle): coinbaseB, paid_fees=31500
    ///   block 6: coinbaseC, includes uncle 5'
    ///   blocks 7-14: simple
    ///   block 15: REMASC executes
    ///
    /// Expected (fullBlockReward = 3327, 1 sibling, previousBroken=false):
    ///   publishersReward = 3327/10 = 332 → coinbaseC
    ///   minersReward = 3327 - 332 = 2995
    ///   individualMiner = 2995/2 = 1497
    ///   minersSurplus = 2995%2 = 1 → burned
    ///   coinbaseA (main miner): 1497
    ///   coinbaseB (sibling miner): 1497 (late=0)
    ///   burnedBalance = 1
    #[test]
    fn remasc_with_one_sibling() {
        let coinbase_a = Address::repeat_byte(0x11); // main miner
        let coinbase_b = Address::repeat_byte(0x22); // sibling miner
        let coinbase_c = Address::repeat_byte(0x33); // uncle includer (publisher)
        let default_miner = Address::repeat_byte(0x01);
        let config = crate::remasc::RemascConfig::regtest();
        let rsk_labs = config.rsk_labs_address;
        let paid_fees = U256::from(21_000u64);

        let uncle = make_uncle(5, coinbase_b, U256::from(31_500u64), 0);

        let mut chain: Vec<ChainBlock> = Vec::new();
        // Blocks 0-4: simple
        for _ in 0..5 {
            chain.push(simple_block(default_miner));
        }
        // Block 5: coinbaseA, paid_fees=21000
        chain.push(ChainBlock {
            miner: coinbase_a,
            paid_fees,
            uncle_count: 0,
            ommers: vec![],
        });
        // Block 6: coinbaseC, includes uncle (block 5')
        chain.push(ChainBlock {
            miner: coinbase_c,
            paid_fees: U256::ZERO,
            uncle_count: 0,
            ommers: vec![uncle],
        });
        // Blocks 7-14: simple
        for _ in 0..8 {
            chain.push(simple_block(default_miner));
        }

        let bs = build_chain_store_ext(&chain);

        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees, // REMASC balance = accumulated fees
        );
        assert!(result.tx_results[0].success);

        let remasc_addr = crate::precompiles::REMASC_ADDR;

        // RSK Labs: 840
        let labs_state = result.state_changes.get(&rsk_labs)
            .expect("RSK Labs should appear");
        assert_eq!(labs_state.info.balance, U256::from(840));

        // Publisher (coinbaseC): 332
        let pub_state = result.state_changes.get(&coinbase_c)
            .expect("publisher should appear");
        assert_eq!(pub_state.info.balance, U256::from(332),
            "publisher gets publishersReward / siblings = 332");

        // Main miner (coinbaseA): 1497
        let miner_a = result.state_changes.get(&coinbase_a)
            .expect("main miner should appear");
        assert_eq!(miner_a.info.balance, U256::from(1497),
            "main miner gets individualMinerReward = 2995/2 = 1497");

        // Sibling miner (coinbaseB): 1497 (no late penalty, included 1 block after)
        let miner_b = result.state_changes.get(&coinbase_b)
            .expect("sibling miner should appear");
        assert_eq!(miner_b.info.balance, U256::from(1497),
            "sibling miner gets 1497 (0 blocks late)");

        // Storage checks
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();

        // rewardBalance = 21000 - 4200 = 16800
        let reward_key = crate::remasc::remasc_storage_key(crate::remasc::REWARD_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&reward_key).unwrap().present_value,
            U256::from(16_800),
        );

        // burnedBalance = minersSurplus = 1
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&burned_key).unwrap().present_value,
            U256::from(1),
            "burned = minersSurplus = 2995 % 2 = 1"
        );

        // Pre-RSKIP85: the federation cut is paid out, not accrued.
        let fed_key = crate::remasc::remasc_storage_key(crate::remasc::FEDERATION_BALANCE_KEY);
        let fed_slot = remasc_state.storage.get(&fed_key);
        assert!(fed_slot.is_none() || fed_slot.unwrap().present_value.is_zero());
    }

    /// Test late uncle inclusion penalty.
    ///
    /// Same as one-sibling test but uncle is included 3 blocks later (block 8 instead of 6).
    /// blocks_late = 8 - 5 - 1 = 2
    /// late_punishment = 1497 * 2 / 20 = 149
    /// sibling miner gets 1497 - 149 = 1348
    /// burned = minersSurplus(1) + late_punishment(149) = 150
    #[test]
    fn remasc_late_uncle_inclusion_penalty() {
        let coinbase_a = Address::repeat_byte(0x11);
        let coinbase_b = Address::repeat_byte(0x22);
        let coinbase_c = Address::repeat_byte(0x33);
        let default_miner = Address::repeat_byte(0x01);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(21_000u64);

        let uncle = make_uncle(5, coinbase_b, U256::from(31_500u64), 0);

        let mut chain: Vec<ChainBlock> = Vec::new();
        for _ in 0..5 { chain.push(simple_block(default_miner)); }
        // Block 5: main block
        chain.push(ChainBlock {
            miner: coinbase_a, paid_fees, uncle_count: 0, ommers: vec![],
        });
        // Blocks 6-7: simple
        for _ in 0..2 { chain.push(simple_block(default_miner)); }
        // Block 8: includes uncle (3 blocks after block 5)
        chain.push(ChainBlock {
            miner: coinbase_c, paid_fees: U256::ZERO, uncle_count: 0,
            ommers: vec![uncle],
        });
        // Blocks 9-14: simple
        for _ in 0..6 { chain.push(simple_block(default_miner)); }

        let bs = build_chain_store_ext(&chain);

        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees,
        );
        assert!(result.tx_results[0].success);

        // blocks_late = 8 - 5 - 1 = 2
        // late_punishment = 1497 * 2 / 20 = 149
        let miner_b = result.state_changes.get(&coinbase_b)
            .expect("sibling miner should appear");
        assert_eq!(miner_b.info.balance, U256::from(1497 - 149),
            "sibling miner gets 1497 - 149(late penalty) = 1348");

        // Main miner still gets full share
        let miner_a = result.state_changes.get(&coinbase_a)
            .expect("main miner should appear");
        assert_eq!(miner_a.info.balance, U256::from(1497));

        // burned = minersSurplus(1) + late_punishment(149) = 150
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&burned_key).unwrap().present_value,
            U256::from(150),
        );
    }

    /// Test broken selection rule with siblings.
    ///
    /// When previousBrokenSelectionRule=true and siblings exist:
    ///   punishment = individualMinerReward_base / punishmentDivisor
    ///   individualMinerReward = base - punishment
    ///   total_punishment_burn = punishment * (siblings + 1)
    ///
    /// With regtest (fullBlockReward=3327, 1 sibling):
    ///   base = 2995/2 = 1497
    ///   punishment = 1497/10 = 149
    ///   individualMinerReward = 1497 - 149 = 1348
    ///   total_punishment_burn = 149 * 2 = 298
    ///   burned = publishersSurplus(0) + minersSurplus(1) + 298 = 299
    #[test]
    fn remasc_sibling_with_previous_broken_selection() {
        let coinbase_a = Address::repeat_byte(0x11);
        let coinbase_b = Address::repeat_byte(0x22);
        let coinbase_c = Address::repeat_byte(0x33);
        let default_miner = Address::repeat_byte(0x01);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(21_000u64);

        let uncle = make_uncle(5, coinbase_b, U256::from(31_500u64), 0);

        let mut chain: Vec<ChainBlock> = Vec::new();
        for _ in 0..5 { chain.push(simple_block(default_miner)); }
        chain.push(ChainBlock {
            miner: coinbase_a, paid_fees, uncle_count: 0, ommers: vec![],
        });
        chain.push(ChainBlock {
            miner: coinbase_c, paid_fees: U256::ZERO, uncle_count: 0,
            ommers: vec![uncle],
        });
        for _ in 0..8 { chain.push(simple_block(default_miner)); }

        let bs = build_chain_store_ext(&chain);

        // Build state with brokenSelectionRule = true pre-seeded
        let trie_store = Arc::new(MemoryTrieStore::new());
        let root = TrieNode::empty();
        let sender = Address::repeat_byte(0xAA);
        let root = put_account(&root, trie_store.as_ref(), &sender, 0,
            U256::from(10u64).pow(U256::from(18)));
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let root = put_account(&root, trie_store.as_ref(), &remasc_addr, 0, paid_fees);

        // Pre-seed brokenSelectionRule = true
        let broken_key = crate::remasc::remasc_storage_key(crate::remasc::BROKEN_SELECTION_RULE_KEY);
        let root = {
            use rustock_trie::TrieKeySlice;
            let slot = B256::from(broken_key);
            let storage_key_bytes = rustock_trie::storage_key(&remasc_addr, &slot);
            let key = TrieKeySlice::from_key(&storage_key_bytes);
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&U256::from(1).to_be_bytes::<32>());
            root.put(&key, &buf, trie_store.as_ref())
        };

        let mut header = dummy_header(15);
        header.beneficiary = Address::repeat_byte(0x99);

        let remasc_tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(100_000),
            to: Bytes::copy_from_slice(remasc_addr.as_slice()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        let executor = RskExecutor::new(
            RskHardforkConfig::all_active(33),
            bs.clone(),
        ).with_remasc_config(config);

        let result = executor
            .execute_block(&header, &[(remasc_tx, sender)], &root, trie_store)
            .unwrap();
        assert!(result.tx_results[0].success);

        // Both miners get 1348 (1497 - 149 punishment)
        let miner_a = result.state_changes.get(&coinbase_a)
            .expect("main miner");
        assert_eq!(miner_a.info.balance, U256::from(1348),
            "miner gets 1497 - 149(punishment) = 1348");

        let miner_b = result.state_changes.get(&coinbase_b)
            .expect("sibling miner");
        assert_eq!(miner_b.info.balance, U256::from(1348),
            "sibling miner also punished: 1348");

        // burned = minersSurplus(1) + total_punishment(149*2=298) = 299
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let burned_key = crate::remasc::remasc_storage_key(crate::remasc::BURNED_BALANCE_KEY);
        assert_eq!(
            remasc_state.storage.get(&burned_key).unwrap().present_value,
            U256::from(299),
        );
    }

    /// Test that brokenSelectionRule flag is set when a sibling has > 2x fees.
    #[test]
    fn remasc_broken_selection_rule_higher_fees() {
        let coinbase_a = Address::repeat_byte(0x11);
        let coinbase_b = Address::repeat_byte(0x22);
        let coinbase_c = Address::repeat_byte(0x33);
        let default_miner = Address::repeat_byte(0x01);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(10_000u64);

        // Uncle paid > 2x processing block's fees → broken selection rule
        let uncle = make_uncle(5, coinbase_b, U256::from(25_000u64), 0);

        let mut chain: Vec<ChainBlock> = Vec::new();
        for _ in 0..5 { chain.push(simple_block(default_miner)); }
        chain.push(ChainBlock {
            miner: coinbase_a, paid_fees, uncle_count: 0, ommers: vec![],
        });
        chain.push(ChainBlock {
            miner: coinbase_c, paid_fees: U256::ZERO, uncle_count: 0,
            ommers: vec![uncle],
        });
        for _ in 0..8 { chain.push(simple_block(default_miner)); }

        let bs = build_chain_store_ext(&chain);

        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees,
        );
        assert!(result.tx_results[0].success);

        // brokenSelectionRule should be set to true
        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let broken_key = crate::remasc::remasc_storage_key(crate::remasc::BROKEN_SELECTION_RULE_KEY);
        assert_eq!(
            remasc_state.storage.get(&broken_key).unwrap().present_value,
            U256::from(1),
            "brokenSelectionRule should be true when sibling fees > 2x"
        );
    }

    /// Test no siblings → brokenSelectionRule stays false.
    #[test]
    fn remasc_no_siblings_selection_rule_false() {
        let miner = Address::repeat_byte(0x11);
        let config = crate::remasc::RemascConfig::regtest();
        let paid_fees = U256::from(21_000);

        let (bs, _) = build_chain_store(16, miner, &[(5, paid_fees)]);

        let result = execute_remasc_at_with_balance(
            &bs, 15,
            U256::from(10u64).pow(U256::from(18)),
            config,
            paid_fees,
        );
        assert!(result.tx_results[0].success);

        let remasc_addr = crate::precompiles::REMASC_ADDR;
        let remasc_state = result.state_changes.get(&remasc_addr).unwrap();
        let broken_key = crate::remasc::remasc_storage_key(crate::remasc::BROKEN_SELECTION_RULE_KEY);
        let broken = remasc_state.storage.get(&broken_key)
            .map(|s| s.present_value)
            .unwrap_or(U256::ZERO);
        assert_eq!(broken, U256::ZERO, "no siblings → brokenSelectionRule = false");
    }
}
