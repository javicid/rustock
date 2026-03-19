use crate::server::{dispatch_for_test, RpcState};
use crate::types::*;
use alloy_primitives::{Address, Bloom, B256, U256, Bytes};
use rustock_core::config::ChainConfig;
use rustock_core::types::header::Header;
use rustock_networking::peers::PeerStore;
use rustock_storage::BlockStore;
use serde_json::{json, Value};
use std::sync::Arc;

fn test_header(number: u64) -> Header {
    Header {
        parent_hash: B256::ZERO,
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Bloom::ZERO,
        extension_data: None,
        difficulty: U256::from(1000),
        number,
        gas_limit: U256::from(8_000_000),
        gas_used: 21000,
        timestamp: 1_600_000_000 + number,
        extra_data: Bytes::new(),
        paid_fees: U256::ZERO,
        minimum_gas_price: U256::from(59_240_000),
        uncle_count: 0,
        umm_root: None,
        bitcoin_merged_mining_header: None,
        bitcoin_merged_mining_merkle_proof: None,
        bitcoin_merged_mining_coinbase_transaction: None,
        cached_hash: None,
        cached_hash_for_merged_mining: None,
    }
}

fn setup_state() -> (RpcState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let header = test_header(42);
    store.update_head(&header, U256::from(42_000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
    };
    (state, tmp)
}

fn make_request(method: &str, params: Value) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        method: method.to_string(),
        params,
        id: Some(json!(1)),
    }
}

// ========== web3 ==========

#[tokio::test]
async fn test_web3_client_version() {
    let (state, _tmp) = setup_state();
    let req = make_request("web3_clientVersion", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("Rustock/0.1.0"));
}

#[tokio::test]
async fn test_web3_sha3() {
    let (state, _tmp) = setup_state();
    let req = make_request("web3_sha3", json!(["0x68656c6c6f"]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    let hash = result.as_str().unwrap();
    assert!(hash.starts_with("0x"));
    assert_eq!(hash.len(), 66);
}

#[tokio::test]
async fn test_web3_sha3_invalid_hex() {
    let (state, _tmp) = setup_state();
    let req = make_request("web3_sha3", json!(["not_hex"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
}

// ========== net ==========

#[tokio::test]
async fn test_net_version() {
    let (state, _tmp) = setup_state();
    let req = make_request("net_version", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    let version = resp.result.unwrap();
    assert_eq!(version, json!(ChainConfig::mainnet().network_id.to_string()));
}

#[tokio::test]
async fn test_net_listening() {
    let (state, _tmp) = setup_state();
    let req = make_request("net_listening", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!(true));
}

#[tokio::test]
async fn test_net_peer_count() {
    let (state, _tmp) = setup_state();
    let req = make_request("net_peerCount", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

#[tokio::test]
async fn test_net_peer_list_empty() {
    let (state, _tmp) = setup_state();
    let req = make_request("net_peerList", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!([]));
}

// ========== eth ==========

#[tokio::test]
async fn test_eth_protocol_version() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_protocolVersion", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x3e"));
}

#[tokio::test]
async fn test_eth_chain_id() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_chainId", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x1e"));
}

#[tokio::test]
async fn test_eth_block_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_blockNumber", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x2a"));
}

#[tokio::test]
async fn test_eth_syncing_not_syncing() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_syncing", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!(false));
}

#[tokio::test]
async fn test_eth_gas_price() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_gasPrice", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert!(result.as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn test_eth_mining() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_mining", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!(false));
}

#[tokio::test]
async fn test_eth_accounts() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_accounts", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!([]));
}

#[tokio::test]
async fn test_eth_get_block_by_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["0x2a", false]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["number"], json!("0x2a"));
    assert_eq!(result["gasUsed"], json!("0x5208"));
    assert!(result["hash"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn test_eth_get_block_by_number_latest() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["latest", false]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["number"], json!("0x2a"));
}

#[tokio::test]
async fn test_eth_get_block_by_number_not_found() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["0xfffff", false]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_block_by_hash() {
    let (state, _tmp) = setup_state();

    let head_hash = state.store.head().unwrap().unwrap();
    let hash_str = format!("{:#x}", head_hash);

    let req = make_request("eth_getBlockByHash", json!([hash_str, false]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["number"], json!("0x2a"));
}

#[tokio::test]
async fn test_eth_get_block_by_hash_not_found() {
    let (state, _tmp) = setup_state();
    let hash = format!("{:#x}", B256::repeat_byte(0xff));
    let req = make_request("eth_getBlockByHash", json!([hash, false]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_block_transaction_count_by_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockTransactionCountByNumber", json!(["0x2a"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_uncle_count_by_block_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getUncleCountByBlockNumber", json!(["0x2a"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

// ========== rpc ==========

#[tokio::test]
async fn test_rpc_modules() {
    let (state, _tmp) = setup_state();
    let req = make_request("rpc_modules", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    let modules = resp.result.unwrap();
    assert_eq!(modules["eth"], json!("1.0"));
    assert_eq!(modules["net"], json!("1.0"));
    assert_eq!(modules["web3"], json!("1.0"));
    assert_eq!(modules["rsk"], json!("1.0"));
}

// ========== rsk ==========

#[tokio::test]
async fn test_rsk_protocol_version() {
    let (state, _tmp) = setup_state();
    let req = make_request("rsk_protocolVersion", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x1"));
}

#[tokio::test]
async fn test_rsk_get_raw_block_header_by_number() {
    let (state, _tmp) = setup_state();
    let req = make_request("rsk_getRawBlockHeaderByNumber", json!(["0x2a"]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    let rlp_hex = result.as_str().unwrap();
    assert!(rlp_hex.starts_with("0x"));
    assert!(rlp_hex.len() > 10);
}

#[tokio::test]
async fn test_rsk_get_raw_block_header_by_hash() {
    let (state, _tmp) = setup_state();
    let head_hash = state.store.head().unwrap().unwrap();
    let hash_str = format!("{:#x}", head_hash);
    let req = make_request("rsk_getRawBlockHeaderByHash", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert!(result.as_str().unwrap().starts_with("0x"));
}

// ========== dispatch / error handling ==========

#[tokio::test]
async fn test_method_not_found() {
    let (state, _tmp) = setup_state();
    let req = make_request("nonexistent_method", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
}

#[tokio::test]
async fn test_unsupported_eth_method() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_sendTransaction", json!(["0x1234", "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.code, METHOD_NOT_FOUND);
    assert!(err.message.contains("execution engine"));
}

#[tokio::test]
async fn test_unsupported_debug_method() {
    let (state, _tmp) = setup_state();
    let req = make_request("debug_traceTransaction", json!(["0x1234"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert!(err.message.contains("execution engine"));
}

#[tokio::test]
async fn test_unsupported_personal_method() {
    let (state, _tmp) = setup_state();
    let req = make_request("personal_unlockAccount", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
}

#[tokio::test]
async fn test_unsupported_txpool_method() {
    let (state, _tmp) = setup_state();
    let req = make_request("txpool_status", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some());
}

// ========== BlockResultDTO format ==========

#[tokio::test]
async fn test_block_dto_has_all_fields() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["0x2a", false]));
    let resp = dispatch_for_test(&state, req).await;
    let block = resp.result.unwrap();

    let required_fields = [
        "number", "hash", "parentHash", "sha3Uncles", "miner",
        "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom",
        "difficulty", "totalDifficulty", "gasLimit", "gasUsed",
        "timestamp", "extraData", "minimumGasPrice",
        "transactions", "uncles", "size",
    ];
    for field in &required_fields {
        assert!(block.get(field).is_some(), "Missing field: {}", field);
    }
}

#[tokio::test]
async fn test_block_dto_hex_encoding() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_getBlockByNumber", json!(["0x2a", false]));
    let resp = dispatch_for_test(&state, req).await;
    let block = resp.result.unwrap();

    let hex_fields = [
        "number", "hash", "parentHash", "sha3Uncles", "miner",
        "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom",
        "difficulty", "totalDifficulty", "gasLimit", "gasUsed",
        "timestamp", "extraData", "minimumGasPrice", "size",
    ];
    for field in &hex_fields {
        let val = block[field].as_str().unwrap_or("");
        assert!(val.starts_with("0x"), "Field {} should be hex: {}", field, val);
    }
}

// ========== batch requests (dispatch-level) ==========

#[tokio::test]
async fn test_batch_dispatch() {
    let (state, _tmp) = setup_state();

    let requests = vec![
        make_request("eth_blockNumber", json!([])),
        make_request("web3_clientVersion", json!([])),
        make_request("nonexistent_method", json!([])),
    ];

    let mut responses = Vec::new();
    for req in requests {
        responses.push(dispatch_for_test(&state, req).await);
    }

    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0].result.as_ref().unwrap(), &json!("0x2a"));
    assert_eq!(responses[1].result.as_ref().unwrap(), &json!("Rustock/0.1.0"));
    assert!(responses[2].error.is_some());
}

// ========== eth_sendRawTransaction ==========

#[tokio::test]
async fn test_eth_send_raw_transaction_no_submitter() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_sendRawTransaction", json!(["0xdeadbeef"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some(), "Should error when tx_submitter is None");
}

#[tokio::test]
async fn test_eth_send_raw_transaction_with_submitter() {
    use crate::server::TxSubmitter;
    use alloy_primitives::B256;
    use sha3::Digest;

    struct MockSubmitter;

    #[async_trait::async_trait]
    impl TxSubmitter for MockSubmitter {
        async fn submit_transaction(&self, raw_tx: alloy_primitives::Bytes) -> Result<B256, String> {
            Ok(B256::from_slice(&sha3::Keccak256::digest(&raw_tx)))
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let header = test_header(1);
    store.update_head(&header, U256::from(1000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: Some(Arc::new(MockSubmitter)),
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
    };

    let req = make_request("eth_sendRawTransaction", json!(["0xdeadbeef"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_none(), "Should succeed with a submitter");
    let result = resp.result.unwrap();
    let hash_str = result.as_str().unwrap();
    assert!(hash_str.starts_with("0x"));
    assert_eq!(hash_str.len(), 66);
}

#[tokio::test]
async fn test_eth_send_raw_transaction_invalid_hex() {
    use crate::server::TxSubmitter;
    use alloy_primitives::B256;

    struct MockSubmitter;

    #[async_trait::async_trait]
    impl TxSubmitter for MockSubmitter {
        async fn submit_transaction(&self, _raw_tx: alloy_primitives::Bytes) -> Result<B256, String> {
            Ok(B256::ZERO)
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());
    let header = test_header(1);
    store.update_head(&header, U256::from(1000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: Some(Arc::new(MockSubmitter)),
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
    };

    let req = make_request("eth_sendRawTransaction", json!(["0xZZZZ"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some(), "Should error on invalid hex");
}

// ========== Phase 6: State queries with trie ==========

fn setup_state_with_trie() -> (RpcState, tempfile::TempDir) {
    use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode, account_key, code_key, storage_key};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let trie_store = Arc::new(MemoryTrieStore::new());

    // Create accounts in the trie
    let mut root = TrieNode::empty();

    // Account with 10000 balance (0x2710) and nonce 1
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826".parse::<alloy_primitives::Address>().unwrap();
    let acct = rustock_trie::AccountState::new(U256::from(1), U256::from(10000));
    let key = account_key(&addr);
    root = root.put(&TrieKeySlice::from_key(&key), &acct.encode(), &*trie_store);

    // Code for the account: [0x01, 0x02, 0x03]
    let ckey = code_key(&addr);
    root = root.put(&TrieKeySlice::from_key(&ckey), &[0x01, 0x02, 0x03], &*trie_store);

    // Storage slot 0x01 with value 42
    let mut slot_bytes = [0u8; 32];
    slot_bytes[31] = 1;
    let slot = B256::from(slot_bytes);
    let skey = storage_key(&addr, &slot);
    root = root.put(&TrieKeySlice::from_key(&skey), &[42], &*trie_store);

    root.save(&*trie_store, true);
    let state_root = root.compute_hash(&*trie_store);

    // Store the root node by its hash
    let root_data = root.to_message(&*trie_store);
    rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

    let header = Header {
        state_root,
        ..test_header(42)
    };
    let hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(42, hash).unwrap();
    store.set_head(hash).unwrap();
    store.put_total_difficulty(hash, U256::from(42_000)).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: Some(trie_store),
        hardfork_cfg: Some(rustock_execution::RskHardforkConfig::mainnet()),
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
    };
    (state, tmp)
}

#[tokio::test]
async fn test_eth_get_balance_with_account() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let req = make_request("eth_getBalance", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x2710"));
}

#[tokio::test]
async fn test_eth_get_balance_missing_account() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0x0000000000000000000000000000000000000001";
    let req = make_request("eth_getBalance", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_transaction_count_with_account() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let req = make_request("eth_getTransactionCount", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x1"));
}

#[tokio::test]
async fn test_eth_get_transaction_count_missing() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0x0000000000000000000000000000000000000001";
    let req = make_request("eth_getTransactionCount", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_code_existing() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let req = make_request("eth_getCode", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x010203"));
}

#[tokio::test]
async fn test_eth_get_code_missing() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0x0000000000000000000000000000000000000001";
    let req = make_request("eth_getCode", json!([addr, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x"));
}

#[tokio::test]
async fn test_eth_get_storage_at_nonexistent_slot() {
    let (state, _tmp) = setup_state_with_trie();
    let addr = "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826";
    let slot = format!("{:#066x}", B256::ZERO);
    let req = make_request("eth_getStorageAt", json!([addr, slot, "latest"]));
    let resp = dispatch_for_test(&state, req).await;
    let expected = "0x0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(resp.result.unwrap(), json!(expected));
}

// ========== Phase 6: Transaction and Receipt Lookup ==========

fn setup_state_with_tx() -> (RpcState, tempfile::TempDir, B256) {
    use alloy_rlp::Encodable;
    use sha3::{Digest, Keccak256};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::from(20_000_000_000u64),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0x12; 20]),
        value: U256::from(1_000_000),
        input: alloy_primitives::Bytes::default(),
        v: 27,
        r: U256::from(100),
        s: U256::from(200),
    };

    let mut tx_buf = Vec::new();
    tx.encode(&mut tx_buf);
    let tx_hash = B256::from_slice(&Keccak256::digest(&tx_buf));

    let header = test_header(1);
    let block_hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(1, block_hash).unwrap();
    store.set_head(block_hash).unwrap();
    store.put_total_difficulty(block_hash, U256::from(1000)).unwrap();

    store.put_body(block_hash, &[tx.clone()], &[]).unwrap();
    store.put_tx_index(tx_hash, block_hash, 0).unwrap();

    let receipt = rustock_core::Receipt {
        post_tx_state: vec![0x01],
        cumulative_gas_used: 21_000,
        gas_used: 21_000,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        logs: vec![],
        status: true,
    };
    store.put_receipts(block_hash, &[receipt]).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
    };
    (state, tmp, tx_hash)
}

#[tokio::test]
async fn test_eth_get_transaction_by_hash() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionByHash", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["hash"], json!(hash_str));
    assert_eq!(result["nonce"], json!("0x0"));
    assert!(result["blockHash"].is_string());
    assert_eq!(result["blockNumber"], json!("0x1"));
    assert_eq!(result["transactionIndex"], json!("0x0"));
    assert_eq!(result["input"], json!("0x"));
    assert_eq!(result["type"], json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_transaction_by_hash_not_found() {
    let (state, _tmp, _) = setup_state_with_tx();
    let hash = format!("{:#x}", B256::repeat_byte(0xff));
    let req = make_request("eth_getTransactionByHash", json!([hash]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

#[tokio::test]
async fn test_eth_get_transaction_by_block_number_and_index() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let req = make_request("eth_getTransactionByBlockNumberAndIndex", json!(["0x1", "0x0"]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    let hash_str = format!("{:#x}", tx_hash);
    assert_eq!(result["hash"], json!(hash_str));
    assert_eq!(result["transactionIndex"], json!("0x0"));
}

#[tokio::test]
async fn test_eth_get_transaction_by_block_hash_and_index() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let block_hash = state.store.head().unwrap().unwrap();
    let block_hash_str = format!("{:#x}", block_hash);
    let req = make_request("eth_getTransactionByBlockHashAndIndex", json!([block_hash_str, "0x0"]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    let hash_str = format!("{:#x}", tx_hash);
    assert_eq!(result["hash"], json!(hash_str));
}

#[tokio::test]
async fn test_eth_get_transaction_receipt() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionReceipt", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["transactionHash"], json!(hash_str));
    assert_eq!(result["transactionIndex"], json!("0x0"));
    assert_eq!(result["blockNumber"], json!("0x1"));
    assert_eq!(result["status"], json!("0x1"));
    assert_eq!(result["gasUsed"], json!("0x5208"));
    assert_eq!(result["cumulativeGasUsed"], json!("0x5208"));
    assert_eq!(result["type"], json!("0x0"));
    assert!(result["contractAddress"].is_null());
}

#[tokio::test]
async fn test_eth_get_transaction_receipt_not_found() {
    let (state, _tmp, _) = setup_state_with_tx();
    let hash = format!("{:#x}", B256::repeat_byte(0xff));
    let req = make_request("eth_getTransactionReceipt", json!([hash]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), Value::Null);
}

// ========== Phase 6: Log filtering ==========

fn setup_state_with_logs() -> (RpcState, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let log_addr = "0x1111111111111111111111111111111111111111".parse::<alloy_primitives::Address>().unwrap();
    let topic1 = B256::repeat_byte(0xAA);

    for block_num in 1u64..=3 {
        let header = test_header(block_num);
        let hash = header.hash();
        store.put_header(&header).unwrap();
        store.put_canonical_hash(block_num, hash).unwrap();
        store.put_total_difficulty(hash, U256::from(block_num * 1000)).unwrap();

        store.put_body(hash, &[], &[]).unwrap();

        let receipt = rustock_core::Receipt {
            post_tx_state: vec![0x01],
            cumulative_gas_used: 21_000,
            gas_used: 21_000,
            logs_bloom: alloy_primitives::Bloom::ZERO,
            logs: vec![
                rustock_core::Log {
                    address: log_addr,
                    topics: vec![topic1],
                    data: vec![block_num as u8].into(),
                }
            ],
            status: true,
        };
        store.put_receipts(hash, &[receipt]).unwrap();

        if block_num == 3 {
            store.set_head(hash).unwrap();
        }
    }

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
    };
    (state, tmp)
}

#[tokio::test]
async fn test_eth_get_logs_by_range() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3"
    }]));
    let resp = dispatch_for_test(&state, req).await;
    let logs = resp.result.unwrap();
    let logs = logs.as_array().unwrap();
    assert_eq!(logs.len(), 3);
}

#[tokio::test]
async fn test_eth_get_logs_by_address() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
        "address": "0x1111111111111111111111111111111111111111"
    }]));
    let resp = dispatch_for_test(&state, req).await;
    let logs = resp.result.unwrap().as_array().unwrap().len();
    assert_eq!(logs, 3);

    // Different address should return nothing
    let req2 = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
        "address": "0x2222222222222222222222222222222222222222"
    }]));
    let resp2 = dispatch_for_test(&state, req2).await;
    assert_eq!(resp2.result.unwrap().as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_eth_get_logs_by_topic() {
    let (state, _tmp) = setup_state_with_logs();
    let topic = format!("{:#x}", B256::repeat_byte(0xAA));
    let req = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
        "topics": [topic]
    }]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap().as_array().unwrap().len(), 3);

    // Non-matching topic
    let wrong_topic = format!("{:#x}", B256::repeat_byte(0xBB));
    let req2 = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3",
        "topics": [wrong_topic]
    }]));
    let resp2 = dispatch_for_test(&state, req2).await;
    assert_eq!(resp2.result.unwrap().as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_eth_new_filter_and_get_changes() {
    let (state, _tmp) = setup_state_with_logs();
    // Create a filter
    let req = make_request("eth_newFilter", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x3"
    }]));
    let resp = dispatch_for_test(&state, req).await;
    let filter_id = resp.result.unwrap();
    assert!(filter_id.is_string());

    // Get changes — since we just created it with last_polled = head (3), no new blocks
    let req2 = make_request("eth_getFilterChanges", json!([filter_id]));
    let resp2 = dispatch_for_test(&state, req2).await;
    let changes = resp2.result.unwrap().as_array().unwrap().len();
    assert_eq!(changes, 0);
}

#[tokio::test]
async fn test_eth_new_block_filter() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_newBlockFilter", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.result.unwrap().is_string());
}

#[tokio::test]
async fn test_eth_uninstall_filter() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_newFilter", json!([{"fromBlock": "0x1"}]));
    let resp = dispatch_for_test(&state, req).await;
    let filter_id = resp.result.unwrap();

    let req2 = make_request("eth_uninstallFilter", json!([filter_id]));
    let resp2 = dispatch_for_test(&state, req2).await;
    assert_eq!(resp2.result.unwrap(), json!(true));

    // Second uninstall should return false
    let req3 = make_request("eth_uninstallFilter", json!([filter_id]));
    let resp3 = dispatch_for_test(&state, req3).await;
    assert_eq!(resp3.result.unwrap(), json!(false));
}

#[tokio::test]
async fn test_eth_new_pending_transaction_filter() {
    let (state, _tmp) = setup_state();
    let req = make_request("eth_newPendingTransactionFilter", json!([]));
    let resp = dispatch_for_test(&state, req).await;
    assert_eq!(resp.result.unwrap(), json!("0x0"));
}

// ========== Phase 6: DTO field name compatibility with rskj ==========

#[tokio::test]
async fn test_transaction_dto_fields_match_rskj() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionByHash", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();

    let required_fields = [
        "hash", "nonce", "blockHash", "blockNumber", "transactionIndex",
        "from", "to", "gas", "gasPrice", "value", "input", "v", "r", "s", "type",
    ];
    for field in &required_fields {
        assert!(result.get(field).is_some(), "Missing TransactionDTO field: {}", field);
    }

    // Verify hex formatting matches rskj conventions
    assert!(result["nonce"].as_str().unwrap().starts_with("0x"));
    assert!(result["gas"].as_str().unwrap().starts_with("0x"));
    assert!(result["gasPrice"].as_str().unwrap().starts_with("0x"));
    assert!(result["value"].as_str().unwrap().starts_with("0x"));
    assert_eq!(result["type"], json!("0x0"));
    // v should be formatted as 0x%02x
    let v_str = result["v"].as_str().unwrap();
    assert!(v_str.starts_with("0x"));
    assert_eq!(v_str, "0x1b"); // v=27 -> 0x1b
}

#[tokio::test]
async fn test_receipt_dto_fields_match_rskj() {
    let (state, _tmp, tx_hash) = setup_state_with_tx();
    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionReceipt", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();

    let required_fields = [
        "transactionHash", "transactionIndex", "blockHash", "blockNumber",
        "cumulativeGasUsed", "gasUsed", "contractAddress", "logs",
        "from", "to", "status", "logsBloom", "type",
    ];
    for field in &required_fields {
        assert!(result.get(field).is_some(), "Missing ReceiptDTO field: {}", field);
    }

    assert_eq!(result["type"], json!("0x0"));
    assert_eq!(result["status"], json!("0x1"));
}

#[tokio::test]
async fn test_receipt_dto_failed_status() {
    use alloy_rlp::Encodable;
    use sha3::{Digest, Keccak256};

    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(BlockStore::open(tmp.path()).unwrap());

    let tx = rustock_core::Transaction {
        nonce: 0,
        gas_price: U256::from(20_000_000_000u64),
        gas_limit: U256::from(21_000),
        to: alloy_primitives::Bytes::from(vec![0x12; 20]),
        value: U256::from(1_000_000),
        input: alloy_primitives::Bytes::default(),
        v: 27,
        r: U256::from(100),
        s: U256::from(200),
    };

    let mut tx_buf = Vec::new();
    tx.encode(&mut tx_buf);
    let tx_hash = B256::from_slice(&Keccak256::digest(&tx_buf));

    let header = test_header(1);
    let block_hash = header.hash();
    store.put_header(&header).unwrap();
    store.put_canonical_hash(1, block_hash).unwrap();
    store.set_head(block_hash).unwrap();
    store.put_total_difficulty(block_hash, U256::from(1000)).unwrap();
    store.put_body(block_hash, &[tx], &[]).unwrap();
    store.put_tx_index(tx_hash, block_hash, 0).unwrap();

    let receipt = rustock_core::Receipt {
        post_tx_state: vec![],
        cumulative_gas_used: 21_000,
        gas_used: 21_000,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        logs: vec![],
        status: false,
    };
    store.put_receipts(block_hash, &[receipt]).unwrap();

    let state = RpcState {
        store,
        peer_store: Arc::new(PeerStore::new()),
        config: Arc::new(ChainConfig::mainnet()),
        tx_submitter: None,
        trie_store: None,
        hardfork_cfg: None,
        filter_store: Arc::new(crate::logs::FilterStore::new()),
        tx_pool: None,
    };

    let hash_str = format!("{:#x}", tx_hash);
    let req = make_request("eth_getTransactionReceipt", json!([hash_str]));
    let resp = dispatch_for_test(&state, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["status"], json!("0x0"));
}

// ========== Phase 6: Log DTO field names ==========

#[tokio::test]
async fn test_log_dto_fields_match_rskj() {
    let (state, _tmp) = setup_state_with_logs();
    let req = make_request("eth_getLogs", json!([{
        "fromBlock": "0x1",
        "toBlock": "0x1"
    }]));
    let resp = dispatch_for_test(&state, req).await;
    let logs = resp.result.unwrap();
    let log = &logs.as_array().unwrap()[0];

    let required_fields = [
        "address", "topics", "data", "blockNumber", "blockHash",
        "transactionHash", "transactionIndex", "logIndex", "removed",
    ];
    for field in &required_fields {
        assert!(log.get(field).is_some(), "Missing LogDTO field: {}", field);
    }

    assert_eq!(log["removed"], json!(false));
    assert!(log["address"].as_str().unwrap().starts_with("0x"));
    assert!(log["blockNumber"].as_str().unwrap().starts_with("0x"));
    assert_eq!(log["logIndex"], json!("0x0"));
}
