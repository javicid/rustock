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
    let req = make_request("eth_getBalance", json!(["0x1234", "latest"]));
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
        async fn submit_transaction(&self, raw_tx: alloy_primitives::Bytes) -> B256 {
            B256::from_slice(&sha3::Keccak256::digest(&raw_tx))
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
        async fn submit_transaction(&self, _raw_tx: alloy_primitives::Bytes) -> B256 {
            B256::ZERO
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
    };

    let req = make_request("eth_sendRawTransaction", json!(["0xZZZZ"]));
    let resp = dispatch_for_test(&state, req).await;
    assert!(resp.error.is_some(), "Should error on invalid hex");
}
