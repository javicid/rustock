use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use rustock_core::config::ChainConfig;
use rustock_execution::RskHardforkConfig;
use rustock_networking::peers::PeerStore;
use rustock_storage::BlockStore;
use rustock_trie::TrieStore;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::types::*;
use crate::{call, eth, logs, net, rsk, state, tx, web3};

/// Trait for submitting raw transactions, allowing the RPC layer to use
/// the P2P relay without depending on the sync crate directly.
#[async_trait::async_trait]
pub trait TxSubmitter: Send + Sync {
    async fn submit_transaction(&self, raw_tx: alloy_primitives::Bytes) -> Result<alloy_primitives::B256, String>;
}

/// Trait for reading from the transaction pool without depending on the sync crate.
pub trait TxPoolReader: Send + Sync {
    fn get_pending_tx(&self, hash: &alloy_primitives::B256) -> Option<(rustock_core::Transaction, alloy_primitives::Address, alloy_primitives::B256)>;
    fn pending_nonce(&self, addr: &alloy_primitives::Address) -> Option<u64>;
    fn pool_status(&self) -> (usize, usize);
}

/// Shared application state available to every RPC handler.
#[derive(Clone)]
pub struct RpcState {
    pub store: Arc<BlockStore>,
    pub peer_store: Arc<PeerStore>,
    pub config: Arc<ChainConfig>,
    pub tx_submitter: Option<Arc<dyn TxSubmitter>>,
    pub trie_store: Option<Arc<dyn TrieStore>>,
    pub hardfork_cfg: Option<RskHardforkConfig>,
    pub filter_store: Arc<logs::FilterStore>,
    pub tx_pool: Option<Arc<dyn TxPoolReader>>,
}

/// Starts the JSON-RPC HTTP server on the given host and port.
pub async fn start_rpc_server(
    host: &str,
    port: u16,
    state: RpcState,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", post(handle_rpc))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    info!("RPC server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_rpc(
    State(state): State<RpcState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim(),
        Err(_) => {
            let resp = JsonRpcResponse::error(Value::Null, PARSE_ERROR, "Invalid UTF-8");
            return (StatusCode::OK, Json(json!(resp)));
        }
    };

    if body_str.starts_with('[') {
        let requests: Vec<JsonRpcRequest> = match serde_json::from_str(body_str) {
            Ok(r) => r,
            Err(_) => {
                let resp = JsonRpcResponse::error(Value::Null, PARSE_ERROR, "Parse error");
                return (StatusCode::OK, Json(json!(resp)));
            }
        };

        if requests.is_empty() {
            let resp = JsonRpcResponse::error(Value::Null, INVALID_REQUEST, "Empty batch");
            return (StatusCode::OK, Json(json!(resp)));
        }

        let mut responses = Vec::with_capacity(requests.len());
        for req in requests {
            responses.push(dispatch(&state, req).await);
        }
        (StatusCode::OK, Json(json!(responses)))
    } else {
        let request: JsonRpcRequest = match serde_json::from_str(body_str) {
            Ok(r) => r,
            Err(_) => {
                let resp = JsonRpcResponse::error(Value::Null, PARSE_ERROR, "Parse error");
                return (StatusCode::OK, Json(json!(resp)));
            }
        };
        let response = dispatch(&state, request).await;
        (StatusCode::OK, Json(json!(response)))
    }
}

async fn dispatch(state: &RpcState, req: JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.unwrap_or(Value::Null);
    let params = &req.params;

    match req.method.as_str() {
        // -- web3 --
        "web3_clientVersion" => web3::web3_client_version(id),
        "web3_sha3" => web3::web3_sha3(id, params),

        // -- net --
        "net_version" => net::net_version(id, &state.config),
        "net_peerCount" => net::net_peer_count(id, &state.peer_store).await,
        "net_listening" => net::net_listening(id),
        "net_peerList" => net::net_peer_list(id, &state.peer_store).await,

        // -- eth --
        "eth_protocolVersion" => eth::eth_protocol_version(id),
        "eth_syncing" => eth::eth_syncing(id, &state.store, &state.peer_store).await,
        "eth_chainId" => eth::eth_chain_id(id, &state.config),
        "eth_blockNumber" => eth::eth_block_number(id, &state.store),
        "eth_gasPrice" => eth::eth_gas_price(id, &state.store),
        "eth_mining" => eth::eth_mining(id),
        "eth_hashrate" => eth::eth_hashrate(id),
        "eth_accounts" => eth::eth_accounts(id),
        "eth_coinbase" => eth::eth_coinbase(id),
        "eth_getBlockByHash" => eth::eth_get_block_by_hash(id, params, &state.store),
        "eth_getBlockByNumber" => eth::eth_get_block_by_number(id, params, &state.store),
        "eth_getBlockTransactionCountByHash" => eth::eth_get_block_transaction_count_by_hash(id, params, &state.store),
        "eth_getBlockTransactionCountByNumber" => eth::eth_get_block_transaction_count_by_number(id, params, &state.store),
        "eth_getUncleCountByBlockHash" => eth::eth_get_uncle_count_by_block_hash(id, params, &state.store),
        "eth_getUncleCountByBlockNumber" => eth::eth_get_uncle_count_by_block_number(id, params, &state.store),

        // -- rpc --
        "rpc_modules" => {
            JsonRpcResponse::success(
                id,
                json!({"eth": "1.0", "net": "1.0", "web3": "1.0", "rpc": "1.0", "rsk": "1.0"}),
            )
        }

        // -- rsk --
        "rsk_protocolVersion" => rsk::rsk_protocol_version(id),
        "rsk_getRawBlockHeaderByHash" => rsk::rsk_get_raw_block_header_by_hash(id, params, &state.store),
        "rsk_getRawBlockHeaderByNumber" => rsk::rsk_get_raw_block_header_by_number(id, params, &state.store),

        "eth_sendRawTransaction" => eth::eth_send_raw_transaction(id, params, &state.tx_submitter).await,

        // -- state queries --
        "eth_getBalance" => state::eth_get_balance(id, params, state),
        "eth_getTransactionCount" => state::eth_get_transaction_count(id, params, state),
        "eth_getCode" => state::eth_get_code(id, params, state),
        "eth_getStorageAt" => state::eth_get_storage_at(id, params, state),

        // -- execution calls --
        "eth_call" => call::eth_call(id, params, state),
        "eth_estimateGas" => call::eth_estimate_gas(id, params, state),

        // -- transaction and receipt lookup --
        "eth_getTransactionByHash" => tx::eth_get_transaction_by_hash(id, params, state),
        "eth_getTransactionByBlockHashAndIndex" => tx::eth_get_transaction_by_block_hash_and_index(id, params, state),
        "eth_getTransactionByBlockNumberAndIndex" => tx::eth_get_transaction_by_block_number_and_index(id, params, state),
        "eth_getTransactionReceipt" => tx::eth_get_transaction_receipt(id, params, state),

        // -- log filtering --
        "eth_getLogs" => logs::eth_get_logs(id, params, state),
        "eth_newFilter" => logs::eth_new_filter(id, params, state),
        "eth_newBlockFilter" => logs::eth_new_block_filter(id, state),
        "eth_newPendingTransactionFilter" => logs::eth_new_pending_transaction_filter(id),
        "eth_getFilterChanges" => logs::eth_get_filter_changes(id, params, state),
        "eth_getFilterLogs" => logs::eth_get_filter_logs(id, params, state),
        "eth_uninstallFilter" => logs::eth_uninstall_filter(id, params, state),

        // -- unsupported methods --
        "eth_sendTransaction"
        | "eth_getCompilers"
        | "eth_compileSolidity"
        | "eth_sign"
        | "eth_signTransaction" => {
            execution_not_available(id, &req.method)
        }

        "txpool_status" => {
            if let Some(pool) = &state.tx_pool {
                let (pending, queued) = pool.pool_status();
                JsonRpcResponse::success(id, json!({
                    "pending": format!("0x{:x}", pending),
                    "queued": format!("0x{:x}", queued),
                }))
            } else {
                execution_not_available(id, "txpool_status")
            }
        }

        m if m.starts_with("debug_")
            || m.starts_with("trace_")
            || m.starts_with("personal_")
            || m.starts_with("evm_")
            || m.starts_with("txpool_")
            || m.starts_with("mnr_")
            || m.starts_with("db_")
            || m.starts_with("sco_") => {
            execution_not_available(id, m)
        }

        _ => JsonRpcResponse::error(id, METHOD_NOT_FOUND, "Method not found"),
    }
}

fn execution_not_available(id: Value, method: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        METHOD_NOT_FOUND,
        format!("Method {} requires execution engine (not yet available)", method),
    )
}

#[cfg(test)]
pub(crate) async fn dispatch_for_test(state: &RpcState, req: JsonRpcRequest) -> JsonRpcResponse {
    dispatch(state, req).await
}
