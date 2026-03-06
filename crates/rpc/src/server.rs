use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use rustock_core::config::ChainConfig;
use rustock_networking::peers::PeerStore;
use rustock_storage::BlockStore;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::types::*;
use crate::{eth, net, rsk, web3};

/// Trait for submitting raw transactions, allowing the RPC layer to use
/// the P2P relay without depending on the sync crate directly.
#[async_trait::async_trait]
pub trait TxSubmitter: Send + Sync {
    async fn submit_transaction(&self, raw_tx: alloy_primitives::Bytes) -> alloy_primitives::B256;
}

/// Shared application state available to every RPC handler.
#[derive(Clone)]
pub struct RpcState {
    pub store: Arc<BlockStore>,
    pub peer_store: Arc<PeerStore>,
    pub config: Arc<ChainConfig>,
    pub tx_submitter: Option<Arc<dyn TxSubmitter>>,
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

        // -- unsupported methods (state, bodies, receipts, tx pool, etc.) --
        "eth_getBalance"
        | "eth_getStorageAt"
        | "eth_getCode"
        | "eth_getTransactionCount"
        | "eth_call"
        | "eth_estimateGas"
        | "eth_sendTransaction"
        | "eth_getTransactionByHash"
        | "eth_getTransactionByBlockHashAndIndex"
        | "eth_getTransactionByBlockNumberAndIndex"
        | "eth_getTransactionReceipt"
        | "eth_getLogs"
        | "eth_newFilter"
        | "eth_newBlockFilter"
        | "eth_newPendingTransactionFilter"
        | "eth_uninstallFilter"
        | "eth_getFilterChanges"
        | "eth_getFilterLogs"
        | "eth_getCompilers"
        | "eth_compileSolidity"
        | "eth_sign"
        | "eth_signTransaction" => {
            light_client_unsupported(id, &req.method)
        }

        m if m.starts_with("debug_")
            || m.starts_with("trace_")
            || m.starts_with("personal_")
            || m.starts_with("evm_")
            || m.starts_with("txpool_")
            || m.starts_with("mnr_")
            || m.starts_with("db_")
            || m.starts_with("sco_") => {
            light_client_unsupported(id, m)
        }

        _ => JsonRpcResponse::error(id, METHOD_NOT_FOUND, "Method not found"),
    }
}

fn light_client_unsupported(id: Value, method: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        METHOD_NOT_FOUND,
        format!("Method {} not available on light client", method),
    )
}

#[cfg(test)]
pub(crate) async fn dispatch_for_test(state: &RpcState, req: JsonRpcRequest) -> JsonRpcResponse {
    dispatch(state, req).await
}
