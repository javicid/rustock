use crate::helpers::to_hex_u64;
use crate::types::JsonRpcResponse;
use rustock_core::config::ChainConfig;
use rustock_networking::peers::PeerStore;
use serde_json::{json, Value};

pub fn net_version(id: Value, config: &ChainConfig) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!(config.network_id.to_string()))
}

pub async fn net_peer_count(id: Value, peer_store: &PeerStore) -> JsonRpcResponse {
    let count = peer_store.count().await;
    JsonRpcResponse::success(id, json!(to_hex_u64(count as u64)))
}

pub fn net_listening(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!(true))
}

pub async fn net_peer_list(id: Value, peer_store: &PeerStore) -> JsonRpcResponse {
    let peers = peer_store.peers().await;
    let list: Vec<String> = peers.iter().map(|p| format!("{:#x}", p)).collect();
    JsonRpcResponse::success(id, json!(list))
}
