use crate::helpers::{
    parse_b256, parse_block_number, to_hex_u256, to_hex_u64, BlockResultDto,
};
use crate::types::*;
use rustock_core::config::ChainConfig;
use rustock_storage::BlockStore;
use serde_json::{json, Value};

pub fn eth_protocol_version(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!("0x3e"))
}

pub fn eth_chain_id(id: Value, config: &ChainConfig) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!(to_hex_u64(config.chain_id as u64)))
}

pub fn eth_block_number(id: Value, store: &BlockStore) -> JsonRpcResponse {
    match get_head_number(store) {
        Some(n) => JsonRpcResponse::success(id, json!(to_hex_u64(n))),
        None => JsonRpcResponse::error(id, INTERNAL_ERROR, "No head block"),
    }
}

pub async fn eth_syncing(
    id: Value,
    store: &BlockStore,
    peer_store: &rustock_networking::peers::PeerStore,
) -> JsonRpcResponse {
    let current = get_head_number(store).unwrap_or(0);
    let best_peer = peer_store.get_best_peer().await;

    match best_peer {
        Some((_, meta)) if meta.best_number > current => {
            JsonRpcResponse::success(
                id,
                json!({
                    "startingBlock": to_hex_u64(0),
                    "currentBlock": to_hex_u64(current),
                    "highestBlock": to_hex_u64(meta.best_number),
                }),
            )
        }
        _ => JsonRpcResponse::success(id, json!(false)),
    }
}

pub fn eth_gas_price(id: Value, store: &BlockStore) -> JsonRpcResponse {
    let price = get_head_header(store)
        .map(|h| to_hex_u256(&h.minimum_gas_price))
        .unwrap_or_else(|| "0x0".to_string());
    JsonRpcResponse::success(id, json!(price))
}

pub fn eth_mining(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!(false))
}

pub fn eth_hashrate(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!("0x0"))
}

pub fn eth_accounts(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!([]))
}

pub fn eth_coinbase(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!("0x0000000000000000000000000000000000000000"))
}

pub fn eth_get_block_by_hash(
    id: Value,
    params: &Value,
    store: &BlockStore,
) -> JsonRpcResponse {
    let hash_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block hash parameter"),
    };
    let hash = match parse_b256(hash_str) {
        Some(h) => h,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block hash"),
    };

    match build_block_dto(store, hash) {
        Some(dto) => JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap()),
        None => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_block_by_number(
    id: Value,
    params: &Value,
    store: &BlockStore,
) -> JsonRpcResponse {
    let bn_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number parameter"),
    };
    let head_num = get_head_number(store).unwrap_or(0);
    let number = match parse_block_number(bn_str, head_num) {
        Some(n) => n,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number"),
    };

    let hash = match store.get_canonical_hash(number) {
        Ok(Some(h)) => h,
        _ => return JsonRpcResponse::success(id, Value::Null),
    };

    match build_block_dto(store, hash) {
        Some(dto) => JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap()),
        None => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_block_transaction_count_by_hash(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let hash_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block hash"),
    };
    let hash = match parse_b256(hash_str) {
        Some(h) => h,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block hash"),
    };
    match store.has_block(hash) {
        Ok(true) => JsonRpcResponse::success(id, json!("0x0")),
        _ => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_block_transaction_count_by_number(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let bn_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number"),
    };
    let head_num = get_head_number(store).unwrap_or(0);
    let number = match parse_block_number(bn_str, head_num) {
        Some(n) => n,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number"),
    };
    match store.get_canonical_hash(number) {
        Ok(Some(_)) => JsonRpcResponse::success(id, json!("0x0")),
        _ => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_uncle_count_by_block_hash(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let hash_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block hash"),
    };
    let hash = match parse_b256(hash_str) {
        Some(h) => h,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block hash"),
    };
    match store.get_header(hash) {
        Ok(Some(h)) => JsonRpcResponse::success(id, json!(to_hex_u64(h.uncle_count))),
        _ => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn eth_get_uncle_count_by_block_number(id: Value, params: &Value, store: &BlockStore) -> JsonRpcResponse {
    let bn_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number"),
    };
    let head_num = get_head_number(store).unwrap_or(0);
    let number = match parse_block_number(bn_str, head_num) {
        Some(n) => n,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number"),
    };
    let hash = match store.get_canonical_hash(number) {
        Ok(Some(h)) => h,
        _ => return JsonRpcResponse::success(id, Value::Null),
    };
    match store.get_header(hash) {
        Ok(Some(h)) => JsonRpcResponse::success(id, json!(to_hex_u64(h.uncle_count))),
        _ => JsonRpcResponse::success(id, Value::Null),
    }
}

// -- internal helpers --------------------------------------------------------

fn get_head_number(store: &BlockStore) -> Option<u64> {
    store.get_head().ok()?
        .and_then(|h| store.get_header(h).ok().flatten())
        .map(|h| h.number)
}

fn get_head_header(store: &BlockStore) -> Option<rustock_core::types::header::Header> {
    store.get_head().ok()?
        .and_then(|h| store.get_header(h).ok().flatten())
}

fn build_block_dto(
    store: &BlockStore,
    hash: alloy_primitives::B256,
) -> Option<BlockResultDto> {
    let header = store.get_header(hash).ok()??;
    let td = store.get_total_difficulty(hash).ok()?.unwrap_or_default();
    Some(BlockResultDto::from_header(&header, hash, td))
}
