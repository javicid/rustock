use crate::helpers::{parse_b256, parse_block_number, to_hex_bytes};
use crate::types::*;
use alloy_rlp::Encodable;
use rustock_storage::BlockStore;
use serde_json::{json, Value};

pub fn rsk_protocol_version(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!("0x1"))
}

pub fn rsk_get_raw_block_header_by_hash(
    id: Value,
    params: &Value,
    store: &BlockStore,
) -> JsonRpcResponse {
    let hash_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block hash"),
    };
    let hash = match parse_b256(hash_str) {
        Some(h) => h,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block hash"),
    };

    match store.get_header(hash) {
        Ok(Some(header)) => {
            let mut buf = Vec::new();
            header.encode(&mut buf);
            JsonRpcResponse::success(id, json!(to_hex_bytes(&buf)))
        }
        _ => JsonRpcResponse::success(id, Value::Null),
    }
}

pub fn rsk_get_raw_block_header_by_number(
    id: Value,
    params: &Value,
    store: &BlockStore,
) -> JsonRpcResponse {
    let bn_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number"),
    };

    let head_num = store
        .get_head()
        .ok()
        .flatten()
        .and_then(|h| store.get_header(h).ok().flatten())
        .map(|h| h.number)
        .unwrap_or(0);

    let number = match parse_block_number(bn_str, head_num) {
        Some(n) => n,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number"),
    };

    let hash = match store.get_canonical_hash(number) {
        Ok(Some(h)) => h,
        _ => return JsonRpcResponse::success(id, Value::Null),
    };

    match store.get_header(hash) {
        Ok(Some(header)) => {
            let mut buf = Vec::new();
            header.encode(&mut buf);
            JsonRpcResponse::success(id, json!(to_hex_bytes(&buf)))
        }
        _ => JsonRpcResponse::success(id, Value::Null),
    }
}
