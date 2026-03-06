use crate::types::*;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

pub fn web3_client_version(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, json!("Rustock/0.1.0"))
}

pub fn web3_sha3(id: Value, params: &Value) -> JsonRpcResponse {
    let input = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing data parameter"),
    };

    let bytes = match hex::decode(input.strip_prefix("0x").unwrap_or(input)) {
        Ok(b) => b,
        Err(_) => return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid hex data"),
    };

    let hash = Keccak256::digest(&bytes);
    JsonRpcResponse::success(id, json!(format!("0x{}", hex::encode(hash))))
}
