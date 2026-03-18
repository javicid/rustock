use crate::dto::CallRequest;
use crate::server::RpcState;
use crate::state::resolve_state_root;
use crate::types::*;
use alloy_primitives::{Address, Bytes, U256};
use rustock_core::Transaction;
use rustock_execution::RskExecutor;
use serde_json::{json, Value};

use crate::helpers::to_hex_bytes;

pub fn eth_call(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(call_req) = params.get(0).and_then(CallRequest::from_json) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid call request");
    };
    let block_param = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");

    let Some((trie_store, hardfork_cfg)) = state.trie_store.clone().zip(state.hardfork_cfg.clone()) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Execution engine not available");
    };

    let Some((root, header)) = resolve_state_root(block_param, state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve block");
    };

    let tx = build_call_tx(&call_req, &header);
    let sender = call_req.from.unwrap_or(Address::ZERO);
    let executor = RskExecutor::new(hardfork_cfg, state.store.clone());

    match executor.execute_tx(&header, &tx, sender, &root, trie_store) {
        Ok(result) => {
            if result.output.is_empty() {
                JsonRpcResponse::success(id, json!("0x"))
            } else {
                JsonRpcResponse::success(id, json!(to_hex_bytes(&result.output)))
            }
        }
        Err(e) => JsonRpcResponse::error(id, INTERNAL_ERROR, format!("Execution failed: {e}")),
    }
}

pub fn eth_estimate_gas(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(call_req) = params.get(0).and_then(CallRequest::from_json) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid call request");
    };
    let block_param = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");

    let Some((trie_store, hardfork_cfg)) = state.trie_store.clone().zip(state.hardfork_cfg.clone()) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Execution engine not available");
    };

    let Some((root, header)) = resolve_state_root(block_param, state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve block");
    };

    let sender = call_req.from.unwrap_or(Address::ZERO);
    let executor = RskExecutor::new(hardfork_cfg, state.store.clone());

    let gas_cap = call_req.gas.unwrap_or(header.gas_limit.to::<u64>());

    // Binary search for the minimum gas that allows the transaction to succeed
    let mut lo = 21_000u64;
    let mut hi = gas_cap;

    // First check if the transaction even succeeds at the gas cap
    let mut tx = build_call_tx(&call_req, &header);
    tx.gas_limit = U256::from(hi);
    match executor.execute_tx(&header, &tx, sender, &root, trie_store.clone()) {
        Ok(result) if result.success => {}
        Ok(_) => {
            return JsonRpcResponse::error(id, INTERNAL_ERROR, "Transaction would revert");
        }
        Err(e) => {
            return JsonRpcResponse::error(id, INTERNAL_ERROR, format!("Execution failed: {e}"));
        }
    }

    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        let mut probe_tx = build_call_tx(&call_req, &header);
        probe_tx.gas_limit = U256::from(mid);

        match executor.execute_tx(&header, &probe_tx, sender, &root, trie_store.clone()) {
            Ok(result) if result.success => hi = mid,
            _ => lo = mid,
        }
    }

    JsonRpcResponse::success(id, json!(crate::helpers::to_hex_u64(hi)))
}

fn build_call_tx(req: &CallRequest, header: &rustock_core::Header) -> Transaction {
    Transaction {
        nonce: 0,
        gas_price: req.gas_price.unwrap_or(U256::ZERO),
        gas_limit: req.gas.map(U256::from).unwrap_or(header.gas_limit),
        to: req.to.map(|a| Bytes::copy_from_slice(a.as_slice())).unwrap_or_default(),
        value: req.value.unwrap_or(U256::ZERO),
        input: req.data.as_deref().map(Bytes::copy_from_slice).unwrap_or_default(),
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
    }
}
