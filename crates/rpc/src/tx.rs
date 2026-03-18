use crate::dto::{ReceiptDto, TransactionDto};
use crate::helpers::{parse_b256, parse_block_number};
use crate::server::RpcState;
use crate::types::*;
use alloy_primitives::{Address, B256};
use alloy_rlp::Encodable;
use serde_json::Value;
use sha3::{Digest, Keccak256};

pub fn eth_get_transaction_by_hash(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid tx hash");
    };

    let Some((block_hash, tx_index)) = state.store.tx_location(tx_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some((transactions, _ommers)) = state.store.body(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(header) = state.store.header(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(tx) = transactions.get(tx_index as usize) else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let sender = recover_sender_or_zero(tx);
    let dto = TransactionDto::from_tx(tx, tx_hash, Some(block_hash), Some(header.number), Some(tx_index), sender);
    JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap())
}

pub fn eth_get_transaction_by_block_hash_and_index(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(block_hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid block hash");
    };
    let Some(index) = params.get(1).and_then(|v| v.as_str()).and_then(parse_hex_u32) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid index");
    };

    tx_by_block_and_index(id, block_hash, index, state)
}

pub fn eth_get_transaction_by_block_number_and_index(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(bn_str) = params.get(0).and_then(|v| v.as_str()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing block number");
    };
    let head_num = head_number(&state.store).unwrap_or(0);
    let Some(number) = parse_block_number(bn_str, head_num) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Invalid block number");
    };
    let Some(block_hash) = state.store.canonical_hash(number).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };
    let Some(index) = params.get(1).and_then(|v| v.as_str()).and_then(parse_hex_u32) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid index");
    };

    tx_by_block_and_index(id, block_hash, index, state)
}

pub fn eth_get_transaction_receipt(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid tx hash");
    };

    let Some((block_hash, tx_index)) = state.store.tx_location(tx_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(header) = state.store.header(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(receipts) = state.store.receipts(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(receipt) = receipts.get(tx_index as usize) else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some((transactions, _)) = state.store.body(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(tx) = transactions.get(tx_index as usize) else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let sender = recover_sender_or_zero(tx);

    // Compute log_index_start: sum of logs in preceding receipts
    let log_index_start: u32 = receipts[..tx_index as usize]
        .iter()
        .map(|r| r.logs.len() as u32)
        .sum();

    let dto = ReceiptDto::from_receipt(
        receipt, tx, tx_hash, block_hash, header.number, tx_index, sender, log_index_start,
    );
    JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap())
}

// --- helpers ---

fn tx_by_block_and_index(id: Value, block_hash: B256, index: u32, state: &RpcState) -> JsonRpcResponse {
    let Some(header) = state.store.header(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some((transactions, _)) = state.store.body(block_hash).ok().flatten() else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let Some(tx) = transactions.get(index as usize) else {
        return JsonRpcResponse::success(id, Value::Null);
    };

    let tx_hash = compute_tx_hash(tx);
    let sender = recover_sender_or_zero(tx);

    let dto = TransactionDto::from_tx(tx, tx_hash, Some(block_hash), Some(header.number), Some(index), sender);
    JsonRpcResponse::success(id, serde_json::to_value(dto).unwrap())
}

fn head_number(store: &rustock_storage::BlockStore) -> Option<u64> {
    store.head().ok()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)
}

fn compute_tx_hash(tx: &rustock_core::Transaction) -> B256 {
    let mut buf = Vec::new();
    tx.encode(&mut buf);
    B256::from_slice(&Keccak256::digest(&buf))
}

fn recover_sender_or_zero(tx: &rustock_core::Transaction) -> Address {
    tx.recover_sender(30).unwrap_or(Address::ZERO)
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).ok()
}
