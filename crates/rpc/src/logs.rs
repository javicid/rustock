use crate::dto::LogDto;
use crate::helpers::{parse_b256, parse_block_number, to_hex_b256, to_hex_u64};
use crate::server::RpcState;
use crate::types::*;
use alloy_primitives::{Address, B256};
use alloy_rlp::Encodable;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

const MAX_BLOCK_RANGE: u64 = 10_000;

/// In-memory filter storage for eth_newFilter / eth_getFilterChanges.
#[derive(Clone)]
pub struct FilterStore {
    filters: Arc<RwLock<HashMap<u64, Filter>>>,
    next_id: Arc<AtomicU64>,
}

impl Default for FilterStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterStore {
    pub fn new() -> Self {
        Self {
            filters: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn insert(&self, filter: Filter) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.filters.write().unwrap().insert(id, filter);
        id
    }

    fn get(&self, id: u64) -> Option<Filter> {
        self.filters.read().unwrap().get(&id).cloned()
    }

    fn update_last_polled(&self, id: u64, block: u64) {
        if let Some(f) = self.filters.write().unwrap().get_mut(&id) {
            f.last_polled_block = block;
        }
    }

    fn remove(&self, id: u64) -> bool {
        self.filters.write().unwrap().remove(&id).is_some()
    }
}

#[derive(Clone, Debug)]
enum FilterKind {
    Log(LogFilter),
    Block,
    PendingTransaction,
}

#[derive(Clone, Debug)]
struct Filter {
    kind: FilterKind,
    last_polled_block: u64,
}

#[derive(Clone, Debug)]
struct LogFilter {
    from_block: Option<u64>,
    to_block: Option<u64>,
    addresses: Vec<Address>,
    topics: Vec<Option<Vec<B256>>>,
}

pub fn eth_get_logs(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_obj) = params.get(0) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing filter object");
    };

    let head_num = head_number(&state.store).unwrap_or(0);
    let filter = parse_log_filter(filter_obj, head_num);

    let from = filter.from_block.unwrap_or(head_num);
    let to = filter.to_block.unwrap_or(head_num);

    if to > from + MAX_BLOCK_RANGE {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Block range exceeds maximum (10000)");
    }

    let logs = collect_logs(from, to, &filter, state);
    JsonRpcResponse::success(id, serde_json::to_value(&logs).unwrap())
}

pub fn eth_new_filter(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_obj) = params.get(0) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing filter object");
    };

    let head_num = head_number(&state.store).unwrap_or(0);
    let log_filter = parse_log_filter(filter_obj, head_num);

    let filter = Filter {
        kind: FilterKind::Log(log_filter),
        last_polled_block: head_num,
    };

    let filter_id = state.filter_store.insert(filter);
    JsonRpcResponse::success(id, json!(to_hex_u64(filter_id)))
}

pub fn eth_new_block_filter(id: Value, state: &RpcState) -> JsonRpcResponse {
    let head_num = head_number(&state.store).unwrap_or(0);
    let filter = Filter {
        kind: FilterKind::Block,
        last_polled_block: head_num,
    };
    let filter_id = state.filter_store.insert(filter);
    JsonRpcResponse::success(id, json!(to_hex_u64(filter_id)))
}

pub fn eth_new_pending_transaction_filter(id: Value) -> JsonRpcResponse {
    // No mempool support — return a dummy filter that always returns empty
    JsonRpcResponse::success(id, json!("0x0"))
}

pub fn eth_get_filter_changes(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_id) = params.get(0).and_then(|v| v.as_str()).and_then(parse_hex_u64) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid filter id");
    };

    if filter_id == 0 {
        return JsonRpcResponse::success(id, json!([]));
    }

    let Some(filter) = state.filter_store.get(filter_id) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Filter not found");
    };

    let head_num = head_number(&state.store).unwrap_or(0);

    match &filter.kind {
        FilterKind::Log(log_filter) => {
            let from = filter.last_polled_block + 1;
            let to = head_num;
            if from > to {
                return JsonRpcResponse::success(id, json!([]));
            }
            let logs = collect_logs(from, to, log_filter, state);
            state.filter_store.update_last_polled(filter_id, head_num);
            JsonRpcResponse::success(id, serde_json::to_value(&logs).unwrap())
        }
        FilterKind::Block => {
            let from = filter.last_polled_block + 1;
            let to = head_num;
            let mut hashes = Vec::new();
            for num in from..=to {
                if let Some(hash) = state.store.canonical_hash(num).ok().flatten() {
                    hashes.push(to_hex_b256(&hash));
                }
            }
            state.filter_store.update_last_polled(filter_id, head_num);
            JsonRpcResponse::success(id, json!(hashes))
        }
        FilterKind::PendingTransaction => {
            JsonRpcResponse::success(id, json!([]))
        }
    }
}

pub fn eth_get_filter_logs(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_id) = params.get(0).and_then(|v| v.as_str()).and_then(parse_hex_u64) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid filter id");
    };

    let Some(filter) = state.filter_store.get(filter_id) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Filter not found");
    };

    match &filter.kind {
        FilterKind::Log(log_filter) => {
            let head_num = head_number(&state.store).unwrap_or(0);
            let from = log_filter.from_block.unwrap_or(head_num);
            let to = log_filter.to_block.unwrap_or(head_num);
            let logs = collect_logs(from, to, log_filter, state);
            JsonRpcResponse::success(id, serde_json::to_value(&logs).unwrap())
        }
        _ => JsonRpcResponse::success(id, json!([])),
    }
}

pub fn eth_uninstall_filter(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(filter_id) = params.get(0).and_then(|v| v.as_str()).and_then(parse_hex_u64) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid filter id");
    };
    let removed = state.filter_store.remove(filter_id);
    JsonRpcResponse::success(id, json!(removed))
}

// --- internal helpers ---

fn collect_logs(from: u64, to: u64, filter: &LogFilter, state: &RpcState) -> Vec<LogDto> {
    let mut result = Vec::new();

    for num in from..=to {
        let Some(block_hash) = state.store.canonical_hash(num).ok().flatten() else {
            continue;
        };
        let Some(receipts) = state.store.receipts(block_hash).ok().flatten() else {
            continue;
        };
        let transactions = state.store.body(block_hash).ok().flatten()
            .map(|(txs, _)| txs)
            .unwrap_or_default();

        let mut global_log_index = 0u32;
        for (tx_idx, receipt) in receipts.iter().enumerate() {
            let tx_hash = transactions.get(tx_idx)
                .map(compute_tx_hash)
                .unwrap_or(B256::ZERO);

            for log in &receipt.logs {
                if matches_filter(log, filter) {
                    result.push(LogDto::from_log(
                        log,
                        block_hash,
                        num,
                        tx_hash,
                        tx_idx as u32,
                        global_log_index,
                    ));
                }
                global_log_index += 1;
            }
        }
    }

    result
}

fn matches_filter(log: &rustock_core::Log, filter: &LogFilter) -> bool {
    if !filter.addresses.is_empty() && !filter.addresses.contains(&log.address) {
        return false;
    }

    for (i, topic_filter) in filter.topics.iter().enumerate() {
        if let Some(allowed) = topic_filter {
            match log.topics.get(i) {
                Some(t) if allowed.contains(t) => {}
                None if allowed.is_empty() => {}
                _ => return false,
            }
        }
    }

    true
}

fn parse_log_filter(obj: &Value, head_num: u64) -> LogFilter {
    let from_block = obj.get("fromBlock")
        .and_then(|v| v.as_str())
        .and_then(|s| parse_block_number(s, head_num));

    let to_block = obj.get("toBlock")
        .and_then(|v| v.as_str())
        .and_then(|s| parse_block_number(s, head_num));

    let addresses = parse_address_filter(obj.get("address"));

    let topics = obj.get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().map(|t| {
                if t.is_null() {
                    None
                } else if let Some(s) = t.as_str() {
                    parse_b256(s).map(|h| vec![h])
                } else if let Some(arr) = t.as_array() {
                    let topics: Vec<B256> = arr.iter()
                        .filter_map(|v| v.as_str().and_then(parse_b256))
                        .collect();
                    if topics.is_empty() { None } else { Some(topics) }
                } else {
                    None
                }
            }).collect()
        })
        .unwrap_or_default();

    LogFilter { from_block, to_block, addresses, topics }
}

fn parse_address_filter(v: Option<&Value>) -> Vec<Address> {
    match v {
        None => vec![],
        Some(Value::String(s)) => s.parse::<Address>().ok().into_iter().collect(),
        Some(Value::Array(arr)) => arr.iter()
            .filter_map(|v| v.as_str()?.parse::<Address>().ok())
            .collect(),
        _ => vec![],
    }
}

fn compute_tx_hash(tx: &rustock_core::Transaction) -> B256 {
    let mut buf = Vec::new();
    tx.encode(&mut buf);
    B256::from_slice(&Keccak256::digest(&buf))
}

fn head_number(store: &rustock_storage::BlockStore) -> Option<u64> {
    store.head().ok()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}
