use crate::helpers::{parse_b256, parse_block_number, to_hex_bytes, to_hex_u256};
use crate::server::RpcState;
use crate::types::*;
use alloy_primitives::{Address, B256};
use rustock_core::Header;
use rustock_storage::BlockStore;
use rustock_trie::{account_key, code_key, storage_key, AccountState, TrieKeySlice, TrieNode};
use serde_json::{json, Value};

pub fn eth_get_balance(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    let block_param = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");

    let Some((root, _header)) = resolve_state_root(block_param, state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve block");
    };

    let key = account_key(&addr);
    match trie_get_account(&root, &key, state) {
        Some(acct) => JsonRpcResponse::success(id, json!(to_hex_u256(&acct.balance))),
        None => JsonRpcResponse::success(id, json!("0x0")),
    }
}

pub fn eth_get_transaction_count(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    let block_param = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");

    // For "pending", return the pool's pending nonce if available
    if block_param == "pending" {
        if let Some(pool) = &state.tx_pool {
            if let Some(pending_nonce) = pool.pending_nonce(&addr) {
                return JsonRpcResponse::success(
                    id,
                    json!(format!("0x{:x}", pending_nonce)),
                );
            }
        }
    }

    let Some((root, _header)) = resolve_state_root(block_param, state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve block");
    };

    let key = account_key(&addr);
    match trie_get_account(&root, &key, state) {
        Some(acct) => JsonRpcResponse::success(id, json!(to_hex_u256(&acct.nonce))),
        None => JsonRpcResponse::success(id, json!("0x0")),
    }
}

pub fn eth_get_code(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    let block_param = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");

    let Some((root, _header)) = resolve_state_root(block_param, state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve block");
    };

    let key = code_key(&addr);
    let expanded = TrieKeySlice::from_key(&key);

    let trie_store = match &state.trie_store {
        Some(ts) => ts.clone(),
        None => return JsonRpcResponse::success(id, json!("0x")),
    };

    match root.get(&expanded, &*trie_store) {
        Some(data) => JsonRpcResponse::success(id, json!(to_hex_bytes(&data))),
        None => JsonRpcResponse::success(id, json!("0x")),
    }
}

pub fn eth_get_storage_at(id: Value, params: &Value, state: &RpcState) -> JsonRpcResponse {
    let Some(addr) = params.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid address");
    };
    let Some(slot) = params.get(1).and_then(|v| v.as_str()).and_then(parse_b256) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing or invalid storage slot");
    };
    let block_param = params.get(2).and_then(|v| v.as_str()).unwrap_or("latest");

    let Some((root, _header)) = resolve_state_root(block_param, state) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "Cannot resolve block");
    };

    let key = storage_key(&addr, &slot);
    let expanded = TrieKeySlice::from_key(&key);

    let trie_store = match &state.trie_store {
        Some(ts) => ts.clone(),
        None => {
            let zero = B256::ZERO;
            return JsonRpcResponse::success(id, json!(format!("{:#066x}", zero)));
        }
    };

    match root.get(&expanded, &*trie_store) {
        Some(data) => {
            let mut padded = [0u8; 32];
            let start = 32usize.saturating_sub(data.len());
            padded[start..].copy_from_slice(&data[..data.len().min(32)]);
            let val = B256::from(padded);
            JsonRpcResponse::success(id, json!(format!("{:#066x}", val)))
        }
        None => {
            let zero = B256::ZERO;
            JsonRpcResponse::success(id, json!(format!("{:#066x}", zero)))
        }
    }
}

/// Resolves a block parameter to a state root and header.
pub fn resolve_state_root(block_param: &str, state: &RpcState) -> Option<(TrieNode, Header)> {
    let trie_store = state.trie_store.as_ref()?;
    let store = &state.store;

    // State queries against "latest" must use the EXECUTED head — the
    // download head can be far ahead and its state doesn't exist yet.
    // Fall back to the chain head when no exec head is tracked.
    let header = match block_param {
        "latest" | "pending" => store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(exec_hash, _)| store.header(exec_hash).ok().flatten())
            .or_else(|| resolve_header(block_param, store))?,
        _ => resolve_header(block_param, store)?,
    };

    // Pre-RSKIP126 (wasabi100) headers carry the legacy Ethereum-style state
    // root, which doesn't exist in the Unitrie store. For the executed head
    // the Unitrie root is tracked alongside it; older pre-wasabi blocks
    // cannot be resolved.
    let root_hash = if trie_store.get(header.state_root.as_slice()).is_some() {
        header.state_root
    } else {
        let (exec_hash, exec_root) = store.exec_head().ok().flatten()?;
        if exec_hash != header.hash() {
            return None;
        }
        exec_root
    };

    let root_data = trie_store.get(root_hash.as_slice())?;
    let root_node = TrieNode::from_message(&root_data, &**trie_store);
    Some((root_node, header))
}

fn resolve_header(block_param: &str, store: &BlockStore) -> Option<Header> {
    let head_num = store.head().ok()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)?;

    match block_param {
        "latest" | "pending" => {
            let hash = store.head().ok()??;
            store.header(hash).ok()?
        }
        "earliest" => {
            let hash = store.canonical_hash(0).ok()??;
            store.header(hash).ok()?
        }
        s if s.starts_with("0x") && s.len() == 66 => {
            if let Some(hash) = parse_b256(s) {
                store.header(hash).ok()?
            } else {
                let num = parse_block_number(s, head_num)?;
                let hash = store.canonical_hash(num).ok()??;
                store.header(hash).ok()?
            }
        }
        s => {
            let num = parse_block_number(s, head_num)?;
            let hash = store.canonical_hash(num).ok()??;
            store.header(hash).ok()?
        }
    }
}

fn trie_get_account(root: &TrieNode, key: &[u8], state: &RpcState) -> Option<AccountState> {
    let trie_store = state.trie_store.as_ref()?;
    let expanded = TrieKeySlice::from_key(key);
    let data = root.get(&expanded, &**trie_store)?;
    AccountState::decode(&data).ok()
}
