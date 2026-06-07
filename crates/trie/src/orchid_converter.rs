//! Unitrie → Orchid state-root conversion.
//!
//! Port of rskj 1.x `co.rsk.trie.TrieConverter` (removed upstream in 2021,
//! commit a16069228). rskj 1.x validated every pre-RSKIP126 mainnet header
//! against this transformation while building the unitrie from genesis, so it
//! provides per-block groundtruth for the unitrie *content* before the
//! wasabi100 state-root check exists in headers.
//!
//! The conversion walks the unitrie down to account level, rewrites each
//! account record into the old Orchid format `RLP[nonce, balance, storageRoot,
//! codeHash]` (storage and code live in separate unitrie subtrees but inside
//! the account record in Orchid), and re-keys accounts/storage cells by their
//! full keccak hashes (the Orchid tries were "secure" tries). Hashing uses the
//! Orchid node serialization (`TrieNode::compute_hash_orchid`).
use crate::node::{empty_trie_hash, keccak, NodeRef, TrieNode};
use crate::{AccountState, TrieKeySlice, TrieStore};
use alloy_primitives::B256;
use alloy_rlp::Encodable;
use std::collections::HashMap;

const SECURE_KEY_SIZE: usize = 10; // bytes
/// domain(1) + secure(10) + address(20), in bits.
const ACCOUNT_KEY_BITS: usize = (1 + SECURE_KEY_SIZE + 20) * 8;
/// domain(1) + secure(10) + REMASC sender address(1), in bits.
const REMASC_KEY_BITS: usize = (1 + SECURE_KEY_SIZE + 1) * 8;
/// domain(1) + secure(10) + address(20) + storage prefix(1) + secure(10), in bits.
const STORAGE_KEY_OFFSET_BITS: usize = 42 * 8;

/// Computes the Orchid-format account-trie root hash for a unitrie state
/// (rskj `TrieConverter.getOrchidAccountTrieRoot`).
pub fn orchid_state_root(src: &TrieNode, store: &dyn TrieStore) -> B256 {
    let mut cache = HashMap::new();
    let key = src.shared_path.clone();
    match convert_account_node(&key, src, true, store, &mut cache) {
        Some(trie) => trie.compute_hash_orchid(true, store),
        None => empty_trie_hash(),
    }
}

fn convert_account_node(
    key: &TrieKeySlice,
    src: &TrieNode,
    remove_first_8_bits: bool,
    store: &dyn TrieStore,
    cache: &mut HashMap<B256, TrieNode>,
) -> Option<TrieNode> {
    if src.is_empty_trie() {
        return None;
    }

    let mut shared_path = src.shared_path.clone();
    if remove_first_8_bits {
        assert!(
            shared_path.length() >= 8,
            "unable to remove first 8 bits if path length is less than 8"
        );
        shared_path = shared_path.slice(8, shared_path.length());
    }

    let child0 = src.left.resolve(store);
    let child1 = src.right.resolve(store);

    let is_remasc_account = key.length() == REMASC_KEY_BITS;
    if (key.length() == ACCOUNT_KEY_BITS || is_remasc_account) && src.value.is_some() {
        // Account level reached: rebuild the Orchid account record.
        let astate = AccountState::decode(src.value.as_deref().unwrap())
            .expect("account node holds a valid account record");

        // Right child (0x80) is the code node; its value hash is the code hash.
        let code_hash = match &child1 {
            Some(c1) => c1.get_value_hash(),
            None => keccak(&[]),
        };

        // Left child (0x00) is the storage subtree; rebuild the Orchid
        // storage trie for it. (rskj sets the same empty-trie hash explicitly
        // for a storage-less REMASC account — the default already covers it.)
        let mut state_root = empty_trie_hash();
        if let Some(c0) = &child0 {
            assert_eq!(c0.shared_path.length(), 7, "first child must be 7-bits length");
            let child0_key = key.rebuild_shared_path(0, &c0.shared_path);
            let root = convert_storage_node(&child0_key, c0, true, false, store, cache);
            state_root = root.compute_hash_orchid(true, store);
        }

        let avalue = encode_orchid_account(&astate, &state_root, &code_hash);
        let orchid_key = if is_remasc_account {
            extract_orchid_account_key(key, shared_path.length(), 1, SECURE_KEY_SIZE + 1)
        } else {
            extract_orchid_account_key(key, shared_path.length(), 20, SECURE_KEY_SIZE + 20)
        };

        return Some(TrieNode::new_leaf(orchid_key, avalue));
    }

    let left = match &child0 {
        Some(c0) => {
            let k = key.rebuild_shared_path(0, &c0.shared_path);
            convert_account_node(&k, c0, false, store, cache)
                .map(|n| NodeRef::Node(Box::new(n)))
                .unwrap_or(NodeRef::Empty)
        }
        None => NodeRef::Empty,
    };
    let right = match &child1 {
        Some(c1) => {
            let k = key.rebuild_shared_path(1, &c1.shared_path);
            convert_account_node(&k, c1, false, store, cache)
                .map(|n| NodeRef::Node(Box::new(n)))
                .unwrap_or(NodeRef::Empty)
        }
        None => NodeRef::Empty,
    };

    Some(TrieNode::from_parts(
        shared_path,
        src.value.clone(),
        src.value_hash,
        left,
        right,
    ))
}

fn convert_storage_node(
    key: &TrieKeySlice,
    src: &TrieNode,
    remove_first_node_prefix: bool,
    only_child: bool,
    store: &dyn TrieStore,
    cache: &mut HashMap<B256, TrieNode>,
) -> TrieNode {
    let src_hash = src.compute_hash(store);
    if !only_child && !remove_first_node_prefix {
        if let Some(cached) = cache.get(&src_hash) {
            return cached.clone();
        }
    }

    let child0 = src.left.resolve(store);
    let child1 = src.right.resolve(store);

    let converted0 = child0.as_ref().map(|c0| {
        let k = key.rebuild_shared_path(0, &c0.shared_path);
        convert_storage_node(
            &k,
            c0,
            false,
            remove_first_node_prefix && child1.is_none(),
            store,
            cache,
        )
    });
    let converted1 = child1.as_ref().map(|c1| {
        let k = key.rebuild_shared_path(1, &c1.shared_path);
        convert_storage_node(
            &k,
            c1,
            false,
            remove_first_node_prefix && child0.is_none(),
            store,
            cache,
        )
    });

    let mut shared_path = src.shared_path.clone();
    let mut value = src.value.clone();
    let mut value_hash = src.value_hash;

    if remove_first_node_prefix {
        // The unitrie storage-prefix node (and its contract marker value)
        // does not exist in the Orchid storage trie.
        shared_path = TrieKeySlice::empty();
        value = None;
        value_hash = None;
        if converted0.is_some() && converted1.is_none() {
            return converted0.unwrap();
        }
        if converted0.is_none() && converted1.is_some() {
            return converted1.unwrap();
        }
    }

    if only_child {
        shared_path = key.slice(key.length() - (shared_path.length() + 1), key.length());
    }

    if !remove_first_node_prefix && converted0.is_none() && converted1.is_none() {
        // Terminal node: re-key the storage cell by its full keccak.
        shared_path = extract_orchid_storage_key(key, &shared_path);
    } else if key.length() >= STORAGE_KEY_OFFSET_BITS {
        panic!("the unitrie storage doesn't share as much structure as we need to rebuild the Orchid trie");
    }

    let left = converted0.map(|n| NodeRef::Node(Box::new(n))).unwrap_or(NodeRef::Empty);
    let right = converted1.map(|n| NodeRef::Node(Box::new(n))).unwrap_or(NodeRef::Empty);
    let new_node = TrieNode::from_parts(shared_path, value, value_hash, left, right);
    if !only_child {
        cache.insert(src_hash, new_node.clone());
    }
    new_node
}

/// Old Orchid account record: `RLP[nonce, balance, storageRoot, codeHash]`.
fn encode_orchid_account(astate: &AccountState, state_root: &B256, code_hash: &B256) -> Vec<u8> {
    let mut payload = Vec::new();
    astate.nonce.encode(&mut payload);
    astate.balance.encode(&mut payload);
    state_root.as_slice().encode(&mut payload);
    code_hash.as_slice().encode(&mut payload);

    let mut out = Vec::with_capacity(payload.len() + 3);
    alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

/// Re-keys an account: the Orchid account trie key is `keccak256(address)`,
/// minus the prefix bits already consumed by the converted trie structure
/// above this node (rskj `extractOrchidAccountKeyPathFromUnitrieKey`).
fn extract_orchid_account_key(
    key: &TrieKeySlice,
    shared_path_len_bits: usize,
    address_len_bytes: usize,
    unitrie_key_size_bytes: usize,
) -> TrieKeySlice {
    assert!(
        shared_path_len_bits >= (unitrie_key_size_bytes - SECURE_KEY_SIZE) * 8,
        "the unitrie doesn't share as much structure as we need to rebuild the Orchid trie"
    );

    let addr_bits = address_len_bytes * 8;
    let encoded_addr = key.slice(key.length() - addr_bits, key.length()).encode();
    let secure_key = keccak(&encoded_addr);
    let expanded = TrieKeySlice::from_key(secure_key.as_slice());
    // Length of the structure shared between the Orchid trie and the unitrie.
    let common_len = unitrie_key_size_bytes * 8 - shared_path_len_bits;
    expanded.slice(common_len, expanded.length())
}

/// Re-keys a storage cell: the Orchid storage trie key is `keccak256` of the
/// 32-byte left-padded slot (the unitrie stores slots stripped of leading
/// zeroes), minus the bits consumed above this node
/// (rskj `extractOrchidStorageKeyPathFromUnitrieKey`).
fn extract_orchid_storage_key(key: &TrieKeySlice, shared_path: &TrieKeySlice) -> TrieKeySlice {
    let leading_zeroes_to_add = STORAGE_KEY_OFFSET_BITS + 32 * 8 - key.length();
    let unsecured = key
        .slice(STORAGE_KEY_OFFSET_BITS, key.length())
        .left_pad(leading_zeroes_to_add);
    let secure_key = keccak(&unsecured.encode());
    let expanded = TrieKeySlice::from_key(secure_key.as_slice());
    // rskj: 42*8 - sharedPath - leadingZeroes; rewritten to avoid intermediate
    // underflow in usize arithmetic.
    let non_shared_offset = key.length() - shared_path.length() - 32 * 8;
    expanded.slice(non_shared_offset, expanded.length())
}
