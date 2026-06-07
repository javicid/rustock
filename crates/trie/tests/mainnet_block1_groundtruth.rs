//! Mainnet block #1 groundtruth: header #1's stateRoot
//! (0x21e18f25...) covers the post-block-1 state — the genesis bridge
//! account, the 1-byte REMASC sender `[0x00]` with nonce 1 (incremented by
//! the REMASC system tx), and the REMASC contract account record created by
//! the system tx's zero-value endowment transfer (frontier
//! creation-on-touch). This exercises the orchid converter's special
//! REMASC-account branch (96-bit unitrie key), which the ported
//! TrieConverterTest fixtures don't cover.
use alloy_primitives::{Address, B256, U256};
use rustock_trie::{
    account_key, account_key_from_bytes, orchid_state_root, storage_prefix_key, AccountState,
    MemoryTrieStore, TrieKeySlice, TrieNode,
};

const HEADER_1_STATE_ROOT: &str = "21e18f252c8579cee053a215b1f56b90f0b0d008716f5bfbf40009bd6c7d8c04";

fn parse_hash(hex: &str) -> B256 {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    B256::from(out)
}

fn addr(hex: &str) -> Address {
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    Address::from(out)
}

#[test]
fn mainnet_block1_unitrie_converts_to_header_state_root() {
    let store = MemoryTrieStore::new();
    let bridge = addr("0000000000000000000000000000000001000006");
    let remasc = addr("0000000000000000000000000000000001000008");
    let bal_21m = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));

    let put = |trie: TrieNode, key: Vec<u8>, value: &[u8]| {
        trie.put(&TrieKeySlice::from_key(&key), value, &store)
    };

    let mut trie = TrieNode::empty();
    // Genesis alloc: bridge with 21M RBTC.
    trie = put(trie, account_key(&bridge), &AccountState::new(U256::ZERO, bal_21m).encode());
    // REMASC system tx sender: special 1-byte [0x00] address, nonce == 1.
    trie = put(
        trie,
        account_key_from_bytes(&[0x00]),
        &AccountState::new(U256::from(1), U256::ZERO).encode(),
    );
    // REMASC contract record created by the zero-value endowment transfer.
    trie = put(trie, account_key(&remasc), &AccountState::new(U256::ZERO, U256::ZERO).encode());
    // The setupContract marker is invisible in the orchid root (the converter
    // strips it), but it is part of the unitrie — include it to prove the
    // conversion ignores it on a storage-less precompile too.
    trie = put(trie, storage_prefix_key(&remasc), &[0x01]);

    assert_eq!(orchid_state_root(&trie, &store), parse_hash(HEADER_1_STATE_ROOT));
}
