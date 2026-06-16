//! Diagnostic: show the unitrie leaf delta produced by executing a single
//! block. Replays from the executed head to <number>-1 (the base), then
//! executes <number> and hash-prune-diffs the two rustock-computed tries.
//! Prints only the leaves that changed — the exact state delta of <number>.
//! No rskj DB needed (both sides are rustock-computed); use when rskj isn't
//! synced past the target.
//!
//! Usage: cargo run -p rustock-cli --release --example diff_self -- <data-dir> <number>

use rustock_core::Block;
use rustock_execution::{BlockProcessor, RskHardforkConfig};
use rustock_storage::{BlockStore, CachedTrieStore};
use rustock_trie::{NodeRef, TrieNode, TrieStore};
use std::sync::Arc;

type Leaf = (Vec<u8>, Option<Vec<u8>>);

fn pack(bits: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (k, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            out[k / 8] |= 0x80 >> (k % 8);
        }
    }
    out
}

fn leaf_of(node: &TrieNode, path: &[u8]) -> Option<Leaf> {
    node.value_hash.as_ref().map(|_| (pack(path), node.value.clone()))
}

fn collect(node: &TrieNode, prefix: &mut Vec<u8>, store: &dyn TrieStore, out: &mut Vec<Leaf>) {
    let start = prefix.len();
    prefix.extend_from_slice(node.shared_path.expand());
    if let Some(l) = leaf_of(node, prefix) {
        out.push(l);
    }
    if let Some(left) = node.left.resolve(store) {
        prefix.push(0);
        collect(&left, prefix, store, out);
        prefix.pop();
    }
    if let Some(right) = node.right.resolve(store) {
        prefix.push(1);
        collect(&right, prefix, store, out);
        prefix.pop();
    }
    prefix.truncate(start);
}

#[allow(clippy::too_many_arguments)]
fn diff(
    a: &NodeRef,
    b: &NodeRef,
    aprefix: &mut Vec<u8>,
    bprefix: &mut Vec<u8>,
    s: &dyn TrieStore,
    aout: &mut Vec<Leaf>,
    bout: &mut Vec<Leaf>,
) {
    if a.get_hash(s) == b.get_hash(s) {
        return;
    }
    match (a.resolve(s), b.resolve(s)) {
        (None, Some(n)) => collect(&n, bprefix, s, bout),
        (Some(n), None) => collect(&n, aprefix, s, aout),
        (Some(an), Some(bn)) => {
            let astart = aprefix.len();
            let bstart = bprefix.len();
            aprefix.extend_from_slice(an.shared_path.expand());
            bprefix.extend_from_slice(bn.shared_path.expand());
            if let Some(l) = leaf_of(&an, aprefix) {
                aout.push(l);
            }
            if let Some(l) = leaf_of(&bn, bprefix) {
                bout.push(l);
            }
            aprefix.push(0);
            bprefix.push(0);
            diff(&an.left, &bn.left, aprefix, bprefix, s, aout, bout);
            aprefix.pop();
            bprefix.pop();
            aprefix.push(1);
            bprefix.push(1);
            diff(&an.right, &bn.right, aprefix, bprefix, s, aout, bout);
            aprefix.truncate(astart);
            bprefix.truncate(bstart);
        }
        (None, None) => unreachable!("hashes differ but both empty"),
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("usage: diff_self <data-dir> <number>");
    let number: u64 = args.next().expect("usage: diff_self <data-dir> <number>").parse()?;

    let store = Arc::new(BlockStore::open(&data_dir)?);
    let (exec_hash, state_root) = store.exec_head()?.expect("no exec_head");
    let exec_number = store.header(exec_hash)?.expect("exec head header").number;
    assert!(number > exec_number, "target #{number} not past exec head #{exec_number}");

    let trie_store: Arc<dyn TrieStore> =
        Arc::new(CachedTrieStore::with_defaults(store.db().clone()));
    let root_data = trie_store.get(state_root.as_slice()).expect("root node");
    let mut root = TrieNode::from_message(&root_data, trie_store.as_ref());

    let processor = BlockProcessor::new(RskHardforkConfig::mainnet(), store.clone());

    let mut base_root: Option<TrieNode> = None;
    for n in exec_number + 1..=number {
        if n == number {
            base_root = Some(root.clone());
        }
        let hash = store.canonical_hash(n)?.expect("canonical hash");
        let header = store.header(hash)?.expect("header");
        let (transactions, ommers) = store.body(hash)?.expect("body");
        let block = Block { header, transactions, ommers };
        let processed = processor.execute_block(&block, &root, trie_store.clone())?;
        root = processed.new_state_root;
    }

    let a_ref = NodeRef::Node(Box::new(base_root.unwrap())); // before #number
    let b_ref = NodeRef::Node(Box::new(root)); // after #number
    let mut aout = Vec::new();
    let mut bout = Vec::new();
    diff(&a_ref, &b_ref, &mut Vec::new(), &mut Vec::new(), trie_store.as_ref(), &mut aout, &mut bout);
    aout.sort();
    bout.sort();

    use std::collections::BTreeMap;
    let before: BTreeMap<Vec<u8>, Option<Vec<u8>>> = aout.into_iter().collect();
    let after: BTreeMap<Vec<u8>, Option<Vec<u8>>> = bout.into_iter().collect();
    let hx = |o: &Option<Vec<u8>>| o.as_ref().map(|v| alloy_primitives::hex::encode(v)).unwrap_or_else(|| "<none>".into());

    let mut keys: Vec<&Vec<u8>> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    eprintln!("=== {} changed leaves at #{number} ===", keys.len());
    for k in keys {
        let b = before.get(k);
        let a = after.get(k);
        match (b, a) {
            (Some(bv), Some(av)) if bv != av => {
                eprintln!("CHANGED key=0x{}\n  before={}\n  after ={}", alloy_primitives::hex::encode(k), hx(bv), hx(av));
            }
            (Some(bv), None) => eprintln!("REMOVED key=0x{}\n  before={}", alloy_primitives::hex::encode(k), hx(bv)),
            (None, Some(av)) => eprintln!("ADDED   key=0x{}\n  after ={}", alloy_primitives::hex::encode(k), hx(av)),
            _ => {}
        }
    }
    Ok(())
}
