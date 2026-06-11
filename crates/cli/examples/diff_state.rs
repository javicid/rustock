//! Localize a post-wasabi state-root divergence to the exact diverging trie
//! leaves. Replays canonical blocks from the executed head up to <number>
//! in memory (computing rustock's — possibly wrong — post-state trie), then
//! diffs it against rskj's own unitrie for the *header's* state root, read
//! directly from rskj's LevelDB. A hash-pruned dual walk descends only where
//! the two tries' subtree hashes differ, so it visits a handful of nodes and
//! finishes instantly even on a multi-million-leaf state.
//!
//! Usage:
//!   cargo run -p rustock-cli --release --example diff_state -- \
//!       <rustock-data-dir> <number> <rskj-unitrie-leveldb-dir>

use rocksdb::{DB, Options};
use rustock_core::Block;
use rustock_execution::{BlockProcessor, RskHardforkConfig};
use rustock_storage::{BlockStore, CachedTrieStore};
use rustock_trie::{NodeRef, TrieNode, TrieStore};
use std::sync::Arc;

struct LevelDbTrieStore {
    db: DB,
}

impl TrieStore for LevelDbTrieStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.db.get(key).ok().flatten()
    }
    fn put(&self, _key: &[u8], _value: &[u8]) {}
}

/// A leaf discovered during the diff: full packed key + its value hash + value.
type Leaf = (Vec<u8>, Option<[u8; 32]>, Option<Vec<u8>>);

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
    node.value_hash.as_ref().map(|vh| {
        (pack(path), Some(vh.0), node.value.clone())
    })
}

/// Collect every leaf in a whole subtree (used when one side is missing).
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
    sa: &dyn TrieStore,
    sb: &dyn TrieStore,
    aout: &mut Vec<Leaf>,
    bout: &mut Vec<Leaf>,
) {
    // Identical subtree (or both empty) — content addressing makes this exact.
    if a.get_hash(sa) == b.get_hash(sb) {
        return;
    }
    match (a.resolve(sa), b.resolve(sb)) {
        (None, Some(n)) => collect(&n, bprefix, sb, bout),
        (Some(n), None) => collect(&n, aprefix, sa, aout),
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
            diff(&an.left, &bn.left, aprefix, bprefix, sa, sb, aout, bout);
            aprefix.pop();
            bprefix.pop();
            aprefix.push(1);
            bprefix.push(1);
            diff(&an.right, &bn.right, aprefix, bprefix, sa, sb, aout, bout);
            aprefix.truncate(astart);
            bprefix.truncate(bstart);
        }
        (None, None) => unreachable!("hashes differ but both empty"),
    }
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("usage: diff_state <data-dir> <number> <rskj-unitrie-dir>");
    let number: u64 =
        args.next().expect("usage: diff_state <data-dir> <number> <rskj-unitrie-dir>").parse()?;
    let rskj_dir = args.next().expect("usage: diff_state <data-dir> <number> <rskj-unitrie-dir>");

    // --- rustock side: replay to <number>, get the computed post-state trie ---
    let store = Arc::new(BlockStore::open(&data_dir)?);
    let (exec_hash, state_root) = store.exec_head()?.expect("no exec_head");
    let exec_number = store.header(exec_hash)?.expect("exec head header").number;
    assert!(number > exec_number, "target #{number} not past exec head #{exec_number}");

    let trie_store: Arc<dyn TrieStore> =
        Arc::new(CachedTrieStore::with_defaults(store.db().clone()));
    let root_data = trie_store.get(state_root.as_slice()).expect("root node");
    let mut root = TrieNode::from_message(&root_data, trie_store.as_ref());

    let processor = BlockProcessor::new(RskHardforkConfig::mainnet(), store.clone());

    let mut header_state_root = None;
    for n in exec_number + 1..=number {
        let hash = store.canonical_hash(n)?.expect("canonical hash");
        let header = store.header(hash)?.expect("header");
        let (transactions, ommers) = store.body(hash)?.expect("body");
        let block = Block { header, transactions, ommers };
        let processed = processor.execute_block(&block, &root, trie_store.clone())?;
        root = processed.new_state_root;
        if n == number {
            header_state_root = Some(block.header.state_root);
            eprintln!(
                "rustock computed root = {:?}\nheader   (rskj) root = {:?}",
                processed.state_root_hash, block.header.state_root
            );
        }
    }
    let header_state_root = header_state_root.unwrap();

    // --- rskj side: open the unitrie LevelDB, resolve the header's root ---
    let mut opts = Options::default();
    let mut bbt = rocksdb::BlockBasedOptions::default();
    bbt.set_block_cache(&rocksdb::Cache::new_lru_cache(1024 * 1024 * 1024));
    opts.set_block_based_table_factory(&bbt);
    let rskj_db = DB::open_for_read_only(&opts, &rskj_dir, false)?;
    let rskj_store = LevelDbTrieStore { db: rskj_db };
    let rskj_root_data = rskj_store
        .get(header_state_root.as_slice())
        .expect("header state root not in rskj unitrie db (is rskj synced past this block?)");
    let rskj_root = TrieNode::from_message(&rskj_root_data, &rskj_store);

    // --- hash-pruned dual walk ---
    let a_ref = NodeRef::Node(Box::new(root));
    let b_ref = NodeRef::Node(Box::new(rskj_root));
    let mut aout = Vec::new();
    let mut bout = Vec::new();
    diff(
        &a_ref,
        &b_ref,
        &mut Vec::new(),
        &mut Vec::new(),
        trie_store.as_ref(),
        &rskj_store,
        &mut aout,
        &mut bout,
    );
    aout.sort();
    bout.sort();

    use std::collections::BTreeMap;
    let amap: BTreeMap<_, _> = aout.iter().map(|(k, vh, v)| (k.clone(), (vh, v))).collect();
    let bmap: BTreeMap<_, _> = bout.iter().map(|(k, vh, v)| (k.clone(), (vh, v))).collect();
    let mut keys: Vec<_> = amap.keys().chain(bmap.keys()).cloned().collect();
    keys.sort();
    keys.dedup();

    let mut ndiff = 0;
    for k in &keys {
        let a = amap.get(k);
        let b = bmap.get(k);
        let same = match (a, b) {
            (Some((avh, _)), Some((bvh, _))) => avh == bvh,
            _ => false,
        };
        if same {
            continue;
        }
        ndiff += 1;
        let fmt = |e: Option<&(&Option<[u8; 32]>, &Option<Vec<u8>>)>| match e {
            None => "<absent>".to_string(),
            Some((_, v)) => match v {
                Some(bytes) => format!("0x{}", hex::encode(bytes)),
                None => "<long-value-not-loaded>".to_string(),
            },
        };
        println!("KEY 0x{}", hex::encode(k));
        println!("  rustock: {}", fmt(a));
        println!("  rskj   : {}", fmt(b));
    }
    eprintln!("\n{ndiff} diverging leaves (rustock {} / rskj {} collected)", aout.len(), bout.len());
    Ok(())
}
