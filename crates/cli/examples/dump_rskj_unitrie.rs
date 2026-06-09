//! Dump every leaf of an rskj unitrie directly from its LevelDB, given a root
//! hash. Post-RSKIP126 (wasabi100, #1,591,000) a header's `state_root` IS the
//! unitrie root, so this lets us oracle-diff any post-wasabi block's state from
//! Rust (no Java). rskj's unitrie LevelDB is content-addressed: nodeHash ->
//! node message bytes, the same scheme rustock uses.
//!
//! Usage: dump_rskj_unitrie <unitrie-leveldb-dir> <root-hash-hex> <out-file>

use rocksdb::{DB, Options};
use rustock_trie::{TrieNode, TrieStore};
use std::io::Write;

struct LevelDbTrieStore {
    db: DB,
}

impl TrieStore for LevelDbTrieStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.db.get(key).ok().flatten()
    }
    fn put(&self, _key: &[u8], _value: &[u8]) {}
}

fn walk(node: &TrieNode, bits: &mut Vec<u8>, store: &dyn TrieStore, out: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    let start = bits.len();
    for &b in node.shared_path.expand() {
        bits.push(b);
    }
    if let Some(val) = &node.value {
        out.push((pack(bits), val.clone()));
    }
    if let Some(left) = node.left.resolve(store) {
        bits.push(0);
        walk(&left, bits, store, out);
        bits.pop();
    }
    if let Some(right) = node.right.resolve(store) {
        bits.push(1);
        walk(&right, bits, store, out);
        bits.pop();
    }
    bits.truncate(start);
}

fn pack(bits: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (k, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            out[k / 8] |= 0x80 >> (k % 8);
        }
    }
    out
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: dump_rskj_unitrie <unitrie-dir> <root-hex> <out-file>");
    let root_hex = args.next().expect("usage: dump_rskj_unitrie <unitrie-dir> <root-hex> <out-file>");
    let out_path = args.next().expect("usage: dump_rskj_unitrie <unitrie-dir> <root-hex> <out-file>");

    let mut opts = Options::default();
    let mut bbt = rocksdb::BlockBasedOptions::default();
    bbt.set_block_cache(&rocksdb::Cache::new_lru_cache(4 * 1024 * 1024 * 1024));
    opts.set_block_based_table_factory(&bbt);
    let db = DB::open_for_read_only(&opts, &dir, false)?;
    let store = LevelDbTrieStore { db };

    let root_hash = hex::decode(root_hex.trim_start_matches("0x"))?;
    let data = store.get(&root_hash).expect("root node not found in unitrie db");
    let root = TrieNode::from_message(&data, &store);
    eprintln!("root={root_hex} walking...");

    let mut leaves = Vec::new();
    let mut bits = Vec::new();
    walk(&root, &mut bits, &store, &mut leaves);
    leaves.sort();

    let mut f = std::io::BufWriter::new(std::fs::File::create(&out_path)?);
    for (k, v) in &leaves {
        writeln!(f, "{}={}", hex::encode(k), hex::encode(v))?;
    }
    eprintln!("wrote {} leaves to {out_path}", leaves.len());
    Ok(())
}
