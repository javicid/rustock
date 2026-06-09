//! Diagnostic: dump every leaf (key=value) of rustock's persisted unitrie at
//! the executed head. Used to diff against rskj's unitrie for the same block
//! to localize receipts-invisible state divergences.
//!
//! Usage: cargo run -p rustock-cli --release --example dump_state -- <data-dir> <out-file>

use rustock_storage::{BlockStore, RocksDbTrieStore};
use rustock_trie::{TrieNode, TrieStore};
use std::io::Write;
use std::sync::Arc;

fn walk(node: &TrieNode, bits: &mut Vec<u8>, store: &dyn TrieStore, out: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    let start = bits.len();
    for &b in node.shared_path.expand() {
        bits.push(b);
    }

    if let Some(val) = &node.value {
        // Pack the accumulated bit-path back into bytes (MSB-first).
        let key = pack(bits);
        out.push((key, val.clone()));
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
    let data_dir = args.next().expect("usage: dump_state <data-dir> <out-file>");
    let out_path = args.next().expect("usage: dump_state <data-dir> <out-file>");

    let store = BlockStore::open(&data_dir)?;
    let (exec_hash, state_root) = store
        .exec_head()?
        .expect("no exec_head persisted");
    let hdr = store.header(exec_hash)?;
    let number = hdr.as_ref().map(|h| h.number).unwrap_or(0);
    let orchid_root = hdr.as_ref().map(|h| h.state_root);
    eprintln!("exec head #{number} hash={exec_hash:?} unitrie_root={state_root:?}");
    eprintln!("header(orchid) state_root={orchid_root:?}");

    let trie_store: Arc<dyn TrieStore> = Arc::new(RocksDbTrieStore::from_db(store.db().clone()));
    let data = trie_store
        .get(state_root.as_slice())
        .expect("root node not found in trie store");
    let root = TrieNode::from_message(&data, trie_store.as_ref());
    let verified = root.compute_hash(trie_store.as_ref());
    eprintln!("recomputed root = {verified:?} (match={})", verified == state_root);

    let mut leaves = Vec::new();
    let mut bits = Vec::new();
    walk(&root, &mut bits, trie_store.as_ref(), &mut leaves);
    leaves.sort();

    let mut f = std::io::BufWriter::new(std::fs::File::create(&out_path)?);
    for (k, v) in &leaves {
        writeln!(f, "{}={}", hex::encode(k), hex::encode(v))?;
    }
    eprintln!("wrote {} leaves to {out_path}", leaves.len());
    Ok(())
}
