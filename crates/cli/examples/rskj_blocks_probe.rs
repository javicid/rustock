//! Probe: can RocksDB open rskj's `blocks` LevelDB, and how far does it reach?
//!
//! rskj stores `hash(32) -> block.getEncoded()` (RLP of [header, txs, ommers])
//! in a LevelDB at <rsk-data>/database/blocks (with a nested MapDB `index`
//! dir we ignore). We open it read-only, decode a sample of values to confirm
//! the format is readable from Rust, and scan for the max block number.
//!
//! Usage: cargo run -p rustock-cli --release --example rskj_blocks_probe -- <blocks-leveldb-dir> [--full]

use alloy_rlp::Decodable;
use rocksdb::{DB, Options, IteratorMode};
use rustock_core::Block;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: rskj_blocks_probe <blocks-leveldb-dir> [--full]");
    let full = args.next().as_deref() == Some("--full");

    let opts = Options::default();
    let db = DB::open_for_read_only(&opts, &path, false)?;
    println!("opened {path} read-only");

    let mut count = 0u64;
    let mut decoded = 0u64;
    let mut max_number = 0u64;
    let mut max_hash = None;
    let mut sample_shown = 0;

    for item in db.iterator(IteratorMode::Start) {
        let (k, v) = item?;
        count += 1;
        // Block records are keyed by 32-byte hash; skip MapDB/metadata keys.
        if k.len() != 32 {
            continue;
        }
        match Block::decode(&mut &v[..]) {
            Ok(b) => {
                decoded += 1;
                let n = b.header.number;
                if n > max_number {
                    max_number = n;
                    max_hash = Some(b.hash());
                }
                if sample_shown < 3 {
                    println!("  sample: #{n} hash={:?} txs={} ommers={}", b.hash(), b.transactions.len(), b.ommers.len());
                    sample_shown += 1;
                }
            }
            Err(e) => {
                if sample_shown < 3 {
                    println!("  decode error on {}-byte value: {e:?}", v.len());
                }
            }
        }
        if !full && decoded >= 5 {
            println!("(sample mode: stop after 5 decoded; pass --full to scan all)");
            break;
        }
    }

    println!("scanned_entries={count} decoded_blocks={decoded} max_number={max_number} max_hash={max_hash:?}");
    Ok(())
}
