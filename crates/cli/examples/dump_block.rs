//! Print a canonical block's header essentials and a per-transaction summary.
//!
//! Usage: cargo run -p rustock-cli --release --example dump_block -- <data-dir> <number>

use rustock_storage::BlockStore;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("usage: dump_block <data-dir> <number>");
    let number: u64 = args.next().expect("usage: dump_block <data-dir> <number>").parse()?;

    let store = BlockStore::open(&data_dir)?;
    let hash = store.canonical_hash(number)?.expect("no canonical hash for number");
    let hdr = store.header(hash)?.expect("no header");
    println!("#{number} hash={hash:?}");
    println!("  parent={:?}", hdr.parent_hash);
    println!("  state_root={:?}", hdr.state_root);
    println!("  gas_used={} gas_limit={}", hdr.gas_used, hdr.gas_limit);
    println!("  coinbase={:?}", hdr.beneficiary);

    match store.body(hash)? {
        Some((txs, ommers)) => {
            println!("  ommers={}", ommers.len());
            println!("  txs={}", txs.len());
            for (i, tx) in txs.iter().enumerate() {
                let to = if tx.to.is_empty() {
                    "CREATE".to_string()
                } else {
                    format!("0x{}", hex::encode(&tx.to))
                };
                println!(
                    "    [{i}] nonce={} to={to} value={} gas_limit={} gas_price={} input_len={}",
                    tx.nonce,
                    tx.value,
                    tx.gas_limit,
                    tx.gas_price,
                    tx.input.len(),
                );
                if !tx.input.is_empty() {
                    let head = &tx.input[..tx.input.len().min(4)];
                    println!("        selector=0x{}", hex::encode(head));
                }
            }
        }
        None => println!("  (no body stored)"),
    }
    Ok(())
}
