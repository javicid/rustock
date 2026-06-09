//! Diagnostic: scan canonical block bodies for transactions whose `to` (or
//! sender, via recovered address) involves a target address. Used to locate the
//! block/op that creates a given account in rskj but not rustock.
//!
//! Usage: cargo run -p rustock-cli --release --example scan_addr -- <data-dir> <hex-addr>...

use rustock_storage::BlockStore;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("usage: scan_addr <data-dir> <hex-addr>...");
    let targets: Vec<Vec<u8>> = args
        .map(|a| alloy_primitives::hex::decode(a.trim_start_matches("0x")).expect("hex addr"))
        .collect();
    assert!(!targets.is_empty(), "provide at least one address");

    let store = BlockStore::open(&data_dir)?;
    let tip = store.exec_head()?.map(|(h, _)| store.header(h).ok().flatten().map(|x| x.number).unwrap_or(0)).unwrap_or(0);
    let scan_to = tip.max(1_591_001).min(1_591_001);
    eprintln!("scanning canonical blocks 0..={scan_to} for {} target(s)", targets.len());

    for n in 0..=scan_to {
        let Some(hash) = store.canonical_hash(n)? else { continue };
        if let Some(hdr) = store.header(hash)? {
            for t in &targets {
                if hdr.beneficiary.as_slice() == t.as_slice() {
                    println!("block #{n} BENEFICIARY 0x{}", alloy_primitives::hex::encode(t));
                }
            }
        }
        let Some((txs, ommers)) = store.body(hash)? else { continue };
        for om in &ommers {
            for t in &targets {
                if om.beneficiary.as_slice() == t.as_slice() {
                    println!("block #{n} OMMER #{} BENEFICIARY 0x{}", om.number, alloy_primitives::hex::encode(t));
                }
            }
        }
        for (i, tx) in txs.iter().enumerate() {
            let to = tx.to.as_ref();
            for t in &targets {
                if to == t.as_slice() {
                    println!(
                        "block #{n} tx[{i}] TO 0x{} value={} data_len={}",
                        alloy_primitives::hex::encode(t),
                        tx.value,
                        tx.input.len()
                    );
                }
                // also flag the address appearing anywhere in calldata
                if tx.input.windows(20).any(|w| w == t.as_slice()) {
                    println!(
                        "block #{n} tx[{i}] CALLDATA contains 0x{} (to=0x{} value={})",
                        alloy_primitives::hex::encode(t),
                        alloy_primitives::hex::encode(to),
                        tx.value
                    );
                }
            }
        }
    }
    eprintln!("scan complete");
    Ok(())
}
