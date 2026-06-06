//! Throwaway diagnostic: find blocks where header.paid_fees (rskj's actual
//! REMASC inflow, consensus-validated by rskj) differs from the naive
//! sum of gasUsed * gasPrice over the block's stored receipts.
//!
//! Usage: cargo run -p rustock-storage --release --example scan_remasc -- <data-dir> <from> <to>

use alloy_primitives::U256;
use rustock_storage::BlockStore;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("data dir");
    let from: u64 = args.next().expect("from").parse()?;
    let to: u64 = args.next().expect("to").parse()?;

    let store = BlockStore::open(&dir)?;
    let mut scanned = 0u64;
    let mut total_diff = U256::ZERO;
    for n in from..=to {
        let Some(hash) = store.canonical_hash(n)? else { continue };
        let Some(header) = store.header(hash)? else { continue };
        let Some((txs, _uncles)) = store.body(hash)? else { continue };
        let Some(receipts) = store.receipts(hash)? else { continue };
        let naive: U256 = txs
            .iter()
            .zip(&receipts)
            .map(|(tx, r)| tx.gas_price * U256::from(r.gas_used))
            .sum();
        if naive != header.paid_fees {
            let (hi, lo, sign) = if naive > header.paid_fees {
                (naive, header.paid_fees, "naive>header")
            } else {
                (header.paid_fees, naive, "header>naive")
            };
            println!(
                "block #{n}: paid_fees={} naive={} diff={} ({sign})",
                header.paid_fees,
                naive,
                hi - lo,
            );
            total_diff += hi - lo;
        }
        scanned += 1;
        if scanned % 200_000 == 0 {
            eprintln!("...scanned to #{n}");
        }
    }
    println!("total abs diff: {total_diff}");
    Ok(())
}
