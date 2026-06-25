//! Rewind the download + executed head to a clean block and drop the canonical
//! pointers above it, so the node re-downloads and re-executes the tail cleanly.
//!
//! Recovers from a corrupted canonical tail (e.g. a buggy-era reorg that left
//! gaps / interleaved forks) WITHOUT a full wipe: everything at or below the
//! target height is preserved; only the canonical number->hash pointers above
//! it are cleared and the heads reset. The next start re-syncs the tail.
//!
//! Usage: cargo run -p rustock-cli --release --example rewind_to -- <data-dir> <number>

use rustock_storage::BlockStore;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("usage: rewind_to <data-dir> <number>");
    let target: u64 = args.next().expect("usage: rewind_to <data-dir> <number>").parse()?;

    let store = BlockStore::open(&data_dir)?;

    let target_hash = store
        .canonical_hash(target)?
        .unwrap_or_else(|| panic!("no canonical hash at #{target}"));
    let header = store
        .header(target_hash)?
        .unwrap_or_else(|| panic!("no header for #{target} {target_hash:?}"));
    let state_root = header.state_root;

    let head_number = store
        .head()?
        .and_then(|h| store.header(h).ok().flatten())
        .map(|h| h.number)
        .unwrap_or(target);

    eprintln!(
        "rewinding to #{target} hash={target_hash:?} state_root={state_root:?}; \
         current download head #{head_number}"
    );

    // Drop canonical pointers above the target so the re-sync rebuilds them.
    let mut cleared = 0u64;
    for n in (target + 1)..=head_number {
        if store.canonical_hash(n)?.is_some() {
            store.delete_canonical_hash(n)?;
            cleared += 1;
        }
    }

    store.set_head(target_hash)?;
    store.set_exec_head(target_hash, state_root)?;

    eprintln!(
        "done: cleared {cleared} canonical pointers (#{}..#{head_number}); \
         head and exec_head reset to #{target}. Next start re-syncs the tail.",
        target + 1
    );
    Ok(())
}
