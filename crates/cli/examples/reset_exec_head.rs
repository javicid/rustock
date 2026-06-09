//! Reset execution to genesis WITHOUT discarding downloaded blocks.
//!
//! Clears the `exec_head` marker so the next node start replays execution
//! from genesis, reusing the already-downloaded headers and bodies instead
//! of re-fetching the whole chain from peers. Use this (rather than wiping
//! the data dir) after a state-invalidating fix, to re-validate against the
//! consensus state roots without paying for a full re-download.
//!
//! Usage: cargo run -p rustock-cli --release --example reset_exec_head -- <data-dir>

use rustock_storage::BlockStore;

fn main() -> anyhow::Result<()> {
    let data_dir = std::env::args()
        .nth(1)
        .expect("usage: reset_exec_head <data-dir>");

    let store = BlockStore::open(&data_dir)?;
    match store.exec_head()? {
        Some((hash, root)) => {
            let number = store.header(hash)?.map(|h| h.number).unwrap_or(0);
            eprintln!("clearing exec_head at #{number} hash={hash:?} root={root:?}");
        }
        None => eprintln!("exec_head already empty"),
    }
    let head = store.head()?;
    store.clear_exec_head()?;
    eprintln!(
        "exec_head cleared; download head retained at {head:?}. Next start replays from genesis."
    );
    Ok(())
}
