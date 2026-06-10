//! Re-execute a single canonical block on top of the executed-head state and
//! print per-transaction results (gas, success) plus the rsk_handler frame
//! trace. Deterministic, offline diagnostic for gas/state divergences.
//!
//! Usage: cargo run -p rustock-cli --release --example replay_block -- <data-dir> <number>

use rustock_execution::{RskExecutor, RskHardforkConfig};
use rustock_storage::{BlockStore, CachedTrieStore};
use rustock_trie::{TrieNode, TrieStore};
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    // Frame tracing is read once by a LazyLock; set before any execution.
    std::env::set_var("RUSTOCK_TRACE_FRAMES", "1");
    tracing_subscriber::fmt()
        .with_env_filter("rustock_execution=debug")
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("usage: replay_block <data-dir> <number>");
    let number: u64 = args.next().expect("usage: replay_block <data-dir> <number>").parse()?;

    let store = Arc::new(BlockStore::open(&data_dir)?);
    let (_, state_root) = store.exec_head()?.expect("no exec_head");
    let trie_store: Arc<dyn TrieStore> =
        Arc::new(CachedTrieStore::with_defaults(store.db().clone()));
    let root_data = trie_store.get(state_root.as_slice()).expect("root node");
    let root = TrieNode::from_message(&root_data, trie_store.as_ref());

    let hash = store.canonical_hash(number)?.expect("canonical hash");
    let header = store.header(hash)?.expect("header");
    let (txs, _ommers) = store.body(hash)?.expect("body");

    let with_senders: Vec<_> = txs
        .iter()
        .map(|tx| {
            // The synthetic REMASC tx (v=r=s=0, gas_limit=0) has no signer.
            let is_remasc = tx.v == 0
                && tx.r.is_zero()
                && tx.s.is_zero()
                && tx.gas_limit.is_zero();
            let sender = if is_remasc {
                alloy_primitives::Address::ZERO
            } else {
                tx.recover_sender(30).expect("recover sender")
            };
            (tx.clone(), sender)
        })
        .collect();

    let executor = RskExecutor::new(RskHardforkConfig::mainnet(), store.clone());
    let result = executor.execute_block(&header, &with_senders, &root, trie_store.clone())?;

    eprintln!("=== block #{number} per-tx results ===");
    let mut total = 0u64;
    for (i, r) in result.tx_results.iter().enumerate() {
        eprintln!(
            "  tx[{i}] success={} gas_used={} output_len={}",
            r.success,
            r.gas_used,
            r.output.len()
        );
        total += r.gas_used;
    }
    eprintln!("total gas_used={total}");

    let new_root = rustock_execution::apply_state_changes(
        &root,
        trie_store.as_ref(),
        &result.state_changes,
        &result.markers,
    );
    let computed = new_root.compute_hash(trie_store.as_ref());
    eprintln!(
        "state root: computed={computed:?} header={:?} match={}",
        header.state_root,
        computed.as_slice() == header.state_root.as_slice()
    );
    Ok(())
}
