//! Re-execute canonical blocks from the executed head up to a target block
//! (in memory, nothing persisted) and report the target's per-transaction
//! results, logs, and computed state/receipts roots vs the header.
//! Deterministic, offline diagnostic for gas/state/receipts divergences.
//!
//! Usage: cargo run -p rustock-cli --release --example replay_block -- <data-dir> <number>

use rustock_core::Block;
use rustock_execution::{BlockProcessor, RskHardforkConfig};
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
    let (exec_hash, state_root) = store.exec_head()?.expect("no exec_head");
    let exec_number = store.header(exec_hash)?.expect("exec head header").number;
    assert!(number > exec_number, "target #{number} not past exec head #{exec_number}");

    let trie_store: Arc<dyn TrieStore> =
        Arc::new(CachedTrieStore::with_defaults(store.db().clone()));
    let root_data = trie_store.get(state_root.as_slice()).expect("root node");
    let mut root = TrieNode::from_message(&root_data, trie_store.as_ref());

    let processor = BlockProcessor::new(RskHardforkConfig::mainnet(), store.clone());

    for n in exec_number + 1..=number {
        // The all-ops tracer flag is read per execute_block; enable it only
        // for the target block so range replays stay tractable.
        if n == number && std::env::var_os("RUSTOCK_TRACE_TARGET_OPS").is_some() {
            std::env::set_var("RUSTOCK_TRACE_ALL_OPS", "1");
        }
        let hash = store.canonical_hash(n)?.expect("canonical hash");
        let header = store.header(hash)?.expect("header");
        let (transactions, ommers) = store.body(hash)?.expect("body");
        let block = Block { header, transactions, ommers };
        let processed = processor.execute_block(&block, &root, trie_store.clone())?;

        if n < number {
            if processed.state_root_hash.as_slice() != block.header.state_root.as_slice() {
                eprintln!(
                    "intermediate block #{n} state diverges: computed={:?} header={:?}",
                    processed.state_root_hash, block.header.state_root
                );
            }
            if processed.receipts_root != block.header.receipts_root {
                eprintln!(
                    "intermediate block #{n} receipts diverges: computed={:?} header={:?}",
                    processed.receipts_root, block.header.receipts_root
                );
            }
            root = processed.new_state_root;
            continue;
        }

        eprintln!("=== block #{n} per-tx results ===");
        for (i, r) in processed.receipts.iter().enumerate() {
            eprintln!("  tx[{i}] status={:?} gas_used={}", r.status, r.gas_used);
            for log in &r.logs {
                eprintln!("    log address={:?}", log.address);
                for t in &log.topics {
                    eprintln!("      topic {t:?}");
                }
                eprintln!("      data 0x{}", alloy_primitives::hex::encode(&log.data));
            }
        }
        eprintln!("total gas_used={}", processed.gas_used);
        eprintln!(
            "state root:    computed={:?} header={:?} match={}",
            processed.state_root_hash,
            block.header.state_root,
            processed.state_root_hash.as_slice() == block.header.state_root.as_slice()
        );
        eprintln!(
            "receipts root: computed={:?} header={:?} match={}",
            processed.receipts_root,
            block.header.receipts_root,
            processed.receipts_root == block.header.receipts_root
        );
    }
    Ok(())
}
