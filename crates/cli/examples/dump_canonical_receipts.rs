//! Decode the canonical TransactionReceipts for a block from the snapshot
//! receipts DB and print each receipt's fields (postTxState, cumulativeGas,
//! gasUsed, status, bloom, #logs). Receipts DB is keyed by txHash ->
//! RLP[ TransactionInfo[ [receiptRLP, blockHash, index], ... ] ].
//!
//! Usage: cargo run -p rustock-cli --release --example dump_canonical_receipts -- \
//!   <data-dir> <number> <snapshot-receipts-leveldb-dir>

use alloy_rlp::Header as RlpHeader;
use rocksdb::{DB, Options};
use rustock_core::Receipt;
use rustock_storage::BlockStore;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("data-dir");
    let number: u64 = args.next().expect("number").parse()?;
    let receipts_dir = args.next().expect("snapshot receipts dir");

    let store = BlockStore::open(&data_dir)?;
    let hash = store.canonical_hash(number)?.expect("canonical hash");
    let (txs, _) = store.body(hash)?.expect("body");

    let opts = Options::default();
    let rdb = DB::open_for_read_only(&opts, &receipts_dir, false)?;

    for (i, tx) in txs.iter().enumerate() {
        let txh = tx.tx_hash();
        // V2 format: combined key = txHash ++ blockHash -> TransactionInfo [receipt, blockHash, index]
        let mut key = txh.as_slice().to_vec();
        key.extend_from_slice(hash.as_slice());
        let ti_bytes = rdb.get(&key)?.expect("V2 combined-key receipt entry");
        // ti_bytes = RLP[ receiptRLP, blockHash, index ]
        let mut buf = ti_bytes.as_slice();
        let outer = RlpHeader::decode(&mut buf).unwrap();
        let mut body = &buf[..outer.payload_length];
        // receiptRLP is the first element (a list)
        let r_start: &[u8] = body;
        let r_hdr = RlpHeader::decode(&mut body).unwrap();
        let header_len = r_start.len() - body.len();
        let receipt_len = header_len + r_hdr.payload_length;
        let receipt_rlp = r_start[..receipt_len].to_vec();
        let receipt = Receipt::decode(&mut receipt_rlp.as_slice()).unwrap();
        println!(
            "tx[{i}] {txh:?} status={} postTxState={} cumGas={} gasUsed={} logs={} bloom_nonzero={}",
            receipt.status,
            hex::encode(&receipt.post_tx_state),
            receipt.cumulative_gas_used,
            receipt.gas_used,
            receipt.logs.len(),
            receipt.logs_bloom != alloy_primitives::Bloom::ZERO,
        );
        println!("    receipt_rlp=0x{}", hex::encode(&receipt_rlp));
    }
    Ok(())
}

use alloy_rlp::Decodable;
