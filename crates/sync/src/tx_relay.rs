use std::num::NonZeroUsize;
use std::sync::Mutex;

use alloy_primitives::{B256, B512, Bytes};
use lru::LruCache;
use rustock_networking::peers::PeerStore;
use rustock_networking::protocol::rsk::{RskMessage, RskSubMessage};
use rustock_networking::protocol::{P2pHandler, P2pMessage};
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use tracing::{debug, trace};

const SEEN_CACHE_SIZE: usize = 32_768;

pub struct TxRelay {
    peer_store: Arc<PeerStore>,
    seen: Mutex<LruCache<B256, ()>>,
}

impl TxRelay {
    pub fn new(peer_store: Arc<PeerStore>) -> Self {
        Self {
            peer_store,
            seen: Mutex::new(LruCache::new(
                NonZeroUsize::new(SEEN_CACHE_SIZE).unwrap(),
            )),
        }
    }

    fn tx_hash(data: &[u8]) -> B256 {
        B256::from_slice(&Keccak256::digest(data))
    }

    fn filter_new_txs(&self, txs: &[Bytes]) -> Vec<Bytes> {
        let mut seen = self.seen.lock().unwrap();
        let mut new_txs = Vec::new();
        for tx in txs {
            let hash = Self::tx_hash(tx);
            if seen.get(&hash).is_none() {
                seen.put(hash, ());
                new_txs.push(tx.clone());
            }
        }
        new_txs
    }

    /// Submit a raw transaction from the RPC layer. Returns the tx hash.
    pub async fn submit_transaction(&self, raw_tx: Bytes) -> B256 {
        let hash = Self::tx_hash(&raw_tx);
        {
            let mut seen = self.seen.lock().unwrap();
            seen.put(hash, ());
        }

        let msg = P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::Transactions(vec![raw_tx]),
        ));
        let sent = self.peer_store.broadcast(msg, &[]).await;
        debug!(tx_hash = %hash, peers = sent, "Broadcast submitted transaction");
        hash
    }
}

impl P2pHandler for TxRelay {
    fn handle_message(&self, id: B512, msg: P2pMessage) -> Option<P2pMessage> {
        if let P2pMessage::RskMessage(m) = msg {
            if let RskSubMessage::Transactions(txs) = m.sub_message {
                let new_txs = self.filter_new_txs(&txs);
                if new_txs.is_empty() {
                    trace!(from = %id, "All transactions already seen, skipping relay");
                    return None;
                }

                debug!(
                    from = %id,
                    total = txs.len(),
                    new = new_txs.len(),
                    "Relaying transactions"
                );

                let relay_msg = P2pMessage::RskMessage(RskMessage::new(
                    RskSubMessage::Transactions(new_txs),
                ));
                let peer_store = self.peer_store.clone();
                let sender = id;
                tokio::spawn(async move {
                    peer_store.broadcast(relay_msg, &[sender]).await;
                });
            }
        }
        None
    }
}
