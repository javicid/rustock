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

use crate::txpool::TransactionPool;

const SEEN_CACHE_SIZE: usize = 32_768;

pub struct TxRelay {
    peer_store: Arc<PeerStore>,
    seen: Mutex<LruCache<B256, ()>>,
    pool: Option<Arc<TransactionPool>>,
}

impl TxRelay {
    pub fn new(peer_store: Arc<PeerStore>) -> Self {
        Self {
            peer_store,
            seen: Mutex::new(LruCache::new(
                NonZeroUsize::new(SEEN_CACHE_SIZE).expect("SEEN_CACHE_SIZE is non-zero"),
            )),
            pool: None,
        }
    }

    pub fn with_pool(peer_store: Arc<PeerStore>, pool: Arc<TransactionPool>) -> Self {
        Self {
            peer_store,
            seen: Mutex::new(LruCache::new(
                NonZeroUsize::new(SEEN_CACHE_SIZE).expect("SEEN_CACHE_SIZE is non-zero"),
            )),
            pool: Some(pool),
        }
    }

    fn tx_hash(data: &[u8]) -> B256 {
        B256::from_slice(&Keccak256::digest(data))
    }

    fn filter_and_validate(&self, txs: &[Bytes]) -> Vec<Bytes> {
        let mut seen = self.seen.lock().expect("seen cache lock poisoned");
        let mut valid_txs = Vec::new();
        for tx_bytes in txs {
            let hash = Self::tx_hash(tx_bytes);
            if seen.get(&hash).is_some() {
                continue;
            }
            seen.put(hash, ());

            if let Some(pool) = &self.pool {
                match pool.add_transaction(tx_bytes) {
                    Ok(_) => valid_txs.push(tx_bytes.clone()),
                    Err(e) => {
                        trace!(tx_hash = %hash, err = %e, "Rejected incoming transaction");
                    }
                }
            } else {
                valid_txs.push(tx_bytes.clone());
            }
        }
        valid_txs
    }

    /// Submit a raw transaction from the RPC layer. Returns the tx hash or an error.
    pub async fn submit_transaction(&self, raw_tx: Bytes) -> Result<B256, String> {
        let hash = if let Some(pool) = &self.pool {
            pool.add_transaction(&raw_tx).map_err(|e| format!("{e}"))?
        } else {
            Self::tx_hash(&raw_tx)
        };

        {
            let mut seen = self.seen.lock().expect("seen cache lock poisoned");
            seen.put(hash, ());
        }

        let msg = P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::Transactions(vec![raw_tx]),
        ));
        let sent = self.peer_store.broadcast(msg, &[]).await;
        debug!(tx_hash = %hash, peers = sent, "Broadcast submitted transaction");
        Ok(hash)
    }

    pub fn pool(&self) -> Option<&Arc<TransactionPool>> {
        self.pool.as_ref()
    }
}

impl P2pHandler for TxRelay {
    fn handle_message(&self, id: B512, msg: &P2pMessage) -> Option<P2pMessage> {
        if let P2pMessage::RskMessage(m) = msg {
            if let RskSubMessage::Transactions(txs) = &m.sub_message {
                let valid_txs = self.filter_and_validate(txs);
                if valid_txs.is_empty() {
                    trace!(from = %id, "No valid new transactions to relay");
                    return None;
                }

                debug!(
                    from = %id,
                    total = txs.len(),
                    valid = valid_txs.len(),
                    "Relaying validated transactions"
                );

                let relay_msg = P2pMessage::RskMessage(RskMessage::new(
                    RskSubMessage::Transactions(valid_txs),
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
