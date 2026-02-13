use rustock_core::validation::HeaderVerifier;
use rustock_core::types::header::Header;
use rustock_storage::BlockStore;
use rustock_networking::protocol::{RskMessage, RskSubMessage, BlockHeadersRequest, BlockHeadersQuery, P2pMessage};
use alloy_primitives::B256;
use anyhow::{Result, Context};
use std::sync::Arc;
use tracing::{info, debug, error};

/// Coordinates the synchronization of the blockchain with peers.
pub struct SyncManager {
    store: Arc<BlockStore>,
    verifier: Arc<HeaderVerifier>,
    pub peer_store: Arc<rustock_networking::peers::PeerStore>,
}

impl SyncManager {
    pub fn new(
        store: Arc<BlockStore>,
        verifier: Arc<HeaderVerifier>,
        peer_store: Arc<rustock_networking::peers::PeerStore>,
    ) -> Self {
        Self { store, verifier, peer_store }
    }

    /// Handles a batch of headers received from a peer.
    /// RSK peers return headers in descending order (from requested hash toward genesis).
    /// We reverse them and store sequentially.
    pub fn handle_headers_response(&self, mut headers: Vec<Header>) -> Result<()> {
        if headers.is_empty() {
            debug!(target: "rustock::sync", "Received empty headers response");
            return Ok(());
        }

        // RSK returns headers in descending order; reverse for ascending processing
        if headers.len() > 1 && headers[0].number > headers[headers.len() - 1].number {
            headers.reverse();
        }

        let first_num = headers.first().map(|h| h.number).unwrap_or(0);
        let last_num = headers.last().map(|h| h.number).unwrap_or(0);
        info!(target: "rustock::sync", "Processing {} headers (#{} -> #{})", headers.len(), first_num, last_num);

        for header in &headers {
            let hash = header.hash();
            
            // Skip if we already have it
            if self.store.get_header(hash)?.is_some() {
                continue;
            }

            // During initial sync we may receive headers whose parents we haven't
            // downloaded yet (e.g. the lowest block in a backward batch).  Store
            // them anyway so we can link them later.
            let parent = self.store.get_header(header.parent_hash)?;

            // Only run full verification when we have the parent
            if let Some(ref p) = parent {
                if let Err(e) = self.verifier.verify(header, Some(p)) {
                    debug!(target: "rustock::sync", "Header #{} failed verification: {:?}", header.number, e);
                    // Store it anyway during download; verification can be re-done later
                }
            }

            // Compute total difficulty
            let parent_td = match &parent {
                Some(p) => self.store.get_total_difficulty(p.hash())?.unwrap_or_default(),
                None => alloy_primitives::U256::ZERO, 
            };
            let new_td = parent_td + header.difficulty;

            // Store header and update head if this is the highest block
            let current_head_hash = self.store.get_head()?;
            let current_td = match current_head_hash {
                Some(h) => self.store.get_total_difficulty(h)?.unwrap_or_default(),
                None => alloy_primitives::U256::ZERO,
            };

            if new_td > current_td {
                self.store.update_head(header, new_td)?;
            } else {
                self.store.put_header(header)?;
                self.store.put_total_difficulty(hash, new_td)?;
            }
        }

        info!(target: "rustock::sync", "Stored headers up to #{}", last_num);
        Ok(())
    }

    /// Helper to create a headers request message.
    pub fn create_headers_request(&self, start_hash: B256, count: u32) -> P2pMessage {
        let req = BlockHeadersRequest {
            id: rand::random(),
            query: BlockHeadersQuery {
                hash: start_hash,
                count,
            },
        };
        P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)))
    }
}

/// A handler that processes inbound headers responses and feeds them to the SyncManager.
pub struct SyncHandler {
    manager: Arc<SyncManager>,
    sync_service: Arc<SyncService>,
}

impl SyncHandler {
    pub fn new(manager: Arc<SyncManager>, sync_service: Arc<SyncService>) -> Self {
        Self { manager, sync_service }
    }
}

impl rustock_networking::protocol::P2pHandler for SyncHandler {
    fn handle_message(&self, id: alloy_primitives::B512, msg: P2pMessage) -> Option<P2pMessage> {
        if let P2pMessage::RskMessage(m) = msg {
            match m.sub_message {
                RskSubMessage::Status(s) => {
                    info!(target: "rustock::sync", "Received status from peer {:?}: #{} (TD: {:?})", id, s.best_block_number, s.total_difficulty);
                    let metadata = rustock_networking::peers::PeerMetadata {
                        best_number: s.best_block_number,
                        best_hash: s.best_block_hash,
                        total_difficulty: s.total_difficulty.unwrap_or_default(),
                        client_id: "".to_string(),
                    };
                    let peer_store = self.manager.peer_store.clone();
                    tokio::spawn(async move {
                        peer_store.update_metadata(&id, metadata).await;
                    });
                }
                RskSubMessage::BlockHeadersResponse(r) => {
                    // Track the lowest block in the response to update the sync frontier
                    let lowest_hash = if !r.headers.is_empty() {
                        // Headers may be in descending order — find the one with the lowest number
                        r.headers.iter()
                            .min_by_key(|h| h.number)
                            .map(|h| h.parent_hash) // The PARENT of the lowest is our next frontier
                    } else {
                        None
                    };

                    match self.manager.handle_headers_response(r.headers) {
                        Ok(()) => {
                            if let Some(hash) = lowest_hash {
                                let svc = self.sync_service.clone();
                                tokio::spawn(async move {
                                    svc.update_frontier(hash).await;
                                });
                            }
                        }
                        Err(e) => {
                            error!(target: "rustock::sync", "Failed to process headers response from {:?}: {:?}", id, e);
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// A background service that periodically initiates synchronization.
/// RSK peers return headers backward (descending), so we request from the
/// peer's best hash and work our way toward genesis.
pub struct SyncService {
    manager: Arc<SyncManager>,
    peer_store: Arc<rustock_networking::peers::PeerStore>,
    /// The lowest block hash we've downloaded so far (our "sync frontier").
    /// We request backward from here next time.
    sync_frontier: tokio::sync::Mutex<Option<B256>>,
}

impl SyncService {
    pub fn new(manager: Arc<SyncManager>, peer_store: Arc<rustock_networking::peers::PeerStore>) -> Self {
        Self { manager, peer_store, sync_frontier: tokio::sync::Mutex::new(None) }
    }

    /// Called by the SyncHandler when we receive headers to update the frontier.
    pub async fn update_frontier(&self, lowest_hash: B256) {
        let mut frontier = self.sync_frontier.lock().await;
        *frontier = Some(lowest_hash);
    }

    pub async fn start(self: Arc<Self>) {
        info!(target: "rustock::sync", "Sync service started");
        loop {
            if let Err(e) = self.sync_step().await {
                debug!(target: "rustock::sync", "Sync step failed: {:?}", e);
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    async fn sync_step(&self) -> Result<()> {
        let best_peer = self.peer_store.get_best_peer().await;
        if best_peer.is_none() {
            return Ok(());
        }
        let (peer_id, metadata) = best_peer.unwrap();

        // Check our current head
        let head_hash = match self.manager.store.get_head()? {
            Some(h) => h,
            None => {
                return Ok(());
            }
        };
        let head_header = self.manager.store.get_header(head_hash)?
            .context("Current head header missing from store")?;

        // Determine which hash to request backward from:
        // - If we have a sync frontier (from a previous response), use it to
        //   continue downloading backward.
        // - Otherwise start from the peer's best hash.
        let frontier = self.sync_frontier.lock().await.clone();
        let request_from = frontier.unwrap_or(metadata.best_hash);

        // Don't request if we've reached genesis
        let genesis_hash = self.manager.store.get_canonical_hash(0)?.unwrap_or_default();
        if request_from == genesis_hash {
            if head_header.number < metadata.best_number {
                debug!(target: "rustock::sync", "Reached genesis, head at #{}", head_header.number);
            }
            return Ok(());
        }

        let count = 100u32;
        let msg = self.manager.create_headers_request(request_from, count);
        info!(target: "rustock::sync", "Requesting {} headers backward from {:?} (our head: #{})",
              count, request_from, head_header.number);
        let _sent = self.peer_store.send_to_peer(&peer_id, msg).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256, Bytes, B512};
    use tempfile::tempdir;

    fn dummy_header(number: u64, parent: B256, difficulty: U256) -> Header {
        Header {
            number,
            parent_hash: parent,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty,
            gas_limit: U256::from(8_000_000),
            gas_used: 0,
            timestamp: number * 15, // Simple linear time
            extra_data: Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
        }
    }

    #[tokio::test]
    async fn test_sync_manager_processing() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        
        // Setup genesis
        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

        // Use a simple verifier without MM rule for unit testing SyncManager logic
        let verifier = Arc::new(HeaderVerifier::new()
            .with_parent_rule(rustock_core::validation::BlockNumberRule)
            .with_parent_rule(rustock_core::validation::ParentHashRule));
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = SyncManager::new(store.clone(), verifier, peer_store);

        // 1. Valid sequential block
        let b1 = dummy_header(1, genesis_hash, U256::from(10));
        manager.handle_headers_response(vec![b1.clone()]).unwrap();

        assert_eq!(store.get_head().unwrap(), Some(b1.hash()));
        assert_eq!(store.get_total_difficulty(b1.hash()).unwrap(), Some(U256::from(11)));

        // 2. Duplicate block (should be ignored)
        manager.handle_headers_response(vec![b1.clone()]).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(b1.hash()));

        // 3. Sidechain block (lower difficulty)
        let b2_side = dummy_header(2, b1.hash(), U256::from(5));
        manager.handle_headers_response(vec![b2_side.clone()]).unwrap();
        
        // Head should still be b1 (Wait, b2_side extends b1, so it should be the head)
        // b2_side has TD = 11 + 5 = 16. Current head b1 has TD 11. 
        // So b2_side SHOULD become the new head.
        assert_eq!(store.get_head().unwrap(), Some(b2_side.hash()));

        // 4. Gap block (parent unknown) — stored anyway during initial sync with
        //    TD = difficulty (parent_td defaults to 0). Should NOT become head
        //    because its TD (1) < current head TD (16).
        let b4 = dummy_header(4, B256::repeat_byte(0xee), U256::from(1));
        let b4_hash = b4.hash();
        manager.handle_headers_response(vec![b4]).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(b2_side.hash()), "Head should not change");
        assert!(store.get_header(b4_hash).unwrap().is_some(), "Gap block should be stored");
        assert_eq!(store.get_total_difficulty(b4_hash).unwrap(), Some(U256::from(1)));
    }

    #[tokio::test]
    async fn test_sync_handler() {
        use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
        use rustock_networking::protocol::P2pHandler;
        
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        
        let verifier = Arc::new(HeaderVerifier::new()); // Stub verifier
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
        let sync_service = Arc::new(SyncService::new(manager.clone(), peer_store));
        let handler = SyncHandler::new(manager.clone(), sync_service);

        let h0 = dummy_header(0, B256::ZERO, U256::from(10));
        let resp = rustock_networking::protocol::rsk::BlockHeadersResponse {
            id: 1,
            headers: vec![h0.clone()],
        };
        let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersResponse(resp)));
        
        let handler_resp = handler.handle_message(B512::ZERO, msg);
        assert!(handler_resp.is_none());
        
        // Header should be in store
        assert!(store.get_header(h0.hash()).unwrap().is_some());
    }
}
