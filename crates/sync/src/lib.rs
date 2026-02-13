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
    /// Validates them sequentially and inserts into storage.
    pub fn handle_headers_response(&self, headers: Vec<Header>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        debug!(target: "rustock::sync", "Processing {} headers", headers.len());

        for header in headers {
            let hash = header.hash();
            
            // 1. Check if we already have it
            if self.store.get_header(hash)?.is_some() {
                continue;
            }

            // 2. Get parent to verify
            let parent = self.store.get_header(header.parent_hash)?;
            if parent.is_none() && header.number > 0 {
                return Err(anyhow::anyhow!("Parent header not found for block #{}", header.number));
            }
            
            // 3. Verify header
            self.verifier.verify(&header, parent.as_ref())
                .context("Header verification failed during sync")?;

            // 4. Update head (this also stores the header and canonical mapping)
            let parent_td = match parent {
                Some(p) => self.store.get_total_difficulty(p.hash())?.unwrap_or_default(),
                None => alloy_primitives::U256::ZERO, 
            };
            
            let new_td = parent_td + header.difficulty;
            
            // Check if this header actually extends the best chain
            let current_head_hash = self.store.get_head()?;
            let current_td = match current_head_hash {
                Some(h) => self.store.get_total_difficulty(h)?.unwrap_or_default(),
                None => alloy_primitives::U256::ZERO,
            };

            if new_td > current_td {
                self.store.update_head(&header, new_td)?;
                info!(target: "rustock::sync", "Chain head updated to block #{} (hash: {})", header.number, hash);
            } else {
                // Just store the header if it's not the best chain yet (ommer/sidechain)
                self.store.put_header(&header)?;
                self.store.put_total_difficulty(hash, new_td)?;
                debug!(target: "rustock::sync", "Stored sidechain header #{} (hash: {})", header.number, hash);
            }
        }

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
}

impl SyncHandler {
    pub fn new(manager: Arc<SyncManager>) -> Self {
        Self { manager }
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
                        client_id: "".to_string(), // TODO: Get from Hello
                    };
                    let peer_store = self.manager.peer_store.clone();
                    tokio::spawn(async move {
                        peer_store.update_metadata(&id, metadata).await;
                    });
                }
                RskSubMessage::BlockHeadersResponse(r) => {
                    if let Err(e) = self.manager.handle_headers_response(r.headers) {
                        error!(target: "rustock::sync", "Failed to process headers response from {:?}: {:?}", id, e);
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// A background service that periodically initiates synchronization.
pub struct SyncService {
    manager: Arc<SyncManager>,
    peer_store: Arc<rustock_networking::peers::PeerStore>,
}

impl SyncService {
    pub fn new(manager: Arc<SyncManager>, peer_store: Arc<rustock_networking::peers::PeerStore>) -> Self {
        Self { manager, peer_store }
    }

    pub async fn start(self) {
        info!(target: "rustock::sync", "Sync service started");
        loop {
            if let Err(e) = self.sync_step().await {
                debug!(target: "rustock::sync", "Sync step failed: {:?}", e);
            }
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
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
            None => return Ok(()), // Should not happen after setup_genesis
        };

        let our_td = self.manager.store.get_total_difficulty(head_hash)?.unwrap_or_default();
        
        // Only sync if peer is better than us
        if metadata.total_difficulty > our_td {
            let head_header = self.manager.store.get_header(head_hash)?
                .context("Current head header missing from store")?;

            let blocks_behind = if metadata.best_number > head_header.number {
                metadata.best_number - head_header.number
            } else {
                0
            };

            if blocks_behind > 0 {
                let count = blocks_behind.min(100) as u32;
                let msg = self.manager.create_headers_request(head_hash, count);
                
                info!(target: "rustock::sync", "Requesting {} headers from best peer {:?} (#{} -> #{})", count, peer_id, head_header.number, head_header.number + count as u64);
                self.peer_store.send_to_peer(&peer_id, msg).await;
            }
        }
        
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

        // 4. Gap block (should fail verification because parent not found or verification error)
        let b4 = dummy_header(4, B256::repeat_byte(0xee), U256::from(1));
        let res = manager.handle_headers_response(vec![b4]);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_sync_handler() {
        use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
        use rustock_networking::protocol::P2pHandler;
        
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        
        let verifier = Arc::new(HeaderVerifier::new()); // Stub verifier
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store));
        let handler = SyncHandler::new(manager.clone());

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
