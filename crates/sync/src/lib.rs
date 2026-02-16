use rustock_core::validation::HeaderVerifier;
use rustock_core::types::header::Header;
use rustock_storage::BlockStore;
use rustock_networking::protocol::{
    RskMessage, RskSubMessage, BlockHeadersRequest, BlockHeadersQuery, P2pMessage,
    BlockHashRequest, SkeletonRequest, BlockIdentifier,
};
use alloy_primitives::{B256, B512};
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, debug, warn, error};

/// rskj caps header responses at CHUNK_SIZE = 192 (RskSystemProperties.java).
/// The skeleton naturally determines chunk sizes, but we clamp at this limit.
const _CHUNK_SIZE: u32 = 192;
/// Maximum skeleton chunks to process per round (rskj default: 20).
const MAX_SKELETON_CHUNKS: usize = 20;
/// Timeout for pending requests before resetting to Idle.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// SyncEvent — forwarded from SyncHandler to the SyncService state machine
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SyncEvent {
    BlockHashResponse { peer: B512, hash: B256 },
    SkeletonResponse { peer: B512, identifiers: Vec<BlockIdentifier> },
    HeadersResponse { peer: B512, headers: Vec<Header> },
}

// ---------------------------------------------------------------------------
// SyncState — the state machine
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum SyncState {
    /// Waiting for peers / nothing to do.
    Idle,
    /// Binary-searching for the last block we share with the peer.
    FindingConnectionPoint {
        peer: B512,
        peer_best: u64,
        start: u64,
        end: u64,
    },
    /// Waiting for the skeleton response.
    DownloadingSkeleton {
        peer: B512,
        peer_best: u64,
        connection_point: u64,
    },
    /// Downloading header chunks along the skeleton.
    DownloadingHeaders {
        peer: B512,
        peer_best: u64,
        skeleton: Vec<BlockIdentifier>,
        connection_point: u64,
        next_chunk_index: usize,
    },
}

impl Default for SyncState {
    fn default() -> Self {
        SyncState::Idle
    }
}

// ---------------------------------------------------------------------------
// SyncManager — validates and stores headers (unchanged logic)
// ---------------------------------------------------------------------------

pub struct SyncManager {
    pub store: Arc<BlockStore>,
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

        let mut stored = 0u64;
        let mut skipped = 0u64;

        for header in &headers {
            let hash = header.hash();

            // Skip if we already have it
            if self.store.get_header(hash)?.is_some() {
                continue;
            }

            // During initial sync we may receive headers whose parents we haven't
            // downloaded yet (e.g. the lowest block in a backward batch).  Store
            // them tentatively so we can link them later.  Only the very first
            // header in each ascending batch should hit this path.
            let parent = self.store.get_header(header.parent_hash)?;

            // When we have the parent, run full verification and reject on failure.
            if let Some(ref p) = parent {
                if let Err(e) = self.verifier.verify(header, Some(p)) {
                    debug!(target: "rustock::sync", "Header #{} ({:?}) failed verification, skipping: {:?}", header.number, hash, e);
                    skipped += 1;
                    continue;
                }
            }

            // Compute total difficulty.
            // For the parent TD lookup, use the hash that was used to find the parent
            // in the store (header.parent_hash), NOT parent.hash() — they may differ
            // for the genesis block whose canonical hash comes from Java's non-standard
            // RLP encoding.
            let parent_td = match &parent {
                Some(_) => self.store.get_total_difficulty(header.parent_hash)?.unwrap_or_default(),
                None => alloy_primitives::U256::ZERO,
            };
            let new_td = parent_td + header.difficulty;

            // Store header and update head if this is the highest-TD block
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
            stored += 1;
        }

        if skipped > 0 {
            info!(target: "rustock::sync", "Stored {} headers (#{} -> #{}), rejected {} invalid", stored, first_num, last_num, skipped);
        } else {
            info!(target: "rustock::sync", "Stored {} headers (#{} -> #{})", stored, first_num, last_num);
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

// ---------------------------------------------------------------------------
// SyncHandler — dispatches inbound messages to the state machine channel
// ---------------------------------------------------------------------------

pub struct SyncHandler {
    manager: Arc<SyncManager>,
    event_tx: mpsc::UnboundedSender<SyncEvent>,
}

impl SyncHandler {
    pub fn new(manager: Arc<SyncManager>, event_tx: mpsc::UnboundedSender<SyncEvent>) -> Self {
        Self { manager, event_tx }
    }
}

impl rustock_networking::protocol::P2pHandler for SyncHandler {
    fn handle_message(&self, id: B512, msg: P2pMessage) -> Option<P2pMessage> {
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
                RskSubMessage::BlockHashResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::BlockHashResponse {
                        peer: id,
                        hash: r.hash,
                    });
                }
                RskSubMessage::SkeletonResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::SkeletonResponse {
                        peer: id,
                        identifiers: r.block_identifiers,
                    });
                }
                RskSubMessage::BlockHeadersResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::HeadersResponse {
                        peer: id,
                        headers: r.headers,
                    });
                }
                _ => {}
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// SyncService — skeleton-based forward sync, matching rskj's approach
// ---------------------------------------------------------------------------

pub struct SyncService {
    manager: Arc<SyncManager>,
    peer_store: Arc<rustock_networking::peers::PeerStore>,
    event_rx: mpsc::UnboundedReceiver<SyncEvent>,
    state: SyncState,
    last_progress: Instant,
}

impl SyncService {
    pub fn new(
        manager: Arc<SyncManager>,
        peer_store: Arc<rustock_networking::peers::PeerStore>,
        event_rx: mpsc::UnboundedReceiver<SyncEvent>,
    ) -> Self {
        Self {
            manager,
            peer_store,
            event_rx,
            state: SyncState::Idle,
            last_progress: Instant::now(),
        }
    }

    pub async fn start(mut self) {
        info!(target: "rustock::sync", "Sync service started (skeleton-based forward sync)");
        let mut timer = tokio::time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    self.on_tick().await;
                }
                event = self.event_rx.recv() => {
                    match event {
                        Some(e) => {
                            self.last_progress = Instant::now();
                            self.handle_event(e).await;
                        }
                        None => break, // Channel closed
                    }
                }
            }
        }
    }

    async fn on_tick(&mut self) {
        match &self.state {
            SyncState::Idle => {
                self.try_start_sync().await;
            }
            _ => {
                if self.last_progress.elapsed() > REQUEST_TIMEOUT {
                    warn!(target: "rustock::sync", "Sync request timed out in state {:?}, resetting",
                        std::mem::discriminant(&self.state));
                    self.state = SyncState::Idle;
                }
            }
        }
    }

    /// If we're behind the best peer, initiate sync by finding the connection point.
    async fn try_start_sync(&mut self) {
        let best_peer = self.peer_store.get_best_peer().await;
        let (peer_id, metadata) = match best_peer {
            Some(p) => p,
            None => return,
        };

        let head_hash = match self.manager.store.get_head().ok().flatten() {
            Some(h) => h,
            None => return,
        };
        let head = match self.manager.store.get_header(head_hash).ok().flatten() {
            Some(h) => h,
            None => return,
        };

        if head.number >= metadata.best_number {
            return; // Already in sync
        }

        info!(target: "rustock::sync", "Starting sync: our head #{}, peer best #{}",
            head.number, metadata.best_number);

        self.state = SyncState::FindingConnectionPoint {
            peer: peer_id,
            peer_best: metadata.best_number,
            start: 0,
            end: metadata.best_number,
        };
        self.last_progress = Instant::now();
        self.send_connection_point_probe().await;
    }

    /// Send a BlockHashRequest for the binary-search midpoint.
    async fn send_connection_point_probe(&self) {
        if let SyncState::FindingConnectionPoint { peer, start, end, .. } = &self.state {
            let mid = start + (end - start) / 2;
            debug!(target: "rustock::sync", "Probing connection point at height #{} (range {}..{})", mid, start, end);
            let msg = create_block_hash_request(mid);
            self.peer_store.send_to_peer(peer, msg).await;
        }
    }

    /// Send a SkeletonRequest for the current connection point.
    async fn send_skeleton_request(&self) {
        if let SyncState::DownloadingSkeleton { peer, connection_point, .. } = &self.state {
            info!(target: "rustock::sync", "Requesting skeleton from #{}", connection_point);
            let msg = create_skeleton_request(*connection_point);
            self.peer_store.send_to_peer(peer, msg).await;
        }
    }

    /// Send a BlockHeadersRequest for the current chunk in the skeleton.
    async fn send_next_chunk_request(&self) {
        if let SyncState::DownloadingHeaders {
            peer, skeleton, connection_point, next_chunk_index, ..
        } = &self.state
        {
            let idx = *next_chunk_index;
            if idx >= skeleton.len() {
                return;
            }

            let hash = skeleton[idx].hash;
            let height = skeleton[idx].number;
            let prev_height = skeleton[idx - 1].number;
            let prev_known = std::cmp::max(prev_height, *connection_point);
            let count = (height - prev_known) as u32;

            if count == 0 {
                // This chunk is already covered; the state machine will advance
                // when we receive the (empty or duplicate) response, or we can
                // self-advance here.
                return;
            }

            info!(target: "rustock::sync", "Requesting {} headers from #{} (chunk {}/{})",
                count, height, idx, skeleton.len() - 1);

            let msg = self.manager.create_headers_request(hash, count);
            self.peer_store.send_to_peer(peer, msg).await;
        }
    }

    // -----------------------------------------------------------------------
    // Event handlers
    // -----------------------------------------------------------------------

    async fn handle_event(&mut self, event: SyncEvent) {
        match event {
            SyncEvent::BlockHashResponse { hash, .. } => {
                self.on_block_hash_response(hash).await;
            }
            SyncEvent::SkeletonResponse { identifiers, .. } => {
                self.on_skeleton_response(identifiers).await;
            }
            SyncEvent::HeadersResponse { headers, .. } => {
                self.on_headers_response(headers).await;
            }
        }
    }

    /// Process a BlockHashResponse during connection-point binary search.
    async fn on_block_hash_response(&mut self, hash: B256) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::FindingConnectionPoint { peer, peer_best, start, end } => {
                let mid = start + (end - start) / 2;
                let known = self.manager.store.has_block(hash).unwrap_or(false);

                let (new_start, new_end) = if known {
                    (mid, end) // We have this block; search higher
                } else {
                    (start, mid) // We don't have it; search lower
                };

                if new_end - new_start <= 1 {
                    let cp = new_start;
                    info!(target: "rustock::sync", "Connection point found at #{}", cp);
                    self.state = SyncState::DownloadingSkeleton {
                        peer,
                        peer_best,
                        connection_point: cp,
                    };
                    self.send_skeleton_request().await;
                } else {
                    self.state = SyncState::FindingConnectionPoint {
                        peer,
                        peer_best,
                        start: new_start,
                        end: new_end,
                    };
                    self.send_connection_point_probe().await;
                }
            }
            other => {
                self.state = other; // Restore; ignore unexpected response
            }
        }
    }

    /// Process a SkeletonResponse: save the skeleton and start chunk downloads.
    async fn on_skeleton_response(&mut self, identifiers: Vec<BlockIdentifier>) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingSkeleton { peer, peer_best, connection_point } => {
                if identifiers.len() < 2 {
                    info!(target: "rustock::sync", "Skeleton too small ({} entries), sync appears complete", identifiers.len());
                    self.state = SyncState::Idle;
                    return;
                }

                info!(target: "rustock::sync", "Received skeleton with {} points (#{} -> #{})",
                    identifiers.len(),
                    identifiers.first().map(|b| b.number).unwrap_or(0),
                    identifiers.last().map(|b| b.number).unwrap_or(0));

                self.state = SyncState::DownloadingHeaders {
                    peer,
                    peer_best,
                    skeleton: identifiers,
                    connection_point,
                    next_chunk_index: 1, // Index 0 is the starting point (already known)
                };
                self.send_next_chunk_request().await;
            }
            other => {
                self.state = other;
            }
        }
    }

    /// Process a HeadersResponse: validate, store, and advance to the next chunk.
    async fn on_headers_response(&mut self, headers: Vec<Header>) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingHeaders {
                peer,
                peer_best,
                skeleton,
                connection_point,
                next_chunk_index,
            } => {
                // Validate and store the chunk
                if let Err(e) = self.manager.handle_headers_response(headers) {
                    error!(target: "rustock::sync", "Failed to process headers chunk: {:?}", e);
                    // state already Idle from mem::take
                    return;
                }

                let next = next_chunk_index + 1;
                if next < skeleton.len() && next <= MAX_SKELETON_CHUNKS {
                    // More chunks in this skeleton to download
                    self.state = SyncState::DownloadingHeaders {
                        peer,
                        peer_best,
                        skeleton,
                        connection_point,
                        next_chunk_index: next,
                    };
                    self.send_next_chunk_request().await;
                } else {
                    // All chunks in this skeleton round processed
                    let our_height = self.our_head_number();
                    if our_height < peer_best {
                        info!(target: "rustock::sync",
                            "Skeleton round complete (head #{}, peer #{}), requesting next skeleton",
                            our_height, peer_best);
                        self.state = SyncState::DownloadingSkeleton {
                            peer,
                            peer_best,
                            connection_point: our_height,
                        };
                        self.send_skeleton_request().await;
                    } else {
                        info!(target: "rustock::sync", "Sync complete! Head at #{}", our_height);
                        // state already Idle from mem::take
                    }
                }
            }
            other => {
                // Not in DownloadingHeaders — still store the headers if valid
                self.state = other;
                let _ = self.manager.handle_headers_response(headers);
            }
        }
    }

    /// Return our current head block number (0 if unknown).
    fn our_head_number(&self) -> u64 {
        self.manager
            .store
            .get_head()
            .ok()
            .flatten()
            .and_then(|h| self.manager.store.get_header(h).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Helper functions to create request messages
// ---------------------------------------------------------------------------

fn create_block_hash_request(height: u64) -> P2pMessage {
    let req = BlockHashRequest {
        id: rand::random(),
        height,
    };
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)))
}

fn create_skeleton_request(start_number: u64) -> P2pMessage {
    let req = SkeletonRequest {
        id: rand::random(),
        start_number,
    };
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)))
}

// ===========================================================================
// Tests
// ===========================================================================

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
            timestamp: number * 15,
            extra_data: Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
        }
    }

    // -- SyncManager tests (validation logic) --------------------------------

    #[tokio::test]
    async fn test_sync_manager_processing() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

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

        // 3. Extension block
        let b2 = dummy_header(2, b1.hash(), U256::from(5));
        manager.handle_headers_response(vec![b2.clone()]).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(b2.hash()));

        // 4. Gap block (parent unknown) — stored with TD = difficulty only
        let b4 = dummy_header(4, B256::repeat_byte(0xee), U256::from(1));
        let b4_hash = b4.hash();
        manager.handle_headers_response(vec![b4]).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(b2.hash()), "Head should not change");
        assert!(store.get_header(b4_hash).unwrap().is_some(), "Gap block should be stored");
        assert_eq!(store.get_total_difficulty(b4_hash).unwrap(), Some(U256::from(1)));
    }

    #[tokio::test]
    async fn test_invalid_header_rejected_when_parent_known() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new()
            .with_parent_rule(rustock_core::validation::BlockNumberRule)
            .with_parent_rule(rustock_core::validation::ParentHashRule));
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = SyncManager::new(store.clone(), verifier, peer_store);

        // Header claims parent is genesis but has wrong block number
        let bad = dummy_header(5, genesis_hash, U256::from(50));
        let bad_hash = bad.hash();
        manager.handle_headers_response(vec![bad]).unwrap();

        assert!(store.get_header(bad_hash).unwrap().is_none(), "Invalid header should be rejected");
        assert_eq!(store.get_head().unwrap(), Some(genesis_hash));
    }

    // -- SyncHandler tests (event forwarding) --------------------------------

    #[tokio::test]
    async fn test_sync_handler_forwards_headers() {
        use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
        use rustock_networking::protocol::P2pHandler;

        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handler = SyncHandler::new(manager, event_tx);

        let h0 = dummy_header(0, B256::ZERO, U256::from(10));
        let resp = rustock_networking::protocol::rsk::BlockHeadersResponse {
            id: 1,
            headers: vec![h0.clone()],
        };
        let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersResponse(resp)));

        let handler_resp = handler.handle_message(B512::ZERO, msg);
        assert!(handler_resp.is_none());

        // Event should be forwarded to the channel
        let event = event_rx.try_recv().unwrap();
        match event {
            SyncEvent::HeadersResponse { headers, .. } => {
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].number, 0);
            }
            _ => panic!("Expected HeadersResponse event"),
        }
    }

    #[tokio::test]
    async fn test_sync_handler_forwards_block_hash() {
        use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
        use rustock_networking::protocol::P2pHandler;
        use rustock_networking::protocol::rsk::BlockHashResponse;

        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handler = SyncHandler::new(manager, event_tx);

        let resp = BlockHashResponse { id: 5, hash: B256::repeat_byte(0xab) };
        let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashResponse(resp)));

        handler.handle_message(B512::ZERO, msg);

        match event_rx.try_recv().unwrap() {
            SyncEvent::BlockHashResponse { hash, .. } => {
                assert_eq!(hash, B256::repeat_byte(0xab));
            }
            _ => panic!("Expected BlockHashResponse event"),
        }
    }

    #[tokio::test]
    async fn test_sync_handler_forwards_skeleton() {
        use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
        use rustock_networking::protocol::P2pHandler;
        use rustock_networking::protocol::rsk::SkeletonResponse;

        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handler = SyncHandler::new(manager, event_tx);

        let resp = SkeletonResponse {
            id: 1,
            block_identifiers: vec![
                BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
                BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
            ],
        };
        let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonResponse(resp)));

        handler.handle_message(B512::ZERO, msg);

        match event_rx.try_recv().unwrap() {
            SyncEvent::SkeletonResponse { identifiers, .. } => {
                assert_eq!(identifiers.len(), 2);
                assert_eq!(identifiers[1].number, 192);
            }
            _ => panic!("Expected SkeletonResponse event"),
        }
    }

    // -- State machine tests -------------------------------------------------

    #[tokio::test]
    async fn test_connection_point_binary_search() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        // Store genesis only
        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        // Simulate: peer is at block 1000, we only have genesis
        let peer = B512::repeat_byte(0x01);
        service.state = SyncState::FindingConnectionPoint {
            peer,
            peer_best: 1000,
            start: 0,
            end: 1000,
        };

        // Probe at midpoint 500: we don't have this block hash
        service.on_block_hash_response(B256::repeat_byte(0xff)).await;
        // Range should narrow: start=0, end=500
        if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
            assert_eq!(*start, 0);
            assert_eq!(*end, 500);
        } else {
            panic!("Expected FindingConnectionPoint, got {:?}", service.state);
        }

        // Probe at 250: don't have it
        service.on_block_hash_response(B256::repeat_byte(0xfe)).await;
        if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
            assert_eq!(*start, 0);
            assert_eq!(*end, 250);
        } else {
            panic!("Expected FindingConnectionPoint");
        }

        // Probe at 125: don't have it
        service.on_block_hash_response(B256::repeat_byte(0xfd)).await;
        if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
            assert_eq!(*start, 0);
            assert_eq!(*end, 125);
        } else {
            panic!("Expected FindingConnectionPoint");
        }

        // Continue narrowing... eventually probe at 1
        // Simulate finding genesis hash — we DO have block 0
        let genesis_hash = dummy_header(0, B256::ZERO, U256::from(1)).hash();

        // Set state to final narrowing: range [0, 1]
        service.state = SyncState::FindingConnectionPoint {
            peer,
            peer_best: 1000,
            start: 0,
            end: 1,
        };
        // Probe at 0: we have genesis
        service.on_block_hash_response(genesis_hash).await;
        // Connection point = 0, should transition to DownloadingSkeleton
        match &service.state {
            SyncState::DownloadingSkeleton { connection_point, .. } => {
                assert_eq!(*connection_point, 0);
            }
            _ => panic!("Expected DownloadingSkeleton, got {:?}", service.state),
        }

        drop(event_tx); // cleanup
    }

    #[tokio::test]
    async fn test_skeleton_to_headers_transition() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        let peer = B512::repeat_byte(0x01);
        service.state = SyncState::DownloadingSkeleton {
            peer,
            peer_best: 384,
            connection_point: 0,
        };

        // Receive skeleton: [0, 192, 384]
        let skeleton = vec![
            BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
            BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
            BlockIdentifier { hash: B256::repeat_byte(0x03), number: 384 },
        ];
        service.on_skeleton_response(skeleton).await;

        match &service.state {
            SyncState::DownloadingHeaders { next_chunk_index, skeleton, .. } => {
                assert_eq!(*next_chunk_index, 1);
                assert_eq!(skeleton.len(), 3);
            }
            _ => panic!("Expected DownloadingHeaders, got {:?}", service.state),
        }

        drop(event_tx);
    }

    #[tokio::test]
    async fn test_empty_skeleton_returns_to_idle() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        let peer = B512::repeat_byte(0x01);
        service.state = SyncState::DownloadingSkeleton {
            peer,
            peer_best: 100,
            connection_point: 0,
        };

        // Skeleton with only 1 entry → too small → Idle
        service.on_skeleton_response(vec![
            BlockIdentifier { hash: B256::ZERO, number: 0 },
        ]).await;

        assert!(matches!(service.state, SyncState::Idle));

        drop(event_tx);
    }

    #[tokio::test]
    async fn test_headers_response_advances_chunks() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        // Build a small chain: genesis + 4 blocks
        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        // Build headers
        let b1 = dummy_header(1, genesis_hash, U256::from(1));
        let b2 = dummy_header(2, b1.hash(), U256::from(1));
        let b3 = dummy_header(3, b2.hash(), U256::from(1));
        let b4 = dummy_header(4, b3.hash(), U256::from(1));

        // Skeleton: [0, 2, 4]
        let skeleton = vec![
            BlockIdentifier { hash: genesis_hash, number: 0 },
            BlockIdentifier { hash: b2.hash(), number: 2 },
            BlockIdentifier { hash: b4.hash(), number: 4 },
        ];

        let peer = B512::repeat_byte(0x01);
        service.state = SyncState::DownloadingHeaders {
            peer,
            peer_best: 4,
            skeleton: skeleton.clone(),
            connection_point: 0,
            next_chunk_index: 1,
        };

        // Chunk 1: headers for blocks 1-2 (descending from b2)
        service.on_headers_response(vec![b2.clone(), b1.clone()]).await;

        // Should advance to chunk 2
        match &service.state {
            SyncState::DownloadingHeaders { next_chunk_index, .. } => {
                assert_eq!(*next_chunk_index, 2);
            }
            _ => panic!("Expected DownloadingHeaders with next_chunk=2, got {:?}", service.state),
        }

        // Chunk 2: headers for blocks 3-4 (descending from b4)
        service.on_headers_response(vec![b4.clone(), b3.clone()]).await;

        // All chunks done and we're at peer_best → Idle
        assert!(matches!(service.state, SyncState::Idle),
            "Expected Idle after final chunk, got {:?}", service.state);

        // Verify all headers are stored
        assert!(store.get_header(b1.hash()).unwrap().is_some());
        assert!(store.get_header(b4.hash()).unwrap().is_some());

        drop(event_tx);
    }
}
