use crate::events::SyncEvent;
use crate::manager::{SyncManager, MAX_SKELETON_CHUNKS};
use crate::progress::SyncProgress;
use crate::state::SyncState;
use crate::tracker::PeerChunkTracker;
use rustock_core::types::header::Header;
use rustock_core::types::transaction::Transaction;
use rustock_core::Block;
use rustock_execution::BlockProcessor;
use rustock_networking::protocol::{
    BlockHashRequest, BlockIdentifier, BodyRequest, P2pMessage, RskMessage, RskSubMessage,
    SkeletonRequest,
};
use rustock_trie::{TrieNode, TrieStore};
use alloy_primitives::{B256, B512};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, debug, trace, warn, error};

/// Timeout for pending requests before resetting to Idle.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between sync tick checks.
const TICK_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum block gap for follow mode. Gaps larger than this trigger skeleton
/// sync; smaller gaps are handled by fetching individual headers.
/// Matches RSKj's `longSyncLimit` (default 24).
const LONG_SYNC_LIMIT: u64 = 24;

fn create_block_hash_request(height: u64) -> P2pMessage {
    let req = BlockHashRequest {
        id: rand::random(),
        height,
    };
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)))
}

fn create_body_request(hash: B256) -> (u64, P2pMessage) {
    let id: u64 = rand::random();
    let req = BodyRequest { id, hash };
    (id, P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyRequest(req))))
}

fn create_skeleton_request(start_number: u64) -> P2pMessage {
    let req = SkeletonRequest {
        id: rand::random(),
        start_number,
    };
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)))
}

/// Skeleton-based forward sync with pipelining, multi-peer downloads,
/// and overlapping skeleton pre-fetch.
pub struct SyncService {
    manager: Arc<SyncManager>,
    peer_store: Arc<rustock_networking::peers::PeerStore>,
    event_rx: mpsc::UnboundedReceiver<SyncEvent>,
    pub(crate) state: SyncState,
    pub(crate) last_progress: Instant,
    progress: SyncProgress,
    block_processor: Option<BlockProcessor>,
    trie_store: Option<Arc<dyn TrieStore>>,
    current_state_root: Option<TrieNode>,
    last_body_height: u64,
    pending_follow_bodies: HashMap<u64, (B256, Header)>,
    tx_pool: Option<Arc<crate::TransactionPool>>,
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
            progress: SyncProgress::new(),
            block_processor: None,
            trie_store: None,
            current_state_root: None,
            last_body_height: 0,
            pending_follow_bodies: HashMap::new(),
            tx_pool: None,
        }
    }

    /// Attach a transaction pool for removing mined txs during block processing.
    pub fn with_tx_pool(mut self, pool: Arc<crate::TransactionPool>) -> Self {
        self.tx_pool = Some(pool);
        self
    }

    /// Attach a block processor for full block validation and execution.
    pub fn with_block_processor(
        mut self,
        processor: BlockProcessor,
        trie_store: Arc<dyn TrieStore>,
        initial_state_root: TrieNode,
    ) -> Self {
        self.block_processor = Some(processor);
        self.trie_store = Some(trie_store);
        self.current_state_root = Some(initial_state_root);
        self
    }

    pub async fn start(mut self) {
        info!(
            target: "rustock::sync",
            "Sync service started (pipelined multi-peer skeleton sync)"
        );
        let mut timer = tokio::time::interval(TICK_INTERVAL);

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
                        None => break,
                    }
                }
            }
        }
    }

    pub(crate) async fn on_tick(&mut self) {
        match &self.state {
            SyncState::Idle => {
                self.try_start_sync().await;
            }
            SyncState::Following => {
                self.check_follow_gap().await;
            }
            _ => {
                if self.last_progress.elapsed() > REQUEST_TIMEOUT {
                    warn!(
                        target: "rustock::sync",
                        "Sync request timed out in state {:?}, resetting",
                        std::mem::discriminant(&self.state)
                    );
                    self.state = SyncState::Idle;
                } else {
                    self.check_disconnected_peers().await;
                    self.log_progress().await;
                }
            }
        }
    }

    /// Detect peers that disconnected while holding in-flight chunks and
    /// reassign those chunks so the round can make progress.
    async fn check_disconnected_peers(&mut self) {
        if let SyncState::DownloadingHeaders { tracker, .. } = &mut self.state {
            let tracked_peers: Vec<B512> = tracker.in_flight.keys().cloned().collect();
            let mut any_removed = false;
            for peer in tracked_peers {
                if !self.peer_store.is_connected(&peer).await {
                    let count = tracker.in_flight.get(&peer).map_or(0, |q| q.len());
                    if count > 0 {
                        debug!(
                            target: "rustock::sync",
                            "Peer {:?} disconnected with {} in-flight chunks, reassigning",
                            &peer.0[..4], count
                        );
                        tracker.handle_peer_disconnect(&peer);
                        any_removed = true;
                    }
                }
            }
            if any_removed {
                self.last_progress = Instant::now();
            }
        }
        if let SyncState::DownloadingHeaders { .. } = &self.state {
            self.fill_pipeline().await;
        }
    }

    /// If we're behind the best peer, initiate sync.
    /// Small gaps (<= LONG_SYNC_LIMIT) enter Following mode;
    /// large gaps use skeleton sync.
    pub(crate) async fn try_start_sync(&mut self) {
        let best_peer = self.peer_store.best_peer().await;
        let (peer_id, metadata) = match best_peer {
            Some(p) => p,
            None => return,
        };

        let head_hash = match self.manager.store.head().ok().flatten() {
            Some(h) => h,
            None => return,
        };
        let head = match self.manager.store.header(head_hash).ok().flatten() {
            Some(h) => h,
            None => return,
        };

        if head.number >= metadata.best_number {
            self.state = SyncState::Following;
            return;
        }

        let gap = metadata.best_number - head.number;

        if gap <= LONG_SYNC_LIMIT {
            info!(
                target: "rustock::sync",
                "Near tip ({} blocks behind), entering follow mode", gap
            );
            self.state = SyncState::Following;
            return;
        }

        info!(
            target: "rustock::sync",
            "Starting sync: our head #{}, peer best #{} ({} blocks behind)",
            head.number, metadata.best_number, gap
        );

        self.progress.reset(head.number);

        let cp = head.number;
        debug!(target: "rustock::sync", "Connection point: #{} (head)", cp);
        self.state = SyncState::DownloadingSkeleton {
            peer: peer_id,
            peer_best: metadata.best_number,
            connection_point: cp,
        };
        self.last_progress = Instant::now();
        self.send_skeleton_request_to(&peer_id, cp).await;
    }

    async fn send_connection_point_probe(&self) {
        if let SyncState::FindingConnectionPoint { peer, start, end, .. } = &self.state {
            let mid = start + (end - start) / 2;
            debug!(
                target: "rustock::sync",
                "Probing connection point at height #{} (range {}..{})",
                mid, start, end
            );
            let msg = create_block_hash_request(mid);
            self.peer_store.send_to_peer(peer, msg).await;
        }
    }

    async fn send_skeleton_request_to(&self, peer: &B512, start: u64) {
        debug!(target: "rustock::sync", "Requesting skeleton from #{}", start);
        let msg = create_skeleton_request(start);
        self.peer_store.send_to_peer(peer, msg).await;
    }

    /// Sends a chunk request for `chunk_idx` in the skeleton to `peer`.
    async fn send_chunk_to_peer(
        &self,
        peer: &B512,
        skeleton: &[BlockIdentifier],
        connection_point: u64,
        chunk_idx: usize,
    ) {
        if chunk_idx == 0 || chunk_idx >= skeleton.len() {
            return;
        }

        let hash = skeleton[chunk_idx].hash;
        let height = skeleton[chunk_idx].number;
        let prev_height = skeleton[chunk_idx - 1].number;
        let prev_known = std::cmp::max(prev_height, connection_point);

        // Skip chunks already covered by the connection point
        if prev_known >= height {
            return;
        }

        let count = (height - prev_known) as u32;

        trace!(
            target: "rustock::sync",
            "Requesting {} headers from #{} (chunk {}/{}) -> peer {:?}",
            count, height, chunk_idx, skeleton.len() - 1,
            &peer.as_slice()[..4]
        );

        let msg = self.manager.create_headers_request(hash, count);
        self.peer_store.send_to_peer(peer, msg).await;
    }

    /// Fill the pipeline for all available peers.
    async fn fill_pipeline(&mut self) {
        if let SyncState::DownloadingHeaders {
            skeleton,
            connection_point,
            tracker,
            ..
        } = &mut self.state
        {
            let peers = self.peer_store.peers().await;
            if peers.is_empty() {
                return;
            }

            // Collect assignments first, then send (to avoid borrow issues)
            let mut assignments: Vec<(B512, usize)> = Vec::new();
            for peer in &peers {
                let capacity = tracker.peer_capacity(peer);
                for _ in 0..capacity {
                    if let Some(idx) = tracker.next_assignment() {
                        tracker.record_sent(*peer, idx);
                        assignments.push((*peer, idx));
                    } else {
                        break;
                    }
                }
            }

            // Clone what we need for sending
            let skeleton_clone = skeleton.clone();
            let cp = *connection_point;

            for (peer, idx) in assignments {
                self.send_chunk_to_peer(&peer, &skeleton_clone, cp, idx).await;
            }
        }
    }

    /// Try to pre-fetch the next skeleton when we've sent the last chunk.
    async fn maybe_prefetch_skeleton(&self) {
        if let SyncState::DownloadingHeaders {
            tracker,
            skeleton,
            pending_next_skeleton,
            ..
        } = &self.state
        {
            // Pre-fetch when all chunks have been assigned but not all processed,
            // and we haven't already pre-fetched.
            if tracker.next_to_assign >= tracker.total_chunks
                && !tracker.is_complete()
                && pending_next_skeleton.is_none()
            {
                let last_height = skeleton.last().map(|b| b.number).unwrap_or(0);
                if let Some(peer) = self.peer_store.peers().await.first() {
                    debug!(
                        target: "rustock::sync",
                        "Pre-fetching next skeleton from #{}",
                        last_height
                    );
                    let msg = create_skeleton_request(last_height);
                    self.peer_store.send_to_peer(peer, msg).await;
                }
            }
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
            SyncEvent::HeadersResponse { peer, headers } => {
                self.on_headers_response(peer, headers).await;
            }
            SyncEvent::BodyResponse { id, transactions, uncles, .. } => {
                self.on_body_response(id, transactions, uncles).await;
            }
            SyncEvent::NewBlockHashes { peer, identifiers } => {
                self.on_new_block_hashes(peer, identifiers).await;
            }
        }
    }

    pub(crate) async fn on_block_hash_response(&mut self, hash: B256) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::FindingConnectionPoint {
                peer, peer_best, start, end,
            } => {
                let mid = start + (end - start) / 2;
                let known = match self.manager.store.has_block(hash) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            target: "rustock::sync",
                            "Storage error during connection-point search: {:?}", e
                        );
                        self.state = SyncState::Idle;
                        return;
                    }
                };

                let (new_start, new_end) = if known {
                    (mid, end)
                } else {
                    (start, mid)
                };

                if new_end - new_start <= 1 {
                    let cp = new_start;
                    debug!(target: "rustock::sync", "Connection point found at #{}", cp);
                    self.state = SyncState::DownloadingSkeleton {
                        peer,
                        peer_best,
                        connection_point: cp,
                    };
                    self.send_skeleton_request_to(&peer, cp).await;
                } else {
                    self.state = SyncState::FindingConnectionPoint {
                        peer, peer_best,
                        start: new_start,
                        end: new_end,
                    };
                    self.send_connection_point_probe().await;
                }
            }
            other => {
                self.state = other;
            }
        }
    }

    pub(crate) async fn on_skeleton_response(&mut self, identifiers: Vec<BlockIdentifier>) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingSkeleton {
                peer: _, peer_best, connection_point,
            } => {
                if identifiers.len() < 2 {
                    debug!(
                        target: "rustock::sync",
                        "Skeleton too small ({} entries), entering follow mode",
                        identifiers.len()
                    );
                    self.state = SyncState::Following;
                    return;
                }

                debug!(
                    target: "rustock::sync",
                    "Received skeleton with {} points (#{} -> #{})",
                    identifiers.len(),
                    identifiers.first().map(|b| b.number).unwrap_or(0),
                    identifiers.last().map(|b| b.number).unwrap_or(0)
                );

                let chunks = std::cmp::min(identifiers.len(), MAX_SKELETON_CHUNKS + 1);
                let tracker = PeerChunkTracker::new(chunks);

                self.state = SyncState::DownloadingHeaders {
                    peer_best,
                    skeleton: identifiers,
                    connection_point,
                    tracker,
                    pending_next_skeleton: None,
                };
                self.fill_pipeline().await;
            }
            // If we're in DownloadingHeaders and receive a skeleton, it's the pre-fetch
            SyncState::DownloadingHeaders {
                peer_best, skeleton, connection_point, tracker,
                pending_next_skeleton: _,
            } => {
                debug!(
                    target: "rustock::sync",
                    "Received pre-fetched skeleton ({} points)",
                    identifiers.len()
                );
                self.state = SyncState::DownloadingHeaders {
                    peer_best,
                    skeleton,
                    connection_point,
                    tracker,
                    pending_next_skeleton: Some(identifiers),
                };
            }
            other => {
                self.state = other;
            }
        }
    }

    pub(crate) async fn on_headers_response(&mut self, peer: B512, headers: Vec<Header>) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingHeaders {
                peer_best,
                skeleton,
                connection_point,
                mut tracker,
                pending_next_skeleton,
            } => {
                // Match the response to a skeleton chunk by content, not FIFO order.
                // Peers may return responses out of order, so FIFO identification
                // would swap chunks and break the TD chain.
                // The highest block number in the response should match a skeleton entry.
                let chunk_idx = identify_chunk_by_content(&headers, &skeleton);

                // Consume the FIFO entry for this peer regardless (keeps queue aligned)
                let _ = tracker.identify_response(&peer);

                match chunk_idx {
                    Some(idx) if idx < tracker.total_chunks => {
                        tracker.buffer_response(idx, headers);
                    }
                    _ => {
                        // Response doesn't match any skeleton entry. This happens when
                        // stale responses from previous skeleton rounds arrive during a
                        // new round. Drop them — processing unordered headers with
                        // potentially-corrupted store TDs can set the head to an
                        // erroneously high TD, preventing legitimate chunks from advancing.
                        warn!(
                            target: "rustock::sync",
                            "Dropped unmatched headers response ({} headers, blocks #{}-#{})",
                            headers.len(),
                            headers.iter().map(|h| h.number).min().unwrap_or(0),
                            headers.iter().map(|h| h.number).max().unwrap_or(0),
                        );
                        self.state = SyncState::DownloadingHeaders {
                            peer_best, skeleton, connection_point, tracker,
                            pending_next_skeleton,
                        };
                        return;
                    }
                }

                // Process all consecutive ready chunks
                let ready = tracker.drain_ready();
                for (_idx, chunk_headers) in &ready {
                    if let Err(e) = self.manager.handle_headers_response(chunk_headers.clone()) {
                        error!(
                            target: "rustock::sync",
                            "Failed to process headers chunk: {:?}", e
                        );
                        self.state = SyncState::Idle;
                        return;
                    }
                }

                if tracker.is_complete() {
                    self.start_body_downloads(peer_best).await;
                } else {
                    // More chunks to go — restore state and refill pipeline
                    self.state = SyncState::DownloadingHeaders {
                        peer_best, skeleton, connection_point, tracker,
                        pending_next_skeleton,
                    };
                    self.fill_pipeline().await;
                    self.maybe_prefetch_skeleton().await;
                }
            }
            other => {
                let is_following = matches!(other, SyncState::Following);
                self.state = other;
                let before_height = self.our_head_number();
                let before_hash = self.manager.store.head().ok().flatten();
                let _ = self.manager.handle_headers_response(headers.clone());
                if is_following {
                    let after_height = self.our_head_number();
                    let after_hash = self.manager.store.head().ok().flatten();
                    if after_hash != before_hash {
                        if after_height > before_height {
                            info!(
                                target: "rustock::sync",
                                "New tip: #{}", after_height
                            );
                        } else {
                            info!(
                                target: "rustock::sync",
                                "Reorg: #{} -> #{} (new head {:?})",
                                before_height, after_height,
                                after_hash
                            );
                        }
                        self.request_follow_bodies(&headers).await;
                    }
                }
            }
        }
    }

    /// Handle NewBlockHashes: fetch announced headers we don't have yet,
    /// and detect potential reorgs (different hash at a height we already have).
    /// Only active in Following state; ignored during skeleton sync.
    pub(crate) async fn on_new_block_hashes(&mut self, peer: B512, identifiers: Vec<BlockIdentifier>) {
        if !matches!(self.state, SyncState::Following) {
            trace!(
                target: "rustock::sync",
                "Ignoring NewBlockHashes ({} entries) — sync in progress",
                identifiers.len()
            );
            return;
        }

        let our_height = self.our_head_number();

        for id in &identifiers {
            if id.number > our_height {
                // New block ahead of our tip — request it
                let metadata = rustock_networking::peers::PeerMetadata {
                    best_number: id.number,
                    best_hash: id.hash,
                    total_difficulty: alloy_primitives::U256::ZERO,
                    client_id: String::new(),
                };
                self.peer_store.update_metadata(&peer, metadata).await;

                let count = (id.number - our_height) as u32;
                trace!(
                    target: "rustock::sync",
                    "NewBlockHashes: requesting {} headers up to #{} from peer {:?}",
                    count, id.number, &peer.as_slice()[..4]
                );
                let msg = self.manager.create_headers_request(id.hash, count);
                self.peer_store.send_to_peer(&peer, msg).await;
            } else {
                // Block at or below our height — check for reorg candidate
                let canonical = self.manager.store
                    .canonical_hash(id.number)
                    .ok()
                    .flatten();

                if canonical == Some(id.hash) {
                    continue; // same block, nothing to do
                }

                // Different hash at a height we already have — potential reorg.
                // Request enough headers to cover a shallow fork.
                let count = std::cmp::min(LONG_SYNC_LIMIT, id.number) as u32;
                debug!(
                    target: "rustock::sync",
                    "NewBlockHashes: reorg candidate at #{} (canonical {:?}, announced {:?}), requesting {} headers",
                    id.number,
                    canonical.map(|h| format!("{:?}", h)).unwrap_or_else(|| "none".into()),
                    id.hash,
                    count
                );
                let msg = self.manager.create_headers_request(id.hash, count);
                self.peer_store.send_to_peer(&peer, msg).await;
            }
        }
    }

    /// In Following state, periodically check if we've fallen too far behind
    /// and need to switch back to skeleton sync.
    pub(crate) async fn check_follow_gap(&mut self) {
        let best_peer = self.peer_store.best_peer().await;
        let (_, metadata) = match best_peer {
            Some(p) => p,
            None => return,
        };

        let our_height = self.our_head_number();
        if our_height == 0 {
            return;
        }

        if metadata.best_number > our_height + LONG_SYNC_LIMIT {
            info!(
                target: "rustock::sync",
                "Fell behind by {} blocks, switching to skeleton sync",
                metadata.best_number - our_height
            );
            self.state = SyncState::Idle;
            self.try_start_sync().await;
        }
    }

    /// Return our current head block number (0 if unknown).
    fn our_head_number(&self) -> u64 {
        self.manager
            .store
            .head()
            .ok()
            .flatten()
            .and_then(|h| self.manager.store.header(h).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0)
    }

    /// After all headers in a skeleton round are downloaded, transition to
    /// body downloading for any headers that don't already have bodies stored.
    pub(crate) async fn start_body_downloads(&mut self, peer_best: u64) {
        let our_height = self.our_head_number();
        let start = self.last_body_height + 1;

        let mut pending = Vec::new();
        for num in start..=our_height {
            if let Ok(Some(hash)) = self.manager.store.canonical_hash(num) {
                if let Ok(None) = self.manager.store.body(hash) {
                    if let Ok(Some(header)) = self.manager.store.header(hash) {
                        pending.push((hash, header));
                    }
                }
            }
        }

        if pending.is_empty() {
            debug!(
                target: "rustock::sync",
                "All bodies already stored up to #{}", our_height
            );
            self.last_body_height = our_height;
            self.continue_after_bodies(peer_best).await;
            return;
        }

        info!(
            target: "rustock::sync",
            "Starting body download for {} blocks (#{} to #{})",
            pending.len(),
            pending.first().map(|(_, h)| h.number).unwrap_or(0),
            pending.last().map(|(_, h)| h.number).unwrap_or(0),
        );

        self.state = SyncState::DownloadingBodies {
            peer_best,
            pending_headers: pending,
            next_request: 0,
            in_flight: HashMap::new(),
        };
        self.last_progress = Instant::now();
        self.send_body_requests().await;
    }

    /// After body downloads (or when no bodies needed), decide whether to
    /// continue syncing headers or enter follow mode.
    async fn continue_after_bodies(&mut self, peer_best: u64) {
        let our_height = self.our_head_number();
        if our_height < peer_best {
            debug!(
                target: "rustock::sync",
                "Skeleton round complete (head #{}, peer #{}), requesting next skeleton",
                our_height, peer_best
            );
            let next_peer = self.peer_store.best_peer().await
                .map(|(id, _)| id)
                .unwrap_or(B512::ZERO);
            self.state = SyncState::DownloadingSkeleton {
                peer: next_peer,
                peer_best,
                connection_point: our_height,
            };
            self.send_skeleton_request_to(&next_peer, our_height).await;
        } else {
            info!(
                target: "rustock::sync",
                "Sync complete! Head at #{}, entering follow mode", our_height
            );
            self.state = SyncState::Following;
        }
    }

    /// In Following mode, request bodies for newly received block headers.
    async fn request_follow_bodies(&mut self, headers: &[Header]) {
        let peers = self.peer_store.peers().await;
        if peers.is_empty() {
            return;
        }
        for header in headers {
            let hash = header.hash();
            if self.manager.store.body(hash).ok().flatten().is_none() {
                let (req_id, msg) = create_body_request(hash);
                let peer = &peers[0];
                self.peer_store.send_to_peer(peer, msg).await;
                self.pending_follow_bodies.insert(req_id, (hash, header.clone()));
            }
        }
    }

    /// Send body requests for up to `MAX_BODY_REQUESTS` pending headers.
    async fn send_body_requests(&mut self) {
        const MAX_BODY_IN_FLIGHT: usize = 8;

        if let SyncState::DownloadingBodies {
            pending_headers,
            next_request,
            in_flight,
            ..
        } = &mut self.state
        {
            let peers = self.peer_store.peers().await;
            if peers.is_empty() {
                return;
            }

            while in_flight.len() < MAX_BODY_IN_FLIGHT && *next_request < pending_headers.len() {
                let (hash, _header) = &pending_headers[*next_request];
                let (req_id, msg) = create_body_request(*hash);
                let peer = &peers[*next_request % peers.len()];
                self.peer_store.send_to_peer(peer, msg).await;
                in_flight.insert(req_id, *next_request);
                *next_request += 1;
            }
        }
    }

    pub(crate) async fn on_body_response(
        &mut self,
        request_id: u64,
        transactions: Vec<Transaction>,
        uncles: Vec<Header>,
    ) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingBodies {
                peer_best,
                pending_headers,
                next_request,
                mut in_flight,
            } => {
                let idx = match in_flight.remove(&request_id) {
                    Some(i) => i,
                    None => {
                        warn!(
                            target: "rustock::sync",
                            "Received body response for unknown request {}", request_id
                        );
                        self.state = SyncState::DownloadingBodies {
                            peer_best,
                            pending_headers,
                            next_request,
                            in_flight,
                        };
                        return;
                    }
                };

                let (hash, _header) = &pending_headers[idx];
                if let Err(e) = self.manager.store.put_body(*hash, &transactions, &uncles) {
                    error!(
                        target: "rustock::sync",
                        "Failed to store body for {:?}: {:?}", hash, e
                    );
                }

                trace!(
                    target: "rustock::sync",
                    "Stored body for block {:?} ({} txs, {} uncles)",
                    hash, transactions.len(), uncles.len()
                );

                // Check if all bodies are done
                let all_done = next_request >= pending_headers.len() && in_flight.is_empty();
                if all_done {
                    info!(
                        target: "rustock::sync",
                        "All {} block bodies downloaded",
                        pending_headers.len()
                    );
                    self.process_downloaded_blocks(&pending_headers).await;
                    self.last_body_height = pending_headers
                        .last()
                        .map(|(_, h)| h.number)
                        .unwrap_or(self.last_body_height);
                    self.continue_after_bodies(peer_best).await;
                } else {
                    self.state = SyncState::DownloadingBodies {
                        peer_best,
                        pending_headers,
                        next_request,
                        in_flight,
                    };
                    self.send_body_requests().await;
                }
            }
            SyncState::Following => {
                self.state = SyncState::Following;
                if let Some((hash, header)) = self.pending_follow_bodies.remove(&request_id) {
                    if let Err(e) = self.manager.store.put_body(hash, &transactions, &uncles) {
                        error!(
                            target: "rustock::sync",
                            "Failed to store follow-mode body for {:?}: {:?}", hash, e
                        );
                        return;
                    }
                    debug!(
                        target: "rustock::sync",
                        "Stored body for block #{} ({} txs) in follow mode",
                        header.number, transactions.len()
                    );
                    self.process_single_block(hash, &header, transactions, uncles).await;
                }
            }
            other => {
                self.state = other;
            }
        }
    }

    /// Process blocks that have been downloaded (headers + bodies).
    /// Executes each block in order, applying state changes to the trie.
    async fn process_downloaded_blocks(
        &mut self,
        pending_headers: &[(B256, Header)],
    ) {
        let (processor, trie_store, state_root) = match (
            &self.block_processor,
            &self.trie_store,
            &self.current_state_root,
        ) {
            (Some(p), Some(ts), Some(sr)) => (p, ts.clone(), sr.clone()),
            _ => {
                debug!(
                    target: "rustock::sync",
                    "No block processor configured, skipping execution"
                );
                return;
            }
        };

        let mut current_root = state_root;
        let mut processed = 0u64;

        for (hash, header) in pending_headers {
            let (transactions, ommers) = match self.manager.store.body(*hash) {
                Ok(Some(body)) => body,
                Ok(None) => {
                    warn!(
                        target: "rustock::sync",
                        "Body not found for block #{} ({:?}), skipping execution",
                        header.number, hash
                    );
                    continue;
                }
                Err(e) => {
                    error!(
                        target: "rustock::sync",
                        "Failed to read body for block #{}: {:?}", header.number, e
                    );
                    break;
                }
            };

            if let Some(pool) = &self.tx_pool {
                pool.remove_mined(&transactions);
            }

            let block = Block {
                header: header.clone(),
                transactions,
                ommers,
            };

            match processor.process_and_commit(&block, &current_root, trie_store.clone()) {
                Ok(result) => {
                    current_root = result.new_state_root;
                    processed += 1;
                    if processed.is_multiple_of(100) {
                        debug!(
                            target: "rustock::sync",
                            "Processed {} blocks (latest #{}, state root {:?})",
                            processed, header.number, result.state_root_hash
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        target: "rustock::sync",
                        "Block #{} execution failed: {}, skipping remaining blocks",
                        header.number, e
                    );
                    break;
                }
            }
        }

        if processed > 0 {
            info!(
                target: "rustock::sync",
                "Processed {} blocks, state root: {:?}",
                processed, current_root.compute_hash(trie_store.as_ref())
            );
            self.current_state_root = Some(current_root);
        }
    }

    /// Process a single block received in follow mode.
    async fn process_single_block(
        &mut self,
        _hash: B256,
        header: &Header,
        transactions: Vec<Transaction>,
        ommers: Vec<Header>,
    ) {
        if let Some(pool) = &self.tx_pool {
            pool.remove_mined(&transactions);
            pool.evict_outdated(header.number);
        }

        let (processor, trie_store, state_root) = match (
            &self.block_processor,
            &self.trie_store,
            &self.current_state_root,
        ) {
            (Some(p), Some(ts), Some(sr)) => (p, ts.clone(), sr.clone()),
            _ => return,
        };

        let block = Block {
            header: header.clone(),
            transactions,
            ommers,
        };

        match processor.process_and_commit(&block, &state_root, trie_store.clone()) {
            Ok(result) => {
                info!(
                    target: "rustock::sync",
                    "Executed block #{}, state root: {:?}",
                    header.number, result.state_root_hash
                );
                self.current_state_root = Some(result.new_state_root);
            }
            Err(e) => {
                warn!(
                    target: "rustock::sync",
                    "Block #{} execution failed: {}", header.number, e
                );
            }
        }
    }

    /// Log sync progress: percentage, speed, ETA, peers.
    async fn log_progress(&mut self) {
        let current = self.our_head_number();
        let peers = self.peer_store.peers().await.len();
        self.progress.log(&self.state, current, peers);
    }
}

/// Identifies which skeleton chunk a headers response belongs to by examining
/// the block numbers in the response.  The highest block number should match
/// one of the skeleton entries, giving us the chunk index.
fn identify_chunk_by_content(
    headers: &[Header],
    skeleton: &[BlockIdentifier],
) -> Option<usize> {
    if headers.is_empty() || skeleton.is_empty() {
        return None;
    }

    // Find the highest block number in the response
    let max_number = headers.iter().map(|h| h.number).max().unwrap();

    // Find the skeleton entry whose number matches
    skeleton
        .iter()
        .position(|entry| entry.number == max_number)
}

