use crate::events::SyncEvent;
use crate::manager::{SyncManager, MAX_SKELETON_CHUNKS};
use crate::state::{PeerChunkTracker, SyncState};
use rustock_core::types::header::Header;
use rustock_networking::protocol::{
    BlockHashRequest, BlockIdentifier, P2pMessage, RskMessage, RskSubMessage, SkeletonRequest,
};
use alloy_primitives::{B256, B512};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, debug, warn, error};

/// Timeout for pending requests before resetting to Idle.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between sync tick checks.
const TICK_INTERVAL: Duration = Duration::from_secs(5);

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

/// Skeleton-based forward sync with pipelining, multi-peer downloads,
/// and overlapping skeleton pre-fetch.
pub struct SyncService {
    manager: Arc<SyncManager>,
    peer_store: Arc<rustock_networking::peers::PeerStore>,
    event_rx: mpsc::UnboundedReceiver<SyncEvent>,
    pub(crate) state: SyncState,
    pub(crate) last_progress: Instant,
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
            _ => {
                if self.last_progress.elapsed() > REQUEST_TIMEOUT {
                    warn!(
                        target: "rustock::sync",
                        "Sync request timed out in state {:?}, resetting",
                        std::mem::discriminant(&self.state)
                    );
                    self.state = SyncState::Idle;
                }
            }
        }
    }

    /// If we're behind the best peer, initiate sync by finding the connection point.
    pub(crate) async fn try_start_sync(&mut self) {
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
            return;
        }

        info!(
            target: "rustock::sync",
            "Starting sync: our head #{}, peer best #{}",
            head.number, metadata.best_number
        );

        self.state = SyncState::FindingConnectionPoint {
            peer: peer_id,
            peer_best: metadata.best_number,
            start: 0,
            end: metadata.best_number,
        };
        self.last_progress = Instant::now();
        self.send_connection_point_probe().await;
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
        info!(target: "rustock::sync", "Requesting skeleton from #{}", start);
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
        let count = (height - prev_known) as u32;

        if count == 0 {
            return;
        }

        info!(
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
            let peers = self.peer_store.get_peers().await;
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
                if let Some(peer) = self.peer_store.get_peers().await.first() {
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
                    info!(target: "rustock::sync", "Connection point found at #{}", cp);
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
                    info!(
                        target: "rustock::sync",
                        "Skeleton too small ({} entries), sync appears complete",
                        identifiers.len()
                    );
                    self.state = SyncState::Idle;
                    return;
                }

                info!(
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
                // Identify which chunk this response belongs to
                let chunk_idx = tracker.identify_response(&peer);
                match chunk_idx {
                    Some(idx) => {
                        tracker.buffer_response(idx, headers);
                    }
                    None => {
                        // Unknown peer response — just try to store
                        let _ = self.manager.handle_headers_response(headers);
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
                    // All chunks in this skeleton round are processed
                    let our_height = self.our_head_number();
                    if our_height < peer_best {
                        // Check if we have a pre-fetched skeleton ready
                        if let Some(next_skel) = pending_next_skeleton {
                            if next_skel.len() >= 2 {
                                info!(
                                    target: "rustock::sync",
                                    "Skeleton round complete (head #{}), using pre-fetched skeleton",
                                    our_height
                                );
                                let chunks = std::cmp::min(
                                    next_skel.len(),
                                    MAX_SKELETON_CHUNKS + 1,
                                );
                                let new_tracker = PeerChunkTracker::new(chunks);
                                self.state = SyncState::DownloadingHeaders {
                                    peer_best,
                                    skeleton: next_skel,
                                    connection_point: our_height,
                                    tracker: new_tracker,
                                    pending_next_skeleton: None,
                                };
                                self.fill_pipeline().await;
                                return;
                            }
                        }
                        info!(
                            target: "rustock::sync",
                            "Skeleton round complete (head #{}, peer #{}), requesting next skeleton",
                            our_height, peer_best
                        );
                        // Pick the best available peer for the next skeleton
                        let next_peer = self.peer_store.get_best_peer().await
                            .map(|(id, _)| id)
                            .unwrap_or(peer);
                        self.state = SyncState::DownloadingSkeleton {
                            peer: next_peer,
                            peer_best,
                            connection_point: our_height,
                        };
                        self.send_skeleton_request_to(&next_peer, our_height).await;
                    } else {
                        info!(
                            target: "rustock::sync",
                            "Sync complete! Head at #{}", our_height
                        );
                        // state is Idle from mem::take
                    }
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
