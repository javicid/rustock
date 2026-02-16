use crate::events::SyncEvent;
use crate::manager::{SyncManager, MAX_SKELETON_CHUNKS};
use crate::state::SyncState;
use rustock_core::types::header::Header;
use rustock_networking::protocol::{
    BlockHashRequest, BlockIdentifier, P2pMessage, RskMessage, RskSubMessage, SkeletonRequest,
};
use alloy_primitives::B256;
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

/// Skeleton-based forward sync, matching rskj's approach.
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
            "Sync service started (skeleton-based forward sync)"
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
                        None => break, // Channel closed
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
            return; // Already in sync
        }

        info!(
            target: "rustock::sync",
            "Starting sync: our head #{}, peer best #{}",
            head.number,
            metadata.best_number
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

    /// Send a BlockHashRequest for the binary-search midpoint.
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

    /// Send a SkeletonRequest for the current connection point.
    async fn send_skeleton_request(&self) {
        if let SyncState::DownloadingSkeleton {
            peer,
            connection_point,
            ..
        } = &self.state
        {
            info!(
                target: "rustock::sync",
                "Requesting skeleton from #{}",
                connection_point
            );
            let msg = create_skeleton_request(*connection_point);
            self.peer_store.send_to_peer(peer, msg).await;
        }
    }

    /// Send a BlockHeadersRequest for the current chunk in the skeleton.
    async fn send_next_chunk_request(&self) {
        if let SyncState::DownloadingHeaders {
            peer,
            skeleton,
            connection_point,
            next_chunk_index,
            ..
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

            info!(
                target: "rustock::sync",
                "Requesting {} headers from #{} (chunk {}/{})",
                count,
                height,
                idx,
                skeleton.len() - 1
            );

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
    pub(crate) async fn on_block_hash_response(&mut self, hash: B256) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::FindingConnectionPoint {
                peer,
                peer_best,
                start,
                end,
            } => {
                let mid = start + (end - start) / 2;
                let known = match self.manager.store.has_block(hash) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            target: "rustock::sync",
                            "Storage error during connection-point search: {:?}",
                            e
                        );
                        self.state = SyncState::Idle;
                        return;
                    }
                };

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
    pub(crate) async fn on_skeleton_response(&mut self, identifiers: Vec<BlockIdentifier>) {
        let old = std::mem::take(&mut self.state);
        match old {
            SyncState::DownloadingSkeleton {
                peer,
                peer_best,
                connection_point,
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
    pub(crate) async fn on_headers_response(&mut self, headers: Vec<Header>) {
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
                    error!(
                        target: "rustock::sync",
                        "Failed to process headers chunk: {:?}",
                        e
                    );
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
                        info!(
                            target: "rustock::sync",
                            "Skeleton round complete (head #{}, peer #{}), requesting next skeleton",
                            our_height, peer_best
                        );
                        self.state = SyncState::DownloadingSkeleton {
                            peer,
                            peer_best,
                            connection_point: our_height,
                        };
                        self.send_skeleton_request().await;
                    } else {
                        info!(
                            target: "rustock::sync",
                            "Sync complete! Head at #{}",
                            our_height
                        );
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
