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
use rustock_storage::BlockStore;
use rustock_trie::{TrieNode, TrieStore};
use alloy_primitives::{B256, B512};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, debug, trace, warn, error};

/// Timeout for pending requests before resetting to Idle.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-peer stall timeout during header download: a peer holding chunks
/// that hasn't responded within this window gets its chunks reassigned
/// and is sidelined (rskj punishes TIMEOUT_MESSAGE peers via peer scoring;
/// without this a single dead-but-connected peer wedges every round, since
/// chunks are processed in order).
const PEER_STALL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a stalled peer is excluded from header-chunk assignment.
const PEER_SIDELINE_DURATION: Duration = Duration::from_secs(300);

/// Interval between sync tick checks.
const TICK_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum block gap for follow mode. Gaps larger than this trigger skeleton
/// sync; smaller gaps are handled by fetching individual headers.
/// Matches RSKj's `longSyncLimit` (default 24).
const LONG_SYNC_LIMIT: u64 = 24;

fn create_block_hash_request(height: u64) -> P2pMessage {
    let req = BlockHashRequest {
        id: rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF,
        height,
    };
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)))
}

fn create_body_request(hash: B256) -> (u64, P2pMessage) {
    // Mask to 63 bits: RSKj uses Java's signed long, so IDs > 2^63 get
    // sign-mangled when echoed back via BigInteger.valueOf(long).
    let id: u64 = rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF;
    let req = BodyRequest { id, hash };
    (id, P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyRequest(req))))
}

fn create_skeleton_request(start_number: u64) -> P2pMessage {
    let req = SkeletonRequest {
        id: rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF,
        start_number,
    };
    P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)))
}

/// An external, local source of block bodies — e.g. a synced rskj LevelDB —
/// consulted before requesting bodies from peers. Lets the node reuse an
/// existing on-disk chain instead of re-downloading it over the network.
pub trait ExternalBlockSource: Send + Sync {
    /// Returns `(transactions, ommers)` for the block with this hash, if known.
    fn body_by_hash(&self, hash: B256) -> Option<(Vec<Transaction>, Vec<Header>)>;
}

/// Result of executing one downloaded batch on a blocking thread.
pub(crate) struct ExecOutcome {
    /// `false` when a block failed to execute (or a parent/body was missing);
    /// the sync must not advance past it.
    pub(crate) all_ok: bool,
    /// State root after the last successfully executed block in the batch.
    /// Becomes the starting root for the next batch's execution.
    pub(crate) new_state_root: TrieNode,
    /// Number of `blocks_since_flush` accumulated but not yet flushed when the
    /// batch ended (carried back so flush cadence survives across batches).
    pub(crate) blocks_since_flush: u64,
}

/// A batch currently executing off the async event loop.
struct ExecutionJob {
    handle: JoinHandle<ExecOutcome>,
    /// `peer_best` of the round that produced this batch, used to decide
    /// whether to keep syncing or enter follow mode after it completes.
    peer_best: u64,
}

/// The execution step run on a blocking thread for one downloaded batch.
/// Captures the (cloneable, thread-safe) handles execution needs; production
/// wires this to [`process_downloaded_blocks`]. Boxed so tests can substitute
/// a controllable stand-in and exercise the scheduling logic in isolation.
pub(crate) type ExecFn = Arc<
    dyn Fn(TrieNode, u64, Vec<(B256, Header)>) -> ExecOutcome + Send + Sync + 'static,
>;

/// Skeleton-based forward sync with pipelining, multi-peer downloads,
/// and overlapping skeleton pre-fetch.
pub struct SyncService {
    manager: Arc<SyncManager>,
    peer_store: Arc<rustock_networking::peers::PeerStore>,
    event_rx: mpsc::UnboundedReceiver<SyncEvent>,
    pub(crate) state: SyncState,
    pub(crate) last_progress: Instant,
    /// Last time a BODY response arrived; drives the stalled-body retry.
    /// Separate from `last_progress`, which any response resets (skeleton
    /// pre-fetches were starving the retry path for minutes).
    last_body_progress: Instant,
    progress: SyncProgress,
    block_processor: Option<Arc<BlockProcessor>>,
    trie_store: Option<Arc<dyn TrieStore>>,
    current_state_root: Option<TrieNode>,
    /// One-batch-ahead execution pipeline: the batch currently executing on a
    /// blocking thread, if any. While set, downloads may run for the next
    /// batch but no further batch may begin executing — enforcing a strict
    /// "one executing, at most one downloading" depth.
    executing: Option<ExecutionJob>,
    /// A fully-downloaded batch parked because execution of the previous batch
    /// is still in flight. Holds `(pending_headers, peer_best)`. Execution
    /// starts (and N+2 download resumes) only once `executing` completes.
    pending_exec: Option<(Vec<(B256, Header)>, u64)>,
    /// Closure run on a blocking thread to execute a batch. Set when a block
    /// processor is attached; tests may override it to control timing/outcome.
    exec_fn: Option<ExecFn>,
    last_body_height: u64,
    pending_follow_bodies: HashMap<u64, (B256, Header)>,
    tx_pool: Option<Arc<crate::TransactionPool>>,
    blocks_since_flush: u64,
    /// Peers excluded from header-chunk assignment (stalled mid-round),
    /// mapped to the instant their sideline expires.
    pub(crate) sidelined: HashMap<B512, Instant>,
    /// Start height of the last skeleton pre-fetch request, so the request
    /// is sent once per round instead of on every incoming event.
    last_prefetch_start: Option<u64>,
    /// Optional local block source (e.g. rskj's LevelDB) tried before peers.
    block_source: Option<Arc<dyn ExternalBlockSource>>,
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
            last_body_progress: Instant::now(),
            progress: SyncProgress::new(),
            block_processor: None,
            trie_store: None,
            current_state_root: None,
            executing: None,
            pending_exec: None,
            exec_fn: None,
            last_body_height: 0,
            pending_follow_bodies: HashMap::new(),
            tx_pool: None,
            blocks_since_flush: 0,
            sidelined: HashMap::new(),
            last_prefetch_start: None,
            block_source: None,
        }
    }

    /// Attach a local block source (e.g. rskj's LevelDB) consulted for bodies
    /// before requesting them from peers.
    pub fn with_block_source(mut self, source: Arc<dyn ExternalBlockSource>) -> Self {
        self.block_source = Some(source);
        self
    }

    /// Fill a missing body from the local block source, if available. Returns
    /// true when the body was found and stored (so no peer request is needed).
    fn try_fill_body_locally(&self, hash: B256) -> bool {
        let Some(source) = &self.block_source else {
            return false;
        };
        match source.body_by_hash(hash) {
            Some((txs, ommers)) => self.manager.store.put_body(hash, &txs, &ommers).is_ok(),
            None => false,
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
        let processor = Arc::new(processor);
        self.block_processor = Some(processor.clone());
        self.trie_store = Some(trie_store.clone());
        self.current_state_root = Some(initial_state_root);

        // Wire the execution step to the real block processor. Cloned handles
        // (Arc<BlockProcessor>, Arc<dyn TrieStore>, Arc<BlockStore>, Arc<pool>)
        // are all Send + Sync, so the closure runs safely on a blocking thread.
        let store = self.manager.store.clone();
        let tx_pool = self.tx_pool.clone();
        self.exec_fn = Some(Arc::new(move |state_root, blocks_since_flush, pending| {
            process_downloaded_blocks(
                &processor,
                trie_store.clone(),
                state_root,
                &store,
                tx_pool.as_deref(),
                blocks_since_flush,
                &pending,
            )
        }));
        self
    }

    /// Test seam: install a controllable execution step and a starting state
    /// root, standing in for a real block processor. Lets scheduling tests
    /// drive batch execution timing/outcome without a full EVM/trie setup.
    #[cfg(test)]
    pub(crate) fn set_test_exec(&mut self, exec_fn: ExecFn) {
        self.exec_fn = Some(exec_fn);
        if self.current_state_root.is_none() {
            self.current_state_root = Some(TrieNode::empty());
        }
    }

    #[cfg(test)]
    pub(crate) fn is_executing_for_test(&self) -> bool {
        self.executing.is_some()
    }

    #[cfg(test)]
    pub(crate) fn has_parked_batch_for_test(&self) -> bool {
        self.pending_exec.is_some()
    }

    #[cfg(test)]
    pub(crate) fn last_body_height_for_test(&self) -> u64 {
        self.last_body_height
    }

    #[cfg(test)]
    pub(crate) fn peer_store_for_test(&self) -> Arc<rustock_networking::peers::PeerStore> {
        self.peer_store.clone()
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
                            let is_progress = matches!(
                                &e,
                                SyncEvent::HeadersResponse { .. }
                                | SyncEvent::BodyResponse { .. }
                                | SyncEvent::SkeletonResponse { .. }
                                | SyncEvent::BlockHashResponse { .. }
                            );
                            if is_progress {
                                self.last_progress = Instant::now();
                            }
                            self.handle_event(e).await;
                        }
                        None => break,
                    }
                }
            }
        }
    }

    pub(crate) async fn on_tick(&mut self) {
        // Reap a finished background execution before driving the state machine
        // so a parked next batch can start executing and downloads can resume.
        self.poll_execution().await;

        match &self.state {
            SyncState::Idle => {
                // Don't kick off a fresh sync round while a batch is executing
                // (or a downloaded batch is parked waiting to execute): that
                // would let a second batch begin downloading ahead of the cap.
                if self.executing.is_none() && self.pending_exec.is_none() {
                    self.try_start_sync().await;
                }
            }
            SyncState::Following => {
                self.check_follow_gap().await;
            }
            SyncState::DownloadingBodies { .. } => {
                if self.last_body_progress.elapsed() > REQUEST_TIMEOUT {
                    warn!(
                        target: "rustock::sync",
                        "Body download timed out, retrying stalled requests"
                    );
                    self.retry_body_requests().await;
                    self.last_body_progress = Instant::now();
                } else {
                    self.log_progress().await;
                }
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

    /// Detect peers that disconnected or stalled while holding in-flight
    /// chunks and reassign those chunks so the round can make progress.
    /// Stalled peers are additionally sidelined from future assignment.
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
            for peer in tracker.stalled_peers(PEER_STALL_TIMEOUT) {
                warn!(
                    target: "rustock::sync",
                    "Peer {:?} stalled with in-flight header chunks, sidelining and reassigning",
                    &peer.0[..4]
                );
                tracker.handle_peer_disconnect(&peer);
                self.sidelined.insert(peer, Instant::now() + PEER_SIDELINE_DURATION);
                any_removed = true;
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

        // A full node syncs from its EXECUTED head: blocks past it are
        // downloaded but have no state, so execution must resume there.
        // Without a block processor (no execution), fall back to the
        // download head.
        let head_hash = if self.block_processor.is_some() {
            match self.manager.store.exec_head().ok().flatten() {
                Some((h, _)) => h,
                None => match self.manager.store.canonical_hash(0).ok().flatten() {
                    Some(h) => h,
                    None => return,
                },
            }
        } else {
            match self.manager.store.head().ok().flatten() {
                Some(h) => h,
                None => return,
            }
        };
        let head = match self.manager.store.header(head_hash).ok().flatten() {
            Some(h) => h,
            None => return,
        };

        // Keep the body/execution cursor aligned with the sync head: a
        // stale (or zero, after restart) cursor would queue blocks below
        // or above the executed head.
        if self.block_processor.is_some() {
            self.last_body_height = head.number;
        }

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

        // If the peer's best hash matches our chain, use our head as connection point.
        // Otherwise, use binary search to find where our chain diverges from the peer.
        let peer_hash_known = self.manager.store.has_block(metadata.best_hash)
            .unwrap_or(false);

        if peer_hash_known || head.number == 0 {
            let cp = head.number;
            debug!(target: "rustock::sync", "Connection point: #{} (head)", cp);
            self.state = SyncState::DownloadingSkeleton {
                peer: peer_id,
                peer_best: metadata.best_number,
                connection_point: cp,
            };
            self.last_progress = Instant::now();
            self.send_skeleton_request_to(&peer_id, cp).await;
        } else {
            debug!(
                target: "rustock::sync",
                "Peer best hash unknown, searching for connection point (0..{})",
                head.number
            );
            self.state = SyncState::FindingConnectionPoint {
                peer: peer_id,
                peer_best: metadata.best_number,
                start: 0,
                end: head.number,
            };
            self.last_progress = Instant::now();
            self.send_connection_point_probe().await;
        }
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
            let mut peers = self.peer_store.peers().await;
            if peers.is_empty() {
                return;
            }

            // Exclude sidelined (stalled) peers; if every peer is sidelined,
            // forgive them all rather than stalling the round.
            let now = Instant::now();
            self.sidelined.retain(|_, until| *until > now);
            if peers.iter().any(|p| !self.sidelined.contains_key(p)) {
                peers.retain(|p| !self.sidelined.contains_key(p));
            } else {
                self.sidelined.clear();
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
    async fn maybe_prefetch_skeleton(&mut self) {
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
                if self.last_prefetch_start == Some(last_height) {
                    return; // already requested; re-sending on every event spams peers
                }
                let peers = self.peer_store.peers().await;
                let peer = peers
                    .iter()
                    .find(|p| !self.sidelined.contains_key(*p))
                    .or_else(|| peers.first());
                if let Some(peer) = peer {
                    debug!(
                        target: "rustock::sync",
                        "Pre-fetching next skeleton from #{}",
                        last_height
                    );
                    let msg = create_skeleton_request(last_height);
                    self.peer_store.send_to_peer(peer, msg).await;
                    self.last_prefetch_start = Some(last_height);
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
            // Don't open a fresh round while a batch is parked waiting to
            // execute (that would put a batch beyond the one-ahead cap in
            // flight). A batch merely executing is fine — that's the point of
            // pipelining, and finish_batch parks rather than over-fetches.
            if self.pending_exec.is_some() {
                return;
            }
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
    /// body downloading. ALL blocks past the cursor are queued so they are
    /// executed in order; bodies already in the store are not re-requested.
    pub(crate) async fn start_body_downloads(&mut self, peer_best: u64) {
        let our_height = self.our_head_number();
        let start = self.last_body_height + 1;

        let mut pending = Vec::new();
        let mut missing_bodies = 0usize;
        for num in start..=our_height {
            if let Ok(Some(hash)) = self.manager.store.canonical_hash(num) {
                if let Ok(Some(header)) = self.manager.store.header(hash) {
                    if matches!(self.manager.store.body(hash), Ok(None))
                        && !self.try_fill_body_locally(hash)
                    {
                        missing_bodies += 1;
                    }
                    pending.push((hash, header));
                }
            }
        }

        if pending.is_empty() {
            debug!(
                target: "rustock::sync",
                "No blocks pending past #{}", self.last_body_height
            );
            self.last_body_height = our_height;
            self.continue_after_bodies(peer_best).await;
            return;
        }

        if missing_bodies == 0 {
            debug!(
                target: "rustock::sync",
                "All {} bodies already stored, executing", pending.len()
            );
            self.finish_batch(&pending, peer_best).await;
            return;
        }

        info!(
            target: "rustock::sync",
            "Starting body download for {} blocks (#{} to #{}, {} bodies to fetch)",
            pending.len(),
            pending.first().map(|(_, h)| h.number).unwrap_or(0),
            pending.last().map(|(_, h)| h.number).unwrap_or(0),
            missing_bodies,
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

    /// A batch (N) finished downloading. Advance the *download* cursor and,
    /// respecting the one-batch-ahead cap, either kick off N's execution on a
    /// blocking thread (freeing the event loop to download N+1) or — if a
    /// previous batch is still executing — park this batch until it completes.
    pub(crate) async fn finish_batch(&mut self, pending: &[(B256, Header)], peer_best: u64) {
        // The download succeeded: advance the download cursor so the next
        // skeleton round queues the blocks that follow this batch. Execution
        // (the exec_head cursor) advances independently when the spawned job
        // completes.
        self.last_body_height = pending
            .last()
            .map(|(_, h)| h.number)
            .unwrap_or(self.last_body_height);

        // No execution configured (header/body-only sync): keep the original
        // straight-through behaviour.
        if self.exec_fn.is_none() {
            self.continue_after_bodies(peer_best).await;
            return;
        }

        if self.executing.is_some() {
            // A previous batch is still executing. Cap depth at one: park this
            // batch and stop downloading (no N+2). It will be executed — and
            // downloads resumed — when the running job is reaped in on_tick.
            // The "at most one parked batch" invariant holds because we never
            // download a further batch while pending_exec is set.
            debug!(
                target: "rustock::sync",
                "Batch downloaded (up to #{}) while previous batch still executing; parking",
                self.last_body_height
            );
            self.pending_exec = Some((pending.to_vec(), peer_best));
            self.state = SyncState::Idle;
        } else {
            // Nothing executing: start this batch on a blocking thread and
            // immediately continue downloading the next batch concurrently.
            self.spawn_execution(pending.to_vec(), peer_best);
            self.continue_after_bodies(peer_best).await;
        }
    }

    /// Move execution of `pending` off the async event loop onto a blocking
    /// thread and track it as `self.executing`. Execution owns the trie state;
    /// concurrent downloading only writes headers/bodies (an independent key
    /// space) and touches network state, so the two cannot race.
    fn spawn_execution(&mut self, pending: Vec<(B256, Header)>, peer_best: u64) {
        let (Some(exec_fn), Some(state_root)) =
            (self.exec_fn.clone(), self.current_state_root.clone())
        else {
            // No processor configured — should not reach here (finish_batch
            // guards on it), but stay safe and just advance.
            return;
        };
        let blocks_since_flush = self.blocks_since_flush;
        let handle = tokio::task::spawn_blocking(move || {
            exec_fn(state_root, blocks_since_flush, pending)
        });
        self.executing = Some(ExecutionJob { handle, peer_best });
    }

    /// If a background execution job has finished, reap it and apply the
    /// outcome (advance the execution cursor or halt). On success, start any
    /// parked next batch and resume downloading; on failure, halt the sync.
    async fn poll_execution(&mut self) {
        let Some(job) = &mut self.executing else { return };
        if !job.handle.is_finished() {
            return;
        }
        let job = self.executing.take().unwrap();
        let outcome = match job.handle.await {
            Ok(o) => o,
            Err(e) => {
                error!(target: "rustock::sync", "Block execution task panicked: {e}");
                self.halt_after_exec_failure();
                return;
            }
        };
        self.blocks_since_flush = outcome.blocks_since_flush;
        self.current_state_root = Some(outcome.new_state_root);

        if !outcome.all_ok {
            self.halt_after_exec_failure();
            return;
        }

        // The batch executed cleanly. If a next batch was parked, execute it
        // now (and only now may downloading resume past the cap). Otherwise
        // continue the normal download flow if we weren't already mid-round.
        if let Some((pending, peer_best)) = self.pending_exec.take() {
            self.spawn_execution(pending, job.peer_best);
            // Resume downloading the batch after the one we just started.
            if matches!(self.state, SyncState::Idle) {
                self.continue_after_bodies(peer_best).await;
            }
        }
    }

    /// A block failed to execute (or its body/parent was missing). Do not
    /// advance past it: reset the download cursor to the executed head so the
    /// retry re-downloads and re-executes from there, drop any parked batch
    /// (it must not execute on the wrong parent state — its already-stored
    /// bodies are kept and reused), and go Idle. Mirrors rskj treating such a
    /// block as invalid and stopping there.
    fn halt_after_exec_failure(&mut self) {
        let exec_number = self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.manager.store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(0);
        self.last_body_height = exec_number;
        self.pending_exec = None;
        error!(
            target: "rustock::sync",
            "Sync halted: block execution failed; will retry from executed head #{exec_number}"
        );
        self.state = SyncState::Idle;
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

    /// Send body requests for pending headers, keeping a window of requests
    /// in flight scaled to the connected peer count. The RSK wire protocol
    /// is one body per request, so throughput comes from pipelining:
    /// ~8 outstanding requests per peer, bounded.
    async fn send_body_requests(&mut self) {
        if let SyncState::DownloadingBodies {
            pending_headers,
            next_request,
            in_flight,
            ..
        } = &mut self.state
        {
            let peers = self.peer_store.peers().await;
            if peers.is_empty() {
                debug!(target: "rustock::sync", "No connected peers for body requests");
                return;
            }

            let max_in_flight = (peers.len() * 8).clamp(8, 96);
            let mut sent = 0u32;
            while in_flight.len() < max_in_flight && *next_request < pending_headers.len() {
                let (hash, _header) = &pending_headers[*next_request];
                // Bodies already in the store don't need a request.
                if matches!(self.manager.store.body(*hash), Ok(Some(_))) {
                    *next_request += 1;
                    continue;
                }
                let (req_id, msg) = create_body_request(*hash);
                let peer = &peers[*next_request % peers.len()];
                if self.peer_store.send_to_peer(peer, msg).await {
                    sent += 1;
                } else {
                    debug!(
                        target: "rustock::sync",
                        "Failed to send body request to peer {:?}, leaving for retry",
                        &peer.0[..4]
                    );
                }
                // Track the request even if the send failed (peer may have just
                // disconnected): the stalled-request retry re-sends everything
                // in flight. Dropping it here would orphan the block — nothing
                // would ever request it again and the batch could never finish.
                in_flight.insert(req_id, *next_request);
                *next_request += 1;
            }
            if sent > 0 {
                debug!(
                    target: "rustock::sync",
                    "Sent {sent} body requests ({} in-flight, {} pending)",
                    in_flight.len(),
                    pending_headers.len().saturating_sub(*next_request)
                );
            }
        }
    }

    /// Re-send all in-flight body requests (they timed out without response).
    async fn retry_body_requests(&mut self) {
        if let SyncState::DownloadingBodies {
            pending_headers,
            in_flight,
            ..
        } = &mut self.state
        {
            let peers = self.peer_store.peers().await;
            if peers.is_empty() {
                warn!(target: "rustock::sync", "No peers for body retry");
                return;
            }

            let stalled: Vec<(u64, usize)> = in_flight.drain().collect();
            let count = stalled.len();
            for (i, (_old_id, idx)) in stalled.into_iter().enumerate() {
                let (hash, header) = &pending_headers[idx];
                debug!(
                    target: "rustock::sync",
                    "Stalled body request: block #{} hash {:?}",
                    header.number, hash
                );
                let (req_id, msg) = create_body_request(*hash);
                let peer = &peers[i % peers.len()];
                // Keep the request tracked even on send failure so the next
                // retry round re-attempts it (see send_body_requests).
                let _ = self.peer_store.send_to_peer(peer, msg).await;
                in_flight.insert(req_id, idx);
            }
            info!(
                target: "rustock::sync",
                "Retried {count} stalled body requests across {} peers",
                peers.len()
            );
        }
    }

    pub(crate) async fn on_body_response(
        &mut self,
        request_id: u64,
        transactions: Vec<Transaction>,
        uncles: Vec<Header>,
    ) {
        self.last_body_progress = Instant::now();
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
                        let known_ids: Vec<u64> = in_flight.keys().copied().collect();
                        warn!(
                            target: "rustock::sync",
                            "Received body response for unknown request {}. In-flight IDs: {:?}",
                            request_id, known_ids
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

                // Advance past entries whose bodies are already stored, then
                // check whether the whole batch is downloaded.
                let mut next_request = next_request;
                while next_request < pending_headers.len()
                    && matches!(
                        self.manager.store.body(pending_headers[next_request].0),
                        Ok(Some(_))
                    )
                {
                    next_request += 1;
                }
                let all_done = next_request >= pending_headers.len() && in_flight.is_empty();
                if all_done {
                    info!(
                        target: "rustock::sync",
                        "All {} block bodies downloaded",
                        pending_headers.len()
                    );
                    self.finish_batch(&pending_headers, peer_best).await;
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
                trie_store.flush();
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
        let downloaded = self.our_head_number();
        let executed = self
            .manager
            .store
            .exec_head()
            .ok()
            .flatten()
            .and_then(|(hash, _)| self.manager.store.header(hash).ok().flatten())
            .map(|h| h.number)
            .unwrap_or(downloaded);
        let peers = self.peer_store.peers().await.len();
        self.progress.log(&self.state, executed, downloaded, peers);
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

/// Execute a downloaded batch (headers + bodies) in order, applying state
/// changes to the trie. Runs on a blocking thread (off the async event loop)
/// so body downloads for the next batch proceed concurrently.
///
/// `all_ok` is `false` when a block failed to execute (or a parent/body was
/// missing); the sync must not advance past it (rskj treats such a block as
/// invalid and stops there). The returned state root and flush counter are
/// carried back into the service for the next batch.
fn process_downloaded_blocks(
    processor: &BlockProcessor,
    trie_store: Arc<dyn TrieStore>,
    state_root: TrieNode,
    store: &BlockStore,
    tx_pool: Option<&crate::TransactionPool>,
    mut blocks_since_flush: u64,
    pending_headers: &[(B256, Header)],
) -> ExecOutcome {
    let mut current_root = state_root;
    let mut processed = 0u64;
    let mut all_ok = true;
    let mut last_executed: Option<(B256, B256)> = None;

    // Lineage guard: the first block must extend the executed head and
    // each block its predecessor; executing out of order would apply
    // transactions to the wrong parent state.
    let mut expected_parent = store
        .exec_head()
        .ok()
        .flatten()
        .map(|(hash, _)| hash)
        .or_else(|| store.canonical_hash(0).ok().flatten());

    for (hash, header) in pending_headers {
        if let Some(parent) = expected_parent {
            if header.parent_hash != parent {
                error!(
                    target: "rustock::sync",
                    "Block #{} does not extend the executed head (parent {:?}, expected {:?}); halting sync",
                    header.number, header.parent_hash, parent
                );
                all_ok = false;
                break;
            }
        }
        expected_parent = Some(*hash);

        let (transactions, ommers) = match store.body(*hash) {
            Ok(Some(body)) => body,
            Ok(None) => {
                // Executing past a missing body would apply the next block
                // to the wrong parent state — halt here instead.
                warn!(
                    target: "rustock::sync",
                    "Body not found for block #{} ({:?}); halting sync at this block",
                    header.number, hash
                );
                all_ok = false;
                break;
            }
            Err(e) => {
                error!(
                    target: "rustock::sync",
                    "Failed to read body for block #{}: {:?}", header.number, e
                );
                all_ok = false;
                break;
            }
        };

        if let Some(pool) = tx_pool {
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
                last_executed = Some((*hash, result.state_root_hash));
                processed += 1;
                blocks_since_flush += 1;
                if blocks_since_flush >= 100 {
                    trie_store.flush();
                    blocks_since_flush = 0;
                    let _ = store.set_exec_head(*hash, result.state_root_hash);
                }
                if processed.is_multiple_of(100) {
                    debug!(
                        target: "rustock::sync",
                        "Processed {} blocks (latest #{}, state root {:?})",
                        processed, header.number, result.state_root_hash
                    );
                }
                if processed.is_multiple_of(1000) {
                    info!(
                        target: "rustock::sync",
                        "Executing batch: #{} ({}/{} blocks)",
                        header.number, processed, pending_headers.len()
                    );
                }
            }
            Err(e) => {
                error!(
                    target: "rustock::sync",
                    "Block #{} execution failed: {}; halting sync at this block",
                    header.number, e
                );
                all_ok = false;
                break;
            }
        }
    }

    if processed > 0 {
        trie_store.flush();
        blocks_since_flush = 0;
        if let Some((hash, root_hash)) = last_executed {
            let _ = store.set_exec_head(hash, root_hash);
        }
        info!(
            target: "rustock::sync",
            "Processed {} blocks, state root: {:?}",
            processed, current_root.compute_hash(trie_store.as_ref())
        );
    }

    ExecOutcome {
        all_ok,
        new_state_root: current_root,
        blocks_since_flush,
    }
}

