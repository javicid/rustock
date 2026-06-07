use alloy_primitives::B512;
use rustock_core::types::header::Header;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Number of chunk requests to keep in flight per peer.
pub(crate) const PIPELINE_DEPTH: usize = 4;

/// Tracks chunk assignment and ordering across multiple peers.
#[derive(Debug)]
pub struct PeerChunkTracker {
    /// Per-peer FIFO of chunk indices that are in flight (in request order).
    pub(crate) in_flight: HashMap<B512, VecDeque<usize>>,
    /// Next skeleton index to assign to a peer.
    pub(crate) next_to_assign: usize,
    /// Next chunk index to process (must process in order for correct TD chain).
    pub(crate) next_to_process: usize,
    /// Buffer for responses that arrived ahead of processing order.
    pub(crate) buffered: BTreeMap<usize, Vec<Header>>,
    /// Total number of chunks in this skeleton.
    pub(crate) total_chunks: usize,
    /// Per-peer instant since which we have been waiting for a response
    /// (set on first outstanding request, refreshed on each response).
    pub(crate) waiting_since: HashMap<B512, Instant>,
}

impl PeerChunkTracker {
    /// Creates a new tracker starting at chunk index 1 (index 0 is the known
    /// starting point in the skeleton).
    pub fn new(skeleton_len: usize) -> Self {
        Self {
            in_flight: HashMap::new(),
            next_to_assign: 1,
            next_to_process: 1,
            buffered: BTreeMap::new(),
            total_chunks: skeleton_len,
            waiting_since: HashMap::new(),
        }
    }

    /// Returns the next chunk index to assign and advances the counter.
    /// Returns `None` if all chunks have been assigned.
    pub fn next_assignment(&mut self) -> Option<usize> {
        if self.next_to_assign >= self.total_chunks {
            return None;
        }
        let idx = self.next_to_assign;
        self.next_to_assign += 1;
        Some(idx)
    }

    /// Records that `chunk_idx` was sent to `peer`.
    pub fn record_sent(&mut self, peer: B512, chunk_idx: usize) {
        self.in_flight
            .entry(peer)
            .or_default()
            .push_back(chunk_idx);
        self.waiting_since.entry(peer).or_insert_with(Instant::now);
    }

    /// Identifies which chunk a response from `peer` corresponds to
    /// by popping the front of that peer's in-flight queue.
    pub fn identify_response(&mut self, peer: &B512) -> Option<usize> {
        let queue = self.in_flight.get_mut(peer)?;
        let idx = queue.pop_front();
        if queue.is_empty() {
            self.waiting_since.remove(peer);
        } else {
            self.waiting_since.insert(*peer, Instant::now());
        }
        idx
    }

    /// Buffers a response for the given chunk index.
    pub fn buffer_response(&mut self, chunk_idx: usize, headers: Vec<Header>) {
        self.buffered.insert(chunk_idx, headers);
    }

    /// Drains all consecutive ready chunks starting from `next_to_process`.
    /// Returns them in order.
    pub fn drain_ready(&mut self) -> Vec<(usize, Vec<Header>)> {
        let mut ready = Vec::new();
        while let Some(headers) = self.buffered.remove(&self.next_to_process) {
            ready.push((self.next_to_process, headers));
            self.next_to_process += 1;
        }
        ready
    }

    /// Returns true if all chunks have been processed.
    pub fn is_complete(&self) -> bool {
        self.next_to_process >= self.total_chunks
    }

    /// Returns how many requests a peer can still accept before hitting
    /// the pipeline depth limit.
    pub fn peer_capacity(&self, peer: &B512) -> usize {
        let current = self.in_flight.get(peer).map_or(0, |q| q.len());
        PIPELINE_DEPTH.saturating_sub(current)
    }

    /// Peers that have chunks in flight but haven't responded within `timeout`.
    pub fn stalled_peers(&self, timeout: Duration) -> Vec<B512> {
        self.waiting_since
            .iter()
            .filter(|(peer, since)| {
                since.elapsed() > timeout
                    && self.in_flight.get(*peer).is_some_and(|q| !q.is_empty())
            })
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Reassigns all in-flight chunks from a disconnected peer back to the
    /// assignment pool by resetting `next_to_assign` to the minimum.
    pub fn handle_peer_disconnect(&mut self, peer: &B512) {
        self.waiting_since.remove(peer);
        if let Some(queue) = self.in_flight.remove(peer) {
            for idx in queue {
                if idx >= self.next_to_process && !self.buffered.contains_key(&idx) && idx < self.next_to_assign {
                    self.next_to_assign = idx;
                }
            }
        }
    }
}
