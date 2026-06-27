use std::time::Instant;

use alloy_primitives::{B256, B512};
use rustock_core::Header;
use rustock_networking::protocol::BlockIdentifier;

use crate::tracker::PeerChunkTracker;

/// An outstanding body request for one block: the request id we're currently
/// waiting on, and when it was last (re)sent. The send time drives the
/// per-request timeout, so only the individually-stalled requests get
/// re-sent rather than re-blasting the whole in-flight window.
#[derive(Debug, Clone)]
pub struct InFlightBody {
    pub req_id: u64,
    pub sent: Instant,
}

/// The state machine for skeleton-based forward sync.
#[derive(Debug, Default)]
pub enum SyncState {
    /// Waiting for peers / nothing to do.
    #[default]
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
    /// Downloading header chunks along the skeleton (pipelined, multi-peer).
    DownloadingHeaders {
        peer_best: u64,
        skeleton: Vec<BlockIdentifier>,
        connection_point: u64,
        tracker: PeerChunkTracker,
        /// Pre-fetched skeleton for the next round (Optimization 4).
        pending_next_skeleton: Option<Vec<BlockIdentifier>>,
    },
    /// Downloading block bodies for headers we already have.
    DownloadingBodies {
        peer_best: u64,
        /// Headers whose bodies we still need, in ascending order.
        pending_headers: Vec<(B256, Header)>,
        /// Index of the next header to request a body for.
        next_request: usize,
        /// Outstanding blocks (requested but not yet stored), keyed by header
        /// index — exactly one entry per block, holding its current request id
        /// and last-sent time for the per-request timeout.
        in_flight: std::collections::HashMap<usize, InFlightBody>,
        /// Every request id ever sent (current or superseded by a retry) → its
        /// header index, so a late response to an old id still applies its body
        /// instead of being discarded as "unknown". Entries are pruned as the
        /// matching blocks are stored.
        id_index: std::collections::HashMap<u64, usize>,
    },
    /// At or near the chain tip — listening for NewBlockHashes announcements
    /// and fetching individual headers as they arrive.
    Following,
}

