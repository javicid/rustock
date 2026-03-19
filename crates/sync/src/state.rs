use alloy_primitives::{B256, B512};
use rustock_core::Header;
use rustock_networking::protocol::BlockIdentifier;

use crate::tracker::PeerChunkTracker;

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
        /// Map of in-flight request IDs to header indices.
        in_flight: std::collections::HashMap<u64, usize>,
    },
    /// At or near the chain tip — listening for NewBlockHashes announcements
    /// and fetching individual headers as they arrive.
    Following,
}

