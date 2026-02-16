use alloy_primitives::B512;
use rustock_networking::protocol::BlockIdentifier;

/// The state machine for skeleton-based forward sync.
#[derive(Debug)]
pub enum SyncState {
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
