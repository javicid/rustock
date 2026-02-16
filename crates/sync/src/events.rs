use alloy_primitives::{B256, B512};
use rustock_core::types::header::Header;
use rustock_networking::protocol::BlockIdentifier;

/// Forwarded from SyncHandler to the SyncService state machine.
#[derive(Debug)]
pub enum SyncEvent {
    BlockHashResponse { peer: B512, hash: B256 },
    SkeletonResponse {
        peer: B512,
        identifiers: Vec<BlockIdentifier>,
    },
    HeadersResponse {
        peer: B512,
        headers: Vec<Header>,
    },
}
