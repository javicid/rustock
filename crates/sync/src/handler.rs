use crate::events::SyncEvent;
use crate::manager::SyncManager;
use alloy_primitives::B512;
use rustock_networking::protocol::{
    BlockHashResponse, BlockHeadersResponse, BlockIdentifier,
    P2pHandler, P2pMessage, RskMessage, RskSubMessage, SkeletonResponse,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::trace;

/// Skeleton step size (must match rskj's chunkSize = 192).
const SKELETON_STEP: u64 = 192;

/// Maximum skeleton entries per response (matches rskj's maxSkeletonChunks = 20).
const MAX_SKELETON_ENTRIES: usize = 20;

/// Maximum headers to serve in a single response.
const MAX_HEADERS_SERVE: u32 = 192;

/// Dispatches inbound messages to the state machine channel and serves
/// data to peers (headers, block hashes, skeletons).
pub struct SyncHandler {
    manager: Arc<SyncManager>,
    event_tx: mpsc::UnboundedSender<SyncEvent>,
}

impl SyncHandler {
    pub fn new(manager: Arc<SyncManager>, event_tx: mpsc::UnboundedSender<SyncEvent>) -> Self {
        Self { manager, event_tx }
    }

    /// Respond to a BlockHeadersRequest by walking backwards from the given
    /// hash, collecting up to `count` headers (same logic as rskj).
    fn serve_headers_request(
        &self,
        request_id: u64,
        hash: alloy_primitives::B256,
        count: u32,
    ) -> Option<P2pMessage> {
        let count = count.min(MAX_HEADERS_SERVE);
        let store = &self.manager.store;

        let first = store.header(hash).ok()??;
        let mut headers = vec![first.clone()];
        let mut current = first;

        for _ in 1..count {
            match store.header(current.parent_hash) {
                Ok(Some(parent)) => {
                    current = parent.clone();
                    headers.push(parent);
                }
                _ => break,
            }
        }

        trace!(
            target: "rustock::sync",
            "Serving {} headers (starting from {:?})",
            headers.len(), hash
        );

        let resp = BlockHeadersResponse {
            id: request_id,
            headers,
        };
        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::BlockHeadersResponse(resp),
        )))
    }

    /// Respond to a BlockHashRequest by looking up the canonical hash at the
    /// requested height.
    fn serve_block_hash_request(
        &self,
        request_id: u64,
        height: u64,
    ) -> Option<P2pMessage> {
        if height == 0 {
            return None;
        }
        let hash = self.manager.store.canonical_hash(height).ok()??;
        trace!(
            target: "rustock::sync",
            "Serving block hash for height #{}: {:?}",
            height, hash
        );
        let resp = BlockHashResponse {
            id: request_id,
            hash,
        };
        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::BlockHashResponse(resp),
        )))
    }

    /// Respond to a SkeletonRequest by constructing evenly-spaced block
    /// identifiers from the requested start (matching rskj's algorithm).
    fn serve_skeleton_request(
        &self,
        request_id: u64,
        start_number: u64,
    ) -> Option<P2pMessage> {
        let store = &self.manager.store;

        // Verify we have the starting block
        store.canonical_hash(start_number).ok()??;

        let best_number = store
            .head()
            .ok()?
            .and_then(|h| store.header(h).ok()?)
            .map(|h| h.number)?;

        let skeleton_start = (start_number / SKELETON_STEP) * SKELETON_STEP;
        let max_skeleton_number = best_number.min(
            skeleton_start + SKELETON_STEP * MAX_SKELETON_ENTRIES as u64,
        );

        let mut identifiers = Vec::new();
        let mut n = skeleton_start;
        while n < max_skeleton_number {
            if let Ok(Some(hash)) = store.canonical_hash(n) {
                identifiers.push(BlockIdentifier { hash, number: n });
            }
            n += SKELETON_STEP;
        }

        // Always include the best block (or the last skeleton point if equal)
        let last_number = best_number.min(n);
        if let Ok(Some(hash)) = store.canonical_hash(last_number) {
            if identifiers.last().map_or(true, |last| last.number != last_number) {
                identifiers.push(BlockIdentifier {
                    hash,
                    number: last_number,
                });
            }
        }

        if identifiers.is_empty() {
            return None;
        }

        trace!(
            target: "rustock::sync",
            "Serving skeleton ({} entries, #{} -> #{})",
            identifiers.len(),
            identifiers.first().map(|b| b.number).unwrap_or(0),
            identifiers.last().map(|b| b.number).unwrap_or(0)
        );

        let resp = SkeletonResponse {
            id: request_id,
            block_identifiers: identifiers,
        };
        Some(P2pMessage::RskMessage(RskMessage::new(
            RskSubMessage::SkeletonResponse(resp),
        )))
    }
}

impl P2pHandler for SyncHandler {
    fn handle_message(&self, id: B512, msg: &P2pMessage) -> Option<P2pMessage> {
        if let P2pMessage::RskMessage(m) = msg {
            match &m.sub_message {
                RskSubMessage::Status(s) => {
                    trace!(
                        target: "rustock::sync",
                        "Received status from peer {:?}: #{} (TD: {:?})",
                        id,
                        s.best_block_number,
                        s.total_difficulty
                    );
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
                        identifiers: r.block_identifiers.clone(),
                    });
                }
                RskSubMessage::BlockHeadersResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::HeadersResponse {
                        peer: id,
                        headers: r.headers.clone(),
                    });
                }
                RskSubMessage::NewBlockHashes(blocks) => {
                    let _ = self.event_tx.send(SyncEvent::NewBlockHashes {
                        peer: id,
                        identifiers: blocks.clone(),
                    });
                }

                // --- Serve data to peers ---
                RskSubMessage::BlockHeadersRequest(r) => {
                    return self.serve_headers_request(r.id, r.query.hash, r.query.count);
                }
                RskSubMessage::BlockHashRequest(r) => {
                    return self.serve_block_hash_request(r.id, r.height);
                }
                RskSubMessage::SkeletonRequest(r) => {
                    return self.serve_skeleton_request(r.id, r.start_number);
                }

                _ => {}
            }
        }
        None
    }
}
