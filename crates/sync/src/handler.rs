use crate::events::SyncEvent;
use crate::manager::SyncManager;
use alloy_primitives::B512;
use rustock_networking::protocol::{P2pHandler, P2pMessage, RskSubMessage};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

/// Dispatches inbound messages to the state machine channel.
pub struct SyncHandler {
    manager: Arc<SyncManager>,
    event_tx: mpsc::UnboundedSender<SyncEvent>,
}

impl SyncHandler {
    pub fn new(manager: Arc<SyncManager>, event_tx: mpsc::UnboundedSender<SyncEvent>) -> Self {
        Self { manager, event_tx }
    }
}

impl P2pHandler for SyncHandler {
    fn handle_message(&self, id: B512, msg: P2pMessage) -> Option<P2pMessage> {
        if let P2pMessage::RskMessage(m) = msg {
            match m.sub_message {
                RskSubMessage::Status(s) => {
                    info!(
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
                        identifiers: r.block_identifiers,
                    });
                }
                RskSubMessage::BlockHeadersResponse(r) => {
                    let _ = self.event_tx.send(SyncEvent::HeadersResponse {
                        peer: id,
                        headers: r.headers,
                    });
                }
                _ => {}
            }
        }
        None
    }
}
