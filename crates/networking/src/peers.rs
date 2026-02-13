use std::collections::HashMap;
use tokio::sync::{Mutex, mpsc};
use alloy_primitives::{B512, U256, B256};
use crate::protocol::P2pMessage;

/// Metadata about a connected peer.
#[derive(Debug, Clone, Default)]
pub struct PeerMetadata {
    pub best_number: u64,
    pub best_hash: B256,
    pub total_difficulty: U256,
    pub client_id: String,
}

struct PeerState {
    sender: mpsc::UnboundedSender<P2pMessage>,
    metadata: PeerMetadata,
}

/// Thread-safe store for tracking active peer connections and their outbound senders.
#[derive(Default)]
pub struct PeerStore {
    connected_peers: Mutex<HashMap<B512, PeerState>>,
}

impl PeerStore {
    pub fn new() -> Self {
        Self { connected_peers: Mutex::new(HashMap::new()) }
    }

    /// Attempts to add a peer to the store. Returns true if it was newly added.
    pub async fn add_peer(&self, id: B512, sender: mpsc::UnboundedSender<P2pMessage>) -> bool {
        let mut peers = self.connected_peers.lock().await;
        use std::collections::hash_map::Entry;
        match peers.entry(id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
                e.insert(PeerState { sender, metadata: PeerMetadata::default() });
                true
            }
        }
    }

    /// Updates the metadata for a peer.
    pub async fn update_metadata(&self, id: &B512, metadata: PeerMetadata) {
        let mut peers = self.connected_peers.lock().await;
        if let Some(state) = peers.get_mut(id) {
            state.metadata = metadata;
        }
    }

    /// Returns the metadata for a specific peer.
    pub async fn get_metadata(&self, id: &B512) -> Option<PeerMetadata> {
        let peers = self.connected_peers.lock().await;
        peers.get(id).map(|s| s.metadata.clone())
    }

    /// Finds the best peer to sync from based on total difficulty.
    pub async fn get_best_peer(&self) -> Option<(B512, PeerMetadata)> {
        let peers = self.connected_peers.lock().await;
        peers.iter()
            .max_by_key(|(_, s)| s.metadata.total_difficulty)
            .map(|(id, s)| (*id, s.metadata.clone()))
    }

    /// Removes a peer from the store.
    pub async fn remove_peer(&self, id: &B512) {
        self.connected_peers.lock().await.remove(id);
    }

    /// Checks if a peer is already connected.
    pub async fn is_connected(&self, id: &B512) -> bool {
        self.connected_peers.lock().await.contains_key(id)
    }

    /// Sends a message to a specific peer.
    pub async fn send_to_peer(&self, id: &B512, msg: P2pMessage) -> bool {
        let peers = self.connected_peers.lock().await;
        if let Some(state) = peers.get(id) {
            state.sender.send(msg).is_ok()
        } else {
            false
        }
    }

    /// Returns a list of all connected peer IDs.
    pub async fn get_peers(&self) -> Vec<B512> {
        self.connected_peers.lock().await.keys().cloned().collect()
    }
    
    /// Returns the number of active peer connections.
    pub async fn count(&self) -> usize {
        self.connected_peers.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B512;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_peer_store_flow() {
        let store = PeerStore::new();
        let id1 = B512::repeat_byte(0x01);
        let id2 = B512::repeat_byte(0x02);
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();

        // Add
        assert!(store.add_peer(id1, tx1).await);
        assert!(store.add_peer(id2, tx2).await);
        assert!(!store.add_peer(id1, mpsc::unbounded_channel().0).await); // Duplicate

        assert_eq!(store.count().await, 2);
        assert!(store.is_connected(&id1).await);
        
        // Get peers
        let peers = store.get_peers().await;
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&id1));
        assert!(peers.contains(&id2));

        // Send
        assert!(store.send_to_peer(&id1, P2pMessage::Ping).await);
        let msg = rx1.recv().await.unwrap();
        assert!(matches!(msg, P2pMessage::Ping));

        // Remove
        store.remove_peer(&id1).await;
        assert_eq!(store.count().await, 1);
        assert!(!store.is_connected(&id1).await);
        assert!(!store.send_to_peer(&id1, P2pMessage::Ping).await);
    }
}
