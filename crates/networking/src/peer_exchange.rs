use crate::discovery::message::DiscoveryNode;
use crate::discovery::table::NodeTable;
use crate::protocol::p2p::PeerInfo;
use crate::protocol::{P2pHandler, P2pMessage};
use alloy_primitives::B512;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

/// Maximum number of peers to return in a Peers response.
const MAX_PEERS_RESPONSE: usize = 25;

/// Handles P2P peer exchange: responds to GetPeers requests and ingests
/// Peers messages into the discovery table for future outbound connections.
pub struct PeerExchangeHandler {
    table: Arc<Mutex<NodeTable>>,
}

impl PeerExchangeHandler {
    pub fn new(table: Arc<Mutex<NodeTable>>) -> Self {
        Self { table }
    }
}

impl P2pHandler for PeerExchangeHandler {
    fn handle_message(&self, id: B512, msg: P2pMessage) -> Option<P2pMessage> {
        match msg {
            P2pMessage::GetPeers => {
                let table = self.table.try_lock().ok()?;
                let nodes = table.get_all_nodes();
                let peers: Vec<PeerInfo> = nodes
                    .into_iter()
                    .filter(|n| n.id != id)
                    .take(MAX_PEERS_RESPONSE)
                    .map(|n| PeerInfo {
                        ip: n.ip,
                        port: n.tcp_port,
                        id: n.id,
                    })
                    .collect();
                debug!(
                    target: "rustock::net",
                    "Responding to GetPeers with {} peers",
                    peers.len()
                );
                Some(P2pMessage::Peers(peers))
            }
            P2pMessage::Peers(peers) => {
                if let Ok(mut table) = self.table.try_lock() {
                    let mut added = 0usize;
                    for peer in &peers {
                        let node = DiscoveryNode {
                            ip: peer.ip.clone(),
                            udp_port: peer.port,
                            tcp_port: peer.port,
                            id: peer.id,
                        };
                        if table.add_node(node) {
                            added += 1;
                        }
                    }
                    info!(
                        target: "rustock::net",
                        "Peer exchange: received {} peers, added {} new to discovery table",
                        peers.len(),
                        added
                    );
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    fn make_handler_with_nodes(
        local_id: B512,
        nodes: Vec<DiscoveryNode>,
    ) -> PeerExchangeHandler {
        let table = crate::discovery::table::NodeTable::new(local_id);
        let table = Arc::new(Mutex::new(table));
        {
            let mut t = table.try_lock().unwrap();
            for n in nodes {
                t.add_node(n);
            }
        }
        PeerExchangeHandler::new(table)
    }

    fn make_node(byte: u8, port: u16) -> DiscoveryNode {
        DiscoveryNode {
            ip: Bytes::from(vec![10, 0, 0, byte]),
            udp_port: port,
            tcp_port: port,
            id: B512::repeat_byte(byte),
        }
    }

    #[test]
    fn test_get_peers_returns_known_nodes() {
        let local_id = B512::repeat_byte(0x00);
        let nodes = vec![make_node(1, 5000), make_node(2, 5001), make_node(3, 5002)];
        let handler = make_handler_with_nodes(local_id, nodes);

        let requester = B512::repeat_byte(0x01);
        let response = handler.handle_message(requester, P2pMessage::GetPeers);

        match response {
            Some(P2pMessage::Peers(peers)) => {
                // Requester's own ID should be filtered out
                assert!(
                    peers.iter().all(|p| p.id != requester),
                    "Requester should not appear in Peers response"
                );
                // Should have at least the other 2 nodes
                assert!(peers.len() >= 2);
            }
            other => panic!("Expected Peers response, got {:?}", other),
        }
    }

    #[test]
    fn test_get_peers_empty_table() {
        let local_id = B512::repeat_byte(0x00);
        let handler = make_handler_with_nodes(local_id, vec![]);

        let requester = B512::repeat_byte(0xFF);
        let response = handler.handle_message(requester, P2pMessage::GetPeers);

        match response {
            Some(P2pMessage::Peers(peers)) => {
                assert!(peers.is_empty());
            }
            other => panic!("Expected Peers response, got {:?}", other),
        }
    }

    #[test]
    fn test_get_peers_respects_max_limit() {
        let local_id = B512::repeat_byte(0x00);
        let nodes: Vec<DiscoveryNode> = (1..=50u8)
            .map(|i| make_node(i, 5000 + i as u16))
            .collect();
        let handler = make_handler_with_nodes(local_id, nodes);

        let requester = B512::repeat_byte(0xFF);
        let response = handler.handle_message(requester, P2pMessage::GetPeers);

        match response {
            Some(P2pMessage::Peers(peers)) => {
                assert!(
                    peers.len() <= MAX_PEERS_RESPONSE,
                    "Should not exceed MAX_PEERS_RESPONSE={}, got {}",
                    MAX_PEERS_RESPONSE,
                    peers.len()
                );
            }
            other => panic!("Expected Peers response, got {:?}", other),
        }
    }

    #[test]
    fn test_peers_message_adds_to_table() {
        let local_id = B512::repeat_byte(0x00);
        let handler = make_handler_with_nodes(local_id, vec![]);

        let incoming_peers = vec![
            PeerInfo {
                ip: Bytes::from(vec![10, 0, 0, 1]),
                port: 5000,
                id: B512::repeat_byte(0x01),
            },
            PeerInfo {
                ip: Bytes::from(vec![10, 0, 0, 2]),
                port: 5001,
                id: B512::repeat_byte(0x02),
            },
        ];

        let sender = B512::repeat_byte(0xAA);
        let response = handler.handle_message(sender, P2pMessage::Peers(incoming_peers));

        // Peers message should not produce a reply
        assert!(response.is_none());

        // Verify nodes were added to the table
        let table = handler.table.try_lock().unwrap();
        let all = table.get_all_nodes();
        assert_eq!(all.len(), 2);
        let ids: Vec<B512> = all.iter().map(|n| n.id).collect();
        assert!(ids.contains(&B512::repeat_byte(0x01)));
        assert!(ids.contains(&B512::repeat_byte(0x02)));
    }

    #[test]
    fn test_peers_message_deduplicates() {
        let local_id = B512::repeat_byte(0x00);
        let existing = make_node(1, 5000);
        let handler = make_handler_with_nodes(local_id, vec![existing]);

        // Send Peers containing the same node again
        let peers = vec![PeerInfo {
            ip: Bytes::from(vec![10, 0, 0, 1]),
            port: 5000,
            id: B512::repeat_byte(0x01),
        }];

        let sender = B512::repeat_byte(0xAA);
        handler.handle_message(sender, P2pMessage::Peers(peers));

        let table = handler.table.try_lock().unwrap();
        let all = table.get_all_nodes();
        // Should still be 1, not duplicated
        let count = all.iter().filter(|n| n.id == B512::repeat_byte(0x01)).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_unrelated_message_ignored() {
        let local_id = B512::repeat_byte(0x00);
        let handler = make_handler_with_nodes(local_id, vec![]);

        let peer = B512::repeat_byte(0x01);
        let response = handler.handle_message(peer, P2pMessage::Disconnect(0));
        assert!(response.is_none());
    }
}
