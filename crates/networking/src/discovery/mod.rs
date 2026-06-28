pub mod message;
pub mod table;

#[cfg(test)]
mod tests;

use tokio::net::UdpSocket;
use message::{DiscoveryPacket, DiscoveryPayload, PongMessage, DiscoveryEndpoint, DiscoveryNode};
use table::NodeTable;
use crate::peers::PeerStore;
use alloy_primitives::B512;
use k256::ecdsa::SigningKey;
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, debug, trace, warn, error};

/// Normal interval between discovery rounds (ping + FindNode sweep).
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(15);
/// Faster interval used while we're below `LOW_PEER_FLOOR` active peers, to
/// re-seed the node table quickly instead of waiting a full round.
const DISCOVERY_INTERVAL_LOW: Duration = Duration::from_secs(5);
/// Active-peer count below which discovery switches to aggressive re-bootstrap:
/// it re-pings every bootstrap address (not just unknown ones) and polls on the
/// shorter interval. This self-heals the isolation that previously needed a
/// manual restart. Not present in rskj (whose Netty/SyncPool stack recovers
/// differently); a rustock improvement.
const LOW_PEER_FLOOR: usize = 4;
/// Backoff after a UDP socket receive error, so a persistently failing socket
/// can't hot-spin the recv loop and flood the logs.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// Service for node discovery using UDP based on RSK protocol.
///
/// rskj requires a full Ping/Pong bonding handshake before responding
/// to FindNode requests. The sequence is:
///   1. We send Ping → peer
///   2. Peer replies with Pong, and also sends us a Ping
///   3. We reply to their Ping with Pong
///   4. Peer adds us to their `establishedConnections`
///   5. Now peer will respond to our FindNode with Neighbors
///
/// We track peers that have sent us a Ping (to whom we replied with Pong)
/// as "bonded", and only send FindNode to those peers.
pub struct DiscoveryService {
    socket: UdpSocket,
    key: SigningKey,
    table: Arc<RwLock<NodeTable>>,
    /// Peers that have completed the bonding handshake (received their Ping,
    /// sent our Pong). Stored as socket addresses since we might not know
    /// the node ID at discovery time.
    bonded: Mutex<HashSet<std::net::SocketAddr>>,
    network_id: u32,
    local_node: DiscoveryNode,
    /// Bootstrap peer addresses (rskj `peer.discovery.ip.list`). Node IDs are
    /// unknown upfront; we ping these and learn IDs from their signed pongs.
    bootstrap_addrs: Vec<std::net::SocketAddr>,
    /// Active peer connections, used to detect when we're isolated and should
    /// re-bootstrap aggressively.
    peer_store: Arc<PeerStore>,
}

impl DiscoveryService {
    pub async fn new(
        listen_addr: &str,
        key: SigningKey,
        table: Arc<RwLock<NodeTable>>,
        network_id: u32,
        local_node: DiscoveryNode,
        bootstrap_addrs: Vec<std::net::SocketAddr>,
        peer_store: Arc<PeerStore>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        Ok(Self {
            socket,
            key,
            table,
            bonded: Mutex::new(HashSet::new()),
            network_id,
            local_node,
            bootstrap_addrs,
            peer_store,
        })
    }

    /// Starts the UDP service loop for processing discovery packets.
    pub async fn start(self: Arc<Self>) {
        let mut buf = [0u8; 4096];
        
        info!(target: "rustock::discovery", "Discovery service started");
        
        let receive_self = self.clone();
        tokio::spawn(async move {
            loop {
                match receive_self.socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        if let Err(e) = receive_self.handle_packet(&buf[..n], addr).await {
                            warn!(target: "rustock::discovery", "Error handling packet from {}: {:?}", addr, e);
                        }
                    }
                    Err(e) => {
                        // A persistent socket error must not hot-spin the loop
                        // (rskj's Netty stack handles this for us); back off so
                        // we don't peg a core and flood the logs.
                        error!(target: "rustock::discovery", "UDP socket error: {:?}", e);
                        tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                    }
                }
            }
        });

        // Background discovery loop
        loop {
            let nodes = self.table.read().await.all_nodes();
            let peer_count = self.peer_store.count().await;
            let low_peers = peer_count < LOW_PEER_FLOOR;

            // Ping bootstrap addresses we don't know yet (no node ID in the
            // table for their address); their pongs/pings get them added. When
            // peers are low, re-ping *every* bootstrap to aggressively re-seed
            // discovery and recover from isolation.
            let known_addrs: HashSet<std::net::SocketAddr> = nodes
                .iter()
                .filter_map(|n| {
                    crate::utils::bytes_to_ip(&n.ip)
                        .map(|ip| std::net::SocketAddr::new(ip, n.udp_port))
                })
                .collect();
            for addr in &self.bootstrap_addrs {
                if low_peers || !known_addrs.contains(addr) {
                    let _ = self.send_ping(*addr).await;
                }
            }

            let bonded = self.bonded.lock().await;

            trace!(
                target: "rustock::discovery",
                "Discovery loop: {} nodes in table, {} bonded, {} active peers{}",
                nodes.len(),
                bonded.len(),
                peer_count,
                if low_peers { " (low — re-bootstrapping)" } else { "" }
            );

            for node in &nodes {
                if let Some(ip) = crate::utils::bytes_to_ip(&node.ip) {
                    let socket_addr = std::net::SocketAddr::new(ip, node.udp_port);
                    let _ = self.send_ping(socket_addr).await;
                    if bonded.contains(&socket_addr) {
                        let _ = self.send_find_node(self.local_node.id, socket_addr).await;
                    }
                }
            }
            drop(bonded);

            // Keep the node table fresh. The bonding and FindNode flow needs
            // multiple rounds: first we Ping, then they Ping us back, then we
            // send FindNode on the next cycle. Poll faster while peers are low.
            let interval = if low_peers { DISCOVERY_INTERVAL_LOW } else { DISCOVERY_INTERVAL };
            tokio::time::sleep(interval).await;
        }
    }

    async fn send_ping(&self, to: std::net::SocketAddr) -> Result<()> {
        use uuid::Uuid;
        let payload = DiscoveryPayload::Ping(message::PingMessage {
            from: DiscoveryEndpoint {
                ip: self.local_node.ip.clone(),
                udp_port: self.local_node.udp_port,
                tcp_port: self.local_node.tcp_port,
            },
            to: self.addr_to_endpoint(to),
            message_id: Uuid::new_v4().to_string(),
            network_id: self.network_id,
        });
        let packet = DiscoveryPacket::create(payload, &self.key)?;
        self.socket.send_to(&packet.encode(), to).await?;
        Ok(())
    }

    async fn send_find_node(&self, target: B512, to: std::net::SocketAddr) -> Result<()> {
        use uuid::Uuid;
        let payload = DiscoveryPayload::FindNode(message::FindNodeMessage {
            target,
            message_id: Uuid::new_v4().to_string(),
            network_id: self.network_id,
        });
        let packet = DiscoveryPacket::create(payload, &self.key)?;
        self.socket.send_to(&packet.encode(), to).await?;
        Ok(())
    }

    async fn handle_packet(&self, buf: &[u8], addr: std::net::SocketAddr) -> Result<()> {
        let packet = DiscoveryPacket::decode(buf)?;
        
        match &packet.payload {
            DiscoveryPayload::Ping(ping) => {
                trace!(target: "rustock::discovery", "Received Ping from {}", addr);
                // Reply with Pong to complete bonding from the remote's perspective
                self.send_pong(ping.message_id.clone(), addr).await?;
                
                let node = DiscoveryNode {
                    ip: crate::utils::ip_to_bytes(addr.ip()),
                    udp_port: addr.port(),
                    tcp_port: ping.from.tcp_port,
                    id: packet.recover_id()?,
                };
                self.table.write().await.add_node(node);

                // Mark this peer as bonded — we replied with Pong, so the
                // remote will accept our FindNode after processing our Pong.
                let newly_bonded = self.bonded.lock().await.insert(addr);
                if newly_bonded {
                    debug!(
                        target: "rustock::discovery",
                        "Bonded with new peer at {}",
                        addr
                    );
                    // Small delay to let the remote process our Pong before
                    // we send FindNode. rskj adds us to establishedConnections
                    // upon receiving our Pong; without this delay, FindNode
                    // may arrive before Pong is processed.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    let _ = self.send_find_node(self.local_node.id, addr).await;
                }
            }
            DiscoveryPayload::Pong(pong) => {
                trace!(target: "rustock::discovery", "Received Pong from {}", addr);
                // Like rskj's PeerExplorer.handlePong: learn the node from the
                // pong, recovering its ID from the packet signature.
                let tcp_port = if pong.from.tcp_port != 0 { pong.from.tcp_port } else { addr.port() };
                let node = DiscoveryNode {
                    ip: crate::utils::ip_to_bytes(addr.ip()),
                    udp_port: addr.port(),
                    tcp_port,
                    id: packet.recover_id()?,
                };
                self.table.write().await.add_node(node);
            }
            DiscoveryPayload::FindNode(find) => {
                trace!(target: "rustock::discovery", "Received FindNode from {}", addr);
                let closest = self.table.read().await.closest_nodes(&find.target, 16);
                self.send_neighbors(find.message_id.clone(), closest, addr).await?;
            }
            DiscoveryPayload::Neighbors(neighbors) => {
                trace!(
                    target: "rustock::discovery",
                    "Received {} neighbors from {}",
                    neighbors.nodes.len(),
                    addr
                );
                let mut table = self.table.write().await;
                for node in &neighbors.nodes {
                    table.add_node(node.clone());
                }
            }
        }
        
        Ok(())
    }

    async fn send_pong(&self, message_id: String, to: std::net::SocketAddr) -> Result<()> {
        let payload = DiscoveryPayload::Pong(PongMessage {
            from: DiscoveryEndpoint {
                ip: self.local_node.ip.clone(),
                udp_port: self.local_node.udp_port,
                tcp_port: self.local_node.tcp_port,
            },
            to: self.addr_to_endpoint(to),
            message_id,
            network_id: self.network_id,
        });
        
        let packet = DiscoveryPacket::create(payload, &self.key)?;
        self.socket.send_to(&packet.encode(), to).await?;
        Ok(())
    }

    async fn send_neighbors(&self, message_id: String, nodes: Vec<DiscoveryNode>, to: std::net::SocketAddr) -> Result<()> {
        let payload = DiscoveryPayload::Neighbors(message::NeighborsMessage {
            nodes,
            message_id,
            network_id: self.network_id,
        });
        
        let packet = DiscoveryPacket::create(payload, &self.key)?;
        self.socket.send_to(&packet.encode(), to).await?;
        Ok(())
    }

    fn addr_to_endpoint(&self, addr: std::net::SocketAddr) -> DiscoveryEndpoint {
        DiscoveryEndpoint {
            ip: crate::utils::ip_to_bytes(addr.ip()),
            udp_port: addr.port(),
            tcp_port: 0,
        }
    }
}
