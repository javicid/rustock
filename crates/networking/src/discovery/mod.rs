pub mod message;
pub mod table;

#[cfg(test)]
mod tests;

use tokio::net::UdpSocket;
use message::{DiscoveryPacket, DiscoveryPayload, PongMessage, DiscoveryEndpoint, DiscoveryNode};
use table::NodeTable;
use alloy_primitives::B512;
use k256::ecdsa::SigningKey;
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, debug, warn, error};

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
    table: Arc<Mutex<NodeTable>>,
    /// Peers that have completed the bonding handshake (received their Ping,
    /// sent our Pong). Stored as socket addresses since we might not know
    /// the node ID at discovery time.
    bonded: Mutex<HashSet<std::net::SocketAddr>>,
    network_id: u32,
    local_node: DiscoveryNode,
}

impl DiscoveryService {
    pub async fn new(
        listen_addr: &str,
        key: SigningKey,
        table: Arc<Mutex<NodeTable>>,
        network_id: u32,
        local_node: DiscoveryNode,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(listen_addr).await?;
        Ok(Self {
            socket,
            key,
            table,
            bonded: Mutex::new(HashSet::new()),
            network_id,
            local_node,
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
                        error!(target: "rustock::discovery", "UDP socket error: {:?}", e);
                    }
                }
            }
        });

        // Background discovery loop
        loop {
            let nodes = self.table.lock().await.get_all_nodes();
            let bonded = self.bonded.lock().await;

            debug!(
                target: "rustock::discovery",
                "Discovery loop: {} nodes in table, {} bonded",
                nodes.len(),
                bonded.len()
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

            // Use 15s interval to keep the node table fresh. The bonding
            // and FindNode flow needs multiple rounds: first we Ping, then
            // they Ping us back, then we send FindNode on the next cycle.
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
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
                debug!(target: "rustock::discovery", "Received Ping from {}", addr);
                // Reply with Pong to complete bonding from the remote's perspective
                self.send_pong(ping.message_id.clone(), addr).await?;
                
                let node = DiscoveryNode {
                    ip: crate::utils::ip_to_bytes(addr.ip()),
                    udp_port: addr.port(),
                    tcp_port: ping.from.tcp_port,
                    id: packet.recover_id()?,
                };
                self.table.lock().await.add_node(node);

                // Mark this peer as bonded — we replied with Pong, so the
                // remote will accept our FindNode after processing our Pong.
                let newly_bonded = self.bonded.lock().await.insert(addr);
                if newly_bonded {
                    info!(
                        target: "rustock::discovery",
                        "Bonded with peer at {}, sending FindNode",
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
            DiscoveryPayload::Pong(_) => {
                debug!(target: "rustock::discovery", "Received Pong from {}", addr);
            }
            DiscoveryPayload::FindNode(find) => {
                debug!(target: "rustock::discovery", "Received FindNode from {}", addr);
                let closest = self.table.lock().await.get_closest_nodes(&find.target, 16);
                self.send_neighbors(find.message_id.clone(), closest, addr).await?;
            }
            DiscoveryPayload::Neighbors(neighbors) => {
                info!(
                    target: "rustock::discovery",
                    "Received {} neighbors from {}",
                    neighbors.nodes.len(),
                    addr
                );
                let mut table = self.table.lock().await;
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
