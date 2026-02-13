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
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, debug, warn, error};

/// Service for node discovery using UDP based on RSK protocol.
pub struct DiscoveryService {
    socket: UdpSocket,
    key: SigningKey,
    table: Arc<Mutex<NodeTable>>,
    network_id: u32,
    _local_node: DiscoveryNode,
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
            network_id,
            _local_node: local_node,
        })
    }

    /// Starts the UDP service loop for processing discovery packets.
    pub async fn start(self: Arc<Self>) {
        let mut buf = [0u8; 4096]; // Larger than Ethernet MTU to handle large Neighbors packets
        
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
            for node in nodes {
                if let Some(ip) = crate::utils::bytes_to_ip(&node.ip) {
                    let socket_addr = std::net::SocketAddr::new(ip, node.udp_port);
                    let _ = self.send_ping(socket_addr).await;
                    let _ = self.send_find_node(self._local_node.id, socket_addr).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }


    async fn send_ping(&self, to: std::net::SocketAddr) -> Result<()> {
        use uuid::Uuid;
        let payload = DiscoveryPayload::Ping(message::PingMessage {
            from: DiscoveryEndpoint {
                ip: self._local_node.ip.clone(),
                udp_port: self._local_node.udp_port,
                tcp_port: self._local_node.tcp_port,
            },
            to: self.addr_to_endpoint(to),
            message_id: Uuid::new_v4().to_string(),
            network_id: self.network_id,
        });
        let packet = DiscoveryPacket::create(payload, &self.key);
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
        let packet = DiscoveryPacket::create(payload, &self.key);
        self.socket.send_to(&packet.encode(), to).await?;
        Ok(())
    }

    async fn handle_packet(&self, buf: &[u8], addr: std::net::SocketAddr) -> Result<()> {
        let packet = DiscoveryPacket::decode(buf)?;
        
        match &packet.payload {
            DiscoveryPayload::Ping(ping) => {
                debug!(target: "rustock::discovery", "Received Ping from {}", addr);
                self.send_pong(ping.message_id.clone(), addr).await?;
                
                let node = DiscoveryNode {
                    ip: crate::utils::ip_to_bytes(addr.ip()),
                    udp_port: addr.port(),
                    tcp_port: ping.from.tcp_port,
                    id: packet.recover_id()?,
                };
                self.table.lock().await.add_node(node);
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
                debug!(target: "rustock::discovery", "Received {} neighbors from {}", neighbors.nodes.len(), addr);
                for node in &neighbors.nodes {
                    self.table.lock().await.add_node(node.clone());
                }
            }
        }
        
        Ok(())
    }

    async fn send_pong(&self, message_id: String, to: std::net::SocketAddr) -> Result<()> {
        let payload = DiscoveryPayload::Pong(PongMessage {
            from: DiscoveryEndpoint {
                ip: self._local_node.ip.clone(),
                udp_port: self._local_node.udp_port,
                tcp_port: self._local_node.tcp_port,
            },
            to: self.addr_to_endpoint(to),
            message_id,
            network_id: self.network_id,
        });
        
        let packet = DiscoveryPacket::create(payload, &self.key);
        self.socket.send_to(&packet.encode(), to).await?;
        Ok(())
    }

    async fn send_neighbors(&self, message_id: String, nodes: Vec<DiscoveryNode>, to: std::net::SocketAddr) -> Result<()> {
        let payload = DiscoveryPayload::Neighbors(message::NeighborsMessage {
            nodes,
            message_id,
            network_id: self.network_id,
        });
        
        let packet = DiscoveryPacket::create(payload, &self.key);
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
