use crate::node::NodeConfig;
use crate::discovery::table::NodeTable;
use crate::protocol::P2pHandler;
use crate::handshake::Handshake;
use crate::peers::PeerStore;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{info, debug};
use tokio::net::TcpStream;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use crate::session::PeerSession;

/// Service that proactively initiates connections to peers discovered in the network.
pub struct OutboundConnector {
    config: NodeConfig,
    table: Arc<Mutex<NodeTable>>,
    peer_store: Arc<PeerStore>,
    handlers: Vec<Arc<dyn P2pHandler>>,
    max_outbound: usize,
}

impl OutboundConnector {
    pub fn new(
        config: NodeConfig, 
        table: Arc<Mutex<NodeTable>>, 
        peer_store: Arc<PeerStore>,
        handlers: Vec<Arc<dyn P2pHandler>>, 
        max_outbound: usize
    ) -> Self {
        Self { config, table, peer_store, handlers, max_outbound }
    }

    /// Starts the outbound connection loop.
    pub async fn start(self) {
        info!(target: "rustock::net", "Outbound connector started (target outbound: {})", self.max_outbound);
        
        loop {
            let current_count = self.peer_store.count().await;
            if current_count < self.max_outbound {
                let needed = self.max_outbound - current_count;
                debug!(target: "rustock::net", "Outbound count: {}/{}. Attempting {} new connections", current_count, self.max_outbound, needed);
                
                let nodes = self.table.lock().await.get_all_nodes();
                let mut attempted = 0;
                
                for node in nodes {
                    if attempted >= needed {
                        break;
                    }

                    if self.peer_store.is_connected(&node.id).await {
                        continue;
                    }

                    if let Some(ip) = crate::utils::bytes_to_ip(&node.ip) {
                        let addr = SocketAddr::new(ip, node.tcp_port);
                        
                        let config = self.config.clone();
                        let handlers = self.handlers.clone();
                        let peer_store = self.peer_store.clone();
                        let remote_id = node.id;
                        
                        tokio::spawn(async move {
                            match TcpStream::connect(addr).await {
                                Ok(stream) => {
                                    debug!(target: "rustock::net", "TCP connected to outbound peer: {}", addr);
                                    let handshake = Handshake::new(stream, config, Some(remote_id));
                                    match tokio::time::timeout(Duration::from_secs(5), handshake.run()).await {
                                        Ok(Ok((peer_id, rsk_status, framed))) => {
                                            let (tx, rx) = mpsc::unbounded_channel();
                                            if peer_store.add_peer(peer_id, tx).await {
                                                info!(target: "rustock::net", "Outbound handshake successful: {:?}", peer_id);
                                                
                                                // Initialize metadata
                                                let metadata = crate::peers::PeerMetadata {
                                                    best_number: rsk_status.best_block_number,
                                                    best_hash: rsk_status.best_block_hash,
                                                    total_difficulty: rsk_status.total_difficulty.unwrap_or_default(),
                                                    client_id: "".to_string(), // TODO: Get from Hello
                                                };
                                                peer_store.update_metadata(&peer_id, metadata).await;

                                                let mut session = PeerSession::from_framed(peer_id, framed, rx);
                                                for handler in handlers {
                                                    session.add_handler(handler);
                                                }
                                                let _ = session.run().await;
                                                peer_store.remove_peer(&peer_id).await;
                                            } else {
                                                debug!(target: "rustock::net", "Outbound handshake finished but peer already connected: {:?}", peer_id);
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            debug!(target: "rustock::net", "Outbound handshake failed for {}: {:?}", addr, e);
                                        }
                                        Err(_) => {
                                            debug!(target: "rustock::net", "Outbound handshake timed out for {}", addr);
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!(target: "rustock::net", "Failed to connect to outbound peer {}: {:?}", addr, e);
                                }
                            }
                        });
                        
                        attempted += 1;
                    }
                }
            }
            
            sleep(Duration::from_secs(30)).await;
        }
    }

}
