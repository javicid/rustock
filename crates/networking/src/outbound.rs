use crate::node::{NodeConfig, register_and_run_session};
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
    ///
    /// Uses aggressive intervals (5s) for the first few cycles to fill
    /// the peer table quickly, then settles to 30s.
    pub async fn start(self) {
        info!(target: "rustock::net", "Outbound connector started (target outbound: {})", self.max_outbound);

        const FAST_INTERVAL: Duration = Duration::from_secs(5);
        const NORMAL_INTERVAL: Duration = Duration::from_secs(30);
        const FAST_CYCLES: u32 = 6;

        let mut cycle = 0u32;

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
                                            info!(target: "rustock::net", "Outbound handshake successful: {:?}", peer_id);
                                            let _ = register_and_run_session(
                                                peer_id, rsk_status, framed, handlers, peer_store,
                                            ).await;
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

            let interval = if cycle < FAST_CYCLES { FAST_INTERVAL } else { NORMAL_INTERVAL };
            sleep(interval).await;
            cycle = cycle.saturating_add(1);
        }
    }

}
