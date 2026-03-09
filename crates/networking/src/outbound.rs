use crate::node::{NodeConfig, register_and_run_session};
use crate::discovery::table::NodeTable;
use crate::protocol::P2pHandler;
use crate::handshake::Handshake;
use crate::peers::PeerStore;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Duration};
use tracing::{info, trace, warn};
use tokio::net::TcpStream;

/// Service that proactively initiates connections to peers discovered in the network.
pub struct OutboundConnector {
    config: NodeConfig,
    table: Arc<RwLock<NodeTable>>,
    peer_store: Arc<PeerStore>,
    handlers: Vec<Arc<dyn P2pHandler>>,
    max_outbound: usize,
}

impl OutboundConnector {
    pub fn new(
        config: NodeConfig, 
        table: Arc<RwLock<NodeTable>>, 
        peer_store: Arc<PeerStore>,
        handlers: Vec<Arc<dyn P2pHandler>>, 
        max_outbound: usize
    ) -> Self {
        Self { config, table, peer_store, handlers, max_outbound }
    }

    /// Starts the outbound connection loop.
    ///
    /// Uses aggressive intervals when below the target peer count and backs
    /// off once the target is met. Tracks recently failed addresses to avoid
    /// retrying the same unreachable nodes every cycle.
    pub async fn start(self) {
        info!(target: "rustock::net", "Outbound connector started (target outbound: {})", self.max_outbound);

        const ACTIVE_INTERVAL: Duration = Duration::from_secs(10);
        const IDLE_INTERVAL: Duration = Duration::from_secs(60);
        const FAIL_COOLDOWN: Duration = Duration::from_secs(120);

        // Track recently failed addresses with the time they failed
        let failed: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));

        loop {
            let current_count = self.peer_store.count().await;

            if current_count >= self.max_outbound {
                sleep(IDLE_INTERVAL).await;
                continue;
            }

            let needed = self.max_outbound - current_count;
            let nodes = self.table.read().await.all_nodes();
            let table_size = nodes.len();

            // Try more candidates than needed since many will fail.
            // Attempt up to 3x needed, capped at available nodes.
            let attempt_limit = std::cmp::min(needed * 3, nodes.len());

            trace!(
                target: "rustock::net",
                "Outbound: {}/{} peers. Trying up to {} of {} discovered nodes",
                current_count, self.max_outbound, attempt_limit, table_size
            );

            let mut attempted = 0;
            let failed_snapshot = failed.lock().await.clone();

            for node in nodes {
                if attempted >= attempt_limit {
                    break;
                }

                if self.peer_store.is_connected(&node.id).await {
                    continue;
                }

                if let Some(ip) = crate::utils::bytes_to_ip(&node.ip) {
                    let addr = SocketAddr::new(ip, node.tcp_port);

                    // Skip recently failed addresses
                    if failed_snapshot.contains(&addr) {
                        continue;
                    }

                    let config = self.config.clone();
                    let handlers = self.handlers.clone();
                    let peer_store = self.peer_store.clone();
                    let remote_id = node.id;
                    let failed_ref = failed.clone();
                    
                    tokio::spawn(async move {
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            TcpStream::connect(addr),
                        ).await {
                            Ok(Ok(stream)) => {
                                trace!(target: "rustock::net", "TCP connected to outbound peer: {}", addr);
                                let handshake = Handshake::new(stream, config, Some(remote_id));
                                match tokio::time::timeout(Duration::from_secs(5), handshake.run()).await {
                                    Ok(Ok((peer_id, rsk_status, framed))) => {
                                        trace!(target: "rustock::net", "Outbound handshake successful: {:?}", &peer_id.as_slice()[..4]);
                                        let _ = register_and_run_session(
                                            peer_id, rsk_status, framed, handlers, peer_store,
                                        ).await;
                                        // Session ended (peer disconnected) — don't blacklist,
                                        // it was a valid peer that may accept again later
                                    }
                                    Ok(Err(e)) => {
                                        trace!(target: "rustock::net", "Outbound handshake failed for {}: {:?}", addr, e);
                                        failed_ref.lock().await.insert(addr);
                                    }
                                    Err(_) => {
                                        trace!(target: "rustock::net", "Outbound handshake timed out for {}", addr);
                                        failed_ref.lock().await.insert(addr);
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                trace!(target: "rustock::net", "Failed to connect to outbound peer {}: {:?}", addr, e);
                                failed_ref.lock().await.insert(addr);
                            }
                            Err(_) => {
                                trace!(target: "rustock::net", "TCP connect timed out for {}", addr);
                                failed_ref.lock().await.insert(addr);
                            }
                        }
                    });
                    
                    attempted += 1;
                }
            }

            if attempted == 0 && table_size > 0 {
                // All nodes are either connected or recently failed — clear the failed set
                // to allow retrying
                warn!(
                    target: "rustock::net",
                    "No new candidates to try ({} in table, {} recently failed). Clearing fail list.",
                    table_size, failed_snapshot.len()
                );
                failed.lock().await.clear();
            }

            // Clear the failed set periodically so nodes get another chance
            let failed_clone = failed.clone();
            tokio::spawn(async move {
                sleep(FAIL_COOLDOWN).await;
                failed_clone.lock().await.clear();
            });

            // Use shorter interval while below target
            sleep(ACTIVE_INTERVAL).await;
        }
    }
}
