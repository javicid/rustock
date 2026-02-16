use tokio::net::{TcpListener, TcpStream};
use crate::protocol::P2pHandler;
use crate::handshake::Handshake;
use crate::peers::PeerStore;
use alloy_primitives::{B512, B256, U256};
use anyhow::{Result, Context};
use std::sync::Arc;
use tracing::{info, error, debug};

/// A P2P Node that manages incoming connections and peer handshakes.
pub struct Node {
    pub config: NodeConfig,
    pub handlers: Vec<Arc<dyn P2pHandler>>,
    peer_store: Arc<PeerStore>,
}

/// Configuration for the P2P node.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub client_id: String,
    pub listen_port: u16,
    pub id: B512,
    pub chain_id: u8,
    pub network_id: u64,
    pub genesis_hash: B256,
    pub best_hash: B256,
    pub total_difficulty: U256,
    pub bootnodes: Vec<String>,
    pub secret_key: [u8; 32],
    pub discovery_port: u16,
    pub data_dir: String,
}

impl Node {
    pub fn new(config: NodeConfig) -> Self {
        Self { 
            config,
            handlers: Vec::new(),
            peer_store: Arc::new(PeerStore::new()),
        }
    }

    pub fn with_peer_store(config: NodeConfig, peer_store: Arc<PeerStore>) -> Self {
        Self {
            config,
            handlers: Vec::new(),
            peer_store,
        }
    }

    /// Adds a message handler to the node.
    pub fn add_handler(&mut self, handler: Arc<dyn P2pHandler>) {
        self.handlers.push(handler);
    }

    /// Starts the P2P node listening on the configured port and starts discovery.
    pub async fn start(&self) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.listen_port);
        let listener = TcpListener::bind(&addr).await.context("Failed to bind listener")?;
        
        info!(target: "rustock::net", "P2P node started on {}", addr);

        // 1. Initialize Discovery
        let table = Arc::new(tokio::sync::Mutex::from(crate::discovery::table::NodeTable::new(self.config.id)));
        let discovery_path = std::path::Path::new(&self.config.data_dir).join("discovery.rlp");
        
        // Load existing nodes
        {
            let mut table_lock = table.lock().await;
            if discovery_path.exists() {
                match tokio::fs::read(&discovery_path).await {
                    Ok(data) => {
                        if let Err(e) = table_lock.decode_and_add(&data) {
                            debug!(target: "rustock::net", "Failed to decode discovery table: {:?}", e);
                        }
                    }
                    Err(e) => {
                        debug!(target: "rustock::net", "Failed to read discovery table: {:?}", e);
                    }
                }
            }
            // Add bootnodes
            for enode in &self.config.bootnodes {
                if let Err(e) = table_lock.add_enode(enode) {
                    error!(target: "rustock::net", "Failed to add bootnode {}: {:?}", enode, e);
                }
            }
        }

        let signing_key = k256::ecdsa::SigningKey::from_slice(&self.config.secret_key)
            .context("Invalid secret key")?;
            
        let local_node = crate::discovery::message::DiscoveryNode {
            ip: alloy_primitives::Bytes::from(vec![127, 0, 0, 1]), // TODO: Resolve local IP
            udp_port: self.config.discovery_port,
            tcp_port: self.config.listen_port,
            id: self.config.id,
        };

        let discovery_addr = format!("0.0.0.0:{}", self.config.discovery_port);
        let discovery = Arc::new(crate::discovery::DiscoveryService::new(
            &discovery_addr,
            signing_key,
            table.clone(),
            self.config.network_id as u32,
            local_node,
        ).await?);

        // Start discovery service in background
        let discovery_task = discovery.start();
        tokio::spawn(discovery_task);

        // Periodically save discovery table
        let table_save = table.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                let data = table_save.lock().await.encode();
                if let Err(e) = tokio::fs::write(&discovery_path, data).await {
                    error!(target: "rustock::net", "Failed to save discovery table: {:?}", e);
                }
            }
        });

        // 2. Start Outbound Connector
        let outbound = crate::outbound::OutboundConnector::new(
            self.config.clone(),
            table.clone(),
            self.peer_store.clone(),
            self.handlers.clone(),
            10, // Max outbound connections
        );
        tokio::spawn(outbound.start());

        // 3. Start Accept Loop
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!(target: "rustock::net", "New connection from: {}", peer_addr);
            
            let config = self.config.clone();
            let handlers = self.handlers.clone();
            let peer_store = self.peer_store.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_incoming(stream, config, handlers, peer_store).await {
                    error!(target: "rustock::net", "Error handling peer {}: {:?}", peer_addr, e);
                }
            });
        }
    }
}

use tokio::sync::mpsc;
use crate::session::PeerSession;
use crate::protocol::rsk::RskStatus;

/// Registers a peer and runs a session. Shared by incoming and outbound connection paths.
pub(crate) async fn register_and_run_session(
    peer_id: B512,
    rsk_status: RskStatus,
    framed: tokio_util::codec::Framed<TcpStream, crate::handshake::HandshakeCodec>,
    handlers: Vec<Arc<dyn P2pHandler>>,
    peer_store: Arc<PeerStore>,
) -> Result<()> {
    let (tx, rx) = mpsc::unbounded_channel();

    if !peer_store.add_peer(peer_id, tx).await {
        debug!(target: "rustock::net", "Peer already connected: {:?}", peer_id);
        return Ok(());
    }

    let metadata = crate::peers::PeerMetadata {
        best_number: rsk_status.best_block_number,
        best_hash: rsk_status.best_block_hash,
        total_difficulty: rsk_status.total_difficulty.unwrap_or_default(),
        client_id: String::new(),
    };
    peer_store.update_metadata(&peer_id, metadata).await;

    let mut session = PeerSession::from_framed(peer_id, framed, rx);
    for handler in handlers {
        session.add_handler(handler);
    }

    let res = session.run().await;
    peer_store.remove_peer(&peer_id).await;
    res
}

/// Handles an incoming connection by performing a handshake and starting a session.
pub async fn handle_incoming(
    stream: TcpStream, 
    config: NodeConfig, 
    handlers: Vec<Arc<dyn P2pHandler>>,
    peer_store: Arc<PeerStore>,
) -> Result<()> {
    let handshake = Handshake::new(stream, config, None);
    let (peer_id, rsk_status, framed) = handshake.run().await?;
    register_and_run_session(peer_id, rsk_status, framed, handlers, peer_store).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B512;
    use tokio::time::{sleep, Duration, timeout};

    #[tokio::test]
    async fn test_handshake() {
        let node1_config = NodeConfig {
            client_id: "Node1".to_string(),
            listen_port: 0,
            id: B512::ZERO,
            chain_id: 33,
            network_id: 33,
            genesis_hash: B256::repeat_byte(0xaa),
            best_hash: B256::repeat_byte(0xaa),
            total_difficulty: U256::ZERO,
            bootnodes: vec![],
            secret_key: [0x42; 32],
            discovery_port: 0,
            data_dir: ".".to_string(),
        };
        
        let node2_config = NodeConfig {
            client_id: "Node2".to_string(),
            listen_port: 0,
            id: B512::repeat_byte(0x01),
            chain_id: 33,
            network_id: 33,
            genesis_hash: B256::repeat_byte(0xaa),
            best_hash: B256::repeat_byte(0xaa),
            total_difficulty: U256::ZERO,
            bootnodes: vec![],
            secret_key: [0x43; 32],
            discovery_port: 0,
            data_dir: ".".to_string(),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{}", port);
        
        let node1_store = Arc::new(PeerStore::new());
        let _node2_store = Arc::new(PeerStore::new());

        let node1_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = timeout(Duration::from_secs(2), handle_incoming(stream, node1_config, vec![], node1_store)).await;
        });

        let node2_task = tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            let stream = TcpStream::connect(addr).await.unwrap();
            let handshake = Handshake::new(stream, node2_config, None);
            let _ = timeout(Duration::from_secs(2), handshake.run()).await;
        });

        let _ = tokio::join!(node1_task, node2_task);
    }

    struct PingHandler;
    impl crate::protocol::P2pHandler for PingHandler {
        fn handle_message(&self, _id: alloy_primitives::B512, msg: crate::protocol::P2pMessage) -> Option<crate::protocol::P2pMessage> {
            if let crate::protocol::P2pMessage::Ping = msg {
                Some(crate::protocol::P2pMessage::Pong)
            } else {
                None
            }
        }
    }

    #[test]
    fn test_handler_logic() {
        let handler = PingHandler;
        let response = handler.handle_message(alloy_primitives::B512::ZERO, crate::protocol::P2pMessage::Ping);
        assert!(matches!(response, Some(crate::protocol::P2pMessage::Pong)));
        
        let response = handler.handle_message(alloy_primitives::B512::ZERO, crate::protocol::P2pMessage::Pong);
        assert!(response.is_none());
    }
}
