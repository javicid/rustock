use crate::protocol::{P2pMessage, HelloMessage, P2P_VERSION, EthStatus, RskStatus, RskMessage, RskSubMessage, Capability};
use crate::node::NodeConfig;
use crate::codec::P2pCodec;
use anyhow::{Result, Context};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use tracing::{info, debug};

use crate::rlpx::{RLPxHandshake, RLPxCodec};
use tokio_util::codec::{Decoder, Encoder};
use bytes::BytesMut;

pub enum HandshakeCodec {
    Plain(P2pCodec),
    RLPx(RLPxCodec),
}

impl Decoder for HandshakeCodec {
    type Item = P2pMessage;
    type Error = anyhow::Error;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        match self {
            Self::Plain(c) => c.decode(src),
            Self::RLPx(c) => c.decode(src),
        }
    }
}

impl Encoder<P2pMessage> for HandshakeCodec {
    type Error = anyhow::Error;
    fn encode(&mut self, item: P2pMessage, dst: &mut BytesMut) -> Result<()> {
        match self {
            Self::Plain(c) => c.encode(item, dst),
            Self::RLPx(c) => c.encode(item, dst),
        }
    }
}

pub struct Handshake {
    stream: TcpStream,
    config: NodeConfig,
    remote_id: Option<alloy_primitives::B512>,
}

impl Handshake {
    pub fn new(stream: TcpStream, config: NodeConfig, remote_id: Option<alloy_primitives::B512>) -> Self {
        Self {
            stream,
            config,
            remote_id,
        }
    }

    /// Performs the full P2P and RSK blockchain handshake.
    pub async fn run(self) -> Result<(alloy_primitives::B512, RskStatus, Framed<TcpStream, HandshakeCodec>)> {
        let stream = self.stream;
        let config = self.config;
        let remote_id = self.remote_id;

        if let Some(remote_pk) = remote_id {
            debug!(target: "rustock::net", "Attempting RLPx handshake with {:?}", remote_pk);
            let rlpx = RLPxHandshake::new(stream, config.clone(), remote_pk);
            let (peer_id, frame_codec, stream) = rlpx.run_initiator().await.context("RLPx handshake failed")?;
            
            let codec = HandshakeCodec::RLPx(RLPxCodec::new(frame_codec));
            let mut framed = Framed::new(stream, codec);
            
            let rsk_status = Self::p2p_handshake(&config, &mut framed).await?;
            Ok((peer_id, rsk_status, framed))
        } else {
            // Placeholder for inbound or plain TCP
            let mut framed = Framed::new(stream, HandshakeCodec::Plain(P2pCodec));
            let (peer_id, rsk_status) = Self::p2p_handshake_inbound(&config, &mut framed).await?;
            Ok((peer_id, rsk_status, framed))
        }
    }

    async fn p2p_handshake<S>(config: &NodeConfig, framed: &mut S) -> Result<RskStatus> 
    where S: StreamExt<Item = Result<P2pMessage, anyhow::Error>> + SinkExt<P2pMessage, Error = anyhow::Error> + Unpin
    {
        Self::send_hello(config, framed).await?;
        let _peer_id = Self::receive_hello(framed).await?;
        
        Self::send_status(config, framed).await?;
        let status = Self::receive_status(config, framed).await?;

        Ok(status)
    }

    async fn p2p_handshake_inbound<S>(config: &NodeConfig, framed: &mut S) -> Result<(alloy_primitives::B512, RskStatus)> 
    where S: StreamExt<Item = Result<P2pMessage, anyhow::Error>> + SinkExt<P2pMessage, Error = anyhow::Error> + Unpin
    {
        let peer_id = Self::receive_hello(framed).await?;
        Self::send_hello(config, framed).await?;
        
        let status = Self::receive_status(config, framed).await?;
        Self::send_status(config, framed).await?;

        Ok((peer_id, status))
    }

    async fn send_hello<S>(config: &NodeConfig, framed: &mut S) -> Result<()> 
    where S: SinkExt<P2pMessage, Error = anyhow::Error> + Unpin
    {
        let hello = HelloMessage {
            protocol_version: P2P_VERSION,
            client_id: config.client_id.clone(),
            capabilities: vec![Capability { name: "rsk".to_string(), version: 62 }],
            listen_port: config.listen_port,
            id: config.id,
        };
        framed.send(P2pMessage::Hello(hello)).await.context("Failed to send Hello")
    }

    async fn receive_hello<S>(framed: &mut S) -> Result<alloy_primitives::B512> 
    where S: StreamExt<Item = Result<P2pMessage, anyhow::Error>> + Unpin
    {
        let msg = framed.next().await
            .context("Connection closed waiting for Hello")??;
        
        if let P2pMessage::Hello(peer_hello) = msg {
            info!(target: "rustock::net", "P2P Handshake successful with peer: {}", peer_hello.client_id);
            Ok(peer_hello.id)
        } else {
            Err(anyhow::anyhow!("Expected Hello, got {:?}", msg))
        }
    }

    async fn send_status<S>(config: &NodeConfig, framed: &mut S) -> Result<()> 
    where S: SinkExt<P2pMessage, Error = anyhow::Error> + Unpin
    {
        let status = EthStatus {
            protocol_version: 0x3f,
            network_id: config.network_id,
            total_difficulty: config.total_difficulty,
            best_hash: config.best_hash,
            genesis_hash: config.genesis_hash,
        };
        framed.send(P2pMessage::EthStatus(status)).await?;
        
        let rsk_status = RskStatus {
            best_block_number: 0, // TODO: Use current best number from Store
            best_block_hash: config.best_hash,
            best_block_parent_hash: None,
            total_difficulty: Some(config.total_difficulty),
        };
        framed.send(P2pMessage::RskMessage(RskMessage::new(RskSubMessage::Status(rsk_status)))).await?;
        Ok(())
    }

    async fn receive_status<S>(config: &NodeConfig, framed: &mut S) -> Result<RskStatus> 
    where S: StreamExt<Item = Result<P2pMessage, anyhow::Error>> + Unpin
    {
        // Wait for EthStatus
        let eth_msg = framed.next().await
            .context("Connection closed waiting for EthStatus")??;
        
        if let P2pMessage::EthStatus(s) = eth_msg {
            if s.genesis_hash != config.genesis_hash {
                return Err(anyhow::anyhow!("Genesis hash mismatch: expected {:?}, got {:?}", config.genesis_hash, s.genesis_hash));
            }
            debug!(target: "rustock::net", "Peer EthStatus: best_hash={:?}", s.best_hash);
        } else {
            return Err(anyhow::anyhow!("Expected EthStatus, got {:?}", eth_msg));
        }

        // Wait for RskStatus
        let rsk_msg = framed.next().await
            .context("Connection closed waiting for RskStatus")??;
        
        if let P2pMessage::RskMessage(m) = rsk_msg {
            if let RskSubMessage::Status(s) = m.sub_message {
                info!(target: "rustock::net", "RSK Handshake successful: peer at block {}", s.best_block_number);
                Ok(s)
            } else {
                Err(anyhow::anyhow!("Expected RskStatus, got {:?}", m.sub_message))
            }
        } else {
            Err(anyhow::anyhow!("Expected RskMessage, got {:?}", rsk_msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B512, B256, U256};
    use tokio::net::TcpListener;
    
    fn mock_config(genesis: B256) -> NodeConfig {
        NodeConfig {
            client_id: "test".to_string(),
            listen_port: 0,
            id: B512::ZERO,
            chain_id: 33,
            network_id: 33,
            genesis_hash: genesis,
            best_hash: genesis,
            total_difficulty: U256::ZERO,
            bootnodes: vec![],
            secret_key: [0; 32],
            discovery_port: 0,
            data_dir: ".".to_string(),
        }
    }

    #[tokio::test]
    async fn test_handshake_genesis_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let genesis1 = B256::repeat_byte(0x11);
        let genesis2 = B256::repeat_byte(0x22);
        
        let client_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let config = mock_config(genesis1);
            let handshake = Handshake::new(stream, config.clone(), None);
            // Send Hello
            let mut framed = tokio_util::codec::Framed::new(handshake.stream, HandshakeCodec::Plain(P2pCodec));
            Handshake::send_hello(&config, &mut framed).await.unwrap();
            // Receive Hello
            let _ = Handshake::receive_hello(&mut framed).await.unwrap();
            // Send Status
            Handshake::send_status(&config, &mut framed).await.unwrap();
            // Should fail here
            Handshake::receive_status(&config, &mut framed).await
        });

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let config = mock_config(genesis2);
            let handshake = Handshake::new(stream, config.clone(), None);
            // Receive Hello
            let mut framed = tokio_util::codec::Framed::new(handshake.stream, HandshakeCodec::Plain(P2pCodec));
            let _ = Handshake::receive_hello(&mut framed).await.unwrap();
            // Send Hello
            Handshake::send_hello(&config, &mut framed).await.unwrap();
            // Receive Status
            Handshake::receive_status(&config, &mut framed).await
        });

        let (res1, res2) = tokio::join!(client_task, server_task);
        let res1: Result<crate::protocol::RskStatus, anyhow::Error> = res1.unwrap();
        let res2: Result<crate::protocol::RskStatus, anyhow::Error> = res2.unwrap();
        
        if let Err(e) = &res1 {
            println!("Res1 error: {:?}", e);
        }
        if let Err(e) = &res2 {
            println!("Res2 error: {:?}", e);
        }
        
        assert!(res1.is_err());
        assert!(res2.is_err());
        
        let err1 = res1.unwrap_err().to_string();
        let err2 = res2.unwrap_err().to_string();
        
        assert!(err1.contains("Genesis hash mismatch") || err1.contains("Connection closed") || err1.contains("Connection reset"));
        assert!(err2.contains("Genesis hash mismatch") || err2.contains("Connection closed") || err2.contains("Connection reset"));
    }
}
