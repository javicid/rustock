use crate::protocol::{P2pMessage, HelloMessage, P2P_VERSION, EthStatus, RskStatus, RskMessage, RskSubMessage, Capability};
use crate::node::NodeConfig;
use crate::codec::P2pCodec;
use anyhow::{Result, Context};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::{StreamExt, SinkExt};
use alloy_primitives::B512;
use tracing::trace;

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
            trace!(target: "rustock::net", "Attempting RLPx handshake with {:?}", remote_pk);
            let rlpx = RLPxHandshake::new(stream, config.clone(), remote_pk);
            let (peer_id, frame_codec, stream) = rlpx.run_initiator().await.context("RLPx handshake failed")?;
            
            let codec = HandshakeCodec::RLPx(RLPxCodec::new(frame_codec));
            let mut framed = Framed::new(stream, codec);
            
            let rsk_status = Self::p2p_handshake(&config, &mut framed).await?;
            Ok((peer_id, rsk_status, framed))
        } else {
            trace!(target: "rustock::net", "Awaiting inbound RLPx handshake");
            let rlpx = RLPxHandshake::new(stream, config.clone(), B512::ZERO);
            let (peer_id, frame_codec, stream) = rlpx.run_responder().await.context("Inbound RLPx handshake failed")?;

            let codec = HandshakeCodec::RLPx(RLPxCodec::new(frame_codec));
            let mut framed = Framed::new(stream, codec);

            let (_, rsk_status) = Self::p2p_handshake_inbound(&config, &mut framed).await?;
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
            trace!(target: "rustock::net", "P2P Handshake successful with peer: {}", peer_hello.client_id);
            Ok(peer_hello.id)
        } else {
            Err(anyhow::anyhow!("Expected Hello, got {:?}", msg))
        }
    }

    async fn send_status<S>(config: &NodeConfig, framed: &mut S) -> Result<()> 
    where S: SinkExt<P2pMessage, Error = anyhow::Error> + Unpin
    {
        let status = EthStatus {
            protocol_version: 0x3e, // RSK protocol version V62
            network_id: config.network_id,
            total_difficulty: config.total_difficulty,
            best_hash: config.best_hash,
            genesis_hash: config.genesis_hash,
        };
        framed.send(P2pMessage::EthStatus(status)).await?;
        
        let rsk_status = RskStatus {
            best_block_number: config.best_block_number,
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
            trace!(target: "rustock::net", "Peer EthStatus: best_hash={:?}", s.best_hash);
        } else {
            return Err(anyhow::anyhow!("Expected EthStatus, got {:?}", eth_msg));
        }

        // Wait for RskStatus
        let rsk_msg = framed.next().await
            .context("Connection closed waiting for RskStatus")??;
        
        if let P2pMessage::RskMessage(m) = rsk_msg {
            if let RskSubMessage::Status(s) = m.sub_message {
                trace!(target: "rustock::net", "RSK Handshake successful: peer at block {}", s.best_block_number);
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
    use k256::SecretKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use tokio::net::TcpListener;

    fn secret_to_public(sk_bytes: &[u8; 32]) -> B512 {
        let sk = SecretKey::from_slice(sk_bytes).unwrap();
        let pk_encoded = sk.public_key().to_encoded_point(false);
        let mut pk_64 = [0u8; 64];
        pk_64.copy_from_slice(&pk_encoded.as_bytes()[1..]);
        B512::from_slice(&pk_64)
    }

    fn mock_config_with_key(genesis: B256, sk: [u8; 32]) -> NodeConfig {
        let id = secret_to_public(&sk);
        NodeConfig {
            client_id: "test".to_string(),
            listen_port: 0,
            id,
            chain_id: 33,
            network_id: 33,
            genesis_hash: genesis,
            best_hash: genesis,
            best_block_number: 0,
            total_difficulty: U256::ZERO,
            bootnodes: vec![],
            secret_key: sk,
            discovery_port: 0,
            data_dir: ".".to_string(),
            external_ip: None,
        }
    }

    fn mock_config(genesis: B256) -> NodeConfig {
        mock_config_with_key(genesis, [0x11; 32])
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
            let mut framed = tokio_util::codec::Framed::new(handshake.stream, HandshakeCodec::Plain(P2pCodec));
            Handshake::send_hello(&config, &mut framed).await.unwrap();
            let _ = Handshake::receive_hello(&mut framed).await.unwrap();
            Handshake::send_status(&config, &mut framed).await.unwrap();
            Handshake::receive_status(&config, &mut framed).await
        });

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let config = mock_config(genesis2);
            let handshake = Handshake::new(stream, config.clone(), None);
            let mut framed = tokio_util::codec::Framed::new(handshake.stream, HandshakeCodec::Plain(P2pCodec));
            let _ = Handshake::receive_hello(&mut framed).await.unwrap();
            Handshake::send_hello(&config, &mut framed).await.unwrap();
            Handshake::receive_status(&config, &mut framed).await
        });

        let (res1, res2) = tokio::join!(client_task, server_task);
        let res1: Result<crate::protocol::RskStatus, anyhow::Error> = res1.unwrap();
        let res2: Result<crate::protocol::RskStatus, anyhow::Error> = res2.unwrap();
        
        assert!(res1.is_err());
        assert!(res2.is_err());
        
        let err1 = res1.unwrap_err().to_string();
        let err2 = res2.unwrap_err().to_string();
        
        assert!(err1.contains("Genesis hash mismatch") || err1.contains("Connection closed") || err1.contains("Connection reset"));
        assert!(err2.contains("Genesis hash mismatch") || err2.contains("Connection closed") || err2.contains("Connection reset"));
    }

    /// Full end-to-end test: outbound initiator (RLPx) connects to inbound
    /// responder (RLPx), both go through `Handshake::run()`.
    #[tokio::test]
    async fn test_inbound_rlpx_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let genesis = B256::repeat_byte(0xAA);
        let sk_client: [u8; 32] = [0x11; 32];
        let sk_server: [u8; 32] = [0x22; 32];
        let pk_server = secret_to_public(&sk_server);
        let pk_client = secret_to_public(&sk_client);

        let client_config = mock_config_with_key(genesis, sk_client);
        let server_config = mock_config_with_key(genesis, sk_server);

        let client_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let handshake = Handshake::new(stream, client_config, Some(pk_server));
            handshake.run().await
        });

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let handshake = Handshake::new(stream, server_config, None);
            handshake.run().await
        });

        let (client_res, server_res) = tokio::join!(client_task, server_task);
        let (client_peer_id, client_rsk_status, _) = client_res.unwrap().unwrap();
        let (server_peer_id, server_rsk_status, _) = server_res.unwrap().unwrap();

        // Each side should see the other's public key
        assert_eq!(client_peer_id, pk_server);
        assert_eq!(server_peer_id, pk_client);

        // Both sides should have exchanged RSK status
        assert_eq!(client_rsk_status.best_block_number, 0);
        assert_eq!(server_rsk_status.best_block_number, 0);
    }
}
