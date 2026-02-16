use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::{Result};
use crate::rlpx::ecies::{AuthInitiate, AuthResponse, ECIES};
use crate::rlpx::frame::FrameCodec;
use crate::node::NodeConfig;
use k256::SecretKey;
use alloy_rlp::{Encodable, Decodable};
use alloy_primitives::{B256, B512};

pub struct RLPxHandshake {
    stream: TcpStream,
    config: NodeConfig,
    remote_pk: B512,
}

impl RLPxHandshake {
    pub fn new(stream: TcpStream, config: NodeConfig, remote_pk: B512) -> Self {
        Self { stream, config, remote_pk }
    }

    pub async fn run_initiator(mut self) -> Result<(B512, FrameCodec, TcpStream)> {
        use k256::elliptic_curve::rand_core::RngCore;
        let mut rng = k256::elliptic_curve::rand_core::OsRng;
        let my_sk = SecretKey::from_slice(&self.config.secret_key)?;
        let my_ephemeral_sk = SecretKey::random(&mut rng);
        let my_nonce = {
            let mut n = [0u8; 32];
            rng.fill_bytes(&mut n);
            B256::from(n)
        };

        // 1. Send AuthInitiate
        let auth_init = AuthInitiate::new(&my_sk, &self.remote_pk, &my_ephemeral_sk, my_nonce)?;
        let mut auth_init_rlp = Vec::new();
        auth_init.encode(&mut auth_init_rlp);
        
        // Pad for EIP-8 Distinguishability (100-300 bytes)
        let pad_len = (rng.next_u32() % 200 + 100) as usize;
        let mut padded = vec![0u8; auth_init_rlp.len() + pad_len];
        padded[..auth_init_rlp.len()].copy_from_slice(&auth_init_rlp);
        rng.fill_bytes(&mut padded[auth_init_rlp.len()..]);

        // EIP-8 Prefix (size as short)
        let overhead = 65 + 16 + 32; // PubKey + IV + MAC
        let encrypted_size = (padded.len() + overhead) as u16;
        let prefix_bytes = encrypted_size.to_be_bytes();
        
        let encrypted_auth_init = ECIES::encrypt(&self.remote_pk, &padded, None, Some(&prefix_bytes))?;
        
        let mut packet = Vec::new();
        packet.extend_from_slice(&prefix_bytes);
        packet.extend_from_slice(&encrypted_auth_init);
        
        self.stream.write_all(&packet).await?;

        // 2. Receive AuthResponse
        // Read prefix (2 bytes)
        let mut prefix = [0u8; 2];
        self.stream.read_exact(&mut prefix).await?;
        let resp_size = u16::from_be_bytes(prefix) as usize;
        
        let mut encrypted_resp = vec![0u8; resp_size];
        self.stream.read_exact(&mut encrypted_resp).await?;
        
        let my_sk_key = SecretKey::from_slice(&self.config.secret_key)?;
        let resp_packet = ECIES::decrypt(&my_sk_key, &encrypted_resp, None, Some(&prefix))?;
        let auth_resp = AuthResponse::decode(&mut &resp_packet[..])?;

        let secrets = ECIES::agree_secret(
            true,
            &my_ephemeral_sk,
            &auth_resp.public_key,
            &my_nonce,
            &auth_resp.nonce,
            &packet,
            &[prefix.as_slice(), encrypted_resp.as_slice()].concat(),
        )?;

        let frame_codec = FrameCodec::new(secrets);
        Ok((self.remote_pk, frame_codec, self.stream))
    }

    pub async fn run_responder(mut self) -> Result<(B512, FrameCodec, TcpStream)> {
        use k256::elliptic_curve::rand_core::RngCore;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let mut rng = k256::elliptic_curve::rand_core::OsRng;
        let my_sk = SecretKey::from_slice(&self.config.secret_key)?;
        let my_ephemeral_sk = SecretKey::random(&mut rng);
        let my_nonce = {
            let mut n = [0u8; 32];
            rng.fill_bytes(&mut n);
            B256::from(n)
        };

        // 1. Receive AuthInitiate
        let mut prefix = [0u8; 2];
        self.stream.read_exact(&mut prefix).await?;
        let auth_size = u16::from_be_bytes(prefix) as usize;

        let mut encrypted_auth = vec![0u8; auth_size];
        self.stream.read_exact(&mut encrypted_auth).await?;

        let initiate_packet = [prefix.as_slice(), encrypted_auth.as_slice()].concat();
        let auth_packet = ECIES::decrypt(&my_sk, &encrypted_auth, None, Some(&prefix))?;
        let auth_init = AuthInitiate::decode(&mut &auth_packet[..])?;

        // 2. Send AuthResponse
        let my_ephemeral_pk_encoded = my_ephemeral_sk.public_key().to_encoded_point(false);
        let mut my_ephemeral_pk_64 = [0u8; 64];
        my_ephemeral_pk_64.copy_from_slice(&my_ephemeral_pk_encoded.as_bytes()[1..]);
        let my_ephemeral_pk = B512::from_slice(&my_ephemeral_pk_64);

        let auth_resp = AuthResponse::new(&my_ephemeral_pk, my_nonce);
        let mut auth_resp_rlp = Vec::new();
        auth_resp.encode(&mut auth_resp_rlp);

        // Pad for EIP-8
        let pad_len = (rng.next_u32() % 200 + 100) as usize;
        let mut padded = vec![0u8; auth_resp_rlp.len() + pad_len];
        padded[..auth_resp_rlp.len()].copy_from_slice(&auth_resp_rlp);
        rng.fill_bytes(&mut padded[auth_resp_rlp.len()..]);

        let overhead = 65 + 16 + 32;
        let encrypted_size = (padded.len() + overhead) as u16;
        let resp_prefix = encrypted_size.to_be_bytes();

        let encrypted_auth_resp = ECIES::encrypt(&auth_init.public_key, &padded, None, Some(&resp_prefix))?;
        let response_packet = [resp_prefix.as_slice(), encrypted_auth_resp.as_slice()].concat();

        self.stream.write_all(&response_packet).await?;

        // 3. Agree Secret
        let remote_ephemeral_pk = auth_init.recover_ephemeral_public_key(&my_sk)?;

        let secrets = ECIES::agree_secret(
            false,
            &my_ephemeral_sk,
            &remote_ephemeral_pk,
            &auth_init.nonce,
            &my_nonce,
            &initiate_packet,
            &response_packet,
        )?;
        
        let frame_codec = FrameCodec::new(secrets);
        Ok((auth_init.public_key, frame_codec, self.stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use crate::node::NodeConfig;
    use alloy_primitives::U256;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use bytes::BytesMut;

    fn mock_config(sk: [u8; 32]) -> NodeConfig {
        NodeConfig {
            client_id: "test".to_string(),
            listen_port: 0,
            id: B512::ZERO,
            chain_id: 33,
            network_id: 33,
            genesis_hash: B256::ZERO,
            best_hash: B256::ZERO,
            total_difficulty: U256::ZERO,
            bootnodes: vec![],
            secret_key: sk,
            discovery_port: 0,
            data_dir: ".".to_string(),
        }
    }

    #[tokio::test]
    async fn test_rlpx_handshake_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let sk1 = [0x11; 32];
        let sk2 = [0x22; 32];
        
        let pk1 = {
            let sk = SecretKey::from_slice(&sk1).unwrap();
            let pk_encoded = sk.public_key().to_encoded_point(false);
            let mut pk_64 = [0u8; 64];
            pk_64.copy_from_slice(&pk_encoded.as_bytes()[1..]);
            B512::from_slice(&pk_64)
        };

        let pk2 = {
            let sk = SecretKey::from_slice(&sk2).unwrap();
            let pk_encoded = sk.public_key().to_encoded_point(false);
            let mut pk_64 = [0u8; 64];
            pk_64.copy_from_slice(&pk_encoded.as_bytes()[1..]);
            B512::from_slice(&pk_64)
        };

        let client_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let handshake = RLPxHandshake::new(stream, mock_config(sk1), pk2);
            handshake.run_initiator().await
        });

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let handshake = RLPxHandshake::new(stream, mock_config(sk2), pk1);
            handshake.run_responder().await
        });

        let (res1, res2) = tokio::join!(client_task, server_task);
        let (responder_static_pk, mut client_codec, _client_stream) = res1.unwrap().unwrap();
        let (initiator_static_pk, mut server_codec, _server_stream) = res2.unwrap().unwrap();
        
        assert_eq!(initiator_static_pk, pk1);
        assert_eq!(responder_static_pk, pk2);

        // Test that encryption/decryption works after handshake
        let msg = b"PING";
        let encoded = client_codec.encode_frame(0, msg).unwrap();
        let mut src = BytesMut::from(&encoded[..]);
        let decoded = server_codec.decode_frame(&mut src).unwrap().unwrap();
        
        assert_eq!(decoded.0, 0);
        assert_eq!(decoded.1, msg);
    }
}
