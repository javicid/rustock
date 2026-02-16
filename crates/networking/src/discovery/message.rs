use alloy_rlp::{RlpDecodable, RlpEncodable, Encodable, Decodable};
use alloy_primitives::{B256, B512, Bytes};
use k256::ecdsa::SigningKey;
use sha3::{Keccak256, Digest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMessageType {
    Ping = 1,
    Pong = 2,
    FindNode = 3,
    Neighbors = 4,
}

impl DiscoveryMessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Ping),
            2 => Some(Self::Pong),
            3 => Some(Self::FindNode),
            4 => Some(Self::Neighbors),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct DiscoveryEndpoint {
    pub ip: Bytes,
    pub udp_port: u16,
    pub tcp_port: u16,
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct PingMessage {
    pub from: DiscoveryEndpoint,
    pub to: DiscoveryEndpoint,
    pub message_id: String,
    pub network_id: u32,
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct PongMessage {
    pub from: DiscoveryEndpoint,
    pub to: DiscoveryEndpoint,
    pub message_id: String,
    pub network_id: u32,
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct FindNodeMessage {
    pub target: B512,
    pub message_id: String,
    pub network_id: u32,
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct DiscoveryNode {
    pub ip: Bytes,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub id: B512,
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct NeighborsMessage {
    pub nodes: Vec<DiscoveryNode>,
    pub message_id: String,
    pub network_id: u32,
}

#[derive(Debug, Clone)]
pub enum DiscoveryPayload {
    Ping(PingMessage),
    Pong(PongMessage),
    FindNode(FindNodeMessage),
    Neighbors(NeighborsMessage),
}

impl Encodable for DiscoveryPayload {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Ping(m) => m.encode(out),
            Self::Pong(m) => m.encode(out),
            Self::FindNode(m) => m.encode(out),
            Self::Neighbors(m) => m.encode(out),
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::Ping(m) => m.length(),
            Self::Pong(m) => m.length(),
            Self::FindNode(m) => m.length(),
            Self::Neighbors(m) => m.length(),
        }
    }
}

impl DiscoveryPayload {
    pub fn msg_type(&self) -> DiscoveryMessageType {
        match self {
            Self::Ping(_) => DiscoveryMessageType::Ping,
            Self::Pong(_) => DiscoveryMessageType::Pong,
            Self::FindNode(_) => DiscoveryMessageType::FindNode,
            Self::Neighbors(_) => DiscoveryMessageType::Neighbors,
        }
    }
}

pub struct DiscoveryPacket {
    pub mdc: B256,
    pub signature: [u8; 65],
    pub msg_type: DiscoveryMessageType,
    pub payload: DiscoveryPayload,
}

impl DiscoveryPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.payload.encode(&mut data);

        let mut packet = Vec::new();
        packet.extend_from_slice(self.mdc.as_slice());
        packet.extend_from_slice(&self.signature);
        packet.push(self.msg_type as u8);
        packet.extend_from_slice(&data);
        packet
    }

    pub fn create(payload: DiscoveryPayload, key: &SigningKey) -> anyhow::Result<Self> {
        let msg_type = payload.msg_type();
        let mut data = Vec::new();
        payload.encode(&mut data);

        let type_raw = vec![msg_type as u8];
        let mut sig_payload = type_raw.clone();
        sig_payload.extend_from_slice(&data);

        let sig_hash = Keccak256::digest(&sig_payload);
        
        let (signature_bytes, recovery_id) = key.sign_prehash_recoverable(&sig_hash)
            .map_err(|e| anyhow::anyhow!("Signing failed: {:?}", e))?;
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&signature_bytes.to_bytes());
        signature[64] = recovery_id.to_byte();

        let mut mdc_payload = Vec::new();
        mdc_payload.extend_from_slice(&signature);
        mdc_payload.extend_from_slice(&type_raw);
        mdc_payload.extend_from_slice(&data);
        
        let mdc = B256::from_slice(&Keccak256::digest(&mdc_payload));

        Ok(Self {
            mdc,
            signature,
            msg_type,
            payload,
        })
    }

    pub fn recover_id(&self) -> anyhow::Result<B512> {
        let mut data = Vec::new();
        self.payload.encode(&mut data);
        
        let mut sig_payload = vec![self.msg_type as u8];
        sig_payload.extend_from_slice(&data);
        let sig_hash = Keccak256::digest(&sig_payload);
        
        let signature_bytes = k256::ecdsa::Signature::from_slice(&self.signature[..64])
            .map_err(|e| anyhow::anyhow!("Invalid signature format: {:?}", e))?;
        let recovery_id = k256::ecdsa::RecoveryId::from_byte(self.signature[64])
            .ok_or_else(|| anyhow::anyhow!("Invalid recovery ID"))?;
            
        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&sig_hash, &signature_bytes, recovery_id)
            .map_err(|e| anyhow::anyhow!("Failed to recover public key: {:?}", e))?;
            
        let full_pubkey = vk.to_encoded_point(false);
        let pubkey_bytes = &full_pubkey.as_bytes()[1..]; // skip 0x04 prefix
        Ok(B512::from_slice(pubkey_bytes))
    }

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        if buf.len() < 32 + 65 + 1 {
            return Err(anyhow::anyhow!("Packet too short"));
        }

        let mdc = B256::from_slice(&buf[0..32]);
        let mut signature = [0u8; 65];
        signature.copy_from_slice(&buf[32..97]);
        
        let actual_mdc = B256::from_slice(&Keccak256::digest(&buf[32..]));
        if mdc != actual_mdc {
            return Err(anyhow::anyhow!("MDC mismatch"));
        }

        let msg_type_raw = buf[97];
        let msg_type = DiscoveryMessageType::from_u8(msg_type_raw)
            .ok_or_else(|| anyhow::anyhow!("Unknown message type: {}", msg_type_raw))?;

        let mut data = &buf[98..];
        let payload = match msg_type {
            DiscoveryMessageType::Ping => DiscoveryPayload::Ping(PingMessage::decode(&mut data)?),
            DiscoveryMessageType::Pong => DiscoveryPayload::Pong(PongMessage::decode(&mut data)?),
            DiscoveryMessageType::FindNode => DiscoveryPayload::FindNode(FindNodeMessage::decode(&mut data)?),
            DiscoveryMessageType::Neighbors => DiscoveryPayload::Neighbors(NeighborsMessage::decode(&mut data)?),
        };

        Ok(Self {
            mdc,
            signature,
            msg_type,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use uuid::Uuid;

    #[test]
    fn test_packet_encoding_decoding() {
        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let local_id = B512::from_slice(&key.verifying_key().to_encoded_point(false).as_bytes()[1..]);

        let ping = PingMessage {
            from: DiscoveryEndpoint {
                ip: Bytes::from(vec![127, 0, 0, 1]),
                udp_port: 30303,
                tcp_port: 30303,
            },
            to: DiscoveryEndpoint {
                ip: Bytes::from(vec![127, 0, 0, 1]),
                udp_port: 30304,
                tcp_port: 30304,
            },
            message_id: Uuid::new_v4().to_string(),
            network_id: 773,
        };

        let payload = DiscoveryPayload::Ping(ping);
        let packet = DiscoveryPacket::create(payload, &key).unwrap();
        let encoded = packet.encode();
        
        let decoded = DiscoveryPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, DiscoveryMessageType::Ping);
        
        let recovered_id = decoded.recover_id().unwrap();
        assert_eq!(recovered_id, local_id);
    }
}
