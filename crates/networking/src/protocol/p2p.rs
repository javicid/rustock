use alloy_rlp::{RlpDecodable, RlpEncodable};
use alloy_primitives::{B512, Bytes};
use crate::protocol::eth::EthStatus;
use crate::protocol::rsk::RskMessage;

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct HelloMessage {
    pub protocol_version: u64,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u16,
    pub id: B512,
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct Capability {
    pub name: String,
    pub version: u64,
}

#[derive(Debug, Clone)]
pub enum P2pMessage {
    Hello(HelloMessage),
    Disconnect(u64),
    Ping,
    Pong,
    GetPeers,
    Peers(Vec<PeerInfo>),
    // Blockchain (Sub-protocol) messages
    // These typically have an offset of 0x10 in the P2P frame
    EthStatus(EthStatus),
    RskMessage(RskMessage),
}

impl P2pMessage {
    pub const HELLO_ID: u8 = 0x00;
    pub const DISCONNECT_ID: u8 = 0x01;
    pub const PING_ID: u8 = 0x02;
    pub const PONG_ID: u8 = 0x03;
    pub const GET_PEERS_ID: u8 = 0x04;
    pub const PEERS_ID: u8 = 0x05;
    
    pub const SUB_PROTOCOL_OFFSET: u8 = 0x10;
}

use alloy_rlp::{Encodable, Decodable};

impl Encodable for P2pMessage {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            P2pMessage::Hello(hello) => {
                out.put_u8(Self::HELLO_ID);
                hello.encode(out);
            }
            P2pMessage::Disconnect(reason) => {
                out.put_u8(Self::DISCONNECT_ID);
                alloy_rlp::encode_list(&[*reason], out);
            }
            P2pMessage::Ping => {
                out.put_u8(Self::PING_ID);
                alloy_rlp::Header { list: true, payload_length: 0 }.encode(out);
            }
            P2pMessage::Pong => {
                out.put_u8(Self::PONG_ID);
                alloy_rlp::Header { list: true, payload_length: 0 }.encode(out);
            }
            P2pMessage::GetPeers => {
                out.put_u8(Self::GET_PEERS_ID);
                alloy_rlp::Header { list: true, payload_length: 0 }.encode(out);
            }
            P2pMessage::Peers(peers) => {
                out.put_u8(Self::PEERS_ID);
                peers.encode(out);
            }
            P2pMessage::EthStatus(status) => {
                out.put_u8(Self::SUB_PROTOCOL_OFFSET + EthStatus::MESSAGE_ID);
                status.encode(out);
            }
            P2pMessage::RskMessage(msg) => {
                out.put_u8(Self::SUB_PROTOCOL_OFFSET + RskMessage::MESSAGE_ID);
                msg.encode(out);
            }
        }
    }

    fn length(&self) -> usize {
        1 + match self {
            P2pMessage::Hello(hello) => hello.length(),
            P2pMessage::Disconnect(reason) => alloy_rlp::list_length(&[*reason]),
            P2pMessage::Ping | P2pMessage::Pong | P2pMessage::GetPeers => 1,
            P2pMessage::Peers(peers) => peers.length(),
            P2pMessage::EthStatus(status) => status.length(),
            P2pMessage::RskMessage(msg) => msg.length(),
        }
    }
}

impl Decodable for P2pMessage {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        if buf.is_empty() {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let id = buf[0];
        *buf = &buf[1..];

        match id {
            Self::HELLO_ID => Ok(P2pMessage::Hello(HelloMessage::decode(buf)?)),
            Self::DISCONNECT_ID => {
                let reasons: Vec<u64> = Vec::decode(buf)?;
                Ok(P2pMessage::Disconnect(reasons.first().cloned().unwrap_or(0)))
            }
            Self::PING_ID => {
                let _ = alloy_rlp::Header::decode(buf)?;
                Ok(P2pMessage::Ping)
            }
            Self::PONG_ID => {
                let _ = alloy_rlp::Header::decode(buf)?;
                Ok(P2pMessage::Pong)
            }
            Self::GET_PEERS_ID => {
                let _ = alloy_rlp::Header::decode(buf)?;
                Ok(P2pMessage::GetPeers)
            }
            Self::PEERS_ID => Ok(P2pMessage::Peers(Vec::<PeerInfo>::decode(buf)?)),
            
            // Sub-protocol range
            code if code >= Self::SUB_PROTOCOL_OFFSET => {
                let sub_id = code - Self::SUB_PROTOCOL_OFFSET;
                match sub_id {
                    EthStatus::MESSAGE_ID => Ok(P2pMessage::EthStatus(EthStatus::decode(buf)?)),
                    RskMessage::MESSAGE_ID => Ok(P2pMessage::RskMessage(RskMessage::decode(buf)?)),
                    _ => Err(alloy_rlp::Error::Custom("Unknown sub-protocol message ID")),
                }
            }
            
            _ => Err(alloy_rlp::Error::Custom("Unknown message ID")),
        }
    }
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct PeerInfo {
    pub ip: Bytes,
    pub port: u16,
    pub id: B512,
}

pub const P2P_VERSION: u64 = 5;

pub trait P2pHandler: Send + Sync {
    fn handle_message(&self, id: B512, msg: P2pMessage) -> Option<P2pMessage>;
}
