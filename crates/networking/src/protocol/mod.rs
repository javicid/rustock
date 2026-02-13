pub mod p2p;
pub mod eth;
pub mod rsk;

pub use p2p::{HelloMessage, P2pMessage, Capability, PeerInfo, P2P_VERSION, P2pHandler};
pub use eth::EthStatus;
pub use rsk::{RskStatus, RskSubMessage, RskMessage, BlockHeadersRequest, BlockHeadersQuery, BlockHeadersResponse};

#[derive(Debug, Clone)]
pub enum BlockchainMessage {
    EthStatus(EthStatus),
    RskMessage(RskMessage),
}
