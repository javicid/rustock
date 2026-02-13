use alloy_rlp::{RlpDecodable, RlpEncodable};
use alloy_primitives::{B256, U256};

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct EthStatus {
    pub protocol_version: u32,
    pub network_id: u64,
    pub total_difficulty: U256,
    pub best_hash: B256,
    pub genesis_hash: B256,
}

impl EthStatus {
    pub const MESSAGE_ID: u8 = 0x00;
}
