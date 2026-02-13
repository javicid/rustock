use alloy_rlp::{Encodable, Decodable, Header as RlpHeader};
use alloy_primitives::{B256, U256};
use super::rlp_compat::{decode_u32_lenient, decode_u64_lenient, decode_u256_lenient};

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Encodable for EthStatus {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut list = Vec::new();
        self.protocol_version.encode(&mut list);
        self.network_id.encode(&mut list);
        self.total_difficulty.encode(&mut list);
        self.best_hash.encode(&mut list);
        self.genesis_hash.encode(&mut list);
        RlpHeader { list: true, payload_length: list.len() }.encode(out);
        out.put_slice(&list);
    }

    fn length(&self) -> usize {
        let len = self.protocol_version.length() + self.network_id.length() +
                  self.total_difficulty.length() + self.best_hash.length() +
                  self.genesis_hash.length();
        RlpHeader { list: true, payload_length: len }.length() + len
    }
}

impl Decodable for EthStatus {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let h = RlpHeader::decode(buf)?;
        if !h.list { return Err(alloy_rlp::Error::UnexpectedString); }
        let mut body = &buf[..h.payload_length];
        *buf = &buf[h.payload_length..];

        Ok(Self {
            protocol_version: decode_u32_lenient(&mut body)?,
            network_id: decode_u64_lenient(&mut body)?,
            total_difficulty: decode_u256_lenient(&mut body)?,
            best_hash: B256::decode(&mut body)?,
            genesis_hash: B256::decode(&mut body)?,
        })
    }
}
