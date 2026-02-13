use crate::types::header::Header;
use crate::types::transaction::Transaction;
use alloy_rlp::{RlpDecodable, RlpEncodable};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpDecodable, RlpEncodable)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transaction>,
    pub ommers: Vec<Header>,
}

impl Block {
    pub fn hash(&self) -> B256 {
        self.header.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::header::Header;
    use crate::types::transaction::Transaction;
    use alloy_primitives::{Address, B256, U256, Bytes};
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn test_block_rlp_roundtrip() {
        let header = Header {
            parent_hash: B256::repeat_byte(1),
            ommers_hash: B256::repeat_byte(2),
            beneficiary: Address::repeat_byte(3),
            state_root: B256::repeat_byte(4),
            transactions_root: B256::repeat_byte(5),
            receipts_root: B256::repeat_byte(6),
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(100),
            number: 1_000,
            gas_limit: U256::from(10_000_000),
            gas_used: 50_000,
            timestamp: 1600000000,
            extra_data: Bytes::from("rustock-test"),
            paid_fees: U256::from(200),
            minimum_gas_price: U256::from(1),
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
        };

        let tx = Transaction {
            nonce: 1,
            gas_price: U256::from(10),
            gas_limit: U256::from(21000),
            to: Bytes::from(Address::repeat_byte(9).as_slice().to_vec()),
            value: U256::from(1000),
            input: Bytes::from(vec![0xAA, 0xBB]),
            v: 27,
            r: U256::from(88),
            s: U256::from(99),
        };

        let block = Block {
            header,
            transactions: vec![tx],
            ommers: vec![],
        };

        // Encode
        let mut buffer = Vec::new();
        block.encode(&mut buffer);

        // Decode
        let decoded_block = Block::decode(&mut buffer.as_slice()).expect("Failed to decode block");

        // Assert
        assert_eq!(block, decoded_block);
    }
}
