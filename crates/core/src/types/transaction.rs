use alloy_primitives::{U256, Bytes};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpDecodable, RlpEncodable)]
pub struct Transaction {
    pub nonce: u64,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: Bytes, // Changed to Bytes to ensure RLP derivation works seamlessly
    pub value: U256,
    pub input: Bytes,
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn test_transaction_rlp_roundtrip() {
        let tx = Transaction {
            nonce: 42,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0x12; 20]),
            value: U256::from(1_000_000_000_000_000_000u64),
            input: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
            v: 1,
            r: U256::from(123),
            s: U256::from(456),
        };

        let mut buffer = Vec::new();
        tx.encode(&mut buffer);

        let decoded = Transaction::decode(&mut buffer.as_slice()).expect("Failed to decode transaction");
        assert_eq!(tx, decoded);
    }
}
