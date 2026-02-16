use alloy_primitives::{Address, Bloom, B256, U256, Bytes};
use alloy_rlp::Encodable;
use serde::{Deserialize, Serialize};
use crate::rlp_compat::{decode_u64_lenient, decode_u256_lenient};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub parent_hash: B256,
    pub ommers_hash: B256,
    pub beneficiary: Address,
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    /// Compressed extension data (RSKIP-351 V1/V2). When present, `logs_bloom`
    /// is set to default and this field contains `RLP([version, hash])`.
    pub extension_data: Option<Bytes>,
    pub difficulty: U256,
    pub number: u64,
    pub gas_limit: U256,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Bytes,
    
    // RSK Specific Fields
    pub paid_fees: U256,
    pub minimum_gas_price: U256,
    pub uncle_count: u64,
    
    // Optional / Advanced RSK fields (Merged Mining)
    pub umm_root: Option<Bytes>,
    pub bitcoin_merged_mining_header: Option<Bytes>,
    pub bitcoin_merged_mining_merkle_proof: Option<Bytes>,
    pub bitcoin_merged_mining_coinbase_transaction: Option<Bytes>,

    /// Hash computed from the original RLP bytes received from the peer.
    /// Java's RLP encoding may differ from Rust's canonical encoding (e.g.
    /// leading zeros in BigInteger values), so we cache the hash at decode
    /// time instead of recomputing it from re-encoded bytes.
    #[serde(skip)]
    pub cached_hash: Option<B256>,
}

impl Encodable for Header {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut list = Vec::new();
        self.parent_hash.encode(&mut list);
        self.ommers_hash.encode(&mut list);
        self.beneficiary.encode(&mut list);
        self.state_root.encode(&mut list);
        self.transactions_root.encode(&mut list);
        self.receipts_root.encode(&mut list);
        self.logs_bloom.encode(&mut list);
        self.difficulty.encode(&mut list);
        self.number.encode(&mut list);
        self.gas_limit.encode(&mut list);
        self.gas_used.encode(&mut list);
        self.timestamp.encode(&mut list);
        self.extra_data.encode(&mut list);
        self.paid_fees.encode(&mut list);
        self.minimum_gas_price.encode(&mut list);
        self.uncle_count.encode(&mut list);
        
        if let Some(umm) = &self.umm_root {
            umm.encode(&mut list);
        }
        if let Some(btc) = &self.bitcoin_merged_mining_header {
            btc.encode(&mut list);
        }
        if let Some(proof) = &self.bitcoin_merged_mining_merkle_proof {
            proof.encode(&mut list);
        }
        if let Some(tx) = &self.bitcoin_merged_mining_coinbase_transaction {
            tx.encode(&mut list);
        }
        
        alloy_rlp::Header { list: true, payload_length: list.len() }.encode(out);
        out.put_slice(&list);
    }

    fn length(&self) -> usize {
        let mut len = self.parent_hash.length() + self.ommers_hash.length() + self.beneficiary.length() +
                      self.state_root.length() + self.transactions_root.length() + self.receipts_root.length() +
                      self.logs_bloom.length() + self.difficulty.length() + self.number.length() +
                      self.gas_limit.length() + self.gas_used.length() + self.timestamp.length() +
                      self.extra_data.length() + self.paid_fees.length() + self.minimum_gas_price.length() +
                      self.uncle_count.length();
        
        if let Some(umm) = &self.umm_root { len += umm.length(); }
        if let Some(btc) = &self.bitcoin_merged_mining_header { len += btc.length(); }
        if let Some(proof) = &self.bitcoin_merged_mining_merkle_proof { len += proof.length(); }
        if let Some(tx) = &self.bitcoin_merged_mining_coinbase_transaction { len += tx.length(); }
        
        alloy_rlp::Header { list: true, payload_length: len }.length() + len
    }
}

impl alloy_rlp::Decodable for Header {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let h = alloy_rlp::Header::decode(buf)?;
        if !h.list { return Err(alloy_rlp::Error::UnexpectedString); }
        let mut body = &buf[..h.payload_length];
        *buf = &buf[h.payload_length..];

        let parent_hash = B256::decode(&mut body)?;
        let ommers_hash = B256::decode(&mut body)?;
        let beneficiary = Address::decode(&mut body)?;
        let state_root = B256::decode(&mut body)?;
        let transactions_root = B256::decode(&mut body)?;
        let receipts_root = B256::decode(&mut body)?;

        // Field 6: logs bloom (256 bytes) OR compressed extension data (shorter).
        // Peek at the RLP header to determine which one.
        let (logs_bloom, extension_data) = {
            let rlp_h = alloy_rlp::Header::decode(&mut &body[..])?;
            if !rlp_h.list && rlp_h.payload_length == 256 {
                // Standard logs bloom (256 bytes)
                (Bloom::decode(&mut body)?, None)
            } else {
                // Compressed extension data (V1/V2 RSKIP-351).
                // Could be an RLP list or string — read the raw bytes either way.
                let before = body;
                let total_len = rlp_h.length() + rlp_h.payload_length;
                let raw = Bytes::copy_from_slice(&before[..total_len]);
                body = &body[total_len..];
                (Bloom::default(), Some(raw))
            }
        };

        let mut header = Self {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            extension_data,
            difficulty: decode_u256_lenient(&mut body)?,
            number: decode_u64_lenient(&mut body)?,
            gas_limit: decode_u256_lenient(&mut body)?,
            gas_used: decode_u64_lenient(&mut body)?,
            timestamp: decode_u64_lenient(&mut body)?,
            extra_data: Bytes::decode(&mut body)?,
            paid_fees: decode_u256_lenient(&mut body)?,
            minimum_gas_price: decode_u256_lenient(&mut body)?,
            uncle_count: decode_u64_lenient(&mut body)?,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
        };

        if !body.is_empty() {
            header.umm_root = Some(Bytes::decode(&mut body)?);
        }
        if !body.is_empty() {
            header.bitcoin_merged_mining_header = Some(Bytes::decode(&mut body)?);
        }
        if !body.is_empty() {
            header.bitcoin_merged_mining_merkle_proof = Some(Bytes::decode(&mut body)?);
        }
        if !body.is_empty() {
            header.bitcoin_merged_mining_coinbase_transaction = Some(Bytes::decode(&mut body)?);
        }
        
        Ok(header)
    }
}

impl Header {
    pub fn hash(&self) -> B256 {
        if let Some(h) = self.cached_hash {
            return h;
        }
        let mut buffer = Vec::new();
        self.encode(&mut buffer);
        alloy_primitives::keccak256(&buffer)
    }

    /// Decode a header from RLP bytes and compute the hash from those original
    /// bytes (before our re-encoding potentially changes them).
    pub fn decode_with_hash(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        use alloy_rlp::Decodable;
        let original = *buf;
        let mut header = <Self as Decodable>::decode(buf)?;
        let consumed = original.len() - buf.len();
        header.cached_hash = Some(alloy_primitives::keccak256(&original[..consumed]));
        Ok(header)
    }

    /// Computes the hash used in the Bitcoin coinbase transaction for merged mining.
    /// This hash excludes the Bitcoin-specific fields themselves.
    pub fn get_hash_for_merged_mining(&self) -> B256 {
        let mut out = Vec::new();
        
        // Manual RLP list encoding for the "base" header fields
        // Order must match rskj's getEncoded(false, false, true)
        let mut list_fields: Vec<Vec<u8>> = vec![
            alloy_rlp::encode(self.parent_hash),
            alloy_rlp::encode(self.ommers_hash),
            alloy_rlp::encode(self.beneficiary),
            alloy_rlp::encode(self.state_root),
            alloy_rlp::encode(self.transactions_root),
            alloy_rlp::encode(self.receipts_root),
            alloy_rlp::encode(self.logs_bloom),
            alloy_rlp::encode(self.difficulty),
            alloy_rlp::encode(self.number),
            alloy_rlp::encode(self.gas_limit),
            alloy_rlp::encode(self.gas_used),
            alloy_rlp::encode(self.timestamp),
            alloy_rlp::encode(self.extra_data.as_ref()),
            alloy_rlp::encode(self.paid_fees),
            alloy_rlp::encode(self.minimum_gas_price),
            alloy_rlp::encode(self.uncle_count),
        ];

        if let Some(umm) = &self.umm_root {
            list_fields.push(alloy_rlp::encode(umm.as_ref()));
        }

        // TODO: Handle RSKIP-351 versions and other extra fields if any
        
        let payload_len = list_fields.iter().map(|f| f.len()).sum::<usize>();
        let rlp_header = alloy_rlp::Header {
            list: true,
            payload_length: payload_len,
        };
        rlp_header.encode(&mut out);
        for field in list_fields {
            out.extend_from_slice(&field);
        }
        alloy_primitives::keccak256(&out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256, Bytes};
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn test_header_rlp_roundtrip() {
        let header = Header {
            parent_hash: B256::repeat_byte(0x11),
            ommers_hash: B256::repeat_byte(0x22),
            beneficiary: Address::repeat_byte(0x33),
            state_root: B256::repeat_byte(0x44),
            transactions_root: B256::repeat_byte(0x55),
            receipts_root: B256::repeat_byte(0x66),
            logs_bloom: Bloom::repeat_byte(0x77),
            extension_data: None,
            difficulty: U256::from(1234567),
            number: 42,
            gas_limit: U256::from(10_000_000),
            gas_used: 123456,
            timestamp: 1700000000,
            extra_data: Bytes::from("extra"),
            paid_fees: U256::from(100),
            minimum_gas_price: U256::from(1),
            uncle_count: 0,
            umm_root: Some(Bytes::from("umm")),
            bitcoin_merged_mining_header: Some(Bytes::from("btc_header")),
            bitcoin_merged_mining_merkle_proof: Some(Bytes::from("proof")),
            bitcoin_merged_mining_coinbase_transaction: Some(Bytes::from("coinbase")),
            cached_hash: None,
        };

        // Encode
        let mut buffer = Vec::new();
        header.encode(&mut buffer);

        // Decode
        let decoded_header = Header::decode(&mut buffer.as_slice()).expect("Failed to decode header");

        // Assert
        assert_eq!(header, decoded_header);
        
        // Hash check (just to ensure it doesn't panic)
        let hash = header.hash();
        assert_ne!(hash, B256::ZERO);
    }
}
