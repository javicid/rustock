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

    /// Merged mining hash computed from the original RLP bytes (base fields
    /// only, excluding bitcoin mining fields). Cached at decode time for the
    /// same Java RLP compatibility reasons as `cached_hash`.
    #[serde(skip)]
    pub cached_hash_for_merged_mining: Option<B256>,
}

/// `BigInteger.toByteArray()` for a non-negative value: zero is the single
/// byte 0x00, and values whose top bit is set get a 0x00 sign prefix. rskj
/// encodes difficulty (`RLP.encodeBlockDifficulty`), gasLimit (raw bytes it
/// produced the same way) and minimumGasPrice
/// (`RLP.encodeSignedCoinNonNullZero`) with these semantics.
fn java_signed_bytes(value: &U256) -> Vec<u8> {
    if value.is_zero() {
        return vec![0];
    }
    let be = value.to_be_bytes::<32>();
    let start = be.iter().position(|b| *b != 0).unwrap();
    let mut out = Vec::with_capacity(33 - start);
    if be[start] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&be[start..]);
    out
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
        java_signed_bytes(&self.difficulty).as_slice().encode(&mut list);
        self.number.encode(&mut list);
        java_signed_bytes(&self.gas_limit).as_slice().encode(&mut list);
        self.gas_used.encode(&mut list);
        self.timestamp.encode(&mut list);
        self.extra_data.encode(&mut list);
        self.paid_fees.encode(&mut list);
        java_signed_bytes(&self.minimum_gas_price).as_slice().encode(&mut list);
        self.uncle_count.encode(&mut list);

        if let Some(umm) = &self.umm_root {
            umm.encode(&mut list);
        }
        // rskj emits the merkle proof and coinbase tx whenever the mining
        // header is present — as empty elements if need be — rather than
        // omitting them (BlockHeader.getEncoded with merged mining fields).
        if let Some(btc) = &self.bitcoin_merged_mining_header {
            btc.encode(&mut list);
            match &self.bitcoin_merged_mining_merkle_proof {
                Some(proof) => proof.encode(&mut list),
                None => list.push(0x80),
            }
            match &self.bitcoin_merged_mining_coinbase_transaction {
                Some(tx) => tx.encode(&mut list),
                None => list.push(0x80),
            }
        }

        alloy_rlp::Header { list: true, payload_length: list.len() }.encode(out);
        out.put_slice(&list);
    }

    fn length(&self) -> usize {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
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
            let mut peek = body;
            let rlp_h = alloy_rlp::Header::decode(&mut peek)?;
            if !rlp_h.list && rlp_h.payload_length == 256 {
                // Standard logs bloom (256 bytes)
                (Bloom::decode(&mut body)?, None)
            } else {
                // Compressed extension data (V1/V2 RSKIP-351).
                // Could be an RLP list or string — read the raw bytes either way.
                let header_len = body.len() - peek.len();
                let total_len = header_len + rlp_h.payload_length;
                let raw = Bytes::copy_from_slice(&body[..total_len]);
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
            cached_hash_for_merged_mining: None,
        };

        // Count remaining RLP items to distinguish header format:
        //   3 items → V0: btc_header, btc_merkle_proof, btc_coinbase_tx
        //   4 items → V1 (RSKIP-153/Hop): umm_root, btc_header, btc_merkle_proof, btc_coinbase_tx
        //   0-2     → partial (pre-orchid blocks without full mining data)
        let remaining_items = {
            let mut count = 0usize;
            let mut rest = body;
            while !rest.is_empty() {
                let mut temp = rest;
                if let Ok(h) = alloy_rlp::Header::decode(&mut temp) {
                    if h.payload_length > temp.len() { break; }
                    rest = &temp[h.payload_length..];
                    count += 1;
                } else {
                    break;
                }
            }
            count
        };

        if remaining_items >= 4 {
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

        // Compute merged mining hash from original RLP bytes.
        // Three cases depending on ummRoot presence:
        //   - ummRoot absent (peer omitted it): hash fields 0-15 only
        //   - ummRoot present but empty: hash fields 0-16 (single keccak256)
        //   - ummRoot present and non-empty (UMM): double-hash
        //       keccak256( keccak256(RLP_LIST(fields_0_16))[0:20] ++ ummRoot )
        let mut parse = &original[..consumed];
        if let Ok(list_h) = alloy_rlp::Header::decode(&mut parse) {
            let body = &parse[..list_h.payload_length];
            let mut cursor = body;
            for _ in 0..16 {
                if cursor.is_empty() { break; }
                let mut temp = cursor;
                if let Ok(item_h) = alloy_rlp::Header::decode(&mut temp) {
                    if item_h.payload_length > temp.len() { break; }
                    cursor = &temp[item_h.payload_length..];
                } else {
                    break;
                }
            }
            let mm_end = body.len() - cursor.len();

            let has_umm_root = header.umm_root.is_some();
            let is_umm_block = header.umm_root.as_ref().is_some_and(|u| !u.is_empty());

            let mm_hash = if has_umm_root {
                // ummRoot is present in the RLP — include it in the hash payload.
                // The miner included ummRoot when encoding for the merged mining
                // hash, so we must do the same regardless of whether ummRoot is
                // empty or non-empty.
                let mut mm_end_with_umm = mm_end;
                if !cursor.is_empty() {
                    let mut temp = cursor;
                    if let Ok(item_h) = alloy_rlp::Header::decode(&mut temp) {
                        if item_h.payload_length <= temp.len() {
                            let header_len = cursor.len() - temp.len();
                            mm_end_with_umm += header_len + item_h.payload_length;
                        }
                    }
                }
                let mm_payload = &body[..mm_end_with_umm];
                let mm_list_h = alloy_rlp::Header { list: true, payload_length: mm_payload.len() };
                let mut mm_buf = Vec::with_capacity(mm_list_h.length() + mm_payload.len());
                mm_list_h.encode(&mut mm_buf);
                mm_buf.extend_from_slice(mm_payload);

                if is_umm_block {
                    // Non-empty ummRoot: apply UMM double-hash
                    let umm_bytes = header.umm_root.as_ref().unwrap();
                    let base = alloy_primitives::keccak256(&mm_buf);
                    let mut input = Vec::with_capacity(20 + umm_bytes.len());
                    input.extend_from_slice(&base.as_slice()[..20]);
                    input.extend_from_slice(umm_bytes.as_ref());
                    alloy_primitives::keccak256(&input)
                } else {
                    // Empty ummRoot present: single hash of fields 0-16
                    alloy_primitives::keccak256(&mm_buf)
                }
            } else {
                // No ummRoot in the RLP at all: hash of fields 0-15 only
                let mm_payload = &body[..mm_end];
                let mm_list_h = alloy_rlp::Header { list: true, payload_length: mm_payload.len() };
                let mut mm_buf = Vec::with_capacity(mm_list_h.length() + mm_payload.len());
                mm_list_h.encode(&mut mm_buf);
                mm_buf.extend_from_slice(mm_payload);
                alloy_primitives::keccak256(&mm_buf)
            };

            header.cached_hash_for_merged_mining = Some(mm_hash);
        }

        Ok(header)
    }

    /// Returns the hash used in the Bitcoin coinbase transaction for merged mining.
    /// Prefers the cached value computed from original (Java) RLP bytes at decode
    /// time; falls back to re-encoding with Rust RLP for programmatically built
    /// headers (e.g., in tests).
    pub fn hash_for_merged_mining(&self) -> B256 {
        if let Some(h) = self.cached_hash_for_merged_mining {
            return h;
        }

        let has_umm_root = self.umm_root.is_some();
        let is_umm_block = self.umm_root.as_ref().is_some_and(|u| !u.is_empty());

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

        if has_umm_root {
            list_fields.push(alloy_rlp::encode(self.umm_root.as_ref().unwrap().as_ref()));
        }

        let mut out = Vec::new();
        let payload_len = list_fields.iter().map(|f| f.len()).sum::<usize>();
        let rlp_header = alloy_rlp::Header {
            list: true,
            payload_length: payload_len,
        };
        rlp_header.encode(&mut out);
        for field in list_fields {
            out.extend_from_slice(&field);
        }

        let base_hash = alloy_primitives::keccak256(&out);

        if is_umm_block {
            let umm_bytes = self.umm_root.as_ref().unwrap();
            let mut input = Vec::with_capacity(20 + umm_bytes.len());
            input.extend_from_slice(&base_hash.as_slice()[..20]);
            input.extend_from_slice(umm_bytes.as_ref());
            alloy_primitives::keccak256(&input)
        } else {
            base_hash
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256, Bytes, keccak256};
    use alloy_rlp::{Decodable, Encodable};

    fn standard_test_header() -> Header {
        Header {
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
            cached_hash_for_merged_mining: None,
        }
    }

    #[test]
    fn test_header_rlp_roundtrip() {
        let header = standard_test_header();

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

    #[test]
    fn test_decode_with_hash_caches_hash() {
        let header = standard_test_header();
        let mut bytes = Vec::new();
        header.encode(&mut bytes);

        let mut slice = bytes.as_slice();
        let decoded = Header::decode_with_hash(&mut slice).expect("decode failed");

        assert!(decoded.cached_hash.is_some());
        assert_eq!(decoded.hash(), decoded.cached_hash.unwrap());
        // For canonical encoding, cached hash equals keccak256(original bytes)
        assert_eq!(decoded.cached_hash.unwrap(), keccak256(&bytes));
    }

    #[test]
    fn test_cached_hash_overrides_computed() {
        let mut header = standard_test_header();
        header.cached_hash = Some(B256::repeat_byte(0xAB));

        assert_eq!(header.hash(), B256::repeat_byte(0xAB));
    }

    #[test]
    fn test_hash_without_cache_computes_from_rlp() {
        let header = standard_test_header();
        assert_eq!(header.cached_hash, None);

        let hash1 = header.hash();
        assert_ne!(hash1, B256::ZERO);

        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_decode_with_hash_differs_from_noncanonical() {
        let header = standard_test_header();
        let mut bytes = Vec::new();
        header.encode(&mut bytes);

        let mut slice = bytes.as_slice();
        let decoded = Header::decode_with_hash(&mut slice).expect("decode failed");

        assert_eq!(decoded.cached_hash.unwrap(), keccak256(&bytes));
    }

    /// Groundtruth: the uncle of RSK MAINNET BLOCK #3397 (header #3395,
    /// hash 0xc1a82a82..., from public-node.rsk.co). Its zero
    /// minimumGasPrice encodes as a raw 0x00 byte (encodeSignedCoinNonNullZero)
    /// and its empty merged-mining proof/coinbase encode as 0x80 placeholders.
    /// Both the uncle's own hash and the block's sha3Uncles must match.
    #[test]
    fn test_mainnet_block_3397_uncle_encoding() {
        let header = Header {
            parent_hash: "0x6e2c4fc25852c65f06d2be44b702029f142d9ab89d5f5f21c24bb00ea890a4c6".parse().unwrap(),
            ommers_hash: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".parse().unwrap(),
            beneficiary: "0x14d3065c8eb89895f4df12450ec6b130049f8034".parse().unwrap(),
            state_root: "0x42536b117ad09ae74da25b5bc25dc1fc98fc1d995a2cba419673807966421624".parse().unwrap(),
            transactions_root: "0x1def8d2ff49af73e1abbb2c973a1af6f496b5e44bd7a93fbd1c0156090a50a9b".parse().unwrap(),
            receipts_root: "0x10494928db1d75522b131648096f37c5982db7ac4da9f0ab0d9820efafa3ecec".parse().unwrap(),
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(0x1ef082d0eba72au64),
            number: 0xd43,
            gas_limit: U256::from(0x4c4b40),
            gas_used: 0x4be3d0,
            timestamp: 0x5a4e720b,
            extra_data: Bytes::from_static(&[0x2a]),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: Some(Bytes::from(
                alloy_primitives::hex::decode("f8441ba100c98acd36a060dd25c8c8d46f42ededd98f7c2c7e5d460c3557a6ba0e693d4d50a053c04cb6bedfa59173811b3b1c2783f4328a7745f136abe58fcd1bac16de76e6").unwrap()
            )),
            bitcoin_merged_mining_merkle_proof: Some(Bytes::new()),
            bitcoin_merged_mining_coinbase_transaction: Some(Bytes::new()),
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        };

        let mut encoded = Vec::new();
        header.encode(&mut encoded);
        let expected_hash: B256 =
            "0xc1a82a82e999490d8570ae9b80a3dcd29d143a65241d02db30e3d174988353d4".parse().unwrap();
        assert_eq!(keccak256(&encoded), expected_hash, "uncle header hash");

        // sha3Uncles of block #3397 = keccak(RLP([uncle_full_encoding]))
        let mut uncles_list = Vec::new();
        alloy_rlp::Header { list: true, payload_length: encoded.len() }.encode(&mut uncles_list);
        uncles_list.extend_from_slice(&encoded);
        let expected_sha3_uncles: B256 =
            "0xed488b69222610bae4c438b50d2472019e3efed77c654771025775d19d2ec648".parse().unwrap();
        assert_eq!(keccak256(&uncles_list), expected_sha3_uncles, "block #3397 sha3Uncles");
    }
}
