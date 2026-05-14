/// RSK transaction receipt — RLP-compatible with rskj.
///
/// rskj encodes receipts as:
///   `[postTxState, cumulativeGas, bloom, logs, gasUsed, status]`
///
/// where `postTxState` is either a 32-byte state root or a 1-byte tx status
/// (pre/post-Byzantium), `status` is `0x01` for success or `0x80`/empty for
/// failure, and each log is `[address, [topic0, ...], data]`.
use alloy_primitives::{Address, Bloom, Bytes, B256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Post-transaction state root or short tx-status indicator.
    /// In modern RSK this is `[0x01]` for success, `[]` for failure.
    pub post_tx_state: Vec<u8>,
    pub cumulative_gas_used: u64,
    pub gas_used: u64,
    pub logs_bloom: Bloom,
    pub logs: Vec<Log>,
    /// Transaction status: `[0x01]` for success, `[]` for failure.
    pub status: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

impl Receipt {
    /// Build a receipt from execution results (post-Byzantium style).
    pub fn new(
        success: bool,
        cumulative_gas_used: u64,
        gas_used: u64,
        logs_bloom: Bloom,
        logs: Vec<Log>,
    ) -> Self {
        let post_tx_state = if success { vec![0x01] } else { vec![] };
        Self {
            post_tx_state,
            cumulative_gas_used,
            gas_used,
            logs_bloom,
            logs,
            status: success,
        }
    }

    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

/// Encodes `[postTxState, cumulativeGas, bloom, logs, gasUsed, status]` to match rskj.
impl Encodable for Receipt {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut inner = Vec::new();

        self.post_tx_state.as_slice().encode(&mut inner);
        encode_bigint_bytes(self.cumulative_gas_used, &mut inner);
        self.logs_bloom.as_slice().encode(&mut inner);

        let mut logs_payload = Vec::new();
        for log in &self.logs {
            log.encode(&mut logs_payload);
        }
        RlpHeader { list: true, payload_length: logs_payload.len() }.encode(&mut inner);
        inner.extend_from_slice(&logs_payload);

        encode_bigint_bytes(self.gas_used, &mut inner);

        let status_bytes: &[u8] = if self.status { &[0x01] } else { &[] };
        status_bytes.encode(&mut inner);

        RlpHeader { list: true, payload_length: inner.len() }.encode(out);
        out.put_slice(&inner);
    }
}

/// Decodes `[postTxState, cumulativeGas, bloom, logs, gasUsed, status]` matching rskj.
impl Decodable for Receipt {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = RlpHeader::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut data = &buf[..header.payload_length];
        *buf = &buf[header.payload_length..];

        let post_tx_state_bytes = alloy_rlp::Header::decode_bytes(&mut data, false)?;
        let post_tx_state = post_tx_state_bytes.to_vec();

        let cum_gas_bytes = alloy_rlp::Header::decode_bytes(&mut data, false)?;
        let cumulative_gas_used = bytes_to_u64(cum_gas_bytes);

        let bloom_bytes = alloy_rlp::Header::decode_bytes(&mut data, false)?;
        let logs_bloom = if bloom_bytes.is_empty() {
            Bloom::ZERO
        } else if bloom_bytes.len() == 256 {
            Bloom::from_slice(bloom_bytes)
        } else {
            // rskj can encode shorter blooms; pad with leading zeros
            let mut full = [0u8; 256];
            let start = 256 - bloom_bytes.len();
            full[start..].copy_from_slice(bloom_bytes);
            Bloom::from_slice(&full)
        };

        let logs_header = RlpHeader::decode(&mut data)?;
        let mut logs_data = &data[..logs_header.payload_length];
        data = &data[logs_header.payload_length..];
        let mut logs = Vec::new();
        while !logs_data.is_empty() {
            logs.push(Log::decode(&mut logs_data)?);
        }

        let gas_used_bytes = alloy_rlp::Header::decode_bytes(&mut data, false)?;
        let gas_used = bytes_to_u64(gas_used_bytes);

        let status = if !data.is_empty() {
            let status_bytes = alloy_rlp::Header::decode_bytes(&mut data, false)?;
            !status_bytes.is_empty() && status_bytes[0] == 0x01
        } else {
            // No status field (old blocks) — derive from postTxState
            post_tx_state.len() == 1 && post_tx_state[0] == 0x01
        };

        Ok(Self {
            post_tx_state,
            cumulative_gas_used,
            gas_used,
            logs_bloom,
            logs,
            status,
        })
    }
}

impl Encodable for Log {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut inner = Vec::new();
        self.address.encode(&mut inner);

        let mut topics_payload = Vec::new();
        for topic in &self.topics {
            topic.encode(&mut topics_payload);
        }
        RlpHeader { list: true, payload_length: topics_payload.len() }.encode(&mut inner);
        inner.extend_from_slice(&topics_payload);

        self.data.encode(&mut inner);

        RlpHeader { list: true, payload_length: inner.len() }.encode(out);
        out.put_slice(&inner);
    }
}

impl Decodable for Log {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = RlpHeader::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut data = &buf[..header.payload_length];
        *buf = &buf[header.payload_length..];

        let address = Address::decode(&mut data)?;

        let topics_header = RlpHeader::decode(&mut data)?;
        let mut topics_data = &data[..topics_header.payload_length];
        data = &data[topics_header.payload_length..];
        let mut topics = Vec::new();
        while !topics_data.is_empty() {
            topics.push(B256::decode(&mut topics_data)?);
        }

        let log_data = Bytes::decode(&mut data)?;

        Ok(Self { address, topics, data: log_data })
    }
}

/// Compute the receipts trie root using the RSK Unitrie.
///
/// Each receipt is keyed by `RLP.encodeInt(index)` and valued at `receipt.getEncoded()`.
/// The root hash is the Unitrie hash of that trie — matching rskj's `BlockHashesHelper`.
pub fn ordered_trie_root(receipts: &[Receipt]) -> B256 {
    use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode};

    let store = MemoryTrieStore::new();
    let mut root = TrieNode::empty();

    for (i, receipt) in receipts.iter().enumerate() {
        let key_bytes = rlp_encode_int(i as u32);
        let key = TrieKeySlice::from_key(&key_bytes);
        root = root.put(&key, &receipt.rlp_encode(), &store);
    }

    root.compute_hash(&store)
}

/// Compute the transactions trie root using the RSK Unitrie.
///
/// Matches rskj's `BlockHashesHelper.getTxTrieRoot`.
pub fn ordered_tx_trie_root(transactions: &[super::transaction::Transaction]) -> B256 {
    use rustock_trie::{MemoryTrieStore, TrieKeySlice, TrieNode};

    let store = MemoryTrieStore::new();
    let mut root = TrieNode::empty();

    for (i, tx) in transactions.iter().enumerate() {
        let key_bytes = rlp_encode_int(i as u32);
        let key = TrieKeySlice::from_key(&key_bytes);
        let encoded = tx.rlp_for_trie();
        root = root.put(&key, &encoded, &store);
    }

    root.compute_hash(&store)
}

/// RLP-encode an integer the same way rskj's `RLP.encodeInt(i)` does.
///
/// rskj encodes ints as big-endian byte arrays with leading-zero stripping,
/// then wraps in an RLP element.
fn rlp_encode_int(val: u32) -> Vec<u8> {
    let be = val.to_be_bytes();
    let trimmed = trim_leading_zeros(&be);
    let mut out = Vec::new();
    trimmed.encode(&mut out);
    out
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Encode a u64 as big-endian bytes (like Java BigInteger.asUnsignedByteArray),
/// then RLP-encode as element.
fn encode_bigint_bytes(val: u64, out: &mut Vec<u8>) {
    let be = val.to_be_bytes();
    let trimmed = trim_leading_zeros(&be);
    trimmed.encode(out);
}

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    for &b in bytes {
        result = (result << 8) | b as u64;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_log() -> Log {
        Log {
            address: Address::repeat_byte(0xAA),
            topics: vec![
                B256::repeat_byte(0x01),
                B256::repeat_byte(0x02),
            ],
            data: Bytes::from(vec![0xDE, 0xAD]),
        }
    }

    fn sample_receipt() -> Receipt {
        Receipt::new(true, 21_000, 21_000, Bloom::ZERO, vec![sample_log()])
    }

    #[test]
    fn test_receipt_rlp_roundtrip() {
        let receipt = sample_receipt();
        let encoded = receipt.rlp_encode();
        let decoded = Receipt::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_receipt_no_logs_roundtrip() {
        let receipt = Receipt::new(false, 50_000, 50_000, Bloom::ZERO, vec![]);
        let encoded = receipt.rlp_encode();
        let decoded = Receipt::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_receipt_multiple_logs_roundtrip() {
        let receipt = Receipt::new(
            true,
            100_000,
            50_000,
            Bloom::ZERO,
            vec![
                Log {
                    address: Address::repeat_byte(0x11),
                    topics: vec![B256::repeat_byte(0xAA)],
                    data: Bytes::from(vec![1, 2, 3]),
                },
                Log {
                    address: Address::repeat_byte(0x22),
                    topics: vec![],
                    data: Bytes::new(),
                },
            ],
        );
        let encoded = receipt.rlp_encode();
        let decoded = Receipt::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_log_rlp_roundtrip() {
        let log = sample_log();
        let mut buf = Vec::new();
        log.encode(&mut buf);
        let decoded = Log::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(log, decoded);
    }

    #[test]
    fn test_ordered_trie_root_empty() {
        let root = ordered_trie_root(&[]);
        assert_ne!(root, B256::ZERO, "empty trie root should not be all zeros");
    }

    #[test]
    fn test_ordered_trie_root_deterministic() {
        let receipts = vec![sample_receipt(), sample_receipt()];
        let root1 = ordered_trie_root(&receipts);
        let root2 = ordered_trie_root(&receipts);
        assert_eq!(root1, root2, "same receipts should produce same root");
    }

    #[test]
    fn test_ordered_trie_root_differs_on_content() {
        let r1 = Receipt::new(true, 21_000, 21_000, Bloom::ZERO, vec![]);
        let r2 = Receipt::new(true, 42_000, 42_000, Bloom::ZERO, vec![]);
        let root_a = ordered_trie_root(&[r1]);
        let root_b = ordered_trie_root(&[r2]);
        assert_ne!(root_a, root_b, "different receipts should produce different root");
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj TransactionReceiptTest
    // -----------------------------------------------------------------------

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Ported from rskj TransactionReceiptTest.test_2.
    /// Decodes a successful receipt from a known RLP blob and validates it.
    #[test]
    fn test_rskj_receipt_success_rlp() {
        let rlp_hex = "f9010c808255aeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c08255ae01";
        let rlp_bytes = hex_to_bytes(rlp_hex);
        let receipt = Receipt::decode(&mut rlp_bytes.as_slice()).unwrap();
        assert!(receipt.status, "receipt status should be success (0x01)");
        assert_eq!(receipt.cumulative_gas_used, 0x55ae);
        assert_eq!(receipt.gas_used, 0x55ae);
        assert_eq!(receipt.logs.len(), 0);

        let re_encoded = receipt.rlp_encode();
        assert_eq!(rlp_bytes, re_encoded, "re-encoded receipt should match rskj bytes");
    }

    /// Ported from rskj TransactionReceiptTest.test_2 (failed variant).
    #[test]
    fn test_rskj_receipt_failed_rlp() {
        let rlp_hex = "f9010c808255aeb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c08255ae80";
        let rlp_bytes = hex_to_bytes(rlp_hex);
        let receipt = Receipt::decode(&mut rlp_bytes.as_slice()).unwrap();
        assert!(!receipt.status, "receipt status should be failure (0x80/empty)");
        assert_eq!(receipt.cumulative_gas_used, 0x55ae);

        let re_encoded = receipt.rlp_encode();
        assert_eq!(rlp_bytes, re_encoded, "re-encoded receipt should match rskj bytes");
    }

    /// Ported from rskj TransactionReceiptTest.test_1.
    /// Old-format receipt with a 64-byte bloom and 5 RLP fields (no explicit status).
    #[test]
    fn test_rskj_receipt_with_log_rlp() {
        // Exact concatenation of the Java string literals from rskj
        let rlp_hex = concat!(
            "f8c5a0966265cc49fa1f10f0445f035258d116563931022a3570a640af5d73a214a8da822b6fb84",
            "0000000100000000100000000000800000000000000000000000000000000000000000000000000000000000200000000000",
            "00014000000000400000000000440f85cf85a94d5ccd26ba09ce1d85148b5081fa3ed77949417bef842a0000000000000000",
            "000000000459d3a7595df9eba241365f4676803586d7d199ca0436f696e73000000000000000000000000000000000000000",
            "0000000000000008002"
        );
        let rlp_bytes = hex_to_bytes(rlp_hex);
        let receipt = Receipt::decode(&mut rlp_bytes.as_slice()).unwrap();

        assert_eq!(receipt.logs.len(), 1, "should have 1 log entry");
        assert_eq!(receipt.cumulative_gas_used, 0x2b6f);
        assert_eq!(receipt.gas_used, 0x02);
        assert_eq!(
            receipt.post_tx_state,
            hex_to_bytes("966265cc49fa1f10f0445f035258d116563931022a3570a640af5d73a214a8da"),
        );
        assert_eq!(
            receipt.logs[0].address,
            Address::from_slice(&hex_to_bytes("d5ccd26ba09ce1d85148b5081fa3ed77949417be")),
        );
        assert_eq!(receipt.logs[0].topics.len(), 2);
        assert_eq!(
            receipt.logs[0].topics[0],
            B256::from_slice(&hex_to_bytes("000000000000000000000000459d3a7595df9eba241365f4676803586d7d199c")),
        );
    }

    /// Ported from rskj BloomTest.test1 — log RLP component.
    #[test]
    fn test_rskj_log_rlp_from_receipt_vector() {
        let log_rlp_hex = "f85a94d5ccd26ba09ce1d85148b5081fa3ed77949417bef842a0000000000000000000000000459d3a7595df9eba241365f4676803586d7d199ca0436f696e7300000000000000000000000000000000000000000000000000000080";
        let rlp_bytes = hex_to_bytes(log_rlp_hex);
        let log = Log::decode(&mut rlp_bytes.as_slice()).unwrap();

        assert_eq!(
            log.address,
            Address::from_slice(&hex_to_bytes("d5ccd26ba09ce1d85148b5081fa3ed77949417be")),
        );
        assert_eq!(log.topics.len(), 2);
        assert!(log.data.is_empty());

        let mut re_encoded = Vec::new();
        log.encode(&mut re_encoded);
        assert_eq!(rlp_bytes, re_encoded, "re-encoded log RLP must match original rskj bytes");
    }

    #[test]
    fn test_rlp_encode_int_matches_rskj() {
        // RLP.encodeInt(0) = 0x80 (empty byte array)
        assert_eq!(rlp_encode_int(0), vec![0x80]);
        // RLP.encodeInt(1) = 0x01 (single byte)
        assert_eq!(rlp_encode_int(1), vec![0x01]);
        // RLP.encodeInt(127) = 0x7f
        assert_eq!(rlp_encode_int(127), vec![0x7f]);
        // RLP.encodeInt(128) = 0x8180
        assert_eq!(rlp_encode_int(128), vec![0x81, 0x80]);
        // RLP.encodeInt(256) = 0x820100
        assert_eq!(rlp_encode_int(256), vec![0x82, 0x01, 0x00]);
    }
}
