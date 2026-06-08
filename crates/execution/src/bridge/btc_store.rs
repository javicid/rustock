//! BTC block store in Bridge contract storage.
//!
//! Mirrors rskj's `RepositoryBtcBlockStoreWithCache`. Each BTC block is stored
//! as a serialized `StoredBlock` in the Bridge contract's storage, keyed by
//! the block's hash. The chain head is stored under a special key.
//!
//! ## StoredBlock serialization format
//!
//! **Legacy (96 bytes):** `[chain_work: 12B BE][height: 4B BE][header: 80B]`
//! **V2 (116 bytes):**    `[chain_work: 32B BE][height: 4B BE][header: 80B]`
//!
//! The BTC block header is the standard 80-byte Bitcoin wire format:
//! `[version: 4B LE][prev_hash: 32B][merkle_root: 32B][time: 4B LE][bits: 4B LE][nonce: 4B LE]`

use alloy_primitives::U256;
use bitcoin::block::Header as BtcHeader;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::BlockHash;

use crate::precompiles::BRIDGE_ADDR;

// ---------------------------------------------------------------------------
// StoredBlock
// ---------------------------------------------------------------------------

const LEGACY_SIZE: usize = 12 + 4 + 80; // 96
const V2_SIZE: usize = 32 + 4 + 80;     // 116
const HEADER_SIZE: usize = 80;
const LEGACY_CHAIN_WORK_SIZE: usize = 12;
const V2_CHAIN_WORK_SIZE: usize = 32;

/// A BTC block header with height and cumulative chain work, stored in
/// the Bridge contract's storage.
#[derive(Debug, Clone)]
pub struct StoredBlock {
    pub header: BtcHeader,
    pub height: u32,
    pub chain_work: U256,
}

impl StoredBlock {
    pub fn new(header: BtcHeader, height: u32, chain_work: U256) -> Self {
        Self {
            header,
            height,
            chain_work,
        }
    }

    /// Block hash (double-SHA256 of the 80-byte header).
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Serialize in the legacy compact format (96 bytes).
    /// Layout: `[chain_work: 12B BE][height: 4B BE][header: 80B]`
    pub fn serialize_compact_legacy(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(LEGACY_SIZE);

        // Chain work: 12 bytes, big-endian, zero-padded
        let cw_bytes = self.chain_work.to_be_bytes::<32>();
        buf.extend_from_slice(&cw_bytes[32 - LEGACY_CHAIN_WORK_SIZE..]);

        // Height: 4 bytes, big-endian
        buf.extend_from_slice(&self.height.to_be_bytes());

        // Header: 80 bytes, standard Bitcoin wire format
        let header_bytes = serialize(&self.header);
        buf.extend_from_slice(&header_bytes);

        debug_assert_eq!(buf.len(), LEGACY_SIZE);
        buf
    }

    /// Serialize in the V2 compact format (116 bytes).
    /// Layout: `[chain_work: 32B BE][height: 4B BE][header: 80B]`
    pub fn serialize_compact_v2(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(V2_SIZE);

        // Chain work: 32 bytes, big-endian
        buf.extend_from_slice(&self.chain_work.to_be_bytes::<32>());

        // Height: 4 bytes, big-endian
        buf.extend_from_slice(&self.height.to_be_bytes());

        // Header: 80 bytes
        let header_bytes = serialize(&self.header);
        buf.extend_from_slice(&header_bytes);

        debug_assert_eq!(buf.len(), V2_SIZE);
        buf
    }

    /// Deserialize from the legacy compact format (96 bytes).
    pub fn deserialize_compact_legacy(data: &[u8]) -> Option<Self> {
        if data.len() != LEGACY_SIZE {
            return None;
        }

        // Chain work: 12 bytes big-endian → U256
        let mut cw_buf = [0u8; 32];
        cw_buf[32 - LEGACY_CHAIN_WORK_SIZE..].copy_from_slice(&data[..LEGACY_CHAIN_WORK_SIZE]);
        let chain_work = U256::from_be_bytes(cw_buf);

        // Height: 4 bytes big-endian
        let height = u32::from_be_bytes([
            data[LEGACY_CHAIN_WORK_SIZE],
            data[LEGACY_CHAIN_WORK_SIZE + 1],
            data[LEGACY_CHAIN_WORK_SIZE + 2],
            data[LEGACY_CHAIN_WORK_SIZE + 3],
        ]);

        // Header: 80 bytes
        let header_start = LEGACY_CHAIN_WORK_SIZE + 4;
        let header: BtcHeader =
            deserialize(&data[header_start..header_start + HEADER_SIZE]).ok()?;

        Some(Self::new(header, height, chain_work))
    }

    /// Deserialize from the V2 compact format (116 bytes).
    pub fn deserialize_compact_v2(data: &[u8]) -> Option<Self> {
        if data.len() != V2_SIZE {
            return None;
        }

        // Chain work: 32 bytes big-endian → U256
        let cw_bytes: [u8; 32] = data[..V2_CHAIN_WORK_SIZE].try_into().unwrap();
        let chain_work = U256::from_be_bytes(cw_bytes);

        // Height: 4 bytes big-endian
        let height = u32::from_be_bytes([
            data[V2_CHAIN_WORK_SIZE],
            data[V2_CHAIN_WORK_SIZE + 1],
            data[V2_CHAIN_WORK_SIZE + 2],
            data[V2_CHAIN_WORK_SIZE + 3],
        ]);

        // Header: 80 bytes
        let header_start = V2_CHAIN_WORK_SIZE + 4;
        let header: BtcHeader =
            deserialize(&data[header_start..header_start + HEADER_SIZE]).ok()?;

        Some(Self::new(header, height, chain_work))
    }

    /// Auto-detect format based on data length.
    pub fn deserialize_compact(data: &[u8]) -> Option<Self> {
        match data.len() {
            LEGACY_SIZE => Self::deserialize_compact_legacy(data),
            V2_SIZE => Self::deserialize_compact_v2(data),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Contract storage access
// ---------------------------------------------------------------------------

/// Key for chain head entry.
const CHAIN_HEAD_KEY: &str = "blockStoreChainHead";

/// Convert a BTC block hash to a U256 storage key.
/// Matches rskj's `DataWord.valueFromHex(blockHash.toString())`: bitcoinj
/// `Sha256Hash` bytes are in DISPLAY order (the conventional big-endian hex),
/// which is the reverse of the bitcoin crate's internal byte order.
pub fn btc_hash_to_storage_key(hash: &BlockHash) -> U256 {
    let mut bytes = *hash.to_raw_hash().as_byte_array();
    bytes.reverse();
    U256::from_be_bytes(bytes)
}

/// Store the chain head.
pub fn store_chain_head<CTX: crate::RskContextTr>(ctx: &mut CTX, block: &StoredBlock, use_v2: bool) {
    let key = super::storage::bridge_storage_key(CHAIN_HEAD_KEY);
    let data = if use_v2 {
        block.serialize_compact_v2()
    } else {
        block.serialize_compact_legacy()
    };
    store_raw_bytes(ctx, key, &data);
}

/// Load the chain head.
pub fn load_chain_head<CTX: crate::RskContextTr>(ctx: &mut CTX) -> Option<StoredBlock> {
    let key = super::storage::bridge_storage_key(CHAIN_HEAD_KEY);
    let data = load_raw_bytes(ctx, key);
    if data.is_empty() {
        return None;
    }
    StoredBlock::deserialize_compact(&data)
}

/// Store a StoredBlock by its hash.
pub fn put_stored_block<CTX: crate::RskContextTr>(ctx: &mut CTX, block: &StoredBlock, use_v2: bool) {
    let hash = block.block_hash();
    let key = btc_hash_to_storage_key(&hash);
    let data = if use_v2 {
        block.serialize_compact_v2()
    } else {
        block.serialize_compact_legacy()
    };
    store_raw_bytes(ctx, key, &data);
}

/// Load a StoredBlock by its hash.
pub fn get_stored_block<CTX: crate::RskContextTr>(ctx: &mut CTX, hash: &BlockHash) -> Option<StoredBlock> {
    let key = btc_hash_to_storage_key(hash);
    let data = load_raw_bytes(ctx, key);
    if data.is_empty() {
        return None;
    }
    StoredBlock::deserialize_compact(&data)
}

// ---------------------------------------------------------------------------
// Raw byte storage: one variable-length value per unitrie key
// (rskj Repository.addStorageBytes / getStorageBytes).
// ---------------------------------------------------------------------------

fn store_raw_bytes<CTX: crate::RskContextTr>(ctx: &mut CTX, base_key: U256, data: &[u8]) {
    ctx.chain_mut()
        .raw_storage
        .put(BRIDGE_ADDR, base_key, Some(data.to_vec()));
}

fn load_raw_bytes<CTX: crate::RskContextTr>(ctx: &mut CTX, base_key: U256) -> Vec<u8> {
    ctx.chain_mut()
        .raw_storage
        .get(BRIDGE_ADDR, base_key)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// BTC chain work computation
// ---------------------------------------------------------------------------

/// Compute the work represented by a compact target (bits field).
/// Matches bitcoinj's `Block.getWork()`: `2^256 / (target + 1)`.
pub fn compute_work(bits: CompactTarget) -> U256 {
    let target = compact_target_to_u256(bits);
    if target.is_zero() {
        return U256::ZERO;
    }
    // 2^256 is not representable in U256, but we can compute:
    // work = (2^256 - target - 1) / (target + 1) + 1
    // which is equivalent to ceiling division.
    let target_plus_one = target.wrapping_add(U256::from(1));
    let max = U256::MAX;
    (max - target) / target_plus_one + U256::from(1)
}

/// Convert CompactTarget (nBits) to a U256 target value.
pub fn compact_target_to_u256(bits: CompactTarget) -> U256 {
    let bits_u32 = bits.to_consensus();
    let exponent = bits_u32 >> 24;
    let mantissa = bits_u32 & 0x007FFFFF;

    if exponent <= 3 {
        let shifted = mantissa >> (8 * (3 - exponent));
        U256::from(shifted)
    } else {
        let shift_bits = 8 * (exponent - 3);
        if shift_bits >= 256 {
            U256::ZERO
        } else {
            U256::from(mantissa) << shift_bits
        }
    }
}

/// Check if a block hash meets the proof-of-work target.
/// The hash (interpreted as a LE U256) must be ≤ target.
pub fn check_proof_of_work(header: &BtcHeader) -> bool {
    let target = compact_target_to_u256(header.bits);
    let hash = header.block_hash();
    let raw = hash.to_raw_hash();
    let hash_bytes: &[u8; 32] = raw.as_byte_array();
    // bitcoin crate stores hashes in "internal byte order" (raw SHA256 output).
    // For PoW, these bytes are interpreted as a little-endian 256-bit number
    // (matching Bitcoin Core's UintToArith256). Valid blocks have trailing
    // zero bytes in internal order (leading zeros in display order).
    let hash_u256 = U256::from_le_bytes(*hash_bytes);
    hash_u256 <= target
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;
    use bitcoin::{CompactTarget, TxMerkleNode};

    fn test_header(version: i32, nonce: u32) -> BtcHeader {
        BtcHeader {
            version: Version::from_consensus(version),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        }
    }

    #[test]
    fn stored_block_legacy_roundtrip() {
        let header = test_header(1, 42);
        let block = StoredBlock::new(header, 100, U256::from(12345));

        let serialized = block.serialize_compact_legacy();
        assert_eq!(serialized.len(), LEGACY_SIZE);

        let deserialized = StoredBlock::deserialize_compact_legacy(&serialized).unwrap();
        assert_eq!(deserialized.height, 100);
        assert_eq!(deserialized.chain_work, U256::from(12345));
        assert_eq!(deserialized.header.nonce, 42);
        assert_eq!(deserialized.header.version.to_consensus(), 1);
    }

    #[test]
    fn stored_block_v2_roundtrip() {
        let header = test_header(2, 99);
        let chain_work = U256::from(1u128) << 100; // large value that doesn't fit in 12 bytes
        let block = StoredBlock::new(header, 500_000, chain_work);

        let serialized = block.serialize_compact_v2();
        assert_eq!(serialized.len(), V2_SIZE);

        let deserialized = StoredBlock::deserialize_compact_v2(&serialized).unwrap();
        assert_eq!(deserialized.height, 500_000);
        assert_eq!(deserialized.chain_work, chain_work);
        assert_eq!(deserialized.header.nonce, 99);
    }

    #[test]
    fn auto_detect_legacy() {
        let block = StoredBlock::new(test_header(1, 1), 0, U256::from(1));
        let data = block.serialize_compact_legacy();
        let decoded = StoredBlock::deserialize_compact(&data).unwrap();
        assert_eq!(decoded.height, 0);
    }

    #[test]
    fn auto_detect_v2() {
        let block = StoredBlock::new(test_header(1, 1), 0, U256::from(1));
        let data = block.serialize_compact_v2();
        let decoded = StoredBlock::deserialize_compact(&data).unwrap();
        assert_eq!(decoded.height, 0);
    }

    #[test]
    fn hash_preserved_through_serialization() {
        let header = test_header(1, 12345);
        let original_hash = header.block_hash();
        let block = StoredBlock::new(header, 10, U256::from(100));

        let legacy = StoredBlock::deserialize_compact_legacy(&block.serialize_compact_legacy()).unwrap();
        assert_eq!(legacy.block_hash(), original_hash);

        let v2 = StoredBlock::deserialize_compact_v2(&block.serialize_compact_v2()).unwrap();
        assert_eq!(v2.block_hash(), original_hash);
    }

    #[test]
    fn legacy_chain_work_truncation() {
        // Chain work that fits in 12 bytes
        let cw = U256::from(0xFFFFFFFFFFFFu64);
        let block = StoredBlock::new(test_header(1, 1), 1, cw);
        let data = block.serialize_compact_legacy();
        let decoded = StoredBlock::deserialize_compact_legacy(&data).unwrap();
        assert_eq!(decoded.chain_work, cw);
    }

    #[test]
    fn compute_work_standard_difficulty() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let work = compute_work(bits);
        assert!(work > U256::ZERO);
    }

    #[test]
    fn compact_target_conversion() {
        // 0x1d00ffff = standard Bitcoin difficulty 1 target
        let target = compact_target_to_u256(CompactTarget::from_consensus(0x1d00ffff));
        // Should be 0x00000000FFFF0000...0000 (with 0xFFFF at bytes 4-5)
        assert!(target > U256::ZERO);
        // Verify it's the expected value
        let expected = U256::from(0xFFFFu64) << (8 * 26);
        assert_eq!(target, expected);
    }

    #[test]
    fn btc_hash_to_key() {
        let header = test_header(1, 1);
        let hash = header.block_hash();
        let key = btc_hash_to_storage_key(&hash);
        assert!(!key.is_zero());
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj
    // -----------------------------------------------------------------------

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.replace(|c: char| c.is_whitespace(), "");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn parse_mainnet_header() -> BtcHeader {
        // Real Bitcoin mainnet block 849137 header (from rskj
        // RepositoryBtcBlockStoreWithCacheChainWorkTest)
        let header_hex = "00e00820925b77c9ff4d0036aa29f3238cde12e9af9d55c34ed302\
                          00000000000000000032a9fa3e12ef87a2327b55db6a16a1227bb3\
                          81db8b269d90aa3a6e38cf39665f91b47766255d0317c1b1575f";
        let bytes = hex_to_bytes(header_hex);
        assert_eq!(bytes.len(), 80);
        deserialize(&bytes).unwrap()
    }

    /// Ported from rskj RepositoryBtcBlockStoreWithCacheChainWorkTest —
    /// verify legacy (96-byte) serialization roundtrip with a real mainnet
    /// block header at height 849137.
    #[test]
    fn rskj_stored_block_legacy_roundtrip_mainnet_849137() {
        let header = parse_mainnet_header();
        let height: u32 = 849_137;
        let original_hash = header.block_hash();

        for chain_work in [
            U256::ZERO,
            U256::from(1u64),
            U256::from(i64::MAX as u64),
            U256::from_str_radix("ffffffffffffffffffffffff", 16).unwrap(), // MAX_WORK_V1
        ] {
            let block = StoredBlock::new(header, height, chain_work);
            let serialized = block.serialize_compact_legacy();
            assert_eq!(serialized.len(), LEGACY_SIZE);

            let deserialized = StoredBlock::deserialize_compact_legacy(&serialized).unwrap();
            assert_eq!(deserialized.height, height);
            assert_eq!(deserialized.chain_work, chain_work);
            assert_eq!(deserialized.block_hash(), original_hash);
        }
    }

    /// Ported from rskj RepositoryBtcBlockStoreWithCacheChainWorkTest —
    /// verify V2 (116-byte) serialization roundtrip with a real mainnet
    /// block header. V2 supports chain work > 12 bytes.
    #[test]
    fn rskj_stored_block_v2_roundtrip_mainnet_849137() {
        let header = parse_mainnet_header();
        let height: u32 = 849_137;
        let original_hash = header.block_hash();

        for chain_work in [
            U256::ZERO,
            U256::from(1u64),
            U256::from(i64::MAX as u64),
            U256::from_str_radix("ffffffffffffffffffffffff", 16).unwrap(),
            U256::from_str_radix("ffffffffffffffffffffffffff", 16).unwrap(), // TOO_LARGE_WORK_V1
            U256::MAX, // MAX_WORK_V2
        ] {
            let block = StoredBlock::new(header, height, chain_work);
            let serialized = block.serialize_compact_v2();
            assert_eq!(serialized.len(), V2_SIZE);

            let deserialized = StoredBlock::deserialize_compact_v2(&serialized).unwrap();
            assert_eq!(deserialized.height, height);
            assert_eq!(deserialized.chain_work, chain_work);
            assert_eq!(deserialized.block_hash(), original_hash);
        }
    }

    /// Verify that the real mainnet header at height 849137 passes PoW check.
    #[test]
    fn rskj_mainnet_849137_passes_pow() {
        let header = parse_mainnet_header();
        assert!(check_proof_of_work(&header), "mainnet block 849137 should pass PoW");
    }

    /// Verify compute_work produces a non-zero result for mainnet difficulty.
    #[test]
    fn rskj_mainnet_849137_work() {
        let header = parse_mainnet_header();
        let work = compute_work(header.bits);
        assert!(work > U256::ZERO);
        // nBits = 0x17035d25 → very high difficulty, work should be large
        let min_expected = U256::from(1u128) << 64;
        assert!(work > min_expected, "mainnet work should be large");
    }

    /// Test 5 real mainnet headers from rskj's BridgeSupportTest.ChainWorkTests
    /// (blocks 849134-849137, 849139).
    #[test]
    fn rskj_mainnet_blocks_849134_to_849139_pow() {
        let headers = [
            // 849134
            "0080b92c24f123130ae29e899f0cab72653722e54cdf3b30445202000000000000000000c72ead65a3b78ab637d1876c00414a77e47bcc5b52667ac1e573633563bea5a695aa7766255d031728d182a8",
            // 849135
            "00004020bf67910b5d3996ee594848b482ee84d0e28c97a9a2d601000000000000000000865e218552bb92df36c962f5163e84a6c2542584fb36be2fa8b2a4246c73a701f1ae7766255d031791836b22",
            // 849136
            "0000003a796f8b7a9d6ba6e13064e7c64e94570f877170262f1f0200000000000000000036b2ab17565a24a9be4626ca801cb31f91232034ba848295475f931a58dd5446e5b07766255d03173b01a491",
            // 849137
            "00e00820925b77c9ff4d0036aa29f3238cde12e9af9d55c34ed30200000000000000000032a9fa3e12ef87a2327b55db6a16a1227bb381db8b269d90aa3a6e38cf39665f91b47766255d0317c1b1575f",
            // 849139
            "00a0b625ffa2f7cbf95219fc74c3db38f84ae265784bc1417c71020000000000000000008e5b319a229376089f4a7b77c90ed90ac19a0532fc4c62426f5a5931ee7e3e8dd2c67766255d03171e91a015",
        ];
        for (i, hdr_hex) in headers.iter().enumerate() {
            let bytes = hex_to_bytes(hdr_hex);
            assert_eq!(bytes.len(), 80, "header {i} wrong size");
            let hdr: BtcHeader = deserialize(&bytes).expect("header {i} deserialize");
            assert!(check_proof_of_work(&hdr), "mainnet block at index {i} should pass PoW");
        }
    }

    /// Ported from rskj BridgeSupportTest.ChainWorkTests — verify that
    /// cumulative chain work from block 849134 plus 3 blocks of work at
    /// nBits=0x17035d25 equals the known chain work at block 849137.
    #[test]
    fn rskj_chain_work_accumulation_849134_to_849137() {
        let cw_849134 = U256::from_str_radix(
            "7ffef81fa11393037c9df17b", 16
        ).unwrap();
        let cw_849137 = U256::from_str_radix(
            "7fffdc6f043e4a69ea179a7a", 16
        ).unwrap();

        // All blocks 849135-849137 have same nBits
        let bits = CompactTarget::from_consensus(0x17035d25);
        let work_per_block = compute_work(bits);
        assert!(work_per_block > U256::ZERO);

        // 849134 + 3 blocks of work should equal 849137
        let computed_cw_849137 = cw_849134 + U256::from(3) * work_per_block;
        assert_eq!(
            computed_cw_849137, cw_849137,
            "chain work accumulation 849134→849137 mismatch"
        );
    }

    /// Verify auto-detect correctly identifies legacy vs V2 format for
    /// a real mainnet header.
    #[test]
    fn rskj_auto_detect_format_mainnet() {
        let header = parse_mainnet_header();
        let block = StoredBlock::new(header, 849_137, U256::from(42u64));

        let legacy_data = block.serialize_compact_legacy();
        let v2_data = block.serialize_compact_v2();

        let from_legacy = StoredBlock::deserialize_compact(&legacy_data).unwrap();
        let from_v2 = StoredBlock::deserialize_compact(&v2_data).unwrap();

        assert_eq!(from_legacy.height, from_v2.height);
        assert_eq!(from_legacy.chain_work, from_v2.chain_work);
        assert_eq!(from_legacy.block_hash(), from_v2.block_hash());
    }
}
