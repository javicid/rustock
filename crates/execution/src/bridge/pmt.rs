//! Partial Merkle Tree (PMT) implementation for BTC transaction inclusion proofs.
//!
//! Implements BIP37 merkleblock encoding, matching bitcoinj-thin's
//! `PartialMerkleTree` used by rskj. The PMT proves that a set of
//! transactions are included in a BTC block's merkle tree.
//!
//! ## Wire format
//!
//! ```text
//! [tx_count: u32 LE][nHashes: varint][hashes: 32*nHashes bytes]
//! [nFlagBytes: varint][flag_bits: nFlagBytes bytes]
//! ```
//!
//! Hashes are in depth-first traversal order. Flag bits (LSB first per byte)
//! indicate whether each node is a "parent of match" (recurse deeper) or a
//! leaf/hash boundary.

use bitcoin::hashes::{sha256d, Hash};

/// A parsed Partial Merkle Tree.
#[derive(Debug)]
pub struct PartialMerkleTree {
    pub tx_count: u32,
    hashes: Vec<[u8; 32]>,
    flag_bits: Vec<bool>,
}

/// Result of PMT verification: merkle root + list of matched tx hashes.
#[derive(Debug)]
pub struct PmtResult {
    pub merkle_root: [u8; 32],
    pub matched_hashes: Vec<[u8; 32]>,
}

impl PartialMerkleTree {
    /// Parse a PMT from its serialized form.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        // tx_count: u32 LE
        let tx_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut offset = 4;

        // nHashes: varint
        let (n_hashes, varint_len) = read_varint(&data[offset..])?;
        offset += varint_len;

        // hashes: 32 * nHashes bytes
        let n_hashes = n_hashes as usize;
        let mut hashes = Vec::with_capacity(n_hashes);
        for _ in 0..n_hashes {
            if offset + 32 > data.len() {
                return None;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            hashes.push(hash);
            offset += 32;
        }

        // nFlagBytes: varint
        let (n_flag_bytes, varint_len) = read_varint(&data[offset..])?;
        offset += varint_len;

        // flag_bits: nFlagBytes bytes
        let n_flag_bytes = n_flag_bytes as usize;
        if offset + n_flag_bytes > data.len() {
            return None;
        }

        let mut flag_bits = Vec::with_capacity(n_flag_bytes * 8);
        for i in 0..n_flag_bytes {
            let byte = data[offset + i];
            for bit in 0..8 {
                flag_bits.push((byte >> bit) & 1 == 1);
            }
        }

        Some(Self {
            tx_count,
            hashes,
            flag_bits,
        })
    }

    /// Validate the expected size of PMT serialized data.
    pub fn has_expected_size(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        let mut offset = 4;

        let (n_hashes, varint_len) = match read_varint(&data[offset..]) {
            Some(v) => v,
            None => return false,
        };
        offset += varint_len;
        let hash_bytes = (n_hashes as usize).checked_mul(32);
        offset = match hash_bytes.and_then(|hb| offset.checked_add(hb)) {
            Some(o) => o,
            None => return false,
        };

        if offset > data.len() {
            return false;
        }

        let (n_flag_bytes, varint_len) = match read_varint(&data[offset..]) {
            Some(v) => v,
            None => return false,
        };
        offset = match offset.checked_add(varint_len).and_then(|o| o.checked_add(n_flag_bytes as usize)) {
            Some(o) => o,
            None => return false,
        };

        offset == data.len()
    }

    /// Extract matched transaction hashes and compute the merkle root.
    ///
    /// Returns `None` if the tree is invalid (malformed bits/hashes, or
    /// the structure doesn't match tx_count).
    pub fn extract_matches(&self) -> Option<PmtResult> {
        if self.tx_count == 0 {
            return None;
        }
        if self.hashes.len() > self.tx_count as usize {
            return None;
        }

        let height = tree_height(self.tx_count);

        let mut bits_used = 0usize;
        let mut hashes_used = 0usize;
        let mut matched = Vec::new();

        let root = self.recursive_extract(
            height,
            0,
            &mut bits_used,
            &mut hashes_used,
            &mut matched,
        )?;

        // Verify all hashes and bits were consumed
        if hashes_used != self.hashes.len() {
            return None;
        }
        // Allow unused padding bits in the last byte
        let used_bytes = bits_used.div_ceil(8);
        let total_bytes = self.flag_bits.len().div_ceil(8);
        if used_bytes != total_bytes {
            return None;
        }

        Some(PmtResult {
            merkle_root: root,
            matched_hashes: matched,
        })
    }

    fn recursive_extract(
        &self,
        height: u32,
        pos: u32,
        bits_used: &mut usize,
        hashes_used: &mut usize,
        matched: &mut Vec<[u8; 32]>,
    ) -> Option<[u8; 32]> {
        if *bits_used >= self.flag_bits.len() {
            return None;
        }
        let parent_of_match = self.flag_bits[*bits_used];
        *bits_used += 1;

        if height == 0 || !parent_of_match {
            // Leaf or non-matching subtree: consume one hash
            if *hashes_used >= self.hashes.len() {
                return None;
            }
            let hash = self.hashes[*hashes_used];
            *hashes_used += 1;

            if height == 0 && parent_of_match {
                matched.push(hash);
            }

            return Some(hash);
        }

        // Internal node that is parent of a match: recurse
        let left = self.recursive_extract(height - 1, pos * 2, bits_used, hashes_used, matched)?;

        let right = if pos * 2 + 1 < tree_width(self.tx_count, height - 1) {
            let r = self.recursive_extract(
                height - 1,
                pos * 2 + 1,
                bits_used,
                hashes_used,
                matched,
            )?;
            // Left and right must differ (protection against 64-byte tx attack)
            if left == r {
                return None;
            }
            r
        } else {
            left
        };

        Some(combine_hashes(&left, &right))
    }
}

/// Combine two 32-byte hashes for the Bitcoin merkle tree.
///
/// Matches rskj's `MerkleTreeUtils.combineLeftRight`: hashes are stored in
/// "display" (big-endian) order, so they must be reversed to "internal"
/// (little-endian/wire) order before concatenation and double-SHA256, then
/// the result is reversed back to display order.
fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut rev_left = *left;
    rev_left.reverse();
    let mut rev_right = *right;
    rev_right.reverse();

    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&rev_left);
    combined[32..].copy_from_slice(&rev_right);

    let hash = sha256d::Hash::hash(&combined);
    let mut result = *hash.as_byte_array();
    result.reverse();
    result
}

/// Compute tree height from transaction count.
fn tree_height(tx_count: u32) -> u32 {
    let mut height = 0u32;
    let mut size = tx_count;
    while size > 1 {
        height += 1;
        size = size.div_ceil(2);
    }
    height
}

/// Compute tree width at a given height.
fn tree_width(tx_count: u32, height: u32) -> u32 {
    (tx_count + (1 << height) - 1) >> height
}

/// Read a Bitcoin varint from a byte slice.
/// Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0..=0xFC => Some((data[0] as u64, 1)),
        0xFD => {
            if data.len() < 3 {
                return None;
            }
            let val = u16::from_le_bytes([data[1], data[2]]);
            Some((val as u64, 3))
        }
        0xFE => {
            if data.len() < 5 {
                return None;
            }
            let val = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            Some((val as u64, 5))
        }
        0xFF => {
            if data.len() < 9 {
                return None;
            }
            let val = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            Some((val, 9))
        }
    }
}

// ---------------------------------------------------------------------------
// Merkle Branch (for getBtcTransactionConfirmations)
// ---------------------------------------------------------------------------

/// A Merkle branch proof: list of sibling hashes + path bits.
///
/// Matches rskj's `MerkleBranch`. The `path` integer encodes which side
/// the target hash is on at each level (bit i: 0 = left, 1 = right).
#[derive(Debug)]
pub struct MerkleBranch {
    pub hashes: Vec<[u8; 32]>,
    pub path: u32,
}

impl MerkleBranch {
    /// Parse from ABI-encoded arguments:
    /// `(bytes32 btcTxHash, bytes32 btcBlockHash, uint256 merkleBranchPath, bytes32[] merkleBranchHashes)`
    ///
    /// The path and hashes are at offsets 64..96 and 96+, respectively.
    pub fn from_abi_args(args: &[u8]) -> Option<(Self, [u8; 32], [u8; 32])> {
        if args.len() < 128 {
            return None;
        }

        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&args[0..32]);

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&args[32..64]);

        let path = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&args[64..96]);
            u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]])
        };

        // Dynamic array offset
        let array_offset = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&args[96..128]);
            u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]) as usize
        };

        if array_offset + 32 > args.len() {
            return None;
        }

        let count = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&args[array_offset..array_offset + 32]);
            u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]) as usize
        };

        let mut hashes = Vec::with_capacity(count);
        let data_start = array_offset + 32;
        for i in 0..count {
            let offset = data_start + i * 32;
            if offset + 32 > args.len() {
                return None;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&args[offset..offset + 32]);
            hashes.push(h);
        }

        let branch = MerkleBranch { hashes, path };
        Some((branch, tx_hash, block_hash))
    }

    /// Reduce the branch from a given tx hash to compute the merkle root.
    pub fn reduce_from(&self, tx_hash: &[u8; 32]) -> [u8; 32] {
        let mut current = *tx_hash;

        for (i, sibling) in self.hashes.iter().enumerate() {
            let is_right = (self.path >> i) & 1 == 1;
            if is_right {
                current = combine_hashes(sibling, &current);
            } else {
                current = combine_hashes(&current, sibling);
            }
        }

        current
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_height_one_tx() {
        assert_eq!(tree_height(1), 0);
    }

    #[test]
    fn tree_height_two_tx() {
        assert_eq!(tree_height(2), 1);
    }

    #[test]
    fn tree_height_three_tx() {
        assert_eq!(tree_height(3), 2);
    }

    #[test]
    fn tree_height_four_tx() {
        assert_eq!(tree_height(4), 2);
    }

    #[test]
    fn tree_width_single() {
        assert_eq!(tree_width(1, 0), 1);
    }

    #[test]
    fn tree_width_two_at_level_zero() {
        assert_eq!(tree_width(2, 0), 2);
        assert_eq!(tree_width(2, 1), 1);
    }

    #[test]
    fn tree_width_three() {
        assert_eq!(tree_width(3, 0), 3);
        assert_eq!(tree_width(3, 1), 2);
        assert_eq!(tree_width(3, 2), 1);
    }

    #[test]
    fn varint_single_byte() {
        assert_eq!(read_varint(&[0x00]), Some((0, 1)));
        assert_eq!(read_varint(&[0x01]), Some((1, 1)));
        assert_eq!(read_varint(&[0xFC]), Some((252, 1)));
    }

    #[test]
    fn varint_two_bytes() {
        assert_eq!(read_varint(&[0xFD, 0xFD, 0x00]), Some((253, 3)));
        assert_eq!(read_varint(&[0xFD, 0xFF, 0xFF]), Some((65535, 3)));
    }

    #[test]
    fn has_expected_size_rejects_short() {
        assert!(!PartialMerkleTree::has_expected_size(&[]));
        assert!(!PartialMerkleTree::has_expected_size(&[0, 0, 0]));
    }

    #[test]
    fn simple_pmt_single_tx() {
        // PMT for a block with 1 transaction (the tx itself is matched)
        // tx_count=1, nHashes=1, hash=all-zeros, nFlagBytes=1, flags=0x01
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // tx_count
        data.push(1); // nHashes (varint)
        data.extend_from_slice(&[0xAA; 32]); // hash
        data.push(1); // nFlagBytes (varint)
        data.push(0x01); // flag bits: bit 0 = 1 (matched)

        assert!(PartialMerkleTree::has_expected_size(&data));

        let pmt = PartialMerkleTree::parse(&data).unwrap();
        assert_eq!(pmt.tx_count, 1);

        let result = pmt.extract_matches().unwrap();
        assert_eq!(result.matched_hashes.len(), 1);
        assert_eq!(result.matched_hashes[0], [0xAA; 32]);
        assert_eq!(result.merkle_root, [0xAA; 32]);
    }

    #[test]
    fn combine_hashes_deterministic() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        let result = combine_hashes(&a, &b);
        // Same inputs should always produce same output
        assert_eq!(result, combine_hashes(&a, &b));
        // Different order should produce different result
        assert_ne!(result, combine_hashes(&b, &a));
    }

    #[test]
    fn merkle_branch_reduce_single() {
        let tx_hash = [0x42; 32];
        let sibling = [0x43; 32];
        let branch = MerkleBranch {
            hashes: vec![sibling],
            path: 0, // tx is on the left
        };
        let root = branch.reduce_from(&tx_hash);
        assert_eq!(root, combine_hashes(&tx_hash, &sibling));
    }

    #[test]
    fn merkle_branch_reduce_right_side() {
        let tx_hash = [0x42; 32];
        let sibling = [0x43; 32];
        let branch = MerkleBranch {
            hashes: vec![sibling],
            path: 1, // tx is on the right
        };
        let root = branch.reduce_from(&tx_hash);
        assert_eq!(root, combine_hashes(&sibling, &tx_hash));
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj
    // -----------------------------------------------------------------------

    /// Ported from rskj PartialMerkleTreeFormatUtilsTest.getHashesCount
    /// and getFlagBitsCount — canonical PMT blob from rskj test suite.
    #[test]
    fn rskj_pmt_canonical_blob_parse() {
        let data = hex_to_bytes(
            "030000000279e7c0da739df8a00f12c0bff55e5438f530aa5859ff98\
             74258cd7bad3fe709746aff897e6a851faa80120d6ae99db30883699\
             ac0428fc7192d6c3fec0ca6409010d"
        );

        // rskj expects: 2 hashes, 1 flag byte, valid size
        assert!(PartialMerkleTree::has_expected_size(&data));

        let pmt = PartialMerkleTree::parse(&data).unwrap();
        assert_eq!(pmt.tx_count, 3); // LE 03000000 = 3
        assert_eq!(pmt.hashes.len(), 2);
        assert_eq!(pmt.flag_bits.len(), 8); // 1 flag byte = 8 bits
    }

    /// Ported from rskj PartialMerkleTreeFormatUtilsTest.doesntHaveExpectedSize
    #[test]
    fn rskj_pmt_invalid_size_rejected() {
        // Truncated/wrong tail (from rskj: ending in "64010d")
        let data = hex_to_bytes(
            "030000000279e7c0da739df8a00f12c0bff55e5438f530aa5859ff98\
             74258cd7bad3fe709746aff897e6a851faa80120d6ae99db30883699\
             ac0428fc7192d6c3fec0ca64010d"
        );
        assert!(!PartialMerkleTree::has_expected_size(&data));
    }

    /// Ported from rskj MerkleBranchTest.oneHashBranch
    /// assertBranchCorrectlyProves(hashes, path, txHash, expectedMerkleRoot)
    #[test]
    fn rskj_merkle_branch_one_hash() {
        let h1 = hex_to_32("3709934297f8bfd8a1cfcf82514bbfdcc910cf4d934e0eabd58b6eb955954b45");
        let tx_hash = hex_to_32("444f6714a6010b452d705531fb9ed850f2578ef28c364676d7e9f3f436c25554");
        let expected_root = hex_to_32("71306e0f38f1f606d7a4eadf22814432321b2a6d6f40c94fdc8e7dd2bbcef47f");

        let branch = MerkleBranch {
            hashes: vec![h1],
            path: 1,
        };
        let root = branch.reduce_from(&tx_hash);
        assert_eq!(root, expected_root, "rskj oneHashBranch root mismatch");
    }

    /// Ported from rskj MerkleBranchTest.twoHashesBranch
    #[test]
    fn rskj_merkle_branch_two_hashes() {
        let h1 = hex_to_32("bfc0770be0c8bc9d06714b00c89cc769286968c28632aa7768f9525a0287d5e6");
        let h2 = hex_to_32("ad13c3242a67436e8958c0b1a76ff017d1e0c36ab7b38b98d7fb3df9ebea2bff");
        let tx_hash = hex_to_32("9f4c1131e3dfab1b0413f97d53cab183f48f4ed0003387e7cbadea0c1f4ce365");
        let expected_root = hex_to_32("14fd0a443ebba0fe62e323b5250fb13042e7840701058fb025032f1527f8f6f5");

        let branch = MerkleBranch {
            hashes: vec![h1, h2],
            path: 3,
        };
        let root = branch.reduce_from(&tx_hash);
        assert_eq!(root, expected_root, "rskj twoHashesBranch root mismatch");
    }

    /// Ported from rskj MerkleBranchTest.threeHashesBranch
    #[test]
    fn rskj_merkle_branch_three_hashes() {
        let h1 = hex_to_32("81aa2c77c201daab3868da9a4c2e29bc1e42bdc804c7c8a4d84c5e7f3866fb3f");
        let h2 = hex_to_32("bed5ecce0c0ffa58236271d4ca49767c968fb6aba6aa3c10abe31170ca826404");
        let h3 = hex_to_32("f733ca23def34db37b79af4c65d5929be741b79a1d74006153892b87487d1137");
        let tx_hash = hex_to_32("807d74e37d9c39a315eb74955889c9be83ba33eaaf9735a9617211870cde22b2");
        let expected_root = hex_to_32("f7f0eb7ba33dd6f37ad11153d1bc803cd6f932051d72fa73343bff59d270e9ef");

        let branch = MerkleBranch {
            hashes: vec![h1, h2, h3],
            path: 5,
        };
        let root = branch.reduce_from(&tx_hash);
        assert_eq!(root, expected_root, "rskj threeHashesBranch root mismatch");
    }

    /// Ported from rskj MerkleBranchTest.threeHashesBranchBis (alternate leaf)
    #[test]
    fn rskj_merkle_branch_three_hashes_bis() {
        let h1 = hex_to_32("807d74e37d9c39a315eb74955889c9be83ba33eaaf9735a9617211870cde22b2");
        let h2 = hex_to_32("bed5ecce0c0ffa58236271d4ca49767c968fb6aba6aa3c10abe31170ca826404");
        let h3 = hex_to_32("f733ca23def34db37b79af4c65d5929be741b79a1d74006153892b87487d1137");
        let tx_hash = hex_to_32("81aa2c77c201daab3868da9a4c2e29bc1e42bdc804c7c8a4d84c5e7f3866fb3f");
        let expected_root = hex_to_32("f7f0eb7ba33dd6f37ad11153d1bc803cd6f932051d72fa73343bff59d270e9ef");

        let branch = MerkleBranch {
            hashes: vec![h1, h2, h3],
            path: 4,
        };
        let root = branch.reduce_from(&tx_hash);
        assert_eq!(root, expected_root, "rskj threeHashesBranchBis root mismatch");
    }

    /// Ported from rskj MerkleBranchTest.threeHashesBranchFailsIfPathIsWrong
    #[test]
    fn rskj_merkle_branch_wrong_path() {
        let h1 = hex_to_32("807d74e37d9c39a315eb74955889c9be83ba33eaaf9735a9617211870cde22b2");
        let h2 = hex_to_32("bed5ecce0c0ffa58236271d4ca49767c968fb6aba6aa3c10abe31170ca826404");
        let h3 = hex_to_32("f733ca23def34db37b79af4c65d5929be741b79a1d74006153892b87487d1137");
        let tx_hash = hex_to_32("81aa2c77c201daab3868da9a4c2e29bc1e42bdc804c7c8a4d84c5e7f3866fb3f");
        let expected_root = hex_to_32("f7f0eb7ba33dd6f37ad11153d1bc803cd6f932051d72fa73343bff59d270e9ef");

        let branch = MerkleBranch {
            hashes: vec![h1, h2, h3],
            path: 3, // wrong path
        };
        let root = branch.reduce_from(&tx_hash);
        assert_ne!(root, expected_root, "Wrong path should produce different root");
    }

    /// Ported from rskj MerkleTreeUtilsTest.combineLeftRight — 3 vectors from
    /// bitcoind regtest (two-transaction blocks).
    #[test]
    fn rskj_combine_left_right_vector_1() {
        let left  = hex_to_32("b945b008fbc3f357db745909958b570773fc14575a36af8bbc195b484e21f366");
        let right = hex_to_32("9880f57b6735152a8c6d4c7e1b3bc6434ee75e459511a642bbb8cb71d3a6b6d8");
        let expected = hex_to_32("ceea4835dd23fae1978a3f6f3f0aa0171e018360272dd5b98d37550fbc978d01");
        assert_eq!(combine_hashes(&left, &right), expected, "rskj combineLeftRight vector 1");
    }

    #[test]
    fn rskj_combine_left_right_vector_2() {
        let left  = hex_to_32("083eafdf670bb1bbc83b63262887e3cf519c3e252fac29adfb92c1e857b37f91");
        let right = hex_to_32("5740915e973a211c71655d10e4c672301c27c287843dcfa97b7aafc04992ec5e");
        let expected = hex_to_32("107857d7233c41d4c37ecaa9ad9d9ab15371f643074866cd23d657e6e99676be");
        assert_eq!(combine_hashes(&left, &right), expected, "rskj combineLeftRight vector 2");
    }

    #[test]
    fn rskj_combine_left_right_vector_3() {
        let left  = hex_to_32("c960ed36a67318cd562d384bfbf41499db1312835e2bfe86805d9465afe9736f");
        let right = hex_to_32("120196be3b0ca6ba07d3cfee53f8dc883781e82afdfba11181184f41a67b9898");
        let expected = hex_to_32("71a12c9bd54735864dd6e12640e6d00d60a42a2e92e4cd0bde3f9f268b7d4345");
        assert_eq!(combine_hashes(&left, &right), expected, "rskj combineLeftRight vector 3");
    }

    /// Ported from rskj PartialMerkleTreeFormatUtilsTest.overflowSize
    #[test]
    fn rskj_pmt_overflow_size() {
        let data = hex_to_bytes(
            "0300ffffff79e7c0da739df8a00f12c0bff55e5438f530aa5859ff98\
             74258cd7bad3fe709746aff897e6a851faa80120d6ae99db30883699\
             ac0428fc7192d6c3fec0ca6409010d"
        );
        // In rskj this throws ArithmeticException due to overflow in hash count.
        // Our parser should either reject it or fail to parse.
        assert!(!PartialMerkleTree::has_expected_size(&data) || PartialMerkleTree::parse(&data).is_none());
    }

    // Test helpers
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.replace(|c: char| c.is_whitespace(), "");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_32(hex: &str) -> [u8; 32] {
        let bytes = hex_to_bytes(hex);
        assert_eq!(bytes.len(), 32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    }
}
