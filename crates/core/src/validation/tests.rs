use super::*;
use crate::types::header::Header;
use alloy_primitives::{Address, B256, U256, Bytes};
use bitcoin::consensus::Encodable;
use bitcoin::{MerkleBlock, ScriptBuf};
use bitcoin::block::Header as BtcHeader;
use bitcoin::transaction::{Transaction as BtcTransaction, TxOut, TxIn, OutPoint, Version};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytes;

fn create_dummy_header(number: u64, timestamp: u64, parent_hash: B256) -> Header {
    Header {
        parent_hash,
        ommers_hash: B256::ZERO,
        beneficiary: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: B256::ZERO,
        receipts_root: B256::ZERO,
        logs_bloom: Default::default(),
        extension_data: None,
        difficulty: U256::ZERO,
        number,
        gas_limit: U256::from(10_000_000),
        gas_used: 0,
        timestamp,
        extra_data: Bytes::default(),
        paid_fees: U256::ZERO,
        minimum_gas_price: U256::ZERO,
        uncle_count: 0,
        umm_root: None,
        bitcoin_merged_mining_header: None,
        bitcoin_merged_mining_merkle_proof: None,
        bitcoin_merged_mining_coinbase_transaction: None,
        cached_hash: None,
    }
}

/// Helper to build valid Merged Mining proof data for testing.
fn build_mm_proof(header: &Header, btc_bits: u32, rsk_tag_hash: Option<B256>) -> (Bytes, Bytes, Bytes) {
    let rsk_tag_hash = rsk_tag_hash.unwrap_or_else(|| header.get_hash_for_merged_mining());
    let mut rsk_tag = b"RSKBLOCK:".to_vec();
    rsk_tag.extend_from_slice(rsk_tag_hash.as_slice());
    
    let pb: &PushBytes = rsk_tag.as_slice().try_into().unwrap();
    let coinbase_tx = BtcTransaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(), 
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(pb),
        }],
    };
    
    let mut coinbase_bytes = Vec::new();
    coinbase_tx.consensus_encode(&mut coinbase_bytes).unwrap();

    let btc_header = BtcHeader {
        version: bitcoin::block::Version::from_consensus(1),
        prev_blockhash: bitcoin::BlockHash::all_zeros(),
        merkle_root: coinbase_tx.compute_txid().into(),
        time: 1000,
        bits: bitcoin::CompactTarget::from_consensus(btc_bits), 
        nonce: 0,
    };
    
    let mut btc_header_bytes = Vec::new();
    btc_header.consensus_encode(&mut btc_header_bytes).unwrap();

    let txids = vec![coinbase_tx.compute_txid()];
    let merkle_block = MerkleBlock::from_header_txids_with_predicate(&btc_header, &txids, |_| true);
    
    let mut merkle_bytes = Vec::new();
    merkle_block.consensus_encode(&mut merkle_bytes).unwrap();

    (Bytes::from(btc_header_bytes), Bytes::from(coinbase_bytes), Bytes::from(merkle_bytes))
}

#[test]
fn test_block_number_rule() {
    let parent = create_dummy_header(10, 100, B256::ZERO);
    let rule = BlockNumberRule;
    
    let header = create_dummy_header(11, 101, parent.hash());
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    let header = create_dummy_header(12, 101, parent.hash());
    assert!(rule.validate_with_parent(&header, &parent).is_err());
}

#[test]
fn test_parent_hash_rule() {
    let parent = create_dummy_header(10, 100, B256::ZERO);
    let rule = ParentHashRule;
    let parent_hash = parent.hash();
    
    let header = create_dummy_header(11, 101, parent_hash);
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    let header = create_dummy_header(11, 101, B256::repeat_byte(0x99));
    assert!(rule.validate_with_parent(&header, &parent).is_err());
}

#[test]
fn test_timestamp_rule() {
    let parent = create_dummy_header(10, 1000, B256::ZERO);
    let rule = TimestampRule::new(15);
    
    let header = create_dummy_header(11, 1001, parent.hash());
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    let header = create_dummy_header(11, 999, parent.hash());
    assert!(matches!(rule.validate_with_parent(&header, &parent), Err(ValidationError::TimestampOlderThanParent { .. })));
}

#[test]
fn test_gas_used_rule() {
    let rule = GasUsedRule;
    let mut header = create_dummy_header(10, 100, B256::ZERO);
    header.gas_limit = U256::from(100);
    
    header.gas_used = 90;
    assert!(rule.validate(&header).is_ok());
    
    header.gas_used = 110;
    assert!(matches!(rule.validate(&header), Err(ValidationError::GasUsedExceedsLimit { .. })));
}

#[test]
fn test_header_verifier() {
    let mut verifier = HeaderVerifier::new();
    verifier = verifier.with_static_rule(GasUsedRule);
    verifier = verifier.with_parent_rule(BlockNumberRule);
    
    let parent = create_dummy_header(10, 100, B256::ZERO);
    let mut header = create_dummy_header(11, 101, parent.hash());
    header.gas_limit = U256::from(100);
    header.gas_used = 50;
    
    // Fully valid
    assert!(verifier.verify(&header, Some(&parent)).is_ok());
    
    // Static rule fails
    header.gas_used = 150;
    assert!(verifier.verify(&header, Some(&parent)).is_err());
    header.gas_used = 50;
    
    // Parent rule fails
    header.number = 15;
    assert!(verifier.verify(&header, Some(&parent)).is_err());
}

#[test]
fn test_difficulty_rule() {
    let config = crate::config::ChainConfig::regtest();
    let rule = DifficultyRule { config: config.clone() };
    
    let mut parent = create_dummy_header(10, 1000, B256::ZERO);
    parent.difficulty = U256::from(20480);
    
    // Scenario 1: Quick block (delta < duration_limit) -> increase difficulty
    let mut header = create_dummy_header(11, 1005, parent.hash());
    header.difficulty = U256::from(20480 + (20480 / 2048));
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    // Scenario 2: Slow block (delta > duration_limit) -> decrease difficulty
    let mut header = create_dummy_header(11, 1015, parent.hash());
    header.difficulty = U256::from(20480 - (20480 / 2048));
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_gas_limit_rule() {
    let config = crate::config::ChainConfig::regtest();
    let rule = BlockParentGasLimitRule { config };
    
    let mut parent = create_dummy_header(10, 1000, B256::ZERO);
    parent.gas_limit = U256::from(102400); 
    
    let mut header = create_dummy_header(11, 1010, parent.hash());
    header.gas_limit = U256::from(102400);
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    header.gas_limit = U256::from(102500);
    assert!(rule.validate_with_parent(&header, &parent).is_ok());
    
    header.gas_limit = U256::from(102501);
    assert!(rule.validate_with_parent(&header, &parent).is_err());
}

#[test]
fn test_merged_mining_rule_success() {
    let config = crate::config::ChainConfig::regtest();
    let rule = MergedMiningRule { config };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::from(1);
    
    let (btc_h, btc_cb, btc_m) = build_mm_proof(&header, 0x207fffff, None);
    header.bitcoin_merged_mining_header = Some(btc_h);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    header.bitcoin_merged_mining_merkle_proof = Some(btc_m);
    
    assert!(rule.validate(&header).is_ok());
}

#[test]
fn test_merged_mining_rule_invalid_pow() {
    let config = crate::config::ChainConfig::regtest();
    let rule = MergedMiningRule { config };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::MAX; 
    
    let (btc_h, btc_cb, btc_m) = build_mm_proof(&header, 0x207fffff, None);
    header.bitcoin_merged_mining_header = Some(btc_h);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    header.bitcoin_merged_mining_merkle_proof = Some(btc_m);
    
    let res = rule.validate(&header);
    assert!(matches!(res, Err(ValidationError::BitcoinPowInvalid { .. })));
}

#[test]
fn test_merged_mining_rule_invalid_merkle() {
    let config = crate::config::ChainConfig::regtest();
    let rule = MergedMiningRule { config };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::from(1);
    
    let (btc_h, btc_cb, _) = build_mm_proof(&header, 0x207fffff, None);
    header.bitcoin_merged_mining_header = Some(btc_h);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    header.bitcoin_merged_mining_merkle_proof = Some(Bytes::from(vec![0u8; 64])); 
    
    let res = rule.validate(&header);
    assert!(matches!(res, Err(ValidationError::BitcoinMerkleProofInvalid)));
}

#[test]
fn test_merged_mining_rule_wrong_tag() {
    let config = crate::config::ChainConfig::regtest();
    let rule = MergedMiningRule { config };
    let mut header = create_dummy_header(10, 1000, B256::ZERO);
    header.difficulty = U256::from(1);
    
    let (btc_h, btc_cb, btc_m) = build_mm_proof(&header, 0x207fffff, Some(B256::repeat_byte(0xee)));
    header.bitcoin_merged_mining_header = Some(btc_h);
    header.bitcoin_merged_mining_coinbase_transaction = Some(btc_cb);
    header.bitcoin_merged_mining_merkle_proof = Some(btc_m);
    
    let res = rule.validate(&header);
    assert!(matches!(res, Err(ValidationError::BitcoinCoinbaseTagInvalid)));
}

// --- Difficulty rule tests (mainnet) ---

#[test]
fn test_difficulty_min_floor_clamping() {
    let config = crate::config::ChainConfig::mainnet();
    let rule = DifficultyRule { config: config.clone() };

    let min_difficulty = U256::from(7_000_000_000_000_000u64); // 7e15
    let mut parent = create_dummy_header(99, 1000, B256::ZERO);
    parent.difficulty = min_difficulty;

    // Slow block: delta = 30s (> 14s duration_limit)
    let mut header = create_dummy_header(100, 1030, parent.hash());
    header.difficulty = min_difficulty;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_difficulty_ten_minute_reset() {
    let config = crate::config::ChainConfig::mainnet();
    let rule = DifficultyRule { config: config.clone() };

    let min_difficulty = U256::from(7_000_000_000_000_000u64);
    let mut parent = create_dummy_header(99, 1000, B256::ZERO);
    parent.difficulty = U256::from(100_000_000_000_000_000u64); // 1e17

    // Delta = 700s (> 600s) -> 10-min reset to min_difficulty (before orchid)
    let mut header = create_dummy_header(100, 1700, parent.hash());
    header.difficulty = min_difficulty;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_difficulty_ten_minute_reset_disabled_after_orchid() {
    let config = crate::config::ChainConfig::mainnet();
    let rule = DifficultyRule { config: config.clone() };

    let mut parent = create_dummy_header(799_999, 1000, B256::ZERO);
    parent.difficulty = U256::from(100_000_000_000_000_000u64); // 1e17

    // Delta = 700s, but orchid active -> no 10-min reset. Slow block with divisor 50.
    // Expected = parent - parent/50 = 98_000_000_000_000_000
    let expected = U256::from(98_000_000_000_000_000u64);
    let mut header = create_dummy_header(800_000, 1700, parent.hash());
    header.difficulty = expected;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_difficulty_rskip156_divisor_change() {
    let config = crate::config::ChainConfig::mainnet();
    let rule = DifficultyRule { config: config.clone() };

    let mut parent = create_dummy_header(2_499_999, 1000, B256::ZERO);
    parent.difficulty = U256::from(100_000_000_000_000_000u64); // 1e17

    // Fast block, papyrus200 active -> divisor 400
    // Expected = parent + parent/400 = 100_250_000_000_000_000
    let expected = U256::from(100_250_000_000_000_000u64);
    let mut header = create_dummy_header(2_500_000, 1005, parent.hash());
    header.difficulty = expected;

    assert!(rule.validate_with_parent(&header, &parent).is_ok());
}

#[test]
fn test_merged_mining_skipped_before_orchid() {
    let config = crate::config::ChainConfig::mainnet();
    let rule = MergedMiningRule { config };

    // Header at block 100 (before orchid=729,000) with NO bitcoin merged mining fields
    let mut header = create_dummy_header(100, 1000, B256::ZERO);
    header.difficulty = U256::from(7_000_000_000_000_000u64);
    // bitcoin_merged_mining_* are None by default in create_dummy_header

    assert!(rule.validate(&header).is_ok());
}

#[test]
fn test_merged_mining_required_after_orchid() {
    let config = crate::config::ChainConfig::mainnet();
    let rule = MergedMiningRule { config };

    // Header at block 800_000 (after orchid) with NO bitcoin merged mining fields
    let mut header = create_dummy_header(800_000, 1000, B256::ZERO);
    header.difficulty = U256::from(7_000_000_000_000_000u64);
    // bitcoin_merged_mining_* are None by default

    let res = rule.validate(&header);
    assert!(res.is_err());
}
