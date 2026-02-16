use super::{HeaderValidator, ValidationError};
use crate::types::header::Header;
use crate::config::ChainConfig;

pub struct MergedMiningRule {
    pub config: std::sync::Arc<ChainConfig>,
}

impl HeaderValidator for MergedMiningRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        use bitcoin::consensus::Decodable;
        use bitcoin::block::Header as BtcHeader;
        use bitcoin::transaction::Transaction as BtcTransaction;
        use bitcoin::MerkleBlock;
        use bitcoin::hashes::Hash;
        use alloy_primitives::{B256, U256};

        // Skip merged mining PoW validation for blocks before the orchid
        // hardfork (RSKIP92/98). Before orchid, fallback mining without
        // proper merged mining fields was allowed.
        if header.number < self.config.activation_heights.orchid {
            return Ok(());
        }

        // 0. Decode fields
        let btc_header_bytes = header.bitcoin_merged_mining_header.as_ref()
            .ok_or(ValidationError::BitcoinHeaderDecodeError)?;
        let mut reader = &btc_header_bytes[..];
        let btc_header: BtcHeader = Decodable::consensus_decode(&mut reader)
            .map_err(|_| ValidationError::BitcoinHeaderDecodeError)?;

        let coinbase_tx_bytes = header.bitcoin_merged_mining_coinbase_transaction.as_ref()
            .ok_or(ValidationError::BitcoinCoinbaseDecodeError)?;
        let mut reader = &coinbase_tx_bytes[..];
        let coinbase_tx: BtcTransaction = Decodable::consensus_decode(&mut reader)
            .map_err(|_| ValidationError::BitcoinCoinbaseDecodeError)?;

        let merkle_proof_bytes = header.bitcoin_merged_mining_merkle_proof.as_ref()
            .ok_or(ValidationError::BitcoinMerkleProofDecodeError)?;
        let mut reader = &merkle_proof_bytes[..];
        let merkle_proof: MerkleBlock = Decodable::consensus_decode(&mut reader)
            .map_err(|_| ValidationError::BitcoinMerkleProofDecodeError)?;

        // 1. Check Bitcoin Header PoW vs RSK Difficulty
        let difficulty = header.difficulty;
        if difficulty.is_zero() {
             return Err(ValidationError::DifficultyZero);
        }

        let target = if difficulty > U256::MAX {
            U256::ZERO
        } else {
            U256::MAX / difficulty
        };

        let btc_hash = btc_header.block_hash();
        let btc_hash_u256 = U256::from_le_slice(btc_hash.as_byte_array());

        if btc_hash_u256 > target {
            return Err(ValidationError::BitcoinPowInvalid {
                hash: B256::from_slice(btc_hash.as_byte_array()),
                target,
            });
        }

        // 2. Validate Merkle Proof
        if merkle_proof.header.block_hash() != btc_header.block_hash() {
             return Err(ValidationError::BitcoinMerkleProofInvalid);
        }

        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        let root = merkle_proof.txn.extract_matches(&mut matches, &mut indexes)
            .map_err(|_| ValidationError::BitcoinMerkleProofInvalid)?;

        if root != btc_header.merkle_root {
            return Err(ValidationError::BitcoinMerkleProofInvalid);
        }

        if matches.is_empty() {
             return Err(ValidationError::BitcoinMerkleProofInvalid);
        }
        
        // The coinbase tx hash must match the first match
        let coinbase_hash = coinbase_tx.compute_txid();
        if matches[0] != coinbase_hash {
             return Err(ValidationError::BitcoinMerkleProofInvalid);
        }

        // 3. Verify RSK Tag in Coinbase
        let rsk_hash = header.hash_for_merged_mining();
        let expected_tag = ["RSKBLOCK:".as_bytes(), rsk_hash.as_slice()].concat();

        let found = coinbase_tx.output.iter().any(|output| {
            output.script_pubkey.is_op_return() && 
            output.script_pubkey.as_bytes().windows(expected_tag.len()).any(|w| w == expected_tag)
        });

        if !found {
            return Err(ValidationError::BitcoinCoinbaseTagInvalid);
        }

        Ok(())
    }
}
