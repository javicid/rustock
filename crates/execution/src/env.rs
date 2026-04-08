/// Block and transaction environment construction for revm.
///
/// Translates RSK block headers and transactions into revm's `BlockEnv`
/// and `TxEnv` structures, accounting for RSK-specific fields like
/// `minimum_gas_price` and merged-mining difficulty.
use alloy_primitives::{Address, B256, Bytes, U256};
use revm::context::{BlockEnv, TxEnv};
use revm::primitives::TxKind;
use revm::primitives::hardfork::SpecId;
use rustock_core::Header;
use crate::hardfork::RskHardforkConfig;
use crate::precompiles::REMASC_ADDR;

/// Build a revm `BlockEnv` from an RSK block header.
///
/// In RSK, transaction fees are credited to the REMASC contract rather than the
/// miner directly. REMASC later distributes rewards with delayed maturity. We
/// set `beneficiary` to `REMASC_ADDR` so revm routes all gas-fee payments to
/// the REMASC account; the actual miner (`header.beneficiary`) is paid later
/// when REMASC runs.
pub fn block_env_from_header(header: &Header, hardfork_cfg: &RskHardforkConfig) -> BlockEnv {
    let spec = hardfork_cfg.spec_id(header.number);
    let prevrandao = if spec.is_enabled_in(SpecId::MERGE) {
        Some(B256::from(header.difficulty.to_be_bytes::<32>()))
    } else {
        None
    };

    BlockEnv {
        number: U256::from(header.number),
        beneficiary: REMASC_ADDR,
        timestamp: U256::from(header.timestamp),
        // RSK stores gas_limit as U256 but revm expects u64
        gas_limit: header.gas_limit.to::<u64>(),
        difficulty: header.difficulty,
        // RSK uses minimum_gas_price instead of EIP-1559 basefee.
        basefee: header.minimum_gas_price.to::<u64>(),
        prevrandao,
        blob_excess_gas_and_price: None,
        ..Default::default()
    }
}

/// Build a revm `TxEnv` from an RSK transaction.
///
/// RSK transactions are legacy-only (no EIP-1559/EIP-2930/EIP-4844).
pub fn tx_env_from_rsk_tx(
    tx: &rustock_core::Transaction,
    sender: Address,
    _hardfork_cfg: &RskHardforkConfig,
) -> TxEnv {
    let kind = if tx.to.is_empty() {
        TxKind::Create
    } else {
        let mut addr_bytes = [0u8; 20];
        let len = tx.to.len().min(20);
        addr_bytes[20 - len..].copy_from_slice(&tx.to[..len]);
        TxKind::Call(Address::from(addr_bytes))
    };

    TxEnv {
        tx_type: 0, // legacy
        caller: sender,
        gas_limit: tx.gas_limit.to::<u64>(),
        gas_price: tx.gas_price.to::<u128>(),
        kind,
        value: tx.value,
        data: Bytes::copy_from_slice(&tx.input),
        nonce: tx.nonce,
        chain_id: None, // RSK legacy transactions may or may not include chain_id in v
        access_list: Default::default(),
        gas_priority_fee: None,
        blob_hashes: Vec::new(),
        max_fee_per_blob_gas: 0,
        authorization_list: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bloom, B256, Bytes as AlBytes};

    fn dummy_header(number: u64) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::repeat_byte(0x01),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(1_000_000),
            number,
            gas_limit: U256::from(6_800_000),
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: AlBytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(59_240_000),
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    #[test]
    fn test_block_env_from_header() {
        let cfg = RskHardforkConfig::mainnet();
        let header = dummy_header(7_500_000);
        let env = block_env_from_header(&header, &cfg);

        assert_eq!(env.number, U256::from(7_500_000u64));
        assert_eq!(env.beneficiary, REMASC_ADDR);
        assert_eq!(env.gas_limit, 6_800_000);
        assert_eq!(env.difficulty, U256::from(1_000_000u64));
        assert_eq!(env.basefee, 59_240_000);
        // Block 7_500_000 is post-Lovell (SHANGHAI), so prevrandao is set to difficulty
        assert_eq!(
            env.prevrandao,
            Some(B256::from(U256::from(1_000_000u64).to_be_bytes::<32>()))
        );
    }

    #[test]
    fn test_block_env_pre_merge_no_prevrandao() {
        let cfg = RskHardforkConfig::mainnet();
        let header = dummy_header(1_000_000); // pre-Papyrus, maps to BYZANTIUM
        let env = block_env_from_header(&header, &cfg);
        assert!(env.prevrandao.is_none());
    }

    #[test]
    fn test_tx_env_call() {
        let cfg = RskHardforkConfig::mainnet();
        let mut to_bytes = vec![0u8; 20];
        to_bytes[19] = 0xAA;
        let tx = rustock_core::Transaction {
            nonce: 5,
            gas_price: U256::from(1_000_000_000u64),
            gas_limit: U256::from(21_000),
            to: AlBytes::from(to_bytes),
            value: U256::from(1_000),
            input: AlBytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let sender = Address::repeat_byte(0xBB);
        let env = tx_env_from_rsk_tx(&tx, sender, &cfg);

        assert_eq!(env.caller, sender);
        assert_eq!(env.nonce, 5);
        assert_eq!(env.gas_limit, 21_000);
        assert_eq!(env.value, U256::from(1_000));
        assert!(matches!(env.kind, TxKind::Call(_)));
    }

    #[test]
    fn test_tx_env_create() {
        let cfg = RskHardforkConfig::mainnet();
        let tx = rustock_core::Transaction {
            nonce: 0,
            gas_price: U256::from(1_000_000_000u64),
            gas_limit: U256::from(100_000),
            to: AlBytes::new(), // empty = contract creation
            value: U256::ZERO,
            input: AlBytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xF3]), // dummy initcode
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        let sender = Address::repeat_byte(0xCC);
        let env = tx_env_from_rsk_tx(&tx, sender, &cfg);

        assert!(matches!(env.kind, TxKind::Create));
        assert_eq!(env.data.len(), 5);
    }
}
