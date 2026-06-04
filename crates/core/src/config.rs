use alloy_primitives::{Address, B256, Bytes, U256, address};

use crate::types::header::Header;

/// Pre-funded account in the genesis state.
#[derive(Debug, Clone)]
pub struct GenesisAlloc {
    pub address: Address,
    pub balance: U256,
    pub nonce: U256,
}

/// Pre-initialized storage entry in the genesis state.
#[derive(Debug, Clone)]
pub struct GenesisStorage {
    pub address: Address,
    pub key: B256,
    pub value: Vec<u8>,
}

/// Hardfork activation heights for a given network.
/// A value of `u64::MAX` means "not yet activated".
#[derive(Clone, Debug)]
pub struct ActivationHeights {
    /// Orchid hardfork – enables RSKIP92/98 (merged mining PoW, no 10-min reset).
    pub orchid: u64,
    /// Wasabi100 hardfork – enables RSKIP110 (fork detection data in merged mining hash).
    pub wasabi100: u64,
    /// Papyrus200 hardfork – enables RSKIP156 (difficulty divisor 50 -> 400).
    pub papyrus200: u64,
}

impl ActivationHeights {
    pub fn mainnet() -> Self {
        Self {
            orchid: 729_000,
            wasabi100: 1_591_000,
            papyrus200: 2_392_700,
        }
    }

    pub fn testnet() -> Self {
        Self {
            orchid: 0,
            wasabi100: 0,
            papyrus200: 0,
        }
    }

    pub fn regtest() -> Self {
        Self {
            orchid: 0,
            wasabi100: 0,
            papyrus200: u64::MAX,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub chain_id: u8,
    pub network_id: u64,
    pub duration_limit: u64,
    pub difficulty_divisor: U256,
    pub min_difficulty: U256,
    pub max_future_block_time: u64,
    pub gas_limit_bound_divisor: u64,
    pub min_gas_limit: u64,
    pub max_gas_limit: u64,
    pub activation_heights: ActivationHeights,
}

impl ChainConfig {
    pub fn mainnet() -> Self {
        Self {
            chain_id: 30,
            network_id: 775,
            duration_limit: 14,
            difficulty_divisor: U256::from(50),
            min_difficulty: U256::from(7_000_000_000_000_000u64), // 7e15, FALLBACK_MINING_DIFFICULTY / 2
            max_future_block_time: 540,
            gas_limit_bound_divisor: 1024,
            min_gas_limit: 5000,
            max_gas_limit: 1_000_000_000,
            activation_heights: ActivationHeights::mainnet(),
        }
    }

    pub fn testnet() -> Self {
        Self {
            chain_id: 31,
            network_id: 8100,
            duration_limit: 14,
            difficulty_divisor: U256::from(50),
            min_difficulty: U256::from(131072),
            max_future_block_time: 540,
            gas_limit_bound_divisor: 1024,
            min_gas_limit: 5000,
            max_gas_limit: 1_000_000_000,
            activation_heights: ActivationHeights::testnet(),
        }
    }

    pub fn regtest() -> Self {
        Self {
            chain_id: 33,
            network_id: 33,
            duration_limit: 10,
            difficulty_divisor: U256::from(2048),
            min_difficulty: U256::from(1),
            max_future_block_time: 0,
            gas_limit_bound_divisor: 1024,
            min_gas_limit: 1,
            max_gas_limit: 10_000_000,
            activation_heights: ActivationHeights::regtest(),
        }
    }

    /// Returns the well-known genesis hash for this network, if one exists.
    /// Mainnet and testnet have hardcoded hashes because Java's RLP encoding
    /// of the genesis difficulty includes a leading zero byte that differs
    /// from standard encoding, producing a different hash.
    pub fn known_genesis_hash(&self) -> Option<B256> {
        match self.chain_id {
            30 => Some("0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0".parse().unwrap()),
            31 => Some("0xcabb7fbe88cd6d922042a32ffc08ce8b1fbb37d650b9d4e7dbfe2a7469adfa42".parse().unwrap()),
            _ => None,
        }
    }

    /// Constructs the genesis header for this network.
    pub fn genesis_header(&self) -> Header {
        let empty_list_hash: B256 = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".parse().unwrap();
        let empty_trie_hash: B256 = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".parse().unwrap();

        match self.chain_id {
            30 => Header {
                parent_hash: B256::ZERO,
                ommers_hash: empty_list_hash,
                beneficiary: "0x3333333333333333333333333333333333333333".parse().unwrap(),
                state_root: "0x9fa70f12726ac738640a86754741bb3f5680520ccc7e6ae9d95ace566a67fe01".parse().unwrap(),
                transactions_root: empty_trie_hash,
                receipts_root: empty_trie_hash,
                logs_bloom: Default::default(),
                extension_data: None,
                difficulty: U256::from(0x00100000),
                number: 0,
                gas_limit: U256::from(0x67c280),
                gas_used: 0,
                timestamp: 0x5a4af5b0,
                extra_data: Bytes::from_static(&hex_literal::hex!("486170707920426974636f696e20446179212030332f4a616e2f32303138202d2052534b20746563686e6f6c6f6779206174207468652073657276696365206f6620736f6369657479")),
                paid_fees: U256::ZERO,
                minimum_gas_price: U256::from(0x0AE85BC0),
                uncle_count: 0,
                umm_root: None,
                bitcoin_merged_mining_header: Some(Bytes::from_static(&[0x00])),
                bitcoin_merged_mining_merkle_proof: Some(Bytes::from_static(&[0x00])),
                bitcoin_merged_mining_coinbase_transaction: Some(Bytes::from_static(&[0x00])),
                cached_hash: None,
                cached_hash_for_merged_mining: None,
            },
            31 => Header {
                parent_hash: B256::ZERO,
                ommers_hash: B256::ZERO,
                beneficiary: Address::ZERO,
                state_root: "0x45bce5168430c42b3d568331753f900a32457b4f3748697cbd8375ff4da72641".parse().unwrap(),
                transactions_root: B256::ZERO,
                receipts_root: B256::ZERO,
                logs_bloom: Default::default(),
                extension_data: None,
                difficulty: U256::from(0x00100000),
                number: 0,
                gas_limit: U256::from(0x4c4b40),
                gas_used: 0,
                timestamp: 0,
                extra_data: Bytes::from_static(&hex_literal::hex!("434d272841")),
                paid_fees: U256::ZERO,
                minimum_gas_price: U256::ZERO,
                uncle_count: 0,
                umm_root: None,
                bitcoin_merged_mining_header: None,
                bitcoin_merged_mining_merkle_proof: None,
                bitcoin_merged_mining_coinbase_transaction: None,
                cached_hash: None,
                cached_hash_for_merged_mining: None,
            },
            _ => Header {
                parent_hash: B256::ZERO,
                ommers_hash: B256::ZERO,
                beneficiary: Address::ZERO,
                state_root: B256::ZERO,
                transactions_root: B256::ZERO,
                receipts_root: B256::ZERO,
                logs_bloom: Default::default(),
                extension_data: None,
                difficulty: U256::from(0x20000),
                number: 0,
                gas_limit: U256::from(10_000_000),
                gas_used: 0,
                timestamp: 0,
                extra_data: Bytes::from("rustock-genesis"),
                paid_fees: U256::ZERO,
                minimum_gas_price: U256::ZERO,
                uncle_count: 0,
                umm_root: None,
                bitcoin_merged_mining_header: None,
                bitcoin_merged_mining_merkle_proof: None,
                bitcoin_merged_mining_coinbase_transaction: None,
                cached_hash: None,
                cached_hash_for_merged_mining: None,
            },
        }
    }

    /// Returns the genesis state allocations for this network.
    ///
    /// For mainnet/testnet, the Bridge contract (0x01000006) is pre-funded with
    /// 21 million RBTC (matching Bitcoin's total supply). This is the only
    /// genesis allocation; all other accounts start empty.
    pub fn genesis_alloc(&self) -> Vec<GenesisAlloc> {
        const BRIDGE: Address = address!("0000000000000000000000000000000001000006");
        // 21_000_000 RBTC = 21_000_000 * 10^18 wei
        let twenty_one_million_rbtc = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));

        match self.chain_id {
            30 | 31 => vec![GenesisAlloc {
                address: BRIDGE,
                balance: twenty_one_million_rbtc,
                nonce: U256::ZERO,
            }],
            _ => vec![],
        }
    }

    /// Returns genesis Bridge storage entries for this network.
    ///
    /// rskj initializes the Bridge with federation data, feePerKb, and
    /// lockingCap at genesis. Without these, Bridge getters return empty
    /// and the first `updateCollections` starts from a blank slate.
    ///
    /// Returns `(slot_key_as_U256, raw_value_bytes)` pairs.
    pub fn genesis_bridge_storage(&self) -> Vec<(U256, Vec<u8>)> {
        match self.chain_id {
            30 | 31 => {
                // Default fee per KB: 10000 satoshis (matching rskj)
                let fee_per_kb_key = bridge_storage_key_ascii("feePerKb");
                let fee_per_kb_value = U256::from(10_000u64);

                // Default locking cap: 21M RBTC in wei
                let locking_cap_key = bridge_storage_key_ascii("lockingCap");
                let locking_cap_value = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));

                vec![
                    (fee_per_kb_key, u256_to_storage_bytes(fee_per_kb_value)),
                    (locking_cap_key, u256_to_storage_bytes(locking_cap_value)),
                ]
            }
            _ => vec![],
        }
    }

    /// Returns the bootstrap node enode URLs for this network.
    pub fn bootnodes(&self) -> Vec<String> {
        match self.chain_id {
            30 => vec![
                "enode://e3a25521354aa99424f5de89cdd2e36aa9b9a96d965d1f7f47d876be0cdbd29c7df327a74170f6a9ea44f54f6ab8ae0dae28e40bb89dbd572a617e2008cfc215@34.203.14.152:5050".into(),
                "enode://f0093935353f94c723a9b67d143ad62464aaf3c959dc05a87f00b637f9c734513493d53f7223633514ea33f2a685878620f0d002cabc05d7f37e6c152774d5da@18.130.226.64:5050".into(),
                "enode://668702f3d526e06b9b9409564f0b09426f84d693444053673c683b5443fa48a39a259c402120409a473a268a2bf62e3d3090ed596d07d1a296ba2925b4260aa7@48.246.52.203:50501".into(),
                "enode://277884485741f237f3f15c7e424263304d9c0205d933ca373302bc6e2468351540f2f7902d33406df77d3419515967b5ae1537243c5b96715f5c9e2b02005470@137.66.19.167:50501".into(),
            ],
            31 => vec![
                "enode://137eb4328a7c2298e26dd15bba4796a7cc30b5097f8a14b384c8dc78caab49fac7a897c39a5a7e87838ac6dc1a80b94891d274a85ac76e7342d66e8a9ed26bf5@snapshot-sync-euw1-1.testnet.rskcomputing.net:50505".into(),
                "enode://fcbfbfce93671320d32ab36ab04ae1564a31892cba219f0a489337aad105dcfc0ebe7d7c2b109d1f4462e8e80588d8ef639b6f321cc1a3f51ec072bed3438105@snapshot-sync-usw2-1.testnet.rskcomputing.net:50505".into(),
            ],
            _ => vec![],
        }
    }
}

/// Encode a short storage key name (≤32 bytes) as rskj's `DataWord.fromString`.
fn bridge_storage_key_ascii(name: &str) -> U256 {
    let bytes = name.as_bytes();
    debug_assert!(bytes.len() <= 32);
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    U256::from_be_bytes(buf)
}

/// Convert a U256 to trimmed big-endian bytes for storage.
fn u256_to_storage_bytes(val: U256) -> Vec<u8> {
    let be = val.to_be_bytes::<32>();
    let start = be.iter().position(|&b| b != 0).unwrap_or(32);
    be[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn test_mainnet_activation_heights() {
        let heights = ActivationHeights::mainnet();
        assert_eq!(heights.orchid, 729_000);
        assert_eq!(heights.wasabi100, 1_591_000);
        assert_eq!(heights.papyrus200, 2_392_700);
    }

    #[test]
    fn test_testnet_activation_heights() {
        let heights = ActivationHeights::testnet();
        assert_eq!(heights.orchid, 0);
        assert_eq!(heights.wasabi100, 0);
        assert_eq!(heights.papyrus200, 0);
    }

    #[test]
    fn test_regtest_activation_heights() {
        let heights = ActivationHeights::regtest();
        assert_eq!(heights.orchid, 0);
        assert_eq!(heights.wasabi100, 0);
        assert_eq!(heights.papyrus200, u64::MAX);
    }

    #[test]
    fn test_mainnet_chain_config() {
        let config = ChainConfig::mainnet();
        assert_eq!(config.chain_id, 30);
        assert_eq!(config.network_id, 775);
        assert_eq!(config.duration_limit, 14);
        assert_eq!(config.difficulty_divisor, U256::from(50));
        assert_eq!(config.min_difficulty, U256::from(7_000_000_000_000_000u64));
    }

    #[test]
    fn test_regtest_chain_config() {
        let config = ChainConfig::regtest();
        assert_eq!(config.chain_id, 33);
        assert_eq!(config.network_id, 33);
        assert_eq!(config.duration_limit, 10);
        assert_eq!(config.difficulty_divisor, U256::from(2048));
        assert_eq!(config.min_difficulty, U256::from(1));
    }

    #[test]
    fn test_mainnet_genesis_header() {
        let config = ChainConfig::mainnet();
        let genesis = config.genesis_header();
        assert_eq!(genesis.number, 0);
        assert_eq!(genesis.parent_hash, B256::ZERO);
        assert_eq!(genesis.difficulty, U256::from(0x00100000));
        assert!(genesis.bitcoin_merged_mining_header.is_some());
    }

    #[test]
    fn test_testnet_genesis_header() {
        let config = ChainConfig::testnet();
        let genesis = config.genesis_header();
        assert_eq!(genesis.number, 0);
        assert_eq!(genesis.difficulty, U256::from(0x00100000));
        assert!(genesis.bitcoin_merged_mining_header.is_none());
    }

    #[test]
    fn test_regtest_genesis_header() {
        let config = ChainConfig::regtest();
        let genesis = config.genesis_header();
        assert_eq!(genesis.number, 0);
        assert_eq!(genesis.difficulty, U256::from(0x20000));
    }

    #[test]
    fn test_known_genesis_hash() {
        let mainnet = ChainConfig::mainnet();
        assert!(mainnet.known_genesis_hash().is_some());

        let testnet = ChainConfig::testnet();
        assert!(testnet.known_genesis_hash().is_some());

        let regtest = ChainConfig::regtest();
        assert!(regtest.known_genesis_hash().is_none());
    }

    #[test]
    fn test_mainnet_bootnodes() {
        let config = ChainConfig::mainnet();
        let nodes = config.bootnodes();
        assert_eq!(nodes.len(), 4);
        assert!(nodes[0].starts_with("enode://"));
    }

    #[test]
    fn test_testnet_bootnodes() {
        let config = ChainConfig::testnet();
        let nodes = config.bootnodes();
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_regtest_bootnodes() {
        let config = ChainConfig::regtest();
        assert!(config.bootnodes().is_empty());
    }

    // -----------------------------------------------------------------------
    // Genesis allocation tests — ported from rskj genesis JSON + GenesisJsonTest
    // -----------------------------------------------------------------------

    /// Ported from rskj rsk-mainnet.json + BridgeSupportIT.
    /// The Bridge (0x01000006) receives exactly 21M RBTC at genesis.
    #[test]
    fn rskj_genesis_bridge_balance_21m() {
        let config = ChainConfig::mainnet();
        let alloc = config.genesis_alloc();

        assert_eq!(alloc.len(), 1, "mainnet genesis should have exactly 1 allocation");

        let bridge = &alloc[0];
        let expected_addr: Address = address!("0000000000000000000000000000000001000006");
        assert_eq!(bridge.address, expected_addr, "allocation should go to Bridge");

        let expected_balance = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));
        assert_eq!(bridge.balance, expected_balance,
            "Bridge should receive 21000000000000000000000000 wei (21M RBTC)");
        assert_eq!(bridge.nonce, U256::ZERO);
    }

    /// Ported from rskj: testnet uses the same 21M alloc.
    #[test]
    fn rskj_genesis_bridge_balance_testnet() {
        let config = ChainConfig::testnet();
        let alloc = config.genesis_alloc();
        assert_eq!(alloc.len(), 1);
        assert_eq!(
            alloc[0].balance,
            U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18))
        );
    }

    /// Regtest has no pre-funded allocations (tests build their own state).
    #[test]
    fn rskj_genesis_regtest_no_alloc() {
        let config = ChainConfig::regtest();
        let alloc = config.genesis_alloc();
        assert!(alloc.is_empty(), "regtest should have no genesis allocations");
    }

    /// Ported from rskj: genesis Bridge storage includes feePerKb and lockingCap.
    #[test]
    fn rskj_genesis_bridge_storage_fee_and_cap() {
        let config = ChainConfig::mainnet();
        let storage = config.genesis_bridge_storage();

        assert_eq!(storage.len(), 2, "should have feePerKb and lockingCap");

        let fee_per_kb_value = U256::from_be_slice(&storage[0].1);
        assert_eq!(fee_per_kb_value, U256::from(10_000u64),
            "feePerKb should be 10000 satoshis");

        let locking_cap_value = U256::from_be_slice(&storage[1].1);
        let expected_cap = U256::from(21_000_000u64) * U256::from(10u64).pow(U256::from(18));
        assert_eq!(locking_cap_value, expected_cap,
            "lockingCap should be 21M RBTC in wei");
    }

    /// Ported from rskj GenesisHashesTest: verify known mainnet genesis hash.
    #[test]
    fn rskj_known_mainnet_genesis_hash() {
        let config = ChainConfig::mainnet();
        let expected: B256 = "0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0".parse().unwrap();
        assert_eq!(config.known_genesis_hash(), Some(expected),
            "mainnet genesis hash must match rskj GenesisHashesTest");
    }

    /// Ported from rskj GenesisHashesTest: verify known testnet genesis hash.
    #[test]
    fn rskj_known_testnet_genesis_hash() {
        let config = ChainConfig::testnet();
        let expected: B256 = "0xcabb7fbe88cd6d922042a32ffc08ce8b1fbb37d650b9d4e7dbfe2a7469adfa42".parse().unwrap();
        assert_eq!(config.known_genesis_hash(), Some(expected),
            "testnet genesis hash must match rskj GenesisHashesTest");
    }
}
