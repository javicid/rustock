use alloy_primitives::U256;

/// Hardfork activation heights for a given network.
/// A value of `u64::MAX` means "not yet activated".
#[derive(Clone, Debug)]
pub struct ActivationHeights {
    /// Orchid hardfork – enables RSKIP92/98 (merged mining PoW, no 10-min reset).
    pub orchid: u64,
    /// Papyrus200 hardfork – enables RSKIP156 (difficulty divisor 50 -> 400).
    pub papyrus200: u64,
}

impl ActivationHeights {
    pub fn mainnet() -> Self {
        Self {
            orchid: 729_000,
            papyrus200: 2_392_700,
        }
    }

    pub fn testnet() -> Self {
        Self {
            orchid: 0,
            papyrus200: 0,
        }
    }

    pub fn regtest() -> Self {
        // Regtest: orchid is active from genesis, but RSKIP156 (papyrus200)
        // is explicitly excluded for regtest in rskj (keeps divisor at 50).
        Self {
            orchid: 0,
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
}
