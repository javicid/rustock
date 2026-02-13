use alloy_primitives::U256;

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
}

impl ChainConfig {
    pub fn mainnet() -> Self {
        Self {
            chain_id: 30,
            network_id: 775,
            duration_limit: 14,
            difficulty_divisor: U256::from(50),
            min_difficulty: U256::from(131072),
            max_future_block_time: 540,
            gas_limit_bound_divisor: 1024,
            min_gas_limit: 5000,
            max_gas_limit: 1_000_000_000,
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
        }
    }
}
