use crate::types::header::Header;
use thiserror::Error;
use alloy_primitives::{B256, U256};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Block number is invalid: expected {expected}, got {got}")]
    InvalidBlockNumber { expected: u64, got: u64 },
    
    #[error("Parent hash mismatch: expected {expected}, got {got}")]
    ParentHashMismatch { expected: String, got: String },
    
    #[error("Timestamp is in the future: current {current}, got {got}")]
    TimestampInFuture { current: u64, got: u64 },
    
    #[error("Timestamp is older than parent: parent {parent}, got {got}")]
    TimestampOlderThanParent { parent: u64, got: u64 },

    #[error("Gas used {used} exceeds gas limit {limit}")]
    GasUsedExceedsLimit { used: u64, limit: u64 },

    #[error("Gas limit {got} out of bounds: [{min}, {max}]")]
    GasLimitOutOfBounds { min: u64, max: u64, got: u64 },

    #[error("Gas limit {got} is invalid compared to parent {parent}")]
    GasLimitInvalid { parent: u64, got: u64 },

    #[error("Difficulty mismatch: expected {expected}, got {got}")]
    DifficultyMismatch { expected: U256, got: U256 },

    #[error("Missing merged mining fields")]
    MissingMergedMiningFields,

    #[error("Bitcoin Proof of Work invalid: hash {hash} exceeds target {target}")]
    BitcoinPowInvalid { hash: B256, target: U256 },

    #[error("Bitcoin Merkle proof invalid")]
    BitcoinMerkleProofInvalid,

    #[error("Bitcoin coinbase tag missing or invalid")]
    BitcoinCoinbaseTagInvalid,
}

pub trait HeaderValidator: Send + Sync {
    fn validate(&self, header: &Header) -> Result<(), ValidationError>;
}

pub trait ParentHeaderValidator: Send + Sync {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError>;
}

/// Orchestrator to run multiple validation rules
pub struct HeaderVerifier {
    pub static_rules: Vec<Box<dyn HeaderValidator>>,
    pub parent_rules: Vec<Box<dyn ParentHeaderValidator>>,
}

impl Default for HeaderVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderVerifier {
    pub fn new() -> Self {
        Self {
            static_rules: Vec::new(),
            parent_rules: Vec::new(),
        }
    }

    /// Creates a standard RSK light client verifier with all consensus rules.
    pub fn default_rsk(config: crate::config::ChainConfig) -> Self {
        Self::new()
            .with_static_rule(GasUsedRule)
            .with_static_rule(GasLimitBoundsRule { 
                min_gas_limit: config.min_gas_limit, 
                max_gas_limit: config.max_gas_limit 
            })
            .with_static_rule(MergedMiningRule { config: config.clone() })
            .with_parent_rule(BlockNumberRule)
            .with_parent_rule(ParentHashRule)
            .with_parent_rule(TimestampRule::new(15)) // 15s drift
            .with_parent_rule(BlockParentGasLimitRule { config: config.clone() })
            .with_parent_rule(DifficultyRule { config })
    }

    pub fn with_static_rule(mut self, rule: impl HeaderValidator + 'static) -> Self {
        self.static_rules.push(Box::new(rule));
        self
    }

    pub fn with_parent_rule(mut self, rule: impl ParentHeaderValidator + 'static) -> Self {
        self.parent_rules.push(Box::new(rule));
        self
    }

    pub fn verify(&self, header: &Header, parent: Option<&Header>) -> Result<(), ValidationError> {
        for rule in &self.static_rules {
            rule.validate(header)?;
        }

        if let Some(parent_header) = parent {
            for rule in &self.parent_rules {
                rule.validate_with_parent(header, parent_header)?;
            }
        }

        Ok(())
    }
}

pub mod header_rules;
pub mod difficulty;
pub mod merged_mining;

pub use header_rules::{BlockNumberRule, ParentHashRule, TimestampRule, GasUsedRule, GasLimitBoundsRule, BlockParentGasLimitRule};
pub use difficulty::DifficultyRule;
pub use merged_mining::MergedMiningRule;

#[cfg(test)]
mod tests;
