use super::{HeaderValidator, ParentHeaderValidator, ValidationError};
use crate::types::header::Header;
use alloy_primitives::U256;
use std::time::{SystemTime, UNIX_EPOCH};

/// Converts a U256 gas limit to u64, returning an error on overflow.
fn gas_limit_as_u64(gas_limit: U256) -> Result<u64, ValidationError> {
    gas_limit.try_into().map_err(|_| ValidationError::GasLimitOverflow)
}

pub struct BlockNumberRule;
impl ParentHeaderValidator for BlockNumberRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        if header.number != parent.number + 1 {
            return Err(ValidationError::InvalidBlockNumber {
                expected: parent.number + 1,
                got: header.number,
            });
        }
        Ok(())
    }
}

pub struct ParentHashRule;
impl ParentHeaderValidator for ParentHashRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        let parent_hash = parent.hash();
        if header.parent_hash != parent_hash {
            return Err(ValidationError::ParentHashMismatch {
                expected: parent_hash,
                got: header.parent_hash,
            });
        }
        Ok(())
    }
}

pub struct TimestampRule {
    max_future_offset: u64,
}

impl TimestampRule {
    pub fn new(max_future_offset: u64) -> Self {
        Self { max_future_offset }
    }
}

impl HeaderValidator for TimestampRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ValidationError::SystemTimeError)?
            .as_secs();
            
        if header.timestamp > now + self.max_future_offset {
            return Err(ValidationError::TimestampInFuture {
                current: now,
                got: header.timestamp,
            });
        }
        Ok(())
    }
}

impl ParentHeaderValidator for TimestampRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        self.validate(header)?;
        if header.timestamp <= parent.timestamp {
            return Err(ValidationError::TimestampOlderThanParent {
                parent: parent.timestamp,
                got: header.timestamp,
            });
        }
        Ok(())
    }
}

pub struct GasUsedRule;
impl HeaderValidator for GasUsedRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        let gas_limit = gas_limit_as_u64(header.gas_limit)?;
        if header.gas_used > gas_limit {
            return Err(ValidationError::GasUsedExceedsLimit {
                used: header.gas_used,
                limit: gas_limit,
            });
        }
        Ok(())
    }
}

pub struct GasLimitBoundsRule {
    pub min_gas_limit: u64,
    pub max_gas_limit: u64,
}

impl HeaderValidator for GasLimitBoundsRule {
    fn validate(&self, header: &Header) -> Result<(), ValidationError> {
        let gas_limit = gas_limit_as_u64(header.gas_limit)?;
        if gas_limit < self.min_gas_limit || gas_limit > self.max_gas_limit {
            return Err(ValidationError::GasLimitOutOfBounds {
                min: self.min_gas_limit,
                max: self.max_gas_limit,
                got: gas_limit,
            });
        }
        Ok(())
    }
}

pub struct BlockParentGasLimitRule {
    pub config: std::sync::Arc<crate::config::ChainConfig>,
}

impl ParentHeaderValidator for BlockParentGasLimitRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        let limit = gas_limit_as_u64(header.gas_limit)?;
        let parent_limit = gas_limit_as_u64(parent.gas_limit)?;
        let divisor = self.config.gas_limit_bound_divisor;
        let delta = parent_limit / divisor;
        
        if limit < parent_limit - delta || limit > parent_limit + delta {
            return Err(ValidationError::GasLimitInvalid {
                parent: parent_limit,
                got: limit,
            });
        }
        Ok(())
    }
}
