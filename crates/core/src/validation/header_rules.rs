use super::{HeaderValidator, ParentHeaderValidator, ValidationError};
use crate::types::header::Header;
use std::time::{SystemTime, UNIX_EPOCH};

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
                expected: format!("{:?}", parent_hash),
                got: format!("{:?}", header.parent_hash),
            });
        }
        Ok(())
    }
}

pub struct TimestampRule {
    pub max_future_offset: u64,
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
            .expect("Time went backwards")
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
        let gas_limit: u64 = header.gas_limit.try_into().unwrap_or(u64::MAX);
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
        let gas_limit: u64 = header.gas_limit.try_into().unwrap_or(u64::MAX);
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
    pub config: crate::config::ChainConfig,
}

impl ParentHeaderValidator for BlockParentGasLimitRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        let limit: u64 = header.gas_limit.try_into().unwrap_or(u64::MAX);
        let parent_limit: u64 = parent.gas_limit.try_into().unwrap_or(u64::MAX);
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
