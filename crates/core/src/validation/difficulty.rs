use super::{ParentHeaderValidator, ValidationError};
use crate::types::header::Header;
use alloy_primitives::U256;

pub struct DifficultyRule {
    pub config: crate::config::ChainConfig,
}

impl ParentHeaderValidator for DifficultyRule {
    fn validate_with_parent(&self, header: &Header, parent: &Header) -> Result<(), ValidationError> {
        let expected = self.calculate_expected_difficulty(header, parent);
        if header.difficulty != expected {
            return Err(ValidationError::DifficultyMismatch {
                expected,
                got: header.difficulty,
            });
        }
        Ok(())
    }
}

impl DifficultyRule {
    fn calculate_expected_difficulty(&self, header: &Header, parent: &Header) -> U256 {
        let delta = header.timestamp.saturating_sub(parent.timestamp);

        if delta == 0 && header.timestamp <= parent.timestamp {
             return parent.difficulty;
        }

        let calc_dur = (1 + header.uncle_count) * self.config.duration_limit;
        
        let sign = if calc_dur > delta {
            1i8
        } else if calc_dur < delta {
            -1i8
        } else {
            0i8
        };

        if sign == 0 {
            return parent.difficulty;
        }

        let quotient = parent.difficulty / self.config.difficulty_divisor;
        
        let mut new_diff = if sign == 1 {
            parent.difficulty + quotient
        } else if parent.difficulty > quotient {
            parent.difficulty - quotient
        } else {
            U256::ZERO
        };

        if new_diff < self.config.min_difficulty {
            new_diff = self.config.min_difficulty;
        }

        new_diff
    }
}
