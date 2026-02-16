use super::{ParentHeaderValidator, ValidationError};
use crate::types::header::Header;
use alloy_primitives::U256;

/// RSKIP156 increases the difficulty divisor from 50 to 400.
const RSKIP156_DIFFICULTY_DIVISOR: U256 = U256::from_limbs([400, 0, 0, 0]);

/// Pre-RSKIP97: if block is mined > 600s after parent, reset to minimum difficulty.
const TEN_MINUTES: u64 = 600;

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
        let activations = &self.config.activation_heights;

        // Pre-RSKIP97 (before orchid): if more than 10 minutes since parent,
        // reset difficulty to minimum to allow fallback private mining.
        let rskip97_active = header.number >= activations.orchid;
        if !rskip97_active {
            let delta_ts = header.timestamp.saturating_sub(parent.timestamp);
            if delta_ts >= TEN_MINUTES {
                return self.config.min_difficulty;
            }
        }

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

        // RSKIP156 (papyrus200): difficulty divisor changes from 50 to 400.
        let divisor = if header.number >= activations.papyrus200 {
            RSKIP156_DIFFICULTY_DIVISOR
        } else {
            self.config.difficulty_divisor
        };

        let quotient = parent.difficulty / divisor;

        let from_parent = if sign == 1 {
            parent.difficulty + quotient
        } else if parent.difficulty > quotient {
            parent.difficulty - quotient
        } else {
            U256::ZERO
        };

        // Clamp to minimum difficulty — matches rskj's max(minDifficulty, fromParent).
        if from_parent < self.config.min_difficulty {
            self.config.min_difficulty
        } else {
            from_parent
        }
    }
}
