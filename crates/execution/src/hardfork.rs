/// RSK hardfork configuration and mapping to revm SpecId.
///
/// RSK activates EVM features individually via RSKIPs rather than bundling
/// them into Ethereum-style hardforks. We map each RSK network upgrade to
/// the closest Ethereum SpecId that captures the same EVM semantics:
///
/// | RSK Upgrade      | Height    | Closest SpecId    | Key changes                          |
/// |------------------|-----------|-------------------|--------------------------------------|
/// | genesis–orchid   | 0–728999  | BYZANTIUM         | REVERT, STATICCALL, RETURNDATASIZE   |
/// | orchid           | 729000    | BYZANTIUM         | (RSK-specific fixes)                 |
/// | wasabi100        | 1591000   | BYZANTIUM         | (RSK-specific fixes)                 |
/// | papyrus200       | 2392700   | PETERSBURG        | SHL/SHR/SAR, CHAINID, CREATE2        |
/// | iris300          | 3614800   | PETERSBURG        | (RSK-specific fixes)                 |
/// | hop400           | 4598500   | PETERSBURG        | (RSK-specific fixes)                 |
/// | fingerroot500    | 5468000   | PETERSBURG        | (RSK-specific fixes)                 |
/// | arrowhead600     | 6223700   | ISTANBUL          | Calldata cost reduction (RSKIP400)   |
/// | lovell700        | 7338024   | SHANGHAI          | Initcode metering (RSKIP438), PUSH0  |
/// | reed800          | 8052200   | SHANGHAI          | (RSK-specific fixes)                 |
use revm::primitives::hardfork::SpecId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RskNetworkUpgrade {
    Genesis,
    Orchid,
    Wasabi100,
    Papyrus200,
    Iris300,
    Hop400,
    Fingerroot500,
    Arrowhead600,
    Arrowhead631,
    Lovell700,
    Reed800,
}

pub const RSK_MAINNET_CHAIN_ID: u64 = 30;
pub const RSK_TESTNET_CHAIN_ID: u64 = 31;

/// Mainnet activation heights.
pub const MAINNET_ACTIVATIONS: &[(u64, RskNetworkUpgrade)] = &[
    (0, RskNetworkUpgrade::Genesis),
    (729_000, RskNetworkUpgrade::Orchid),
    (1_591_000, RskNetworkUpgrade::Wasabi100),
    (2_392_700, RskNetworkUpgrade::Papyrus200),
    (3_614_800, RskNetworkUpgrade::Iris300),
    (4_598_500, RskNetworkUpgrade::Hop400),
    (5_468_000, RskNetworkUpgrade::Fingerroot500),
    (6_223_700, RskNetworkUpgrade::Arrowhead600),
    (6_549_300, RskNetworkUpgrade::Arrowhead631),
    (7_338_024, RskNetworkUpgrade::Lovell700),
    (8_052_200, RskNetworkUpgrade::Reed800),
];

/// Testnet activation heights.
pub const TESTNET_ACTIVATIONS: &[(u64, RskNetworkUpgrade)] = &[
    (0, RskNetworkUpgrade::Genesis),
    (0, RskNetworkUpgrade::Orchid),
    (863_000, RskNetworkUpgrade::Wasabi100),
    (1_580_000, RskNetworkUpgrade::Papyrus200),
    (2_060_500, RskNetworkUpgrade::Iris300),
    (3_103_000, RskNetworkUpgrade::Hop400),
    (4_015_800, RskNetworkUpgrade::Fingerroot500),
    (4_927_100, RskNetworkUpgrade::Arrowhead600),
    (5_254_700, RskNetworkUpgrade::Arrowhead631),
    (5_735_824, RskNetworkUpgrade::Lovell700),
    (6_420_700, RskNetworkUpgrade::Reed800),
];

/// Configuration that determines which RSK features are active at a given block.
#[derive(Debug, Clone)]
pub struct RskHardforkConfig {
    activations: Vec<(u64, RskNetworkUpgrade)>,
    pub chain_id: u64,
}

impl RskHardforkConfig {
    pub fn mainnet() -> Self {
        Self {
            activations: MAINNET_ACTIVATIONS.to_vec(),
            chain_id: RSK_MAINNET_CHAIN_ID,
        }
    }

    pub fn testnet() -> Self {
        Self {
            activations: TESTNET_ACTIVATIONS.to_vec(),
            chain_id: RSK_TESTNET_CHAIN_ID,
        }
    }

    pub fn regtest() -> Self {
        Self {
            activations: vec![(0, RskNetworkUpgrade::Reed800)],
            chain_id: 33,
        }
    }

    pub fn for_network(network_id: u64) -> Self {
        match network_id {
            30 => Self::mainnet(),
            31 => Self::testnet(),
            _ => Self::regtest(),
        }
    }

    /// Creates a config where all upgrades are active from genesis (useful for testing).
    pub fn all_active(chain_id: u64) -> Self {
        Self {
            activations: vec![(0, RskNetworkUpgrade::Reed800)],
            chain_id,
        }
    }

    /// Returns the active RSK network upgrade at the given block height.
    pub fn active_upgrade(&self, block_number: u64) -> RskNetworkUpgrade {
        let mut active = RskNetworkUpgrade::Genesis;
        for &(height, upgrade) in &self.activations {
            if block_number >= height {
                active = upgrade;
            } else {
                break;
            }
        }
        active
    }

    /// Maps the RSK network upgrade to the closest revm SpecId.
    pub fn spec_id(&self, block_number: u64) -> SpecId {
        upgrade_to_spec_id(self.active_upgrade(block_number))
    }

    /// Whether CHAINID opcode is available (RSKIP152, activated at Papyrus200).
    pub fn has_chainid(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// Whether calldata cost is reduced from 68 to 16 (RSKIP400, Arrowhead600).
    pub fn has_reduced_calldata_cost(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead600
    }

    /// Whether initcode metering is active (RSKIP438, Lovell700).
    pub fn has_initcode_metering(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// Whether StoredBlock V2 format is active (RSKIP454, Lovell700).
    pub fn has_stored_block_v2(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }
}

fn upgrade_to_spec_id(upgrade: RskNetworkUpgrade) -> SpecId {
    match upgrade {
        RskNetworkUpgrade::Genesis
        | RskNetworkUpgrade::Orchid
        | RskNetworkUpgrade::Wasabi100 => SpecId::BYZANTIUM,

        RskNetworkUpgrade::Papyrus200
        | RskNetworkUpgrade::Iris300
        | RskNetworkUpgrade::Hop400
        | RskNetworkUpgrade::Fingerroot500 => SpecId::PETERSBURG,

        RskNetworkUpgrade::Arrowhead600
        | RskNetworkUpgrade::Arrowhead631 => SpecId::ISTANBUL,

        RskNetworkUpgrade::Lovell700
        | RskNetworkUpgrade::Reed800 => SpecId::SHANGHAI,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_genesis_is_byzantium() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(0), SpecId::BYZANTIUM);
        assert_eq!(cfg.spec_id(728_999), SpecId::BYZANTIUM);
    }

    #[test]
    fn test_mainnet_papyrus_is_petersburg() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(2_392_700), SpecId::PETERSBURG);
        assert!(!cfg.has_chainid(2_392_699));
        assert!(cfg.has_chainid(2_392_700));
    }

    #[test]
    fn test_mainnet_arrowhead_is_istanbul() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(6_223_700), SpecId::ISTANBUL);
        assert!(cfg.has_reduced_calldata_cost(6_223_700));
        assert!(!cfg.has_reduced_calldata_cost(6_223_699));
    }

    #[test]
    fn test_mainnet_lovell_is_shanghai() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.spec_id(7_338_024), SpecId::SHANGHAI);
        assert!(cfg.has_initcode_metering(7_338_024));
    }

    #[test]
    fn test_all_active() {
        let cfg = RskHardforkConfig::all_active(33);
        assert_eq!(cfg.spec_id(0), SpecId::SHANGHAI);
        assert!(cfg.has_chainid(0));
        assert!(cfg.has_reduced_calldata_cost(0));
        assert!(cfg.has_initcode_metering(0));
        assert_eq!(cfg.chain_id, 33);
    }

    #[test]
    fn test_upgrade_ordering() {
        assert!(RskNetworkUpgrade::Genesis < RskNetworkUpgrade::Orchid);
        assert!(RskNetworkUpgrade::Orchid < RskNetworkUpgrade::Papyrus200);
        assert!(RskNetworkUpgrade::Papyrus200 < RskNetworkUpgrade::Arrowhead600);
        assert!(RskNetworkUpgrade::Arrowhead600 < RskNetworkUpgrade::Lovell700);
        assert!(RskNetworkUpgrade::Lovell700 < RskNetworkUpgrade::Reed800);
    }
}
