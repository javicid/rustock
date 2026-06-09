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
    /// Testnet-only on mainnet config (height -1 in rskj main.conf).
    Reed810,
    Vetiver900,
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
    // reed810 = -1 on mainnet (testnet-only); vetiver900 skips over it.
    (8_804_200, RskNetworkUpgrade::Vetiver900),
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
    // arrowhead631 = -1 on testnet (rskj testnet.conf)
    (5_735_824, RskNetworkUpgrade::Lovell700),
    (6_420_700, RskNetworkUpgrade::Reed800),
    (7_139_600, RskNetworkUpgrade::Reed810),
    (7_604_200, RskNetworkUpgrade::Vetiver900),
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
            activations: vec![(0, RskNetworkUpgrade::Vetiver900)],
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
            activations: vec![(0, RskNetworkUpgrade::Vetiver900)],
            chain_id,
        }
    }

    /// First block at which `upgrade` activates, if it activates on this network.
    pub fn activation_height(&self, upgrade: RskNetworkUpgrade) -> Option<u64> {
        self.activations.iter().find(|(_, u)| *u == upgrade).map(|(h, _)| *h)
    }

    /// rskj `ActivationConfig.ForBlock.isActivating`: the upgrade activates
    /// exactly at this block.
    pub fn is_activating(&self, upgrade: RskNetworkUpgrade, block_number: u64) -> bool {
        self.activation_height(upgrade) == Some(block_number)
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

    /// Whether the Unitrie state root is used in headers (RSKIP126, Wasabi100).
    /// Before this, headers contain a legacy Ethereum-style state root that
    /// doesn't match the Unitrie hash.
    pub fn has_unitrie_state_root(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
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

    /// RSKIP87: unlimited lock whitelist entries (Orchid, mainnet 729_000).
    pub fn has_rskip87(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Orchid
    }

    /// RSKIP88: invalid Bridge calldata throws instead of silently returning
    /// null (Orchid, mainnet 729_000).
    pub fn has_rskip88(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Orchid
    }

    /// RSKIP123: multikey federation members; disables the single-key "add"
    /// federation-change function (Wasabi100).
    pub fn has_rskip123(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// RSKIP125 (wasabi): a contract created by the CREATE/CREATE2 opcode has
    /// its nonce initialized to 1.
    pub fn has_rskip125(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// RSKIP140 (papyrus): the EXTCODEHASH opcode becomes available.
    pub fn has_rskip140(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// RSKIP383: longer federation activation age (Fingerroot500).
    pub fn has_rskip383(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP146: release request queue stores RSK tx hash (Papyrus200, mainnet 2_392_700).
    pub fn has_rskip146(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// RSKIP176: use updateCollections tx hash as pegouts-waiting-for-signatures key (Iris300).
    pub fn has_rskip176(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP199: BTC main-chain height -> hash index in bridge storage (Iris300).
    pub fn has_rskip199(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP134: per-hash processed-peg-in entries replace the single
    /// btcTxHashesAP map (Papyrus200).
    pub fn has_rskip134(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Papyrus200
    }

    /// RSKIP185: peg-out refund to sender on rejection (Iris300).
    pub fn has_rskip185(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP219: updated minimum peg-in tx value (Iris300).
    pub fn has_rskip219(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP201: peg-out BTC transactions use version 2 (Iris300).
    pub fn has_rskip201(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP271: peg-out batching and nextPegoutHeight tracking (Hop400, mainnet 4_598_500).
    pub fn has_rskip271(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Hop400
    }

    /// RSKIP375: pegouts-waiting-for-signatures keyed by the pegout creation
    /// RSK tx hash again (Fingerroot500).
    pub fn has_rskip375(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP453: internal creates with an unpayable code deposit (or
    /// over-max-size code) FAIL instead of deploying with empty code
    /// (Lovell700).
    pub fn has_rskip453(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP434: lifts the BTC chainwork-overflow header block (Arrowhead631).
    pub fn has_rskip434(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Arrowhead631
    }

    /// RSKIP170: pegin_btc event replaces lock_btc (Iris300).
    pub fn has_rskip170(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Iris300
    }

    /// RSKIP326: add_signature is only logged when a signature is actually
    /// applied (Fingerroot500).
    pub fn has_rskip326(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Fingerroot500
    }

    /// RSKIP459: mark rejected non-refundable peg-ins as processed (Lovell700).
    /// Disabled again by RSKIP551 at Vetiver900.
    pub fn has_rskip459(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Lovell700
    }

    /// RSKIP136 (bahamas — mainnet 3_397, testnet/regtest genesis): correct
    /// gas accounting for direct precompile calls. Before it, rskj checked
    /// the tx gas limit against the precompile cost alone and recorded
    /// gasUsed = precompileCost + intrinsicCost, which can EXCEED the limit.
    pub fn has_rskip136(&self, block_number: u64) -> bool {
        let height = match self.chain_id {
            RSK_MAINNET_CHAIN_ID => 3_397,
            _ => 0,
        };
        block_number >= height
    }

    /// RSKIP124: public receiveHeaders with header-count-based cost (Wasabi100).
    pub fn has_rskip124(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// RSKIP132: recalculated receiveHeaders cost (Wasabi100; testnet
    /// overrides the height to 43_550 in testnet.conf consensusRules).
    pub fn has_rskip132(&self, block_number: u64) -> bool {
        if self.chain_id == RSK_TESTNET_CHAIN_ID {
            return block_number >= 43_550;
        }
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Wasabi100
    }

    /// areBridgeTxsPaid (rskj reference.conf: afterBridgeSync — mainnet
    /// 370_000, testnet 114_000). Before activation, federation/authorized
    /// transactions to the Bridge execute for free with zero gas
    /// (BridgeUtils.isFreeBridgeTx).
    pub fn has_are_bridge_txs_paid(&self, block_number: u64) -> bool {
        let height = match self.chain_id {
            RSK_MAINNET_CHAIN_ID => 370_000,
            RSK_TESTNET_CHAIN_ID => 114_000,
            _ => 0,
        };
        block_number >= height
    }

    /// RSKIP536: additional BlockHeader precompile methods. Maps to reed810 in
    /// reference.conf; mainnet overrides it to the vetiver900 height (8_804_200)
    /// via main.conf consensusRules. `>= Reed810` is exact on both networks
    /// because mainnet jumps Reed800 -> Vetiver900 at that height.
    pub fn has_rskip536(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Reed810
    }

    /// RSKIP540: min pegout value as extra pegout in fee estimation;
    /// enables getEstimatedFeesForPegOutAmount (Vetiver900).
    pub fn has_rskip540(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }

    /// RSKIP544: EIP-3541, reject new contract code starting with 0xEF (Vetiver900).
    pub fn has_rskip544(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }

    /// RSKIP551: disables RSKIP459 (Vetiver900).
    pub fn has_rskip551(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }

    /// RSKIP552: Blake2F data handling improvements (Vetiver900).
    pub fn has_rskip552(&self, block_number: u64) -> bool {
        self.active_upgrade(block_number) >= RskNetworkUpgrade::Vetiver900
    }
}

fn upgrade_to_spec_id(upgrade: RskNetworkUpgrade) -> SpecId {
    match upgrade {
        RskNetworkUpgrade::Genesis
        | RskNetworkUpgrade::Orchid => SpecId::BYZANTIUM,

        // Wasabi enables the Constantinople shift opcodes (RSKIP120) and
        // CREATE2 (RSKIP125), but NOT EXTCODEHASH (RSKIP140, papyrus).
        // PETERSBURG is the closest spec (Constantinople minus EIP-1283 SSTORE
        // gas, which RSK never adopted); EXTCODEHASH is gated off separately
        // until papyrus in rsk_instructions::install.
        RskNetworkUpgrade::Wasabi100
        | RskNetworkUpgrade::Papyrus200
        | RskNetworkUpgrade::Iris300
        | RskNetworkUpgrade::Hop400
        | RskNetworkUpgrade::Fingerroot500 => SpecId::PETERSBURG,

        RskNetworkUpgrade::Arrowhead600
        | RskNetworkUpgrade::Arrowhead631 => SpecId::ISTANBUL,

        RskNetworkUpgrade::Lovell700
        | RskNetworkUpgrade::Reed800
        | RskNetworkUpgrade::Reed810
        | RskNetworkUpgrade::Vetiver900 => SpecId::SHANGHAI,
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

    // -----------------------------------------------------------------------
    // RSKIP activation tests — ported from rskj activation height tables
    // -----------------------------------------------------------------------

    /// RSKIP87 (unlimited whitelist) activates at Orchid (mainnet 729_000).
    #[test]
    fn test_rskip87_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip87(728_999));
        assert!(cfg.has_rskip87(729_000));
    }

    /// RSKIP146 (queue with tx hash) activates at Papyrus200 (mainnet 2_392_700).
    #[test]
    fn test_rskip146_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip146(2_392_699));
        assert!(cfg.has_rskip146(2_392_700));
    }

    /// RSKIP271 (peg-out batching) activates at Hop400 (mainnet 4_598_500).
    #[test]
    fn test_rskip271_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip271(4_598_499));
        assert!(cfg.has_rskip271(4_598_500));
    }

    /// RSKIP185 and RSKIP176 activate at Iris300 (mainnet 3_614_800).
    #[test]
    fn test_rskip185_rskip176_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert!(!cfg.has_rskip185(3_614_799));
        assert!(cfg.has_rskip185(3_614_800));
        assert!(!cfg.has_rskip176(3_614_799));
        assert!(cfg.has_rskip176(3_614_800));
    }

    /// All RSKIPs active with all_active config.
    #[test]
    fn test_all_rskips_active() {
        let cfg = RskHardforkConfig::all_active(33);
        assert!(cfg.has_rskip87(0));
        assert!(cfg.has_rskip146(0));
        assert!(cfg.has_rskip176(0));
        assert!(cfg.has_rskip185(0));
        assert!(cfg.has_rskip219(0));
        assert!(cfg.has_rskip271(0));
        assert!(cfg.has_rskip536(0));
        assert!(cfg.has_rskip540(0));
        assert!(cfg.has_rskip544(0));
        assert!(cfg.has_rskip551(0));
        assert!(cfg.has_rskip552(0));
    }

    /// Vetiver900 activates at mainnet 8_804_200 (rskj main.conf), skipping
    /// reed810 which is -1 on mainnet.
    #[test]
    fn test_vetiver900_mainnet() {
        let cfg = RskHardforkConfig::mainnet();
        assert_eq!(cfg.active_upgrade(8_804_199), RskNetworkUpgrade::Reed800);
        assert_eq!(cfg.active_upgrade(8_804_200), RskNetworkUpgrade::Vetiver900);
        for has in [
            RskHardforkConfig::has_rskip540,
            RskHardforkConfig::has_rskip544,
            RskHardforkConfig::has_rskip551,
            RskHardforkConfig::has_rskip552,
        ] {
            assert!(!has(&cfg, 8_804_199));
            assert!(has(&cfg, 8_804_200));
        }
        // rskip536 is overridden to the vetiver900 height on mainnet
        // (main.conf consensusRules: rskip536 = 8804200).
        assert!(!cfg.has_rskip536(8_804_199));
        assert!(cfg.has_rskip536(8_804_200));
    }

    /// Testnet: reed810 at 7_139_600, vetiver900 at 7_604_200 (rskj testnet.conf).
    #[test]
    fn test_vetiver900_testnet() {
        let cfg = RskHardforkConfig::testnet();
        assert_eq!(cfg.active_upgrade(7_139_599), RskNetworkUpgrade::Reed800);
        assert_eq!(cfg.active_upgrade(7_139_600), RskNetworkUpgrade::Reed810);
        assert_eq!(cfg.active_upgrade(7_604_200), RskNetworkUpgrade::Vetiver900);
        // rskip536 maps to reed810 on testnet (reference.conf).
        assert!(!cfg.has_rskip536(7_139_599));
        assert!(cfg.has_rskip536(7_139_600));
        // vetiver900-mapped rskips activate later.
        assert!(!cfg.has_rskip544(7_604_199));
        assert!(cfg.has_rskip544(7_604_200));
    }
}
