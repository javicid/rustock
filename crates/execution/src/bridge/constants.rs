//! Bridge configuration constants, ported from rskj's `BridgeConstants`.
//!
//! Each network (mainnet, testnet, regtest) has its own set of parameters
//! controlling BTC confirmations, peg-in/peg-out limits, federation setup, etc.

/// Network-specific Bridge parameters.
#[derive(Debug, Clone)]
pub struct BridgeConstants {
    /// BTC network identifier ("mainnet", "testnet", "regtest").
    pub btc_network: BtcNetwork,

    // -- Confirmation thresholds --

    /// Minimum BTC confirmations for a peg-in to be accepted (mainnet: 100).
    pub btc2rsk_minimum_acceptable_confirmations: u32,
    /// Minimum RSK confirmations before a pegout is eligible (mainnet: 4000).
    pub rsk2btc_minimum_acceptable_confirmations: u32,

    // -- Header relay --

    /// Maximum BTC headers accepted in a single `receiveHeaders` call.
    pub max_btc_headers_per_rsk_block: u32,
    /// Minimum seconds between `receiveHeader` calls (rate limiting).
    pub min_seconds_between_calls_receive_header: u64,
    /// Maximum depth for BTC blockchain queries.
    pub max_depth_blockchain_accepted: u32,

    // -- Peg-in / peg-out limits --

    /// Minimum peg-in value in BTC satoshis (legacy, pre-RSKIP219).
    pub legacy_minimum_pegin_tx_value: u64,
    /// Minimum peg-in value in BTC satoshis (post-RSKIP219).
    pub minimum_pegin_tx_value: u64,
    /// Minimum peg-out value in BTC satoshis (legacy).
    pub legacy_minimum_pegout_tx_value: u64,
    /// Minimum peg-out value in BTC satoshis (post-RSKIP271).
    pub minimum_pegout_tx_value: u64,

    // -- Peg-out batching --

    /// Maximum inputs per peg-out BTC transaction.
    pub max_inputs_per_pegout_transaction: u32,
    /// Number of RSK blocks between peg-out batches.
    pub number_of_blocks_between_pegouts: u64,

    // -- Update period --

    /// How often `updateCollections` should be called (in RSK blocks).
    pub update_bridge_execution_period: u64,

    // -- BTC block index --

    /// BTC height when the block index feature activates.
    pub btc_height_when_block_index_activates: u32,
    /// Max depth to search blocks below the index activation height.
    pub max_depth_to_search_blocks_below_index_activation: u32,

    /// BTC transaction confirmation max depth.
    pub btc_transaction_confirmation_max_depth: u32,
}

/// BTC network selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl BridgeConstants {
    pub fn mainnet() -> Self {
        Self {
            btc_network: BtcNetwork::Mainnet,
            btc2rsk_minimum_acceptable_confirmations: 100,
            rsk2btc_minimum_acceptable_confirmations: 4000,
            max_btc_headers_per_rsk_block: 500,
            min_seconds_between_calls_receive_header: 300,
            max_depth_blockchain_accepted: 4320,
            legacy_minimum_pegin_tx_value: 1_000_000, // 0.01 BTC
            minimum_pegin_tx_value: 500_000,           // 0.005 BTC
            legacy_minimum_pegout_tx_value: 800_000,   // 0.008 BTC
            minimum_pegout_tx_value: 400_000,          // 0.004 BTC
            max_inputs_per_pegout_transaction: 20,
            number_of_blocks_between_pegouts: 360,
            update_bridge_execution_period: 1,
            btc_height_when_block_index_activates: 696_000,
            max_depth_to_search_blocks_below_index_activation: 4320,
            btc_transaction_confirmation_max_depth: 4320,
        }
    }

    pub fn testnet() -> Self {
        Self {
            btc_network: BtcNetwork::Testnet,
            btc2rsk_minimum_acceptable_confirmations: 10,
            rsk2btc_minimum_acceptable_confirmations: 10,
            max_btc_headers_per_rsk_block: 500,
            min_seconds_between_calls_receive_header: 300,
            max_depth_blockchain_accepted: 4320,
            legacy_minimum_pegin_tx_value: 1_000_000,
            minimum_pegin_tx_value: 500_000,
            legacy_minimum_pegout_tx_value: 500_000,
            minimum_pegout_tx_value: 250_000,
            max_inputs_per_pegout_transaction: 20,
            number_of_blocks_between_pegouts: 360,
            update_bridge_execution_period: 1,
            btc_height_when_block_index_activates: 2_000_000,
            max_depth_to_search_blocks_below_index_activation: 4320,
            btc_transaction_confirmation_max_depth: 4320,
        }
    }

    pub fn regtest() -> Self {
        Self {
            btc_network: BtcNetwork::Regtest,
            btc2rsk_minimum_acceptable_confirmations: 1,
            rsk2btc_minimum_acceptable_confirmations: 10,
            max_btc_headers_per_rsk_block: 500,
            min_seconds_between_calls_receive_header: 0,
            max_depth_blockchain_accepted: 4320,
            legacy_minimum_pegin_tx_value: 1_000_000,
            minimum_pegin_tx_value: 500_000,
            legacy_minimum_pegout_tx_value: 500_000,
            minimum_pegout_tx_value: 250_000,
            max_inputs_per_pegout_transaction: 20,
            number_of_blocks_between_pegouts: 1,
            update_bridge_execution_period: 1,
            btc_height_when_block_index_activates: 0,
            max_depth_to_search_blocks_below_index_activation: 4320,
            btc_transaction_confirmation_max_depth: 4320,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_confirmations() {
        let c = BridgeConstants::mainnet();
        assert_eq!(c.btc2rsk_minimum_acceptable_confirmations, 100);
        assert_eq!(c.rsk2btc_minimum_acceptable_confirmations, 4000);
    }

    #[test]
    fn regtest_confirmations() {
        let c = BridgeConstants::regtest();
        assert_eq!(c.btc2rsk_minimum_acceptable_confirmations, 1);
    }

    #[test]
    fn mainnet_pegin_limits() {
        let c = BridgeConstants::mainnet();
        assert_eq!(c.legacy_minimum_pegin_tx_value, 1_000_000);
        assert_eq!(c.minimum_pegin_tx_value, 500_000);
    }
}
