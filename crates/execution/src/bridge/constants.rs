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

    // -- Fee parameters --

    /// Genesis fee per KB in satoshis (used when no vote has set it yet).
    /// Mainnet: 5 × MILLICOIN = 500_000 sat/KB.
    pub genesis_fee_per_kb: u64,

    // -- Free bridge transactions (pre-areBridgeTxsPaid) --

    /// Genesis federation BTC public keys (compressed hex), from rskj
    /// Federation*NetConstants. Their derived RSK addresses may send free
    /// transactions to the Bridge before areBridgeTxsPaid activates.
    pub genesis_federation_public_keys: &'static [&'static str],
    /// Authorized senders for free bridge txs (uncompressed hex): the
    /// federation-change, lock-whitelist and feePerKb authorizer keys
    /// (rskj BridgeUtils.isFromAuthorizedSender).
    pub authorized_free_tx_keys: &'static [&'static str],
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
            // 5 × MILLICOIN = 5 × 100_000 = 500_000 sat/KB
            genesis_fee_per_kb: 500_000,
            // rskj FederationMainNetConstants.genesisFederationPublicKeys
            genesis_federation_public_keys: &[
                "03b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2",
                "027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344",
                "0355a2e9bf100c00fc0a214afd1bf272647c7824eb9cb055480962f0c382596a70",
                "02566d5ded7c7db1aa7ee4ef6f76989fb42527fcfdcddcd447d6793b7d869e46f7",
                "0294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adc",
                "0372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6",
                "0340df69f28d69eef60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb44",
                "02ac1901b6fba2c1dbd47d894d2bd76c8ba1d296d65f6ab47f1c6b22afb53e73eb",
                "031aabbeb9b27258f98c2bf21f36677ae7bae09eb2d8c958ef41a20a6e88626d26",
                "0245ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffeea",
                "02550cc87fa9061162b1dd395a16662529c9d8094c0feca17905a3244713d65fe8",
                "02481f02b7140acbf3fcdd9f72cf9a7d9484d8125e6df7c9451cfa55ba3b077265",
                "03f909ae15558c70cc751aff9b1f495199c325b13a9e5b934fd6299cd30ec50be8",
                "02c6018fcbd3e89f3cf9c7f48b3232ea3638eb8bf217e59ee290f5f0cfb2fb9259",
                "03b65694ccccda83cbb1e56b31308acd08e993114c33f66a456b627c2c1c68bed6",
            ],
            // federationChange + lockWhitelist + feePerKb authorizers
            // (FederationMainNetConstants, WhitelistMainNetConstants,
            // FeePerKbMainNetConstants)
            authorized_free_tx_keys: &[
                "04e593d4cde25137b13f19462bc4c02e97ba2ed5a3860813497abf9b4eeb9259e37e0384d12cfd2d9a7a0ba606b31ee34317a9d7f4a8591c6bcf5dfd5563248b2f",
                "045e7f2563e73d44d149c19cffca36e1898597dc759d76166b8104103c0d3f351a8a48e3a224544e9a649ad8ebcfdbd6c39744ddb85925f19c7e3fd48f07fc1c06",
                "0441945e4e272936106f6200b36162f3510e8083535c15e175ac82deaf828da955b85fd72b7534f2a34cedfb45fa63b728cc696a2bd3c5d39ec799ec2618e9aa9f",
                "041a2449e9d63409c5a8ea3a21c4109b1a6634ee88fd57176d45ea46a59713d5e0b688313cf252128a3e49a0b2effb4b413e5a2525a6fa5894d059f815c9d9efa6",
                "0448f51638348b034995b1fd934fe14c92afde783e69f120a46ee16eb6bdc2e4f6b5e37772094c68c0dea2b1be3d96ea9651a9eebda7304914c8047f4e3e251378",
                "0484c66f75548baf93e322574adac4e4579b6a53f8d11fab640e14c90118e6983ef24b0de349a3e88f72e81e771ae1c897cef446fd7f4da71778c532aee3b6c41b",
                "04bb6435dc1ea12da843ebe213893d136c1624acd681fff82551498ae00bf28e9323164b00daf925fa75177463b8254a2aae8a1713e4d851a84ea369c193e9ce51",
            ],
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
            // 1 × MILLICOIN = 100_000 sat/KB
            genesis_fee_per_kb: 100_000,
            // rskj FederationTestNetConstants.genesisFederationPublicKeys
            genesis_federation_public_keys: &[
                "039a060badbeb24bee49eb2063f616c0f0f0765d4ca646b20a88ce828f259fcdb9",
                "02afc230c2d355b1a577682b07bc2646041b5d0177af0f98395a46018da699b6da",
                "0344a3c38cd59afcba3edcebe143e025574594b001700dec41e59409bdbd0f2a09",
                "034844a99cd7028aa319476674cc381df006628be71bc5593b8b5fdb32bb42ef85",
            ],
            // federationChange + lockWhitelist + feePerKb authorizers
            // (FederationTestNetConstants, WhitelistTestNetConstants,
            // FeePerKbTestNetConstants)
            authorized_free_tx_keys: &[
                "04d9052c2022f6f35da53f04f02856ff5e59f9836eec03daad0328d12c5c66140205da540498e46cd05bf63c1201382dd84c100f0d52a10654159965aea452c3f2",
                "04bf889f2035c8c441d7d1054b6a449742edd04d202f44a29348b4140b34e2a81ce66e388f40046636fd012bd7e3cecd9b951ffe28422334722d20a1cf6c7926fb",
                "047e707e4f67655c40c539363fb435d89574b8fe400971ba0290de9c2adbb2bd4e1e5b35a2188b9409ff2cc102292616efc113623483056bb8d8a02bf7695670ea",
                "04bf7e3bca7f7c58326382ed9c2516a8773c21f1b806984bb1c5c33bd18046502d97b28c0ea5b16433fbb2b23f14e95b36209f304841e814017f1ede1ecbdcfce3",
                "04701d1d27f8c2ae97912d96fb1f82f10c2395fd320e7a869049268c6b53d2060dfb2e22e3248955332d88cd2ae29a398f8f3858e48dd6d8ffbc37dfd6d1aa4934",
                "045ef89e4a5645dc68895dbc33b4c966c3a0a52bb837ecdd2ba448604c4f47266456d1191420e1d32bbe8741f8315fde4d1440908d400e5998dbed6549d499559b",
                "0455db9b3867c14e84a6f58bd2165f13bfdba0703cb84ea85788373a6a109f3717e40483aa1f8ef947f435ccdf10e530dd8b3025aa2d4a7014f12180ee3a301d27",
            ],
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
            genesis_fee_per_kb: 100_000,
            // Regtest has areBridgeTxsPaid from genesis; no free senders needed.
            genesis_federation_public_keys: &[],
            authorized_free_tx_keys: &[],
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

    // -----------------------------------------------------------------------
    // Tests ported from rskj BridgeConstantsTest.java
    // -----------------------------------------------------------------------

    /// Ported from rskj BridgeConstantsTest.getMinimumPegoutTxValue
    /// Mainnet: 400_000 sat, Testnet: 250_000 sat, Regtest: 250_000 sat
    #[test]
    fn rskj_minimum_pegout_tx_value_mainnet() {
        assert_eq!(BridgeConstants::mainnet().minimum_pegout_tx_value, 400_000);
    }

    #[test]
    fn rskj_minimum_pegout_tx_value_testnet() {
        assert_eq!(BridgeConstants::testnet().minimum_pegout_tx_value, 250_000);
    }

    #[test]
    fn rskj_minimum_pegout_tx_value_regtest() {
        assert_eq!(BridgeConstants::regtest().minimum_pegout_tx_value, 250_000);
    }

    /// Ported from rskj BridgeConstantsTest.minimumPeginTxValueArgProvider
    /// Legacy: 1_000_000 sat (0.01 BTC), Post-RSKIP219: 500_000 sat (0.005 BTC)
    #[test]
    fn rskj_minimum_pegin_values() {
        for c in [BridgeConstants::mainnet(), BridgeConstants::testnet(), BridgeConstants::regtest()] {
            assert_eq!(c.legacy_minimum_pegin_tx_value, 1_000_000, "legacy pegin min");
            assert_eq!(c.minimum_pegin_tx_value, 500_000, "RSKIP219 pegin min");
        }
    }

    /// Ported from rskj BridgeConstantsTest — legacy pegout values
    #[test]
    fn rskj_legacy_minimum_pegout_values() {
        assert_eq!(BridgeConstants::mainnet().legacy_minimum_pegout_tx_value, 800_000);
        assert_eq!(BridgeConstants::testnet().legacy_minimum_pegout_tx_value, 500_000);
        assert_eq!(BridgeConstants::regtest().legacy_minimum_pegout_tx_value, 500_000);
    }
}
