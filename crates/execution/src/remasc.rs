/// REMASC (Reward Manager Smart Contract) configuration, storage layout, and helpers.
///
/// REMASC distributes miner fees with delayed maturity. This module provides:
/// - `RemascConfig`: network-specific parameters (maturity, divisors, addresses)
/// - Storage key encoding matching rskj's `DataWord.fromString`
/// - Journal-based sload/sstore and balance transfer helpers
/// - `process_miners_fees`: core fee distribution algorithm
use alloy_primitives::{Address, U256};
use revm::context_interface::{Block as BlockTr, ContextTr, JournalTr};
use revm::precompile::PrecompileError;
use rustock_storage::BlockStore;
use std::sync::Arc;

use alloy_primitives::B256;
use rustock_core::Header;

use crate::precompiles::REMASC_ADDR;

/// Maximum number of blocks after a block in which its uncle can be included.
const UNCLE_GENERATION_LIMIT: u64 = 7;

// ---------------------------------------------------------------------------
// RemascConfig
// ---------------------------------------------------------------------------

/// REMASC parameters loaded from rskj's `remasc.json`.
#[derive(Debug, Clone)]
pub struct RemascConfig {
    /// Blocks until mining fees become eligible for distribution (mainnet: 4000).
    pub maturity: u64,
    /// Reward pool is divided into this many slices (mainnet: 10).
    pub synthetic_span: u64,
    /// RSK Labs receives `1/rsk_labs_divisor` of the synthetic reward (default 5 = 20%).
    pub rsk_labs_divisor: u64,
    /// Federation receives `1/federation_divisor` of the synthetic reward (default 100 = 1%).
    pub federation_divisor: u64,
    /// Punishment burn when the selection rule was broken (default 10 = 10%).
    pub punishment_divisor: u64,
    /// Publisher share in sibling path (default 10 = 10%).
    pub publishers_divisor: u64,
    /// Late uncle inclusion penalty scaling (default 20).
    pub late_uncle_inclusion_punishment_divisor: u64,
    /// RSK Labs reward address (pre-RSKIP218).
    pub rsk_labs_address: Address,
    /// RSK Labs reward address (post-RSKIP218).
    pub rsk_labs_address_rskip218: Address,
    /// Block height at which RSKIP218 activates (changes the labs payout address).
    pub rskip218_activation_height: u64,
    /// Block height at which RSKIP85 activates (minimum payable reward gates).
    pub rskip85_activation_height: u64,
    /// RSKIP85: synthetic reward must exceed mgp * this (rskj Constants 200_000).
    pub minimum_payable_gas: u64,
    /// RSKIP85: per-federator share must exceed mgp * this (rskj Constants 50_000).
    pub federator_minimum_payable_gas: u64,
    /// Genesis federation BTC public keys, used for federation payouts while
    /// no federation is stored in the Bridge.
    pub genesis_federation_public_keys: &'static [&'static str],
}

impl RemascConfig {
    pub fn mainnet() -> Self {
        Self {
            maturity: 4000,
            synthetic_span: 10,
            rsk_labs_divisor: 5,
            federation_divisor: 100,
            punishment_divisor: 10,
            publishers_divisor: 10,
            late_uncle_inclusion_punishment_divisor: 20,
            rsk_labs_address: "14d3065c8Eb89895f4df12450EC6b130049F8034"
                .parse()
                .unwrap(),
            rsk_labs_address_rskip218: "dcb12179ba4697350f66224c959bdd9c282818df"
                .parse()
                .unwrap(),
            rskip218_activation_height: 3_614_800, // rskj: rskip218 = iris300
            rskip85_activation_height: 729_000,     // rskj: rskip85 = orchid
            minimum_payable_gas: 200_000,
            federator_minimum_payable_gas: 50_000,
            genesis_federation_public_keys:
                crate::bridge::constants::BridgeConstants::mainnet().genesis_federation_public_keys,
        }
    }

    pub fn testnet() -> Self {
        Self {
            maturity: 50,
            synthetic_span: 10,
            rsk_labs_divisor: 5,
            federation_divisor: 100,
            punishment_divisor: 10,
            publishers_divisor: 10,
            late_uncle_inclusion_punishment_divisor: 20,
            rsk_labs_address: "dabadabadabadabadabadabadabadabadaba0003"
                .parse()
                .unwrap(),
            rsk_labs_address_rskip218: "dabadabadabadabadabadabadabadabadaba0003"
                .parse()
                .unwrap(),
            rskip218_activation_height: 2_060_500, // rskj: rskip218 = iris300
            rskip85_activation_height: 0,           // rskj: rskip85 = orchid (testnet 0)
            minimum_payable_gas: 200_000,
            federator_minimum_payable_gas: 50_000,
            genesis_federation_public_keys:
                crate::bridge::constants::BridgeConstants::testnet().genesis_federation_public_keys,
        }
    }

    pub fn regtest() -> Self {
        Self {
            maturity: 10,
            synthetic_span: 5,
            rsk_labs_divisor: 5,
            federation_divisor: 100,
            punishment_divisor: 10,
            publishers_divisor: 10,
            late_uncle_inclusion_punishment_divisor: 20,
            rsk_labs_address: "dabadabadabadabadabadabadabadabadaba0001"
                .parse()
                .unwrap(),
            rsk_labs_address_rskip218: "dabadabadabadabadabadabadabadabadaba0001"
                .parse()
                .unwrap(),
            rskip218_activation_height: 0,
            rskip85_activation_height: 0,
            minimum_payable_gas: 200_000,
            federator_minimum_payable_gas: 50_000,
            genesis_federation_public_keys:
                crate::bridge::constants::BridgeConstants::regtest().genesis_federation_public_keys,
        }
    }

    /// Returns the correct RSK Labs address for the given block height.
    pub fn labs_address_at(&self, block_number: u64) -> Address {
        if block_number >= self.rskip218_activation_height {
            self.rsk_labs_address_rskip218
        } else {
            self.rsk_labs_address
        }
    }
}

// ---------------------------------------------------------------------------
// Storage key encoding (matches rskj DataWord.fromString)
// ---------------------------------------------------------------------------

/// Encode a short ASCII key the same way rskj's `DataWord.fromString` does:
/// UTF-8 bytes right-aligned (left-padded with zeros) in a 32-byte big-endian word.
pub fn remasc_storage_key(name: &str) -> U256 {
    let bytes = name.as_bytes();
    debug_assert!(
        bytes.len() <= 32,
        "REMASC storage key must be <= 32 bytes"
    );
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    U256::from_be_bytes(buf)
}

pub const REWARD_BALANCE_KEY: &str = "rewardBalance";
pub const BURNED_BALANCE_KEY: &str = "burnedBalance";
pub const BROKEN_SELECTION_RULE_KEY: &str = "brokenSelectionRule";
pub const FEDERATION_BALANCE_KEY: &str = "federationBalance";

// ---------------------------------------------------------------------------
// Journal-based storage helpers
// ---------------------------------------------------------------------------

/// Read a `U256` coin value from REMASC contract storage via the journal.
pub fn remasc_sload<CTX: crate::RskContextTr>(ctx: &mut CTX, key: U256) -> U256 {
    ctx.journal_mut()
        .sload(REMASC_ADDR, key)
        .map(|sl| sl.data)
        .unwrap_or(U256::ZERO)
}

/// Write a `U256` coin value to REMASC contract storage via the journal.
pub fn remasc_sstore<CTX: crate::RskContextTr>(ctx: &mut CTX, key: U256, value: U256) {
    let _ = ctx.journal_mut().sstore(REMASC_ADDR, key, value);
}

/// Read a boolean flag from REMASC contract storage (0 = false, nonzero = true).
pub fn remasc_load_bool<CTX: crate::RskContextTr>(ctx: &mut CTX, key: U256) -> bool {
    remasc_sload(ctx, key) != U256::ZERO
}

/// Write a boolean flag to REMASC contract storage (false → 0, true → 1).
pub fn remasc_store_bool<CTX: crate::RskContextTr>(ctx: &mut CTX, key: U256, value: bool) {
    remasc_sstore(ctx, key, if value { U256::from(1) } else { U256::ZERO });
}

// ---------------------------------------------------------------------------
// Balance transfer helper
// ---------------------------------------------------------------------------

/// Transfer `amount` from the REMASC contract balance to `recipient`.
///
/// Uses `journal.transfer()` which atomically decrements the sender and
/// increments the recipient, matching rskj's `RemascFeesPayer.transferPayment`.
/// Returns `true` on success, `false` if REMASC has insufficient funds.
pub fn remasc_transfer<CTX: crate::RskContextTr>(ctx: &mut CTX, recipient: Address, amount: U256) -> bool {
    if amount.is_zero() {
        return true;
    }
    matches!(ctx.journal_mut().transfer(REMASC_ADDR, recipient, amount), Ok(None))
}

// ---------------------------------------------------------------------------
// Sibling struct and collection (Stage 6c)
// ---------------------------------------------------------------------------

/// A sibling is an uncle header whose `number` matches the processing block.
/// Matches rskj's `co.rsk.remasc.Sibling`.
#[derive(Debug, Clone)]
pub struct Sibling {
    pub hash: B256,
    pub coinbase: Address,
    pub paid_fees: U256,
    /// Coinbase of the block that included this uncle.
    pub included_block_coinbase: Address,
    /// Height of the block that included this uncle.
    pub included_height: u64,
    pub uncle_count: u64,
}

/// Collect siblings for the processing block from the canonical chain.
///
/// Walks blocks `candidate_number + 1` through `candidate_number + UNCLE_GENERATION_LIMIT`,
/// checking each block's ommers for headers with `number == candidate_number`.
fn collect_siblings(
    block_store: &BlockStore,
    candidate_number: u64,
    current_number: u64,
) -> Result<Vec<Sibling>, PrecompileError> {
    let mut siblings = Vec::new();
    let end = (candidate_number + UNCLE_GENERATION_LIMIT).min(current_number);

    for height in (candidate_number + 1)..=end {
        let hash = match block_store
            .canonical_hash(height)
            .map_err(|e| PrecompileError::other(format!("REMASC: {e}")))?
        {
            Some(h) => h,
            None => continue,
        };

        let including_header = block_store
            .header(hash)
            .map_err(|e| PrecompileError::other(format!("REMASC: {e}")))?;
        let including_header = match including_header {
            Some(h) => h,
            None => continue,
        };

        let body = block_store
            .body(hash)
            .map_err(|e| PrecompileError::other(format!("REMASC: {e}")))?;
        let (_, ommers) = body.unwrap_or_default();

        for ommer in &ommers {
            if ommer.number == candidate_number {
                siblings.push(Sibling {
                    hash: ommer.hash(),
                    coinbase: ommer.beneficiary,
                    paid_fees: ommer.paid_fees,
                    included_block_coinbase: including_header.beneficiary,
                    included_height: height,
                    uncle_count: ommer.uncle_count,
                });
            }
        }
    }

    Ok(siblings)
}

// ---------------------------------------------------------------------------
// Selection rule (Stage 6c)
// ---------------------------------------------------------------------------

/// Determines if the block selection rule was broken.
/// Matches rskj's `SelectionRule.isBrokenSelectionRule`.
///
/// The rule is broken if any sibling:
/// - paid more than 2x the processing block's fees, OR
/// - paid at least half the processing block's fees AND has a smaller hash, OR
/// - any sibling's uncle_count exceeds the processing block's uncle_count.
fn is_broken_selection_rule(processing: &Header, siblings: &[Sibling]) -> bool {
    let two = U256::from(2);
    let mut max_uncle_count: u64 = 0;

    for sibling in siblings {
        max_uncle_count = max_uncle_count.max(sibling.uncle_count);

        // sibling.paidFees > processing.paidFees * 2
        if sibling.paid_fees > processing.paid_fees * two {
            return true;
        }

        // processing.paidFees < sibling.paidFees * 2 AND sibling.hash < processing.hash
        if processing.paid_fees < sibling.paid_fees * two {
            let proc_hash = processing.hash();
            if sibling.hash.as_slice() < proc_hash.as_slice() {
                return true;
            }
        }
    }

    max_uncle_count > processing.uncle_count
}

// ---------------------------------------------------------------------------
// SiblingPaymentCalculator (Stage 6c)
// ---------------------------------------------------------------------------

/// Pre-computed reward splits for the with-siblings payment path.
/// Matches rskj's `SiblingPaymentCalculator`.
struct SiblingPayment {
    individual_publisher_reward: U256,
    publishers_surplus: U256,
    individual_miner_reward: U256,
    miners_surplus: U256,
    /// Per-miner punishment if previousBrokenSelectionRule; zero otherwise.
    punishment: U256,
}

impl SiblingPayment {
    fn calculate(
        full_block_reward: U256,
        previous_broken: bool,
        siblings_count: u64,
        config: &RemascConfig,
    ) -> Self {
        let publishers_reward = full_block_reward / U256::from(config.publishers_divisor);
        let miners_reward = full_block_reward - publishers_reward;

        let n = U256::from(siblings_count);
        let individual_publisher_reward = publishers_reward / n;
        let publishers_surplus = publishers_reward % n;

        let n_plus_1 = U256::from(siblings_count + 1);
        let individual_miner_base = miners_reward / n_plus_1;
        let miners_surplus = miners_reward % n_plus_1;

        let (individual_miner_reward, punishment) = if previous_broken {
            let p = individual_miner_base / U256::from(config.punishment_divisor);
            (individual_miner_base - p, p)
        } else {
            (individual_miner_base, U256::ZERO)
        };

        Self {
            individual_publisher_reward,
            publishers_surplus,
            individual_miner_reward,
            miners_surplus,
            punishment,
        }
    }
}

// ---------------------------------------------------------------------------
// Core algorithm: processMinersFees
// ---------------------------------------------------------------------------

/// rskj `RemascFeesPayer.payMiningFees`: transfer plus a `mining_fee_topic`
/// log (topics: [topic, payee-as-word], data: RLP([processingBlockHash, value])).
/// Format groundtruthed by the mainnet #4010 REMASC receipt.
fn pay_mining_fees<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    processing_block_hash: alloy_primitives::B256,
    to: Address,
    value: U256,
) {
    use alloy_rlp::Encodable;
    use revm::context_interface::JournalTr;

    remasc_transfer(ctx, to, value);

    let mut topic_payee = [0u8; 32];
    topic_payee[12..].copy_from_slice(to.as_slice());

    let mut inner = Vec::with_capacity(40);
    processing_block_hash.as_slice().encode(&mut inner);
    value.encode(&mut inner); // RLP.encodeCoin: unsigned minimal, empty for zero
    let mut data = Vec::with_capacity(inner.len() + 3);
    alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut data);
    data.extend_from_slice(&inner);

    ctx.journal_mut().log(revm::primitives::Log::new_unchecked(
        REMASC_ADDR,
        vec![
            crate::bridge::events::legacy_topic("mining_fee_topic"),
            alloy_primitives::B256::new(topic_payee),
        ],
        alloy_primitives::Bytes::from(data),
    ));
}

/// Active federation members as RSK addresses: the Bridge-stored federation,
/// or the genesis federation while none is stored. Members are ordered by
/// compressed BTC public key (rskj Federation constructor), groundtruthed by
/// the mainnet #4010 payout order.
fn federation_rsk_addresses<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &RemascConfig,
    bridge_config: &crate::bridge::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    processing_block_number: u64,
) -> Vec<Address> {
    // The Bridge account may be cold outside revm's transact flow; journal
    // storage reads require the account to be loaded.
    use revm::context_interface::JournalTr;
    let _ = ctx.journal_mut().load_account(crate::precompiles::BRIDGE_ADDR);
    let stored = crate::bridge::peg::federation_keys_or_genesis(
        ctx,
        bridge_config,
        hardfork_cfg,
        processing_block_number,
    );
    let _ = config;
    stored
        .iter()
        .filter_map(|k| crate::bridge::federation::rsk_address_from_public_key(k))
        .collect()
}

/// rskj `Remasc.payToFederation`: the accumulated federation balance plus this
/// block's cut, split evenly across the federators (remainder to the last one)
/// and paid every block before RSKIP85; afterwards it accrues until the
/// per-federator share clears the minimum payable amount.
fn pay_to_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &RemascConfig,
    bridge_config: &crate::bridge::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    processing_block_hash: alloy_primitives::B256,
    processing_block_number: u64,
    current_number: u64,
    synthetic_reward: U256,
) -> U256 {
    let federation_reward = synthetic_reward / U256::from(config.federation_divisor);
    let fed_key = remasc_storage_key(FEDERATION_BALANCE_KEY);
    let pay_total = remasc_sload(ctx, fed_key) + federation_reward;

    // rskj builds the REMASC FederationSupport with the PROCESSING block
    // (the matured one): the federation is resolved at that height, so a
    // newly committed federation is paid only once the processing block
    // itself passes the activation age (mainnet #667,426 still paid the
    // genesis federation).
    let federators = federation_rsk_addresses(
        ctx,
        config,
        bridge_config,
        hardfork_cfg,
        processing_block_number,
    );
    if federators.is_empty() {
        remasc_sstore(ctx, fed_key, pay_total);
        return federation_reward;
    }

    let n = U256::from(federators.len() as u64);
    let per_federator = pay_total / n;
    let remainder = pay_total % n;

    if current_number >= config.rskip85_activation_height {
        let min_payable = U256::from(ctx.block().basefee())
            * U256::from(config.federator_minimum_payable_gas);
        if per_federator < min_payable {
            remasc_sstore(ctx, fed_key, pay_total);
            return federation_reward;
        }
        remasc_sstore(ctx, fed_key, U256::ZERO);
    }
    // Before RSKIP85 the stored balance is never written and stays zero.

    let last = federators.len() - 1;
    for (k, federator) in federators.iter().enumerate() {
        let amount = if k == last { per_federator + remainder } else { per_federator };
        pay_mining_fees(ctx, processing_block_hash, *federator, amount);
    }
    federation_reward
}

/// Implements rskj's `Remasc.processMinersFees()`.
///
/// This runs when the REMASC precompile is called (last tx of each block).
/// It distributes fees from the block that matured `config.maturity` blocks ago.
pub fn process_miners_fees<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &RemascConfig,
    bridge_config: &crate::bridge::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    block_store: Option<&Arc<BlockStore>>,
) -> Result<(), PrecompileError> {
    let current_number = ctx.block().number().to::<u64>();

    let candidate_block_number = match current_number.checked_sub(config.maturity) {
        Some(n) if n >= 1 => n,
        _ => return Ok(()),
    };

    let block_store = block_store
        .ok_or_else(|| PrecompileError::other("REMASC: no block store configured"))?;

    // Find the processing block (the block whose fees are being distributed)
    let processing_hash = block_store
        .canonical_hash(candidate_block_number)
        .map_err(|e| PrecompileError::other(format!("REMASC: {e}")))?
        .ok_or_else(|| PrecompileError::other("REMASC: processing block not found"))?;

    let processing_header = block_store
        .header(processing_hash)
        .map_err(|e| PrecompileError::other(format!("REMASC: {e}")))?
        .ok_or_else(|| PrecompileError::other("REMASC: processing header not found"))?;

    // Accrue the processing block's fees into rewardBalance
    let reward_key = remasc_storage_key(REWARD_BALANCE_KEY);
    let mut reward_balance = remasc_sload(ctx, reward_key);
    reward_balance += processing_header.paid_fees;
    remasc_sstore(ctx, reward_key, reward_balance);

    // Synthetic span gate
    if candidate_block_number < config.synthetic_span {
        return Ok(());
    }

    // Collect siblings from descendant blocks
    let siblings = collect_siblings(block_store, candidate_block_number, current_number)?;

    // Selection rule
    let broken_key = remasc_storage_key(BROKEN_SELECTION_RULE_KEY);
    let previous_broken = remasc_load_bool(ctx, broken_key);
    let broken = is_broken_selection_rule(&processing_header, &siblings);
    remasc_store_bool(ctx, broken_key, !siblings.is_empty() && broken);

    // Calculate synthetic reward slice
    let synthetic_reward = reward_balance / U256::from(config.synthetic_span);

    // RSKIP85: skip distribution while the synthetic reward is below the
    // minimum payable amount (checked before debiting the reward balance).
    if current_number >= config.rskip85_activation_height {
        let min_payable =
            U256::from(ctx.block().basefee()) * U256::from(config.minimum_payable_gas);
        if synthetic_reward < min_payable {
            return Ok(());
        }
    }

    // Debit from reward balance
    reward_balance -= synthetic_reward;
    remasc_sstore(ctx, reward_key, reward_balance);

    // Pay RSK Labs (use RSKIP218 address if active)
    let rsk_labs_pay = synthetic_reward / U256::from(config.rsk_labs_divisor);
    let labs_addr = config.labs_address_at(current_number);
    pay_mining_fees(ctx, processing_hash, labs_addr, rsk_labs_pay);
    let mut remaining = synthetic_reward - rsk_labs_pay;

    // Pay the federation its cut (rskj Remasc.payToFederation)
    let federation_reward =
        pay_to_federation(
            ctx,
            config,
            bridge_config,
            hardfork_cfg,
            processing_hash,
            candidate_block_number,
            current_number,
            remaining,
        );
    remaining -= federation_reward;

    if !siblings.is_empty() {
        pay_with_siblings(ctx, config, processing_hash, &processing_header, remaining, &siblings, previous_broken);
    } else {
        // No-sibling path
        if previous_broken {
            let punishment = remaining / U256::from(config.punishment_divisor);
            remaining -= punishment;
            add_to_burned(ctx, punishment);
        }
        pay_mining_fees(ctx, processing_hash, processing_header.beneficiary, remaining);
    }

    Ok(())
}

/// Distribute rewards when siblings exist.
/// Matches rskj's `Remasc.payWithSiblings`.
fn pay_with_siblings<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &RemascConfig,
    processing_hash: alloy_primitives::B256,
    processing_header: &Header,
    full_block_reward: U256,
    siblings: &[Sibling],
    previous_broken: bool,
) {
    let calc = SiblingPayment::calculate(
        full_block_reward,
        previous_broken,
        siblings.len() as u64,
        config,
    );

    // Pay publishers (each sibling's included_block_coinbase)
    for sibling in siblings {
        pay_mining_fees(ctx, processing_hash, sibling.included_block_coinbase, calc.individual_publisher_reward);
    }
    add_to_burned(ctx, calc.publishers_surplus);
    add_to_burned(ctx, calc.miners_surplus);

    // Pay sibling miners with late-inclusion penalty
    let late_divisor = U256::from(config.late_uncle_inclusion_punishment_divisor);
    let processing_number = processing_header.number;
    for sibling in siblings {
        let blocks_late = sibling.included_height.saturating_sub(processing_number + 1);
        let late_punishment = calc.individual_miner_reward * U256::from(blocks_late) / late_divisor;
        let sibling_pay = calc.individual_miner_reward - late_punishment;
        pay_mining_fees(ctx, processing_hash, sibling.coinbase, sibling_pay);
        add_to_burned(ctx, late_punishment);
    }

    // Burn punishment for all miners if previous selection was broken
    if previous_broken {
        let total_punishment = calc.punishment * U256::from(siblings.len() as u64 + 1);
        add_to_burned(ctx, total_punishment);
    }

    // Pay main chain miner
    pay_mining_fees(ctx, processing_hash, processing_header.beneficiary, calc.individual_miner_reward);
}

/// Add amount to burnedBalance storage.
fn add_to_burned<CTX: crate::RskContextTr>(ctx: &mut CTX, amount: U256) {
    if amount.is_zero() {
        return;
    }
    let burned_key = remasc_storage_key(BURNED_BALANCE_KEY);
    let burned = remasc_sload(ctx, burned_key);
    remasc_sstore(ctx, burned_key, burned + amount);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_key_reward_balance() {
        let key = remasc_storage_key(REWARD_BALANCE_KEY);
        let bytes = key.to_be_bytes::<32>();
        // "rewardBalance" is 13 bytes, so positions 0..19 are zero
        assert_eq!(&bytes[..19], &[0u8; 19]);
        assert_eq!(&bytes[19..], b"rewardBalance");
    }

    #[test]
    fn storage_key_burned_balance() {
        let key = remasc_storage_key(BURNED_BALANCE_KEY);
        let bytes = key.to_be_bytes::<32>();
        // "burnedBalance" is 13 bytes, so positions 0..19 are zero
        assert_eq!(&bytes[..19], &[0u8; 19]);
        assert_eq!(&bytes[19..], b"burnedBalance");
    }

    #[test]
    fn storage_key_broken_selection_rule() {
        let key = remasc_storage_key(BROKEN_SELECTION_RULE_KEY);
        let bytes = key.to_be_bytes::<32>();
        // "brokenSelectionRule" is 19 bytes
        assert_eq!(&bytes[..13], &[0u8; 13]);
        assert_eq!(&bytes[13..], b"brokenSelectionRule");
    }

    #[test]
    fn storage_key_federation_balance() {
        let key = remasc_storage_key(FEDERATION_BALANCE_KEY);
        let bytes = key.to_be_bytes::<32>();
        // "federationBalance" is 17 bytes
        assert_eq!(&bytes[..15], &[0u8; 15]);
        assert_eq!(&bytes[15..], b"federationBalance");
    }

    #[test]
    fn remasc_config_mainnet_values() {
        let cfg = RemascConfig::mainnet();
        assert_eq!(cfg.maturity, 4000);
        assert_eq!(cfg.synthetic_span, 10);
        assert_eq!(cfg.rsk_labs_divisor, 5);
        assert_eq!(cfg.federation_divisor, 100);
        assert_eq!(cfg.punishment_divisor, 10);
        assert_eq!(cfg.publishers_divisor, 10);
        assert_eq!(cfg.late_uncle_inclusion_punishment_divisor, 20);
    }

    #[test]
    fn remasc_config_regtest_values() {
        let cfg = RemascConfig::regtest();
        assert_eq!(cfg.maturity, 10);
        assert_eq!(cfg.synthetic_span, 5);
    }

    #[test]
    fn remasc_config_testnet_values() {
        let cfg = RemascConfig::testnet();
        assert_eq!(cfg.maturity, 50);
        assert_eq!(cfg.synthetic_span, 10);
    }

    /// Verify that storage keys match rskj's DataWord.fromString encoding.
    ///
    /// In rskj, `DataWord.valueOf(byte[])` places data at offset `32 - len`
    /// (right-aligned, big-endian). We replicate this so our sload/sstore
    /// targets the same slots as rskj.
    #[test]
    fn storage_key_matches_rskj_dataword() {
        let key = remasc_storage_key("rewardBalance");
        let actual_hex = format!("{:064x}", key);
        assert_eq!(
            actual_hex,
            "0000000000000000000000000000000000000072657761726442616c616e6365",
            "storage key must match rskj DataWord.fromString"
        );
    }

    /// Cross-check against the hardcoded hex in rskj's RemascFeesPayerTest.java:
    ///   `"000000000000000000000000000000006d696e696e675f6665655f746f706963"`
    /// which is `DataWord.fromString("mining_fee_topic")` (16 bytes).
    /// This is an independent rskj test vector that validates our encoding
    /// function against a different string length.
    #[test]
    fn storage_key_matches_rskj_mining_fee_topic() {
        let key = remasc_storage_key("mining_fee_topic");
        let actual_hex = format!("{:064x}", key);
        assert_eq!(
            actual_hex,
            "000000000000000000000000000000006d696e696e675f6665655f746f706963",
            "must match rskj RemascFeesPayerTest line 77"
        );
    }

    /// Verify all four REMASC storage keys against manually computed hex values.
    /// Each hex is the UTF-8 bytes of the key name, right-aligned in 32 bytes.
    #[test]
    fn all_storage_keys_hex() {
        let cases = [
            (REWARD_BALANCE_KEY,         "0000000000000000000000000000000000000072657761726442616c616e6365"),
            (BURNED_BALANCE_KEY,         "000000000000000000000000000000000000006275726e656442616c616e6365"),
            (BROKEN_SELECTION_RULE_KEY,  "0000000000000000000000000062726f6b656e53656c656374696f6e52756c65"),
            (FEDERATION_BALANCE_KEY,     "00000000000000000000000000000066656465726174696f6e42616c616e6365"),
        ];
        for (name, expected) in &cases {
            let key = remasc_storage_key(name);
            let actual = format!("{:064x}", key);
            let expected_clean = expected.replace(' ', "");
            assert_eq!(actual, expected_clean, "key mismatch for {name}");
        }
    }

    // -----------------------------------------------------------------------
    // Stage 6c unit tests: SelectionRule + SiblingPaymentCalculator
    // -----------------------------------------------------------------------

    fn test_header(paid_fees: u64, uncle_count: u64) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::repeat_byte(0x01),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: alloy_primitives::Bloom::ZERO,
            extension_data: None,
            difficulty: U256::from(1_000_000),
            number: 5,
            gas_limit: U256::from(6_800_000),
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: alloy_primitives::Bytes::new(),
            paid_fees: U256::from(paid_fees),
            minimum_gas_price: U256::ZERO,
            uncle_count,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    fn test_sibling(paid_fees: u64, uncle_count: u64, hash_byte: u8) -> Sibling {
        let mut hash = B256::default();
        hash.0[0] = hash_byte;
        Sibling {
            hash,
            coinbase: Address::repeat_byte(0x22),
            paid_fees: U256::from(paid_fees),
            included_block_coinbase: Address::repeat_byte(0x33),
            included_height: 6,
            uncle_count,
        }
    }

    #[test]
    fn selection_rule_higher_fees_breaks() {
        let proc = test_header(10_000, 0);
        // sibling fees 25000 > 2 * 10000 = 20000 → broken
        let sibs = vec![test_sibling(25_000, 0, 0xFF)];
        assert!(is_broken_selection_rule(&proc, &sibs));
    }

    #[test]
    fn selection_rule_equal_fees_not_broken() {
        let proc = test_header(10_000, 0);
        // sibling fees 10000 not > 20000, and processing fees 10000 not < 20000
        let sibs = vec![test_sibling(10_000, 0, 0xFF)];
        assert!(!is_broken_selection_rule(&proc, &sibs));
    }

    #[test]
    fn selection_rule_lower_hash_breaks() {
        let mut proc = test_header(10_000, 0);
        // Ensure processing hash is high
        proc.extra_data = alloy_primitives::Bytes::copy_from_slice(&[0xFF; 20]);
        let proc_hash = proc.hash();

        // sibling fees within range but has lower hash
        let mut sib = test_sibling(6_000, 0, 0x00);
        sib.hash = B256::ZERO; // lower than any computed hash

        // 10000 < 6000*2=12000 AND sib.hash(00..) < proc.hash → broken
        if proc_hash.as_slice() > sib.hash.as_slice() {
            assert!(is_broken_selection_rule(&proc, &[sib]));
        }
    }

    #[test]
    fn selection_rule_more_uncles_breaks() {
        let proc = test_header(10_000, 1);
        // sibling has 2 uncles, processing has 1 → broken
        let sibs = vec![test_sibling(5_000, 2, 0xFF)];
        assert!(is_broken_selection_rule(&proc, &sibs));
    }

    #[test]
    fn selection_rule_no_siblings_not_broken() {
        let proc = test_header(10_000, 0);
        assert!(!is_broken_selection_rule(&proc, &[]));
    }

    #[test]
    fn payment_calculator_no_punishment() {
        let config = RemascConfig::regtest();
        let calc = SiblingPayment::calculate(
            U256::from(3327), false, 1, &config,
        );
        assert_eq!(calc.individual_publisher_reward, U256::from(332));
        assert_eq!(calc.publishers_surplus, U256::ZERO);
        assert_eq!(calc.individual_miner_reward, U256::from(1497));
        assert_eq!(calc.miners_surplus, U256::from(1));
        assert_eq!(calc.punishment, U256::ZERO);
    }

    #[test]
    fn payment_calculator_with_punishment() {
        let config = RemascConfig::regtest();
        let calc = SiblingPayment::calculate(
            U256::from(3327), true, 1, &config,
        );
        // punishment = 1497 / 10 = 149
        assert_eq!(calc.punishment, U256::from(149));
        assert_eq!(calc.individual_miner_reward, U256::from(1348));
    }

    #[test]
    fn payment_calculator_two_siblings() {
        let config = RemascConfig::regtest();
        let calc = SiblingPayment::calculate(
            U256::from(3327), false, 2, &config,
        );
        // publishersReward = 3327/10 = 332
        // individualPublisher = 332/2 = 166
        // publishersSurplus = 332%2 = 0
        assert_eq!(calc.individual_publisher_reward, U256::from(166));
        assert_eq!(calc.publishers_surplus, U256::ZERO);
        // minersReward = 3327 - 332 = 2995
        // individualMiner = 2995/3 = 998
        // minersSurplus = 2995%3 = 1
        assert_eq!(calc.individual_miner_reward, U256::from(998));
        assert_eq!(calc.miners_surplus, U256::from(1));
    }

    /// Groundtruth from the mainnet #4010 REMASC receipt: the mining_fee_topic
    /// word and the RLP data for a zero-value payment of block #10's hash.
    #[test]
    fn mining_fee_log_format_matches_mainnet_4010() {
        use alloy_rlp::Encodable;

        let topic = crate::bridge::events::legacy_topic("mining_fee_topic");
        assert_eq!(
            hex::encode(topic),
            "000000000000000000000000000000006d696e696e675f6665655f746f706963"
        );

        let block_hash: alloy_primitives::B256 =
            "0x6f086032613dfeb7f289c5d44c707a085d5b5b67b0139a5cdf70bbc9df46ff43".parse().unwrap();
        let mut inner = Vec::new();
        block_hash.as_slice().encode(&mut inner);
        U256::ZERO.encode(&mut inner);
        let mut data = Vec::new();
        alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut data);
        data.extend_from_slice(&inner);
        assert_eq!(
            hex::encode(&data),
            "e2a06f086032613dfeb7f289c5d44c707a085d5b5b67b0139a5cdf70bbc9df46ff4380"
        );
    }

    /// Groundtruth from the mainnet #4010 REMASC receipt: federators are paid
    /// in compressed-BTC-pubkey order; the first payee is 0x1888fa... and the
    /// last 0xf74b7e..., between the labs and miner payments.
    #[test]
    fn genesis_federation_payout_order_matches_mainnet_4010() {
        let config = RemascConfig::mainnet();
        let mut keys: Vec<Vec<u8>> = config
            .genesis_federation_public_keys
            .iter()
            .filter_map(|h| alloy_primitives::hex::decode(h).ok())
            .collect();
        keys.sort();
        let addrs: Vec<Address> = keys
            .iter()
            .filter_map(|k| crate::bridge::federation::rsk_address_from_public_key(k))
            .collect();
        assert_eq!(addrs.len(), 15);
        assert_eq!(addrs[0], "0x1888fa870b97a4845a6a1f7eee4ebb507dbe0967".parse::<Address>().unwrap());
        assert_eq!(addrs[1], "0x530aad5be57e9be2084881b1d84f2a30e896ae36".parse::<Address>().unwrap());
        assert_eq!(addrs[14], "0xf74b7e0d5bdd14eaedf725bb1549ce14abeb71dd".parse::<Address>().unwrap());
    }
}
