//! Bridge governance — federation voting, fee/whitelist/locking cap management.
//!
//! ## Federation lifecycle
//!
//! 1. `createFederation()` — creates a new pending federation (if none exists)
//! 2. `addFederatorPublicKey(bytes)` / `addFederatorPublicKeyMultikey(bytes,bytes,bytes)`
//!    — adds a member to the pending federation
//! 3. `commitFederation(bytes pendingHash)` — commits the pending federation
//!    as the new active federation, demoting the current one to retiring
//! 4. `rollbackFederation()` — discards the pending federation
//!
//! ## Other governance
//!
//! - `voteFeePerKbChange(int256)` — authorized vote on BTC fee per KB
//! - `addOneOffLockWhitelistAddress` / `addUnlimitedLockWhitelistAddress`
//!   / `removeLockWhitelistAddress` / `setLockWhitelistDisableBlockDelay`
//! - `increaseLockingCap(int256)` — increase the RBTC locking cap
//!
//! ## Lock whitelist
//!
//! The lock whitelist controls which BTC addresses can participate in peg-in.
//! Two whitelist variants:
//! - One-off: each address has a maximum transfer value and is removed after use.
//!   Stored under `lockWhitelist` key (pre and post-RSKIP87).
//! - Unlimited: no transfer limit. Stored under `unlimitedLockWhitelist` key (post-RSKIP87).
//!
//! Serialization matches rskj `BridgeSerializationUtils.serializeOneOffLockWhitelist`:
//!   RLP_list [ hash160_0, bigint(maxVal_0), ..., bigint(disableBlockHeight) ]

use alloy_primitives::{Bytes, U256};
use revm::context_interface::ContextTr;
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::serialization;
use super::storage::*;

// ---------------------------------------------------------------------------
// BTC address ABI decoding helpers
// ---------------------------------------------------------------------------

/// ABI-decode a `string` argument at the given parameter slot.
/// Returns the decoded UTF-8 string or an error.
fn abi_decode_string_arg(args: &[u8], slot: usize) -> Result<String, PrecompileError> {
    if args.len() < (slot + 1) * 32 {
        return Err(PrecompileError::other("governance: args too short for string param"));
    }
    let offset = U256::from_be_slice(&args[slot * 32..(slot + 1) * 32]).to::<usize>();
    if offset + 32 > args.len() {
        return Err(PrecompileError::other("governance: string offset out of bounds"));
    }
    let len = U256::from_be_slice(&args[offset..offset + 32]).to::<usize>();
    let data_start = offset + 32;
    if data_start + len > args.len() {
        return Err(PrecompileError::other("governance: string data out of bounds"));
    }
    String::from_utf8(args[data_start..data_start + len].to_vec())
        .map_err(|_| PrecompileError::other("governance: invalid UTF-8 in string"))
}

/// Decode a BTC address string (Base58Check) to its 20-byte hash160.
///
/// Matches rskj's `BridgeUtils.parseBtcAddressFromHex` / Address.fromBase58:
/// Base58Check decode → version byte + 20-byte hash160 + 4-byte checksum.
fn btc_address_to_hash160(addr_str: &str) -> Result<[u8; 20], PrecompileError> {
    let decoded = bitcoin::base58::decode_check(addr_str)
        .map_err(|_| PrecompileError::other("governance: invalid BTC address (bad Base58Check)"))?;
    if decoded.len() != 21 {
        return Err(PrecompileError::other("governance: BTC address decoded to wrong length"));
    }
    let mut hash160 = [0u8; 20];
    hash160.copy_from_slice(&decoded[1..21]);
    Ok(hash160)
}

/// ABI-decode an `int256` argument at the given parameter slot as a u64.
fn abi_decode_int256_as_u64(args: &[u8], slot: usize) -> Option<u64> {
    if args.len() < (slot + 1) * 32 {
        return None;
    }
    let word = &args[slot * 32..(slot + 1) * 32];
    // Only accept non-negative values that fit in u64 (leading bytes must be 0x00)
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    Some(u64::from_be_bytes(buf))
}

// ---------------------------------------------------------------------------
// Storage key constants for governance
// ---------------------------------------------------------------------------

// Use the shared constant from storage.rs
use super::storage::FEE_PER_KB_KEY;
const LOCKING_CAP_KEY: &str = "lockingCap";

// ---------------------------------------------------------------------------
// Federation change methods
// ---------------------------------------------------------------------------

/// Federation-change governance (rskj FederationSupportImpl
/// .voteFederationChange): createFederation / addFederatorPublicKey /
/// commitFederation / rollbackFederation are VOTES in an ABICallElection
/// keyed by (function, args); only a MAJORITY of the federation-change
/// authorizer keys executes the action. Mainnet block #648,926 carried the
/// first winning commit.

const FEDERATION_ELECTION_KEY: &str = "federationElection";

fn federation_change_authorizers(
    config: &super::constants::BridgeConstants,
) -> Vec<alloy_primitives::Address> {
    config
        .federation_change_authorizer_keys
        .iter()
        .filter_map(|hex| {
            alloy_primitives::hex::decode(hex)
                .ok()
                .and_then(|k| super::federation::rsk_address_from_public_key(&k))
        })
        .collect()
}

/// `createFederation()` → int256
pub fn create_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let code = vote_federation_change(ctx, "create", vec![], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `addFederatorPublicKey(bytes key)` → int256 (pre-RSKIP123 only)
pub fn add_federator_public_key<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let Ok(pubkey) = decode_bytes_arg(args) else {
        return Ok(encode_int_result(gas_cost, -10));
    };
    let code = vote_federation_change(ctx, "add", vec![pubkey], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `addFederatorPublicKeyMultikey(bytes btcKey, bytes rskKey, bytes mstKey)`
/// → int256 (post-RSKIP123)
pub fn add_federator_public_key_multikey<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    // TODO(rustock): multikey members (RSKIP123, wasabi100) store three keys
    // per member; the vote piping is in place but the pending-federation and
    // federation serialization formats must move to the member format before
    // the first post-wasabi federation change.
    let Ok(btc_key) = decode_bytes_arg(args) else {
        return Ok(encode_int_result(gas_cost, -10));
    };
    let code =
        vote_federation_change(ctx, "add-multi", vec![btc_key], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `commitFederation(bytes pendingHash)` → int256
pub fn commit_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let Ok(hash) = decode_bytes_arg(args) else {
        return Ok(encode_int_result(gas_cost, -10));
    };
    let code = vote_federation_change(ctx, "commit", vec![hash], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

/// `rollbackFederation()` → int256
pub fn rollback_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let code = vote_federation_change(ctx, "rollback", vec![], config, hardfork_cfg, tx_ctx);
    Ok(encode_int_result(gas_cost, code))
}

fn vote_federation_change<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    function: &str,
    args: Vec<Vec<u8>>,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> i64 {
    let authorizers = federation_change_authorizers(config);
    if !authorizers.contains(&tx_ctx.rsk_sender) {
        return -10; // UNAUTHORIZED_CALLER
    }

    // Dry-run first; only register the vote when the call would succeed.
    let dry = execute_federation_change(ctx, function, &args, true, config, hardfork_cfg);
    if dry != 1 {
        return dry;
    }

    let spec = super::vote::AbiCallSpec::new(function, args.clone());
    let mut election = super::vote::Election::load(ctx, FEDERATION_ELECTION_KEY);
    if !election.vote(&spec, tx_ctx.rsk_sender) {
        return -10; // GENERIC_ERROR (duplicate vote)
    }

    let required = authorizers.len() / 2 + 1;
    let mut code = 1i64;
    if let Some(winner) = election.winner(required) {
        code = execute_federation_change(ctx, function, &args, false, config, hardfork_cfg);
        // create/commit clear the whole election inside the action;
        // clearWinners then removes the winning entry.
        if matches!(function, "create" | "commit") && code == 1 {
            election.clear();
        } else {
            election.remove(winner);
        }
    }
    election.store(ctx, FEDERATION_ELECTION_KEY);
    code
}

/// rskj FederationSupportImpl.executeVoteFederationChangeFunction.
fn execute_federation_change<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    function: &str,
    args: &[Vec<u8>],
    dry_run: bool,
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) -> i64 {
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    match function {
        "create" => {
            if !bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY).is_empty() {
                return -1; // PENDING_FEDERATION_ALREADY_EXISTS
            }
            let new_fed = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
            let old_fed = super::federation::load_stored_federation(ctx, OLD_FEDERATION_KEY);
            let age = federation_activation_age(config, hardfork_cfg, block_number);
            if let (Some(new), Some(_)) = (&new_fed, &old_fed) {
                if block_number < new.creation_block + age {
                    return -2; // EXISTING_FEDERATION_AWAITING_ACTIVATION
                }
                return -3; // RETIRING_FEDERATION_ALREADY_EXISTS
            }
            if dry_run {
                return 1;
            }
            bridge_store_bytes_named(
                ctx,
                PENDING_FEDERATION_KEY,
                &serialize_pending_federation(&[]),
            );
            1
        }
        "add" | "add-multi" => {
            if function == "add" && hardfork_cfg.has_rskip123(block_number) {
                return -10; // "add" disabled post-RSKIP123
            }
            let pending_data = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
            if pending_data.is_empty() {
                return -1; // FEDERATION_NON_EXISTENT
            }
            let key_bytes = &args[0];
            // BtcECKey.fromPublicOnly failure -> BridgeIllegalArgumentException
            if k256::PublicKey::from_sec1_bytes(key_bytes).is_err() {
                return -10;
            }
            let mut members = deserialize_pending_federation(&pending_data);
            if members.iter().any(|k| k == key_bytes) {
                return -2; // FEDERATOR_ALREADY_PRESENT
            }
            if dry_run {
                return 1;
            }
            members.push(key_bytes.clone());
            bridge_store_bytes_named(
                ctx,
                PENDING_FEDERATION_KEY,
                &serialize_pending_federation(&members),
            );
            1
        }
        "commit" => {
            let pending_data = bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY);
            if pending_data.is_empty() {
                return -1; // FEDERATION_NON_EXISTENT
            }
            let members = deserialize_pending_federation(&pending_data);
            if members.len() < 2 {
                return -2; // INSUFFICIENT_MEMBERS
            }
            // PendingFederation.getHash: keccak over the sorted-keys RLP.
            let pending_hash = {
                use sha3::{Digest, Keccak256};
                Keccak256::digest(serialize_pending_federation(&members))
            };
            if args[0] != pending_hash[..] {
                return -3; // PENDING_FEDERATION_MISMATCHED_HASH
            }
            if dry_run {
                return 1;
            }
            commit_pending_federation(ctx, &members, config, hardfork_cfg);
            1
        }
        "rollback" => {
            if bridge_load_bytes_named(ctx, PENDING_FEDERATION_KEY).is_empty() {
                return -1; // FEDERATION_NON_EXISTENT
            }
            if dry_run {
                return 1;
            }
            bridge_store_bytes_named(ctx, PENDING_FEDERATION_KEY, &[]);
            1
        }
        _ => -10, // NON_EXISTING_FUNCTION_CALLED
    }
}

pub(crate) fn federation_activation_age(
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    block_number: u64,
) -> u64 {
    if hardfork_cfg.has_rskip383(block_number) {
        config.federation_activation_age
    } else {
        config.federation_activation_age_legacy
    }
}

/// rskj legacyCommitPendingFederation: build the federation from the pending
/// keys, move the active federation's UTXOs to the old-federation set, store
/// active as old / built as new, wipe the pending federation, and log the
/// legacy commit_federation event.
fn commit_pending_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    pending_keys: &[Vec<u8>],
    config: &super::constants::BridgeConstants,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
) {
    use revm::context_interface::Block as _;
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let timestamp = ctx.block().timestamp().to::<u64>();

    // Built federation: compressed sorted keys, creation time = block
    // timestamp (raw seconds value stored through Instant.ofEpochMilli
    // pre-RSKIP419), creation block = this block.
    let mut new_keys: Vec<[u8; 33]> = pending_keys
        .iter()
        .filter_map(|k| {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            let parsed = k256::PublicKey::from_sec1_bytes(k).ok()?;
            parsed.to_encoded_point(true).as_bytes().try_into().ok()
        })
        .collect();
    new_keys.sort();

    // Move active-federation UTXOs to the old set.
    let active_utxos = load_federation_utxos(ctx);
    store_federation_utxos(ctx, &[]);
    super::storage::store_old_federation_utxos(ctx, &active_utxos);

    // Current ACTIVE federation becomes the old one (genesis when none).
    let active = super::federation::load_stored_federation(ctx, NEW_FEDERATION_KEY);
    let (old_keys, old_time, old_block) = match &active {
        Some(fed) => (fed.keys.clone(), fed.creation_time_millis, fed.creation_block),
        None => (
            super::peg::genesis_federation_keys(config),
            config.genesis_federation_creation_time_millis,
            1,
        ),
    };

    bridge_store_bytes_named(
        ctx,
        OLD_FEDERATION_KEY,
        &super::federation::serialize_federation_only_btc_keys(&old_keys, old_time, old_block),
    );
    bridge_store_bytes_named(
        ctx,
        NEW_FEDERATION_KEY,
        &super::federation::serialize_federation_only_btc_keys(&new_keys, timestamp, block_number),
    );
    bridge_store_bytes_named(ctx, PENDING_FEDERATION_KEY, &[]);

    // Legacy commit_federation event (pre-RSKIP146).
    let old_redeem =
        super::peg::build_federation_redeem_script(&old_keys, old_keys.len() / 2 + 1);
    let new_redeem =
        super::peg::build_federation_redeem_script(&new_keys, new_keys.len() / 2 + 1);
    let activation =
        block_number + federation_activation_age(config, hardfork_cfg, block_number);
    super::events::log_legacy_commit_federation(
        ctx,
        &super::peg::redeem_script_hash160_pub(&old_redeem),
        &old_keys,
        &super::peg::redeem_script_hash160_pub(&new_redeem),
        &new_keys,
        activation,
    );
}

// ---------------------------------------------------------------------------
// Fee per KB voting
// ---------------------------------------------------------------------------

/// `voteFeePerKbChange(int256 feePerKb)` → int256
///
/// Authorized vote to change the BTC fee per KB for peg-out transactions.
///
/// rskj FeePerKbSupportImpl.voteFeePerKbChange: votes accumulate in an
/// ABICallElection stored under `feePerKbElection`; the fee only changes
/// when a MAJORITY of the authorizer keys vote the same value, after which
/// the election is cleared.
/// Returns 1 successful vote/winner, -1 negative fee or duplicate vote,
/// -2 fee above maximum, -10 unauthorized.
pub fn vote_fee_per_kb_change<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("voteFeePerKbChange: args too short"));
    }

    let authorizers: Vec<alloy_primitives::Address> = config
        .fee_per_kb_authorizer_keys
        .iter()
        .filter_map(|hex| {
            alloy_primitives::hex::decode(hex)
                .ok()
                .and_then(|k| super::federation::rsk_address_from_public_key(&k))
        })
        .collect();
    let sender = tx_ctx.rsk_sender;
    if !authorizers.contains(&sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    // Negative (int256 sign bit) or zero is not a positive coin.
    if args[0] & 0x80 != 0 {
        return Ok(encode_int_result(gas_cost, -1));
    }
    let fee_value = U256::from_be_slice(&args[..32]);
    if fee_value.is_zero() {
        return Ok(encode_int_result(gas_cost, -1));
    }
    if fee_value > U256::from(config.max_fee_per_kb) {
        return Ok(encode_int_result(gas_cost, -2));
    }
    let fee_satoshis = fee_value.to::<u64>();

    // MAJORITY of the authorizer set must vote the same value. Entries are
    // keyed by the RLP-ENCODED coin (serializeCoin) bytes, like rskj's
    // ABICallSpec arguments.
    let required = authorizers.len() / 2 + 1;
    let coin_encoded = serialization::rlp_encode_u64(fee_satoshis);
    let mut election = load_fee_per_kb_election(ctx);
    let entry = election
        .iter_mut()
        .find(|(value, _)| *value == coin_encoded);
    let voters = match entry {
        Some((_, voters)) => voters,
        None => {
            election.push((coin_encoded, Vec::new()));
            &mut election.last_mut().expect("just pushed").1
        }
    };
    if voters.contains(&sender) {
        return Ok(encode_int_result(gas_cost, -1)); // duplicate vote
    }
    voters.push(sender);

    if voters.len() >= required {
        // rskj setFeePerKb: serializeCoin (RLP).
        bridge_store_u256(ctx, FEE_PER_KB_KEY, U256::from(fee_satoshis));
        store_fee_per_kb_election(ctx, &[]);
    } else {
        store_fee_per_kb_election(ctx, &election);
    }

    Ok(encode_int_result(gas_cost, 1))
}

const FEE_PER_KB_ELECTION_KEY: &str = "feePerKbElection";

/// rskj BridgeSerializationUtils.serializeElection for the feePerKb
/// election: RLP list of (ABICallSpec, voters) pairs sorted by the
/// serialized spec bytes. The spec is
/// `RLP[ "setFeePerKb", RLP[ rlp(serializeCoin(fee)) ] ]` and the voters a
/// sorted RLP list of 20-byte addresses.
fn serialize_fee_per_kb_spec(coin_encoded: &[u8]) -> Vec<u8> {
    use super::serialization::{rlp_encode_element, rlp_encode_list};
    let args = rlp_encode_list(&[rlp_encode_element(coin_encoded)]);
    rlp_encode_list(&[rlp_encode_element(b"setFeePerKb"), args])
}

fn store_fee_per_kb_election<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    election: &[(Vec<u8>, Vec<alloy_primitives::Address>)],
) {
    use super::serialization::{rlp_encode_element, rlp_encode_list};
    let mut entries: Vec<(Vec<u8>, &Vec<alloy_primitives::Address>)> = election
        .iter()
        .map(|(coin, voters)| (serialize_fee_per_kb_spec(coin), voters))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut items = Vec::with_capacity(entries.len() * 2);
    for (spec, voters) in entries {
        items.push(spec);
        let mut sorted: Vec<&alloy_primitives::Address> = voters.iter().collect();
        sorted.sort();
        let voter_items: Vec<Vec<u8>> = sorted
            .iter()
            .map(|v| rlp_encode_element(v.as_slice()))
            .collect();
        items.push(rlp_encode_list(&voter_items));
    }
    let data = rlp_encode_list(&items);
    bridge_store_bytes_named(ctx, FEE_PER_KB_ELECTION_KEY, &data);
}

fn load_fee_per_kb_election<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
) -> Vec<(Vec<u8>, Vec<alloy_primitives::Address>)> {
    use super::serialization::rlp_decode_list;
    let data = bridge_load_bytes_named(ctx, FEE_PER_KB_ELECTION_KEY);
    if data.is_empty() {
        return Vec::new();
    }
    let Some(items) = rlp_decode_list(&data) else {
        return Vec::new();
    };
    let mut election = Vec::new();
    let mut i = 0;
    while i + 1 < items.len() {
        // spec: RLP[function, RLP[args]]; the argument is kept as the
        // RLP-encoded coin bytes (rskj compares raw spec arguments).
        let coin = rlp_decode_list(&items[i])
            .filter(|spec| spec.len() == 2 && spec[0] == b"setFeePerKb")
            .and_then(|spec| rlp_decode_list(&spec[1]))
            .and_then(|args| args.first().cloned());
        let voters = rlp_decode_list(&items[i + 1])
            .map(|vs| {
                vs.into_iter()
                    .filter(|v| v.len() == 20)
                    .map(|v| alloy_primitives::Address::from_slice(&v))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(coin) = coin {
            election.push((coin, voters));
        }
        i += 2;
    }
    election
}

// ---------------------------------------------------------------------------
// Locking cap
// ---------------------------------------------------------------------------

/// `increaseLockingCap(int256 newCap)` → bool
///
/// Increases the RBTC locking cap. Can only increase, never decrease.
/// Returns true if successful.
pub fn increase_locking_cap<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("increaseLockingCap: args too short"));
    }

    let new_cap = U256::from_be_slice(&args[..32]);

    let current_cap = bridge_load_u256(ctx, LOCKING_CAP_KEY);

    // Can only increase
    if new_cap <= current_cap {
        let output = [0u8; 32];
        return Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()));
    }

    // rskj setLockingCap: serializeCoin (RLP).
    bridge_store_u256(ctx, LOCKING_CAP_KEY, new_cap);

    let mut output = [0u8; 32];
    output[31] = 1; // true
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// Whitelist management
// ---------------------------------------------------------------------------

/// `addLockWhitelistAddress(string address, int256 maxTransferValue)` → int256
///
/// Legacy alias for `addOneOffLockWhitelistAddress` (per rskj BridgeMethods.java).
/// Adds a one-off entry with the given max transfer value.
///
/// Returns:
///   1  = success
///  -1  = address already in whitelist
///  -2  = invalid address
pub fn add_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    add_one_off_lock_whitelist_address(ctx, args, gas_cost, config, tx_ctx)
}

/// rskj AddressBasedAuthorizer (minimum ONE): the tx sender must be the RSK
/// address of one of the whitelist-change authorizer keys.
fn is_whitelist_change_authorized(
    config: &super::constants::BridgeConstants,
    sender: alloy_primitives::Address,
) -> bool {
    config.whitelist_authorizer_keys.iter().any(|hex| {
        alloy_primitives::hex::decode(hex)
            .ok()
            .and_then(|k| super::federation::rsk_address_from_public_key(&k))
            .is_some_and(|a| a == sender)
    })
}

/// `addOneOffLockWhitelistAddress(string address, int256 maxTransferValue)` → int256
///
/// Adds a one-off entry to the lock whitelist.
/// The entry allows one peg-in up to `maxTransferValue` satoshis.
///
/// Returns:
///   1  = success
///  -1  = address already in whitelist
///  -2  = invalid address
pub fn add_one_off_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let addr_str = match abi_decode_string_arg(args, 0) {
        Ok(s) => s,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    let hash160 = match btc_address_to_hash160(&addr_str) {
        Ok(h) => h,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    let max_val = match abi_decode_int256_as_u64(args, 1) {
        Some(v) => v,
        None => return Ok(encode_int_result(gas_cost, -2)),
    };

    if !is_whitelist_change_authorized(config, tx_ctx.rsk_sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    let (mut entries, disable_h) = load_one_off_whitelist(ctx);

    // Duplicates across BOTH whitelists (rskj LockWhitelist.isWhitelisted)
    if entries.iter().any(|(h, _)| h == &hash160)
        || load_unlimited_whitelist(ctx).contains(&hash160)
    {
        return Ok(encode_int_result(gas_cost, -1));
    }

    entries.push((hash160, max_val));
    store_one_off_whitelist(ctx, &entries, disable_h);

    Ok(encode_int_result(gas_cost, 1))
}

/// `addUnlimitedLockWhitelistAddress(string address)` → int256
///
/// Adds an unlimited entry to the lock whitelist (active post-RSKIP87).
/// Unlimited entries have no transfer cap and are never consumed.
///
/// Returns:
///   1  = success
///  -1  = address already in unlimited whitelist
///  -2  = invalid address
pub fn add_unlimited_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    let addr_str = match abi_decode_string_arg(args, 0) {
        Ok(s) => s,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    let hash160 = match btc_address_to_hash160(&addr_str) {
        Ok(h) => h,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    if !is_whitelist_change_authorized(config, tx_ctx.rsk_sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    let mut entries = load_unlimited_whitelist(ctx);

    // Duplicates across BOTH whitelists (rskj LockWhitelist.isWhitelisted)
    if entries.iter().any(|h| h == &hash160)
        || load_one_off_whitelist(ctx).0.iter().any(|(h, _)| h == &hash160)
    {
        return Ok(encode_int_result(gas_cost, -1));
    }

    entries.push(hash160);
    store_unlimited_whitelist(ctx, &entries);

    Ok(encode_int_result(gas_cost, 1))
}

/// `removeLockWhitelistAddress(string address)` → int256
///
/// Removes an address from either the one-off or unlimited lock whitelist.
///
/// Returns:
///   1  = success
///  -1  = address not found
///  -2  = invalid address
pub fn remove_lock_whitelist_address<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    if !is_whitelist_change_authorized(config, tx_ctx.rsk_sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    let addr_str = match abi_decode_string_arg(args, 0) {
        Ok(s) => s,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    let hash160 = match btc_address_to_hash160(&addr_str) {
        Ok(h) => h,
        Err(_) => return Ok(encode_int_result(gas_cost, -2)),
    };

    // Try to remove from one-off whitelist first
    let (mut one_off, disable_h) = load_one_off_whitelist(ctx);
    let before_len = one_off.len();
    one_off.retain(|(h, _)| h != &hash160);
    if one_off.len() < before_len {
        store_one_off_whitelist(ctx, &one_off, disable_h);
        return Ok(encode_int_result(gas_cost, 1));
    }

    // Try unlimited whitelist
    let mut unlimited = load_unlimited_whitelist(ctx);
    let before_len = unlimited.len();
    unlimited.retain(|h| h != &hash160);
    if unlimited.len() < before_len {
        store_unlimited_whitelist(ctx, &unlimited);
        return Ok(encode_int_result(gas_cost, 1));
    }

    Ok(encode_int_result(gas_cost, -1))
}

/// `setLockWhitelistDisableBlockDelay(int256 delay)` → int256
///
/// rskj WhitelistSupportImpl: sets the whitelist disable height to the BTC
/// best-chain height plus the delay, inside the one-off whitelist blob.
/// Returns 1 success, -1 delay already set, -2 invalid delay,
/// -10 unauthorized.
pub fn set_lock_whitelist_disable_block_delay<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &super::constants::BridgeConstants,
    tx_ctx: &crate::precompiles::BridgeTxContext,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other(
            "setLockWhitelistDisableBlockDelay: args too short",
        ));
    }

    if !is_whitelist_change_authorized(config, tx_ctx.rsk_sender) {
        return Ok(encode_int_result(gas_cost, -10));
    }

    let (entries, disable_h) = load_one_off_whitelist(ctx);
    if disable_h < i32::MAX {
        return Ok(encode_int_result(gas_cost, -1)); // delay already set
    }

    let delay = U256::from_be_slice(&args[..32]).to::<u64>() as i64;
    let best_height = super::btc_store::load_chain_head(ctx)
        .map(|h| h.height as i64)
        .unwrap_or(0);
    if delay + best_height <= best_height {
        return Ok(encode_int_result(gas_cost, -2)); // invalid delay
    }

    store_one_off_whitelist(ctx, &entries, (best_height + delay) as i32);

    Ok(encode_int_result(gas_cost, 1))
}

// ---------------------------------------------------------------------------
// Read-only governance methods
// ---------------------------------------------------------------------------

/// `getActivePowpegRedeemScript()` → bytes
pub fn get_active_powpeg_redeem_script<CTX: crate::RskContextTr>(
    _ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Return empty bytes (no federation configured yet)
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

/// `getActiveFederationCreationBlockHeight()` → uint256
pub fn get_active_federation_creation_block_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let val = bridge_load_u256(ctx, ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY);
    let output = val.to_be_bytes::<32>();
    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Federation RLP serialization (matching BridgeSerializationUtils)
// ---------------------------------------------------------------------------

/// Serialize a pending federation as an RLP list of member public keys.
fn serialize_pending_federation(member_keys: &[Vec<u8>]) -> Vec<u8> {
    // rskj PendingFederation.serializeOnlyBtcKeys sorts by the key bytes
    // (BtcECKey.PUBKEY_COMPARATOR); the keccak of this serialization is the
    // hash the commit vote must match.
    let mut sorted = member_keys.to_vec();
    sorted.sort();
    let encoded_keys: Vec<Vec<u8>> = sorted
        .iter()
        .map(|k| serialization::rlp_encode_element(k))
        .collect();
    serialization::rlp_encode_list(&encoded_keys)
}

/// Deserialize a pending federation from RLP → list of member public keys.
fn deserialize_pending_federation(data: &[u8]) -> Vec<Vec<u8>> {
    serialization::rlp_decode_list(data).unwrap_or_default()
}


/// Decode a single `bytes` ABI argument from calldata.
fn decode_bytes_arg(args: &[u8]) -> Result<Vec<u8>, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("bytes arg: too short"));
    }
    let offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    if offset + 32 > args.len() {
        return Err(PrecompileError::other("bytes arg: offset out of bounds"));
    }
    let len = U256::from_be_slice(&args[offset..offset + 32]).to::<usize>();
    let start = offset + 32;
    if start + len > args.len() {
        return Err(PrecompileError::other("bytes arg: data out of bounds"));
    }
    Ok(args[start..start + len].to_vec())
}

fn encode_int_result(gas_cost: u64, value: i64) -> PrecompileOutput {
    let mut output = [0u8; 32];
    if value >= 0 {
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        output = [0xFF; 32];
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    }
    PrecompileOutput::new(gas_cost, output.to_vec().into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_int_success() {
        let out = encode_int_result(0, 1);
        assert_eq!(out.bytes[31], 1);
    }

    #[test]
    fn encode_int_error() {
        let out = encode_int_result(0, -1);
        assert!(out.bytes.iter().all(|&b| b == 0xFF));
    }

    // -----------------------------------------------------------------------
    // Federation serialization tests — ported from rskj
    // BridgeSerializationUtilsTest.serializeAndDeserializeFederationOnlyBtcKeys
    // -----------------------------------------------------------------------

    /// Ported from rskj: pending federation roundtrip (list of public keys).
    #[test]
    fn rskj_pending_federation_roundtrip() {
        let keys: Vec<Vec<u8>> = vec![
            vec![0x02; 33],
            vec![0x03; 33],
            vec![0x04; 33],
        ];

        let encoded = serialize_pending_federation(&keys);
        let decoded = deserialize_pending_federation(&encoded);

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], keys[0]);
        assert_eq!(decoded[1], keys[1]);
        assert_eq!(decoded[2], keys[2]);
    }

    /// Ported from rskj: empty pending federation.
    #[test]
    fn rskj_pending_federation_empty() {
        let keys: Vec<Vec<u8>> = vec![];
        let encoded = serialize_pending_federation(&keys);
        let decoded = deserialize_pending_federation(&encoded);
        assert!(decoded.is_empty());
    }

    /// Ported from rskj: committed federation roundtrip with known values.
    /// Matches BridgeSerializationUtilsTest pattern: 6 keys, creation_time=5000,
/// rskj serializeFederationOnlyBtcKeys layout:
    /// RLP[creationTime(millis), creationBlockNumber, RLP[keys...]] with
    /// keys sorted lexicographically.
    #[test]
    fn rskj_federation_only_btc_keys_roundtrip() {
        let mut keys: Vec<[u8; 33]> = (100u8..106).map(|i| [i; 33]).collect();
        keys.reverse(); // serializer must sort

        let encoded =
            super::super::federation::serialize_federation_only_btc_keys(&keys, 5000, 42);
        let decoded = serialization::rlp_decode_list(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(serialization::rlp_decode_u64(&decoded[0]), 5000);
        assert_eq!(serialization::rlp_decode_u64(&decoded[1]), 42);
        let decoded_keys = serialization::rlp_decode_list(&decoded[2]).unwrap();
        assert_eq!(decoded_keys.len(), 6);
        assert_eq!(decoded_keys[0], vec![100u8; 33], "keys sorted");
    }
}
