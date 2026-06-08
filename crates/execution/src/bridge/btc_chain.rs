//! BTC header chain validation for the Bridge.
//!
//! Implements `receiveHeader` and `receiveHeaders` — the methods that allow
//! relayers to submit BTC block headers to the Bridge contract, building
//! an SPV header chain in contract storage.
//!
//! Error codes (matching rskj):
//! -  1: success
//! - -1: block already known
//! - -2: called too soon (rate limiting)
//! - -3: previous block not found
//! - -4: too far ahead of chain tip
//! - -5: invalid proof of work

use alloy_primitives::{Bytes, U256};
use bitcoin::block::Header as BtcHeader;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::BlockHash;
use revm::context_interface::{Block as BlockTr, ContextTr};
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::btc_store::{
    check_proof_of_work, compute_work, get_stored_block, load_chain_head, put_stored_block,
    store_chain_head, StoredBlock,
};
use super::constants::BridgeConstants;
use crate::hardfork::RskHardforkConfig;

// Error codes
const SUCCESS: i64 = 1;
const ERR_ALREADY_KNOWN: i64 = -1;
const ERR_TOO_SOON: i64 = -2;
const ERR_PREV_NOT_FOUND: i64 = -3;
const ERR_INVALID_POW: i64 = -5;

/// Process a single BTC header submitted via `receiveHeader(bytes)`.
///
/// Returns ABI-encoded int256 result code.
pub fn receive_header<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    config: &BridgeConstants,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let gas_cost = 10_600u64;

    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);

    // Decode ABI-encoded `bytes` argument
    let header_bytes = decode_abi_bytes(args).ok_or_else(|| {
        PrecompileError::other("receiveHeader: invalid ABI encoding")
    })?;

    // Rate limiting
    let last_timestamp =
        super::storage::bridge_load_timestamp(ctx, super::storage::RECEIVE_HEADERS_TIMESTAMP_KEY);
    let current_timestamp = ctx.block().timestamp();

    if config.min_seconds_between_calls_receive_header > 0
        && current_timestamp < last_timestamp + config.min_seconds_between_calls_receive_header
    {
        return Ok(encode_int_result(gas_cost, ERR_TOO_SOON));
    }

    // Deserialize BTC header (80 bytes)
    if header_bytes.len() < 80 {
        return Err(PrecompileError::other("receiveHeader: header too short"));
    }

    let btc_header: BtcHeader = deserialize(&header_bytes[..80])
        .map_err(|_| PrecompileError::other("receiveHeader: invalid BTC header"))?;

    let block_hash = btc_header.block_hash();

    // Check if already known
    if get_stored_block(ctx, &block_hash).is_some() {
        return Ok(encode_int_result(gas_cost, ERR_ALREADY_KNOWN));
    }

    // Check PoW
    if !check_proof_of_work(&btc_header) {
        return Ok(encode_int_result(gas_cost, ERR_INVALID_POW));
    }

    // Find parent
    let parent = get_stored_block(ctx, &btc_header.prev_blockhash);
    let parent = match parent {
        Some(p) => p,
        None => return Ok(encode_int_result(gas_cost, ERR_PREV_NOT_FOUND)),
    };

    // Compute chain work
    let work = compute_work(btc_header.bits);
    let new_chain_work = parent.chain_work.wrapping_add(work);
    let new_height = parent.height + 1;

    let stored = StoredBlock::new(btc_header, new_height, new_chain_work);

    // Store the block
    put_stored_block(ctx, &stored, use_v2);

    // Update chain head if this extends the best chain
    let is_new_best = match load_chain_head(ctx) {
        Some(head) => new_chain_work > head.chain_work,
        None => true,
    };

    if is_new_best {
        set_chain_head(ctx, &stored, use_v2, rskip199);
    }

    // Update timestamp (rskj serializeLong -> RLP)
    super::storage::bridge_store_timestamp(
        ctx,
        super::storage::RECEIVE_HEADERS_TIMESTAMP_KEY,
        current_timestamp.to::<u64>(),
    );

    Ok(encode_int_result(gas_cost, SUCCESS))
}

/// Update the chain head (rskj `RepositoryBtcBlockStoreWithCache.setChainHead`
/// + `setMainChainBlock`): the height->hash main-chain index only exists from
/// RSKIP199 (iris300).
fn set_chain_head<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    stored: &StoredBlock,
    use_v2: bool,
    rskip199: bool,
) {
    store_chain_head(ctx, stored, use_v2);
    if rskip199 {
        super::storage::bridge_store_btc_block_hash_by_height(
            ctx,
            stored.height,
            bitcoin_hash_to_b256(&stored.header.block_hash()),
        );
    }
}

/// rskj `BtcBlockStoreWithCache.getStoredBlockAtMainChainHeight`: the
/// main-chain block at `height`.
///
/// rskj only persists the height→hash index from RSKIP199 (iris300); before
/// that it WALKS the main chain from the head down `depth = head - height`
/// parents (`getStoredBlockAtMainChainDepth`). We mirror that exactly — the
/// index is empty pre-RSKIP199, so a height lookup must walk. Returns `None`
/// when the height is above the head or the chain cannot be walked to it.
pub(crate) fn stored_block_at_main_chain_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    height: u32,
    rskip199: bool,
) -> Option<StoredBlock> {
    let head = load_chain_head(ctx)?;
    if height > head.height {
        return None; // depth < 0: above the chain head
    }
    let depth = head.height - height;

    // From RSKIP199, the indexed lookup; it may be absent for blocks below the
    // index activation, in which case rskj falls back to the walk.
    if rskip199 {
        if let Some(hash) = super::storage::bridge_load_btc_block_hash_by_height(ctx, height) {
            return get_stored_block(ctx, &b256_to_bitcoin_hash(&hash));
        }
    }

    // Walk `depth` parents down from the head (getStoredBlockAtMainChainDepth).
    let mut block_hash = head.header.block_hash();
    for _ in 0..depth {
        block_hash = get_stored_block(ctx, &block_hash)?.header.prev_blockhash;
    }
    let block = get_stored_block(ctx, &block_hash)?;
    (block.height == height).then_some(block)
}

/// Seed the bridge BTC chain on first use. rskj does this in two steps that
/// both persist: `RepositoryBtcBlockStoreWithCache.checkIfInitialized` writes
/// the BTC GENESIS stored block as chain head, then
/// `BridgeSupport.ensureBtcBlockStore` runs bitcoinj's
/// `CheckpointManager.checkpoint`, which adds the checkpoint block (see
/// `BridgeConstants::btc_checkpoint`) and moves the chain head to it — BOTH
/// stored-block entries remain in bridge storage (mainnet block #457).
pub fn ensure_btc_chain_seeded<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    config: &BridgeConstants,
    use_v2: bool,
    rskip199: bool,
) {
    if load_chain_head(ctx).is_some() {
        return;
    }

    let network = match config.btc_network {
        super::constants::BtcNetwork::Mainnet => bitcoin::Network::Bitcoin,
        super::constants::BtcNetwork::Testnet => bitcoin::Network::Testnet,
        super::constants::BtcNetwork::Regtest => bitcoin::Network::Regtest,
    };
    let genesis = bitcoin::constants::genesis_block(network);
    let genesis_stored = StoredBlock::new(genesis.header, 0, compute_work(genesis.header.bits));
    put_stored_block(ctx, &genesis_stored, use_v2);

    let head = match config.btc_checkpoint {
        Some((header_hex, height, chain_work_hex)) => {
            let bytes = match alloy_primitives::hex::decode(header_hex) {
                Ok(b) => b,
                Err(_) => return,
            };
            let header: BtcHeader = match deserialize(&bytes) {
                Ok(h) => h,
                Err(_) => return,
            };
            let work = U256::from_be_slice(&alloy_primitives::hex::decode(chain_work_hex).unwrap_or_default());
            let checkpoint = StoredBlock::new(header, height, work);
            put_stored_block(ctx, &checkpoint, use_v2);
            checkpoint
        }
        None => genesis_stored,
    };

    set_chain_head(ctx, &head, use_v2, rskip199);
}

pub fn receive_headers<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    let headers = decode_abi_bytes_array(args).ok_or_else(|| {
        PrecompileError::other("receiveHeaders: invalid ABI encoding")
    })?;

    // NOTE: rskj's receiveHeaders has NO rate limiting — the
    // minSecondsBetweenCallsToReceiveHeader window only applies to the
    // singular receiveHeader (RSKIP200). The federation calls this every
    // few blocks.
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let rskip434 = hardfork_cfg.has_rskip434(block_number);
    let rskip199 = hardfork_cfg.has_rskip199(block_number);

    ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);
    let is_mainnet = matches!(config.btc_network, super::constants::BtcNetwork::Mainnet);

    let max_headers = config.max_btc_headers_per_rsk_block as usize;
    let count = headers.len().min(max_headers);

    let mut processed = 0i64;

    for header_bytes in headers.iter().take(count) {
        if header_bytes.len() < 80 {
            continue;
        }

        let btc_header: BtcHeader = match deserialize(&header_bytes[..80]) {
            Ok(h) => h,
            Err(_) => continue,
        };

        let block_hash = btc_header.block_hash();

        // Skip if already known
        if get_stored_block(ctx, &block_hash).is_some() {
            continue;
        }

        // Check PoW
        if !check_proof_of_work(&btc_header) {
            continue;
        }

        // Find parent
        let parent = match get_stored_block(ctx, &btc_header.prev_blockhash) {
            Some(p) => p,
            None => continue,
        };

        // rskj cannotProcessNextBlock: bitcoinj's 12-byte chainwork
        // overflows at BTC mainnet #849,138; headers from there cannot be
        // processed until RSKIP434.
        if parent.height + 1 >= config.block_with_too_much_chain_work_height
            && is_mainnet
            && !rskip434
        {
            break;
        }

        let work = compute_work(btc_header.bits);
        let new_chain_work = parent.chain_work.wrapping_add(work);
        let new_height = parent.height + 1;

        let stored = StoredBlock::new(btc_header, new_height, new_chain_work);
        put_stored_block(ctx, &stored, use_v2);

        let is_new_best = match load_chain_head(ctx) {
            Some(head) => new_chain_work > head.chain_work,
            None => true,
        };

        if is_new_best {
            set_chain_head(ctx, &stored, use_v2, rskip199);
        }

        processed += 1;
    }

    Ok(encode_int_result(gas_cost, processed))
}

// ---------------------------------------------------------------------------
// BTC chain query methods
// ---------------------------------------------------------------------------

/// `getBtcBlockchainBestChainHeight()` → int256
pub fn get_best_chain_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let height = match load_chain_head(ctx) {
        Some(head) => head.height as i64,
        None => 0,
    };
    Ok(encode_int_result(gas_cost, height))
}

/// `getBtcBlockchainBestBlockHeader()` → bytes
pub fn get_best_block_header<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    match load_chain_head(ctx) {
        Some(head) => {
            let header_bytes = serialize(&head.header);
            Ok(PrecompileOutput::new(gas_cost, encode_abi_bytes(&header_bytes).into()))
        }
        None => Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    }
}

/// `getBtcBlockchainBlockHeaderByHash(bytes32)` → bytes
pub fn get_block_header_by_hash<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("getBlockHeaderByHash: args too short"));
    }

    let hash = b256_to_bitcoin_hash(&alloy_primitives::B256::from_slice(&args[..32]));

    match get_stored_block(ctx, &hash) {
        Some(block) => {
            let header_bytes = serialize(&block.header);
            Ok(PrecompileOutput::new(gas_cost, encode_abi_bytes(&header_bytes).into()))
        }
        None => Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    }
}

/// `getBtcBlockchainBlockHeaderByHeight(uint256)` → bytes
pub fn get_block_header_by_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("getBlockHeaderByHeight: args too short"));
    }

    let height_u256 = U256::from_be_slice(&args[..32]);
    let height = height_u256.to::<u32>();

    // Look up hash by height, then get the block
    let hash_b256 = super::storage::bridge_load_btc_block_hash_by_height(ctx, height);
    let hash = match hash_b256 {
        Some(h) => b256_to_bitcoin_hash(&h),
        None => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };

    match get_stored_block(ctx, &hash) {
        Some(block) => {
            let header_bytes = serialize(&block.header);
            Ok(PrecompileOutput::new(gas_cost, encode_abi_bytes(&header_bytes).into()))
        }
        None => Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    }
}

/// `getBtcBlockchainParentBlockHeaderByHash(bytes32)` → bytes
pub fn get_parent_block_header_by_hash<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other("getParentBlockHeaderByHash: args too short"));
    }

    let hash = b256_to_bitcoin_hash(&alloy_primitives::B256::from_slice(&args[..32]));

    let block = match get_stored_block(ctx, &hash) {
        Some(b) => b,
        None => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };

    let parent = match get_stored_block(ctx, &block.header.prev_blockhash) {
        Some(p) => p,
        None => return Ok(PrecompileOutput::new(gas_cost, Bytes::new())),
    };

    let header_bytes = serialize(&parent.header);
    Ok(PrecompileOutput::new(gas_cost, encode_abi_bytes(&header_bytes).into()))
}

// ---------------------------------------------------------------------------
// ABI encoding/decoding helpers
// ---------------------------------------------------------------------------

/// Decode a single ABI-encoded `bytes` argument.
fn decode_abi_bytes(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 64 {
        return None;
    }
    // First 32 bytes: offset (should be 0x20 = 32)
    let offset = U256::from_be_slice(&data[..32]).to::<usize>();
    if offset + 32 > data.len() {
        return None;
    }
    // At the offset: length, then the data
    let len = U256::from_be_slice(&data[offset..offset + 32]).to::<usize>();
    let data_start = offset + 32;
    if data_start + len > data.len() {
        return None;
    }
    Some(data[data_start..data_start + len].to_vec())
}

/// Decode an ABI-encoded `bytes[]` argument (dynamic array of dynamic bytes).
fn decode_abi_bytes_array(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.len() < 64 {
        return None;
    }
    // First 32 bytes: offset to the array
    let array_offset = U256::from_be_slice(&data[..32]).to::<usize>();
    if array_offset + 32 > data.len() {
        return None;
    }
    // At array_offset: number of elements
    let count = U256::from_be_slice(&data[array_offset..array_offset + 32]).to::<usize>();
    if count == 0 {
        return Some(Vec::new());
    }

    let offsets_start = array_offset + 32;
    let mut result = Vec::with_capacity(count);

    for i in 0..count {
        let offset_pos = offsets_start + i * 32;
        if offset_pos + 32 > data.len() {
            return None;
        }
        let elem_offset = U256::from_be_slice(&data[offset_pos..offset_pos + 32]).to::<usize>();
        let abs_offset = array_offset + 32 + elem_offset;
        if abs_offset + 32 > data.len() {
            return None;
        }
        let elem_len = U256::from_be_slice(&data[abs_offset..abs_offset + 32]).to::<usize>();
        let elem_start = abs_offset + 32;
        if elem_start + elem_len > data.len() {
            return None;
        }
        result.push(data[elem_start..elem_start + elem_len].to_vec());
    }

    Some(result)
}

/// ABI-encode a `bytes` return value.
fn encode_abi_bytes(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(64 + data.len().div_ceil(32) * 32);
    // Offset
    let mut offset = [0u8; 32];
    offset[31] = 0x20;
    result.extend_from_slice(&offset);
    // Length
    let len = U256::from(data.len());
    result.extend_from_slice(&len.to_be_bytes::<32>());
    // Data (padded to 32 bytes)
    result.extend_from_slice(data);
    let pad_len = (32 - data.len() % 32) % 32;
    result.extend(std::iter::repeat_n(0u8, pad_len));
    result
}

/// ABI-encode an int256 result.
fn encode_int_result(gas_cost: u64, value: i64) -> PrecompileOutput {
    let mut output = [0u8; 32];
    if value >= 0 {
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    } else {
        // Sign-extend for negative values
        output = [0xFF; 32];
        output[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    }
    PrecompileOutput::new(gas_cost, output.to_vec().into())
}

// ---------------------------------------------------------------------------
// Hash conversion helpers
// ---------------------------------------------------------------------------

/// Convert a bitcoin `BlockHash` to an alloy `B256` in DISPLAY byte order
/// (bitcoinj `Sha256Hash` bytes — what rskj renders in storage, ABI values
/// and serialized hashes).
pub fn bitcoin_hash_to_b256(hash: &BlockHash) -> alloy_primitives::B256 {
    use bitcoin::hashes::Hash;
    let mut bytes = *hash.to_raw_hash().as_byte_array();
    bytes.reverse();
    alloy_primitives::B256::from(bytes)
}

/// Convert an alloy `B256` in DISPLAY byte order to a bitcoin `BlockHash`.
pub fn b256_to_bitcoin_hash(b: &alloy_primitives::B256) -> BlockHash {
    use bitcoin::hashes::Hash;
    let mut bytes = b.0;
    bytes.reverse();
    BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The inlined mainnet checkpoint must decode to the bitcoinj checkpoint
    /// rskj seeds from: BTC #499,968,
    /// 000000000000000000296e10eb4987c4eb9b7ba0841102dec4480e5d6b89acb5.
    #[test]
    fn mainnet_btc_checkpoint_decodes_to_expected_block() {
        let (header_hex, height, work_hex) =
            BridgeConstants::mainnet().btc_checkpoint.unwrap();
        assert_eq!(height, 499_968);
        let bytes = alloy_primitives::hex::decode(header_hex).unwrap();
        let header: BtcHeader = deserialize(&bytes).unwrap();
        assert_eq!(
            header.block_hash().to_string(),
            "000000000000000000296e10eb4987c4eb9b7ba0841102dec4480e5d6b89acb5"
        );
        let work = U256::from_be_slice(&alloy_primitives::hex::decode(work_hex).unwrap());
        assert!(!work.is_zero());
    }

    #[test]
    fn encode_int_positive() {
        let output = encode_int_result(0, 1);
        let bytes: &[u8] = &output.bytes;
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[30], 0);
    }

    #[test]
    fn encode_int_negative() {
        let output = encode_int_result(0, -1);
        let bytes: &[u8] = &output.bytes;
        assert_eq!(bytes.len(), 32);
        // -1 in two's complement is all 0xFF
        assert!(bytes.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn encode_int_negative_two() {
        let output = encode_int_result(0, -2);
        let bytes: &[u8] = &output.bytes;
        assert_eq!(bytes[31], 0xFE);
        for &b in &bytes[..24] {
            assert_eq!(b, 0xFF);
        }
    }

    #[test]
    fn abi_bytes_roundtrip() {
        let original = vec![1u8, 2, 3, 4, 5];
        let encoded = encode_abi_bytes(&original);
        let decoded = decode_abi_bytes(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn abi_bytes_80_byte_header() {
        let data = vec![0xABu8; 80];
        let encoded = encode_abi_bytes(&data);
        let decoded = decode_abi_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hash_conversion_roundtrip() {
        let hash_bytes = alloy_primitives::B256::repeat_byte(0x42);
        let btc_hash = b256_to_bitcoin_hash(&hash_bytes);
        let back = bitcoin_hash_to_b256(&btc_hash);
        assert_eq!(back, hash_bytes);
    }
}
