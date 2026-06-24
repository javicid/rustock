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

// receiveHeader result codes — must match rskj BridgeSupport exactly
// (BridgeSupport.java:96-100). A from-scratch client that picked its own
// codes (e.g. SUCCESS=1) would fork because callers branch on these values.
const SUCCESS: i64 = 0;
const ERR_TOO_SOON: i64 = -1;
const ERR_BLOCK_TOO_OLD: i64 = -2;
const ERR_PREV_NOT_FOUND: i64 = -3;
const ERR_ALREADY_KNOWN: i64 = -4;
const ERR_UNEXPECTED_EXCEPTION: i64 = -99;

/// Process a single BTC header submitted via `receiveHeader(bytes)`.
///
/// Returns ABI-encoded int256 result code.
pub fn receive_header<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
    config: &BridgeConstants,
    use_v2: bool,
    hardfork_cfg: &RskHardforkConfig,
) -> Result<PrecompileOutput, PrecompileError> {
    // `gas_cost` is rskj `Bridge.getGasForData` = RECEIVE_HEADER functionCost
    // (10_600) + `data.length * 2` (Bridge.java:296-321). The data cost must be
    // included: charging only the bare 10_600 undercharged every receiveHeader
    // call by `2 * input.len()` (mainnet #6,223,762 tx[2]: 2*164 = 328 gas).
    let block_number = revm::context_interface::Block::number(ctx.block()).to::<u64>();
    let rskip199 = hardfork_cfg.has_rskip199(block_number);
    ensure_btc_chain_seeded(ctx, config, use_v2, rskip199);

    // Decode ABI-encoded `bytes` argument
    let header_bytes = decode_abi_bytes(args).ok_or_else(|| {
        PrecompileError::other("receiveHeader: invalid ABI encoding")
    })?;

    // Deserialize BTC header (80 bytes). rskj has already parsed the header
    // (Bridge.receiveHeader takes a BtcBlock) by this point, so the order of
    // checks below mirrors BridgeSupport.receiveHeader (BridgeSupport.java:227).
    if header_bytes.len() < 80 {
        return Err(PrecompileError::other("receiveHeader: header too short"));
    }

    let btc_header: BtcHeader = deserialize(&header_bytes[..80])
        .map_err(|_| PrecompileError::other("receiveHeader: invalid BTC header"))?;

    let block_hash = btc_header.block_hash();

    // 1. Already saved? (rskj checks this FIRST, before the time window.)
    if get_stored_block(ctx, &block_hash).is_some() {
        return Ok(encode_int_result(gas_cost, ERR_ALREADY_KNOWN));
    }

    // 2. Called too soon (RSKIP200 rate limit).
    let last_timestamp =
        super::storage::bridge_load_timestamp(ctx, super::storage::RECEIVE_HEADERS_TIMESTAMP_KEY);
    let current_timestamp = ctx.block().timestamp();
    if config.min_seconds_between_calls_receive_header > 0
        && current_timestamp < last_timestamp + config.min_seconds_between_calls_receive_header
    {
        return Ok(encode_int_result(gas_cost, ERR_TOO_SOON));
    }

    // 3. Parent (previous block) must be known.
    let parent = match get_stored_block(ctx, &btc_header.prev_blockhash) {
        Some(p) => p,
        None => return Ok(encode_int_result(gas_cost, ERR_PREV_NOT_FOUND)),
    };

    let new_height = parent.height + 1;

    // 4. Too old: bestChainHeight - newHeight > maxDepthBlockchainAccepted.
    let best_height = load_chain_head(ctx).map(|h| h.height).unwrap_or(0);
    if (best_height as i64) - (new_height as i64) > config.max_depth_blockchain_accepted as i64 {
        return Ok(encode_int_result(gas_cost, ERR_BLOCK_TOO_OLD));
    }

    // 5. cannotProcessNextBlock: the bitcoinj 12-byte chainwork overflow guard
    // (BridgeSupport.cannotProcessNextBlock). Same gate as receiveHeaders.
    let is_mainnet = matches!(config.btc_network, super::constants::BtcNetwork::Mainnet);
    if new_height >= config.block_with_too_much_chain_work_height
        && is_mainnet
        && !hardfork_cfg.has_rskip434(block_number)
    {
        return Ok(encode_int_result(gas_cost, ERR_UNEXPECTED_EXCEPTION));
    }

    // 6. btcBlockChain.add(header) — bitcoinj throws on bad PoW or any other
    // error, which rskj catches and maps to UNEXPECTED_EXCEPTION.
    if !check_proof_of_work(&btc_header) {
        return Ok(encode_int_result(gas_cost, ERR_UNEXPECTED_EXCEPTION));
    }

    // Compute chain work
    let work = compute_work(btc_header.bits);
    let new_chain_work = parent.chain_work.wrapping_add(work);

    let stored = StoredBlock::new(btc_header, new_height, new_chain_work);

    // Store the block and, when it extends the best chain or wins a reorg,
    // update the chain head and the height->hash main-chain index
    // (bitcoinj `BtcAbstractBlockChain.connectBlock`).
    connect_block(ctx, &stored, &parent, use_v2, rskip199);

    // Update timestamp (rskj serializeLong -> RLP)
    super::storage::bridge_store_timestamp(
        ctx,
        super::storage::RECEIVE_HEADERS_TIMESTAMP_KEY,
        current_timestamp.to::<u64>(),
    );

    Ok(encode_int_result(gas_cost, SUCCESS))
}

/// Connect a freshly built `StoredBlock` to the BTC header chain, mirroring
/// bitcoinj `BtcAbstractBlockChain.connectBlock` in header-only mode
/// (`shouldVerifyTransactions() == false`, which is how the Bridge runs it).
///
/// `stored` is the new block (height/work already computed from `parent`); the
/// caller has already verified PoW, rejected already-known blocks, and resolved
/// `parent` (= bitcoinj `storedPrev`). `connectBlock` itself always persists the
/// block via `addToBlockStore`, then:
///
/// - if the block extends the current best chain (`parent == chainHead`), it
///   becomes the new head directly; or
/// - if it forks the chain but has **strictly more work** than the head
///   (`StoredBlock.moreWorkThan`, i.e. `chainWork >` — ties do NOT reorg), it
///   triggers `handleNewBestChain`, which rewrites the height->hash main-chain
///   index for **every** block on the new branch above the split point, then
///   sets the head.
///
/// rustock previously only ever set the head's single index entry, so a BTC
/// reorg deeper than one block left stale entries at the intermediate heights —
/// the divergence localized to the `btcBlockHeight-<height>` cell.
fn connect_block<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    stored: &StoredBlock,
    parent: &StoredBlock,
    use_v2: bool,
    rskip199: bool,
) {
    // `addToBlockStore`: persist the block unconditionally.
    put_stored_block(ctx, stored, use_v2);

    let head = match load_chain_head(ctx) {
        Some(h) => h,
        // No head yet (chain not seeded): treat as a direct extension.
        None => {
            set_chain_head(ctx, stored, use_v2, rskip199);
            return;
        }
    };

    // Direct extension of the best chain (`storedPrev.equals(chainHead)`).
    if parent.header.block_hash() == head.header.block_hash() {
        set_chain_head(ctx, stored, use_v2, rskip199);
        return;
    }

    // Fork. Only reorganize if the new block has strictly more work than the
    // current head (bitcoinj `StoredBlock.moreWorkThan` uses `>` — a tie keeps
    // the existing head). A fork with <= work is stored but does not move the
    // head or touch the main-chain index.
    if stored.chain_work > head.chain_work {
        handle_new_best_chain(ctx, stored, &head, use_v2, rskip199);
    }
}

/// bitcoinj `handleNewBestChain`: reindex the new branch and set the head.
/// Rewrites `setMainChainBlock(height, hash)` for every block on the new branch
/// from the split point (exclusive) up to the new head, then sets the head
/// (which itself reindexes the head height).
fn handle_new_best_chain<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    new_head: &StoredBlock,
    old_head: &StoredBlock,
    use_v2: bool,
    rskip199: bool,
) {
    if rskip199 {
        // Resolve a block's parent (bitcoinj `StoredBlock.getPrev`) from
        // Bridge storage. Collected eagerly because the reindex below also
        // mutates `ctx`, so we cannot hold a borrowing closure across it.
        let split = find_split(new_head, old_head, |h| get_stored_block(ctx, h));
        // bitcoinj getPartialChain(newChainHead, splitPoint): the new branch
        // blocks above the split, walked from the head down via getPrev.
        let new_branch = get_partial_chain(new_head, &split, |h| get_stored_block(ctx, h));
        for block in new_branch {
            super::storage::bridge_store_btc_block_hash_by_height(
                ctx,
                block.height,
                bitcoin_hash_to_b256(&block.header.block_hash()),
            );
        }
    }
    set_chain_head(ctx, new_head, use_v2, rskip199);
}

/// bitcoinj `findSplit(newChainHead, oldChainHead, store)`: walk both branches
/// back (by `getPrev`) until they meet at the common ancestor. `get_prev`
/// resolves a block's parent stored block. Returns the split-point stored block.
fn find_split(
    new_head: &StoredBlock,
    old_head: &StoredBlock,
    mut get_prev: impl FnMut(&BlockHash) -> Option<StoredBlock>,
) -> StoredBlock {
    let mut current_chain_cursor = old_head.clone();
    let mut new_chain_cursor = new_head.clone();
    while current_chain_cursor.header.block_hash() != new_chain_cursor.header.block_hash() {
        if current_chain_cursor.height > new_chain_cursor.height {
            current_chain_cursor = get_prev(&current_chain_cursor.header.prev_blockhash)
                .expect("findSplit: attempt to follow an orphan chain");
        } else {
            new_chain_cursor = get_prev(&new_chain_cursor.header.prev_blockhash)
                .expect("findSplit: attempt to follow an orphan chain");
        }
    }
    current_chain_cursor
}

/// bitcoinj `getPartialChain(higher, lower, store)`: blocks from `higher` down
/// to (but excluding) `lower`, in head→split order. Walks from the in-memory
/// `higher` and resolves ancestors via `get_prev` (the head's own parent is
/// already persisted by the time we get here).
fn get_partial_chain(
    higher: &StoredBlock,
    lower: &StoredBlock,
    mut get_prev: impl FnMut(&BlockHash) -> Option<StoredBlock>,
) -> Vec<StoredBlock> {
    debug_assert!(higher.height > lower.height, "higher and lower are reversed");
    let mut results = Vec::new();
    let mut cursor = higher.clone();
    loop {
        results.push(cursor.clone());
        cursor = get_prev(&cursor.header.prev_blockhash)
            .expect("getPartialChain: ran off the end of the chain");
        if cursor.header.block_hash() == lower.header.block_hash() {
            break;
        }
    }
    results
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
        connect_block(ctx, &stored, &parent, use_v2, rskip199);
    }

    // rskj `receiveHeaders` is a VOID method (BridgeMethods.RECEIVE_HEADERS
    // declares no output, Bridge::receiveHeaders is BridgeMethodExecutorVoid).
    // Bridge.execute therefore returns the void value — `null` before RSKIP417
    // and EMPTY_BYTE_ARRAY afterwards (Bridge.calculateVoidReturnValue) — both
    // of which give the caller RETURNDATASIZE 0. Returning a 32-byte int here
    // makes a calling contract decode 32 bytes where rskj sees 0, forking the
    // execution (mainnet #6,223,768 tx[0]: relay 0x82494fb1 OOGs vs success).
    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
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

    // Look up hash by height, then get the block.
    //
    // rskj returns `EMPTY_BYTE_ARRAY` when the block is absent (or
    // `getStoredBlockAtMainChainHeight` throws and `Bridge` catches it), but
    // `Bridge.execute` always ABI-encodes the `byte[]` result via
    // `encodeOutputs` (Bridge.java:418), so an empty result is returned as the
    // ABI encoding of an empty `bytes` (offset `0x20` + length `0x00` = 64
    // bytes), NOT as zero-length return data.
    let hash_b256 = super::storage::bridge_load_btc_block_hash_by_height(ctx, height);
    let header_bytes = hash_b256
        .map(|h| b256_to_bitcoin_hash(&h))
        .and_then(|hash| get_stored_block(ctx, &hash))
        .map(|block| serialize(&block.header))
        .unwrap_or_default();
    Ok(PrecompileOutput::new(gas_cost, encode_abi_bytes(&header_bytes).into()))
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

    // As in `get_block_header_by_height`, an absent block yields rskj's
    // `EMPTY_BYTE_ARRAY`, which `Bridge.execute` still ABI-encodes as an empty
    // `bytes` (64 bytes), not zero-length return data.
    let header_bytes = get_stored_block(ctx, &hash)
        .and_then(|block| get_stored_block(ctx, &block.header.prev_blockhash))
        .map(|parent| serialize(&parent.header))
        .unwrap_or_default();
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
    // rskj's `SolidityType.BytesType.encode` sizes the data section as
    // `((len - 1) / 32 + 1) * 32` using Java's truncating integer division
    // (SolidityType.java:296). For a non-empty array this is the usual
    // `ceil(len/32)*32`, but for an EMPTY array `(0 - 1) / 32 == -1 / 32 == 0`
    // in Java, so `+ 1` yields one 32-byte zero word rather than zero words:
    // empty `bytes` encodes to offset(0x20) + length(0) + one zero word = 96
    // bytes, not 64. Rust's `/` truncates toward zero just like Java's, so the
    // same expression reproduces the quirk exactly. This is consensus-critical:
    // the extra word changes RETURNDATASIZE (and downstream memory expansion)
    // in callers that copy the bridge's return data.
    let data_section = (((data.len() as i64 - 1) / 32 + 1) * 32) as usize;
    let mut result = Vec::with_capacity(64 + data_section);
    // Offset
    let mut offset = [0u8; 32];
    offset[31] = 0x20;
    result.extend_from_slice(&offset);
    // Length
    let len = U256::from(data.len());
    result.extend_from_slice(&len.to_be_bytes::<32>());
    // Data (padded per rskj's BytesType formula)
    result.extend_from_slice(data);
    result.resize(64 + data_section, 0);
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
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;
    use bitcoin::{CompactTarget, TxMerkleNode};
    use std::collections::HashMap;

    /// Build a `StoredBlock` whose header points at `prev` and carries a
    /// distinguishing `nonce` (so sibling blocks at the same height get
    /// distinct hashes). `chain_work` is the cumulative work.
    fn link(prev: BlockHash, nonce: u32, height: u32, chain_work: u64) -> StoredBlock {
        let header = BtcHeader {
            version: Version::from_consensus(1),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        };
        StoredBlock::new(header, height, U256::from(chain_work))
    }

    /// A tiny in-memory block store: hash -> StoredBlock, mirroring what the
    /// Bridge persists via `put_stored_block`.
    fn store_of(blocks: &[StoredBlock]) -> HashMap<BlockHash, StoredBlock> {
        blocks
            .iter()
            .map(|b| (b.header.block_hash(), b.clone()))
            .collect()
    }

    /// bitcoinj `findSplit` + `getPartialChain`: a reorg of depth 3 must report
    /// the common ancestor as the split point and list every new-branch block
    /// above it, head-first. This is the core of the #3,622,582 fix (the BTC
    /// main-chain index must be rewritten for ALL reorganized heights).
    #[test]
    fn reorg_find_split_and_partial_chain() {
        // Common trunk: g(100) <- a(101). Then two branches fork at `a`:
        //   old:  a <- o2(102) <- o3(103)            (head: o3)
        //   new:  a <- n2(102) <- n3(103) <- n4(104) (head: n4, more work)
        let g = link(BlockHash::all_zeros(), 0, 100, 100);
        let a = link(g.header.block_hash(), 1, 101, 110);
        let o2 = link(a.header.block_hash(), 2, 102, 120);
        let o3 = link(o2.header.block_hash(), 3, 103, 130);
        let n2 = link(a.header.block_hash(), 12, 102, 121);
        let n3 = link(n2.header.block_hash(), 13, 103, 132);
        let n4 = link(n3.header.block_hash(), 14, 104, 143);

        let store = store_of(&[
            g.clone(),
            a.clone(),
            o2.clone(),
            o3.clone(),
            n2.clone(),
            n3.clone(),
            n4.clone(),
        ]);
        let get_prev = |h: &BlockHash| store.get(h).cloned();

        // Split point is the fork ancestor `a`.
        let split = find_split(&n4, &o3, get_prev);
        assert_eq!(split.header.block_hash(), a.header.block_hash());
        assert_eq!(split.height, 101);

        // New branch above the split, head-first: [n4, n3, n2].
        let partial = get_partial_chain(&n4, &split, get_prev);
        let hashes: Vec<_> = partial.iter().map(|b| b.header.block_hash()).collect();
        assert_eq!(
            hashes,
            vec![
                n4.header.block_hash(),
                n3.header.block_hash(),
                n2.header.block_hash(),
            ],
            "every reorganized height must be reindexed, not just the head"
        );
        // The split point itself is excluded.
        assert!(!hashes.contains(&a.header.block_hash()));
    }

    /// When the new head is a direct child of the old head (no fork), the split
    /// is the old head and the partial chain is just the new block.
    #[test]
    fn reorg_direct_extension_partial_chain_is_single_block() {
        let a = link(BlockHash::all_zeros(), 1, 101, 110);
        let b = link(a.header.block_hash(), 2, 102, 120);
        let store = store_of(&[a.clone(), b.clone()]);
        let get_prev = |h: &BlockHash| store.get(h).cloned();

        let split = find_split(&b, &a, get_prev);
        assert_eq!(split.header.block_hash(), a.header.block_hash());

        let partial = get_partial_chain(&b, &a, get_prev);
        assert_eq!(partial.len(), 1);
        assert_eq!(partial[0].header.block_hash(), b.header.block_hash());
    }

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
        // 80 bytes → offset + length + ceil(80/32)*32 = 32 + 32 + 96 = 160.
        assert_eq!(encoded.len(), 160);
    }

    /// Ground truth: rskj `SolidityType.BytesType.encode` allocates
    /// `((len - 1) / 32 + 1) * 32` data bytes with Java's truncating division.
    /// For an EMPTY `byte[]`, `-1 / 32 == 0`, so it still emits one 32-byte zero
    /// word — empty `bytes` encodes to 96 bytes (offset + length + one word),
    /// not 64. `getBtcBlockchainBlockHeaderByHeight` for an out-of-range height
    /// returns rskj's `EMPTY_BYTE_ARRAY`, which `Bridge.execute` ABI-encodes
    /// this way; the extra word changed RETURNDATASIZE and forked the caller at
    /// mainnet #8,417,579 (tx[0], 34912 vs 34401 gas).
    #[test]
    fn abi_bytes_empty_matches_rskj_96_bytes() {
        let encoded = encode_abi_bytes(&[]);
        assert_eq!(encoded.len(), 96, "empty bytes must encode to 96, not 64");
        // offset 0x20, length 0, one zero word.
        assert_eq!(encoded[31], 0x20);
        assert!(encoded[32..].iter().all(|&b| b == 0));
        assert_eq!(decode_abi_bytes(&encoded).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hash_conversion_roundtrip() {
        let hash_bytes = alloy_primitives::B256::repeat_byte(0x42);
        let btc_hash = b256_to_bitcoin_hash(&hash_bytes);
        let back = bitcoin_hash_to_b256(&btc_hash);
        assert_eq!(back, hash_bytes);
    }

    /// Ground truth: rskj `BridgeSupport` receiveHeader result codes
    /// (BridgeSupport.java:96-100 + the `return 0;` success). A from-scratch
    /// client that picked different values (rustock previously used SUCCESS=1,
    /// TOO_SOON=-2, ALREADY_KNOWN=-1, a bogus INVALID_POW=-5) forks because the
    /// calling contract branches on these integers (mainnet #6,223,768 tx[0]).
    #[test]
    fn receive_header_result_codes_match_rskj() {
        assert_eq!(SUCCESS, 0); // return 0
        assert_eq!(ERR_TOO_SOON, -1); // RECEIVE_HEADER_CALLED_TOO_SOON
        assert_eq!(ERR_BLOCK_TOO_OLD, -2); // RECEIVE_HEADER_BLOCK_TOO_OLD
        assert_eq!(ERR_PREV_NOT_FOUND, -3); // RECEIVE_HEADER_CANT_FOUND_PREVIOUS_BLOCK
        assert_eq!(ERR_ALREADY_KNOWN, -4); // RECEIVE_HEADER_BLOCK_PREVIOUSLY_SAVED
        assert_eq!(ERR_UNEXPECTED_EXCEPTION, -99); // RECEIVE_HEADER_UNEXPECTED_EXCEPTION
    }
}
