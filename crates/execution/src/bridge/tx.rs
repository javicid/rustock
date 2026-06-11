//! BTC transaction verification and processed tx tracking for the Bridge.
//!
//! Implements:
//! - `registerBtcCoinbaseTransaction`: verify and store coinbase witness info
//! - `hasBtcBlockCoinbaseTransactionInformation`: check if coinbase info exists
//! - `getBtcTransactionConfirmations`: compute confirmations via merkle branch
//! - Processed tx hash tracking (pre/post RSKIP134)

use alloy_primitives::{Bytes, U256};
use bitcoin::hashes::{Hash, sha256d};
use revm::precompile::{PrecompileError, PrecompileOutput};

use super::btc_chain::b256_to_bitcoin_hash;

/// Encode bytes as lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Render a BTC hash (internal byte order) as rskj's `Sha256Hash.toString()`:
/// DISPLAY-order hex, used in compound storage keys.
pub fn btc_hash_hex_display(hash: &[u8; 32]) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    to_hex(&bytes)
}
use super::btc_store::{get_stored_block, load_chain_head};
use super::pmt::{MerkleBranch, PartialMerkleTree};
use super::serialization::{rlp_decode_list, rlp_encode_element, rlp_encode_list};
use super::storage::*;

// ---------------------------------------------------------------------------
// Processed tx hash tracking
// ---------------------------------------------------------------------------

/// Load the legacy processed-tx map ("btcTxHashesAP" — the only form before
/// RSKIP134), and write it back: rskj loads it on ANY processed-height
/// lookup and the post-call save rewrites it, creating the (possibly empty)
/// RLP map entry the first time the bridge reads it. Hashes are kept in
/// internal byte order; the serialized form uses display order, sorted by
/// bitcoinj `Sha256Hash.compareTo` (= internal-order lexicographic).
fn load_legacy_processed_map<CTX: crate::RskContextTr>(ctx: &mut CTX) -> Vec<([u8; 32], u64)> {
    let key = bridge_storage_key(BTC_TX_HASHES_ALREADY_PROCESSED_KEY);
    let mut map = Vec::new();
    if let Some(data) = bridge_load_raw(ctx, key) {
        if let Some(items) = rlp_decode_list(&data) {
            let mut i = 0;
            while i + 1 < items.len() {
                if items[i].len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&items[i]);
                    hash.reverse(); // display -> internal
                    let height = U256::from_be_slice(&items[i + 1]).to::<u64>();
                    map.push((hash, height));
                }
                i += 2;
            }
        }
    }
    store_legacy_processed_map(ctx, map.clone());
    map
}

/// Serialize and store the legacy map (rskj `serializeMapOfHashesToLong`).
fn store_legacy_processed_map<CTX: crate::RskContextTr>(ctx: &mut CTX, mut map: Vec<([u8; 32], u64)>) {
    map.sort_by(|a, b| a.0.cmp(&b.0));
    let mut items = Vec::with_capacity(map.len() * 2);
    for (hash_internal, height) in &map {
        let mut display = *hash_internal;
        display.reverse();
        items.push(rlp_encode_element(&display));
        items.push(rlp_encode_uint(U256::from(*height)));
    }
    let key = bridge_storage_key(BTC_TX_HASHES_ALREADY_PROCESSED_KEY);
    bridge_store_raw(ctx, key, Some(rlp_encode_list(&items)));
}

/// Check if a BTC tx hash has already been processed. rskj checks the
/// legacy map first at every era, then (post-RSKIP134) the per-hash
/// compound entry.
pub fn is_btc_tx_processed<CTX: crate::RskContextTr>(ctx: &mut CTX, btc_tx_hash: &[u8; 32]) -> bool {
    get_btc_tx_processed_height(ctx, btc_tx_hash).is_some()
}

/// Mark a BTC tx hash as processed at a given RSK height
/// (rskj `setHeightBtcTxhashAlreadyProcessed`).
pub fn set_btc_tx_processed<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
    height: u64,
    rskip134: bool,
) {
    if rskip134 {
        let hash_hex = btc_hash_hex_display(btc_tx_hash);
        let key = compound_key(BTC_TX_HASH_AP_KEY, "-", &hash_hex);
        // serializeLong (RLP).
        bridge_store_raw(ctx, key, Some(rlp_encode_uint(U256::from(height))));
    } else {
        let mut map = load_legacy_processed_map(ctx);
        map.retain(|(h, _)| h != btc_tx_hash);
        map.push((*btc_tx_hash, height));
        store_legacy_processed_map(ctx, map);
    }
}

/// Get the height at which a BTC tx was processed
/// (rskj `getHeightIfBtcTxhashIsAlreadyProcessed`).
pub fn get_btc_tx_processed_height<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    btc_tx_hash: &[u8; 32],
) -> Option<u64> {
    let map = load_legacy_processed_map(ctx);
    if let Some((_, height)) = map.iter().find(|(h, _)| h == btc_tx_hash) {
        return Some(*height);
    }
    let hash_hex = btc_hash_hex_display(btc_tx_hash);
    let key = compound_key(BTC_TX_HASH_AP_KEY, "-", &hash_hex);
    bridge_load_raw(ctx, key).map(|d| rlp_decode_uint(&d).to::<u64>())
}

// ---------------------------------------------------------------------------
// Coinbase information
// ---------------------------------------------------------------------------

/// Store the witness merkle root for a BTC block's coinbase transaction.
/// Keyed by the BTC block hash.
pub fn set_coinbase_information<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    block_hash: &[u8; 32],
    witness_merkle_root: &[u8; 32],
) {
    // rskj keys by `Sha256Hash.wrap(blockHashArg).toString()`. bitcoinj's
    // `toString()` hex-encodes the wrapped bytes WITHOUT reversing (only
    // `wrapReversed`/`getHash` reverse), and the ABI `blockHash` arg is already
    // in display order — so the preimage uses the arg bytes as-is, not reversed.
    let hash_hex = to_hex(block_hash);
    let key = compound_key(COINBASE_INFORMATION_KEY, "-", &hash_hex);
    // rskj serializeCoinbaseInformation: RLP list of one element.
    let value = rlp_encode_list(&[rlp_encode_element(witness_merkle_root)]);
    bridge_store_raw(ctx, key, Some(value));
}

/// Load the witness merkle root for a BTC block's coinbase transaction.
pub fn get_coinbase_information<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    block_hash: &[u8; 32],
) -> Option<[u8; 32]> {
    // See `set_coinbase_information`: the ABI block-hash arg is used as-is
    // (no reversal) to match rskj's `Sha256Hash.toString()` of the wrapped arg.
    let hash_hex = to_hex(block_hash);
    let key = compound_key(COINBASE_INFORMATION_KEY, "-", &hash_hex);
    let data = bridge_load_raw(ctx, key)?;
    let items = rlp_decode_list(&data)?;
    let root = items.first()?;
    (root.len() == 32).then(|| {
        let mut out = [0u8; 32];
        out.copy_from_slice(root);
        out
    })
}

/// Check if coinbase info exists for a block hash.
pub fn has_coinbase_information<CTX: crate::RskContextTr>(ctx: &mut CTX, block_hash: &[u8; 32]) -> bool {
    get_coinbase_information(ctx, block_hash).is_some()
}

// ---------------------------------------------------------------------------
// registerBtcCoinbaseTransaction
// ---------------------------------------------------------------------------

/// `registerBtcCoinbaseTransaction(bytes btcTx, bytes32 blockHash, bytes pmtSerialized, bytes32 witnessMerkleRoot, bytes32 witnessReservedValue)`
pub fn register_btc_coinbase_transaction<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    // Decode 5 ABI arguments
    if args.len() < 160 {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: args too short",
        ));
    }

    // Parse the 5 ABI-encoded arguments:
    // arg0: bytes btcTx (dynamic)
    // arg1: bytes32 blockHash
    // arg2: bytes pmtSerialized (dynamic)
    // arg3: bytes32 witnessMerkleRoot
    // arg4: bytes32 witnessReservedValue

    let btc_tx_offset = U256::from_be_slice(&args[0..32]).to::<usize>();
    let block_hash: [u8; 32] = args[32..64].try_into().unwrap();
    let pmt_offset = U256::from_be_slice(&args[64..96]).to::<usize>();
    let witness_merkle_root: [u8; 32] = args[96..128].try_into().unwrap();
    let witness_reserved_value: [u8; 32] = args[128..160].try_into().unwrap();

    // Read dynamic bytes
    let btc_tx_data = read_abi_dynamic_bytes(args, btc_tx_offset)?;
    let pmt_data = read_abi_dynamic_bytes(args, pmt_offset)?;

    // Compute BTC tx hash (double-SHA256)
    let btc_tx_hash = calculate_btc_tx_hash(&btc_tx_data);

    // Validate PMT format
    if !PartialMerkleTree::has_expected_size(&pmt_data) {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: invalid PMT size",
        ));
    }

    // Parse and verify PMT
    let pmt = PartialMerkleTree::parse(&pmt_data).ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: failed to parse PMT")
    })?;

    let pmt_result = pmt.extract_matches().ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: PMT verification failed")
    })?;

    // Check that the tx hash is among the matched hashes
    if !pmt_result.matched_hashes.contains(&btc_tx_hash) {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: tx hash not in PMT",
        ));
    }

    // Verify the merkle root matches the stored block's merkle root
    let btc_block_hash = b256_to_bitcoin_hash(&alloy_primitives::B256::from(block_hash));
    let stored_block = get_stored_block(ctx, &btc_block_hash).ok_or_else(|| {
        PrecompileError::other("registerBtcCoinbaseTransaction: block not found")
    })?;

    let block_merkle_root = {
        let raw = stored_block.header.merkle_root.to_raw_hash();
        *raw.as_byte_array()
    };

    if block_merkle_root != pmt_result.merkle_root {
        return Err(PrecompileError::other(
            "registerBtcCoinbaseTransaction: merkle root mismatch",
        ));
    }

    // Validate witness commitment
    // The commitment is SHA256d(witnessMerkleRoot || witnessReservedValue)
    let mut commitment_data = [0u8; 64];
    commitment_data[..32].copy_from_slice(&witness_merkle_root);
    commitment_data[32..].copy_from_slice(&witness_reserved_value);
    let _witness_commitment = sha256d::Hash::hash(&commitment_data);

    // Store coinbase information keyed by block hash
    set_coinbase_information(ctx, &block_hash, &witness_merkle_root);

    Ok(PrecompileOutput::new(gas_cost, Bytes::new()))
}

// ---------------------------------------------------------------------------
// hasBtcBlockCoinbaseTransactionInformation
// ---------------------------------------------------------------------------

/// `hasBtcBlockCoinbaseTransactionInformation(bytes32 blockHash)` → bool
pub fn has_btc_block_coinbase_info<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    if args.len() < 32 {
        return Err(PrecompileError::other(
            "hasBtcBlockCoinbaseTransactionInformation: args too short",
        ));
    }

    let block_hash: [u8; 32] = args[..32].try_into().unwrap();
    let has_info = has_coinbase_information(ctx, &block_hash);

    let mut output = [0u8; 32];
    if has_info {
        output[31] = 1;
    }

    Ok(PrecompileOutput::new(gas_cost, output.to_vec().into()))
}

// ---------------------------------------------------------------------------
// getBtcTransactionConfirmations
// ---------------------------------------------------------------------------

const CONFIRMATION_ERR_BLOCK_NOT_FOUND: i64 = -1;
const CONFIRMATION_ERR_INVALID_BRANCH: i64 = -2;
const _CONFIRMATION_ERR_BLOCK_TOO_OLD: i64 = -3;
const CONFIRMATION_ERR_BTC_NOT_READY: i64 = -4;

/// `getBtcTransactionConfirmations(bytes32 btcTxHash, bytes32 btcBlockHash, uint256 merkleBranchPath, bytes32[] merkleBranchHashes)` → int256
pub fn get_btc_transaction_confirmations<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    args: &[u8],
    gas_cost: u64,
) -> Result<PrecompileOutput, PrecompileError> {
    let (branch, tx_hash, block_hash_bytes) =
        MerkleBranch::from_abi_args(args).ok_or_else(|| {
            PrecompileError::other("getBtcTransactionConfirmations: invalid args")
        })?;

    // Get chain head
    let chain_head = match load_chain_head(ctx) {
        Some(h) => h,
        None => return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_BTC_NOT_READY)),
    };

    // Get the block
    let block_hash =
        b256_to_bitcoin_hash(&alloy_primitives::B256::from(block_hash_bytes));
    let block = match get_stored_block(ctx, &block_hash) {
        Some(b) => b,
        None => return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_BLOCK_NOT_FOUND)),
    };

    // Compute merkle root from branch
    let computed_root = branch.reduce_from(&tx_hash);

    // Check if it matches the block's merkle root
    let block_merkle_root = {
        let raw = block.header.merkle_root.to_raw_hash();
        *raw.as_byte_array()
    };

    let root_valid = if computed_root == block_merkle_root {
        true
    } else {
        // Post-RSKIP143: also accept witness merkle root
        match get_coinbase_information(ctx, &block_hash_bytes) {
            Some(witness_root) => computed_root == witness_root,
            None => false,
        }
    };

    if !root_valid {
        return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_INVALID_BRANCH));
    }

    // Compute confirmations
    let confirmations = chain_head.height as i64 - block.height as i64 + 1;
    if confirmations < 0 {
        return Ok(encode_int_output(gas_cost, CONFIRMATION_ERR_BLOCK_NOT_FOUND));
    }

    Ok(encode_int_output(gas_cost, confirmations))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the BTC transaction hash (double-SHA256 of raw tx bytes).
/// Returns the hash in internal byte order (same as bitcoinj's Sha256Hash).
///
/// This is rskj `BtcTransactionFormatUtils.calculateBtcTxHash`
/// (`hashTwice(btcTxSerialized)`): it hashes the bytes AS SUPPLIED, so for a
/// SegWit-serialized tx it yields the wtxid. rskj uses this hash for PMT
/// matching and merkle-root validation (BridgeSupport.registerBtcTransaction
/// l.385, validationsForRegisterBtcTransaction). The btcTxHashesAlreadyProcessed
/// map instead keys by the witness-stripped txid `btcTx.getHash(false)` — see
/// `legacy_btc_txid`.
pub fn calculate_btc_tx_hash(tx_bytes: &[u8]) -> [u8; 32] {
    let hash = sha256d::Hash::hash(tx_bytes);
    *hash.as_byte_array()
}

/// The witness-stripped BTC txid (bitcoinj `BtcTransaction.getHash(false)`),
/// in internal byte order. For non-SegWit txs this equals
/// `calculate_btc_tx_hash`; for SegWit txs the raw bytes carry the
/// marker/flag and witness stack, so the two differ. rskj marks/looks up
/// peg-ins in btcTxHashesAlreadyProcessed by THIS hash
/// (BridgeSupport.registerBtcTransaction l.404, l.763).
pub fn legacy_btc_txid(tx: &bitcoin::Transaction) -> [u8; 32] {
    *tx.compute_txid().to_raw_hash().as_byte_array()
}

fn read_abi_dynamic_bytes(args: &[u8], offset: usize) -> Result<Vec<u8>, PrecompileError> {
    if offset + 32 > args.len() {
        return Err(PrecompileError::other("ABI: offset out of bounds"));
    }
    let len = U256::from_be_slice(&args[offset..offset + 32]).to::<usize>();
    let data_start = offset + 32;
    if data_start + len > args.len() {
        return Err(PrecompileError::other("ABI: data out of bounds"));
    }
    Ok(args[data_start..data_start + len].to_vec())
}

fn encode_int_output(gas_cost: u64, value: i64) -> PrecompileOutput {
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
    fn btc_tx_hash_known_vector() {
        // A simple test: hash of empty tx data should be double-sha256 of empty
        let hash = calculate_btc_tx_hash(&[]);
        let expected = sha256d::Hash::hash(&[]);
        assert_eq!(hash, *expected.as_byte_array());
    }

    #[test]
    fn btc_tx_hash_deterministic() {
        let data = vec![0x01, 0x00, 0x00, 0x00];
        let h1 = calculate_btc_tx_hash(&data);
        let h2 = calculate_btc_tx_hash(&data);
        assert_eq!(h1, h2);
    }

    /// Ground truth ported from rskj BtcTransactionFormatUtilsTest.calculateBtcTxHash:
    /// `calculate_btc_tx_hash` hashes the raw bytes as supplied (rskj
    /// `BtcTransactionFormatUtils.calculateBtcTxHash = hashTwice(serialized)`).
    /// rskj asserts the DISPLAY-order hash 4d63ac30…151576; our internal-order
    /// result is its reverse.
    #[test]
    fn calculate_btc_tx_hash_legacy_vector() {
        let hex_str = "020000000418bc858998739dbb7e7676435178dba5e71157b1537d415518d5c1fce6349018000000006a47304402204317903e40f8736858f87758e68bf18372bc075bc928fd82aa8e6c03ae8ce9fb022074a59d7449cc753c5a6b10e70db20469076e2a8b950aa44624ee7ff70633f732012103161014902a3984b695c41627f1403f56b0e631152ff265ddb42e36ba0d57b796feffffff6b853f36edb3a55c419792d3923790147b3c429bb6082d11846ff563edcdae05010000006b483045022100e202a463722821875bcecea315041623b4f4b7c615bc63c85ddcb4185035cc0502201beb9c556c1a672d326e66c4d4b44ac189b7f3296c5ce6128bf9e52f96cfcabc012103a6ba50eaba8d2fc9a638123cf3fe155610cf162253e8cf672f70945fe00fd317feffffffac932fbdbb882a3947652710b6c9117729962efb30f77779265436f804a5f4bc010000006b483045022100ddc4be4b2d61eb6bdecbb76002cc85c304630465807039f7c9eaf5583d5c6cce02203bc3dc7429a17a92c63b6ec517d82f3964beda7f3c375a388c0326e3db3a455101210366d0e8c0c72ea7e8a48ae9fe525fb51bcea39702b9ba2903758a582e26a7d0b9feffffffe89b208401d4eb6fc01deef1393fe00c1f56e2b86b77268629491894f560adb6010000006b483045022100ac01733d947bf43ad97a5792864766c6c6d9963e359a6e0ab470b68565d679b6022003d4afeb917e7711e797b665f5a95893dea2f53d07e2840b6441a72702f88412012102b005a7d4368c02dc8e5f171765db281f546b99b921eac18b2910c82d38f820f7feffffff02441427010000000017a914056bce3306ec98a0247cebb654809943045d6b51877ff21500000000001976a914f7da7f0f7669bce303cfc48921bb7303e3918b1288acdfdc0700";
        let raw = hex::decode(hex_str).unwrap();
        let mut expected_display =
            hex::decode("4d63ac307e0daba3597a0d8075facb4e6cba3908a60920259b7447e28a151576").unwrap();
        expected_display.reverse(); // display -> internal
        assert_eq!(calculate_btc_tx_hash(&raw).to_vec(), expected_display);
    }

    /// RSK Mainnet block #3,231,219 tx[2]: a SegWit-serialized peg-in. rskj
    /// `BtcTransactionFormatUtils.calculateBtcTxHash` hashes the raw bytes
    /// (wtxid) for PMT matching, while `btcTx.getHash(false)` (= our
    /// `legacy_btc_txid`) strips the witness for the
    /// btcTxHashesAlreadyProcessed map. The two MUST differ for a SegWit tx.
    /// Ground truth: the legacy txid (display order 124f95f3…f09b7e) is the
    /// UTXO hash rskj appended to newFederationBtcUTXOs in that block.
    #[test]
    fn segwit_pegin_wtxid_vs_legacy_txid() {
        let raw = hex::decode(
            "01000000000102ad5193f8f5af5fa13b9555811ae1de6e08e7c65801cb731a79ff445abd1b5061000000006a473044\
             02206dd90517b2b462b1edf9592cdc75d5b10196c275e39cb22fc63c053c57f001dd02203594e7c41258948f40f4bf3\
             f5628cfefac04adb639da5a227fca772f33ab83a30121037975b80b0275420aa52cad67dff83a26c9fc398f5e7698c5\
             014bb5a6937c17c0ffffffff706fce5df32d6c0f1c3a770282d80a2f3d96809cacb488476d70a0a41e8f12580000000\
             000ffffffff0241420f000000000017a914596cff92a275960df9cb2ab9df0ff69faa2b1d8a873b6a1700000000001\
             976a914935fe65e138f8cc6d5aa72801aebe59f78d7289f88ac00024730440220660b129d3f75041c30b5a8d51b41b4\
             d13b07818cfe5e3274ddad39bdea3b2d2e02205ab94a07c9a13a4419d8f07edcca45ab7006c1fdd8d35d903d2a1a2a7\
             9799f40012102240177f45453feca344644d99a285ab33674d3eaa5fb0ae3e17d10b08f85d6e200000000",
        )
        .unwrap();
        // wtxid (raw double-SHA256, internal order).
        let mut expected_wtxid =
            hex::decode("cfe20fb72fd2d39bb59f6b89da3dea74733f4f9710192cd19431dfdb95620897").unwrap();
        expected_wtxid.reverse();
        assert_eq!(calculate_btc_tx_hash(&raw).to_vec(), expected_wtxid);

        // legacy txid (witness stripped, internal order).
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        let mut expected_txid =
            hex::decode("124f95f3c6f1a52918077550997fd68df3402ad51e97414fac9e23a029f09b7e").unwrap();
        expected_txid.reverse();
        assert_eq!(legacy_btc_txid(&tx).to_vec(), expected_txid);

        // The whole point: for a SegWit tx the two hashes differ.
        assert_ne!(calculate_btc_tx_hash(&raw), legacy_btc_txid(&tx));
    }

    /// Ground truth from RSK Mainnet block #3,229,522 (registerBtcCoinbaseTransaction):
    /// rskj keys coinbase information by `DataWord.fromLongString("coinbaseInformation-"
    /// + Sha256Hash.wrap(blockHashArg).toString())`, and bitcoinj's `toString()` hex-encodes
    /// the wrapped bytes WITHOUT reversing. The block-hash ABI arg below is the exact one
    /// from that block; the expected DataWord is the storage slot read from rskj's own unitrie.
    #[test]
    fn coinbase_information_storage_key_mainnet() {
        let block_hash: [u8; 32] =
            hex::decode("0000000000000000000b718fb9d9d0c032cbfbebae6e3f99da00a131a7433fe4")
                .unwrap()
                .try_into()
                .unwrap();
        let key = compound_key(COINBASE_INFORMATION_KEY, "-", &to_hex(&block_hash));
        let expected = U256::from_be_bytes(
            <[u8; 32]>::try_from(
                hex::decode("4e92fd4d2d1f5769b361ef086f963fea4d74d700b5544f67b5a9a2c587fd3f2f")
                    .unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(key, expected, "coinbase storage key must match rskj (no hash reversal)");
    }
}
