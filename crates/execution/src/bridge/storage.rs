//! Bridge storage provider — journal-based read/write for Bridge contract state.
//!
//! Mirrors rskj's `BridgeStorageProvider` and `FederationStorageProvider`.
//! All keys use `DataWord.fromString` encoding (same as REMASC storage keys).
//! Compound keys use `DataWord.fromLongString` (SHA3 of the concatenated string).

use alloy_primitives::{Address, B256, U256};
use revm::context_interface::{ContextTr, JournalTr};
use sha3::{Digest, Keccak256};

use crate::precompiles::BRIDGE_ADDR;

// ---------------------------------------------------------------------------
// Key encoding (matches rskj DataWord.fromString / fromLongString)
// ---------------------------------------------------------------------------

/// Encode a short key (≤32 bytes) as rskj's `DataWord.fromString`:
/// UTF-8 bytes right-aligned in a 32-byte big-endian word.
pub fn bridge_storage_key(name: &str) -> U256 {
    let bytes = name.as_bytes();
    debug_assert!(bytes.len() <= 32, "key must be ≤32 bytes");
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    U256::from_be_bytes(buf)
}

/// Encode a long key (>32 bytes or compound) as rskj's `DataWord.fromLongString`:
/// Keccak256 hash of the UTF-8 bytes.
pub fn bridge_storage_key_long(name: &str) -> U256 {
    let hash = Keccak256::digest(name.as_bytes());
    U256::from_be_bytes(hash.into())
}

/// Build a compound key: `base_key + delimiter + identifier`, then hash.
/// Matches rskj's `BridgeStorageIndexKey.getCompoundKey(delimiter, identifier)`.
pub fn compound_key(base: &str, delimiter: &str, identifier: &str) -> U256 {
    let combined = format!("{}{}{}", base, delimiter, identifier);
    if combined.len() <= 32 {
        bridge_storage_key(&combined)
    } else {
        bridge_storage_key_long(&combined)
    }
}

// ---------------------------------------------------------------------------
// Bridge storage index keys (from rskj BridgeStorageIndexKey)
// ---------------------------------------------------------------------------

pub const BTC_TX_HASHES_ALREADY_PROCESSED_KEY: &str = "btcTxHashesAP";
pub const RELEASE_REQUEST_QUEUE_KEY: &str = "releaseRequestQueue";
pub const PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY: &str = "releaseTransactionSet";
pub const RELEASES_OUTPOINTS_VALUES_KEY: &str = "releasesOutpointsValues";
pub const PEGOUTS_WAITING_FOR_SIGNATURES_KEY: &str = "rskTxsWaitingFS";
pub const RELEASE_REQUEST_QUEUE_WITH_TXHASH_KEY: &str = "releaseRequestQueueWithTxHash";
pub const PEGOUTS_WAITING_FOR_CONFIRMATIONS_WITH_TXHASH_KEY: &str = "releaseTransactionSetWithTxHash";
pub const RECEIVE_HEADERS_TIMESTAMP_KEY: &str = "receiveHeadersLastTimestamp";
pub const NEXT_PEGOUT_HEIGHT_KEY: &str = "nextPegoutHeight";

// Compound key bases
pub const BTC_TX_HASH_AP_KEY: &str = "btcTxHashAP";
pub const COINBASE_INFORMATION_KEY: &str = "coinbaseInformation";
pub const BTC_BLOCK_HEIGHT_KEY: &str = "btcBlockHeight";
pub const FAST_BRIDGE_HASH_USED_KEY: &str = "fastBridgeHashUsedInBtcTx";
pub const FAST_BRIDGE_FEDERATION_INFO_KEY: &str = "fastBridgeFederationInformation";
pub const PEGOUT_TX_SIG_HASH_KEY: &str = "pegoutTxSigHash";

// SVP keys
pub const SVP_FUND_TX_HASH_UNSIGNED_KEY: &str = "svpFundTxHashUnsigned";
pub const SVP_FUND_TX_SIGNED_KEY: &str = "svpFundTxSigned";
pub const SVP_SPEND_TX_HASH_UNSIGNED_KEY: &str = "svpSpendTxHashUnsigned";
pub const SVP_SPEND_TX_WAITING_FOR_SIGNATURES_KEY: &str = "svpSpendTxWaitingForSignatures";

// BTC block store
pub const BLOCK_STORE_CHAIN_HEAD_KEY: &str = "blockStoreChainHead";

// ---------------------------------------------------------------------------
// Federation storage index keys (from rskj FederationStorageIndexKey)
// ---------------------------------------------------------------------------

pub const NEW_FEDERATION_BTC_UTXOS_KEY: &str = "newFederationBtcUTXOs";
pub const NEW_FEDERATION_BTC_UTXOS_TESTNET_PRE_HOP_KEY: &str = "newFederationBtcUTXOsForTestnet";
pub const NEW_FEDERATION_BTC_UTXOS_TESTNET_POST_HOP_KEY: &str = "newFedBtcUTXOsForTestnetPostHop";
pub const OLD_FEDERATION_BTC_UTXOS_KEY: &str = "oldFederationBtcUTXOs";

pub const NEW_FEDERATION_KEY: &str = "newFederation";
pub const OLD_FEDERATION_KEY: &str = "oldFederation";
pub const PENDING_FEDERATION_KEY: &str = "pendingFederation";
pub const PROPOSED_FEDERATION_KEY: &str = "proposedFederation";

pub const FEDERATION_ELECTION_KEY: &str = "federationElection";
pub const ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY: &str = "activeFedCreationBlockHeight";
pub const NEXT_FEDERATION_CREATION_BLOCK_HEIGHT_KEY: &str = "nextFedCreationBlockHeight";
pub const LAST_RETIRED_FEDERATION_P2SH_SCRIPT_KEY: &str = "lastRetiredFedP2SHScript";

// Federation format version keys
pub const NEW_FEDERATION_FORMAT_VERSION_KEY: &str = "newFederationFormatVersion";
pub const OLD_FEDERATION_FORMAT_VERSION_KEY: &str = "oldFederationFormatVersion";
pub const PENDING_FEDERATION_FORMAT_VERSION_KEY: &str = "pendingFederationFormatVersion";
pub const PROPOSED_FEDERATION_FORMAT_VERSION_KEY: &str = "proposedFederationFormatVersion";

// ---------------------------------------------------------------------------
// Journal-based read/write helpers
// ---------------------------------------------------------------------------

/// Read a U256 from Bridge contract storage via the journal.
pub fn bridge_sload<CTX: ContextTr>(ctx: &mut CTX, key: U256) -> U256 {
    ctx.journal_mut()
        .sload(BRIDGE_ADDR, key)
        .map(|sl| sl.data)
        .unwrap_or(U256::ZERO)
}

/// Write a U256 to Bridge contract storage via the journal.
pub fn bridge_sstore<CTX: ContextTr>(ctx: &mut CTX, key: U256, value: U256) {
    let _ = ctx.journal_mut().sstore(BRIDGE_ADDR, key, value);
}

/// Read raw bytes from Bridge contract storage.
/// Values larger than 32 bytes are stored across multiple consecutive slots.
/// For Phase 1, only single-slot (≤32 byte) values are supported.
pub fn bridge_load_u256<CTX: ContextTr>(ctx: &mut CTX, key_name: &str) -> U256 {
    let key = bridge_storage_key(key_name);
    bridge_sload(ctx, key)
}

/// Write a U256 value to Bridge contract storage by key name.
pub fn bridge_store_u256<CTX: ContextTr>(ctx: &mut CTX, key_name: &str, value: U256) {
    let key = bridge_storage_key(key_name);
    bridge_sstore(ctx, key, value);
}

/// Read a timestamp (u64) from storage.
pub fn bridge_load_timestamp<CTX: ContextTr>(ctx: &mut CTX, key_name: &str) -> u64 {
    bridge_load_u256(ctx, key_name).to::<u64>()
}

/// Write a timestamp (u64) to storage.
pub fn bridge_store_timestamp<CTX: ContextTr>(ctx: &mut CTX, key_name: &str, value: u64) {
    bridge_store_u256(ctx, key_name, U256::from(value));
}

/// Read a BTC block hash (stored as raw 32-byte value) keyed by height.
/// Uses compound key: `btcBlockHeight-{height_hex}`.
pub fn bridge_load_btc_block_hash_by_height<CTX: ContextTr>(ctx: &mut CTX, height: u32) -> Option<B256> {
    let key = compound_key(BTC_BLOCK_HEIGHT_KEY, "-", &format!("{:x}", height));
    let val = bridge_sload(ctx, key);
    if val.is_zero() {
        None
    } else {
        Some(B256::from(val.to_be_bytes::<32>()))
    }
}

/// Store a BTC block hash by height (for the main chain index).
pub fn bridge_store_btc_block_hash_by_height<CTX: ContextTr>(ctx: &mut CTX, height: u32, hash: B256) {
    let key = compound_key(BTC_BLOCK_HEIGHT_KEY, "-", &format!("{:x}", height));
    bridge_sstore(ctx, key, U256::from_be_bytes(hash.0));
}

/// Transfer amount from Bridge contract to recipient.
pub fn bridge_transfer<CTX: ContextTr>(ctx: &mut CTX, recipient: Address, amount: U256) -> bool {
    if amount.is_zero() {
        return true;
    }
    matches!(
        ctx.journal_mut().transfer(BRIDGE_ADDR, recipient, amount),
        Ok(None)
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_key_short() {
        let key = bridge_storage_key("btcTxHashesAP");
        let bytes = key.to_be_bytes::<32>();
        assert_eq!(&bytes[32 - 13..], b"btcTxHashesAP");
        assert_eq!(&bytes[..19], &[0u8; 19]);
    }

    #[test]
    fn storage_key_chain_head() {
        let key = bridge_storage_key(BLOCK_STORE_CHAIN_HEAD_KEY);
        let bytes = key.to_be_bytes::<32>();
        let expected = b"blockStoreChainHead";
        assert_eq!(&bytes[32 - expected.len()..], expected);
    }

    #[test]
    fn compound_key_btc_height() {
        let key = compound_key(BTC_BLOCK_HEIGHT_KEY, "-", "ff");
        // "btcBlockHeight-ff" is 17 bytes, fits in 32, so uses fromString
        let bytes = key.to_be_bytes::<32>();
        assert_eq!(&bytes[32 - 17..], b"btcBlockHeight-ff");
    }

    #[test]
    fn compound_key_long_hashes() {
        // A compound key with a long identifier should use keccak256
        let long_id = "aabbccdd11223344aabbccdd11223344";
        let key = compound_key(BTC_TX_HASH_AP_KEY, "-", long_id);
        // "btcTxHashAP-" + 32 hex chars = 43 bytes > 32, so hashed
        let expected = bridge_storage_key_long(&format!("btcTxHashAP-{}", long_id));
        assert_eq!(key, expected);
    }

    #[test]
    fn all_bridge_keys_are_short_enough() {
        let keys = [
            BTC_TX_HASHES_ALREADY_PROCESSED_KEY,
            RELEASE_REQUEST_QUEUE_KEY,
            PEGOUTS_WAITING_FOR_CONFIRMATIONS_KEY,
            RELEASES_OUTPOINTS_VALUES_KEY,
            PEGOUTS_WAITING_FOR_SIGNATURES_KEY,
            RECEIVE_HEADERS_TIMESTAMP_KEY,
            NEXT_PEGOUT_HEIGHT_KEY,
            BLOCK_STORE_CHAIN_HEAD_KEY,
        ];
        for k in &keys {
            assert!(k.len() <= 32, "Key too long: {k}");
        }
    }

    #[test]
    fn all_federation_keys_are_short_enough() {
        let keys = [
            NEW_FEDERATION_BTC_UTXOS_KEY,
            OLD_FEDERATION_BTC_UTXOS_KEY,
            NEW_FEDERATION_KEY,
            OLD_FEDERATION_KEY,
            PENDING_FEDERATION_KEY,
            PROPOSED_FEDERATION_KEY,
            FEDERATION_ELECTION_KEY,
            ACTIVE_FEDERATION_CREATION_BLOCK_HEIGHT_KEY,
        ];
        for k in &keys {
            assert!(k.len() <= 32, "Key too long: {k}");
        }
    }

    // -----------------------------------------------------------------------
    // Tests ported from rskj
    // -----------------------------------------------------------------------

    /// Ported from rskj DataWordTest.testFromString — verifies that a
    /// 32-byte ASCII key is stored as-is (right-aligned, no hashing).
    #[test]
    fn rskj_from_string_32_byte_key() {
        let input = "01234567890123456789012345678901";
        assert_eq!(input.len(), 32);
        let key = bridge_storage_key(input);
        let bytes = key.to_be_bytes::<32>();
        assert_eq!(&bytes, input.as_bytes());
    }

    /// Ported from rskj DataWordTest.testFromString — short keys are
    /// right-aligned with leading zeros.
    #[test]
    fn rskj_from_string_short_key_right_aligned() {
        let input = "hello";
        let key = bridge_storage_key(input);
        let bytes = key.to_be_bytes::<32>();
        assert_eq!(&bytes[27..], b"hello");
        assert_eq!(&bytes[..27], &[0u8; 27]);
    }

    /// Ported from rskj DataWordTest.testFromLongString — verifies that
    /// long keys are Keccak256 hashed.
    #[test]
    fn rskj_from_long_string_is_keccak256() {
        let value = "012345678901234567890123456789012345678901234567890123456789";
        assert!(value.len() > 32);
        let key = bridge_storage_key_long(value);

        let expected_hash = Keccak256::digest(value.as_bytes());
        let expected = U256::from_be_bytes(expected_hash.into());
        assert_eq!(key, expected);
    }

    /// Verify compound_key switches from fromString to fromLongString at
    /// the 32-byte boundary (matching rskj's BridgeStorageIndexKey behavior).
    #[test]
    fn rskj_compound_key_boundary() {
        // Short compound: "btcBlockHeight-ff" = 17 bytes → fromString
        let short = compound_key("btcBlockHeight", "-", "ff");
        let short_bytes = short.to_be_bytes::<32>();
        assert_eq!(&short_bytes[32 - 17..], b"btcBlockHeight-ff");

        // Long compound: key + delimiter + 64-char hash → >32 bytes → keccak256
        let long_id = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
        let long_key = compound_key("btcTxHashAP", "-", long_id);
        let combined = format!("btcTxHashAP-{}", long_id);
        assert!(combined.len() > 32);
        let expected = bridge_storage_key_long(&combined);
        assert_eq!(long_key, expected);
    }

    /// Verify that the chain head key "blockStoreChainHead" produces the
    /// same storage slot as rskj's DataWord.fromString("blockStoreChainHead").
    #[test]
    fn rskj_chain_head_key_matches() {
        let key = bridge_storage_key("blockStoreChainHead");
        let bytes = key.to_be_bytes::<32>();
        // "blockStoreChainHead" = 19 bytes, right-aligned
        assert_eq!(&bytes[13..], b"blockStoreChainHead");
        assert_eq!(&bytes[..13], &[0u8; 13]);
    }

    /// Verify that concrete Bridge storage key names produce consistent
    /// encodings (regression test).
    #[test]
    fn rskj_bridge_storage_keys_deterministic() {
        let keys_and_lengths = [
            ("btcTxHashesAP", 13),
            ("releaseRequestQueue", 19),
            ("releaseTransactionSet", 21),
            ("rskTxsWaitingFS", 15),
            ("receiveHeadersLastTimestamp", 27),
            ("newFederation", 13),
            ("oldFederation", 13),
            ("pendingFederation", 17),
            ("federationElection", 18),
        ];
        for (name, expected_len) in &keys_and_lengths {
            assert_eq!(name.len(), *expected_len, "key length mismatch for {name}");
            let key = bridge_storage_key(name);
            let bytes = key.to_be_bytes::<32>();
            assert_eq!(&bytes[32 - expected_len..], name.as_bytes());
            // Leading bytes must be zero
            for &b in &bytes[..32 - expected_len] {
                assert_eq!(b, 0, "non-zero leading byte for key {name}");
            }
        }
    }
}
