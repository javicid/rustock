/// Unitrie key derivation matching rskj's TrieKeyMapper.
///
/// All keys share a unified keyspace in the single trie:
/// - Account: `0x00 || keccak256(addr)[0:10] || addr`  (31 bytes for 20-byte addr)
/// - Code:    `account_key || 0x80`
/// - Storage: `account_key || 0x00 || keccak256(slot)[0:10] || strip_leading_zeros(slot)`
use alloy_primitives::{Address, B256};
use sha3::{Digest, Keccak256};

const SECURE_KEY_SIZE: usize = 10;
const DOMAIN_PREFIX: u8 = 0x00;
const STORAGE_PREFIX: u8 = 0x00;
const CODE_PREFIX: u8 = 0x80;

fn secure_prefix(data: &[u8]) -> [u8; SECURE_KEY_SIZE] {
    let hash = Keccak256::digest(data);
    let mut prefix = [0u8; SECURE_KEY_SIZE];
    prefix.copy_from_slice(&hash[..SECURE_KEY_SIZE]);
    prefix
}

/// rskj `ByteUtil.stripLeadingZeroes` with the default `valueForZero =
/// ZERO_BYTE_ARRAY`: a leading run of zeros is removed, but an ALL-zero input
/// returns a single `0x00` byte (not empty). The storage slot 0x00..00 must
/// keep that trailing byte or its unitrie key (hence the state root) diverges.
fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    match data.iter().position(|&b| b != 0) {
        Some(start) => &data[start..],
        None if data.is_empty() => data,
        None => &data[data.len() - 1..], // all zeros → single 0x00 byte
    }
}

/// Computes the trie key for an account address.
/// Result: `0x00 || keccak256(addr)[0:10] || addr` (31 bytes for standard 20-byte addresses).
pub fn account_key(addr: &Address) -> Vec<u8> {
    account_key_from_bytes(addr.as_slice())
}

/// Computes the trie key for an account from raw address bytes.
/// REMASC uses a 1-byte address `[0x00]`, producing a 12-byte key.
pub fn account_key_from_bytes(addr_bytes: &[u8]) -> Vec<u8> {
    let prefix = secure_prefix(addr_bytes);
    let mut key = Vec::with_capacity(1 + SECURE_KEY_SIZE + addr_bytes.len());
    key.push(DOMAIN_PREFIX);
    key.extend_from_slice(&prefix);
    key.extend_from_slice(addr_bytes);
    key
}

/// Computes the trie key of an account's storage-prefix node.
/// Result: `account_key || 0x00`. rskj `setupContract` stores `[0x01]` here
/// for every contract; the node is consensus-relevant (part of the unitrie
/// state root) even though no RPC exposes it.
pub fn storage_prefix_key(addr: &Address) -> Vec<u8> {
    let mut key = account_key(addr);
    key.push(STORAGE_PREFIX);
    key
}

/// Computes the trie key for an account's code.
/// Result: `account_key || 0x80`.
pub fn code_key(addr: &Address) -> Vec<u8> {
    code_key_from_bytes(addr.as_slice())
}

pub fn code_key_from_bytes(addr_bytes: &[u8]) -> Vec<u8> {
    let mut key = account_key_from_bytes(addr_bytes);
    key.push(CODE_PREFIX);
    key
}

/// Computes the trie key for a storage slot.
/// Result: `account_key || 0x00 || keccak256(slot)[0:10] || strip_leading_zeros(slot)`.
pub fn storage_key(addr: &Address, slot: &B256) -> Vec<u8> {
    storage_key_from_bytes(addr.as_slice(), slot.as_slice())
}

pub fn storage_key_from_bytes(addr_bytes: &[u8], slot_bytes: &[u8]) -> Vec<u8> {
    let acct_key = account_key_from_bytes(addr_bytes);
    let stripped = strip_leading_zeros(slot_bytes);
    let slot_prefix = secure_prefix(slot_bytes);

    let mut key = Vec::with_capacity(acct_key.len() + 1 + SECURE_KEY_SIZE + stripped.len());
    key.extend_from_slice(&acct_key);
    key.push(STORAGE_PREFIX);
    key.extend_from_slice(&slot_prefix);
    key.extend_from_slice(stripped);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_key_length() {
        let addr = Address::ZERO;
        let key = account_key(&addr);
        // 1 (domain) + 10 (secure) + 20 (addr) = 31
        assert_eq!(key.len(), 31);
        assert_eq!(key[0], 0x00); // domain prefix
    }

    #[test]
    fn test_code_key_length() {
        let addr = Address::ZERO;
        let key = code_key(&addr);
        assert_eq!(key.len(), 32); // account key + 0x80
        assert_eq!(*key.last().unwrap(), 0x80);
    }

    #[test]
    fn test_storage_key() {
        let addr = Address::ZERO;
        let slot = B256::ZERO;
        let key = storage_key(&addr, &slot);
        // account_key (31) + 1 (storage prefix) + 10 (secure) + 1 (all-zero slot
        // strips to a single 0x00 byte, rskj ByteUtil.stripLeadingZeroes) = 43
        assert_eq!(key.len(), 43);
        assert_eq!(*key.last().unwrap(), 0x00);
    }

    #[test]
    fn test_storage_key_with_nonzero_slot() {
        let addr = Address::ZERO;
        let mut slot_bytes = [0u8; 32];
        slot_bytes[31] = 1; // slot = 1
        let slot = B256::from(slot_bytes);
        let key = storage_key(&addr, &slot);
        // account_key (31) + 1 (storage prefix) + 10 (secure) + 1 (stripped) = 43
        assert_eq!(key.len(), 43);
    }

    /// Ground truth from rskj's unitrie (mainnet #3397 dump): the REMASC
    /// `siblings` storage cell (`addStorageBytes(REMASC, DataWord("siblings"),
    /// ...)`) lives at this exact 50-byte unitrie key.
    #[test]
    fn rskj_remasc_siblings_storage_key() {
        let remasc: Address = "0x0000000000000000000000000000000001000008".parse().unwrap();
        // DataWord.fromString("siblings"): UTF-8 right-aligned in 32 bytes.
        let mut slot = [0u8; 32];
        let name = b"siblings";
        slot[32 - name.len()..].copy_from_slice(name);
        let key = storage_key(&remasc, &B256::from(slot));
        assert_eq!(
            alloy_primitives::hex::encode(key),
            "00611cb96d0a346b10bab90000000000000000000000000000000001000008005a7de95ffc33d519294c7369626c696e6773"
        );
    }

    #[test]
    fn test_remasc_account_key() {
        // REMASC address is a single byte [0x00]
        let key = account_key_from_bytes(&[0x00]);
        // 1 (domain) + 10 (secure) + 1 (addr) = 12
        assert_eq!(key.len(), 12);
    }

    #[test]
    fn test_deterministic_keys() {
        let addr = Address::from([0xAB; 20]);
        let k1 = account_key(&addr);
        let k2 = account_key(&addr);
        assert_eq!(k1, k2);
    }
}
