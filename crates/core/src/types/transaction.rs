use alloy_primitives::{Address, B256, U256, Bytes};
use alloy_rlp::{Decodable, Encodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::rlp_compat::{decode_u64_lenient, decode_u256_lenient};

#[derive(Clone, Debug, Serialize, Deserialize, RlpEncodable)]
pub struct Transaction {
    pub nonce: u64,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: Bytes,
    pub value: U256,
    pub input: Bytes,
    pub v: u64,
    pub r: U256,
    pub s: U256,

    /// Original RLP bytes received from the peer. Java's RLP encoding differs
    /// from Rust's canonical encoding (leading-zero BigIntegers), so we cache
    /// the original bytes and use them for transactions_root computation.
    #[serde(skip)]
    #[rlp(skip)]
    pub cached_rlp: Option<Vec<u8>>,
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.gas_price == other.gas_price
            && self.gas_limit == other.gas_limit
            && self.to == other.to
            && self.value == other.value
            && self.input == other.input
            && self.v == other.v
            && self.r == other.r
            && self.s == other.s
    }
}

impl Eq for Transaction {}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::new(),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        }
    }
}

impl Decodable for Transaction {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let original = *buf;
        let h = alloy_rlp::Header::decode(buf)?;
        if !h.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let mut body = &buf[..h.payload_length];
        *buf = &buf[h.payload_length..];

        let consumed = original.len() - buf.len();
        let cached = original[..consumed].to_vec();

        Ok(Self {
            nonce: decode_u64_lenient(&mut body)?,
            gas_price: decode_u256_lenient(&mut body)?,
            gas_limit: decode_u256_lenient(&mut body)?,
            to: Bytes::decode(&mut body)?,
            value: decode_u256_lenient(&mut body)?,
            input: Bytes::decode(&mut body)?,
            v: decode_u64_lenient(&mut body)?,
            r: decode_u256_lenient(&mut body)?,
            s: decode_u256_lenient(&mut body)?,
            cached_rlp: Some(cached),
        })
    }
}

impl Transaction {
    /// Returns the RLP encoding to use for trie root computation.
    /// Prefers the original bytes (from peer) to match Java's encoding;
    /// falls back to re-encoding if no cached bytes are available.
    pub fn rlp_for_trie(&self) -> Vec<u8> {
        if let Some(ref cached) = self.cached_rlp {
            return cached.clone();
        }
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

impl Transaction {
    /// Compute the signing hash for this transaction, dispatching based on `v`.
    ///
    /// EIP-155 transactions include `[chainId, 0, 0]` in the RLP; legacy ones do not.
    pub fn signing_hash(&self, chain_id: u64) -> B256 {
        if let Some(hash) = self.signing_hash_from_cached(chain_id) {
            return hash;
        }
        if self.is_eip155(chain_id) {
            self.signing_hash_eip155(chain_id)
        } else {
            self.signing_hash_legacy()
        }
    }

    /// Signing hash built from the ORIGINAL (network) encoding. rskj signs
    /// over the raw decoded byte arrays (Transaction.getEncodedRaw), which
    /// may use non-canonical zero encodings — e.g. a literal 0x00 byte for a
    /// zero gasLimit. Re-encoding the parsed fields canonically changes the
    /// hash and recovers the wrong sender, so the first six item encodings
    /// are reused verbatim.
    fn signing_hash_from_cached(&self, chain_id: u64) -> Option<B256> {
        let cached = self.cached_rlp.as_ref()?;
        let mut buf = cached.as_slice();
        let header = alloy_rlp::Header::decode(&mut buf).ok()?;
        if !header.list || buf.len() < header.payload_length {
            return None;
        }
        let mut rest = &buf[..header.payload_length];
        let mut inner = Vec::with_capacity(header.payload_length + 8);
        for _ in 0..6 {
            let item = take_rlp_item(&mut rest)?;
            inner.extend_from_slice(item);
        }
        if self.is_eip155(chain_id) {
            chain_id.encode(&mut inner);
            0u8.encode(&mut inner);
            0u8.encode(&mut inner);
        }
        Some(Self::rlp_wrap_and_hash(&inner))
    }

    /// EIP-155 signing hash: `keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))`.
    pub fn signing_hash_eip155(&self, chain_id: u64) -> B256 {
        let mut inner = Vec::with_capacity(256);
        self.nonce.encode(&mut inner);
        self.gas_price.encode(&mut inner);
        self.gas_limit.encode(&mut inner);
        self.to.encode(&mut inner);
        self.value.encode(&mut inner);
        self.input.encode(&mut inner);
        chain_id.encode(&mut inner);
        0u8.encode(&mut inner);
        0u8.encode(&mut inner);

        Self::rlp_wrap_and_hash(&inner)
    }

    /// Legacy (pre-EIP-155) signing hash: `keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data]))`.
    pub fn signing_hash_legacy(&self) -> B256 {
        let mut inner = Vec::with_capacity(256);
        self.nonce.encode(&mut inner);
        self.gas_price.encode(&mut inner);
        self.gas_limit.encode(&mut inner);
        self.to.encode(&mut inner);
        self.value.encode(&mut inner);
        self.input.encode(&mut inner);

        Self::rlp_wrap_and_hash(&inner)
    }

    fn rlp_wrap_and_hash(inner: &[u8]) -> B256 {
        let mut buf = Vec::with_capacity(inner.len() + 5);
        alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut buf);
        buf.extend_from_slice(inner);
        B256::from_slice(&Keccak256::digest(&buf))
    }
}

/// Advance past one RLP item, returning its full encoding (header + payload).
fn take_rlp_item<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let start = *buf;
    let mut peek = *buf;
    let header = alloy_rlp::Header::decode(&mut peek).ok()?;
    let total = (start.len() - peek.len()) + header.payload_length;
    if start.len() < total {
        return None;
    }
    let (item, rest) = start.split_at(total);
    *buf = rest;
    Some(item)
}

impl Transaction {

    /// Recover the sender address from the transaction signature.
    ///
    /// RSK chain IDs: mainnet=30, testnet=31, regtest=33.
    pub fn recover_sender(&self, chain_id: u64) -> anyhow::Result<Address> {
        let hash = self.signing_hash(chain_id);

        let recovery_id = if self.is_eip155(chain_id) {
            let rid = self.v as i64 - chain_id as i64 * 2 - 35;
            if !(0..=1).contains(&rid) {
                anyhow::bail!("invalid EIP-155 v value: {} for chain_id {}", self.v, chain_id);
            }
            rid as u8
        } else {
            if self.v != 27 && self.v != 28 {
                anyhow::bail!("invalid legacy v value: {}", self.v);
            }
            (self.v - 27) as u8
        };

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        sig_bytes[32..].copy_from_slice(&self.s.to_be_bytes::<32>());

        let signature = k256::ecdsa::Signature::from_slice(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))?;
        let recid = k256::ecdsa::RecoveryId::from_byte(recovery_id)
            .ok_or_else(|| anyhow::anyhow!("invalid recovery id: {recovery_id}"))?;

        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(hash.as_slice(), &signature, recid)
            .map_err(|e| anyhow::anyhow!("ECDSA recovery failed: {e}"))?;

        let pubkey_bytes = vk.to_encoded_point(false);
        let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
        Ok(Address::from_slice(&pubkey_hash[12..]))
    }

    pub fn is_eip155(&self, chain_id: u64) -> bool {
        self.v != 27 && self.v != 28 && self.v >= chain_id * 2 + 35
    }

    /// Recover the compressed (33-byte) secp256k1 public key from the transaction signature.
    ///
    /// Used to derive the BTC P2PKH address for peg-out destination:
    /// `RIPEMD160(SHA256(compressed_pubkey))` = BTC hash160.
    ///
    /// Returns `None` if the signature is invalid or missing.
    pub fn recover_compressed_pubkey(&self, chain_id: u64) -> Option<[u8; 33]> {
        let hash = self.signing_hash(chain_id);

        let recovery_id = if self.is_eip155(chain_id) {
            let rid = self.v as i64 - chain_id as i64 * 2 - 35;
            if !(0..=1).contains(&rid) { return None; }
            rid as u8
        } else {
            if self.v != 27 && self.v != 28 { return None; }
            (self.v - 27) as u8
        };

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        sig_bytes[32..].copy_from_slice(&self.s.to_be_bytes::<32>());

        let signature = k256::ecdsa::Signature::from_slice(&sig_bytes).ok()?;
        let recid = k256::ecdsa::RecoveryId::from_byte(recovery_id)?;

        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(
            hash.as_slice(),
            &signature,
            recid,
        ).ok()?;

        let compressed = vk.to_encoded_point(true);
        let mut arr = [0u8; 33];
        arr.copy_from_slice(compressed.as_bytes());
        Some(arr)
    }

    /// Compute the Keccak256 hash of this transaction's RLP bytes.
    /// This is the standard Ethereum/RSK transaction hash.
    pub fn tx_hash(&self) -> B256 {
        let rlp = self.rlp_for_trie();
        B256::from_slice(&Keccak256::digest(&rlp))
    }

    /// Derive the BTC P2PKH destination hash160 for this transaction's sender.
    ///
    /// Matches rskj's `BridgeUtils.recoverBtcAddressFromEthTransaction`:
    /// recovers the compressed public key from the ECDSA signature, then computes
    /// `RIPEMD160(SHA256(compressed_pubkey))`.
    pub fn btc_sender_hash160(&self, chain_id: u64) -> Option<[u8; 20]> {
        use sha2::Digest as Sha2Digest;
        let compressed = self.recover_compressed_pubkey(chain_id)?;
        let sha256_hash = sha2::Sha256::digest(&compressed);
        let hash160 = ripemd::Ripemd160::digest(sha256_hash);
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&hash160);
        Some(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use alloy_rlp::Decodable;

    #[test]
    fn test_transaction_rlp_roundtrip() {
        let tx = Transaction {
            nonce: 42,
            gas_price: U256::from(20_000_000_000u64),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0x12; 20]),
            value: U256::from(1_000_000_000_000_000_000u64),
            input: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
            v: 1,
            r: U256::from(123),
            s: U256::from(456),
            cached_rlp: None,
        };

        let mut buffer = Vec::new();
        tx.encode(&mut buffer);

        let decoded = Transaction::decode(&mut buffer.as_slice()).expect("Failed to decode transaction");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_signing_hash_eip155() {
        let tx = Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0xBB; 20]),
            value: U256::from(1000),
            input: Bytes::new(),
            v: 95, // chain_id=30: 30*2+35=95
            r: U256::from(1),
            s: U256::from(1),
            cached_rlp: None,
        };
        assert!(tx.is_eip155(30));

        let hash1 = tx.signing_hash(30);
        let hash2 = tx.signing_hash(30);
        assert_eq!(hash1, hash2, "signing hash should be deterministic");

        let hash_direct = tx.signing_hash_eip155(31);
        assert_ne!(hash1, hash_direct, "different chain_id should produce different hash");

        let legacy = tx.signing_hash_legacy();
        assert_ne!(hash1, legacy, "EIP-155 hash differs from legacy hash");
    }

    #[test]
    fn test_signing_hash_legacy() {
        let tx = Transaction {
            nonce: 0,
            gas_price: U256::from(1),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0xBB; 20]),
            value: U256::from(1000),
            input: Bytes::new(),
            v: 27,
            r: U256::from(1),
            s: U256::from(1),
            cached_rlp: None,
        };

        let hash = tx.signing_hash(30);
        assert_ne!(hash, B256::ZERO);
    }

    #[test]
    fn test_recover_sender_roundtrip() {
        use k256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let chain_id = 33u64; // regtest

        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::from(0),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0xBB; 20]),
            value: U256::from(100),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };

        // Compute signing hash before v/r/s are set — use EIP-155 variant directly
        let hash = tx.signing_hash_eip155(chain_id);

        let (signature, recid) = signing_key
            .sign_prehash_recoverable(hash.as_slice())
            .unwrap();

        let sig_bytes = signature.to_bytes();
        tx.r = U256::from_be_slice(&sig_bytes[..32]);
        tx.s = U256::from_be_slice(&sig_bytes[32..]);
        tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;

        // Now recover_sender uses signing_hash(chain_id) which checks v → EIP-155
        let recovered = tx.recover_sender(chain_id).unwrap();

        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let expected_addr = Address::from_slice(
            &Keccak256::digest(&pubkey.as_bytes()[1..])[12..],
        );

        assert_eq!(recovered, expected_addr, "recovered sender should match signing key");
    }

    /// Regression for mainnet block #457: rskj signs over the ORIGINAL field
    /// byte arrays, which may use non-canonical zero encodings (the free
    /// bridge txs encode gasLimit as a literal 0x00 byte). The signing hash
    /// must reuse the original encoding, not a canonical re-encoding.
    #[test]
    fn test_recover_sender_with_noncanonical_zero_gas_limit() {
        use k256::ecdsa::SigningKey;

        // [nonce=empty, gasPrice=0x01, gasLimit=0x00 (raw zero byte), to, value=empty, data=empty]
        let mut fields = vec![0x80, 0x01, 0x00, 0x94];
        fields.extend_from_slice(&[0x11u8; 20]);
        fields.extend_from_slice(&[0x80, 0x80]);

        // rskj getEncodedRaw with chainId 30: fields ++ [chainId, empty, empty]
        let mut sign_inner = fields.clone();
        sign_inner.extend_from_slice(&[30, 0x80, 0x80]);
        let mut sign_buf = Vec::new();
        alloy_rlp::Header { list: true, payload_length: sign_inner.len() }.encode(&mut sign_buf);
        sign_buf.extend_from_slice(&sign_inner);
        let sign_hash: [u8; 32] = Keccak256::digest(&sign_buf).into();

        // Sign with private key 0x...01 (address 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf)
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        let sk = SigningKey::from_slice(&key_bytes).unwrap();
        let (sig, rid) = sk.sign_prehash_recoverable(&sign_hash).unwrap();

        // Assemble the signed tx: fields ++ [v, r, s] (EIP-155, chainId 30)
        let mut inner = fields;
        let v = 35u64 + 60 + rid.to_byte() as u64;
        v.encode(&mut inner);
        U256::from_be_slice(&sig.r().to_bytes()).encode(&mut inner);
        U256::from_be_slice(&sig.s().to_bytes()).encode(&mut inner);
        let mut raw = Vec::new();
        alloy_rlp::Header { list: true, payload_length: inner.len() }.encode(&mut raw);
        raw.extend_from_slice(&inner);

        let tx = Transaction::decode(&mut raw.as_slice()).unwrap();
        assert_eq!(tx.gas_limit, U256::ZERO);
        let sender = tx.recover_sender(30).unwrap();
        let expected: Address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf".parse().unwrap();
        assert_eq!(sender, expected, "sender must recover from the original encoding");
    }
}
