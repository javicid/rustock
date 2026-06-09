/// RSK account state RLP encoding.
///
/// Accounts are stored in the Unitrie as RLP lists:
/// - `[nonce, balance]` when stateFlags == 0
/// - `[nonce, balance, stateFlags]` otherwise
///
/// Unlike Ethereum, RSK does not store storageRoot or codeHash in the account.
/// These are derived from the Unitrie key layout instead.
use alloy_primitives::U256;
use alloy_rlp::{Decodable, Encodable};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountState {
    pub nonce: U256,
    pub balance: U256,
    pub state_flags: u32,
}

impl AccountState {
    pub fn new(nonce: U256, balance: U256) -> Self {
        Self { nonce, balance, state_flags: 0 }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // nonce: rskj `RLP.encodeBigInteger` — zero is RLP-empty (0x80),
        // non-zero is the unsigned minimal big-endian bytes (standard RLP).
        let nonce_enc = encode_u256(&self.nonce);
        // balance: rskj `RLP.encodeSignedCoinNonNullZero` — zero is the single
        // byte 0x00 (NOT RLP-empty), non-zero is the SIGNED big-endian bytes
        // (`Coin.getBytes` = `BigInteger.toByteArray`, leading 0x00 when the top
        // bit is set). This differs from `nonce`/standard RLP and is required
        // for the unitrie account record to match rskj byte-for-byte.
        let balance_enc = encode_coin_nonnull_zero(&self.balance);

        if self.state_flags != 0 {
            let flags_enc = encode_u32(self.state_flags);
            let total = nonce_enc.len() + balance_enc.len() + flags_enc.len();
            alloy_rlp::Header { list: true, payload_length: total }.encode(&mut buf);
            buf.extend_from_slice(&nonce_enc);
            buf.extend_from_slice(&balance_enc);
            buf.extend_from_slice(&flags_enc);
        } else {
            let total = nonce_enc.len() + balance_enc.len();
            alloy_rlp::Header { list: true, payload_length: total }.encode(&mut buf);
            buf.extend_from_slice(&nonce_enc);
            buf.extend_from_slice(&balance_enc);
        }
        buf
    }

    pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
        let mut cursor = data;
        let header = alloy_rlp::Header::decode(&mut cursor)?;
        anyhow::ensure!(header.list, "AccountState must be an RLP list");

        let nonce = decode_u256(&mut cursor)?;
        // balance uses the NonNullZero/signed encoding; read it leniently
        // (accepts 0x00, signed leading-zero bytes, and the legacy 0x80).
        let balance = decode_coin(&mut cursor)?;

        let state_flags = if !cursor.is_empty() {
            decode_u32(&mut cursor)?
        } else {
            0
        };

        Ok(Self { nonce, balance, state_flags })
    }
}

fn encode_u256(v: &U256) -> Vec<u8> {
    let mut buf = Vec::new();
    v.encode(&mut buf);
    buf
}

/// rskj `RLP.encodeSignedCoinNonNullZero`: zero balance is the single raw byte
/// `0x00`; a non-zero balance is `RLP.encodeElement(Coin.getBytes())` where
/// `Coin.getBytes()` is `BigInteger.toByteArray()` (signed two's-complement, so
/// a leading `0x00` is prepended when the most-significant bit is set).
fn encode_coin_nonnull_zero(balance: &U256) -> Vec<u8> {
    if balance.is_zero() {
        return vec![0x00];
    }
    let be = balance.to_be_bytes::<32>();
    let start = be.iter().position(|b| *b != 0).unwrap();
    let mut signed = Vec::with_capacity(33 - start);
    if be[start] & 0x80 != 0 {
        signed.push(0);
    }
    signed.extend_from_slice(&be[start..]);
    let mut out = Vec::new();
    signed.as_slice().encode(&mut out);
    out
}

/// Read one RLP byte-string item and interpret it as an unsigned big-endian
/// integer (leading zeros, signed-sign bytes, and the legacy RLP-empty form all
/// decode to the same value). Inverse of `encode_coin_nonnull_zero`.
fn decode_coin(cursor: &mut &[u8]) -> anyhow::Result<U256> {
    let first = *cursor.first().ok_or_else(|| anyhow::anyhow!("coin: empty"))?;
    let bytes: &[u8] = if first < 0x80 {
        let b = &cursor[..1];
        *cursor = &cursor[1..];
        b
    } else if first < 0xb8 {
        let len = (first - 0x80) as usize;
        anyhow::ensure!(cursor.len() >= 1 + len, "coin: short string truncated");
        let b = &cursor[1..1 + len];
        *cursor = &cursor[1 + len..];
        b
    } else {
        let ll = (first - 0xb7) as usize;
        anyhow::ensure!(cursor.len() >= 1 + ll, "coin: long header truncated");
        let len = cursor[1..1 + ll].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        anyhow::ensure!(cursor.len() >= 1 + ll + len, "coin: long string truncated");
        let b = &cursor[1 + ll..1 + ll + len];
        *cursor = &cursor[1 + ll + len..];
        b
    };
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    anyhow::ensure!(bytes.len() - start <= 32, "coin: value exceeds 32 bytes");
    Ok(U256::from_be_slice(&bytes[start..]))
}

fn encode_u32(v: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    let u = U256::from(v);
    u.encode(&mut buf);
    buf
}

fn decode_u256(cursor: &mut &[u8]) -> anyhow::Result<U256> {
    Ok(U256::decode(cursor)?)
}

fn decode_u32(cursor: &mut &[u8]) -> anyhow::Result<u32> {
    let v = U256::decode(cursor)?;
    Ok(v.to::<u32>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_basic() {
        let acct = AccountState::new(U256::from(42), U256::from(1_000_000));
        let encoded = acct.encode();
        let decoded = AccountState::decode(&encoded).unwrap();
        assert_eq!(decoded, acct);
    }

    #[test]
    fn test_encode_decode_with_flags() {
        let acct = AccountState {
            nonce: U256::from(1),
            balance: U256::from(2),
            state_flags: 3,
        };
        let encoded = acct.encode();
        let decoded = AccountState::decode(&encoded).unwrap();
        assert_eq!(decoded, acct);
    }

    #[test]
    fn test_encode_decode_zero() {
        let acct = AccountState::default();
        let encoded = acct.encode();
        let decoded = AccountState::decode(&encoded).unwrap();
        assert_eq!(decoded, acct);
    }

    #[test]
    fn test_no_flags_when_zero() {
        let acct = AccountState::new(U256::from(1), U256::from(2));
        let encoded = acct.encode();
        // With flags=0, the list should have 2 items, not 3
        let acct_with_flags = AccountState {
            nonce: U256::from(1),
            balance: U256::from(2),
            state_flags: 1,
        };
        let encoded_with_flags = acct_with_flags.encode();
        assert!(encoded.len() < encoded_with_flags.len());
    }

    /// Ground truth from rskj's unitrie (mainnet #3397, dumped via
    /// `co.rsk.cli.tools.ExportState`): a zero-balance account encodes the
    /// balance as the single byte `0x00` (`RLP.encodeSignedCoinNonNullZero`),
    /// NOT the RLP-empty `0x80`. The REMASC contract (nonce 0, balance 0) is
    /// `c28000`; a fresh EOA (nonce 1, balance 0) is `c20100`.
    #[test]
    fn rskj_nonnull_zero_balance_encoding() {
        assert_eq!(
            alloy_primitives::hex::encode(AccountState::new(U256::ZERO, U256::ZERO).encode()),
            "c28000",
            "nonce 0 / balance 0 (REMASC contract record)"
        );
        assert_eq!(
            alloy_primitives::hex::encode(AccountState::new(U256::from(1), U256::ZERO).encode()),
            "c20100",
            "nonce 1 / balance 0 (fresh EOA)"
        );
    }

    /// rskj `Coin.getBytes()` is `BigInteger.toByteArray()` (signed), so a
    /// balance whose minimal big-endian top byte has its high bit set gets a
    /// leading `0x00`. Balance 128 (0x80) → element `82 00 80`.
    #[test]
    fn signed_balance_high_bit_gets_zero_prefix() {
        assert_eq!(
            alloy_primitives::hex::encode(AccountState::new(U256::ZERO, U256::from(128)).encode()),
            "c480820080"
        );
        // round-trips back to the same value
        let enc = AccountState::new(U256::from(7), U256::from(128)).encode();
        assert_eq!(AccountState::decode(&enc).unwrap(), AccountState::new(U256::from(7), U256::from(128)));
    }

    /// Decoding tolerates the NonNullZero form (0x00), signed leading zeros,
    /// and the legacy RLP-empty form (0x80) — all map to the same value.
    #[test]
    fn decode_coin_tolerates_encodings() {
        // c28000 (NonNullZero zero) and the legacy c28080 both decode to (0,0).
        assert_eq!(AccountState::decode(&alloy_primitives::hex::decode("c28000").unwrap()).unwrap(), AccountState::new(U256::ZERO, U256::ZERO));
        assert_eq!(AccountState::decode(&alloy_primitives::hex::decode("c28080").unwrap()).unwrap(), AccountState::new(U256::ZERO, U256::ZERO));
    }

    #[test]
    fn test_large_balance() {
        let balance = U256::from(10u64).pow(U256::from(18)); // 1 ETH/RBTC in wei
        let acct = AccountState::new(U256::ZERO, balance);
        let encoded = acct.encode();
        let decoded = AccountState::decode(&encoded).unwrap();
        assert_eq!(decoded.balance, balance);
    }
}
