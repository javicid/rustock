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
        let nonce_enc = encode_u256(&self.nonce);
        let balance_enc = encode_u256(&self.balance);

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
        let balance = decode_u256(&mut cursor)?;

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

    #[test]
    fn test_large_balance() {
        let balance = U256::from(10u64).pow(U256::from(18)); // 1 ETH/RBTC in wei
        let acct = AccountState::new(U256::ZERO, balance);
        let encoded = acct.encode();
        let decoded = AccountState::decode(&encoded).unwrap();
        assert_eq!(decoded.balance, balance);
    }
}
