//! Federation types for the RSK Bridge.
//!
//! A Federation is a group of signers that control the Bridge's BTC multisig
//! wallet. Each member has three key types: BTC, RSK, and MST (merged-mining
//! signing tool). The federation address is derived from the BTC public keys
//! using a P2SH multisig script.

/// A member of a Bridge federation.
///
/// Matches rskj's `FederationMember`. Each member has three public keys:
/// - BTC key: used for signing BTC transactions (peg-out, migration)
/// - RSK key: used for authorization checks on RSK
/// - MST key: used for merged-mining signing tool operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationMember {
    /// Compressed BTC public key (33 bytes).
    pub btc_public_key: Vec<u8>,
    /// Compressed RSK public key (33 bytes).
    pub rsk_public_key: Vec<u8>,
    /// Compressed MST public key (33 bytes).
    pub mst_public_key: Vec<u8>,
}

impl FederationMember {
    pub fn new(btc_key: Vec<u8>, rsk_key: Vec<u8>, mst_key: Vec<u8>) -> Self {
        Self {
            btc_public_key: btc_key,
            rsk_public_key: rsk_key,
            mst_public_key: mst_key,
        }
    }

    /// Create a member with the same key for all three types (legacy format).
    pub fn from_single_key(key: Vec<u8>) -> Self {
        Self {
            btc_public_key: key.clone(),
            rsk_public_key: key.clone(),
            mst_public_key: key,
        }
    }
}

/// Key type identifiers matching rskj's `FederationMember.KeyType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationKeyType {
    BTC = 0,
    RSK = 1,
    MST = 2,
}

impl FederationKeyType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "btc" => Some(Self::BTC),
            "rsk" => Some(Self::RSK),
            "mst" => Some(Self::MST),
            _ => None,
        }
    }
}

/// Arguments for creating a new federation.
#[derive(Debug, Clone)]
pub struct FederationArgs {
    pub members: Vec<FederationMember>,
    pub creation_time: u64,
    pub creation_block_number: u64,
    /// BTC network parameters (determines address format).
    pub btc_network: super::constants::BtcNetwork,
}

/// A standard multisig federation.
///
/// Matches rskj's `Federation` / `StandardMultisigFederation`.
/// The federation controls a P2SH multisig BTC address.
#[derive(Debug, Clone)]
pub struct Federation {
    pub members: Vec<FederationMember>,
    pub creation_time: u64,
    pub creation_block_number: u64,
    pub btc_network: super::constants::BtcNetwork,
}

impl Federation {
    pub fn new(args: FederationArgs) -> Self {
        Self {
            members: args.members,
            creation_time: args.creation_time,
            creation_block_number: args.creation_block_number,
            btc_network: args.btc_network,
        }
    }

    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// M-of-N threshold: floor(N/2) + 1 (simple majority).
    pub fn threshold(&self) -> usize {
        self.members.len() / 2 + 1
    }

    /// Get a member's public key by index and type.
    pub fn get_public_key(&self, index: usize, key_type: FederationKeyType) -> Option<&[u8]> {
        let member = self.members.get(index)?;
        Some(match key_type {
            FederationKeyType::BTC => &member.btc_public_key,
            FederationKeyType::RSK => &member.rsk_public_key,
            FederationKeyType::MST => &member.mst_public_key,
        })
    }

    /// Get the BTC public key of a member by index.
    pub fn get_btc_public_key(&self, index: usize) -> Option<&[u8]> {
        self.get_public_key(index, FederationKeyType::BTC)
    }
}

/// Emergency Recovery Protocol (ERP) federation.
///
/// Extends the standard federation with time-locked emergency keys
/// that can be used to recover funds if the main federation keys
/// become unavailable after a specified CSV delay.
#[derive(Debug, Clone)]
pub struct ErpFederation {
    /// The standard federation.
    pub federation: Federation,
    /// ERP public keys (emergency recovery).
    pub erp_public_keys: Vec<Vec<u8>>,
    /// CSV (CheckSequenceVerify) delay in BTC blocks.
    pub csv_value: u64,
}

impl ErpFederation {
    pub fn new(federation: Federation, erp_keys: Vec<Vec<u8>>, csv_value: u64) -> Self {
        Self {
            federation,
            erp_public_keys: erp_keys,
            csv_value,
        }
    }

    pub fn size(&self) -> usize {
        self.federation.size()
    }

    pub fn threshold(&self) -> usize {
        self.federation.threshold()
    }
}

/// Pending federation (being assembled, not yet committed).
#[derive(Debug, Clone)]
pub struct PendingFederation {
    pub members: Vec<FederationMember>,
}

impl PendingFederation {
    pub fn new(members: Vec<FederationMember>) -> Self {
        Self { members }
    }

    pub fn size(&self) -> usize {
        self.members.len()
    }
}

/// Federation change response codes matching rskj.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationChangeResponseCode {
    Successful = 1,
    AlreadyExists = -1,
    DoesNotExist = -2,
    InsufficientMembers = -3,
    Unauthorized = -10,
    GenericError = 0,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_threshold() {
        let members: Vec<FederationMember> = (0..5)
            .map(|i| FederationMember::from_single_key(vec![i; 33]))
            .collect();
        let fed = Federation {
            members,
            creation_time: 0,
            creation_block_number: 0,
            btc_network: super::super::constants::BtcNetwork::Regtest,
        };
        assert_eq!(fed.size(), 5);
        assert_eq!(fed.threshold(), 3); // 5/2 + 1 = 3
    }

    #[test]
    fn federation_threshold_even() {
        let members: Vec<FederationMember> = (0..4)
            .map(|i| FederationMember::from_single_key(vec![i; 33]))
            .collect();
        let fed = Federation {
            members,
            creation_time: 0,
            creation_block_number: 0,
            btc_network: super::super::constants::BtcNetwork::Regtest,
        };
        assert_eq!(fed.threshold(), 3); // 4/2 + 1 = 3
    }

    #[test]
    fn get_public_key_by_type() {
        let btc = vec![0x02; 33];
        let rsk = vec![0x03; 33];
        let mst = vec![0x04; 33];
        let member = FederationMember::new(btc.clone(), rsk.clone(), mst.clone());
        let fed = Federation {
            members: vec![member],
            creation_time: 0,
            creation_block_number: 0,
            btc_network: super::super::constants::BtcNetwork::Regtest,
        };

        assert_eq!(fed.get_public_key(0, FederationKeyType::BTC).unwrap(), &btc);
        assert_eq!(fed.get_public_key(0, FederationKeyType::RSK).unwrap(), &rsk);
        assert_eq!(fed.get_public_key(0, FederationKeyType::MST).unwrap(), &mst);
        assert!(fed.get_public_key(1, FederationKeyType::BTC).is_none());
    }
}
