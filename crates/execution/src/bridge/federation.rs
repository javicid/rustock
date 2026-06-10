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

/// RSK address of a federation member from its secp256k1 public key
/// (compressed or uncompressed): keccak256 of the uncompressed point's
/// 64 coordinate bytes, last 20 bytes (rskj ECKey.getAddress).
pub fn rsk_address_from_public_key(key: &[u8]) -> Option<alloy_primitives::Address> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha3::Digest;
    let parsed = k256::PublicKey::from_sec1_bytes(key).ok()?;
    let point = parsed.to_encoded_point(false);
    let digest = sha3::Keccak256::digest(&point.as_bytes()[1..]);
    Some(alloy_primitives::Address::from_slice(&digest[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground truth: rskj's mainnet `newFederation` cell transitions from the
    /// only-BTC-keys format (#1,591,008) to the RSKIP123 multikey member
    /// format (#1,591,009), where each member is `RLP[btc, rsk, mst]` with
    /// rsk = mst = btc for the legacy genesis federation. Both byte strings
    /// are dumped from the synced ~/.rsk/mainnet unitrie.
    #[test]
    fn rskj_multikey_federation_serialization_groundtruth_1591009() {
        use super::super::serialization::{rlp_decode_list, rlp_decode_u64};
        use alloy_primitives::hex;

        let old = hex::decode(
            "f9020a845bbe1690830c7085f901fea10245ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffeeaa1024cd9f00935993695af7e6c35165550a79eeac9fdfe95df83c5fdd8692ba2ef9ea1027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344a10294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adca102ac1901b6fba2c1dbd47d894d2bd76c8ba1d296d65f6ab47f1c6b22afb53e73eba102c6018fcbd3e89f3cf9c7f48b3232ea3638eb8bf217e59ee290f5f0cfb2fb9259a1031aabbeb9b27258f98c2bf21f36677ae7bae09eb2d8c958ef41a20a6e88626d26a103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93a10340df69f28d69eef60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb44a10372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6a103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6a103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2a103b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573a103d789669ec532f756461d3d6d83b316ed0c4272d48dc3b60cce0f494e9a09d3e7a103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d",
        )
        .unwrap();
        let new = hex::decode(
            "f90642845bbe1690830c7085f90636b868f866a10245ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffeeaa10245ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffeeaa10245ef34f5ee218005c9c21227133e8568a4f3f11aeab919c66ff7b816ae1ffeeab868f866a1024cd9f00935993695af7e6c35165550a79eeac9fdfe95df83c5fdd8692ba2ef9ea1024cd9f00935993695af7e6c35165550a79eeac9fdfe95df83c5fdd8692ba2ef9ea1024cd9f00935993695af7e6c35165550a79eeac9fdfe95df83c5fdd8692ba2ef9eb868f866a1027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344a1027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344a1027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936d85548d9395bcc2344b868f866a10294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adca10294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adca10294c817150f78607566e961b3c71df53a22022a80acbb982f83c0c8baac040adcb868f866a102ac1901b6fba2c1dbd47d894d2bd76c8ba1d296d65f6ab47f1c6b22afb53e73eba102ac1901b6fba2c1dbd47d894d2bd76c8ba1d296d65f6ab47f1c6b22afb53e73eba102ac1901b6fba2c1dbd47d894d2bd76c8ba1d296d65f6ab47f1c6b22afb53e73ebb868f866a102c6018fcbd3e89f3cf9c7f48b3232ea3638eb8bf217e59ee290f5f0cfb2fb9259a102c6018fcbd3e89f3cf9c7f48b3232ea3638eb8bf217e59ee290f5f0cfb2fb9259a102c6018fcbd3e89f3cf9c7f48b3232ea3638eb8bf217e59ee290f5f0cfb2fb9259b868f866a1031aabbeb9b27258f98c2bf21f36677ae7bae09eb2d8c958ef41a20a6e88626d26a1031aabbeb9b27258f98c2bf21f36677ae7bae09eb2d8c958ef41a20a6e88626d26a1031aabbeb9b27258f98c2bf21f36677ae7bae09eb2d8c958ef41a20a6e88626d26b868f866a103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93a103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93a103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93b868f866a10340df69f28d69eef60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb44a10340df69f28d69eef60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb44a10340df69f28d69eef60845da7d81ff60a9060d4da35c767f017b0dd4e20448fb44b868f866a10372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6a10372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6a10372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6b868f866a103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6a103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6a103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989fb880f6b868f866a103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2a103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2a103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cbad2b868f866a103b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573a103b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573a103b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573b868f866a103d789669ec532f756461d3d6d83b316ed0c4272d48dc3b60cce0f494e9a09d3e7a103d789669ec532f756461d3d6d83b316ed0c4272d48dc3b60cce0f494e9a09d3e7a103d789669ec532f756461d3d6d83b316ed0c4272d48dc3b60cce0f494e9a09d3e7b868f866a103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8da103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8da103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d",
        )
        .unwrap();

        let outer = rlp_decode_list(&old).unwrap();
        let time = rlp_decode_u64(&outer[0]);
        let block = rlp_decode_u64(&outer[1]);
        let members: Vec<StoredMember> = rlp_decode_list(&outer[2])
            .unwrap()
            .iter()
            .map(|k| StoredMember::from_stored(k).unwrap())
            .collect();
        assert_eq!(members.len(), 15);

        // Multikey re-serialization must match rskj byte-for-byte.
        assert_eq!(serialize_federation_multikey(&members, time, block), new);
        // And the only-BTC form must still round-trip to the pre-wasabi bytes.
        let keys: Vec<[u8; 33]> = members.iter().map(|m| m.btc).collect();
        assert_eq!(serialize_federation_only_btc_keys(&keys, time, block), old);

        // The multikey bytes decode back to the same members.
        let reloaded = rlp_decode_list(&new).unwrap();
        let remembers: Vec<StoredMember> = rlp_decode_list(&reloaded[2])
            .unwrap()
            .iter()
            .map(|k| StoredMember::from_stored(k).unwrap())
            .collect();
        assert_eq!(remembers, members);
    }

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

/// A federation member as stored in bridge state: compressed BTC, RSK and
/// MST public keys (rskj `FederationMember`). Legacy (pre-RSKIP123) members
/// carry only a BTC key, with rsk = mst = btc
/// (`FederationMember.getFederationMemberFromKey`). The derived ordering is
/// rskj's `BTC_RSK_MST_PUBKEYS_COMPARATOR` (lexicographic by btc, rsk, mst).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StoredMember {
    pub btc: [u8; 33],
    pub rsk: [u8; 33],
    pub mst: [u8; 33],
}

impl StoredMember {
    pub fn from_btc(key: [u8; 33]) -> Self {
        Self { btc: key, rsk: key, mst: key }
    }

    /// rskj `BridgeSerializationUtils.serializeFederationMember`:
    /// `RLP[btcKey, rskKey, mstKey]`, all compressed.
    pub fn to_rlp(&self) -> Vec<u8> {
        use super::serialization::{rlp_encode_element, rlp_encode_list};
        rlp_encode_list(&[
            rlp_encode_element(&self.btc),
            rlp_encode_element(&self.rsk),
            rlp_encode_element(&self.mst),
        ])
    }

    /// Decode a member from either stored shape: a bare 33-byte compressed
    /// BTC key (pre-RSKIP123) or `RLP[btc, rsk, mst]` (post-RSKIP123). rskj
    /// picks the format by the presence of the format-version cell; the two
    /// shapes are unambiguous (a compressed key starts with 0x02/0x03, an
    /// RLP list with >= 0xc0), so shape detection is equivalent.
    pub fn from_stored(data: &[u8]) -> Option<Self> {
        if data.len() == 33 {
            return Some(Self::from_btc(data.try_into().ok()?));
        }
        let keys = super::serialization::rlp_decode_list(data)?;
        if keys.len() != 3 {
            return None;
        }
        Some(Self {
            btc: keys[0].as_slice().try_into().ok()?,
            rsk: keys[1].as_slice().try_into().ok()?,
            mst: keys[2].as_slice().try_into().ok()?,
        })
    }
}

/// A federation stored under newFederation/oldFederation:
/// `RLP[ creationTime(millis), creationBlockNumber, RLP[member...] ]`, where
/// each member is a bare BTC key (pre-RSKIP123) or an element-wrapped
/// `RLP[btc, rsk, mst]` (post-RSKIP123).
#[derive(Debug, Clone)]
pub struct StoredFederation {
    pub members: Vec<StoredMember>,
    pub creation_time_millis: u64,
    pub creation_block: u64,
}

impl StoredFederation {
    pub fn btc_keys(&self) -> Vec<[u8; 33]> {
        self.members.iter().map(|m| m.btc).collect()
    }
}

pub fn serialize_federation_only_btc_keys(
    keys: &[[u8; 33]],
    creation_time_millis: u64,
    creation_block: u64,
) -> Vec<u8> {
    use super::serialization::{rlp_encode_element, rlp_encode_list, rlp_encode_u64};
    let mut sorted = keys.to_vec();
    sorted.sort();
    let key_items: Vec<Vec<u8>> = sorted.iter().map(|k| rlp_encode_element(k)).collect();
    rlp_encode_list(&[
        rlp_encode_u64(creation_time_millis),
        rlp_encode_u64(creation_block),
        rlp_encode_list(&key_items),
    ])
}

/// Post-RSKIP123 (wasabi) federation serialization. Each member is
/// `RLP[btcKey, rskKey, mstKey]`, wrapped as an RLP element inside the member
/// list (rskj `BridgeSerializationUtils.serializeFederation` /
/// `serializeFederationMember`). Members are ordered by
/// `BTC_RSK_MST_PUBKEYS_COMPARATOR` (the derived `StoredMember` ordering).
pub fn serialize_federation_multikey(
    members: &[StoredMember],
    creation_time_millis: u64,
    creation_block: u64,
) -> Vec<u8> {
    use super::serialization::{rlp_encode_element, rlp_encode_list, rlp_encode_u64};
    let mut sorted = members.to_vec();
    sorted.sort();
    let member_items: Vec<Vec<u8>> =
        sorted.iter().map(|m| rlp_encode_element(&m.to_rlp())).collect();
    rlp_encode_list(&[
        rlp_encode_u64(creation_time_millis),
        rlp_encode_u64(creation_block),
        rlp_encode_list(&member_items),
    ])
}

pub fn load_stored_federation<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    storage_key: &str,
) -> Option<StoredFederation> {
    use super::serialization::{rlp_decode_list, rlp_decode_u64};
    use super::storage::bridge_load_bytes_named;
    let data = bridge_load_bytes_named(ctx, storage_key);
    if data.is_empty() {
        return None;
    }
    let outer = rlp_decode_list(&data)?;
    if outer.len() != 3 {
        return None;
    }
    // The member list is either only-BTC-keys (each element is a 33-byte
    // compressed key) or, post-RSKIP123, multikey (each element wraps
    // RLP[btcKey, rskKey, mstKey]).
    let members = rlp_decode_list(&outer[2])?
        .iter()
        .filter_map(|m| StoredMember::from_stored(m))
        .collect();
    Some(StoredFederation {
        members,
        creation_time_millis: rlp_decode_u64(&outer[0]),
        creation_block: rlp_decode_u64(&outer[1]),
    })
}

/// rskj `FederationStorageProviderImpl.saveNewFederation`: when a Bridge call
/// has loaded the active (new) federation, `save()` re-serializes it. Once
/// RSKIP123 (wasabi) is active it switches to the multikey member format and
/// persists the format-version cell (`newFederationFormatVersion = 1000`,
/// `STANDARD_MULTISIG_FEDERATION`). The first such save after activation
/// migrates the stored federation in place (mainnet #1,591,009's
/// updateCollections); the value is stable thereafter. No-op before RSKIP123.
pub fn save_new_federation_multikey<CTX: crate::RskContextTr>(
    ctx: &mut CTX,
    hardfork_cfg: &crate::hardfork::RskHardforkConfig,
    block_number: u64,
) {
    use super::serialization::rlp_encode_u64;
    use super::storage::{
        bridge_store_bytes_named, NEW_FEDERATION_FORMAT_VERSION_KEY, NEW_FEDERATION_KEY,
    };
    if !hardfork_cfg.has_rskip123(block_number) {
        return;
    }
    let Some(fed) = load_stored_federation(ctx, NEW_FEDERATION_KEY) else {
        return;
    };
    bridge_store_bytes_named(ctx, NEW_FEDERATION_FORMAT_VERSION_KEY, &rlp_encode_u64(1000));
    let data =
        serialize_federation_multikey(&fed.members, fed.creation_time_millis, fed.creation_block);
    bridge_store_bytes_named(ctx, NEW_FEDERATION_KEY, &data);
}
