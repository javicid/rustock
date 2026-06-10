//! rskj `ABICallElection` — authorized multi-vote elections stored in Bridge
//! storage, used by the federation-change governance (rskj
//! `FederationSupportImpl.voteFederationChange`).
//!
//! Serialization matches `BridgeSerializationUtils.serializeElection`:
//! an RLP list of `(spec, voters)` pairs ordered by
//! `ABICallSpec.byBytesComparator` — SIGNED-byte lexicographic order of
//! `getEncoded()` (the raw concatenation of function name and argument
//! bytes, NOT the RLP serialization) — where
//! `spec = RLP[ function-name, RLP[ rlp(arg), ... ] ]` and `voters` is the
//! unsigned-lexicographically sorted RLP list of 20-byte addresses.

use alloy_primitives::Address;

use super::serialization::{rlp_decode_list, rlp_encode_element, rlp_encode_list};
use super::storage::{bridge_load_bytes_named, bridge_store_bytes_named};

/// rskj `ABICallSpec`: a voted function call (name + raw argument bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiCallSpec {
    pub function: Vec<u8>,
    pub args: Vec<Vec<u8>>,
}

impl AbiCallSpec {
    pub fn new(function: &str, args: Vec<Vec<u8>>) -> Self {
        Self {
            function: function.as_bytes().to_vec(),
            args,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let arg_items: Vec<Vec<u8>> = self.args.iter().map(|a| rlp_encode_element(a)).collect();
        rlp_encode_list(&[
            rlp_encode_element(&self.function),
            rlp_encode_list(&arg_items),
        ])
    }

    /// rskj `ABICallSpec.getEncoded`: function-name UTF-8 bytes followed by
    /// the raw argument bytes, concatenated (the byBytesComparator key).
    fn encoded(&self) -> Vec<u8> {
        let mut out = self.function.clone();
        for arg in &self.args {
            out.extend_from_slice(arg);
        }
        out
    }

    fn deserialize(data: &[u8]) -> Option<Self> {
        let items = rlp_decode_list(data)?;
        if items.len() != 2 {
            return None;
        }
        let args = rlp_decode_list(&items[1])?;
        Some(Self {
            function: items[0].clone(),
            args,
        })
    }
}

/// Java/Guava `SignedBytes.lexicographicalComparator`: lexicographic over
/// bytes compared as SIGNED i8 (0x80..0xff sort before 0x00..0x7f).
pub fn signed_bytes_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.iter().map(|&v| v as i8).cmp(b.iter().map(|&v| v as i8))
}

/// rskj `ABICallElection`: votes per call spec.
#[derive(Debug, Default)]
pub struct Election {
    pub entries: Vec<(AbiCallSpec, Vec<Address>)>,
}

impl Election {
    pub fn load<CTX: crate::RskContextTr>(ctx: &mut CTX, storage_key: &str) -> Self {
        let data = bridge_load_bytes_named(ctx, storage_key);
        if data.is_empty() {
            return Self::default();
        }
        let Some(items) = rlp_decode_list(&data) else {
            return Self::default();
        };
        let mut entries = Vec::new();
        let mut i = 0;
        while i + 1 < items.len() {
            if let Some(spec) = AbiCallSpec::deserialize(&items[i]) {
                let voters = rlp_decode_list(&items[i + 1])
                    .map(|vs| {
                        vs.into_iter()
                            .filter(|v| v.len() == 20)
                            .map(|v| Address::from_slice(&v))
                            .collect()
                    })
                    .unwrap_or_default();
                entries.push((spec, voters));
            }
            i += 2;
        }
        Self { entries }
    }

    pub fn store<CTX: crate::RskContextTr>(&self, ctx: &mut CTX, storage_key: &str) {
        bridge_store_bytes_named(ctx, storage_key, &self.to_bytes());
    }

    /// rskj `BridgeSerializationUtils.serializeElection`.
    pub fn to_bytes(&self) -> Vec<u8> {
        // rskj sorts specs by byBytesComparator: SIGNED-byte lexicographic
        // order of getEncoded() (Guava SignedBytes.lexicographicalComparator).
        let mut serialized: Vec<(Vec<u8>, Vec<u8>, &Vec<Address>)> = self
            .entries
            .iter()
            .map(|(spec, voters)| (spec.encoded(), spec.serialize(), voters))
            .collect();
        serialized.sort_by(|a, b| signed_bytes_cmp(&a.0, &b.0));

        let mut items = Vec::with_capacity(serialized.len() * 2);
        for (_, spec, voters) in serialized {
            items.push(spec);
            let mut sorted: Vec<&Address> = voters.iter().collect();
            sorted.sort();
            let voter_items: Vec<Vec<u8>> = sorted
                .iter()
                .map(|v| rlp_encode_element(v.as_slice()))
                .collect();
            items.push(rlp_encode_list(&voter_items));
        }
        rlp_encode_list(&items)
    }

    /// rskj `ABICallElection.vote`: false when the voter already voted for
    /// this same spec.
    pub fn vote(&mut self, spec: &AbiCallSpec, voter: Address) -> bool {
        let entry = self.entries.iter_mut().find(|(s, _)| s == spec);
        let voters = match entry {
            Some((_, voters)) => voters,
            None => {
                self.entries.push((spec.clone(), Vec::new()));
                &mut self.entries.last_mut().expect("just pushed").1
            }
        };
        if voters.contains(&voter) {
            return false;
        }
        voters.push(voter);
        true
    }

    /// Index of the first spec with enough votes.
    pub fn winner(&self, required: usize) -> Option<usize> {
        self.entries
            .iter()
            .position(|(_, voters)| voters.len() >= required)
    }

    /// rskj `clearWinners`: drop the winning spec's entry.
    pub fn remove(&mut self, index: usize) {
        self.entries.remove(index);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact ground truth: the mainnet `federationElection` cell at
    /// #2,426,416 — three add-multi votes by one authorizer. rskj orders
    /// specs by SIGNED-byte comparison of getEncoded() (function || args),
    /// so the key starting 0x03b6 (b6 = -74 as i8) sorts FIRST, before
    /// 0x0325 and 0x0372 — the opposite of unsigned order.
    #[test]
    fn rskj_election_signed_byte_spec_order_groundtruth_2426416() {
        use alloy_primitives::hex;
        let k1 = hex::decode("03b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573").unwrap();
        let k2 = hex::decode("03250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93").unwrap();
        let k3 = hex::decode("0372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6").unwrap();
        let voter = Address::from_slice(&hex::decode("d41f4d4c7fc8d5fa9468d0c466c9a726397f91b6").unwrap());
        // Insert in unsigned-ascending order (k2, k3, k1) — the serialized
        // order must come out signed: k1, k2, k3.
        let election = Election {
            entries: [&k2, &k3, &k1]
                .into_iter()
                .map(|k| {
                    (AbiCallSpec::new("add-multi", vec![k.clone(), k.clone(), k.clone()]), vec![voter])
                })
                .collect(),
        };
        let expected = hex::decode(
            "f9019ef872896164642d6d756c7469f866a103b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573a103b65cd7c22e70c0\
             823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573a103b65cd7c22e70c0823882c6e71ac2c279ed31cbe29cb4a1c00572ce539c0c4573d5\
             94d41f4d4c7fc8d5fa9468d0c466c9a726397f91b6f872896164642d6d756c7469f866a103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d214\
             0c1a365b2723a2bf93a103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a365b2723a2bf93a103250c11be0561b1d7ae168b1f59e39c\
             bc1fd1ba3cf4d2140c1a365b2723a2bf93d594d41f4d4c7fc8d5fa9468d0c466c9a726397f91b6f872896164642d6d756c7469f866a10372cd46831f\
             3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6a10372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638\
             c6a10372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6ee0638c6d594d41f4d4c7fc8d5fa9468d0c466c9a726397f91b6",
        )
        .unwrap();
        assert_eq!(election.to_bytes(), expected);
    }

    #[test]
    fn signed_bytes_cmp_negative_first() {
        use std::cmp::Ordering;
        assert_eq!(signed_bytes_cmp(&[0xb6], &[0x25]), Ordering::Less);
        assert_eq!(signed_bytes_cmp(&[0x25], &[0x72]), Ordering::Less);
        assert_eq!(signed_bytes_cmp(&[0x01], &[0x01, 0x02]), Ordering::Less);
        assert_eq!(signed_bytes_cmp(&[0x7f], &[0x80]), Ordering::Greater);
    }

    #[test]
    fn vote_dedups_per_spec_and_finds_winner() {
        let mut election = Election::default();
        let spec = AbiCallSpec::new("create", vec![]);
        let a = Address::repeat_byte(1);
        let b = Address::repeat_byte(2);

        assert!(election.vote(&spec, a));
        assert!(!election.vote(&spec, a), "duplicate vote rejected");
        assert_eq!(election.winner(2), None);
        assert!(election.vote(&spec, b));
        assert_eq!(election.winner(2), Some(0));
    }

    #[test]
    fn spec_roundtrip() {
        let spec = AbiCallSpec::new("commit", vec![vec![0xAA; 32]]);
        let de = AbiCallSpec::deserialize(&spec.serialize()).unwrap();
        assert_eq!(de, spec);
    }
}
