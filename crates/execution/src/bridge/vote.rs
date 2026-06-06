//! rskj `ABICallElection` — authorized multi-vote elections stored in Bridge
//! storage, used by the federation-change governance (rskj
//! `FederationSupportImpl.voteFederationChange`).
//!
//! Serialization matches `BridgeSerializationUtils.serializeElection`:
//! an RLP list of `(spec, voters)` pairs ordered by the serialized spec
//! bytes, where `spec = RLP[ function-name, RLP[ rlp(arg), ... ] ]` and
//! `voters` is the lexicographically sorted RLP list of 20-byte addresses.

use alloy_primitives::Address;
use revm::context_interface::ContextTr;

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

/// rskj `ABICallElection`: votes per call spec.
#[derive(Debug, Default)]
pub struct Election {
    pub entries: Vec<(AbiCallSpec, Vec<Address>)>,
}

impl Election {
    pub fn load<CTX: ContextTr>(ctx: &mut CTX, storage_key: &str) -> Self {
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

    pub fn store<CTX: ContextTr>(&self, ctx: &mut CTX, storage_key: &str) {
        let mut serialized: Vec<(Vec<u8>, &Vec<Address>)> = self
            .entries
            .iter()
            .map(|(spec, voters)| (spec.serialize(), voters))
            .collect();
        serialized.sort_by(|a, b| a.0.cmp(&b.0));

        let mut items = Vec::with_capacity(serialized.len() * 2);
        for (spec, voters) in serialized {
            items.push(spec);
            let mut sorted: Vec<&Address> = voters.iter().collect();
            sorted.sort();
            let voter_items: Vec<Vec<u8>> = sorted
                .iter()
                .map(|v| rlp_encode_element(v.as_slice()))
                .collect();
            items.push(rlp_encode_list(&voter_items));
        }
        bridge_store_bytes_named(ctx, storage_key, &rlp_encode_list(&items));
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
