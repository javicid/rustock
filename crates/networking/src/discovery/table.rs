use alloy_primitives::B512;
use crate::discovery::message::DiscoveryNode;
use std::time::{Duration, Instant};

pub const BUCKET_SIZE: usize = 16;
pub const NUM_BUCKETS: usize = 256;

/// A node that hasn't been refreshed by our periodic discovery pings for this
/// long is treated as dead and may be evicted to make room for a fresh node in
/// a full bucket. rskj instead pings the least-recently-seen entry on the spot
/// (`NodeChallengeManager`) and evicts it only if it fails to pong; rustock's
/// discovery loop already pings every table node every 15s, so a stale
/// `last_seen` is the equivalent "lost challenge" signal. A bucket of
/// still-responsive nodes is left intact, matching rskj's bias toward keeping
/// known-good peers over unverified newcomers. See docs/java-compatibility.md.
const EVICTION_STALENESS: Duration = Duration::from_secs(90);

/// A table slot: the discovered node plus when we last heard from it (mirrors
/// rskj `BucketEntry`'s `lastSeenTime`). `last_seen` is liveness-only state and
/// is never serialized — it is not part of the wire/disk `DiscoveryNode`.
struct BucketEntry {
    node: DiscoveryNode,
    last_seen: Instant,
}

pub struct NodeTable {
    local_id: B512,
    buckets: Vec<Vec<BucketEntry>>,
}

impl NodeTable {
    pub fn new(local_id: B512) -> Self {
        Self {
            local_id,
            // `BucketEntry` is intentionally not `Clone`, so build the buckets
            // with an iterator instead of the `vec![_; N]` (clone) macro.
            buckets: (0..NUM_BUCKETS).map(|_| Vec::new()).collect(),
        }
    }

    pub fn add_node(&mut self, node: DiscoveryNode) -> bool {
        if node.id == self.local_id {
            return false;
        }

        let distance = self.xor_distance(&node.id);
        let bucket_idx = self.distance_to_bucket(distance);
        let now = Instant::now();

        let bucket = &mut self.buckets[bucket_idx];

        if let Some(pos) = bucket.iter().position(|e| e.node.id == node.id) {
            // Known node: refresh recency (move to end) and last-seen time.
            let mut entry = bucket.remove(pos);
            entry.last_seen = now;
            bucket.push(entry);
            true
        } else if bucket.len() < BUCKET_SIZE {
            bucket.push(BucketEntry { node, last_seen: now });
            true
        } else {
            // Bucket full. Entries are kept least-recently-seen first, so the
            // front is the eviction candidate (rskj `Bucket.getOldestEntry`).
            // Evict it only if it has gone stale — i.e. our periodic pings
            // stopped refreshing it, the equivalent of rskj's challenged node
            // failing to pong. Otherwise reject the newcomer.
            if bucket.first().is_some_and(|e| now.duration_since(e.last_seen) >= EVICTION_STALENESS) {
                bucket.remove(0);
                bucket.push(BucketEntry { node, last_seen: now });
                true
            } else {
                false
            }
        }
    }

    pub fn closest_nodes(&self, target: &B512, count: usize) -> Vec<DiscoveryNode> {
        let mut nodes: Vec<_> = self.buckets.iter().flat_map(|b| b.iter().map(|e| e.node.clone())).collect();
        nodes.sort_by_cached_key(|n| self.xor_distance_between(&n.id, target));
        nodes.truncate(count);
        nodes
    }

    pub fn all_nodes(&self) -> Vec<DiscoveryNode> {
        self.buckets.iter().flat_map(|b| b.iter().map(|e| e.node.clone())).collect()
    }

    /// Total number of nodes across all buckets (without cloning).
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serializes the table to RLP bytes.
    pub fn encode(&self) -> Vec<u8> {
        use alloy_rlp::Encodable;
        let nodes = self.all_nodes();
        let mut buf = Vec::new();
        nodes.encode(&mut buf);
        buf
    }

    /// Loads nodes from RLP-encoded bytes.
    pub fn decode_and_add(&mut self, data: &[u8]) -> anyhow::Result<()> {
        use alloy_rlp::Decodable;
        let mut ptr = data;
        let nodes = Vec::<DiscoveryNode>::decode(&mut ptr)
            .map_err(|e| anyhow::anyhow!("Failed to decode nodes: {:?}", e))?;

        for node in nodes {
            self.add_node(node);
        }
        Ok(())
    }

    /// Parses an enode URL and adds it to the table.
    /// Format: enode://<hex_id>@<ip>:<tcp_port>?discport=<udp_port>
    pub fn add_enode(&mut self, enode: &str) -> anyhow::Result<bool> {
        use alloy_primitives::hex::FromHex;

        if !enode.starts_with("enode://") {
            return Err(anyhow::anyhow!("Invalid enode prefix"));
        }
        
        let rest = &enode[8..];
        let parts: Vec<&str> = rest.split('@').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Missing @ in enode"));
        }
        
        let id_hex = parts[0];
        let addr_parts: Vec<&str> = parts[1].split(':').collect();
        if addr_parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid address format in enode"));
        }
        
        let host = addr_parts[0];
        let port_part = addr_parts[1];
        
        // Split port from query params
        let mut tcp_port_str = port_part;
        let mut udp_port = None;

        if let Some(pos) = port_part.find('?') {
            tcp_port_str = &port_part[..pos];
            let query = &port_part[pos+1..];
            for param in query.split('&') {
                if let Some(val) = param.strip_prefix("discport=") {
                    udp_port = Some(val.parse::<u16>()?);
                }
            }
        }

        let tcp_port: u16 = tcp_port_str.parse()?;
        let udp_port = udp_port.unwrap_or(tcp_port);

        // Resolve host to IP
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", host, tcp_port);
        let ip = addr_str.to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve hostname: {}", host))?
            .ip();
        
        let id = B512::from_hex(id_hex)?;
        
        let node = DiscoveryNode {
            ip: alloy_primitives::Bytes::from(match ip {
                std::net::IpAddr::V4(a) => a.octets().to_vec(),
                std::net::IpAddr::V6(a) => a.octets().to_vec(),
            }),
            udp_port,
            tcp_port,
            id,
        };
        
        Ok(self.add_node(node))
    }

    fn xor_distance(&self, other: &B512) -> [u8; 64] {
        self.xor_distance_between(&self.local_id, other)
    }

    fn xor_distance_between(&self, a: &B512, b: &B512) -> [u8; 64] {
        let mut res = [0u8; 64];
        let a_bytes = a.as_slice();
        let b_bytes = b.as_slice();
        for i in 0..64 {
            res[i] = a_bytes[i] ^ b_bytes[i];
        }
        res
    }

    fn distance_to_bucket(&self, distance: [u8; 64]) -> usize {
        for (i, byte) in distance.iter().enumerate() {
            if *byte != 0 {
                return (i * 8) + (7 - byte.leading_zeros() as usize);
            }
        }
        0
    }

    /// Test helper: age every entry past the eviction threshold so the next
    /// `add_node` into a full bucket treats the oldest entry as dead.
    #[cfg(test)]
    fn force_all_stale(&mut self) {
        let old = Instant::now()
            .checked_sub(EVICTION_STALENESS + Duration::from_secs(1))
            .expect("test platform Instant should be old enough");
        for bucket in &mut self.buckets {
            for entry in bucket {
                entry.last_seen = old;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    /// All these IDs share the top bit set (byte 0 = 0x80) and differ only in
    /// the last byte, so they collide in the same bucket — letting us fill one.
    fn node_in_shared_bucket(tag: u8) -> DiscoveryNode {
        let mut id = [0u8; 64];
        id[0] = 0x80;
        id[63] = tag;
        DiscoveryNode {
            ip: Bytes::from(vec![10, 0, 0, 1]),
            udp_port: 5050,
            tcp_port: 5050,
            id: B512::from_slice(&id),
        }
    }

    #[test]
    fn full_bucket_keeps_fresh_nodes_and_rejects_newcomer() {
        let mut table = NodeTable::new(B512::ZERO);
        for i in 0..BUCKET_SIZE as u8 {
            assert!(table.add_node(node_in_shared_bucket(i)));
        }
        assert_eq!(table.len(), BUCKET_SIZE);

        // Bucket is full of freshly-seen nodes: a newcomer is rejected, and no
        // existing node is dropped (rskj keeps responsive peers).
        let newcomer = node_in_shared_bucket(0xFF);
        assert!(!table.add_node(newcomer.clone()));
        assert_eq!(table.len(), BUCKET_SIZE);
        assert!(!table.all_nodes().iter().any(|n| n.id == newcomer.id));
    }

    #[test]
    fn full_bucket_evicts_stale_oldest_for_newcomer() {
        let mut table = NodeTable::new(B512::ZERO);
        for i in 0..BUCKET_SIZE as u8 {
            assert!(table.add_node(node_in_shared_bucket(i)));
        }
        let oldest = node_in_shared_bucket(0);

        // Once every entry is stale (our pings stopped refreshing them), the
        // least-recently-seen node is evicted to admit the newcomer.
        table.force_all_stale();
        let newcomer = node_in_shared_bucket(0xFF);
        assert!(table.add_node(newcomer.clone()));
        assert_eq!(table.len(), BUCKET_SIZE);
        assert!(table.all_nodes().iter().any(|n| n.id == newcomer.id));
        assert!(!table.all_nodes().iter().any(|n| n.id == oldest.id));
    }

    #[test]
    fn re_adding_refreshes_recency() {
        let mut table = NodeTable::new(B512::ZERO);
        for i in 0..BUCKET_SIZE as u8 {
            assert!(table.add_node(node_in_shared_bucket(i)));
        }
        // Mark all stale, then touch node 0 so it becomes most-recently-seen.
        table.force_all_stale();
        assert!(table.add_node(node_in_shared_bucket(0)));

        // The newcomer now evicts the *new* oldest (node 1), not the refreshed 0.
        let newcomer = node_in_shared_bucket(0xFF);
        assert!(table.add_node(newcomer));
        assert!(table.all_nodes().iter().any(|n| n.id == node_in_shared_bucket(0).id));
        assert!(!table.all_nodes().iter().any(|n| n.id == node_in_shared_bucket(1).id));
    }
}
