use alloy_primitives::B512;
use crate::discovery::message::DiscoveryNode;

pub const BUCKET_SIZE: usize = 16;
pub const NUM_BUCKETS: usize = 256;

pub struct NodeTable {
    local_id: B512,
    buckets: Vec<Vec<DiscoveryNode>>,
}

impl NodeTable {
    pub fn new(local_id: B512) -> Self {
        Self {
            local_id,
            buckets: vec![Vec::new(); NUM_BUCKETS],
        }
    }

    pub fn add_node(&mut self, node: DiscoveryNode) -> bool {
        if node.id == self.local_id {
            return false;
        }

        let distance = self.xor_distance(&node.id);
        let bucket_idx = self.distance_to_bucket(distance);
        
        let bucket = &mut self.buckets[bucket_idx];
        
        if let Some(pos) = bucket.iter().position(|n| n.id == node.id) {
            // Move to end (most recently seen)
            let n = bucket.remove(pos);
            bucket.push(n);
            true
        } else if bucket.len() < BUCKET_SIZE {
            bucket.push(node);
            true
        } else {
            // Bucket full, should ideally ping the least recently seen
            false
        }
    }

    pub fn get_closest_nodes(&self, target: &B512, count: usize) -> Vec<DiscoveryNode> {
        let mut nodes = Vec::new();
        for bucket in &self.buckets {
            nodes.extend(bucket.iter().cloned());
        }

        // Sort by distance to target
        nodes.sort_by_cached_key(|n| self.xor_distance_between(&n.id, target));
        nodes.truncate(count);
        nodes
    }

    pub fn get_all_nodes(&self) -> Vec<DiscoveryNode> {
        let mut nodes = Vec::new();
        for bucket in &self.buckets {
            nodes.extend(bucket.iter().cloned());
        }
        nodes
    }

    /// Serializes the table to RLP bytes.
    pub fn encode(&self) -> Vec<u8> {
        use alloy_rlp::Encodable;
        let nodes = self.get_all_nodes();
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
}
