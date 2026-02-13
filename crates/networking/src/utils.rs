use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use alloy_primitives::Bytes;

/// Converts a byte slice to an IpAddr.
pub fn bytes_to_ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => {
            // Try parsing as UTF-8 string (Rootstock format)
            if let Ok(s) = std::str::from_utf8(bytes) {
                s.parse().ok()
            } else {
                None
            }
        }
    }
}

/// Converts an IpAddr to Bytes.
pub fn ip_to_bytes(ip: IpAddr) -> Bytes {
    Bytes::from(ip.to_string().into_bytes())
}
