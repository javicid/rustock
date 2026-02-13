//! Lenient RLP integer decoders for compatibility with Java's BigInteger encoding.
//!
//! Java's `BigInteger.toByteArray()` includes a leading zero byte for positive
//! numbers whose most significant bit is set (sign extension). alloy_rlp rejects
//! these as non-canonical. These helpers strip leading zeros before parsing.

use alloy_primitives::U256;
use alloy_rlp::Header;

/// Decode a u8 from RLP, tolerating leading zeros.
pub fn decode_u8_lenient(buf: &mut &[u8]) -> alloy_rlp::Result<u8> {
    let h = Header::decode(buf)?;
    if h.list {
        return Err(alloy_rlp::Error::UnexpectedList);
    }
    let bytes = &buf[..h.payload_length];
    *buf = &buf[h.payload_length..];

    if bytes.is_empty() {
        return Ok(0);
    }
    // Strip leading zeros
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[start..];
    if stripped.is_empty() {
        return Ok(0);
    }
    if stripped.len() > 1 {
        return Err(alloy_rlp::Error::Overflow);
    }
    Ok(stripped[0])
}

/// Decode a u32 from RLP, tolerating leading zeros.
pub fn decode_u32_lenient(buf: &mut &[u8]) -> alloy_rlp::Result<u32> {
    let h = Header::decode(buf)?;
    if h.list {
        return Err(alloy_rlp::Error::UnexpectedList);
    }
    let bytes = &buf[..h.payload_length];
    *buf = &buf[h.payload_length..];

    if bytes.is_empty() {
        return Ok(0);
    }
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[start..];
    if stripped.is_empty() {
        return Ok(0);
    }
    if stripped.len() > 4 {
        return Err(alloy_rlp::Error::Overflow);
    }
    let mut value: u32 = 0;
    for &b in stripped {
        value = value << 8 | b as u32;
    }
    Ok(value)
}

/// Decode a u64 from RLP, tolerating leading zeros.
pub fn decode_u64_lenient(buf: &mut &[u8]) -> alloy_rlp::Result<u64> {
    let h = Header::decode(buf)?;
    if h.list {
        return Err(alloy_rlp::Error::UnexpectedList);
    }
    let bytes = &buf[..h.payload_length];
    *buf = &buf[h.payload_length..];

    if bytes.is_empty() {
        return Ok(0);
    }
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[start..];
    if stripped.is_empty() {
        return Ok(0);
    }
    if stripped.len() > 8 {
        return Err(alloy_rlp::Error::Overflow);
    }
    let mut value: u64 = 0;
    for &b in stripped {
        value = value << 8 | b as u64;
    }
    Ok(value)
}

/// Decode a U256 from RLP, tolerating leading zeros.
pub fn decode_u256_lenient(buf: &mut &[u8]) -> alloy_rlp::Result<U256> {
    let h = Header::decode(buf)?;
    if h.list {
        return Err(alloy_rlp::Error::UnexpectedList);
    }
    let bytes = &buf[..h.payload_length];
    *buf = &buf[h.payload_length..];

    if bytes.is_empty() {
        return Ok(U256::ZERO);
    }
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[start..];
    if stripped.is_empty() {
        return Ok(U256::ZERO);
    }
    if stripped.len() > 32 {
        return Err(alloy_rlp::Error::Overflow);
    }
    Ok(U256::from_be_slice(stripped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_with_leading_zero() {
        // Java's BigInteger.toByteArray() for 0x800000 → [0x00, 0x80, 0x00, 0x00]
        // RLP: 0x84 0x00 0x80 0x00 0x00  (string of length 4)
        let encoded = [0x84, 0x00, 0x80, 0x00, 0x00];
        let mut buf = encoded.as_slice();
        let val = decode_u64_lenient(&mut buf).unwrap();
        assert_eq!(val, 0x800000);
    }

    #[test]
    fn test_u256_with_leading_zero() {
        // A U256 value with a leading zero byte
        let encoded = [0x82, 0x00, 0xff];
        let mut buf = encoded.as_slice();
        let val = decode_u256_lenient(&mut buf).unwrap();
        assert_eq!(val, U256::from(0xff));
    }

    #[test]
    fn test_u64_canonical() {
        // Normal u64 without leading zeros
        let encoded = [0x83, 0x80, 0x00, 0x00];
        let mut buf = encoded.as_slice();
        let val = decode_u64_lenient(&mut buf).unwrap();
        assert_eq!(val, 0x800000);
    }
}
