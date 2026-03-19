/// Bitcoin-style CompactSize (VarInt) encoding, matching rskj's bitcoinj VarInt.
///
/// | First byte | Total bytes | Range                   |
/// |------------|-------------|-------------------------|
/// | 0–252      | 1           | 0–252                   |
/// | 0xFD       | 3           | 253–65,535  (LE uint16) |
/// | 0xFE       | 5           | 65,536–2^32 (LE uint32) |
/// | 0xFF       | 9           | 2^32+       (LE uint64) |
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value < 253 {
        vec![value as u8]
    } else if value <= 0xFFFF {
        let mut buf = vec![0xFD, 0, 0];
        buf[1..3].copy_from_slice(&(value as u16).to_le_bytes());
        buf
    } else if value <= 0xFFFF_FFFF {
        let mut buf = vec![0xFE, 0, 0, 0, 0];
        buf[1..5].copy_from_slice(&(value as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xFF, 0, 0, 0, 0, 0, 0, 0, 0];
        buf[1..9].copy_from_slice(&value.to_le_bytes());
        buf
    }
}

/// Returns `(value, bytes_consumed)`.
pub fn decode_varint(data: &[u8]) -> (u64, usize) {
    let first = data[0];
    if first < 253 {
        (first as u64, 1)
    } else if first == 253 {
        let v = u16::from_le_bytes([data[1], data[2]]);
        (v as u64, 3)
    } else if first == 254 {
        let v = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        (v as u64, 5)
    } else {
        let v = u64::from_le_bytes([
            data[1], data[2], data[3], data[4],
            data[5], data[6], data[7], data[8],
        ]);
        (v, 9)
    }
}

pub fn varint_size(value: u64) -> usize {
    if value < 253 { 1 }
    else if value <= 0xFFFF { 3 }
    else if value <= 0xFFFF_FFFF { 5 }
    else { 9 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_values() {
        for v in 0..=252u64 {
            let enc = encode_varint(v);
            assert_eq!(enc.len(), 1);
            let (dec, sz) = decode_varint(&enc);
            assert_eq!(dec, v);
            assert_eq!(sz, 1);
        }
    }

    #[test]
    fn test_two_byte_values() {
        for &v in &[253u64, 1000, 65535] {
            let enc = encode_varint(v);
            assert_eq!(enc.len(), 3);
            assert_eq!(enc[0], 0xFD);
            let (dec, sz) = decode_varint(&enc);
            assert_eq!(dec, v);
            assert_eq!(sz, 3);
        }
    }

    #[test]
    fn test_four_byte_values() {
        for &v in &[65536u64, 1_000_000, 0xFFFF_FFFF] {
            let enc = encode_varint(v);
            assert_eq!(enc.len(), 5);
            assert_eq!(enc[0], 0xFE);
            let (dec, sz) = decode_varint(&enc);
            assert_eq!(dec, v);
            assert_eq!(sz, 5);
        }
    }

    #[test]
    fn test_eight_byte_values() {
        let v: u64 = 0x1_0000_0000;
        let enc = encode_varint(v);
        assert_eq!(enc.len(), 9);
        assert_eq!(enc[0], 0xFF);
        let (dec, sz) = decode_varint(&enc);
        assert_eq!(dec, v);
        assert_eq!(sz, 9);
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(varint_size(0), 1);
        assert_eq!(varint_size(252), 1);
        assert_eq!(varint_size(253), 3);
        assert_eq!(varint_size(65535), 3);
        assert_eq!(varint_size(65536), 5);
        assert_eq!(varint_size(0xFFFF_FFFF), 5);
        assert_eq!(varint_size(0x1_0000_0000), 9);
    }
}
