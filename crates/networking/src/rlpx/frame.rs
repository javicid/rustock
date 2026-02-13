use anyhow::{Result};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use sha3::{Keccak256, Digest};
use bytes::{BytesMut, Buf};
use alloy_rlp::{Encodable, Decodable};
use alloy_primitives::{B256};
use crate::rlpx::ecies::RLPxSecrets;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Parsed header-data from an RLPx frame header.
#[derive(Debug, Clone)]
enum FrameType {
    /// Normal single-frame message: header-data = rlp([0])
    Normal,
    /// First frame of a chunked message: header-data = rlp([0, contextId, totalFrameSize])
    ChunkedFirst { _context_id: usize, total_size: usize },
    /// Continuation frame: header-data = rlp([0, contextId])
    ChunkedContinuation { _context_id: usize },
}

pub struct FrameCodec {
    enc: Aes256Ctr,
    dec: Aes256Ctr,
    mac_secret: B256,
    egress_mac: Keccak256,
    ingress_mac: Keccak256,
    is_head_read: bool,
    total_body_size: usize,
    current_frame_type: FrameType,
    // Multi-frame (chunked) message assembly
    assembling: bool,
    assembly_buf: Vec<u8>,
    assembly_expected: usize,
    assembly_protocol_id: u8,
}

impl FrameCodec {
    pub fn new(secrets: RLPxSecrets) -> Self {
        let iv = [0u8; 16];
        let enc = Aes256Ctr::new(&secrets.aes.0.into(), &iv.into());
        let dec = Aes256Ctr::new(&secrets.aes.0.into(), &iv.into());
        
        Self {
            enc,
            dec,
            mac_secret: secrets.mac,
            egress_mac: secrets.egress_mac,
            ingress_mac: secrets.ingress_mac,
            is_head_read: false,
            total_body_size: 0,
            current_frame_type: FrameType::Normal,
            assembling: false,
            assembly_buf: Vec::new(),
            assembly_expected: 0,
            assembly_protocol_id: 0,
        }
    }

    pub fn encode_frame(&mut self, protocol_id: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut header_data = Vec::new();
        alloy_rlp::encode_list(&[0u8], &mut header_data);
        
        let mut head_buffer = [0u8; 32];
        let mut proto_rlp = Vec::new();
        protocol_id.encode(&mut proto_rlp);
        let actual_total_size = payload.len() + proto_rlp.len();
        
        head_buffer[0] = (actual_total_size >> 16) as u8;
        head_buffer[1] = (actual_total_size >> 8) as u8;
        head_buffer[2] = actual_total_size as u8;
        
        head_buffer[3..3+header_data.len()].copy_from_slice(&header_data);

        self.enc.apply_keystream(&mut head_buffer[0..16]);

        let mac = Self::update_mac_static(&self.mac_secret, &mut self.egress_mac, &head_buffer[0..16])?;
        head_buffer[16..32].copy_from_slice(&mac[0..16]);

        let mut out = Vec::with_capacity(32 + actual_total_size + 16 + 16);
        out.extend_from_slice(&head_buffer);

        let mut body = Vec::new();
        body.extend_from_slice(&proto_rlp);
        body.extend_from_slice(payload);
        
        let padding = 16 - (body.len() % 16);
        let actual_padding = if padding == 16 { 0 } else { padding };
        if actual_padding > 0 {
            body.resize(body.len() + actual_padding, 0u8);
        }

        self.enc.apply_keystream(&mut body);
        
        self.egress_mac.update(&body);
        let fmac_seed = Self::do_sum_static(&self.egress_mac);
        let fmac = Self::update_mac_static(&self.mac_secret, &mut self.egress_mac, &fmac_seed[0..16])?;
        
        out.extend_from_slice(&body);
        out.extend_from_slice(&fmac[0..16]);

        Ok(out)
    }

    pub fn decode_frame(&mut self, src: &mut BytesMut) -> Result<Option<(u8, Vec<u8>)>> {
        if !self.is_head_read {
            if src.len() < 32 {
                return Ok(None);
            }

            let mut head_buffer = [0u8; 32];
            head_buffer.copy_from_slice(&src[0..32]);

            let expected_mac = Self::update_mac_static(&self.mac_secret, &mut self.ingress_mac, &head_buffer[0..16])?;
            if head_buffer[16..32] != expected_mac[0..16] {
                return Err(anyhow::anyhow!("RLPx Header MAC mismatch"));
            }

            self.dec.apply_keystream(&mut head_buffer[0..16]);
            self.total_body_size = ((head_buffer[0] as usize) << 16) | ((head_buffer[1] as usize) << 8) | (head_buffer[2] as usize);
            self.current_frame_type = Self::parse_header_data(&head_buffer[3..16]);
            self.is_head_read = true;
            src.advance(32);
        }

        let padding = 16 - (self.total_body_size % 16);
        let actual_padding = if padding == 16 { 0 } else { padding };
        let body_and_mac_size = self.total_body_size + actual_padding + 16;
        
        if src.len() < body_and_mac_size {
            return Ok(None);
        }

        let mut body = src.split_to(self.total_body_size + actual_padding).to_vec();
        let provided_fmac = src.split_to(16).to_vec();

        self.ingress_mac.update(&body);
        let fmac_seed = Self::do_sum_static(&self.ingress_mac);
        let fmac = Self::update_mac_static(&self.mac_secret, &mut self.ingress_mac, &fmac_seed[0..16])?;
        
        if provided_fmac != fmac[0..16] {
            return Err(anyhow::anyhow!("RLPx Frame MAC mismatch"));
        }

        self.dec.apply_keystream(&mut body);
        self.is_head_read = false;

        let body_data = &body[..self.total_body_size];

        // ---- Multi-frame (chunked) message assembly ----
        match &self.current_frame_type {
            FrameType::ChunkedFirst { total_size, .. } => {
                // First frame of a chunked message.
                // Java's totalFrameSize = msg.getEncoded().length (RLP data, no code byte).
                // But the first frame body = [code_byte] + [RLP chunk], so extract code byte
                // BEFORE buffering, so assembly_buf only contains RLP data.
                let total_size = *total_size;
                let mut ptr = body_data;
                let protocol_id = u8::decode(&mut ptr)?;
                let rlp_chunk = ptr; // body without code byte

                self.assembling = true;
                self.assembly_expected = total_size;
                self.assembly_protocol_id = protocol_id;
                self.assembly_buf.clear();
                self.assembly_buf.extend_from_slice(rlp_chunk);
                if self.assembly_buf.len() >= self.assembly_expected {
                    // Rare: complete in one frame
                    self.assembling = false;
                    let payload = self.assembly_buf[..self.assembly_expected].to_vec();
                    self.assembly_buf.clear();
                    return Ok(Some((protocol_id, payload)));
                }
                return Ok(None);
            }
            FrameType::ChunkedContinuation { .. } => {
                if self.assembling {
                    // Continuation frame: Java writeFrame prepends RLP-encoded ptype to
                    // EVERY frame body, so strip the ptype before buffering, just like
                    // we do for ChunkedFirst.
                    let mut ptr = body_data;
                    let _ptype = u8::decode(&mut ptr)?;
                    let rlp_chunk = ptr;
                    self.assembly_buf.extend_from_slice(rlp_chunk);
                    if self.assembly_buf.len() >= self.assembly_expected {
                        self.assembling = false;
                        let protocol_id = self.assembly_protocol_id;
                        let payload = self.assembly_buf[..self.assembly_expected].to_vec();
                        self.assembly_buf.clear();
                        return Ok(Some((protocol_id, payload)));
                    }
                    return Ok(None);
                } else {
                    // Continuation frame but not assembling — stale/orphaned chunk, skip it
                    return Ok(None);
                }
            }
            FrameType::Normal => {
                // Normal single-frame message
                let mut body_ptr = body_data;
                let protocol_id = u8::decode(&mut body_ptr)?;
                let payload = body_ptr.to_vec();
                Ok(Some((protocol_id, payload)))
            }
        }
    }

    /// Parse the header-data from the decrypted frame header (bytes 3..16).
    /// Java rskj format:
    ///   Non-chunked:  rlp([0])                          — 1 element
    ///   Chunked-0:    rlp([0, contextId, totalFrameSize]) — 3 elements
    ///   Chunked-N:    rlp([0, contextId])                — 2 elements
    fn parse_header_data(data: &[u8]) -> FrameType {
        // data is bytes 3..16 of the decrypted header (with zero padding)
        if data.is_empty() { return FrameType::Normal; }

        // Decode outer RLP list header
        let prefix = data[0];
        if prefix < 0xc0 {
            // Not a list — treat as normal
            return FrameType::Normal;
        }

        let (list_start, list_len) = if prefix <= 0xf7 {
            (1usize, (prefix - 0xc0) as usize)
        } else {
            let ll = (prefix - 0xf7) as usize;
            if data.len() < 1 + ll { return FrameType::Normal; }
            let mut len: usize = 0;
            for i in 0..ll { len = (len << 8) | (data[1 + i] as usize); }
            (1 + ll, len)
        };

        let list_data = &data[list_start..data.len().min(list_start + list_len)];

        // Decode individual elements from the list
        let mut elems: Vec<usize> = Vec::new();
        let mut pos = 0;
        while pos < list_data.len() && elems.len() < 4 {
            let b = list_data[pos];
            if b == 0x00 || b == 0x80 {
                // RLP for integer 0
                elems.push(0);
                pos += 1;
            } else if b < 0x80 {
                // Single-byte integer (1-127)
                elems.push(b as usize);
                pos += 1;
            } else if b <= 0xb7 {
                // Short string encoding for larger integers
                let slen = (b - 0x80) as usize;
                if pos + 1 + slen > list_data.len() { break; }
                let mut val: usize = 0;
                for i in 0..slen { val = (val << 8) | (list_data[pos + 1 + i] as usize); }
                elems.push(val);
                pos += 1 + slen;
            } else {
                break; // Unexpected encoding
            }
        }

        match elems.len() {
            3 => FrameType::ChunkedFirst { _context_id: elems[1], total_size: elems[2] },
            2 => FrameType::ChunkedContinuation { _context_id: elems[1] },
            _ => FrameType::Normal,
        }
    }

    fn update_mac_static(mac_secret: &B256, mac: &mut Keccak256, seed: &[u8]) -> Result<[u8; 32]> {
        let mut aes_block = Self::do_sum_static(mac);
        let cipher = Aes256::new(&mac_secret.0.into());
        
        // RLPx updateMac uses only 16 bytes for the block encryption? 
        // No, Aes256 uses 16 byte blocks.
        let mut block = [0u8; 16];
        block.copy_from_slice(&aes_block[0..16]);
        cipher.encrypt_block((&mut block).into());
        
        for i in 0..16 {
            aes_block[i] = block[i] ^ seed[i];
        }
        mac.update(&aes_block[0..16]);
        Ok(Self::do_sum_static(mac))
    }

    fn do_sum_static(mac: &Keccak256) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.clone().finalize());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_secrets() -> RLPxSecrets {
        RLPxSecrets {
            aes: B256::repeat_byte(0x11),
            mac: B256::repeat_byte(0x22),
            token: B256::repeat_byte(0x33),
            egress_mac: Keccak256::new(),
            ingress_mac: Keccak256::new(),
        }
    }

    fn make_codec_pair() -> (FrameCodec, FrameCodec) {
        (FrameCodec::new(make_secrets()), FrameCodec::new(make_secrets()))
    }

    // ---- parse_header_data tests ----

    #[test]
    fn test_parse_header_data_normal() {
        // rlp([0]) — Java encodes int 0 as 0x80
        // rlp list of 1 byte: 0xc1, 0x80
        let mut data = [0u8; 13];
        data[0] = 0xc1;
        data[1] = 0x80;
        assert!(matches!(FrameCodec::parse_header_data(&data), FrameType::Normal));
    }

    #[test]
    fn test_parse_header_data_chunked_first_small_values() {
        // rlp([0, contextId=1, totalSize=100])
        // Elements: 0x80 (int 0), 0x01 (int 1), 0x64 (int 100)
        // List payload = 3 bytes → prefix 0xc3
        let mut data = [0u8; 13];
        data[0] = 0xc3; // list of 3 bytes
        data[1] = 0x80; // int 0
        data[2] = 0x01; // int 1
        data[3] = 0x64; // int 100
        match FrameCodec::parse_header_data(&data) {
            FrameType::ChunkedFirst { _context_id, total_size } => {
                assert_eq!(_context_id, 1);
                assert_eq!(total_size, 100);
            }
            other => panic!("Expected ChunkedFirst, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_header_data_chunked_first_large_total_size() {
        // rlp([0, contextId=5, totalSize=109355])
        // 109355 = 0x01AB2B → 3 bytes → RLP: 0x83, 0x01, 0xAB, 0x2B
        // Elements: 0x80 (int 0), 0x05 (int 5), [0x83, 0x01, 0xAB, 0x2B]
        // List payload = 1 + 1 + 4 = 6 bytes → prefix 0xc6
        let mut data = [0u8; 13];
        data[0] = 0xc6; // list of 6 bytes
        data[1] = 0x80; // int 0
        data[2] = 0x05; // int 5
        data[3] = 0x83; // string of 3 bytes
        data[4] = 0x01;
        data[5] = 0xAB;
        data[6] = 0x2B;
        match FrameCodec::parse_header_data(&data) {
            FrameType::ChunkedFirst { _context_id, total_size } => {
                assert_eq!(_context_id, 5);
                assert_eq!(total_size, 109355);
            }
            other => panic!("Expected ChunkedFirst, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_header_data_continuation() {
        // rlp([0, contextId=3])
        // Elements: 0x80 (int 0), 0x03 (int 3)
        // List payload = 2 bytes → prefix 0xc2
        let mut data = [0u8; 13];
        data[0] = 0xc2; // list of 2 bytes
        data[1] = 0x80; // int 0
        data[2] = 0x03; // int 3
        match FrameCodec::parse_header_data(&data) {
            FrameType::ChunkedContinuation { _context_id } => {
                assert_eq!(_context_id, 3);
            }
            other => panic!("Expected ChunkedContinuation, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_header_data_empty() {
        assert!(matches!(FrameCodec::parse_header_data(&[]), FrameType::Normal));
    }

    #[test]
    fn test_parse_header_data_not_a_list() {
        // A string prefix instead of a list — should fall back to Normal
        let data = [0x83, 0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(FrameCodec::parse_header_data(&data), FrameType::Normal));
    }

    // ---- Normal single-frame roundtrip ----

    #[test]
    fn test_frame_codec_roundtrip() {
        let (mut encoder, mut decoder) = make_codec_pair();

        let protocol_id = 0x01;
        let payload = b"Hello RLPx Frame!";
        
        let encoded = encoder.encode_frame(protocol_id, payload).unwrap();
        let mut src = BytesMut::from(&encoded[..]);
        
        let decoded = decoder.decode_frame(&mut src).unwrap().unwrap();
        assert_eq!(decoded.0, protocol_id);
        assert_eq!(decoded.1, payload);
    }

    // ---- Multi-frame (chunked) assembly tests ----
    //
    // These simulate what the Java rskj node sends: messages split into multiple
    // frames, each with its own header-data and a ptype prefix in the body.

    /// Encode a single frame with custom header-data, mimicking Java writeFrame.
    /// The body on the wire is: [ptype] [payload_chunk], encrypted and MAC'd.
    fn encode_java_frame(
        codec: &mut FrameCodec,
        protocol_id: u8,
        payload_chunk: &[u8],
        header_data: &[u8],
    ) -> Vec<u8> {
        let mut head_buffer = [0u8; 32];
        let mut proto_rlp = Vec::new();
        protocol_id.encode(&mut proto_rlp);
        let total_size = payload_chunk.len() + proto_rlp.len();

        head_buffer[0] = (total_size >> 16) as u8;
        head_buffer[1] = (total_size >> 8) as u8;
        head_buffer[2] = total_size as u8;
        let hd_len = header_data.len().min(13);
        head_buffer[3..3 + hd_len].copy_from_slice(&header_data[..hd_len]);

        codec.enc.apply_keystream(&mut head_buffer[0..16]);
        let mac = FrameCodec::update_mac_static(&codec.mac_secret, &mut codec.egress_mac, &head_buffer[0..16]).unwrap();
        head_buffer[16..32].copy_from_slice(&mac[0..16]);

        let mut body = Vec::new();
        body.extend_from_slice(&proto_rlp);
        body.extend_from_slice(payload_chunk);
        let padding = 16 - (body.len() % 16);
        if padding < 16 {
            body.resize(body.len() + padding, 0u8);
        }

        codec.enc.apply_keystream(&mut body);
        codec.egress_mac.update(&body);
        let fmac_seed = FrameCodec::do_sum_static(&codec.egress_mac);
        let fmac = FrameCodec::update_mac_static(&codec.mac_secret, &mut codec.egress_mac, &fmac_seed[0..16]).unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(&head_buffer);
        out.extend_from_slice(&body);
        out.extend_from_slice(&fmac[0..16]);
        out
    }

    /// Build RLP-encoded header-data for a normal frame: rlp([0])
    fn header_data_normal() -> Vec<u8> {
        let mut out = Vec::new();
        alloy_rlp::encode_list(&[0u8], &mut out);
        out
    }

    /// Build RLP-encoded header-data for a chunked-first frame:
    /// rlp([0, context_id, total_frame_size])
    fn header_data_chunked_first(context_id: u8, total_frame_size: usize) -> Vec<u8> {
        // Manually build: list([encode_int(0), encode_int(ctx), encode_int(total)])
        let mut elems = Vec::new();
        0u8.encode(&mut elems);  // RLP for 0 → 0x80
        context_id.encode(&mut elems);
        (total_frame_size as u64).encode(&mut elems);
        let mut out = Vec::new();
        alloy_rlp::Header { list: true, payload_length: elems.len() }.encode(&mut out);
        out.extend_from_slice(&elems);
        out
    }

    /// Build RLP-encoded header-data for a continuation frame: rlp([0, context_id])
    fn header_data_continuation(context_id: u8) -> Vec<u8> {
        let mut elems = Vec::new();
        0u8.encode(&mut elems);
        context_id.encode(&mut elems);
        let mut out = Vec::new();
        alloy_rlp::Header { list: true, payload_length: elems.len() }.encode(&mut out);
        out.extend_from_slice(&elems);
        out
    }

    #[test]
    fn test_chunked_two_frames() {
        let (mut encoder, mut decoder) = make_codec_pair();

        let protocol_id: u8 = 0x18;
        // The full payload (what Java calls msg.getEncoded(), without ptype)
        let payload: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        let total_size = payload.len(); // Java's totalFrameSize

        // Split into two chunks
        let chunk1 = &payload[..60];
        let chunk2 = &payload[60..];

        let hd_first = header_data_chunked_first(1, total_size);
        let hd_cont = header_data_continuation(1);

        // Encode two frames the way Java does
        let frame1 = encode_java_frame(&mut encoder, protocol_id, chunk1, &hd_first);
        let frame2 = encode_java_frame(&mut encoder, protocol_id, chunk2, &hd_cont);

        let mut src = BytesMut::new();
        src.extend_from_slice(&frame1);
        src.extend_from_slice(&frame2);

        // First decode should return None (assembly in progress)
        let r1 = decoder.decode_frame(&mut src).unwrap();
        assert!(r1.is_none(), "First frame should not produce a message yet");

        // Second decode should complete the assembly
        let r2 = decoder.decode_frame(&mut src).unwrap();
        assert!(r2.is_some(), "Second frame should complete assembly");
        let (pid, assembled) = r2.unwrap();
        assert_eq!(pid, protocol_id);
        assert_eq!(assembled, payload);
    }

    #[test]
    fn test_chunked_four_frames() {
        let (mut encoder, mut decoder) = make_codec_pair();

        let protocol_id: u8 = 0x18;
        let payload: Vec<u8> = (0..250).map(|i| (i % 256) as u8).collect();
        let total_size = payload.len();

        // Split into 4 chunks of ~62-63 bytes each
        let chunks: Vec<&[u8]> = payload.chunks(63).collect();
        assert_eq!(chunks.len(), 4);

        let hd_first = header_data_chunked_first(1, total_size);
        let hd_cont = header_data_continuation(1);

        let mut src = BytesMut::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let hd = if i == 0 { &hd_first } else { &hd_cont };
            let frame = encode_java_frame(&mut encoder, protocol_id, chunk, hd);
            src.extend_from_slice(&frame);
        }

        // Decode frames 1-3: should return None
        for i in 0..3 {
            let r = decoder.decode_frame(&mut src).unwrap();
            assert!(r.is_none(), "Frame {} should not produce a message", i);
        }

        // Frame 4: should complete assembly
        let r = decoder.decode_frame(&mut src).unwrap();
        assert!(r.is_some(), "Last frame should complete assembly");
        let (pid, assembled) = r.unwrap();
        assert_eq!(pid, protocol_id);
        assert_eq!(assembled, payload);
    }

    #[test]
    fn test_chunked_then_normal_frame() {
        // Verify that after completing a chunked message, a normal frame works
        let (mut encoder, mut decoder) = make_codec_pair();

        let protocol_id: u8 = 0x18;
        let payload: Vec<u8> = (0..80).collect();
        let hd_first = header_data_chunked_first(1, payload.len());
        let hd_cont = header_data_continuation(1);

        let frame1 = encode_java_frame(&mut encoder, protocol_id, &payload[..50], &hd_first);
        let frame2 = encode_java_frame(&mut encoder, protocol_id, &payload[50..], &hd_cont);

        // Now a normal frame
        let normal_payload = b"normal message";
        let normal_frame = encode_java_frame(&mut encoder, 0x01, normal_payload, &header_data_normal());

        let mut src = BytesMut::new();
        src.extend_from_slice(&frame1);
        src.extend_from_slice(&frame2);
        src.extend_from_slice(&normal_frame);

        // Chunked frames
        assert!(decoder.decode_frame(&mut src).unwrap().is_none());
        let chunked = decoder.decode_frame(&mut src).unwrap().unwrap();
        assert_eq!(chunked.0, protocol_id);
        assert_eq!(chunked.1, payload);

        // Normal frame should work correctly after
        let normal = decoder.decode_frame(&mut src).unwrap().unwrap();
        assert_eq!(normal.0, 0x01);
        assert_eq!(normal.1, normal_payload.to_vec());
    }

    #[test]
    fn test_orphaned_continuation_ignored() {
        // A continuation frame with no preceding ChunkedFirst should be skipped
        let (mut encoder, mut decoder) = make_codec_pair();

        let hd_cont = header_data_continuation(99);
        let orphan = encode_java_frame(&mut encoder, 0x18, b"orphan data", &hd_cont);

        // Then a normal frame
        let normal = encode_java_frame(&mut encoder, 0x01, b"real message", &header_data_normal());

        let mut src = BytesMut::new();
        src.extend_from_slice(&orphan);
        src.extend_from_slice(&normal);

        // Orphaned continuation should be silently skipped
        let r1 = decoder.decode_frame(&mut src).unwrap();
        assert!(r1.is_none(), "Orphaned continuation should return None");

        // Normal frame should decode fine
        let r2 = decoder.decode_frame(&mut src).unwrap().unwrap();
        assert_eq!(r2.0, 0x01);
        assert_eq!(r2.1, b"real message".to_vec());
    }

    #[test]
    fn test_chunked_large_payload() {
        // Simulate a realistic scenario: ~100KB payload split into 32KB chunks
        let (mut encoder, mut decoder) = make_codec_pair();

        let protocol_id: u8 = 0x18;
        let payload: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let total_size = payload.len();
        let chunk_size = 32_768;

        let hd_first = header_data_chunked_first(1, total_size);
        let hd_cont = header_data_continuation(1);

        let chunks: Vec<&[u8]> = payload.chunks(chunk_size).collect();
        // 100_000 / 32_768 = 3 full + 1 partial = 4 frames
        assert_eq!(chunks.len(), 4);

        let mut src = BytesMut::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let hd = if i == 0 { &hd_first } else { &hd_cont };
            let frame = encode_java_frame(&mut encoder, protocol_id, chunk, hd);
            src.extend_from_slice(&frame);
        }

        // First 3 frames return None
        for _ in 0..3 {
            assert!(decoder.decode_frame(&mut src).unwrap().is_none());
        }

        // Last frame completes assembly
        let (pid, assembled) = decoder.decode_frame(&mut src).unwrap().unwrap();
        assert_eq!(pid, protocol_id);
        assert_eq!(assembled.len(), total_size);
        assert_eq!(assembled, payload);
    }
}
