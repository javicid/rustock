use anyhow::{Result};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use sha3::{Keccak256, Digest};
use bytes::{BytesMut, Buf};
use alloy_rlp::{Encodable, Decodable};
use alloy_primitives::{B256};
use crate::rlpx::ecies::RLPxSecrets;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub struct FrameCodec {
    enc: Aes256Ctr,
    dec: Aes256Ctr,
    mac_secret: B256,
    egress_mac: Keccak256,
    ingress_mac: Keccak256,
    is_head_read: bool,
    total_body_size: usize,
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

        let mut body_ptr = &body[..self.total_body_size];
        let protocol_id = u8::decode(&mut body_ptr)?;
        let payload = body_ptr.to_vec();

        Ok(Some((protocol_id, payload)))
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

    #[test]
    fn test_frame_codec_roundtrip() {
        let aes = B256::repeat_byte(0x11);
        let mac = B256::repeat_byte(0x22);
        let token = B256::repeat_byte(0x33);
        
        let secrets = RLPxSecrets {
            aes: aes.clone(),
            mac: mac.clone(),
            token,
            egress_mac: Keccak256::new(),
            ingress_mac: Keccak256::new(),
        };

        // We need to simulate the ingress/egress state correctly
        // Initials secrets don't have MAC state updated with packets yet
        // In reality, agree_secret handles this.
        
        let mut encoder = FrameCodec::new(secrets);
        
        // Re-create secrets for decoder to have same start state
        let secrets2 = RLPxSecrets {
            aes: aes.clone(),
            mac: mac.clone(),
            token: B256::repeat_byte(0x33),
            egress_mac: Keccak256::new(),
            ingress_mac: Keccak256::new(),
        };
        let mut decoder = FrameCodec::new(secrets2);

        let protocol_id = 0x01;
        let payload = b"Hello RLPx Frame!";
        
        let encoded = encoder.encode_frame(protocol_id, payload).unwrap();
        let mut src = BytesMut::from(&encoded[..]);
        
        let decoded = decoder.decode_frame(&mut src).unwrap().unwrap();
        assert_eq!(decoded.0, protocol_id);
        assert_eq!(decoded.1, payload);
    }
}
