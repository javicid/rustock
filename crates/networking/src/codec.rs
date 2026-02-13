use crate::protocol::P2pMessage;
use alloy_rlp::{Decodable, Encodable};
use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use anyhow::Result;

pub trait P2pCodecTrait: Encoder<P2pMessage, Error = anyhow::Error> + Decoder<Item = P2pMessage, Error = anyhow::Error> {}
impl P2pCodecTrait for P2pCodec {}

pub struct P2pCodec;

impl Decoder for P2pCodec {
    type Item = P2pMessage;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.is_empty() {
            return Ok(None);
        }

        // We need at least the ID and the RLP header to know the length
        // P2pMessage RLP is encoded as: [ID] [RLP_PAYLOAD]
        // But the alloy_rlp Decodable for P2pMessage actually handles the ID.
        
        let mut data = &src[..];
        match P2pMessage::decode(&mut data) {
            Ok(msg) => {
                let consumed = src.len() - data.len();
                src.advance(consumed);
                Ok(Some(msg))
            }
            Err(alloy_rlp::Error::InputTooShort) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("RLP decode error: {:?}", e)),
        }
    }
}

impl Encoder<P2pMessage> for P2pCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: P2pMessage, dst: &mut BytesMut) -> Result<()> {
        let mut buffer = Vec::new();
        item.encode(&mut buffer);
        dst.extend_from_slice(&buffer);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::P2pMessage;
    
    #[test]
    fn test_codec_ping_pong() {
        let mut codec = P2pCodec;
        let mut dst = BytesMut::new();
        
        // Encode Ping
        codec.encode(P2pMessage::Ping, &mut dst).unwrap();
        assert!(!dst.is_empty());

        // Decode Ping
        let decoded = codec.decode(&mut dst).unwrap().unwrap();
        assert!(matches!(decoded, P2pMessage::Ping));
        assert!(dst.is_empty());
    }

    #[test]
    fn test_codec_partial_decode() {
        let mut codec = P2pCodec;
        let mut dst = BytesMut::new();
        
        // Encode Ping
        codec.encode(P2pMessage::Ping, &mut dst).unwrap();
        
        // Split into partials
        let mut partial = dst.split_to(1); // Just the ID
        let res = codec.decode(&mut partial).unwrap();
        assert!(res.is_none());
        assert_eq!(partial.len(), 1); // Should not advance if incomplete
        
        // Add back the rest
        partial.extend_from_slice(&dst);
        let res = codec.decode(&mut partial).unwrap().unwrap();
        assert!(matches!(res, P2pMessage::Ping));
    }
}
