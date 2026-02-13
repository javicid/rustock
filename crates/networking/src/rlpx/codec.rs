use crate::protocol::P2pMessage;
use crate::rlpx::frame::FrameCodec;
use bytes::{BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use anyhow::Result;
use alloy_rlp::{Decodable, Encodable};
use crate::codec::P2pCodecTrait;

pub struct RLPxCodec {
    frame_codec: FrameCodec,
}

impl P2pCodecTrait for RLPxCodec {}

impl RLPxCodec {
    pub fn new(frame_codec: FrameCodec) -> Self {
        Self { frame_codec }
    }
}

impl Decoder for RLPxCodec {
    type Item = P2pMessage;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        match self.frame_codec.decode_frame(src)? {
            Some((protocol_id, payload)) => {
                // Prepend protocol_id to payload to satisfy P2pMessage::decode
                let mut data = Vec::with_capacity(payload.len() + 1);
                data.push(protocol_id);
                data.extend_from_slice(&payload);
                
                let mut ptr = &data[..];
                let msg = P2pMessage::decode(&mut ptr)?;
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<P2pMessage> for RLPxCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: P2pMessage, dst: &mut BytesMut) -> Result<()> {
        let mut buffer = Vec::new();
        item.encode(&mut buffer);
        
        if buffer.is_empty() {
            return Err(anyhow::anyhow!("Cannot encode empty P2P message"));
        }
        
        let protocol_id = buffer[0];
        let payload = &buffer[1..];
        
        let frame = self.frame_codec.encode_frame(protocol_id, payload)?;
        dst.extend_from_slice(&frame);
        Ok(())
    }
}
