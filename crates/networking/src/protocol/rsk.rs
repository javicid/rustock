use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable, Header as RlpHeader};
use alloy_primitives::{B256, U256};
use rustock_core::Header;
use super::rlp_compat::{decode_u8_lenient, decode_u64_lenient, decode_u256_lenient, decode_u32_lenient};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RskStatus {
    pub best_block_number: u64,
    pub best_block_hash: B256,
    pub best_block_parent_hash: Option<B256>,
    pub total_difficulty: Option<U256>,
}

impl Encodable for RskStatus {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut list = Vec::new();
        self.best_block_number.encode(&mut list);
        self.best_block_hash.encode(&mut list);
        
        if let (Some(parent), Some(td)) = (self.best_block_parent_hash, self.total_difficulty) {
            parent.encode(&mut list);
            td.encode(&mut list);
        }
        
        RlpHeader { list: true, payload_length: list.len() }.encode(out);
        out.put_slice(&list);
    }

    fn length(&self) -> usize {
        let mut len = self.best_block_number.length() + self.best_block_hash.length();
        if let (Some(parent), Some(td)) = (self.best_block_parent_hash, self.total_difficulty) {
            len += parent.length() + td.length();
        }
        RlpHeader { list: true, payload_length: len }.length() + len
    }
}

impl Decodable for RskStatus {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = RlpHeader::decode(buf)?;
        let mut body = &buf[..header.payload_length];
        *buf = &buf[header.payload_length..];

        let best_block_number = decode_u64_lenient(&mut body)?;
        let best_block_hash = B256::decode(&mut body)?;

        let mut status = Self {
            best_block_number,
            best_block_hash,
            best_block_parent_hash: None,
            total_difficulty: None,
        };

        if !body.is_empty() {
            status.best_block_parent_hash = Some(B256::decode(&mut body)?);
            status.total_difficulty = Some(decode_u256_lenient(&mut body)?);
        }

        Ok(status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BlockHeadersRequest {
    pub id: u64,
    pub query: BlockHeadersQuery,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BlockHeadersQuery {
    pub hash: B256,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct BlockHeadersResponse {
    pub id: u64,
    pub headers: Vec<Header>,
}

/// A block identifier used in skeleton responses (hash + number).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIdentifier {
    pub hash: B256,
    pub number: u64,
}

/// Request the hash of the block at a given height (type 8).
/// Used during connection-point binary search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashRequest {
    pub id: u64,
    pub height: u64,
}

/// Response with the block hash at the requested height (type 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashResponse {
    pub id: u64,
    pub hash: B256,
}

/// Request the skeleton (evenly-spaced block identifiers) from a starting height (type 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonRequest {
    pub id: u64,
    pub start_number: u64,
}

/// Response with a list of block identifiers forming the skeleton (type 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkeletonResponse {
    pub id: u64,
    pub block_identifiers: Vec<BlockIdentifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RskMessageType {
    Status = 1,
    BlockHashRequest = 8,
    BlockHeadersRequest = 9,
    BlockHeadersResponse = 10,
    SkeletonResponse = 13,
    SkeletonRequest = 16,
    BlockHashResponse = 18,
}

#[derive(Debug, Clone)]
pub enum RskSubMessage {
    Status(RskStatus),
    BlockHashRequest(BlockHashRequest),
    BlockHeadersRequest(BlockHeadersRequest),
    BlockHeadersResponse(BlockHeadersResponse),
    SkeletonRequest(SkeletonRequest),
    SkeletonResponse(SkeletonResponse),
    BlockHashResponse(BlockHashResponse),
    /// An RSK message type we don't need to handle (e.g. Transactions, NewBlockHashes, etc.)
    Unknown(u8),
}

impl RskSubMessage {
    pub fn message_type(&self) -> RskMessageType {
        match self {
            RskSubMessage::Status(_) => RskMessageType::Status,
            RskSubMessage::BlockHashRequest(_) => RskMessageType::BlockHashRequest,
            RskSubMessage::BlockHeadersRequest(_) => RskMessageType::BlockHeadersRequest,
            RskSubMessage::BlockHeadersResponse(_) => RskMessageType::BlockHeadersResponse,
            RskSubMessage::SkeletonRequest(_) => RskMessageType::SkeletonRequest,
            RskSubMessage::SkeletonResponse(_) => RskMessageType::SkeletonResponse,
            RskSubMessage::BlockHashResponse(_) => RskMessageType::BlockHashResponse,
            RskSubMessage::Unknown(_) => RskMessageType::Status, // Not used for encoding
        }
    }

    /// Encodes parameters as a List. 
    /// Corresponds to Java's getEncodedMessage() [id + params] or [params for status]
    fn encode_params(&self, out: &mut Vec<u8>) {
        match self {
            RskSubMessage::Status(s) => {
                let mut list = Vec::new();
                s.best_block_number.encode(&mut list);
                s.best_block_hash.encode(&mut list);
                if let (Some(parent), Some(td)) = (s.best_block_parent_hash, s.total_difficulty) {
                    parent.encode(&mut list);
                    td.encode(&mut list);
                }
                RlpHeader { list: true, payload_length: list.len() }.encode(out);
                out.extend_from_slice(&list);
            }
            RskSubMessage::BlockHeadersRequest(r) => {
                // RLP([id, RLP([hash, count])])
                let mut query_params = Vec::new();
                r.query.hash.encode(&mut query_params);
                r.query.count.encode(&mut query_params);
                
                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: query_params.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&query_params);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                // The inner list is pre-encoded RLP, so it's just appended to the outer list
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BlockHeadersResponse(r) => {
                // RLP([id, RLP([RLP([headers])])])
                let mut headers_payload = Vec::new();
                for h in &r.headers {
                    h.encode(&mut headers_payload);
                }
                
                let mut headers_list = Vec::new();
                RlpHeader { list: true, payload_length: headers_payload.len() }.encode(&mut headers_list);
                headers_list.extend_from_slice(&headers_payload);

                let mut wrapped_headers = Vec::new();
                RlpHeader { list: true, payload_length: headers_list.len() }.encode(&mut wrapped_headers);
                wrapped_headers.extend_from_slice(&headers_list);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&wrapped_headers);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BlockHashRequest(r) => {
                // RLP([id, RLP([height])])
                let mut inner = Vec::new();
                r.height.encode(&mut inner);

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: inner.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&inner);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::BlockHashResponse(r) => {
                // RLP([id, RLP([hash])])
                let mut inner = Vec::new();
                r.hash.encode(&mut inner);

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: inner.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&inner);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::SkeletonRequest(r) => {
                // RLP([id, RLP([startNumber])])
                let mut inner = Vec::new();
                r.start_number.encode(&mut inner);

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: inner.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&inner);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&inner_list);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::SkeletonResponse(r) => {
                // RLP([id, RLP([RLP([bid_0, bid_1, ...])])])
                // Each bid = RLP([hash, number])
                let mut bids_payload = Vec::new();
                for bid in &r.block_identifiers {
                    let mut bid_elems = Vec::new();
                    bid.hash.encode(&mut bid_elems);
                    bid.number.encode(&mut bid_elems);
                    RlpHeader { list: true, payload_length: bid_elems.len() }.encode(&mut bids_payload);
                    bids_payload.extend_from_slice(&bid_elems);
                }

                let mut inner_list = Vec::new();
                RlpHeader { list: true, payload_length: bids_payload.len() }.encode(&mut inner_list);
                inner_list.extend_from_slice(&bids_payload);

                let mut outer = Vec::new();
                RlpHeader { list: true, payload_length: inner_list.len() }.encode(&mut outer);
                outer.extend_from_slice(&inner_list);

                let mut params = Vec::new();
                r.id.encode(&mut params);
                params.extend_from_slice(&outer);

                RlpHeader { list: true, payload_length: params.len() }.encode(out);
                out.extend_from_slice(&params);
            }
            RskSubMessage::Unknown(_) => {
                // Unknown messages are not encoded/sent
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RskMessage {
    pub sub_message: RskSubMessage,
}

impl RskMessage {
    pub const MESSAGE_ID: u8 = 0x08;

    pub fn new(sub_message: RskSubMessage) -> Self {
        Self { sub_message }
    }
}

impl Encodable for RskMessage {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let mut params_rlp = Vec::new();
        self.sub_message.encode_params(&mut params_rlp);
        
        // Java Message.getEncoded(): RLP([type, RLP_String(params_rlp)])
        let mut msg_rlp = Vec::new();
        (self.sub_message.message_type() as u8).encode(&mut msg_rlp);
        // encodeElement wraps in Rlp String (Blob)
        RlpHeader { list: false, payload_length: params_rlp.len() }.encode(&mut msg_rlp);
        msg_rlp.extend_from_slice(&params_rlp);
        
        let mut wrapped_msg = Vec::new();
        RlpHeader { list: true, payload_length: msg_rlp.len() }.encode(&mut wrapped_msg);
        wrapped_msg.extend_from_slice(&msg_rlp);

        // Java RskMessage.encode(): RLP([wrapped_msg])
        let mut final_rlp = Vec::new();
        RlpHeader { list: true, payload_length: wrapped_msg.len() }.encode(&mut final_rlp);
        final_rlp.extend_from_slice(&wrapped_msg);

        out.put_slice(&final_rlp);
    }

    fn length(&self) -> usize {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
    }
}

impl Decodable for RskMessage {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let h1 = RlpHeader::decode(buf)?;
        let mut b1 = &buf[..h1.payload_length];
        *buf = &buf[h1.payload_length..];

        let h2 = RlpHeader::decode(&mut b1)?;
        let mut b2 = &b1[..h2.payload_length];

        let type_byte = decode_u8_lenient(&mut b2)?;
        
        // Next is the body_blob (RLP String)
        let body_h = RlpHeader::decode(&mut b2)?;
        if body_h.list {
            return Err(alloy_rlp::Error::Custom("Expected RLP string for body blob"));
        }
        let mut body_params = &b2[..body_h.payload_length];

        let sub_message = match type_byte {
            1 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let best_block_number = decode_u64_lenient(&mut list_body)?;
                let best_block_hash = B256::decode(&mut list_body)?;
                let mut status = RskStatus {
                    best_block_number,
                    best_block_hash,
                    best_block_parent_hash: None,
                    total_difficulty: None,
                };
                if !list_body.is_empty() {
                    status.best_block_parent_hash = Some(B256::decode(&mut list_body)?);
                    status.total_difficulty = Some(decode_u256_lenient(&mut list_body)?);
                }
                RskSubMessage::Status(status)
            }
            9 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;
                
                let query_h = RlpHeader::decode(&mut list_body)?;
                let mut query_body = &list_body[..query_h.payload_length];
                let hash = B256::decode(&mut query_body)?;
                let count = decode_u32_lenient(&mut query_body)?;

                RskSubMessage::BlockHeadersRequest(BlockHeadersRequest {
                    id,
                    query: BlockHeadersQuery { hash, count },
                })
            }
            10 => {
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let outer_h = RlpHeader::decode(&mut list_body)?;
                let mut outer_body = &list_body[..outer_h.payload_length];
                
                let inner_h = RlpHeader::decode(&mut outer_body)?;
                let mut inner_body = &outer_body[..inner_h.payload_length];

                let mut headers = Vec::new();
                while !inner_body.is_empty() {
                    headers.push(Header::decode(&mut inner_body)?);
                }
                RskSubMessage::BlockHeadersResponse(BlockHeadersResponse { id, headers })
            }
            8 => {
                // BlockHashRequest: RLP([id, RLP([height])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let inner_h = RlpHeader::decode(&mut list_body)?;
                let mut inner_body = &list_body[..inner_h.payload_length];
                let height = decode_u64_lenient(&mut inner_body)?;

                RskSubMessage::BlockHashRequest(BlockHashRequest { id, height })
            }
            13 => {
                // SkeletonResponse: RLP([id, RLP([RLP([bid_0, bid_1, ...])])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let outer_h = RlpHeader::decode(&mut list_body)?;
                let mut outer_body = &list_body[..outer_h.payload_length];

                let inner_h = RlpHeader::decode(&mut outer_body)?;
                let mut inner_body = &outer_body[..inner_h.payload_length];

                let mut block_identifiers = Vec::new();
                while !inner_body.is_empty() {
                    let bid_h = RlpHeader::decode(&mut inner_body)?;
                    let mut bid_body = &inner_body[..bid_h.payload_length];
                    inner_body = &inner_body[bid_h.payload_length..];
                    let hash = B256::decode(&mut bid_body)?;
                    let number = decode_u64_lenient(&mut bid_body)?;
                    block_identifiers.push(BlockIdentifier { hash, number });
                }

                RskSubMessage::SkeletonResponse(SkeletonResponse { id, block_identifiers })
            }
            16 => {
                // SkeletonRequest: RLP([id, RLP([startNumber])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let inner_h = RlpHeader::decode(&mut list_body)?;
                let mut inner_body = &list_body[..inner_h.payload_length];
                let start_number = decode_u64_lenient(&mut inner_body)?;

                RskSubMessage::SkeletonRequest(SkeletonRequest { id, start_number })
            }
            18 => {
                // BlockHashResponse: RLP([id, RLP([hash])])
                let list_h = RlpHeader::decode(&mut body_params)?;
                let mut list_body = &body_params[..list_h.payload_length];
                let id = decode_u64_lenient(&mut list_body)?;

                let inner_h = RlpHeader::decode(&mut list_body)?;
                let mut inner_body = &list_body[..inner_h.payload_length];
                let hash = B256::decode(&mut inner_body)?;

                RskSubMessage::BlockHashResponse(BlockHashResponse { id, hash })
            }
            other => {
                // Skip unknown message types gracefully (Transactions, NewBlockHashes, etc.)
                RskSubMessage::Unknown(other)
            }
        };

        Ok(RskMessage { sub_message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rlp::{Encodable, Decodable};

    #[test]
    fn test_rsk_status_rlp() {
        let status = RskStatus {
            best_block_number: 1234,
            best_block_hash: B256::repeat_byte(0x11),
            best_block_parent_hash: Some(B256::repeat_byte(0x22)),
            total_difficulty: Some(U256::from(9999)),
        };

        let mut buf = Vec::new();
        status.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskStatus::decode(&mut decode_buf).unwrap();
        assert_eq!(status, decoded);
    }

    #[test]
    fn test_rsk_message_rlp_status() {
        let status = RskStatus {
            best_block_number: 1,
            best_block_hash: B256::repeat_byte(0xaa),
            best_block_parent_hash: None,
            total_difficulty: None,
        };
        let msg = RskMessage::new(RskSubMessage::Status(status));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();
        
        if let RskSubMessage::Status(s) = decoded.sub_message {
            assert_eq!(s.best_block_number, 1);
            assert_eq!(s.best_block_hash, B256::repeat_byte(0xaa));
        } else {
            panic!("Expected Status message");
        }
    }

    #[test]
    fn test_rsk_message_rlp_headers_request() {
        let req = BlockHeadersRequest {
            id: 42,
            query: BlockHeadersQuery {
                hash: B256::repeat_byte(0xbb),
                count: 10,
            },
        };
        let msg = RskMessage::new(RskSubMessage::BlockHeadersRequest(req));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();
        
        if let RskSubMessage::BlockHeadersRequest(r) = decoded.sub_message {
            assert_eq!(r.id, 42);
            assert_eq!(r.query.count, 10);
            assert_eq!(r.query.hash, B256::repeat_byte(0xbb));
        } else {
            panic!("Expected BlockHeadersRequest message");
        }
    }

    #[test]
    fn test_rsk_message_rlp_block_hash_request() {
        let req = BlockHashRequest { id: 7, height: 12345 };
        let msg = RskMessage::new(RskSubMessage::BlockHashRequest(req));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BlockHashRequest(r) = decoded.sub_message {
            assert_eq!(r.id, 7);
            assert_eq!(r.height, 12345);
        } else {
            panic!("Expected BlockHashRequest, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_block_hash_response() {
        let resp = BlockHashResponse { id: 7, hash: B256::repeat_byte(0xcc) };
        let msg = RskMessage::new(RskSubMessage::BlockHashResponse(resp));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::BlockHashResponse(r) = decoded.sub_message {
            assert_eq!(r.id, 7);
            assert_eq!(r.hash, B256::repeat_byte(0xcc));
        } else {
            panic!("Expected BlockHashResponse, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_skeleton_request() {
        let req = SkeletonRequest { id: 99, start_number: 5000 };
        let msg = RskMessage::new(RskSubMessage::SkeletonRequest(req));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::SkeletonRequest(r) = decoded.sub_message {
            assert_eq!(r.id, 99);
            assert_eq!(r.start_number, 5000);
        } else {
            panic!("Expected SkeletonRequest, got {:?}", decoded.sub_message);
        }
    }

    #[test]
    fn test_rsk_message_rlp_skeleton_response() {
        let resp = SkeletonResponse {
            id: 99,
            block_identifiers: vec![
                BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
                BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
                BlockIdentifier { hash: B256::repeat_byte(0x03), number: 384 },
            ],
        };
        let msg = RskMessage::new(RskSubMessage::SkeletonResponse(resp));

        let mut buf = Vec::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.as_slice();
        let decoded = RskMessage::decode(&mut decode_buf).unwrap();

        if let RskSubMessage::SkeletonResponse(r) = decoded.sub_message {
            assert_eq!(r.id, 99);
            assert_eq!(r.block_identifiers.len(), 3);
            assert_eq!(r.block_identifiers[0].hash, B256::repeat_byte(0x01));
            assert_eq!(r.block_identifiers[0].number, 0);
            assert_eq!(r.block_identifiers[1].number, 192);
            assert_eq!(r.block_identifiers[2].number, 384);
        } else {
            panic!("Expected SkeletonResponse, got {:?}", decoded.sub_message);
        }
    }
}
