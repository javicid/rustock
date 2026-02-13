# Java RSK Node (rskj) Compatibility Notes

This document describes behaviors specific to the Java RSK node (`rskj`) that
diverge from standard Ethereum RLPx implementations (e.g. geth, reth). These
must be preserved in the Rust client for interoperability.

## 1. Multi-Frame (Chunked) RLPx Messages

**Source**: `rskj/.../rlpx/FrameCodec.java`, `rskj/.../rlpx/MessageCodec.java`

Standard Ethereum clients (geth, reth) send each P2P message as a single RLPx
frame regardless of size. The Java RSK node splits messages larger than ~32 KB
into multiple frames, each with its own header and MAC.

### How chunking works

`MessageCodec.splitMessageToFrames` slices `msg.getEncoded()` into chunks of
`maxFramePayloadSize` (32,768 bytes). Each chunk becomes a `Frame` object that
shares the same `contextId` and message `type` (code).

The first frame carries `totalFrameSize = msg.getEncoded().length` in its
header-data. Continuation frames carry only the `contextId`.

### Header-data encoding

Bytes 3-15 of the decrypted 16-byte frame header contain RLP-encoded
header-data:

| Frame kind    | header-data                                     | RLP element count |
|---------------|-------------------------------------------------|-------------------|
| Normal        | `rlp([0])`                                      | 1                 |
| Chunked-first | `rlp([0, contextId, totalFrameSize])`           | 3                 |
| Continuation  | `rlp([0, contextId])`                           | 2                 |

### ptype prefix on every frame body

`FrameCodec.writeFrame` prepends the RLP-encoded message type (`ptype`) to the
encrypted body of **every** frame, not just the first:

```java
byte[] ptype = RLP.encodeInt((int) frame.type);
int totalSize = frame.size + ptype.length;   // frame-size in header
// ...
enc.processBytes(ptype, ...);                // written first
// then the payload chunk follows
```

For message code 24 (0x18), `ptype` is a single byte `0x18`.  The receiver
must strip this prefix from every frame body before concatenating the payload
chunks.

**Key consequence**: `totalFrameSize` from the header-data equals
`msg.getEncoded().length` and does **not** include the per-frame ptype bytes.
After stripping ptype from each frame, the concatenated payload must equal
exactly `totalFrameSize` bytes.

### Rust implementation

See `crates/networking/src/rlpx/frame.rs`:

- `FrameType` enum identifies frame kinds via `parse_header_data`.
- `ChunkedFirst` extracts the protocol_id (ptype) and begins assembly.
- `ChunkedContinuation` strips the ptype and appends only the data portion.
- Assembly completes when `assembly_buf.len() >= totalFrameSize`.

---

## 2. Non-Canonical RLP Integer Encoding

**Source**: Java's `BigInteger.toByteArray()`

Java's `BigInteger` serialization includes a leading zero byte for positive
values whose most significant bit is set (sign extension). For example, the
value `0x80` is encoded as `[0x00, 0x80]` rather than `[0x80]`.

Standard RLP decoders (including `alloy_rlp`) reject these as non-canonical.
Lenient decoders in `crates/networking/src/protocol/rlp_compat.rs` strip
leading zeros before parsing:

- `decode_u8_lenient`
- `decode_u32_lenient`
- `decode_u64_lenient`
- `decode_u256_lenient`

These are used wherever integer fields arrive from the Java node (block
headers, status messages, request IDs, etc.).

---

## 3. Compressed Block Headers (RSKIP-351)

**Source**: `rskj/.../core/BlockHeader.java`, RSKIP-351

Recent RSK blocks replace the 256-byte `logsBloom` field (RLP field index 6)
with a shorter `extensionData` blob containing `rlp([version, hash])`. This
significantly reduces header size.

The Rust `Header::decode` in `crates/core/src/types/header.rs` peeks at the
RLP header of field 6:

- If it is a **non-list** of exactly **256 bytes** -> standard `logsBloom`.
- Otherwise -> compressed `extensionData`; store the raw bytes and set
  `logsBloom` to default.

---

## 4. RSK Sub-Protocol Message Wrapping

**Source**: `rskj/.../net/messages/Message.java`

RSK messages use a double-wrapped RLP structure that differs from standard
Ethereum eth sub-protocol messages:

```
RLP([                          // outer list  (RskMessage.encode)
  RLP([                        // inner list  (Message.getEncoded)
    type_byte,                 // e.g. 10 for BlockHeadersResponse
    RLP_String(body_params)    // body as an RLP string (not list)
  ])
])
```

The body is encoded as an **RLP string** (blob), not a list. Inside that
string, the actual parameters are a nested RLP list. `RskMessage::decode` in
`crates/networking/src/protocol/rsk.rs` handles this unwrapping.

### Unknown message types

The Java node sends many message types beyond what a light client needs
(Transactions, NewBlockHashes, GetBlockHeaders from peers, etc.). These are
handled gracefully via `RskSubMessage::Unknown(u8)` to avoid crashing sessions.

---

## 5. Backward Header Delivery

RSK peers return `BlockHeadersResponse` in **descending** block number order
(highest first). `SyncManager::handle_headers_response` reverses the list
before processing so headers are stored in ascending order.

---

## References

- rskj source: `../rskj/rskj-core/src/main/java/org/ethereum/net/rlpx/`
- RSKIP-351: Compressed block header format
- RLPx spec: https://github.com/ethereum/devp2p/blob/master/rlpx.md
