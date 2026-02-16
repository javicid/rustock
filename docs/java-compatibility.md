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

## 2. Non-Canonical RLP Integer Encoding & Header Hash Incompatibility

**Source**: Java's `BigInteger.toByteArray()`

### The problem

Java's `BigInteger` uses two's-complement representation. `toByteArray()`
includes a **leading `0x00` byte** for positive values whose most significant
bit is set, to preserve the sign:

```
BigInteger(127).toByteArray()  → [0x7F]           // MSB < 0x80, no padding
BigInteger(128).toByteArray()  → [0x00, 0x80]     // MSB = 0x80, sign byte added
BigInteger(256).toByteArray()  → [0x01, 0x00]     // MSB < 0x80, no padding
BigInteger(32768).toByteArray()→ [0x00, 0x80, 0x00]// MSB = 0x80, sign byte added
```

The original `ethereumj` (from which `rskj` is forked) passes
`BigInteger.toByteArray()` directly to `RLP.encodeElement()` for integer fields
like `difficulty`, `gasLimit`, `paidFees`, and `minimumGasPrice`. This violates
the canonical RLP specification (Ethereum Yellow Paper), which requires integers
to use their minimal byte representation with **no** leading zeros.

**This is a Java language characteristic, not a deliberate design decision.**
The `BigInteger` sign-byte behavior is baked into the JVM, and the original
ethereumj authors simply used the natural serialization without stripping
leading zeros. The rskj node inherited this behavior.

### Consequences

1. **Decoding**: Standard RLP decoders (including `alloy_rlp`) reject these
   non-canonical integers. Lenient decoders are needed on the receiving side.

2. **Header hashing**: The hash of a block header is `keccak256(RLP(header))`.
   Because Java encodes some integer fields with an extra byte, the RLP output
   differs from canonical encoding. **Re-encoding a decoded header in Rust
   produces different bytes and therefore a different hash.** This is
   value-dependent: blocks whose `difficulty` happens to be `0x80XXXX...` are
   affected, while `0x7FXXXX...` is not.

3. **Chain breaks**: When block N+1 stores `parent_hash = java_hash(block_N)`,
   but our store indexes block N under `rust_hash(block_N)`, the parent lookup
   fails. This causes total-difficulty chains to break and the head to stop
   advancing.

### Rust mitigations

**Lenient decoding** (`crates/networking/src/protocol/rlp_compat.rs`):

- `decode_u8_lenient`, `decode_u32_lenient`, `decode_u64_lenient`,
  `decode_u256_lenient`
- Strip leading zeros before parsing. Used wherever integer fields arrive from
  the Java node (block headers, status messages, request IDs, etc.).

**Cached hash from original bytes** (`crates/core/src/types/header.rs`):

- `Header` carries an optional `cached_hash: Option<B256>` field.
- `Header::decode_with_hash()` computes `keccak256` over the **original RLP
  bytes** received from the peer (before decoding and re-encoding), and stores
  the result in `cached_hash`.
- `Header::hash()` returns `cached_hash` when present, falling back to
  `keccak256(self.encode())` for locally-constructed headers.
- The network message decoder (`crates/networking/src/protocol/rsk.rs`) uses
  `decode_with_hash` for all `BlockHeadersResponse` payloads.

This is the same approach used by production Ethereum clients (Geth, Reth):
cache the hash from wire bytes rather than recomputing from re-encoded data.
It decouples hash identity from encoding, making the client resilient to any
encoding differences across implementations.

**ParentHashRule omission** (`crates/core/src/validation/mod.rs`):

The `ParentHashRule` (which re-derives the parent's hash via `parent.hash()`)
is intentionally excluded from the default verifier. During sync, parent-hash
consistency is already guaranteed by the store lookup: we find the parent by
`header.parent_hash`, so a successful lookup proves the hash matches. This
avoids the need to reproduce Java's exact encoding for the parent.

### Why not make Rust encoding match Java?

We considered implementing a "Java-compatible" RLP encoder, but decided against
it:

- **Value-dependent**: the extra byte only appears when MSB ≥ `0x80`. We would
  need to replicate this quirk for every field that Java encodes via
  `BigInteger`, which is fragile and hard to verify.
- **Not all fields use BigInteger**: Java encodes some fields as `long`, some
  as raw bytes, some as `BigInteger`. Matching the exact per-field behavior
  requires tracking rskj's internal type choices.
- **Violates the RLP spec**: non-canonical encoding would break interop with
  standard Ethereum tooling and libraries (`alloy-rlp`, `ssz`, etc.).
- **Fragile over time**: if rskj changes how it encodes a field, our mimicry
  would silently break.

The cached-hash approach is more robust: it works for all headers, all values,
and all future protocol versions, without requiring byte-level encoding
compatibility.

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

## 5. Descending Header Delivery

**Source**: `rskj/.../net/NodeBlockProcessor.java` (`processBlockHeadersRequest`)

RSK peers return `BlockHeadersResponse` in **descending** block number order
(highest first). The server starts at the requested hash and walks
`getParentHash()` backward for `count` blocks.

`SyncManager::handle_headers_response` in `crates/sync/src/lib.rs` reverses
the list before processing so headers are stored in ascending order.

---

## 6. Skeleton-Based Forward Sync Protocol

**Source**: `rskj/.../net/sync/` (multiple state classes)

The Java `rskj` node uses a multi-phase skeleton-based sync, **not** a simple
backward download. The Rust light client mirrors this approach.

### Sync phases

| Phase | Java class | Rust equivalent |
|-------|-----------|-----------------|
| 1. Find connection point | `FindingConnectionPointSyncState` | `SyncState::FindingConnectionPoint` |
| 2. Download skeleton | `DownloadingSkeletonSyncState` | `SyncState::DownloadingSkeleton` |
| 3. Download headers | `DownloadingHeadersSyncState` | `SyncState::DownloadingHeaders` |
| 4. Download bodies | `DownloadingBodiesSyncState` | *(skipped — light client)* |

### Phase 1: Connection point (binary search)

Uses `BlockHashRequest` (type 8) / `BlockHashResponse` (type 18) to
binary-search for the highest block that both the local store and the peer
share. Search range: `[0, peerBestBlockNumber]`. Converges in `O(log N)` steps.

The Java `ConnectionPointFinder` uses the algorithm:
- `mid = start + (end - start) / 2`
- Peer responds with the hash at `mid`
- If we have it locally: `start = mid` (search higher)
- If we don't: `end = mid` (search lower)
- When `end - start <= 1`: connection point = `start`

### Phase 2: Skeleton download

Sends `SkeletonRequest` (type 16) with the connection point height. The peer
responds with `SkeletonResponse` (type 13) containing a list of
`BlockIdentifier(hash, number)` at intervals of `CHUNK_SIZE = 192` blocks.

Server-side skeleton construction (`NodeBlockProcessor.processSkeletonRequest`):
- Rounds start down to nearest multiple of 192
- Adds entries every 192 blocks up to `maxSkeletonChunks * 192` (default: 3840)
- Appends the best block as the final entry
- Result: at most 21 entries covering up to 3840 blocks per skeleton round

### Phase 3: Chunk-by-chunk header download

For each pair of adjacent skeleton points `[S_{i-1}, S_i]`:
- Request `count = S_i.number - max(S_{i-1}.number, connectionPoint)` headers
  starting from `S_i.hash`
- Peer responds with headers in descending order
- Client reverses to ascending, validates each header against its parent
- Since chunks are processed in order from the connection point forward,
  every header has a known parent and can be **fully verified**

When all chunks in a skeleton are processed and the node is still behind the
peer, a new skeleton is requested from the current head.

### Key constants (from `RskSystemProperties.java`)

| Constant | Value | Meaning |
|----------|-------|---------|
| `CHUNK_SIZE` | 192 | Headers per chunk / skeleton interval |
| `maxSkeletonChunks` | 20 | Max chunks per skeleton round |
| `timeoutWaitingRequest` | 30 s | Per-request timeout |

### Message types used

| Message | Type ID | Fields |
|---------|---------|--------|
| `BlockHashRequest` | 8 | `id`, `height` |
| `BlockHashResponse` | 18 | `id`, `hash` |
| `SkeletonRequest` | 16 | `id`, `startNumber` |
| `SkeletonResponse` | 13 | `id`, `blockIdentifiers[]` |
| `BlockHeadersRequest` | 9 | `id`, `hash`, `count` |
| `BlockHeadersResponse` | 10 | `id`, `headers[]` |

All extend `MessageWithId` and use the RSK double-wrapped RLP encoding
described in section 4.

### Rust implementation

See `crates/sync/src/lib.rs`:
- `SyncState` enum drives the state machine
- `SyncHandler` forwards inbound messages to `SyncService` via an mpsc channel
- `SyncService::start()` runs the event loop (timer ticks + channel events)
- `SyncManager::handle_headers_response()` validates and stores each chunk

---

## 7. Hardfork-Gated Validation Rules

**Source**: `rskj/.../config/blockchain/upgrades/ActivationConfig.java`,
`rskj/.../config/Constants.java`

Several consensus rules are activated at specific block heights (hardforks).
Applying them to blocks before their activation height causes false rejections
during sync.

### Activation heights (mainnet)

| Hardfork | Block | Relevant RSKIPs |
|----------|-------|-----------------|
| Orchid | 729,000 | RSKIP92 (merged mining PoW), RSKIP97 (no 10-min reset), RSKIP98 (no fallback mining) |
| Papyrus200 | 2,392,700 | RSKIP156 (difficulty divisor 50 → 400) |

### Merged mining (RSKIP92/98)

Before Orchid, RSK allowed "fallback mining" without proper Bitcoin merged
mining fields. The `MergedMiningRule` in `crates/core/src/validation/merged_mining.rs`
skips validation for blocks below `activation_heights.orchid`.

After Orchid, the rule validates:
1. Bitcoin header PoW against RSK difficulty target
2. Merkle proof linking coinbase to Bitcoin header
3. RSK tag (`RSKBLOCK:` + hash) in coinbase outputs

### Difficulty calculation

The `DifficultyRule` in `crates/core/src/validation/difficulty.rs` applies
three hardfork-gated behaviors matching `rskj/.../core/DifficultyCalculator.java`:

1. **Minimum difficulty floor**: `max(minDifficulty, fromParent)`. Mainnet
   minimum is `7,000,000,000,000,000` (7e15), derived from
   `FALLBACK_MINING_DIFFICULTY / 2 = 14e15 / 2`. This prevents difficulty
   from dropping below the floor during slow-block periods.

2. **10-minute reset** (pre-RSKIP97, before block 729,000): if
   `header.timestamp ≥ parent.timestamp + 600`, difficulty resets to minimum.
   This allowed recovery from mining stalls before Orchid.

3. **RSKIP156 divisor change** (from block 2,392,700): difficulty divisor
   increases from 50 to 400, making difficulty adjustments smoother. Note:
   regtest is explicitly excluded from this change in rskj
   (`getChainId() != REGTEST_CHAIN_ID`).

### Rust implementation

`ChainConfig` in `crates/core/src/config.rs` includes an `ActivationHeights`
struct with `orchid` and `papyrus200` fields. Both `MergedMiningRule` and
`DifficultyRule` check `header.number` against these heights before applying
hardfork-specific logic.

---

## References

- rskj source: `../rskj/rskj-core/src/main/java/org/ethereum/net/rlpx/`
- rskj sync: `../rskj/rskj-core/src/main/java/co/rsk/net/sync/`
- RSKIP-351: Compressed block header format
- RLPx spec: https://github.com/ethereum/devp2p/blob/master/rlpx.md
