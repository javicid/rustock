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

**Lenient decoding** (`crates/core/src/rlp_compat.rs`):

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

## 8. Java `HashMap` Iteration Order in Consensus Serialization

**Source**: `rskj/.../peg/BridgeSerializationUtils.java`
(`serializeOneOffLockWhitelist`), `rskj/.../peg/whitelist/LockWhitelist.java`,
`co.rsk.bitcoinj.core.VersionedChecksummedBytes`

### The problem

Some consensus-critical Bridge state is serialized by **iterating a Java
`HashMap`** and writing entries in iteration order. `HashMap` iteration order
is not insertion order and not sorted — it is the order in which entries sit
in the hash-table buckets, which depends on each key's `hashCode()`, the
table capacity, and the JVM's bucketing/resize algorithm. Because the
serialized bytes feed directly into the unitrie (and thus the block's state
root), **the state root depends on Java's `HashMap` layout**.

This is a Java-compatibility constraint, not a deliberate design choice: the
serialized order is tied to a specific JDK's `HashMap` iteration behavior, so
the Rust client must reproduce Java 8's `HashMap` ordering bit-for-bit to
match historical mainnet state. (It also pins a Java node to a compatible JDK,
since the iteration order is implementation-dependent.)

### Where it appears

The **one-off lock whitelist** (`addLockWhitelistAddress` /
`addOneOffLockWhitelistAddress`). rskj's `LockWhitelist` holds a
`HashMap<Address, LockWhitelistEntry>`; `serializeOneOffLockWhitelist` writes
`RLP([hash160_0, maxVal_0, hash160_1, maxVal_1, ..., disableBlockHeight])`
with the `hash160`/`maxVal` pairs in **map iteration order**.

With a single entry, order is irrelevant. With two or more, insertion order
and `HashMap` order diverge. This surfaced as the first orchid-converted
state-root mismatch at **mainnet #3304** — the second `addLockWhitelistAddress`
on mainnet. (Pre-RSKIP126 state roots are not validated during normal sync, so
such a divergence stays invisible until the first unitrie state-root check at
Wasabi100 / #1,591,000 — or until the diagnostic
`RUSTOCK_ORCHID_CHECK_INTERVAL` per-block converter check catches it at its
origin.)

### Java 8 `HashMap` semantics replicated

- Initial capacity 16, load factor 0.75 (resize when `size` exceeds
  `0.75 * capacity`).
- Bucket index: `spread(h) & (capacity - 1)` where `spread(h) = h ^ (h >>> 16)`.
- Within a bucket: insertion order.
- Resize doubles capacity and re-buckets while preserving per-bucket order
  (the lo/hi split). rskj deserializes into a fresh `HashMap` in the stored
  order each block, so re-serializing is a fixed point we mirror by reordering
  the current entries.

### Key `hashCode`

The map key is a `co.rsk.bitcoinj.core.Address`, whose `hashCode()` (inherited
from `VersionedChecksummedBytes`) is:

```java
com.google.common.base.Objects.hashCode(version, Arrays.hashCode(bytes))
// = 31 * (31 * 1 + version) + Arrays.hashCode(bytes)
```

Empirically (validated against the #3304 mainnet state root), the array hashed
must be the **version-prefixed 21 bytes** `[version] ++ hash160`, with the
mainnet P2PKH `version = 0x00`.

### Rust implementation

`crates/execution/src/bridge/storage.rs`:

- `java_bytes_hashcode` — Java `Arrays.hashCode(byte[])` (signed bytes).
- `whitelist_key_hashcode` — the `Address` key hash above.
- `java_hashmap_order` — Java 8 `HashMap` iteration order for a set of keys.
- `serialize_one_off_whitelist` reorders entries via `java_hashmap_order`
  before RLP-encoding.

Locked in by groundtruth unit tests against the #3303 (single-entry) and
#3304 (two-entry) state roots.

### Open caveats (see TODO)

- The exact key-hash variant (Guava-wrapped vs bare `Arrays.hashCode` over the
  21-byte array) is indistinguishable with only two entries; both reproduce
  #3304. Validate at the first 3+-entry whitelist block.
- The `version` byte is assumed `0x00` (mainnet P2PKH); a P2SH whitelist entry
  would need its real version.
- Post-RSKIP87, the unlimited whitelist is merged into the same map before
  `getAll` filters one-off entries, so unlimited keys can perturb one-off
  ordering — handle when both coexist.
- Other Bridge collections serialized from Java `Map`/`Set` (e.g. UTXO sets,
  the processed-tx set) may carry the same ordering dependency; audit if a
  state-root mismatch points at one.

---

## 9. Unitrie Account & Storage Encoding (byte-exact match with rskj)

The pre-RSKIP126 (Orchid) state root is validated by converting rustock's
unitrie to the Orchid format — and that conversion *normalises* account
nonce/balance (it decodes and re-encodes them) and re-keys storage cells by
their slot hash. So three unitrie-encoding incompatibilities were invisible to
the Orchid diagnostic yet would diverge the real unitrie state root at the
wasabi100 (#1,591,000) check. All three were surfaced together as the first
mainnet block with an uncle (#3,397) and ground-truthed by dumping rskj's
own #3,397 unitrie (`co.rsk.cli.tools.ExportState` against a synced
`~/.rsk/mainnet`); after the fixes rustock's #3,397 unitrie matches rskj's
byte-for-byte (7,588 leaves).

### 9a. Account balance: `RLP.encodeSignedCoinNonNullZero`

rskj's `AccountState.getEncoded()` (`org.ethereum.core.AccountState`) encodes
the two fields differently:

- **nonce** — `RLP.encodeBigInteger`: zero is RLP-empty (`0x80`), non-zero is
  the unsigned minimal big-endian bytes. This is standard RLP.
- **balance** — `RLP.encodeSignedCoinNonNullZero`: zero is the single byte
  `0x00` (NOT RLP-empty `0x80`), and a non-zero balance is
  `RLP.encodeElement(Coin.getBytes())` where `Coin.getBytes()` is
  `BigInteger.toByteArray()` — *signed* two's-complement, so a leading `0x00`
  is prepended whenever the most-significant bit of the minimal encoding is set.

rustock had encoded balance with the same standard RLP as nonce (zero → `0x80`),
which differs for every zero-balance account (the REMASC contract record is
`c28000` in rskj vs the old `c28080`; a fresh nonce-1 EOA is `c20100` vs
`c20180`). Handled in `crates/trie/src/account.rs` (`encode_coin_nonnull_zero`
on encode, a lenient `decode_coin` that accepts `0x00`, signed leading zeros and
the legacy `0x80` on decode).

### 9b. Storage key for the all-zero slot: `ByteUtil.stripLeadingZeroes`

`TrieKeyMapper.getAccountStorageKey` builds a storage key as
`accountStoragePrefix || keccak(subkey)[0:10] || stripLeadingZeroes(subkey)`.
rskj's `ByteUtil.stripLeadingZeroes` is called with the default
`valueForZero = ZERO_BYTE_ARRAY`, so an **all-zero** slot (storage slot `0`)
strips to a single `0x00` byte, not to empty. rustock stripped it to empty,
shortening the unitrie key of every slot-0 cell by one byte. Handled in
`crates/trie/src/key_mapper.rs` (`strip_leading_zeros` returns one `0x00` byte
for all-zero input).

### 9c. REMASC `siblings` storage cell

`RemascStorageProvider.save()` calls `saveSiblings()` on **every** REMASC
execution (the last tx of every block), with no guard:
`addStorageBytes(REMASC_ADDR, DataWord.fromString("siblings"),
RLP.encodedEmptyList())` — a single `0xc0` byte. The cell is created at block #1
and never changes value, but it is part of the unitrie (and the state root) from
then on. rustock never wrote it; the cell first became visible in the Orchid
diagnostic at #3,397 (siblings are not re-keyed away like the other normalised
content). Handled in `crates/execution/src/executor.rs` (the REMASC system-tx
branch writes the cell through the raw-storage overlay every block).

**Open item — Orchid converter vs `addStorageBytes`:** with the siblings cell
now present, rustock's Orchid converter (`orchid_state_root`) no longer
reproduces the pre-126 header root (it includes/mis-structures the cell where
rskj's `TrieConverter` does not). This is a *diagnostic-only* limitation — the
real consensus check is the unitrie root from wasabi100 onward — but it means
`RUSTOCK_ORCHID_CHECK_INTERVAL` can no longer be used as a pre-126 bisect tool
until the converter's `addStorageBytes` handling is aligned with rskj. Logged in
TODO.

---

## 10. Storage-Prefix Marker Only for Genuine Contract Creations

rskj writes a "storage root" sentinel — `0x01` at the trie key
`getAccountStoragePrefixKey(addr) = accountKey || 0x00` — via
`MutableRepository.setupContract` (`org.ethereum.db.MutableRepository`). It is
called **only** for genuine contract setups:

- a `CREATE` transaction with non-empty data (`TransactionExecutor.create`; an
  empty-data create "doesn't even call setupContract()"),
- the `CREATE`/`CREATE2` opcodes (`Program.createContract`),
- a successful precompiled-contract call (`TransactionExecutor.executePrecompiled`
  / `Program.callToPrecompiledAddress`),
- precompile activation bookkeeping (`BlockExecutor.maintainPrecompiledContractStorageRoots`)
  and genesis contracts.

It is **not** called for an ordinary account that merely received value.

revm complicates this under RSK's "frontier forever" rules (Spurious Dragon
never activates): `JournalInner::finalize` *materialises* every account that is
touched, empty, and previously non-existent by calling `Account::mark_created()`
— setting the global `Created` flag (with **no** `CreatedLocal`) purely so the
empty account survives the commit. A genuine CREATE instead goes through
`JournalInner::create_account_checkpoint`, which calls `mark_created_locally()`
(`CreatedLocal` + `Created`) and deploys code.

rustock originally wrote the marker for *every* `Created` account, so these
materialised empties got spurious `accountKey || 0x00 = 0x01` cells that rskj's
unitrie does not have. Ground truth: dumping rskj's mainnet unitrie at
\#1,590,999 vs rustock's showed ~20 such extra cells (all code-less, storage-less
EOAs that had taken value), which would diverge the wasabi100 state root.

Fix (`crates/execution/src/state.rs`): inside the `Created` branch, write the
marker only when the account has non-empty code **or** is `is_created_locally()`
(and is not in `skip_created`). `CreatedLocal` alone is insufficient — it is
cleared when an account is cold-loaded again in a later transaction of the same
block (revm's EIP-6780 handling, `JournalInner::load_account`), so a contract
created and re-called within one block would lose it; the `has_code` term covers
those. Precompile markers continue to be written through `ContractMarkers::precompiles`.

### 10a. Empty-data CREATE transactions must be excluded explicitly

The `is_created_locally()` term above is necessary but not sufficient. A
top-level **CREATE transaction carrying empty data** still goes through revm's
`create_account_checkpoint` (so it is `CreatedLocal`), yet rskj's
`TransactionExecutor.create()` explicitly does *not* call `setupContract()` for
it — "if there is no data, then the account is created, but without code nor
storage. It doesn't even call setupContract() to setup a storage root". The
resulting account is `c28000` (nonce 0, balance 0, no code, no storage) with no
storage-prefix cell. The `CREATE`/`CREATE2` *opcodes* always call
`setupContract` (even with empty init code), so only the transaction case is
special.

rustock records these addresses in `ContractMarkers::skip_created` during the
transaction loop (`executor.rs`: when `tx.to.is_empty() && tx.input.is_empty()`
and the tx succeeds) and excludes them in the marker test. This requires the
created address, computed with the standard scheme
`keccak(rlp([sender, nonce]))[12:]` (`extract_created_address`). That helper
was originally a stub returning `None`, so the skip never fired and 13 such
accounts kept spurious markers at \#1,590,999; computing the real address closes
the gap. Ground truth: the canonical CREATE vector (sender `0x6ac7…dbf0`,
nonce 0 → `0xcd23…cd8d`).

---

## 11. Bridge UTXO and Lock-Whitelist Serialization Order

Two byte-exact Bridge-storage incompatibilities surfaced by diffing rustock's
mainnet unitrie against rskj's at #1,590,999 (same entries, different bytes):

### 11a. Federation UTXO BTC tx-hash byte order

`UTXO.serializeToStream` writes `hash.getBytes()`. In bitcoinj a transaction's
hash is a `Sha256Hash.wrapReversed(...)`, so `getBytes()` is already in *display*
(reversed) order. rustock keeps `tx_hash` in display order
(`btc_txid_event_bytes`), but `serialize_utxo` reversed it again to internal
order before storing — byte-diverging every `newFederationBtcUTXOs` entry. Fix:
store `tx_hash` as-is (and read it as-is on deserialize). In-memory semantics are
unchanged; only the stored bytes are corrected.
(`crates/execution/src/bridge/storage.rs`).

### 11b. Lock-whitelist entries are sorted by hash160, not Java HashMap order

rskj's `LockWhitelist` holds its entries in a
`SortedMap<Address, LockWhitelistEntry>` — a `TreeMap` ordered by
`Comparator.comparing(Address::getHash160, UnsignedBytes.lexicographicalComparator())`.
So `serializeOneOffLockWhitelist` and `serializeUnlimitedLockWhitelist` emit
addresses sorted by their 20-byte hash160 ascending, independent of insertion
order. rustock had (mis)reproduced this as Java *HashMap* bucket order; that only
happened to match the 2-entry #3304 groundtruth (where sorted and HashMap order
coincide). The 7- and 17-entry whitelist cells at #1,590,999 are plainly sorted.
Fix: sort entries by hash160 ascending in both serializers; the Java-HashMap
bucket-order helpers were removed. (`crates/execution/src/bridge/storage.rs`,
superseding the approach in commit `a75a432`).

---

## 12. REMASC `brokenSelectionRule` Cell Written via `addStorageBytes`

`RemascStorageProvider.saveBrokenSelectionRule` writes the flag with
`addStorageBytes(REMASC, "brokenSelectionRule", new byte[]{0|1})` — a literal
single byte — on every `save()` once the field has been set
(`Remasc.processMinersFees`: `setBrokenSelectionRule(!siblings.isEmpty() && broken)`).
So the cell is present in the unitrie even when the rule is *not* broken
(value `0x00`), exactly like the `siblings` cell.

rustock stored it with a plain SSTORE of `0`/`1`. SSTORE of `0` writes no trie
cell (zero is the absence of a slot), so the `brokenSelectionRule = 00` cell was
missing from rustock's unitrie at #1,590,999. Fixed by writing it through the
raw-storage (`addStorageBytes`) overlay as a 1-byte value, matching the REMASC
`siblings` handling (`crates/execution/src/remasc.rs`). The cross-block read
(`getBrokenSelectionRule`) still works: a stored `00`/`01` byte reads back as
`0`/`1` through the normal storage path.

---

## 13. Zero-Value REMASC Payment Creates the Recipient

`RemascFeesPayer.transferPayment` (`co.rsk.remasc`) pays a miner with:

```java
this.repository.addBalance(contractAddress, value.negate());
this.repository.addBalance(toAddress, value);
```

`MutableRepository.addBalance` always calls `getAccountStateOrCreateNew`, so a
payment of `value == 0` still **creates** the recipient account; under RSK's
frontier rules that empty account (nonce 0, balance 0, no code, no marker)
persists in the unitrie. There is no zero-guard.

rustock's `remasc_transfer` short-circuited `amount.is_zero()` and returned
without touching the recipient, so miners paid a 0 REMASC reward were absent
from rustock's unitrie. Ground truth: two such beneficiaries (e.g. the miner of
block #142,347) exist as empty accounts in rskj at #1,590,999 but were missing
from rustock. Fix: on a zero amount, `load_account` + `touch_account` the
recipient so revm materialises the empty account exactly as rskj does
(`crates/execution/src/remasc.rs`). The frontier materialisation relies on the
journal spec being pinned pre-Spurious-Dragon (`RskHandler::load_accounts` →
`HOMESTEAD`), and the empty account correctly gets no storage-prefix marker
(see §10).

---

## 14. RSKIP123 Multikey Federation Serialization (wasabi)

Before RSKIP123 (wasabi, #1,591,000) the Bridge serializes a federation with
`serializeFederationOnlyBtcKeys`: each member is its 33-byte compressed BTC
key. From wasabi on, `FederationStorageProviderImpl.saveNewFederation`
switches to `serializeFederation`, where each member is
`RLP[btcKey, rskKey, mstKey]` (`FederationMember.serialize`), wrapped as an RLP
element inside the member list. For the legacy genesis federation, members
carry only a BTC key, so `rsk = mst = btc`
(`FederationMember.getFederationMemberFromKey`) — three identical keys per
member. It also persists `newFederationFormatVersion = 1000`
(`STANDARD_MULTISIG_FEDERATION`, via `serializeInteger` → `0x8203e8`). Member
order is `BTC_RSK_MST_PUBKEYS_COMPARATOR`, which for legacy members reduces to
BTC-key byte order (identical to the only-BTC ordering).

Crucially, rskj's `BridgeStorageProvider.save()` runs at the end of *every*
Bridge transaction and re-serializes the active federation **if the call loaded
it**. So the first post-wasabi Bridge tx that loads the federation migrates the
stored `newFederation` cell in place (and creates the format-version cell). On
mainnet that is #1,591,009's `updateCollections` (blocks #1,591,000–008 carried
no federation-loading Bridge tx). The value is stable thereafter.

rustock wrote only the legacy single-key format and never the format-version
cell, diverging at #1,591,009 (the first block whose state root is checked
*and* whose Bridge state changes). Fix (`crates/execution/src/bridge/`):
`serialize_federation_multikey` (federation.rs), a version-aware
`load_stored_federation` that auto-detects multikey members (so getters keep
reading the BTC key after migration), and `save_new_federation_multikey` called
from `update_collections` (peg.rs). Ground-truthed against rskj's
#1,591,008→#1,591,009 `newFederation` bytes. The broader gap — *every*
federation-loading Bridge method re-serializes on save in rskj — is harmless
once migrated (the value is idempotent), but if a future block's first
fed-loading Bridge tx is *not* `updateCollections`, extend the trigger there.

---

## 15. RSKIP125 Created-Contract Nonce (wasabi)

rskj has no EIP-161, so before wasabi a freshly created contract keeps nonce 0.
From RSKIP125 (wasabi, #1,591,000) on, `Program.createContract` calls
`increaseNonce(contractAddress)` after `createAccount`, so a contract created by
the **CREATE/CREATE2 opcode** starts at nonce 1. A top-level CREATE
*transaction* is unaffected: `TransactionExecutor.create` only does
`createAccount` (and `setupContract` for non-empty data) — it never bumps the
nonce, at any era (see §10a).

revm seeds a created account's nonce to 1 from the per-era `CfgEnv` spec, so
`RskHandler` reset it to 0 to reproduce rskj's frontier behavior. That reset is
correct for the top-level tx frame (always) and for every create pre-wasabi, but
post-RSKIP125 an internal create must keep nonce 1. Fix
(`crates/execution/src/rsk_handler.rs`): the first (transaction) create frame is
always set to 0; internal create frames are set to `1` when RSKIP125 is active,
`0` otherwise (`has_rskip125`, threaded via `RskHandler::with_rskip125`). The
address a contract derives for a sub-CREATE is unchanged — it uses the nonce
*before* the bump — so only the stored nonce differs.

Diverged at mainnet #1,613,128: a `transferAndCall` (ERC677) callback ran an
internal CREATE that deployed an empty contract; rskj stored it as nonce 1
(`c20100`), rustock as nonce 0 (`c28000`) — the only differing unitrie cell.

---

## 16. Pre-RSKIP150 Unbounded Precompile Output Write (gas-free memory extension)

**rskj behavior**: before RSKIP150 ("twoToThree", mainnet 2,018,000 / testnet
504,000), an internal CALL-family invocation of a precompile saves the
precompile's FULL output into the caller's memory at the CALL's outOffs,
ignoring the declared outSize (`Program.callToPrecompiledAddress` →
`saveOutAfterExecution` → `Program.memorySave(outOffs, out)`; the limited
`memorySaveLimited(outOffs, out, outSize)` only arrives with RSKIP150). The
write goes through `Memory.write(..., limited=false)` → `Memory.extend`,
which silently grows the gas-visible memory size (`softSize`, word-aligned)
WITHOUT charging expansion gas — so every later memory expansion in the
caller is measured from the extended size, and MSIZE reports it.

**Trigger**: mainnet #1,661,324 — a Solidity 0.5 proxy (0xEDD695…4080)
forwards `getCoinbaseAddress(int256)` to the BlockHeaderContract precompile
(0x01000010) with outSize=0 and then ABI-decodes via RETURNDATACOPY. rskj's
hidden 96-byte write extends memory from 0xc0 to 0xe0 for free, so the
RETURNDATACOPY pays no expansion; rustock charged +3 gas per call (89 calls
= +267 on the block's gasUsed, computed 1,025,939 vs header 1,025,672).
Ground-truthed against rskj's own per-opcode dump (`dump.block` config +
`ExecuteBlocks` on a clone of a synced DB): after the fix the entire
54,742-opcode trace (pc/opcode/gas) is byte-identical.

**rskj source**: `org.ethereum.vm.program.Program#callToPrecompiledAddress`,
`#saveOutAfterExecution` (`@Deprecated executePrecompiled`, pre-RSKIP197
path), `org.ethereum.vm.program.Memory#write/#extend`.

**rustock**: `RskHandler::run_exec_loop` captures successful precompile call
results (frame-less `frame_init` returns) and, pre-RSKIP150, replays the
unbounded write via `write_unbounded_precompile_output` (resize +
`MemoryGas::set_words_num` with no charge). The CALL instructions preserve
the REAL outOffs for zero-size out regions (`rsk_memory_input_and_out_ranges`
in `rsk_instructions.rs`; revm substitutes a `usize::MAX` sentinel).
`RskNetworkUpgrade::TwoToThree` + `has_rskip150` gate it. Note: on testnet
rskj activates twoToThree (504,000) BEFORE wasabi (863,000); the linear
upgrade ladder models it as wasabi-coincident (RSKIP150 missing only in the
testnet 504k–863k window).

**Related edge (not implemented, in TODO)**: pre-RSKIP150 a precompile
returning Java `null` (e.g. Bridge void methods via internal CALL) makes
`memorySave` throw an NPE that fails the calling frame with all its gas;
rustock's precompiles return empty bytes instead. No mainnet block hit this
so far (direct precompile transactions don't go through this path).

---

## 17. BlockHeaderContract `getGasLimit` Returns Raw Header Bytes

**rskj behavior**: `GetGasLimit.internalExecute` returns
`block.getGasLimit()` — the header's raw RLP element bytes (minimal unsigned
big-endian) — while the other numeric methods (`getMinGasPrice`,
`getDifficulty`, `getGasUsed`) return `BigInteger.toByteArray()` (signed,
0x00-prefixed when the high bit is set).

**rskj source**: `co.rsk.pcc.blockheader.GetGasLimit`.

**rustock**: `u256_to_raw_minimal_bytes` in `precompiles.rs` (vs
`u256_to_java_bigint_bytes` for the BigInteger fields). Indistinguishable
while mainnet gas limits keep the top byte < 0x80 (6.8M = 0x67C280), but a
10M (0x989680) limit would have diverged.

---

## 18. ethereumj ABI: Empty `bytes` Pads to One Full Zero Word

**rskj behavior**: native contracts encode return values with ethereumj's
`SolidityType.BytesType.encode`, which pads with `((len - 1) / 32 + 1) * 32`
bytes. Java integer division gives `-1/32 == 0`, so an EMPTY byte array pads
to 32 zero bytes: the ABI encoding of empty `bytes` is 96 bytes
(offset + length=0 + one zero word), not the canonical 64.

**Trigger**: mainnet #1,669,062 — `getCoinbaseAddress(4000)` hits
BlockHeaderContract's `MAX_DEPTH` bound (`BlockAccessor.getBlock`:
`depth >= 4000 → Optional.empty`) and returns the empty result. The caller's
RETURNDATACOPY copies 3 words in rskj vs 2 in rustock: −3 gas (header
3,013,192 vs computed 3,013,189). After the fix the full 176,338-opcode
trace is byte-identical to rskj's.

**rskj source**: `org.ethereum.solidity.SolidityType.BytesType#encode`.

**rustock**: `abi_encode_bytes` in `precompiles.rs` (used by the
BlockHeaderContract and HDWalletUtils result paths). The bridge's separate
encoders still encode canonically; no current bridge method/event emits
empty dynamic bytes (TODO note to audit if one ever does).

---

## 19. RSKIP123 Federation-Change Storage (format-version cells, multikey members)

**rskj behavior**: once RSKIP123 (wasabi, mainnet #1,591,000) is active,
`BridgeStorageProvider`'s save path writes a format-version cell
(`RLP(1000)` = `0x8203e8`, `STANDARD_MULTISIG_FEDERATION`) next to each
federation cell it saves:

- `savePendingFederation` writes `pendingFederationFormatVersion` on EVERY
  save — including the saves that CLEAR the pending federation
  (`commitFederation` / `rollbackFederation` set it to null, which deletes
  the data cell but still writes the version cell). The flag-based dirty
  tracking (`shouldSavePendingFederation`) means any `setPendingFederation`
  call triggers it.
- `saveNewFederation` / `saveOldFederation` write
  `newFederationFormatVersion` / `oldFederationFormatVersion`. The old-
  federation version cell is written even when the old federation is being
  cleared at migration end (`getOldFederationFormatVersion` defaults to 1000
  for null).

Serialization formats (all members carry compressed btc/rsk/mst keys,
sorted by `FederationMember.BTC_RSK_MST_PUBKEYS_COMPARATOR`):

- Federation (new/old): `RLP[time, block, RLP[elem(RLP[btc,rsk,mst])...]]` —
  each member's RLP list is wrapped as an RLP *element*.
- Pending federation: `RLP[RLP[btc,rsk,mst]...]` — member lists embedded
  DIRECTLY in the outer list (no element wrap), an asymmetry between
  `serializeFederation` and `serializePendingFederation`.
- `PendingFederation.getHash()` is keccak over the SORTED-BTC-KEYS
  serialization (`serializePendingFederationOnlyBtcKeys`) at every era —
  even when the stored bytes are multikey.

Also: `Bridge.addFederatorPublicKeyMultikey` puts the three RAW argument
byte arrays into the vote's `ABICallSpec` (the stored election serializes
them verbatim); key parsing happens at vote-execution time, and any parse
failure is `BridgeIllegalArgumentException` → -10. `rollbackFederation`
clears the WHOLE election on success (like create/commit), not just the
winning entry.

**Trigger**: mainnet #2,132,960 — the 2019 federation change starts with a
winning `createFederation()` vote. rskj writes the empty pending federation
(`0xc0`) AND `pendingFederationFormatVersion = 0x8203e8`; rustock wrote only
the former: state root mismatch with exact gas match (84,501). Found by
unitrie leaf-diff vs the synced rskj DB (single extra leaf), and the
executing method identified by re-running the block under rskj
`ExecuteBlocks` with TRACE logging (`TRACE [bridge] createFederation` —
selector 0x1183d5d1 is createFederation, not updateCollections).

**rskj source**: `co.rsk.peg.BridgeStorageProvider` (Wasabi-era;
`FederationStorageProviderImpl` in modern rskj),
`BridgeSerializationUtils`, `PendingFederation`, `BridgeSupport
.commitFederation/rollbackFederation`, `Bridge.addFederatorPublicKeyMultikey`.

**rustock**: `bridge/federation.rs` (`StoredMember` triplets,
`serialize_federation_multikey`), `bridge/governance.rs`
(`store_pending_federation`, `serialize_pending_federation_multikey`,
3-arg add-multi votes, rollback election clear, multikey commit),
`bridge/peg.rs` (old-federation version cell at migration end).

---

## 20. RSKIP134 Locking Cap (lazy initialization + peg-in gate)

Post-papyrus200 (RSKIP134, mainnet #2,392,700) the Bridge enforces a peg-in
locking cap, with consensus-visible storage semantics:

- **Lazy initialization**: `BridgeSupport.getLockingCap()` initializes the
  cap to `bridgeConstants.getInitialLockingCap()` (mainnet 300 BTC =
  30,000,000,000 sat; testnet 200 BTC; regtest 1,000 BTC) the FIRST time it
  is read with no stored value, and the provider persists it on the bridge
  save (`saveLockingCap`, `serializeCoin` → RLP scalar `0x8506fc23ac00`).
  Reads happen from the peg-in gate, from `increaseLockingCap`, and from
  the (local-only) `getLockingCap` method — so the first mainnet peg-in
  after papyrus200 materializes the `lockingCap` cell.
- **Peg-in gate**: `verifyLockDoesNotSurpassLockingCap` runs only when the
  whitelist check passed (`&&` short-circuit — a whitelist rejection never
  initializes the cap). Federation current funds = `maxRbtc` (21M BTC) −
  Bridge contract balance (truncating wei→satoshi); if funds + amount
  exceed the cap, the peg-in is refunded via the same
  `generateRejectionRelease` as a whitelist rejection.
- **increaseLockingCap**: value ≤ 0 or not a long →
  `BridgeIllegalArgumentException` (tx fails post-RSKIP88); then authorizer
  check (minimum ONE of the increase-locking-cap keys) BEFORE any cap read
  — an unauthorized call does not initialize the cell; then the new cap
  must be ≥ current (equal allowed) and ≤ current ×
  `lockingCapIncrementsMultiplier` (2). A failed bound check still
  persists the lazily-initialized value.

**Trigger**: mainnet #2,395,450 — first peg-in after papyrus200. rskj wrote
`lockingCap = RLP(30_000_000_000)`; rustock had no locking-cap layer in the
peg-in path: state root mismatch with exact gas match (216,376), single
missing unitrie leaf.

**rskj source**: `co.rsk.peg.BridgeSupport.getLockingCap/increaseLockingCap/
verifyLockDoesNotSurpassLockingCap/getBtcLockedInFederation`,
`BridgeStorageProvider.saveLockingCap` (PAPYRUS-2.0.0),
`BridgeMainNetConstants` (initialLockingCap, increaseLockingCapAuthorizer).

**rustock**: `bridge/peg.rs` (`get_or_init_locking_cap`,
`verify_lock_does_not_surpass_locking_cap`, gate in
`register_btc_transaction`), `bridge/governance.rs`
(`increase_locking_cap`), `bridge/getters.rs` (`get_locking_cap`),
`bridge/constants.rs` (locking-cap constants per network).

---

## 21. RSKIP146 Pegout-Set Split Cells (one set, two storage cells)

Post-RSKIP146 (papyrus200) rskj keeps ONE in-memory
`ReleaseTransactionSet` but persists it across TWO bridge storage cells,
split by whether each entry carries a requesting RSK tx hash:

- `releaseTransactionSet` (legacy): `getEntriesWithoutHash()` only, pair
  format `[btc_tx_raw, block_number]`.
- `releaseTransactionSetWithTxHash`: `getEntriesWithHash()` only, triple
  format `[btc_tx_raw, block_number, rsk_tx_hash]`.

`getReleaseTransactionSet` loads BOTH cells into the one set;
`saveReleaseTransactionSet` writes BOTH cells on every save (each sorted by
serialized BTC tx bytes). Post-RSKIP146, every new entry carries a hash —
new pegouts land in the with-txhash cell while the legacy cell is
re-written as the empty list `0xc0`. The same load-merge/save-split applies
to the release request queue (`releaseRequestQueue` /
`releaseRequestQueueWithTxHash`).

Entry hash sources (all post-RSKIP146, with `logReleaseBtcRequested`):
- `updateCollections` pegout creation: the updateCollections RSK tx hash.
- `generateRejectionRelease` (whitelist/cap-rejected peg-in refund): the
  `registerBtcTransaction` RSK tx hash.
- `processFundsMigration`: the updateCollections RSK tx hash, with the
  release_requested amount = sum of the selected (spent) UTXO values.

**Trigger**: mainnet #2,421,462 — the first pegout created after
papyrus200. rustock wrote the new (hash-bearing) entry into the LEGACY cell
and left the with-txhash cell empty; rskj has them exactly swapped. Exact
gas match (69,280), two-leaf unitrie diff (same payload, wrong cell).

**rskj source**: `co.rsk.peg.BridgeStorageProvider
.getReleaseTransactionSet/saveReleaseTransactionSet`,
`BridgeSerializationUtils.serializeReleaseTransactionSet[WithTxHash]`
(getEntriesWithoutHash/getEntriesWithHash split),
`BridgeSupport.generateRejectionRelease/processFundsMigration`
(PAPYRUS-2.0.0).

**rustock**: `bridge/peg.rs` (`load_pegout_confirmation_set` /
`store_pegout_confirmation_set`, used by updateCollections pegout creation
+ confirmation promotion, peg-in rejection refunds, funds migration;
rejection and migration entries now carry the RSK tx hash and log
release_requested).

---

## 22. Election Spec Ordering: SIGNED-byte comparison of getEncoded()

`BridgeSerializationUtils.serializeElection` sorts the vote specs with
`ABICallSpec.byBytesComparator`, which is Guava
`SignedBytes.lexicographicalComparator()` over `ABICallSpec.getEncoded()`:

- **getEncoded() is NOT the RLP serialization** — it is the raw
  concatenation of the function-name UTF-8 bytes and each argument's raw
  bytes.
- **Bytes compare as SIGNED Java bytes**: 0x80–0xff are negative and sort
  BEFORE 0x00–0x7f. A compressed pubkey arg starting `03b6...` sorts before
  `0325...` and `0372...` — the opposite of unsigned order.

Voters within an entry sort by *unsigned* lexicographic order
(`RskAddress.LEXICOGRAPHICAL_COMPARATOR`, Guava UnsignedBytes) — the two
comparators differ on purpose.

This applies to both elections: `federationElection` and
`feePerKbElection` (spec encoded = `"setFeePerKb" || serializeCoin(fee)`).

**Trigger**: mainnet #2,426,416 — the third concurrent add-multi vote of
the 2019 federation change introduced a member key whose second byte was
0xb6 (negative as i8). rustock sorted the three specs unsigned (25, 72,
b6); rskj signed (b6, 25, 72): same entries, same lengths, different
order, one-leaf state-root divergence with exact gas match (156,016).

**rskj source**: `co.rsk.peg.ABICallSpec.byBytesComparator/getEncoded`,
`BridgeSerializationUtils.serializeElection/serializeVoters`
(PAPYRUS-2.0.0; unchanged in modern rskj).

**rustock**: `bridge/vote.rs` (`signed_bytes_cmp`, `AbiCallSpec::encoded`,
`Election::to_bytes`), `bridge/governance.rs`
(`store_fee_per_kb_election`). Byte-exact groundtruth test from the
mainnet cell: `rskj_election_signed_byte_spec_order_groundtruth_2426416`.

---

## 23. RSKIP146 commit_federation Event (Solidity format)

Post-RSKIP146, `BridgeEventLoggerImpl.logCommitFederation` emits the
Solidity-format event instead of the legacy padded-string-topic one:

- Signature `commit_federation(bytes,string,bytes,string,int256)`, topic
  `0x5b9466a0b50d1cab12eeb0b3b5d387ece7659afcc56bb15704535e6954de8c4e`,
  no indexed params.
- Data (standard ABI): old federation's sorted compressed BTC pubkeys
  flat-concatenated as one `bytes`, old federation Base58Check P2SH
  address as `string`, the same pair for the new federation, and the
  activation height (`block + federationActivationAge`) as `int256`.

**Trigger**: mainnet #2,426,478 — the commitFederation of the 2019
federation change. rustock emitted the legacy RLP event; receipts root
mismatched with exact gas (62,032) and exact state root (the storage side
of the commit was already correct).

**rskj source**: `co.rsk.peg.utils.BridgeEventLoggerImpl
.logCommitFederation/logCommitFederationInSolidityFormat`,
`BridgeEvents.COMMIT_FEDERATION` (PAPYRUS-2.0.0).

**rustock**: `bridge/events.rs` (`log_solidity_commit_federation`,
`commit_federation_event_data` with byte-exact mainnet groundtruth test),
`bridge/governance.rs` (`commit_pending_federation` gates legacy vs
Solidity on RSKIP146; `p2sh_base58_address`).

---

## 24. RSKIP151/152: SELFBALANCE and CHAINID at papyrus200 (no Istanbul repricing)

RSK activates the two Istanbul opcodes individually at papyrus200 —
RSKIP152 CHAINID (0x46, BASE tier = 2 gas) and RSKIP151 SELFBALANCE
(0x47, LOW tier = 5 gas) — WITHOUT adopting the rest of Istanbul (no
EIP-1884 repricing, no EIP-2200 SSTORE metering). rustock keeps the revm
SpecId at PETERSBURG for papyrus, so revm's spec-checked `chainid`/
`selfbalance` impls halted `NotActivated`; rskj executed them fine.
Before papyrus200 both opcodes are invalid in rskj (`invalidOpCode`,
consuming all frame gas), whereas revm's NotActivated halt returns the
frame's remaining gas — both directions needed custom instructions.

**Trigger**: mainnet #2,430,894 — a CREATE2-deployed contract using
CHAINID/SELFBALANCE; rustock failed the tx consuming the full 353,934 gas
limit (rskj: success, 235,956).

**rskj source**: `org.ethereum.vm.VM` (OP_CHAINID gated on RSKIP152,
OP_SELFBALANCE on RSKIP151), `OpCode.java` (CHAINID BASE_TIER,
SELFBALANCE LOW_TIER), `reference.conf` (rskip151/152 = papyrus200).

**rustock**: `rsk_instructions.rs` (`rsk_chainid`/`rsk_selfbalance`
uncheck-ed impls installed when `has_chainid`; `invalid_opcode` installed
before papyrus), `executor.rs` install sites + regression test
`test_chainid_selfbalance_activate_at_papyrus`.

---

## 25. addSignature: redeem-script membership gates application (not the event)

In `BridgeSupport.processSigning`, a federator's signatures are verified
against the federator's OWN public key — membership in the *federation*
admits the call, but only membership in the input's *redeem script*
admits the insertion: `Script.getSigInsertionIndex` →
`findKeyInRedeem` throws `IllegalStateException` when the key is not
among the redeem keys, and processSigning catches it ("a member of the
active federation is trying to sign a tx of the retiring one") and
returns. Crucially the `add_signature` event was already emitted before
verification (pre-RSKIP326), so an ineffective vote is
indistinguishable from an effective one in the logs of that tx.

The mid-loop return also means inputs signed in earlier iterations of
the same call KEEP their signatures (the cached BtcTransaction was
mutated in place and is persisted by the provider save).

**Trigger**: mainnet #2,448,984 — the first funds-migration pegout of
the 2019 federation change being signed. tx[4]'s federator is a
new-federation-only member; its signature verifies against its own key
but its key is not in the old federation's 5-of-9 redeem script. rskj
skipped the insertion (completing the pegout at tx[5]); rustock's
`sig_insertion_index` returned a fallback index and inserted it,
completing at tx[4] with a foreign signature — receipts root mismatch
(`release_btc` one tx early), exact gas.

**rskj source**: `co.rsk.peg.BridgeSupport.processSigning`
(PAPYRUS-2.0.0), `co.rsk.bitcoinj.script.Script.getSigInsertionIndex/
findKeyInRedeem`.

**rustock**: `bridge/peg.rs` `apply_signatures_to_tx` (redeem-membership
gate per input, returning with earlier inputs kept), regression test
`add_signature_rejects_key_not_in_redeem_script`.

---

## 26. returnDataBuffer survives calls that execute nothing (no EIP-211 clear)

rskj's `Program` resets the caller's `returnDataBuffer` only inside
`executeCode` (the callee HAS code), inside `callToPrecompiledAddress`,
and inside `getProgramResult` (CREATE with the init actually attempted).
A CALL-family op that resolves WITHOUT running anything — empty-code
callee (plain value transfer), call-depth limit, insufficient endowment
— returns early and leaves the PREVIOUS call's return data in the
buffer. Canonical EVM (EIP-211) clears the buffer on every call-family
instruction. The same applies to CREATE's depth/endowment pre-checks.

So in rskj, `RETURNDATASIZE`/`RETURNDATACOPY` after a value transfer to
an EOA still see the prior call's output — and Solidity's generated
`call(...)` return-value handling (`if returndatasize == expected`)
takes the OTHER branch.

**Trigger**: mainnet #2,669,886 — a Uniswap-style router's
addLiquidityETH ends with a dust refund (`to.call{value}("")` to an
EOA); the following RETURNDATASIZE check saw 0 in rustock vs 32 (the
prior mint() output) in rskj: −76 gas from the divergent branch, same
logs, receipts+state root mismatch via cumulative gas/fees only.
Diagnosed with the per-opcode oracle (first divergence: one JUMPI taking
different branches at equal gas).

**rskj source**: `org.ethereum.vm.program.Program.callToAddress`
(empty-code path commits without touching the buffer) /
`executeCode`/`callToPrecompiledAddress`/`getProgramResult`
(PAPYRUS-2.0.0; unchanged in modern rskj).

**rustock**: `rsk_handler.rs` `run_exec_loop` — when `frame_init`
resolves a Call without creating a frame and the callee is not an
active precompile (or a Create fails its depth/endowment pre-checks),
the caller's return buffer is snapshotted and restored after
`frame_return_result` undoes revm's EIP-211 clear. Regression test
`test_empty_code_call_preserves_return_data_buffer`.

---

## 27. RSKIP150: EVM call-stack limit is 400 (not 1024)

From RSKIP150 (twoToThree, mainnet #2,018,000) rskj's
`Program.getMaxDepth()` returns 400 (1024 before). The deep checks in
`callToAddress`, `callToPrecompiledAddress` and `createContract` push 0,
refund the requested child gas, and return — before any
returnDataBuffer reset, so the buffer is preserved (§26).

revm hard-codes `CALL_STACK_LIMIT = 1024`, so unbounded recursion runs
~2.5× deeper and burns correspondingly more gas before hitting the
ceiling.

**Trigger**: mainnet #2,814,761 — a factory tx recursing ~1,046
gas/frame. rskj cut it off at depth 400 (tx FAILED at 550,834 gas);
rustock recursed past 700 frames and consumed the full 826,251 limit.

**rskj source**: `org.ethereum.vm.program.Program.getMaxDepth/
callToAddress/createContract` (gated on RSKIP150).

**rustock**: `rsk_handler.rs` `run_exec_loop` — a FrameInit with depth >
400 (when RSKIP150 is active) is answered with a synthesized CallTooDeep
outcome (full child-gas refund, return buffer preserved) instead of
being initialized. Regression test
`test_rskip150_call_depth_capped_at_400` (recursion counter stops at
401 frames). Pre-RSKIP150 blocks keep revm's 1024.

---

## 28. RSKIP143 BtcLockSender: peg-in sender types (processable vs lockable)

rskj classifies a peg-in's sender from the FIRST input via
`BtcLockSenderProvider` (P2PKH → P2SH-P2WPKH → P2SH-MULTISIG →
P2SH-P2WSH, first match wins), then applies two distinct gates:

- `txIsProcessable`: P2PKH always; everything else only post-RSKIP143
  (papyrus200). Unparseable/unprocessable → plain return, tx NOT marked
  as processed.
- `txIsLockable`: P2PKH and (post-RSKIP143) P2SH-P2WPKH. A processable
  but non-lockable sender (P2SH-MULTISIG, P2SH-P2WSH) is refunded via
  `generateRejectionRelease` ("tx type not supported") WITHOUT
  consulting the whitelist or locking cap, then marked processed.

The sender's BTC address (whitelist key, refund output) is the P2SH
script hash for the P2SH variants — the refund output is a P2SH script,
not P2PKH. Parser details: P2PKH = scriptSig `[sig, valid pubkey]`;
P2SH-P2WPKH = 1-chunk scriptSig + 2-push witness with compressed pubkey,
address = hash160(0x0014||hash160(pubkey)); P2SH-MULTISIG = scriptSig
`[.., sigs.., multisig redeem]`, address = hash160(redeem); P2SH-P2WSH =
1-chunk scriptSig + ≥3-push witness ending in a multisig redeem, address
= hash160(0x0020||sha256(redeem)).

**Trigger**: mainnet #2,851,909 tx 2 — a P2SH-multisig peg-in of ~19.7
BTC. rskj refunded it (rejection entry in the with-txhash pegout set +
processed mark + release_requested); rustock's P2PKH-only parser bailed
without doing anything: two-leaf state diff + missing event.

**rskj source**: `co.rsk.peg.btcLockSender.*` (PAPYRUS-2.0.0),
`BridgeUtils.txIsProcessable`, `BridgeSupport.txIsLockable/
registerBtcTransaction`.

**rustock**: `bridge/peg.rs` (`PeginSender`, `classify_pegin_sender`,
`is_sent_to_multisig`, lockable/processable gates, P2SH refunds,
`sender_base58_address` for the lock_btc event).

---

## 29. Pegout dusty-change surplus is burned to 0xff…ff

When bitcoinj's `completeTx` (recipientsPayFees) finds the pegout's
change output below the non-dust minimum (`3 × 5000 × (outputLen+148) /
1000`, 2,700 sat for the federation P2SH), it raises the change to that
minimum and deducts the difference from the recipient output. The
federation then spends LESS BTC than the user pegged out, so rskj's
`adjustBalancesIfChangeOutputWasDust` — unconditional since the genesis
bridge — burns the surplus: `transferTo(BURN_ADDRESS, …)` moves
`sentByUser − (sumInputs − change)` (satoshis × 10^10 wei) from the
Bridge account to `0xffffffffffffffffffffffffffffffffffffffff`
(`BridgeSupport.BURN_ADDRESS`), creating that account on first use.

The change amount is read as `getOutput(1)` in the papyrus-era code and
as `getValueSentToMe(wallet)` from the HOP batching refactor; both equal
the value paid back to the federation P2SH script for every reachable
case (individual pegouts have exactly one P2PKH recipient + the change
at index 1).

**Trigger**: mainnet #3,103,055 tx 1 (updateCollections) — a 9,999,400
sat pegout against UTXOs leaving 600 sat of change, raised to 2,700.
rskj burned 2,100 sat (21,000,000,000,000 wei); rustock built the
byte-identical BTC tx (receipts root matched) but skipped the burn:
two-leaf state diff (missing 0xff…ff account + Bridge balance high by
the same amount).

**rskj source**: `co.rsk.peg.BridgeSupport.adjustBalancesIfChangeOutputWasDust`
(called from `processPegoutsIndividually` and, post-RSKIP271,
`processPegoutsInBatch` with the batch's total value).

**rustock**: `bridge/peg.rs` `update_collections` — the `settle` closure
(shared by the individual and batch paths, mirroring rskj's two call
sites) computes the surplus and transfers it from `BRIDGE_ADDR` to
`BURN_ADDR`. Test `update_collections_burns_dusty_change_surplus`
(executor.rs) ports rskj `BridgeSupportIT.callUpdateCollectionsChangeGetsOutOfDust`
(1 BTC request vs 1 BTC + 100 sat UTXO → 2,600 sat burned).

---

## 30. Suicided accounts are deleted per-TRANSACTION, not per-block

rskj deletes a selfdestructed account from the repository at the END of
the destroying transaction: `TransactionExecutor.finalization()` runs
`result.getDeleteAccounts().forEach(address -> track.delete(...))`
against the per-block repository (after the per-tx `cacheTrack` has
committed). A LATER transaction in the same block therefore sees the
address as nonexistent, and under RSK's frontier-forever account rules
(no EIP-158/161, see §"eternal frontier") merely calling or sending 0
value to it re-creates a fresh `(nonce 0, balance 0)` account node via
`addBalance(0)`. Block-end state can thus contain a BRAND-NEW account
at an address destroyed earlier in the same block — with the old code,
storage and storage-prefix marker gone (the delete is recursive over
the whole subtree) but a fresh account leaf present.

revm keeps ONE journal for the whole block: the `SelfDestructed` and
`Touched` status flags are sticky across transactions, and a destroyed
account's info/storage are only wiped lazily on the next cold load
(`JournalInner::load_account_mut_optional`, which clears the *local*
selfdestruct flag but not the global ones). So at block end rustock
could not distinguish "destroyed" from "destroyed, then re-created by a
later tx" — both looked like `SelfDestructed | Touched` and the
re-created account vanished with the delete.

**rustock**: two-part fix.
- `executor.rs` `execute_block`: when a tx commits, every journal entry
  with `is_selfdestructed_locally()` is neutralized eagerly — info and
  storage wiped (exactly what revm's next cold load would do) and the
  `Touched`/local flags cleared. A later tx that touches the address
  re-marks `Touched`.
- `state.rs` `apply_state_changes`: a `SelfDestructed` account always
  gets its subtree recursively deleted first; if it is ALSO `Touched`
  (re-created later in the block) the fresh account state is then
  written on top instead of being skipped.

Edge cases verified: re-creation by zero-value and value-carrying
transfers; selfdestruct in the last tx (plain delete); selfdestruct to
self (balance burned, rskj transfers to itself then deletes); destroy →
CREATE2 re-deploy at the same address → destroy again (the rskj comment
in `TransactionExecutor`: "the remote case there is a CREATE2 creating
a deleted account" — the wiped journal entry must also pass revm's
CREATE2 collision check). The per-tx suicide refund also matches: rskj
grants 24,000 per address in the TX's `deleteAccounts` set
(`TransactionExecutor` `addFutureRefund`), revm keys
`previously_destroyed` off the per-tx local flag, so destroying a
re-created account in a later tx refunds again in both.

**Trigger**: mainnet #3,173,807 — tx 0 selfdestructs
`0xceb1…f1a`, tx 1 calls the same address and re-creates it as a fresh
empty account. rskj's block-end trie has the new `(0,0)` leaf; rustock
deleted it (one-leaf state diff).

**rskj source**: `org.ethereum.core.TransactionExecutor.finalization`
(`track.delete`), `MutableRepository.delete` → `deleteRecursive`.

**rustock**: `crates/execution/src/executor.rs` (post-tx
neutralization), `crates/execution/src/state.rs`
(`apply_state_changes`). Tests: `selfdestruct_then_recreate_in_same_block`,
`selfdestruct_in_last_tx_deletes_account_entirely`,
`selfdestruct_to_self_burns_balance`,
`selfdestruct_recreate_via_create2_then_selfdestruct_again`
(executor.rs), `test_selfdestructed_then_recreated_account_rewritten_fresh`
(state.rs).

---

## 31. Coinbase-information storage key: `Sha256Hash.toString()` does NOT reverse

`registerBtcCoinbaseTransaction` (RSKIP143) stores the witness merkle root
for a BTC block, keyed by that block's hash. rskj derives the storage slot
in `BridgeStorageProvider.getStorageKeyForCoinbaseInformation`:

```java
COINBASE_INFORMATION.getCompoundKey("-", btcTxHash.toString());
// = DataWord.fromLongString("coinbaseInformation-" + blockHash.toString())
```

where `blockHash = Sha256Hash.wrap(args[1])` is built from the raw ABI
`bytes32` argument (`Bridge.registerBtcCoinbaseTransaction`). The consensus
trap is bitcoinj's `Sha256Hash.toString()`: it hex-encodes the wrapped bytes
**verbatim, without reversing** (only `wrapReversed()` and the
double-SHA256 `getHash()` paths reverse). So the storage-key preimage uses
the block-hash arg bytes exactly as passed — which on mainnet are already in
big-endian display order (leading zeros).

This is the opposite of the *processed-BTC-tx-hash* map
(`getStorageKeyForBtcTxHashAlreadyProcessed`), whose `Sha256Hash` is computed
internally (little-endian raw double-SHA256) and whose `toString()` therefore
*does* differ from the raw bytes. rustock models that case with
`btc_hash_hex_display` (reverse-then-hex) — correct there, **wrong** for the
coinbase key, which must hex the arg bytes as-is.

**Consensus-load-bearing:** a from-scratch client that "naturally" reverses
BTC hashes to display order before formatting the key (as one would for a
`Sha256Hash`) computes a *different* storage slot, stores the identical
`CoinbaseInformation` value under the wrong key, and forks — receipts and gas
are unaffected (the Bridge emits no log here pre-RSKIP146), so only the state
root catches it.

**Trigger**: mainnet #3,229,522 — tx 1 `registerBtcCoinbaseTransaction` for
BTC block `0000…0b718fb9…7433fe4`. rustock stored the witness merkle root at
`keccak("coinbaseInformation-" + reverse(arg))`, rskj at
`keccak("coinbaseInformation-" + arg)` — a two-leaf state diff (same value,
wrong slot), gas and receipts identical.

**rskj source**: `co.rsk.peg.Bridge.registerBtcCoinbaseTransaction`
(`Sha256Hash.wrap(args[1])`), `BridgeStorageProvider`
`getStorageKeyForCoinbaseInformation`, `BridgeStorageIndexKey.getCompoundKey`,
bitcoinj `Sha256Hash.toString()`.

**rustock**: `crates/execution/src/bridge/tx.rs` — `set_coinbase_information`
/ `get_coinbase_information` now key with `to_hex(block_hash)` (no reversal).
Test: `coinbase_information_storage_key_mainnet` (byte-exact slot from rskj's
unitrie). The divergence was localized with the new `diff_state` example
(`crates/cli/examples/diff_state.rs`), a hash-pruned dual walk of rustock's
computed trie vs rskj's LevelDB unitrie at the header root.

---

## 32. SegWit peg-ins: wtxid for PMT/merkle, txid (no witness) for the processed map; witness-root read byte order

A SegWit-serialized peg-in carries the BTC marker/flag and a witness stack,
so its raw double-SHA256 (the wtxid) differs from its witness-stripped txid.
rskj uses BOTH hashes, for different purposes, inside one
`registerBtcTransaction`:

```java
// BridgeSupport.registerBtcTransaction
Sha256Hash btcTxHash = BtcTransactionFormatUtils.calculateBtcTxHash(btcTxSerialized);
//   = hashTwice(btcTxSerialized)  -> over the RAW bytes  -> WTXID
...
if (isAlreadyBtcTxHashProcessed(btcTx.getHash(false))) { ... }   // l.404
...
provider.setHeightBtcTxhashAlreadyProcessed(btcTx.getHash(false), rskHeight); // markTxAsProcessed l.763
//   getHash(false)  -> WITNESS-STRIPPED txid
```

- **PMT matching / merkle-root validation** (`validationsForRegisterBtcTransaction`)
  use `calculateBtcTxHash` = the **wtxid**. For a SegWit peg-in the supplied
  PMT proves inclusion in the BTC block's **witness** merkle tree, so the
  matched hash IS the wtxid and the PMT root is the witness merkle root.
- **`btcTxHashesAlreadyProcessed`** is keyed by `getHash(false)` = the
  **legacy txid**. The same legacy txid is what `registerNewUtxos` records as
  the UTXO outpoint.

A from-scratch client that uses a single "the BTC tx hash" everywhere either
never finds the wtxid in the PMT (if it strips the witness for hashing) or
marks/looks up the processed map under the wrong key (if it hashes raw bytes).
Both fork: the first SILENTLY rejects a valid peg-in (no credit, no UTXO, tx
not even marked processed), the state root being the only witness.

A second, coupled trap is the **witness-root fallback byte order** in
`isBlockMerkleRootValid` (RSKIP143): when the PMT root != the block's legacy
merkle root, rskj reads `provider.getCoinbaseInformation(blockHeader.getHash())`
and compares its stored witness merkle root to the PMT root. The coinbase info
is keyed by the block hash in **display** order (§31) and its stored witness
root is also **display** order (`registerBtcCoinbaseTransaction` reverses it
for the commitment, `Sha256Hash.twiceOf(witnessMerkleRoot.getReversedBytes(),
…)`), whereas the PMT root is in **internal** (little-endian) order. The
lookup key and the compared value must therefore both be reversed.

**Trigger**: mainnet #3,231,219 — tx 2 `registerBtcTransaction`, a 2-input
SegWit peg-in of 1,000,001 sat to the active federation
(`a914596cff92…87`). wtxid `cfe2…0897`, txid `124f…9b7e`. rskj locks it
(credits `0xded5…24e6` with `0x2386f4c3cce400` wei, appends UTXO `124f…9b7e`,
writes `btcTxHashesAlreadyProcessed[124f…9b7e] = 0x314df3`); rustock bailed at
"merkle root mismatch" (wrong byte order on the witness-root read) and then,
once that was fixed, would have keyed the processed map by the wtxid. Gas and
receipts are identical (all status=true, total 370427).

**rskj source**: `co.rsk.peg.BridgeSupport.registerBtcTransaction` (l.385,
404, 763), `markTxAsProcessed`, `validationsForRegisterBtcTransaction`,
`isBlockMerkleRootValid` (l.3336), `BtcTransactionFormatUtils.calculateBtcTxHash`,
`co.rsk.peg.Bridge.registerBtcCoinbaseTransaction` (`Sha256Hash.wrap(args[3])`),
`BridgeSupport.validateWitnessInformation` (`getReversedBytes()`).

**rustock**: `crates/execution/src/bridge/tx.rs` — `calculate_btc_tx_hash`
hashes raw bytes (wtxid, for PMT) and the new `legacy_btc_txid` returns the
witness-stripped txid via `compute_txid`. `crates/execution/src/bridge/peg.rs`
— `register_btc_transaction` re-checks the processed map with `legacy_txid`
after parsing and marks all processed entries with it; the witness-root
fallback reverses both the block-hash lookup key and the stored witness root
(same fix mirrored in `register_fast_bridge_btc_transaction`). Tests:
`calculate_btc_tx_hash_legacy_vector` (ported from rskj
`BtcTransactionFormatUtilsTest`) and `segwit_pegin_wtxid_vs_legacy_txid`
(block #3,231,219 ground truth). Verified end-to-end with `diff_state`
(0 diverging leaves, root `0x3a66…f3d8`).

---

## 33. `rskTxsWaitingFS` order: Keccak256 compares bytes from the LAST byte (reverse)

The pegouts-waiting-for-signatures map (`rskTxsWaitingFS`,
`pegoutsWaitingForSignatures`) is a Java `SortedMap<Keccak256, BtcTransaction>`
(a `TreeMap`), and rskj serializes it in iteration order — i.e. sorted by the
`Keccak256` key's natural ordering. The trap is `Keccak256.compareTo`
(`co.rsk.crypto.Keccak256`): it compares the 32 bytes **unsigned, from index 31
down to index 0** — reverse (little-endian) byte order, not the forward
big-endian order you get from comparing a `[u8; 32]` or a `BTreeMap<[u8;32]>`
key directly.

```java
public int compareTo(Keccak256 o) {
    for (int i = HASH_LEN - 1; i >= 0; i--) {
        final int thisByte = this.bytes[i] & 0xff;
        final int otherByte = o.bytes[i] & 0xff;
        if (thisByte > otherByte) return 1;
        if (thisByte < otherByte) return -1;
    }
    return 0;
}
```

So two entries whose hashes order one way big-endian can order the *other* way
under rskj's comparator, producing a different `RLP.encodeList` and a different
storage cell — identical entries, identical bytes, swapped positions.

**Consensus-load-bearing:** a from-scratch client that holds this map in any
forward-ordered structure (sorted set/map over the raw hash, or "I'll just sort
the keys") serializes the entries in the wrong order the moment two waiting
pegouts' request-tx hashes disagree between big- and little-endian ordering, and
forks — gas and receipts are unaffected (the map is internal Bridge state).

**Trigger**: mainnet #3,340,065 (migration window — two pegouts waiting for
signatures). Hashes `285b09…d10c` (last byte `0x0c`) and `12b7dd…baf0` (last
byte `0xf0`): rskj orders `285b09…` first (`0x0c < 0xf0`), rustock's
`BTreeMap<[u8;32]>` ordered `12b7dd…` first (`0x12 < 0x28`). One-leaf state diff,
gas + receipts identical.

**rskj source**: `co.rsk.crypto.Keccak256.compareTo`,
`BridgeSerializationUtils.serializeRskTxsWaitingForSignatures` (iterates the
`SortedMap`), `BridgeStorageProvider` `PEGOUTS_WAITING_FOR_SIGNATURES`.

**rustock**: `crates/execution/src/bridge/peg.rs`
`serialize_rsk_txs_waiting_for_signatures` re-sorts entries by reversed key
bytes (`a.iter().rev().cmp(b.iter().rev())`) before encoding, rather than
trusting the in-memory `BTreeMap`'s forward iteration order. Test:
`rsk_txs_waiting_fs_keccak_reverse_byte_order` (block #3,340,065 ground truth).

---

## 34. Confirmed-pegout selection follows Java `HashSet` iteration order

`updateCollections` → `processConfirmedPegouts` moves *one* confirmed pegout per
call from `pegoutsWaitingForConfirmations` into `pegoutsWaitingForSignatures`.
It picks that entry with
`PegoutsWaitingForConfirmations.getNextPegoutWithEnoughConfirmations`:

```java
return entries.stream()
    .filter(entry -> hasEnoughConfirmations(entry, currentBlockNumber, minimumConfirmations))
    .findFirst();
```

`entries` is a Java `HashSet<Entry>`, so `findFirst()` returns the first
confirmed entry in **`HashSet` iteration order**, not the storage order. The
storage cell is sorted by serialized BTC-tx bytes (`Entry.BTC_TX_COMPARATOR`,
java-compat §21), so a client that selects the first confirmed entry in the
sorted/stored order picks the wrong pegout whenever two confirmed entries share
a creation height (both cross the confirmation threshold on the same block).

`HashSet` iteration walks the backing table's buckets `0 .. table.length`
ascending, and within a bucket in insertion order. The bucket is
`(table.length - 1) & spread(hash)` with `spread(h) = h ^ (h >>> 16)` and

```
hash = Objects.hash(btcTransaction, Long(pegoutCreationRskBlockNumber))
     = 31 * (31 + btcTransaction.hashCode()) + Long.hashCode(height)
```

`btcTransaction.hashCode()` is bitcoinj `Sha256Hash.hashCode()` of the txid: the
last four bytes of the **display-order** hash read big-endian
(`Ints.fromBytes(bytes[28], bytes[29], bytes[30], bytes[31])`).
`Long.hashCode(v) = (int)(v ^ (v >>> 32))`; all of it is signed 32-bit `int`
arithmetic, but the bucket index is a bitwise AND so unsigned `u32` with wrapping
arithmetic reproduces the exact bit pattern.

**Table capacity is the incremental-insertion history, NOT a pre-size from the
final count.** rskj does NOT build the set with `new HashSet<>(collection)`.
`BridgeStorageProvider.getPegoutsWaitingForConfirmations` does
`Set entries = new HashSet<>(deser(legacyCell).getEntries())` (post-RSKIP146 the
legacy cell is `0xc0`, so this is the empty collection → capacity 16) then
`entries.addAll(deser(withTxHashCell).getEntries())` and caches `entries`
directly. `HashSet.addAll` is `AbstractCollection.addAll`, i.e. one `add` per
element; `deserializePegoutsWaitingForConfirmations` likewise adds one-by-one to
a `new HashSet<>()`. So the table starts at capacity 16 and doubles whenever
`size > capacity * 0.75` (`HashMap.putVal`: `if (++size > threshold) resize()`,
`threshold = (int)(cap * 0.75)`). After `n` insertions the capacity is the
smallest power of two `>= 16` with `n <= floor(cap * 0.75)`:

| n        | 0–12 | 13–24 | 25–48 | 49–96 |
|----------|------|-------|-------|-------|
| capacity | 16   | 32    | 64    | 128   |

This differs from the `new HashSet<>(collection)` pre-size formula
`tableSizeFor(max((int)(n/0.75)+1, 16))` exactly at the resize boundaries: at
`n = 12` the pre-size formula gives 32 but the incremental capacity is 16; at
`n = 24` it gives 64 vs 32. A wrong capacity reshuffles every bucket index and
forks the selection. (The #3,345,557 case had `n = 13`, where both formulas give
32, which is why the original pre-size code happened to pass.)

The insertion order into the set is the deserialization order = the stored
`BTC_TX_COMPARATOR` order, which only matters for the intra-bucket tiebreak.
**Latent edge (TODO):** in rskj the SAME cached set object survives the in-block
`add()`s done earlier in the same `updateCollections` (migration/pegout
creation), so its real insertion order is "pre-block entries (deser order) then
in-block adds (add order)". rustock reloads the set from storage between the add
and select steps, re-sorting by `BTC_TX_COMPARATOR`. The final *capacity* is
identical (it depends only on the total count, not the order), so this only
diverges if 2+ entries that confirm on the same block land in the *same* bucket
AND were added in-block in an order differing from `BTC_TX_COMPARATOR` — left
unfixed, logged.

**Consensus-load-bearing:** which BTC pegout transaction is promoted to be
signed (and which is left in the confirmation set) is pure Bridge state — gas
and receipts are unaffected — yet it forks the unitrie. A from-scratch client
that iterates the confirmation set in any natural/sorted order diverges as soon
as two confirmed entries share a creation height.

**Trigger**: mainnet #3,345,557 (migration window). Two entries created at height
3,341,556 both reach 4000 confirmations at this block; their entry hashes land in
`HashSet` buckets 9 (`a7c69a46…:1` input, pegoutCreationRskTxHash `26dc74c8…`)
and 20 (`0260d432…:1` input, `3c218098…`) of the 32-bucket table. rskj promotes
the bucket-9 tx; rustock previously promoted the lexicographically-smaller
bucket-20 tx, producing a one-leaf diff in both `releaseTransactionSetWithTxHash`
and `rskTxsWaitingFS`.

**rskj source**:
`co.rsk.peg.PegoutsWaitingForConfirmations.getNextPegoutWithEnoughConfirmations`
and `Entry.hashCode`; `co.rsk.bitcoinj.core.BtcTransaction.hashCode` /
`Sha256Hash.hashCode`; `co.rsk.peg.BridgeSupport.processConfirmedPegouts`;
`BridgeStorageProvider.getPegoutsWaitingForConfirmations` (`new HashSet<>(…)`).

**rustock**: `crates/execution/src/bridge/peg.rs`
`next_pegout_with_enough_confirmations` / `pegout_entry_hash` (replicate the
bucket order) + `java_hashset_capacity` (incremental-insertion capacity), called
from `process_confirmed_pegouts` (Step 2 of `update_collections`). Tests:
`rskj_next_pegout_hashset_iteration_order_groundtruth` (block #3,345,557 ground
truth), `java_hashset_capacity_resize_boundaries` and
`pegout_selection_at_16_to_32_resize_boundary` (the n=12/13/24/25 capacity
boundaries).

---

## 35. `getCompoundKey` ALWAYS Keccak256-hashes, and `btcBlockHeight` uses the DECIMAL height

The RSKIP199 BTC-best-block-hash-by-height index (`getBtcBestBlockHashByHeight` /
`setBtcBestBlockHashByHeight`) keys its storage cell with

```java
private DataWord getStorageKeyForBtcBlockIndex(Integer height) {
    return BTC_BLOCK_HEIGHT.getCompoundKey("-", height.toString());
}
```

Two implementation details are consensus-load-bearing here:

1. **`getCompoundKey` is unconditionally `fromLongString` (Keccak256).**
   `BridgeStorageIndexKey.getCompoundKey` is
   `DataWord.fromLongString(key + delimiter + identifier)`, and
   `DataWord.fromLongString(s) = valueOf(HashUtil.keccak256(s.getBytes(UTF_8)))`.
   It hashes the concatenated string **regardless of length** — there is no
   `fromString` (right-aligned ASCII) fallback for strings ≤ 32 bytes. The other
   compound keys (`coinbaseInformation-<txhash>`, `btcTxHashAP-<txhash>`,
   `fastBridgeHashUsedInBtcTx-<…>`) all exceed 32 bytes, so a length-conditional
   implementation happened to match them — but `btcBlockHeight-<height>` is short
   (e.g. `"btcBlockHeight-696552"` = 21 bytes), exposing the bug.

2. **The identifier is the DECIMAL height** (`Integer.toString()`), not hex.

So the slot for height 696552 is `keccak256("btcBlockHeight-696552")` =
`0x16237937c05c75734c886e3a18c663be516f8140f821c7e6c277dc78d76e78fd`, NOT the
right-aligned ASCII of `"btcBlockHeight-aa0e8"` (the hex form rustock used).

**Consensus-load-bearing:** the stored value (the BTC block hash) is identical;
only the storage *key* differs, so gas and receipts match while the unitrie
forks. A from-scratch client that (a) right-aligns short compound key strings
like every other Bridge `fromString` key, or (b) formats the height as hex,
diverges the first time this index is written.

**Trigger**: mainnet #3,614,822. The block writes the RSKIP199 index for BTC
height 696552; rustock stored the value under `fromString("btcBlockHeight-aa0e8")`
(hex, ASCII-padded) instead of `fromLongString("btcBlockHeight-696552")`,
producing a two-leaf diff (one absent leaf each side) on the Bridge contract.

**rskj source**: `co.rsk.peg.BridgeStorageProvider.getStorageKeyForBtcBlockIndex`
(`height.toString()`); `co.rsk.peg.BridgeStorageIndexKey.getCompoundKey`
(`DataWord.fromLongString`); `org.ethereum.vm.DataWord.fromLongString`.

**rustock**: `crates/execution/src/bridge/storage.rs` — `compound_key` now always
calls `bridge_storage_key_long` (Keccak256); `bridge_{load,store}_btc_block_hash_by_height`
now format the height with `height.to_string()` (decimal). Tests:
`compound_key_btc_height` (block #3,614,822 slot ground truth) and
`rskj_compound_key_always_keccak`.

---

## 36. RSKIP185: a rejected direct peg-out refunds the sender and logs `release_request_rejected`

A direct RBTC transfer to the Bridge address (empty calldata, non-zero value)
invokes `BridgeSupport.releaseBtc()` → `requestRelease()`. Post-RSKIP219 the
peg-out value must be **≥ `minValue`**, where

```java
Coin requireFundsForFee = feePerKB.multiply(pegoutSize).divide(1000);
requireFundsForFee = requireFundsForFee.add(
    requireFundsForFee.times(minimumPegoutValuePercentageToReceiveAfterFee).divide(100));
Coin minValue = Coin.valueOf(Math.max(minimumPegoutTxValue.value, requireFundsForFee.value));
if (valueToReleaseInSatoshis.isLessThan(minValue)) { /* reject */ }
```

When the value is below `minValue` and **RSKIP185** (Iris300, mainnet
3,614,800) is active, `requestRelease` calls `refundAndEmitRejectEvent`, which:

1. **Refunds** the value back to the sender:
   `rskRepository.transfer(BRIDGE_ADDR, sender, refundValue)`. Pre-RSKIP427 the
   refund is `Coin.fromBitcoin(weis.toBitcoin())` — i.e. the wei amount
   **truncated to satoshi granularity** (`floor(wei/1e10) * 1e10`).
2. **Logs** `release_request_rejected(address indexed sender, uint256 amount,
   int256 reason)`. Pre-RSKIP427 `amount` is in **satoshis**
   (`amountInWeis.toBitcoin().getValue()`); `reason` is the
   `RejectedPegoutReason` enum value: **`LOW_AMOUNT=1`**, `CALLER_CONTRACT=2`,
   **`FEE_ABOVE_VALUE=3`**. The reason is `FEE_ABOVE_VALUE` iff
   `minValue == requireFundsForFee` (the fee estimate is the binding bound),
   else `LOW_AMOUNT`.

Before RSKIP185 the request was silently dropped (no refund, no log; the value
stayed at the Bridge). rustock previously took that silent-drop path
unconditionally, and never computed the fee-based `minValue`/reason.

**Consensus-load-bearing:** gasUsed and tx status are unaffected (the rejection
charges no extra gas, and the net balance change is the same once refunded), so
a from-scratch client that forgets to emit the event forks **only on the
receipts root** (missing log → missing bloom + log entry), while a client that
forgets the refund forks only on the state root. The `pegoutSize`/`feePerKb`
inputs to `minValue` also alter the *reason* value embedded in the log data.

**Trigger**: mainnet #3,615,279 tx 9 — a 10,000-sat (1e14-wei) direct transfer
to the Bridge. 10,000 < 400,000 (`minimumPegoutTxValue`) and the fee-based
estimate at `feePerKb=30,000` is ≈ 1e5 sat (≪ 400,000), so `minValue =
minimumPegoutTxValue` → reason `LOW_AMOUNT`. rustock emitted no log; the
receipts root forked (`0x767c…` vs `0x499b…`) and, downstream of the missing
refund, the state root (`0x9bff…` vs `0xaa20…`).

**rskj source**: `co.rsk.peg.BridgeSupport.releaseBtc` / `requestRelease` /
`refundAndEmitRejectEvent`; `co.rsk.peg.utils.BridgeEventLoggerImpl.logReleaseBtcRequestRejected`;
`co.rsk.peg.utils.RejectedPegoutReason`; `co.rsk.peg.BridgeUtils.getRegularPegoutTxSize`
→ `BridgeUtilsLegacy.calculatePegoutTxSize` (pre-RSKIP271).

**rustock**: `crates/execution/src/bridge/peg.rs` — `release_btc` now computes
`require_funds_for_fee` (via `regular_pegout_tx_size`) and the `minValue`/reason,
and on rejection (RSKIP185+) refunds `amount_satoshis * 1e10` wei and calls
`super::events::log_release_request_rejected`
(`crates/execution/src/bridge/events.rs`). The percentage gap constant
`minimum_pegout_value_percentage_to_receive_after_fee` (mainnet/testnet 80,
regtest 20) was added to `BridgeConstants`. Tests:
`solidity_release_request_rejected_matches_mainnet_3615279` (event topic + data
ground truth), `regular_pegout_tx_size_within_2pct_of_real_tx` (ported from rskj
`BridgeUtilsLegacyTest`), `require_funds_for_fee_below_minimum_pegout_value`.

---

## 37. RSKIP171: a CALL that runs no new frame CLEARS the caller's returnDataBuffer (iris300)

The mirror image of §26. rskj's `Program.cleanReturnDataBuffer` is era-gated:

```java
private void cleanReturnDataBuffer() {
    if (getActivations().isActive(ConsensusRule.RSKIP171)) {
        returnDataBuffer = null; // reset when the call created no new call frame
    }
}
```

It is invoked from every CALL/CREATE path that runs **no new frame** —
`callToAddress` empty-code branch (plain value transfer / call to an EOA) and
insufficient-endowment branch, `createContract` insufficient-funds branch,
`callToPrecompiledAddress` out-of-gas branch:

- **Pre-RSKIP171** (no-op): the *previous* call's return data survives — this
  is the §26 behavior (mainnet #2,669,886): `RETURNDATASIZE` after a no-frame
  call still reports the prior call's size.
- **Post-RSKIP171** (iris300, mainnet **#3,614,800**): the buffer is reset to
  empty, exactly like canonical EVM / EIP-211 — `RETURNDATASIZE` reports 0.

**Consensus-load-bearing.** The call's own gasUsed and status are unaffected,
but the post-call `RETURNDATASIZE`/`RETURNDATACOPY` value steers a contract
down a different branch. A from-scratch client that keeps the §26 preservation
past iris300 forks on the **state and receipts roots** wherever a contract
reads return data after a no-frame call — and may spend a different amount of
gas on the divergent path, even running out of gas where the canonical client
succeeds.

**Trigger.** mainnet **#3,616,094** tx 8 — a DEX router (`0x5a0d867e…`) sends
RBTC change to an EOA (`0x60f096e5…`, empty code) via a value-bearing CALL,
then executes `RETURNDATASIZE` to validate the *prior* WRBTC `transfer()`'s
32-byte output. rustock (still using the §26 preservation) reported size 32
where rskj reported 0, took the wrong branch, overspent ~77 gas and ran the
top-level call **out of gas**, reverting the whole swap. gasUsed and receipts
matched at the originally-reported halt #3,616,195 because the corruption was a
clean revert of all of tx 8's state, surfacing only as a state-root divergence;
the real origin was #3,616,094.

**rskj source.** `org.ethereum.vm.program.Program.cleanReturnDataBuffer`
(called from `callToAddress` / `createContract` / `callToPrecompiledAddress`);
`ConsensusRule.RSKIP171` (reference.conf `rskip171 = iris300`). Ground truth:
`org.ethereum.vm.VMTest.returnDataSizeAfterCallToNonExistentContract`
(active → 0) and `beforeIrisReturnDataSizeAfterCallToNonExistentContract`
(inactive → 32).

**rustock.** `RskHandler` gained an `rskip171_active` flag
(`crates/execution/src/rsk_handler.rs`); when set, the §26
returnDataBuffer-preservation (`rskj_preserves`) is disabled so revm's default
EIP-211 clearing stands. Wired from `RskHardforkConfig::has_rskip171` (iris300,
`crates/execution/src/hardfork.rs`) at both `RskExecutor` call sites
(`crates/execution/src/executor.rs`). Tests, the two halves of rskj's VMTest
pair: `test_empty_code_call_preserves_return_data_buffer` (pre-iris #2,500,000
→ 32) and `test_empty_code_call_clears_return_data_buffer_post_rskip171`
(#3,616,094 → 0).

---

## 38. `NEW_ACCT_CALL` / `NEW_ACCT_SUICIDE` charge on trie EXISTENCE, not EIP-161 emptiness

rskj's VM charges the 25,000-gas new-account surcharge on **trie existence**
(`track.isExist(addr)`), with no value condition (frontier style; EIP-161's
`value>0` gate never applied):

- `Program.getCallGas` / CALL: charges `NEW_ACCT_CALL` whenever the callee does
  not exist.
- `VM.doSUICIDE` (`VM.java`): `if (!program.getStorage().isExist(beneficiary))
  gasCost += GasCost.NEW_ACCT_SUICIDE;` — **unconditional on the suiciding
  contract's balance.**

The distinction matters for accounts that *exist in the unitrie but are empty*
(`nonce=0, balance=0, no code`) — these genuinely occur on RSK (zero-paid
miners; an account re-created after a same-block selfdestruct, see §30). rskj
does NOT charge for a CALL/suicide targeting such an account (it exists);
EIP-161 emptiness would charge.

**CALL path — already correct via the HOMESTEAD journal pin.** revm's CALL gas
(`load_account_delegated`) keys the new-account cost on `account.is_empty`,
where `is_empty` is computed by the journal as `state_clear_aware_is_empty(spec)`
with `spec = journal.cfg.spec`. rustock pins that journal spec to
**`SpecId::HOMESTEAD`** (`rsk_handler.rs`, the "frontier-forever" pin), and under
a pre-Spurious-Dragon spec `state_clear_aware_is_empty` collapses to
`is_loaded_as_not_existing_not_touched()`. revm sets `LoadedAsNotExisting` only
when `Database::basic` returns `None` (the trie has no node — see
`journal/inner.rs` `load_account_mut_optional`); a DB-returned empty `(0,0,no
code)` account gets status `Loaded`. rustock's `basic_ref`
(`database.rs`) returns `None` exactly when the trie has no account node. So
revm's `is_empty` == rskj's `!isExist`, and the CALL surcharge is already keyed
on existence. (This also explains why a precompile is charged `NEW_ACCT_CALL`
only once over the chain's lifetime — §ref `test_precompile_new_account_charged_only_once_across_blocks`.)

**SUICIDE path — fixed.** revm's stock `selfdestruct` instruction gates the
beneficiary top-up on `should_charge_topup = had_value && !target_exists` once
Spurious Dragon is active (the *interpreter* spec, always ≥ Byzantium for RSK).
So a **zero-balance** contract self-destructing to an absent beneficiary skipped
the 25,000 charge — a latent divergence from rskj's value-independent
`!isExist`. rustock now installs a `rsk_selfdestruct` override
(`crates/execution/src/rsk_instructions.rs`) that mirrors revm's instruction but
drops the `had_value &&` gate (`should_charge_topup = !res.target_exists`). Base
cost (5,000, rskj `GasCost.SUICIDE`) is the opcode's static gas; cold cost and
refund are unchanged. (`target_exists` itself is `!is_empty` computed under the
pinned HOMESTEAD journal spec, so it is true trie existence — matching rskj.)

**Consensus-load-bearing:** the surcharge changes gasUsed → receipts root, so a
from-scratch client that uses EIP-161 emptiness (or revm's `had_value` suicide
gate) forks on the receipts root the first time a CALL/suicide targets an
existing-but-empty account, or a zero-value contract suicides to an absent
beneficiary. A from-scratch client must charge the 25,000 on `!isExist`
regardless of value.

**rskj source**: `org.ethereum.vm.VM.doSUICIDE` (NEW_ACCT_SUICIDE on `!isExist`);
`org.ethereum.vm.program.Program.getCallGas`; `org.ethereum.vm.GasCost`
(`SUICIDE=5000`, `NEW_ACCT_SUICIDE=25000`).

**rustock**: `crates/execution/src/rsk_instructions.rs` — `rsk_selfdestruct`
(SELFDESTRUCT override) and the existing CALL path's reliance on the HOMESTEAD
journal pin. Tests (`crates/execution/src/executor.rs`):
`test_new_acct_call_charged_on_existence_not_emptiness` (CALL: existing-but-empty
target not charged, absent target charged) and
`test_new_acct_suicide_charged_on_existence_regardless_of_value` (zero-balance
suicide to an absent beneficiary still pays 25,000).

---

## 39. RSKIP185: an ACCEPTED direct peg-out logs `release_request_received`

§36 covered the *rejected* direct peg-out (refund + `release_request_rejected`).
RSKIP185 (iris300) also adds an event on the **accepted** path: after enqueuing
the release request, `BridgeSupport.requestRelease` (rskj `BridgeSupport.java`
l.1006-1020) calls
`eventLogger.logReleaseBtcRequestReceived(sender, destinationAddress, releaseRequestedValueInWeis)`.
rustock's `release_btc` enqueued the request but emitted nothing on success, so
the receipt was missing one log — the **receipts root** forked while gasUsed,
tx status and the **state root** all matched (the enqueue is identical, and a
peg-out moves no balance in this tx).

**Event encoding (`BridgeEventLoggerImpl.logReleaseBtcRequestReceived`).** The
variant is era-gated: pre-RSKIP326 → `RELEASE_REQUEST_RECEIVED_LEGACY`, after →
`RELEASE_REQUEST_RECEIVED`. At iris300 (RSKIP326/RSKIP427 not yet active) the
**legacy** variant applies:

- signature `release_request_received(address,bytes,uint256)`, topic0 =
  `0x8e04e2f2c246a91202761c435d6a4971bdc7af0617f0c739d900ecd12a6d7266`.
- topic1 (indexed `sender`) = the RSK tx sender.
- data = ABI `(bytes btcDestinationAddress, uint256 amount)`: the destination is
  the **20-byte hash160** (`btcDestinationAddress.getHash160()`), and the amount
  is in **satoshis** (`amountInWeis.toBitcoin()`), not wei. Head = [offset 0x40,
  amount]; tail = [len 20, hash160 right-padded].

**Post-RSKIP326 (fingerroot500, mainnet #5,468,000)** the destination becomes the
Base58 address `string` (`btcDestinationAddress.toString()`) and the signature's
second arg switches `bytes`→`string`. **Post-RSKIP427 (lovell700, mainnet
#7,338,024)** the amount of BOTH `release_request_received` and
`release_request_rejected` becomes full wei (`amountInWeis.asBigInteger()`)
instead of satoshis. Both gates are now implemented (`has_rskip326` /
`has_rskip427` selecting the signature/encoding in
`bridge/events.rs::log_release_request_received` / `log_release_request_rejected`,
fed from `bridge/peg.rs::release_btc`); neither is active in the current sync
window (post-iris, pre-fingerroot), so the legacy form still applies today. Tests
`release_request_received_post_rskip326_427_string_and_wei` and
`release_request_rejected_post_rskip427_amount_is_wei` cover the forward forms.

rskj source for the forward forms:
`co.rsk.peg.utils.BridgeEventLoggerImpl.logReleaseBtcRequestReceived` /
`logReleaseBtcRequestRejected` (the `activations.isActive(RSKIP326)` /
`RSKIP427` branches); `co.rsk.peg.BridgeEvents.RELEASE_REQUEST_RECEIVED`.

**Consensus-load-bearing:** the extra log changes the receipts root, so a
from-scratch client that only emits the *rejected* event (or no event) forks the
receipts root on the first accepted post-iris peg-out. Trigger: mainnet
**#3,615,289** tx 0 — a 400,000-sat (0.004 RBTC) direct transfer to the Bridge,
accepted and logged (header receipts root
`0xd213036b9ceffe97185518d3aa15f5d8dcfdaa8cd35d3b2ea146f2ca1689a94d`).

**rskj source**: `co.rsk.peg.BridgeSupport.requestRelease`;
`co.rsk.peg.utils.BridgeEventLoggerImpl.logReleaseBtcRequestReceived`;
`co.rsk.peg.BridgeEvents.RELEASE_REQUEST_RECEIVED_LEGACY`.

**rustock**: `crates/execution/src/bridge/events.rs`
(`log_release_request_received`), wired into `release_btc`'s accepted path
(`crates/execution/src/bridge/peg.rs`) under `has_rskip185`. Groundtruth test
`release_request_received_matches_mainnet_3615289` (events.rs) reproduces the
#3,615,289 receipt log byte-for-byte.

---

## 40. RSKIP197: a failing precompile CALL is handled (push 0, refund surplus) instead of aborting the caller

Pre-iris, `Program.callToPrecompiledAddress` runs the deprecated
`executePrecompiled`: it `refundGas(msg.gas - requiredGas)` first, then
`out = contract.execute(data)`. If `execute` throws (a `VMException` wrapped in a
`RuntimeException`, or any unchecked exception), the exception **propagates out of
the calling frame** — the caller fails with an exceptional halt that consumes all
of its remaining gas, and the stack is left untouched (no `0` pushed). This is the
behavior `ProgramBeforeRSKIP197Test` asserts (`assertTrue(program.getStack().empty())`
after the throw) and that the DSL test `PrecompiledContractsCallErrorHandlingTests
.handleErrorOnFailedPrecompiledContractCall_beforeIris` asserts as
`assertTransactionFail(...)` for the RSK precompiles.

From **RSKIP197 (iris300, mainnet #3,614,800)** the call dispatches to
`executePrecompiledAndHandleError`:

```java
try {
    this.returnDataBuffer = contract.execute(data);
    this.memorySaveLimited(outOffs, this.returnDataBuffer, outSize);
    this.stackPushOne();          // success: push 1
    track.commit();
} catch (Exception e) {
    this.stackPushZero();         // failure: push 0
    track.rollback();
    this.returnDataBuffer = null;
} finally {
    this.refundGas(msg.getGas().longValue() - requiredGas, CALL_PRECOMPILED_CAUSE);
}
```

So post-197 a **non-OOG** precompile failure is *handled*: the call pushes `0`,
rolls back the precompile's state, clears the return buffer, **refunds the surplus
forwarded gas, and execution CONTINUES**. The precompile costs exactly
`requiredGas` (= `getGasForData(data)`). `ProgramTest
.testCallToPrecompiledAddress_throwPrecompiledContractException` is the
groundtruth: post-197 `program.getResult().getGasUsed() == gasCost` and the stack
shows `0`. (The earlier `requiredGas > msg.gas` branch — a genuine OOG — is
unchanged across eras: it consumes all of the call's gas and pushes `0`.)

**Reachable precompiles at iris.** Among the precompiles revm reports a *non-OOG*
`Err` for, only these can throw post-iris: BN128 add/mul/pairing (0x06–0x08,
`BN128PrecompiledContract.unsafeExecute` throws on an invalid result post-197) and
BLAKE2F (0x09, RSKIP153 iris; `Blake2F.execute` throws on a bad input length or a
bad final-block byte). ECRecover/SHA256/RIPEMD160/Identity never throw (they pad
or catch), and modexp's only non-OOG error (`ModexpEip7823LimitSize`) is a
Shanghai/Osaka feature not active at iris's PETERSBURG spec. `requiredGas`:
add = 150, mul = 6 000, pairing = 45 000 + 34 000·(len/192) (EIP-1108 / Istanbul,
matching rskj `BN128*.getGasForData`); blake2f = the big-endian `u32` rounds when
`len == 213`, else 0 (`Blake2F.getGasForData`).

**Consensus-load-bearing.** revm's `insert_call_outcome` returns the unspent child
gas to the caller only for `is_ok_or_revert()` results; `PrecompileError`/
`PrecompileOOG` are neither, so revm consumes the *entire forwarded* child gas on a
precompile failure (push 0, continue). That happens to match an OOG but **not**
the post-197 non-OOG case, where rskj refunds the surplus (charging only
`requiredGas`). A from-scratch client that burns the full forwarded gas on a
post-iris bn128/blake2f failure forks on **gasUsed → receipts root** wherever a
contract CALLs one of those precompiles with invalid input and forwards more gas
than `requiredGas`. (The pre-iris frame-abort behavior is a closed, already-
validated window for these precompiles — pre-197 bn128 returns empty=success and
blake2f does not yet exist; the pre-197 frame-kill for the RSK stateful precompiles
called internally is logged in TODO, not yet observed on mainnet.)

**rskj source**: `org.ethereum.vm.program.Program.callToPrecompiledAddress` /
`executePrecompiledAndHandleError` (post-197) vs `executePrecompiled` (pre-197,
`@Deprecated`); `ConsensusRule.RSKIP197` (reference.conf `rskip197 = iris300`);
`co.rsk.pcc.altBN128.BN128PrecompiledContract` (safe/unsafe execute);
`org.ethereum.vm.PrecompiledContracts.Blake2F`. Groundtruth tests:
`org.ethereum.vm.program.ProgramTest` (post-197 `gasUsed == gasCost`) and
`ProgramBeforeRSKIP197Test` (pre-197 propagation), plus
`PrecompiledContractsCallErrorHandlingTests` (before/after iris).

**rustock**: `crates/execution/src/precompiles.rs` — on a non-fatal, non-OOG
precompile `Err`, when `has_rskip197` is active, the result is recorded as a
`Revert` with empty output (so revm refunds the surplus via `is_ok_or_revert` and
pushes `0` via `!is_ok`, leaving the returnDataBuffer empty) and the call is
charged exactly `rskip197_required_gas_on_error(addr, input)`. Pre-iris the
existing `PrecompileError`/`PrecompileOOG` path is preserved.
`RskHardforkConfig::has_rskip197` (iris300) added in
`crates/execution/src/hardfork.rs`. Test:
`test_rskip197_failing_precompile_refunds_surplus_gas`
(`crates/execution/src/executor.rs`) — a contract CALLs blake2f with a bad
final-block byte forwarding 900 000 gas; post-iris the tx settles far below the
forwarded gas and the CALL pushes 0 (ported from rskj `ProgramTest`).

## 41. RSKIP181: a rejected peg-in logs `rejected_pegin`

RSKIP181 (iris300, mainnet #3,614,800) adds peg-in rejection events. In the
iris-era legacy peg-in path (`BridgeSupport.processPegInVersionLegacy`, used
until the arrowhead631 `registerPegIn` refactor), a peg-in that was classified as
a valid PEGIN (so it passed the minimum-value gate in `PegUtils.getTransactionType`)
but is then refused emits `rejected_pegin` before being refunded:

```java
if (shouldProcessPegInVersionLegacy(...)) {           // = lockable && whitelisted && capOk
    executePegIn(...);
} else {
    if (activations.isActive(RSKIP181)) {
        if (!isTxLockableForLegacyVersion(...)) {                       // not P2PKH / (post-143) P2SH-P2WPKH
            eventLogger.logRejectedPegin(btcTx, LEGACY_PEGIN_MULTISIG_SENDER);   // reason 2
        } else if (!verifyLockDoesNotSurpassLockingCap(btcTx, totalAmount)) {    // RSKIP134 cap
            eventLogger.logRejectedPegin(btcTx, PEGIN_CAP_SURPASSED);            // reason 1
        }
    }
    generateRejectionRelease(...);
    markTxAsProcessed(btcTx);
}
```

Two quirks a from-scratch client could get wrong:

- **A whitelist-only rejection logs NOTHING.** `shouldProcess` short-circuits
  `lockable && whitelisted && capOk`; the rejection branch re-checks only
  lockable and cap, NOT the whitelist. So a lockable, cap-OK, but non-whitelisted
  peg-in is refunded with no event.
- **The cap re-check in the rejection branch lazily initializes the locking-cap
  cell** (`getLockingCap` persists the network default on first read, §20). For a
  lockable peg-in that failed the whitelist, the cap was NOT evaluated in
  `shouldProcess` (short-circuit), so the `else if !verifyLockDoesNotSurpassLockingCap`
  here is the first evaluation and writes the cell — a state side effect on the
  rejection path.

Event: `rejected_pegin(bytes32 indexed btcTxHash, int256 reason)`, topic0
`0x708ce1ead20561c5894a93be3fee64b326b2ad6c198f8253e4bb56f1626053d6`, topic1 =
`btcTx.getHash().getBytes()` (the witness-stripped legacy txid in **display**
order), data = `int256(reason)` (`RejectedPeginReason`: PEGIN_CAP_SURPASSED=1,
LEGACY_PEGIN_MULTISIG_SENDER=2, LEGACY_PEGIN_UNDETERMINED_SENDER=3,
PEGIN_V1_INVALID_PAYLOAD=4, INVALID_AMOUNT=5).

**Consensus-load-bearing:** the log changes the receipts root / logs bloom, so a
client that omits it forks on the first post-iris peg-in refused for a
multisig/P2SH-not-lockable sender or a locking-cap-surpassing amount. This is
reachable in the CURRENT sync window (we are past iris300).

**rskj source**: `co.rsk.peg.BridgeSupport.processPegInVersionLegacy`,
`isTxLockableForLegacyVersion`, `shouldProcessPegInVersionLegacy`;
`co.rsk.peg.utils.BridgeEventLoggerImpl.logRejectedPegin`;
`co.rsk.peg.pegin.RejectedPeginReason`; `co.rsk.peg.BridgeEvents.REJECTED_PEGIN`.

**rustock**: `crates/execution/src/bridge/events.rs::log_rejected_pegin`, wired
into `register_btc_transaction`'s rejection branch
(`crates/execution/src/bridge/peg.rs`) under `has_rskip181`, replicating the
`!lockable → 2 / else !capOk → 1 / whitelist-only → none` selection (the cap
re-check reuses `cap_ok`, preserving the lazy-init side effect).
`has_rskip181` (iris300) added in `crates/execution/src/hardfork.rs`. Test:
`rejected_pegin_topic_and_data` (events.rs).

**Not implemented (logged in TODO):** `unrefundable_pegin` (rskj
`logNonRefundablePegin`) — in the iris-era legacy path it is only reachable via
the v1 `refundTxSender` no-refund-address case and the arrowhead+ `handleNonRefundablePegin`
multisig-to-different-fed-types case; neither is reachable in the current window.
Also the `LEGACY_PEGIN_UNDETERMINED_SENDER` (reason 3) `rejected_pegin` from
`txIsProcessableInLegacyVersion` failing is not wired — a PEGIN-classified tx has
a determinable sender, so it is effectively unreachable in the legacy era; revisit
if a receipts mismatch points at an undetermined-sender peg-in.

## 42. BTC header reorg: the `btcBlockHeight-<h>` main-chain index must be rewritten for EVERY reorganized height

When a relayer submits BTC headers (`receiveHeader` / `receiveHeaders`), the
Bridge feeds them to bitcoinj's `BtcBlockChain` via `btcBlockChain.add(header)`.
bitcoinj's `BtcAbstractBlockChain.connectBlock` is not a simple "store + advance
head if more work": it has full fork/reorg bookkeeping.

For a header whose parent is the current chain head it extends the best chain
directly: `addToBlockStore` (persist) then `setChainHead`, which writes the
height→hash index entry (`setBtcBestBlockHashByHeight`, RSKIP199/iris300) for
that one height. But for a header that **forks** the chain and has *strictly*
more cumulative work than the current head (`StoredBlock.moreWorkThan` uses `>`,
so a work tie does NOT reorg), it runs `handleNewBestChain`:

1. `findSplit(newHead, oldHead)` — walk both branches back via `getPrev` to the
   common ancestor.
2. `getPartialChain(newHead, split)` — the new branch's blocks above the split,
   head-first.
3. **For every block in that partial chain: `setMainChainBlock(height, hash)`** —
   i.e. rewrite the `btcBlockHeight-<height>` index entry for *each* reorganized
   height, not just the new head's height.
4. `setChainHead(newHead)`.

**The consensus-critical quirk:** a from-scratch client that merely stored each
block and pointed the height index at the new head would leave the *intermediate*
reorganized heights pointing at the old (orphaned) branch's hashes — a state-root
fork that only manifests on a BTC reorg deeper than one block. rustock previously
did exactly that (it had no fork/reorg path at all), and it forked from the
network at RSK mainnet block **#3,622,582** on the single leaf
`btcBlockHeight-697008` (gas and receipts matched; one diverging unitrie leaf).

**rskj source:** `co.rsk.bitcoinj.core.BtcAbstractBlockChain.connectBlock` /
`handleNewBestChain` / `findSplit` / `getPartialChain` (bitcoinj-thin
0.14.4-rsk-18); `co.rsk.peg.RepositoryBtcBlockStoreWithCache.setChainHead` →
`setMainChainBlock` → `BridgeStorageProvider.setBtcBestBlockHashByHeight`
(gated on RSKIP199); `co.rsk.peg.BridgeSupport.receiveHeaders` /
`receiveHeader` calling `btcBlockChain.add`. The index value is
`BridgeSerializationUtils.serializeSha256Hash` = `RLP.encodeElement(hash)`
(`0xa0` + 32 bytes), keyed by `DataWord.fromLongString("btcBlockHeight-" + height)`
with the height as a DECIMAL string (see §35).

**rustock:** `crates/execution/src/bridge/btc_chain.rs` —
`connect_block` (replaces the old inline "put + set head if more work" in both
`receive_header` and `receive_headers`), `handle_new_best_chain`, `find_split`,
`get_partial_chain`. The reorg reindex runs only under RSKIP199 (mirrors the
gating in `setBtcBestBlockHashByHeight`). Tests:
`reorg_find_split_and_partial_chain`, `reorg_direct_extension_partial_chain_is_single_block`
(btc_chain.rs). Verified: replay of #3,622,582 reproduces the exact header state
root `0x038ae437…` (0 diverging leaves) and 419 downstream blocks
(→ #3,623,000) match state + receipts roots exactly.

## 43. RSKIP170: peg-in v1 OP_RETURN parser (exact payload layout + reject-vs-legacy distinction)

A peg-in BTC tx may carry an `RSKT`-magic OP_RETURN output that overrides the
sender-derived destination with an explicit one ("peg-in v1", RSKIP170,
iris300). rskj parses it in `PeginInstructionsProvider.buildPeginInstructions`
+ `PeginInstructionsBase` + `PeginInstructionsVersion1`.

**Payload layout** (the data pushed after the `OP_RETURN` opcode, i.e. bitcoinj
`getChunks().get(1).data`):

```
[0..4]   "RSKT" magic = 0x52534b54
[4]      protocol version (u8); only 1 is supported
[5..25]  RSK destination address (20 bytes)            ── length 25 stops here
[25]     BTC refund address type: 1 = P2PKH, 2 = P2SH
[26..46] refund address hash160 (20 bytes)             ── length 46
```

Valid payload lengths are **exactly 25 or 46**.

**An OP_RETURN counts as "for RSK"** only when its second chunk is data of
length ≥ 4 starting with the RSKT magic (`hasOpReturnForRsk`). rskj scans ALL
outputs; **more than one** RSKT OP_RETURN throws `PeginInstructionsException`.

**The reject-vs-legacy distinction is consensus-critical**
(`PeginInstructionsProvider`):
- **No** RSKT OP_RETURN → `NoOpReturnException` → `Optional.empty()` →
  peg-in falls back to **legacy (v0)** processing (sender-derived destination,
  whitelist + locking-cap gate). Modeled as `Ok(None)`.
- A **malformed** RSKT OP_RETURN (>1 RSKT output, unsupported version, bad
  length, bad refund-address type) → `PeginInstructionsException` →
  `processPegIn` **rejects** the peg-in: refund to the sender, mark processed,
  and (RSKIP181) log `rejected_pegin(PEGIN_V1_INVALID_PAYLOAD = 4)`. Modeled as
  `Err(PeginInstructionsError)`.

**The v1 processing path differs from legacy**
(`BridgeSupport.processPegInVersion1`, IRIS-3.0.0 l.570): it does **NOT** consult
the lock whitelist — only the locking cap (`verifyLockDoesNotSurpassLockingCap`).
A cap-surpassed v1 peg-in refunds via `refundTxSender` (to the v1 refund address
if present, else the BtcLockSender address; if neither, non-refundable) and logs
`rejected_pegin(PEGIN_CAP_SURPASSED = 1)`. The destination credited is the
OP_RETURN's `rskDestinationAddress`; `pegin_btc` is logged with
`protocolVersion = 1`. The tx is marked processed at the end of `processPegIn`
(both legacy and v1 success paths).

**rustock:** `crates/execution/src/bridge/pegin_instructions.rs`
(`build_pegin_instructions`, the parser + 11 ported tests), wired into
`peg.rs::register_btc_transaction` (the v1/v0 branch, `v1_refund_target`,
`emit_pegin_rejection_release`). The old `extract_rsk_destination`
(`script_bytes[2..22]` of any OP_RETURN, no magic/version/length checks) and the
`has_op_return_destination` v1-flag heuristic were removed. Tests ported from
rskj `PeginInstructionsProviderTest` / `PeginInstructionsVersion1Test`
(byte layout from `PegTestUtils.createOpReturnScriptForRsk`).

## 44. RSKIP176 flyover: `registerFastBridgeBtcTransaction` (derivation hash, flyover P2SH, return codes)

The flyover (fast-bridge) peg-in lets a Liquidity Bridge Contract (LBC) register
a BTC tx that paid a *derivation-specific* federation P2SH and have the funds
credited to the LBC. Full port of rskj `BridgeSupport.registerFlyoverBtcTransaction`
(RSKIP176, iris300). The method is only callable from another contract and
returns an `int256`.

**ABI:** `registerFastBridgeBtcTransaction(bytes btcTx, uint256 height,
bytes pmt, bytes32 derivationArgumentsHash, bytes userRefundAddress,
address lbcAddress, bytes lpBtcAddress, bool shouldTransferToContract)
→ int256`, fixed gas 25 000 (`BridgeMethods.REGISTER_FAST_BRIDGE_BTC_TRANSACTION`).

**Return value:** the locked amount **in wei** on success
(`co.rsk.core.Coin.fromBitcoin(totalAmount).asBigInteger()`), or a negative
`FlyoverTxResponseCodes` on every reject/unprocessable path: REFUNDED_USER(-100),
REFUNDED_LP(-200), NOT_CONTRACT(-300), INVALID_SENDER(-301),
ALREADY_PROCESSED(-302), VALIDATIONS(-303), VALUE_ZERO(-304), GENERIC(-900).
The method only ever *fails the tx* for a malformed BTC tx / PMT (rskj's outer
try/catch otherwise returns GENERIC_ERROR).

**Derivation hash** (`PegUtils.getFlyoverDerivationHash`):
`keccak256(derivationArgumentsHash(32) || userRefundAddrBytes || lbcAddress(20)
|| lpBtcAddrBytes)`. **The array-copy order puts the LBC address BEFORE the LP
address — NOT the parameter order.** The BTC address bytes are
`serializeBtcAddressWithVersion`; pre-RSKIP284 (iris) that is
`BigInteger.valueOf(version).toByteArray() || hash160`, which for every mainnet
address version round-trips the input `[version || hash160]` arg unchanged — so
the raw 21-byte ABI args are used verbatim. Ground-truth vector
(`56d4f6bd…44d8`) ported from rskj `PegUtilsTest`.

**Flyover redeem script** (`FlyoverRedeemScriptBuilderImpl.of`):
`PUSH(derivationHash 32) OP_DROP <federationRedeemScript chunks>`; the flyover
P2SH = HASH160 of that (`createP2SHOutputScript`, the non-segwit form at iris).
Ground-truth redeem + P2SH hash160 (`18fc3b52…7730`) ported from rskj `PegUtilsTest`.

**Storage keys** (`BridgeStorageProvider`):
- flyover-hash-used: `fastBridgeHashUsedInBtcTx-` + `Sha256Hash.toString()`
  (**display** order) + `Keccak256.toString()` (**forward** order), value = one
  TRUE byte. **The mark and the second already-used check use the
  witness-stripped legacy txid (`getHash(false)`)**; only the FIRST already-used
  check uses the wtxid (`calculateBtcTxHash`). (This subsumes the narrow
  wtxid-vs-txid item the old stub got wrong.)
- flyover federation info: `fastBridgeFederationInformation-` +
  hex(flyoverFederationRedeemScriptHash), value =
  `RLP([derivationHash, federationP2SHHash])`.

**Flow:** isContractTx (call depth > 1) → sender == lbcAddress → wtxid
already-used check → validationsForRegisterBtcTransaction → parse tx → legacy-txid
already-used check → build active flyover P2SH → validateFlyoverPeginValue
(pre-293: amount to the flyover address must be non-zero) →
verifyLockDoesNotSurpassLockingCap (RSKIP134): on surplus, mark used + refund
(LP if shouldTransferToContract, else user) via an empty-wallet release with the
FLYOVER redeem script + return REFUNDED_LP/USER → else transferTo(lbcAddress),
mark used, save flyover fed info, add the flyover UTXOs to the ACTIVE federation
UTXO set, return the wei amount.

**Gates:** RSKIP176 = iris300 (the whole subsystem). RSKIP293 (hop400) adds the
retiring-federation flyover and a per-UTXO minimum to the value validation —
NOT implemented (logged in TODO.md); a `has_rskip293` guard warns if a retiring
federation exists post-hop400 so the gap is loud before it can fork.

**rustock:** `crates/execution/src/bridge/peg.rs` —
`register_fast_bridge_btc_transaction` (replaces the PMT-only stub),
`flyover_derivation_hash`, `flyover_redeem_script`, `flyover_hash_used_key`,
`is_flyover_derivation_hash_used`, `mark_flyover_derivation_hash_used`,
`set_flyover_federation_information`, `emit_flyover_rejection_release`. The
caller address + call depth are plumbed through `execute_bridge`/`execute_method`/
`run_bridge` (precompiles.rs `inputs.caller` + `journal().depth()`). Tests:
`flyover_derivation_hash_groundtruth`, `flyover_redeem_script_and_p2sh_groundtruth`,
`flyover_hash_used_key_byte_order` (peg.rs).

## 45. EXTCODEHASH keys on TRIE EXISTENCE (rskj `isExist`), not EIP-161 emptiness

**rskj behavior** (`org.ethereum.vm.VM.doEXTCODEHASH` →
`Program.getCodeHashAt(addr, standard=RSKIP169)` →
`MutableRepository.getCodeHashStandard`):

```java
// VM.doEXTCODEHASH
if (isPrecompiledContract) {            // any active precompile
    stackPush(keccak256(EMPTY));        // keccak256("")
} else {
    Keccak256 h = getCodeHashAt(addr, RSKIP169);
    stackPush(h.equals(ZERO_HASH) ? ZERO : h);
}
// MutableRepository.getCodeHashStandard (RSKIP169 / standard path):
if (!isExist(addr))    return ZERO_HASH;           // not in the trie -> 0
if (!isContract(addr)) return KECCAK_256_OF_EMPTY; // present, no code -> keccak256("")
return internalGetValueHash(getCodeKey(addr))      // contract -> its code hash
         .orElse(KECCAK_256_OF_EMPTY);
```

The existence test is `isExist` = **the account node is present in the trie**.
RSK never adopted EIP-161/EIP-1052 emptiness, so an account that exists but is
"empty" by Ethereum's definition (nonce 0, balance 0, no code) hashes to
`keccak256("")`, **not** 0. Only a genuinely absent account hashes to 0. Active
precompiles always hash to `keccak256("")` regardless of their stored state.

**revm divergence:** revm's stock `EXTCODEHASH` (`instructions/host.rs`) returns
`B256::ZERO` whenever `AccountInfo::is_empty()` (EIP-161: balance == 0 &&
nonce == 0 && no code), otherwise the code hash. So an *existing-but-empty*
account wrongly hashes to 0 instead of `keccak256("")`.

**Mainnet impact — block #3,631,998 tx[1]** (computed gasUsed 27,540 vs header
27,529, +11): a token-bridge `receiveTokensTo(token, to, amount)` call validated
the token via `EXTCODEHASH(token) == keccak256("")`. The token
`0xdAC17F958D2ee523a2206206994597C13D831ec7` (USDT-on-Ethereum) has no code on
RSK but its account *node existed* in the trie (a prior 0-value call had created
it under frontier semantics). rskj returned `keccak256("")` (account exists, not
a contract) → the proxy took one branch; rustock returned 0 → the other branch,
diverging the revert path and the gas. A receipts + state-root fork (both tx[1]
status and gasUsed differed).

**rustock:** `crates/execution/src/rsk_instructions.rs` — `rsk_extcodehash`
replaces revm's stock instruction whenever RSKIP140 is active. It keys on the
HOST's `is_empty` flag (the journal sets it `true` only when `Database::basic`
returned `None`, i.e. the trie has no node — see the HOMESTEAD journal pin in
`RskHandler`, §10a/account-semantics), which is exactly rskj's `isExist`:
absent → 0; present-but-codeless → `keccak256("")`; contract → its code hash.
Active precompiles (passed via `extcodehash_precompiles`, gated on RSKIP140 in
`executor.rs`) → `keccak256("")`. Test:
`test_extcodehash_existing_empty_account_is_keccak_empty` (executor.rs).

## 46. COINBASE returns the real miner (`header.getCoinbase`), NOT the gas-fee recipient

In RSK, transaction gas fees are credited to the REMASC contract
(`0x…01000008`), which later distributes rewards with delayed maturity — the
miner (`header.getCoinbase()`, e.g. `0x31fe561e…`) is not paid directly during
transaction execution. But the `COINBASE` opcode (`org.ethereum.vm.OpCode.COINBASE`
→ `Program.getCoinbase()` → `ProgramInvoke.getCoinbase()` → the *block header's*
coinbase) still returns the **real miner address**, not REMASC.

These are two distinct roles of the same conceptual "beneficiary": (a) the gas-fee
recipient and (b) the value the `COINBASE` opcode exposes to contracts. rskj keeps
them separate; a naive port that uses one field for both will diverge whenever a
contract reads `block.coinbase`.

**Consensus-critical:** a from-scratch client that points `COINBASE` at the
fee recipient (REMASC) forks from the network the first time any contract mints/
sends/logs to `block.coinbase`. Mainnet **#3,650,574** exposed this: a token's
mint-to-coinbase emitted a `Transfer` to `0x…01000008` (REMASC) in rustock vs the
real miner `0x31fe561eb2c628cd32ec52573d7c4b7e4c278bfa` in rskj — diverging both
the state root and the receipts root.

**rskj:** `Program.getCoinbase()` returns `invoke.getCoinbase()`, sourced from the
block header; fee crediting to REMASC happens separately in `TransactionExecutor`.

**rustock:** `crates/execution/src/env.rs` pins `BlockEnv.beneficiary = REMASC_ADDR`
so revm's `reward_beneficiary` routes gas fees to REMASC. To stop that from
corrupting the opcode, `crates/execution/src/rsk_instructions.rs` installs
`rsk_coinbase`, which pushes the real miner stashed in the `REAL_COINBASE`
thread-local (set from `header.beneficiary` in `executor.rs`'s two `install`
call sites). Test: `test_coinbase_returns_real_miner_not_remasc` (executor.rs).

## 47. RSKIP185: a ZERO-value `releaseBtc` call is rejected-and-logged, not silently dropped

`BridgeSupport.releaseBtc(rskTx)` (`co.rsk.peg.BridgeSupport`, line ~882)
unconditionally forwards an EOA peg-out request to `requestRelease` — there is
**no zero-value short-circuit**. `requestRelease` computes
`valueToReleaseInSatoshis = releaseRequestedValueInWeis.toBitcoin()` (0 for a
zero-value call) and, post-RSKIP219, rejects it because `0 < minValue =
max(minimumPegoutTxValue, requireFundsForFee)`. The reject reason is
`LOW_AMOUNT(1)` when `minValue == minimumPegoutTxValue` (the flat minimum binds)
and `FEE_ABOVE_VALUE(3)` when the fee estimate binds. Post-RSKIP185 the rejection
is **not** a silent drop: `refundAndEmitRejectEvent` refunds the sender (a no-op
transfer of 0 wei for a zero value) and `eventLogger.logReleaseBtcRequestRejected`
emits `release_request_rejected(address indexed sender, uint256 amount, int256
reason)` — a receipts-visible log.

**Consensus-critical:** a from-scratch client that treats a zero-value (or
sub-satoshi) call to the Bridge as a no-op forks on the receipts root the first
time such a call lands post-iris300. Mainnet **#4,212,341** tx 3 exposed this: a
`value=0`, empty-input EOA call to `0x…01000006` emitted
`release_request_rejected(sender=0x6338723180b802c5a5201f8ed12398eb7da31998,
amount=0, reason=1)` (topic0 `0xb607c3e1fbe6b38cd145b15b837f7b722b199caa60e3057b36c141adee3b75e7`)
on the public node, while rustock emitted nothing — gas and state root matched,
only the receipts root diverged (header
`0xabdfe1bc…` vs computed `0xae1c39b0…`).

This is the same family as §36/§39 (the *rejected* and *accepted* direct peg-out
branches of `requestRelease`); the remaining unported arm was the degenerate
zero/sub-satoshi amount, which rustock had short-circuited before reaching the
reject logic.

**rskj source:** `co.rsk.peg.BridgeSupport.releaseBtc` / `requestRelease` /
`refundAndEmitRejectEvent` / `emitRejectEvent`, `co.rsk.peg.RejectedPegoutReason`.

**rustock:** `crates/execution/src/bridge/peg.rs` (`release_btc`) — the
`call_value_wei.is_zero()` and `amount_satoshis_u256.is_zero()` early-returns were
removed so a zero amount flows into the existing RSKIP219/RSKIP185 reject path
(refund + `log_release_request_rejected`). Test:
`solidity_release_request_rejected_zero_value_mainnet_4212341`
(`crates/execution/src/bridge/events.rs`), ground-truthed against the #4,212,341
tx 3 public-node receipt.

## 48. RSKIP271: `nextPegoutHeight` is advanced even when the release queue is EMPTY

Post-RSKIP271 (Hop400, mainnet **#4,598,500**) peg-outs are batched. Each
`updateCollections` calls `processPegoutsInBatch`, which is gated by
`currentBlock >= nextPegoutCreationBlockNumber` (`BridgeSupport.java:1501`). When
the gate is open, after attempting to batch any pending requests it runs:

```java
// set the next pegout creation block number when there are no pending pegout
// requests to be processed or they have been already processed
if (pegoutRequests.getEntries().isEmpty()) {
    long nextPegoutHeight = currentBlockNumber + bridgeConstants.getNumberOfBlocksBetweenPegouts();
    provider.setNextPegoutHeight(nextPegoutHeight);   // BridgeSupport.java:1554-1559
}
```

The key subtlety: this fires when the queue is empty *after* processing —
**including the case where it was empty to begin with**. At Hop400 the
`nextPegoutHeight` storage cell is unset (reads as 0), so the gate
`currentBlock >= 0` is always open, and the very first `updateCollections` after
activation writes the cell (`= currentBlock + 360` on mainnet,
`numberOfBlocksBetweenPegouts`, `BridgeMainNetConstants.java:45`). That write
mutates Bridge storage and therefore the state root.

**Consensus-critical:** a client that only updates `nextPegoutHeight` on the
batching success path (i.e. when a BTC tx was actually built) never advances the
cell while the queue is empty, so its Bridge storage — and the state root —
forks from rskj. Mainnet **#4,598,511** (11 blocks past Hop400) exposed this: the
block's `updateCollections` ran with an empty queue, rskj wrote
`nextPegoutHeight = 4,598,871`, rustock wrote nothing → state root diverged
(header `0x4f8a8d62…` vs computed `0x502cdda…`) while gas and receipts matched.
A failed/insufficient batch build leaves the queue non-empty and thus does NOT
advance the height (rskj returns early at lines 1513/1533, before the tail).

**rskj source:** `co.rsk.peg.BridgeSupport.processPegoutsInBatch`
(`rskj-core/src/main/java/co/rsk/peg/BridgeSupport.java:1490-1560`).

**rustock:** `crates/execution/src/bridge/peg.rs` (`update_collections`) — the
`nextPegoutHeight` write was moved out of the batching-success branch into a tail
gated on `use_rskip271 && queue_emptied`, where `queue_emptied` is true when the
queue started empty or was fully batched. Test:
`rskip271_next_pegout_height_formula_mainnet`
(`crates/execution/src/bridge/peg.rs`), ground-truthed against the #4,598,511
header state root and the mainnet `numberOfBlocksBetweenPegouts = 360`.

## 49. RSKIP271: a batched peg-out logs `batch_pegout_created` AND stores the emptied queue as `[0xc0]`

When the RSKIP271 (Hop400) batching gate opens *with* a non-empty release queue,
`BridgeSupport.processPegoutsInBatch` builds one batched BTC tx for the whole
queue and does two things a from-scratch client easily gets wrong:

1. **Two distinct events, in order.** `settleReleaseRequest` first logs
   `release_requested(rskTxHash, btcTxHash, amount)` (the same event the
   individual path uses, keyed by the batch creation RSK tx hash, total amount),
   and *then* `processPegoutsInBatch` logs a **second** event
   `batch_pegout_created(bytes32 indexed btcTxHash, bytes releaseRskTxHashes)`
   (`BridgeSupport.java:1543` then `:1548`). `releaseRskTxHashes` is
   `serializeRskTxHashes` — the raw concatenation of every batched request's
   32-byte RSK creation tx hash, ABI-encoded as a single dynamic `bytes`
   (`BridgeEventLoggerImpl.java:277-288,404-418`). Emitting only
   `release_requested` (or only `batch_pegout_created`) gives the wrong receipt
   logs → wrong logsBloom → wrong receipts root.

2. **The emptied queue cell holds `[0xc0]`, not empty bytes.** After batching,
   rskj clears the queue and `BridgeStorageProvider.saveReleaseRequestQueue`
   re-serializes the now-empty queue via `serializeReleaseRequestQueueWithTxHash`
   (`BridgeStorageProvider.java:196-206`), which is `RLP.encodeList([])` = the
   single byte `0xc0`. Writing the cell as zero-length bytes instead produces a
   different trie leaf value → wrong state root (logs are not in the trie, so
   this is a *separate* divergence from #1).

**Consensus-critical:** both are implementation quirks. A client that fires the
"natural" single release event, or that represents an empty queue as empty bytes
rather than RLP `[]`, computes correct gas yet forks on receipts and/or state.
Mainnet **#4,598,891** exposed both at once (the first real batched peg-out after
the prior empty-queue fix): receipts root header `0x59daa4b0…` and state root
header `0x6e0b7633…`, with rustock computing `0xc5177f49…` / `0xdae534c7…` until
fixed.

**rskj source:** `co.rsk.peg.BridgeSupport.processPegoutsInBatch` /
`settleReleaseRequest` (`BridgeSupport.java:1490-1560,1378-1437`),
`co.rsk.peg.utils.BridgeEventLoggerImpl.logBatchPegoutCreated`
(`:277-288,404-418`), `co.rsk.peg.BridgeStorageProvider.saveReleaseRequestQueue`
(`:196-206`).

**rustock:** `crates/execution/src/bridge/events.rs`
(`log_batch_pegout_created`) and `crates/execution/src/bridge/peg.rs`
(`update_collections`, RSKIP271 batch branch) — emits both events in rskj order
and stores the emptied with-txhash queue via
`serialize_release_queue_with_hash(&[])` (= `[0xc0]`). Both are inside the
`use_rskip271` branch, so pre-Hop400 blocks are unaffected. Test:
`batch_pegout_created_event_matches_mainnet_4598891`
(`crates/execution/src/bridge/events.rs`), ground-truthed against the #4,598,891
tx 2 event topics/data.

## 50. A Bridge method that THROWS consumes only `requiredGas`, NOT all the gas (direct tx = invisible-exception SUCCESS; internal CALL = plain failure)

When a top-level transaction calls a precompile (the Bridge), rskj
`TransactionExecutor.call` precomputes `requiredGas = getGasForData(data)` and
`gasUsed = requiredGas + basicTxCost` **before** invoking
`precompiledContract.execute(data)`. If `execute` throws — and `Bridge.execute`
wraps any method `RuntimeException`/`BridgeIllegalArgumentException` in a
`VMException` — the catch block merely does `result.setException(e)` and then
`result.spendGas(gasUsed)`; it does **not** call `execError(...)`. Consequences
(`TransactionExecutor.java:344-377,564,681-682`,
`TransactionExecutionSummary.java:63-85,177-178`):

- **Receipt status = SUCCESS** (`executionError` stays empty → `SUCCESS_STATUS`).
- **Receipt `gasUsed` = `requiredGas + basicTxCost`** (`getGasConsumed =
  gasLimit - gasLeftover`, with `gasLeftover = gasLimit - gasUsed`); the unused
  gas is refunded.
- **But the sender is charged the FULL gas limit as a fee**: the summary is
  flagged `markAsFailed()` because `result.getException() != null`, and
  `getFee()` returns `calcCost(gasLimit)` (refund/leftover = 0). REMASC receives
  `gasLimit * gasPrice`.
- **No logs, no endowment** (the throw aborts before they take effect).

This is the same "invisible exception" already implemented for a post-RSKIP88
parse failure (§ for `addLockWhitelistAddress` / #764,123) — a method throw is
just another `VMException` on the identical code path. For an **internal**
(depth>1) Bridge CALL, rskj `Program.executePrecompiledAndHandleError`
(`Program.java:1568-1570,1628-1647`) had already charged `requiredGas` before the
call and, on a throw, pushes zero (the CALL fails) and refunds `gas -
requiredGas`, so only `requiredGas` is consumed and the caller sees a plain CALL
failure.

**Consensus-critical:** a from-scratch client that lets a precompile error
forfeit the whole forwarded gas (revm's default `InstructionResult::PrecompileError`)
forks both on gas-used and on receipt status. Mainnet **#4,600,948** tx[3]
(`registerBtcCoinbaseTransaction`, PMT verification fails) exposed this: header
total gas `388220` (tx[3] = `41880` intrinsic + `11224` getGasForData = `53104`,
receipt SUCCESS), rustock computed `1335116` (tx[3] = `1000000`, status false)
until fixed.

**rustock:** `crates/execution/src/bridge/mod.rs` — `execute_bridge` wraps the
`execute_method` result: a non-OOG, non-`Fatal` throw becomes an
`INVISIBLE_EXCEPTION_MARKER` (depth 1) or `INTERNAL_BRIDGE_THROW_MARKER`
(depth>1), each carrying the `requiredGas`. `crates/execution/src/precompiles.rs`
`run_stateful` records exactly that `requiredGas` (invisible → `Return`, sender
charged full limit via the `invisible_exception` flag read by `RskHandler`;
internal → `Revert`, leftover refunded). Tests:
`test_rskip540_estimated_fees_for_pegout_amount_below_minimum_fails`
(`crates/execution/src/executor.rs`), ground-truthed against rskj
`BridgeTest.getEstimatedFeesForPegOutAmount_withAmountBelowMinimum_shouldThrowBridgeIllegalArgumentException`
and matching #4,600,948 tx[3]'s `53104`.

## 51. `registerBtcCoinbaseTransaction`: tx-not-in-PMT and merkle-root mismatch `return` (success), they do NOT throw

`Bridge.registerBtcCoinbaseTransaction` is `throws VMException`, but only SOME
failure paths actually throw. rskj `BridgeSupport.registerBtcCoinbaseTransaction`
(`rskj-core/src/main/java/co/rsk/peg/BridgeSupport.java`):

- **tx not in the supplied PMT** (l.2503-2511): `logger.warn(...)` + `return;`.
- **supplied merkle root != block's merkle root** (l.2546-2555): `logger.warn(...)`
  + `return;`.

Both `return` WITHOUT storing coinbase info and WITHOUT throwing. The other
paths DO throw `BridgeIllegalArgumentException`: witness-reserved-value length
!= 32 (l.2485), PMT wrong size (l.2495), PMT parse failure (l.2515), block not
registered (l.2536).

**Consensus-critical fee impact.** Because these two cases do not throw, the
`TransactionExecutionSummary` is NOT `markAsFailed()`, so `getFee()` returns
`calcCost(gasLimit - gasLeftover - gasRefund)` = `gasUsed * gasPrice` — NOT the
full `gasLimit * gasPrice` of the invisible-exception path (§50). A from-scratch
client that treated a coinbase-registration failure as an exception would
over-bill the sender `(gasLimit - gasUsed) * gasPrice` into `paidFees` and fork
the block. Mainnet **#4,603,038** tx[2] (`registerBtcCoinbaseTransaction`,
selector `0xccf417ae`, a merkle-root mismatch: gasUsed `82544`, gasLimit
`1000000`, gasPrice `60000000`) exposed this: rustock had introduced §50's
method-throw wrapper, which turned the mismatch into an invisible exception and
billed the full limit, computing `paidFees` `177892013503048` vs header
`122844653503048` — a `55,047,360,000,000` over-charge that equals exactly
`(1000000 - 82544) * 60000000`.

**rustock:** `crates/execution/src/bridge/tx.rs`
`register_btc_coinbase_transaction` now returns `Ok(PrecompileOutput::new(...))`
(success no-op) for the tx-not-in-PMT and merkle-root-mismatch checks, instead
of `Err`, so §50's wrapper never sees a throw and the fee stays `gasUsed *
gasPrice`. The genuine-throw paths (PMT size/parse, block not found) are
unchanged, preserving #4,600,948 tx[3]'s invisible-exception behavior. Test:
`test_register_btc_coinbase_tx_hash_not_in_pmt_succeeds`
(`crates/execution/src/executor.rs`), ground-truthed against rskj
`BridgeSupportTest.when_RegisterBtcCoinbaseTransaction_HashNotInPmt_noSent` /
`..._not_equal_merkle_root_noSent`, and matching #4,603,038's state root.

## §52 commitFederation: ERP federation redeem script (RSKIP201/284/293/353)

**rskj behavior.** Once RSKIP201 (iris300) is active, `commitFederation`
builds the new federation as an **ERP federation**, not a standard multisig
(`co/rsk/peg/federation/PendingFederation.java:117-133` →
`FederationFactory.java`). The *type* is selected by activations:
- `!RSKIP201` → standard multisig (`FederationFormatVersion` 1000).
- `RSKIP201 && !RSKIP353` → **non-standard ERP** (2000); the builder is chosen
  by `NonStandardErpRedeemScriptBuilderFactory`: with RSKIP284 & RSKIP293 both
  active (mainnet hop400) it is `NonStandardErpRedeemScriptBuilder`.
- `RSKIP353 && !RSKIP305` → **P2SH-ERP** (3000), `P2shErpRedeemScriptBuilder`.
- `RSKIP305` → P2SH-P2WSH-ERP (4000), same redeem template as P2SH-ERP.

RSKIP→fork (rskj `reference.conf`): rskip201=iris300, rskip284/293=hop400,
**rskip353=hop401** (mainnet 4,976,300), rskip305=reed800. So at the first real
mainnet federation change, **#4,652,781** (hop400-era, hop401 NOT yet active),
the committed federation is a **non-standard ERP federation**, address
`3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh`.

**Redeem-script template** (`NonStandardErpRedeemScriptBuilder.java:46-61`,
`P2shErpRedeemScriptBuilder.java:49-66`):
`OP_NOTIF <default-multisig> OP_ELSE <push csv> OP_CHECKSEQUENCEVERIFY OP_DROP
<emergency-multisig> OP_ENDIF`. Non-standard strips the trailing
`OP_CHECKMULTISIG` (`ErpRedeemScriptBuilderUtils.removeOpCheckMultisig`, last
chunk) from BOTH inner scripts and appends ONE `OP_CHECKMULTISIG` after
`OP_ENDIF`; P2SH-ERP keeps each inner `OP_CHECKMULTISIG` and emits nothing
after `OP_ENDIF`. Default threshold = `members/2+1`; emergency threshold =
`erpKeys/2+1` (`ErpFederation.getNumberOfEmergencySignaturesRequired`). Inner
multisig keys are sorted unsigned-lexicographically by compressed pubkey
(`ScriptBuilder.createRedeemScript` → `BtcECKey.PUBKEY_COMPARATOR`).

**Consensus-critical CSV-delay encoding.** The CSV value
(`erpFedActivationDelay`, mainnet 52,560) is pushed via
`Utils.signedLongToByteArrayLE` = `reverseBytes(BigInteger.valueOf(v)
.toByteArray())`: minimal big-endian two's complement (Java keeps a leading
`0x00` sign byte when the top bit is set), reversed to LE. For 52,560 this is
`50 cd 00` (3 bytes), NOT the BIP68-minimal `50 cd`. A from-scratch client doing
minimal CSV encoding forks.

**Storage / event.** The federation format-version cells
(`newFederationFormatVersion`/`oldFederationFormatVersion`) store the TYPE
integer (1000/2000/3000); the commit_federation event logs
`newFederation.getAddress()` (the ERP P2SH base58) and
`lastRetiredFederationP2SHScript` is the retiring fed's `getP2SHScript()` (its
own type's redeem; RSKIP377 — which would switch to `getDefaultP2SHScript()` —
is fingerroot500, inactive here).

**rustock.** `crates/execution/src/bridge/peg.rs`
`build_committed_federation_redeem_script` + `build_erp_redeem_script` +
`signed_long_to_byte_array_le`; type selection via new
`hardfork.rs::has_rskip353`/`has_rskip305` (explicit per-chain hop401/reed800
heights, since rustock collapses hop401 into Hop400). Wired into
`governance.rs::commit_pending_federation` for the new and (creation-block-keyed)
old federation redeem scripts and the format-version cells
(`federation_format_version`). Ground-truth tests:
`nonstandard_erp_federation_address_mainnet_4652781` (the on-chain address),
`p2sh_erp_federation_address_rskj_fixture` (ported from rskj
`P2shErpFederationTest`), `erp_csv_delay_encoding_groundtruth`. Verified by both
the state root (`0xf133febc…`) and receipts root (`0x883ea305…`) of #4,652,781.

## References

- rskj source: `../rskj/rskj-core/src/main/java/org/ethereum/net/rlpx/`
- rskj sync: `../rskj/rskj-core/src/main/java/co/rsk/net/sync/`
- RSKIP-351: Compressed block header format
- RLPx spec: https://github.com/ethereum/devp2p/blob/master/rlpx.md
