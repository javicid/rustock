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

## References

- rskj source: `../rskj/rskj-core/src/main/java/org/ethereum/net/rlpx/`
- rskj sync: `../rskj/rskj-core/src/main/java/co/rsk/net/sync/`
- RSKIP-351: Compressed block header format
- RLPx spec: https://github.com/ethereum/devp2p/blob/master/rlpx.md
