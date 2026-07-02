# Java/JVM & Library Artifacts in RSK Consensus

Consensus-load-bearing behaviors that are **not visible in rskj's own source
code** — they hide inside the JDK (`HashMap`/`HashSet` iteration order and
capacity sizing, `BigInteger.toByteArray()` sign bytes, signed `byte`
comparison, truncating integer division) or inside Java-ecosystem libraries
(bitcoinj byte-order conventions, Guava comparators and hashing). This is the
most dangerous category: a from-scratch client can read every line of rskj and
still fork unless it also reproduces Java internals bit-for-bit.

Part of the rskj compatibility catalogue; section numbers (§N) are historical
and shared across the whole catalogue — the index in
[`java-compatibility.md`](./java-compatibility.md) maps every § to its file.

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

## 8. Java `HashMap` Iteration Order in Consensus Serialization

> **Superseded by §11b** (below): the lock whitelist turned out to be a
> `TreeMap` sorted by hash160, not a `HashMap` — the 2-entry #3304 groundtruth
> happened to match both orders, and the Java-HashMap emulation described here
> was removed. Kept for the record, and because the JDK-internals analysis is
> what §34's real `HashSet` dependence builds on.

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

**Table capacity is the `new HashSet<>(collection)` PRE-SIZE from the final
count, NOT an incremental-insertion history.** The set that
`getNextPegoutWithEnoughConfirmations` iterates is the cached
`this.entries` field of the `PegoutsWaitingForConfirmations` object. The LAST
step of `BridgeStorageProvider.getPegoutsWaitingForConfirmations` is
`pegoutsWaitingForConfirmations = new PegoutsWaitingForConfirmations(entries)`,
and that constructor is

```java
public PegoutsWaitingForConfirmations(Set<Entry> entries) {
    this.entries = new HashSet<>(entries);   // collection constructor → PRE-SIZE
}
```

`HashSet(Collection c)` calls `this(Math.max((int)(c.size()/.75f)+1, 16))`, and
`HashMap(int initialCapacity)` stores `threshold = tableSizeFor(initialCapacity)`
which the first `resize()` adopts as the table length. So for `n` final entries
the table capacity is the next power of two `>= max((int)(n/0.75)+1, 16)`:

| n        | 0–11 | 12–23 | 24–47 | 48–95 |
|----------|------|-------|-------|-------|
| capacity | 16   | 32    | 64    | 128   |

(The intermediate `new HashSet<>(legacyCell)` / `addAll(withTxHashCell)` steps
ARE incremental, but their result is then handed to the collection constructor,
which re-buckets everything into the pre-sized table — so only the final
constructor's sizing is observable to `getNextPegoutWithEnoughConfirmations`.)

This pre-size is one doubling LARGER than an incremental default-16 fill of the
same `n` at the boundaries: at `n = 12` the pre-size gives 32 but an incremental
fill stays at 16; at `n = 24` it gives 64 vs 32. A wrong capacity reshuffles
every bucket index and forks the selection. The #3,345,557 case had `n = 13`,
where both 16-incremental-then-resize and pre-size give 32, which is why an
incremental model happened to pass that ground truth while still being wrong.

The insertion order into the final set is the iteration order of the
intermediate `HashSet` it is copied from, which only matters for the intra-bucket
tiebreak.

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

**Capacity-boundary trigger**: mainnet #3,344,303. The confirmation set has
exactly `n = 12` entries, of which the two created at height 3,340,302 both reach
4000 confirmations here. With the correct PRE-SIZE capacity 32 they land in
buckets 15 (txid `20806dad…`, rskTxHash `2ad6d4c3…`) and 21 (txid `415c147f…`,
rskTxHash `ca7dcb44…`), so rskj promotes the bucket-15 `20806dad…` tx. An
incremental capacity 16 puts them in buckets 15 and 5, promoting the wrong
`415c147f…` tx — forking both `releaseTransactionSetWithTxHash` and
`rskTxsWaitingFS` (computed root `0x62047bea…` vs header `0x0d4bed56…`). This is
the boundary the incorrect incremental model got wrong even though #3,345,557
(n=13) still passed.

**rskj source**:
`co.rsk.peg.PegoutsWaitingForConfirmations.getNextPegoutWithEnoughConfirmations`
and `Entry.hashCode`; `co.rsk.bitcoinj.core.BtcTransaction.hashCode` /
`Sha256Hash.hashCode`; `co.rsk.peg.BridgeSupport.processConfirmedPegouts`;
`BridgeStorageProvider.getPegoutsWaitingForConfirmations` (`new HashSet<>(…)`).

**rustock**: `crates/execution/src/bridge/peg.rs`
`next_pegout_with_enough_confirmations` / `pegout_entry_hash` (replicate the
bucket order) + `java_hashset_capacity` (the `HashSet(Collection)` pre-size
capacity `tableSizeFor(max((int)(n/0.75)+1, 16))`), called from Step 2 of
`update_collections`. Tests:
`rskj_next_pegout_hashset_iteration_order_groundtruth` (block #3,345,557 ground
truth), `java_hashset_capacity_resize_boundaries` (the n=11/12/23/24/47/48
capacity boundaries), `pegout_selection_at_16_to_32_resize_boundary` (n=13), and
`pegout_selection_n12_presize_picks_rskj_entry` (the #3,344,303 n=12 boundary
regression).

---

