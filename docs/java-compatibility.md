# Java RSK Node (rskj) Compatibility Notes — Index

This is the index of the rskj compatibility catalogue: behaviors that are
consensus- or protocol-load-bearing because of a **language or implementation
artifact of `rskj`** — things a spec-following client could implement
"correctly" and still fork from the network.

The catalogue is split by the *nature* of each quirk:

- [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) — behaviors hidden in
  **JDK or Java-library internals**, invisible in rskj's own source
  (`HashMap`/`HashSet` order, `BigInteger` sign bytes, signed-byte comparison,
  bitcoinj byte order, Guava hashing).
- [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) — **accidental rskj code
  paths frozen into consensus**: visible in the source, clearly unintended,
  but mainnet history depends on them (some later corrected by an RSKIP).
- [`design-divergences.md`](./design-divergences.md) — **deliberate,
  non-canonical RSK design**: per-RSKIP fork policy, fork-independent gas
  constants, frontier-forever account semantics, Bridge/peg semantics.
- [`wire-protocol.md`](./wire-protocol.md) — RLPx framing, message encoding,
  sync protocol, and discovery (interop-load-bearing, mostly non-consensus).

Section numbers (§N) are historical and shared across the whole catalogue —
cross-references like "see §30" resolve through the map below. Numbering is not
sequential: some numbers live in [`consensus-port-log.md`](./consensus-port-log.md)
(see the cross-reference list at the bottom). **New entries** go into the file
matching their nature, plus a row here.

**Companion doc:** RSKIP *feature* slices implemented to keep the sync
advancing — bridge peg-in/peg-out classification, federation lifecycle, SVP,
segwit, Bridge event emissions, and hardfork opcode installs — are logged in
[`consensus-port-log.md`](./consensus-port-log.md). Those entries describe
behavior an RSKIP *specifies*; where a feature slice also surfaces a genuine
implementation quirk, it is cross-referenced below.

## Section map

| § | Title | File |
|---|-------|------|
| 1 | Multi-frame (chunked) RLPx messages | [`wire-protocol.md`](./wire-protocol.md) |
| 2 | Non-canonical RLP integers (`BigInteger.toByteArray()` sign byte) & header-hash caching | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 3 | Compressed block headers (RSKIP-351) | [`wire-protocol.md`](./wire-protocol.md) |
| 4 | RSK sub-protocol double-wrapped RLP messages | [`wire-protocol.md`](./wire-protocol.md) |
| 5 | Descending header delivery | [`wire-protocol.md`](./wire-protocol.md) |
| 6 | Skeleton-based forward sync protocol | [`wire-protocol.md`](./wire-protocol.md) |
| 7 | Hardfork-gated validation rules (merged mining, difficulty) | [`design-divergences.md`](./design-divergences.md) |
| 8 | Java `HashMap` iteration order in whitelist serialization *(superseded by §11b)* | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 9 | Unitrie account & storage encoding (signed coin, slot-0 key, REMASC `siblings`) | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 10 | Storage-prefix marker only for genuine contract creations (+10a empty-data CREATE) | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 11 | Bridge UTXO byte order (11a) & whitelist sorted by hash160 (11b) | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 12 | REMASC `brokenSelectionRule` cell written via `addStorageBytes` | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 13 | Zero-value REMASC payment creates the recipient | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 14 | Federation serialization (RSKIP123) | [`consensus-port-log.md`](./consensus-port-log.md) |
| 15 | RSKIP125 created-contract nonce (wasabi) | [`design-divergences.md`](./design-divergences.md) |
| 16 | Pre-RSKIP150 unbounded precompile output write (gas-free memory extension) | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 17 | BlockHeaderContract `getGasLimit` returns raw header bytes | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 18 | ethereumj ABI: empty `bytes` pads to one full zero word | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 19 | Federation storage format-version cell (RSKIP123) | [`consensus-port-log.md`](./consensus-port-log.md) |
| 22 | Election spec ordering: SIGNED-byte comparison of `getEncoded()` | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 24 | RSKIP151/152: SELFBALANCE & CHAINID at papyrus200, no Istanbul repricing | [`design-divergences.md`](./design-divergences.md) |
| 26 | returnDataBuffer survives calls that execute nothing (no EIP-211 clear) | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 27 | RSKIP150: EVM call-stack limit is 400 | [`design-divergences.md`](./design-divergences.md) |
| 29 | Pegout dusty-change surplus burned to 0xff…ff | [`design-divergences.md`](./design-divergences.md) |
| 30 | Suicided accounts deleted per-TRANSACTION, not per-block | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 31 | Coinbase-info storage key: `Sha256Hash.toString()` does NOT reverse | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 32 | SegWit peg-ins: wtxid for PMT, txid for the processed map | [`design-divergences.md`](./design-divergences.md) |
| 33 | `rskTxsWaitingFS` order: `Keccak256.compareTo` compares bytes in REVERSE | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 34 | Confirmed-pegout selection follows Java `HashSet` iteration order | [`quirks-java-artifacts.md`](./quirks-java-artifacts.md) |
| 35 | `getCompoundKey` always Keccak256-hashes; `btcBlockHeight` uses decimal | [`design-divergences.md`](./design-divergences.md) |
| 37 | RSKIP171: no-frame CALL clears the returnDataBuffer (iris300, pairs with §26) | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 38 | `NEW_ACCT_CALL`/`NEW_ACCT_SUICIDE` charge on trie EXISTENCE, not emptiness | [`design-divergences.md`](./design-divergences.md) |
| 40 | RSKIP197: failing precompile CALL handled (push 0, refund surplus) | [`design-divergences.md`](./design-divergences.md) |
| 45 | EXTCODEHASH keys on trie existence, not EIP-161 emptiness | [`design-divergences.md`](./design-divergences.md) |
| 46 | COINBASE returns the real miner, not the gas-fee recipient (REMASC) | [`design-divergences.md`](./design-divergences.md) |
| 50 | Bridge method throw = invisible-exception SUCCESS charging `requiredGas` | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 51 | `registerBtcCoinbaseTransaction` no-op returns vs throws (+51b witness commitment) | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 52 | Flyover response codes are full 256-bit two's complement (+ 21-byte address gate) | [`design-divergences.md`](./design-divergences.md) |
| 53 | Arrowhead600 takes only EIP-2028 from Istanbul | [`design-divergences.md`](./design-divergences.md) |
| 64 | Pegout sig-hash key uses INTERNAL byte order (RSKIP379) | [`consensus-port-log.md`](./consensus-port-log.md) |
| 65 | Nested CREATE/CREATE2 constructor's gas refund is discarded | [`quirks-frozen-bugs.md`](./quirks-frozen-bugs.md) |
| 68 | lovell700 maps to SHANGHAI but none of Berlin/London's gas changes apply | [`design-divergences.md`](./design-divergences.md) |
| 69 | lovell700 TLOAD/TSTORE/MCOPY (RSKIP446/445) despite the SHANGHAI mapping | [`design-divergences.md`](./design-divergences.md) |
| 71 | EIP-3529 also zeroed the SELFDESTRUCT refund — RSK keeps 24000 | [`design-divergences.md`](./design-divergences.md) |
| 72 | EIP-2929: also zero `warm_storage_read_cost` (cold SELFDESTRUCT beneficiary) | [`design-divergences.md`](./design-divergences.md) |
| 73 | EIP-2929 dropped EXTCODECOPY's flat base — re-pin to 700 | [`design-divergences.md`](./design-divergences.md) |
| 76 | Rejected peg-out refund: full wei vs satoshi-truncated (RSKIP427) | [`consensus-port-log.md`](./consensus-port-log.md) |
| 88 | Empty Bridge `byte[]` return ABI-encodes to 96 bytes | [`consensus-port-log.md`](./consensus-port-log.md) |
| — | Discovery NodeTable eviction (liveness, non-consensus) | [`wire-protocol.md`](./wire-protocol.md) |

## Quirks logged with their feature (cross-reference to `consensus-port-log.md`)

A few entries are written up in
[`consensus-port-log.md`](./consensus-port-log.md) because their bulk is an
RSKIP *feature* slice, but each one also turns on a genuine implementation
quirk of the kind this document catalogs. They are summarized here so the quirk
is discoverable from the quirk index; the full feature writeup (rskj citations,
block, replay verification) lives in the port log under the named section.

- **§64 — pegout sig-hash key uses INTERNAL byte order (not reversed).** Every
  other txid-keyed Bridge cell keys on a BTC txid string, which bitcoinj
  produces in *display* (reversed) order via `Sha256Hash.wrapReversed`. But the
  RSKIP379 pegout index keys on `sigHash.toString()`, and that `sigHash` is a
  `hashForSignature`/`Sha256Hash.twiceOf` result stored in **internal** order,
  whose `toString()` is a plain `HEX.encode` with no reversal. A client that
  reused its txid "reverse-then-hex" helper here would key the wrong cell. →
  *§64 in [`consensus-port-log.md`](./consensus-port-log.md).*

- **§76 — rejected peg-out refund is full wei, not satoshi-truncated
  (RSKIP427/lovell700).** Pre-RSKIP427 the refund value is the wei amount
  truncated to satoshi granularity (`Coin.fromBitcoin(value.toBitcoin())`),
  leaving the sub-satoshi remainder in the Bridge; from RSKIP427 the full wei is
  refunded. A truncation/rounding quirk gated on a fork — and a
  receipts-invisible balance fork if you get the gate wrong. →
  *§76 in [`consensus-port-log.md`](./consensus-port-log.md).*

- **§88 — an empty Bridge `byte[]` return ABI-encodes to 96 bytes, not 64.**
  `SolidityType.BytesType.encode` sizes the data section as
  `((len - 1) / 32 + 1) * 32` with Java's truncating integer division; for
  `len == 0`, `-1 / 32 == 0`, so it still emits **one** zero word
  (`offset + length + one zero word` = 96 bytes). Same family as §18, but on the
  Bridge return path, and it forks the *caller* via `RETURNDATASIZE`. →
  *§88 in [`consensus-port-log.md`](./consensus-port-log.md).*

- **§14 / §19 — federation serialization & storage are byte-exact
  (RSKIP123).** Member encoding (`RLP[btcKey, rskKey, mstKey]`, with
  `rsk = mst = btc` for legacy members), member ordering
  (`BTC_RSK_MST_PUBKEYS_COMPARATOR`), and the format-version cell
  (`serializeInteger(1000)` → `0x8203e8`, re-written with the federation's *own*
  version, not always 1000) are all consensus-load-bearing serialization
  choices. Kept with the federation-lifecycle feature rather than next to the
  unitrie encoding rules (§9). → *§14 and §19 in
  [`consensus-port-log.md`](./consensus-port-log.md).*
