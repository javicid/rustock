# RSK Consensus Port Log (RSKIP Feature Slices)

Log of RSKIP-specified features ported to rustock to keep the RSK Mainnet sync
advancing from genesis to tip: bridge peg-in/peg-out handling, federation
lifecycle, SVP, segwit (reed800), Bridge event emissions, and hardfork opcode
installs. Unlike the pure implementation-quirk catalogue in
[`java-compatibility.md`](./java-compatibility.md), these document behavior an
RSKIP *specifies* — a from-scratch client reading the RSKIP would implement them
the same way. Each entry cites the rskj source, names where rustock matches it,
and records the mainnet block where it first mattered plus the replay
verification.

Entries keep their original section numbers from when they lived in
`java-compatibility.md`. Numbering is historical, not sequential, and a few
numbers collide — that predates this split. A handful of entries also carry a
load-bearing implementation quirk (e.g. §64 `sigHash` `toString()` byte order,
§76 wei-vs-satoshi truncation, §88 ABI empty-`bytes` padding) noted inline.

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

### 19a. `saveNewFederation` re-writes the cell with the federation's OWN format version (not always 1000)

**rskj behavior**: `FederationStorageProviderImpl.save()`
(`FederationStorageProviderImpl.java:329-346`) calls `saveNewFederation`
(lines 365-377), which writes `newFederationFormatVersion =
newFederation.getFormatVersion()` (line 375). `getFormatVersion()`
(`Federation.java:66-67`) returns the version the federation was DESERIALIZED
with: `getNewFederation` (lines 109-130) reads the existing
`newFederationFormatVersion` cell via `getStorageVersion` and passes it to
`deserializeFederationAccordingToVersion`
(`BridgeSerializationUtils.java:419-453`), which constructs the federation with
that exact version (1000 STANDARD, 2000 NON_STANDARD_ERP, 3000 P2SH_ERP, 4000
P2SH_P2WSH_ERP); when no cell exists it falls back to STANDARD (1000). So a
re-save round-trips the stored version unchanged.

**Dirtiness asymmetry** (consensus-critical): `saveNewFederation` guards ONLY
on `newFederation == null` — there is NO dirty flag, so a federation merely
READ (cached by `getNewFederation`) is re-serialized and its version cell
re-written on every bridge call that resolves the active federation
(`updateCollections`, `registerBtcTransaction` both do). In contrast,
`saveOldFederation` (lines 379-392) and `savePendingFederation` (403-416) are
guarded by `shouldSaveOldFederation` / `shouldSavePendingFederation`, set ONLY
by `setOldFederation` / `setPendingFederation` (lines 178-182, 210-213) — a
pure read does NOT re-write the old/pending cells. A from-scratch client that
either (a) hardcodes the re-saved newFederation version to 1000, or (b) guards
newFederation writes behind a dirty flag, or (c) re-writes oldFederation on a
read, forks.

**Trigger**: mainnet #4,652,783 — two blocks after the first real
`commitFederation` (#4,652,781) stored an ERP `newFederation` at format **2000**
and a standard `oldFederation` at format **1000**. `updateCollections` +
`registerBtcTransaction` resolve the active federation, so rskj re-writes
`newFederationFormatVersion` = 2000 (unchanged) and leaves
`oldFederationFormatVersion` = 1000 untouched. rustock had hardcoded the
re-saved value to `RLP(1000)`, corrupting the ERP fed's version cell to 1000:
state root mismatch with receipts root matching (pure trie-state divergence,
all gas/logs correct). The federation member-data cell itself is identical
across formats 1000-4000 (multikey serialization is format-independent), so
only the version cell diverged.

**rskj source**: `FederationStorageProviderImpl.saveNewFederation`
/`getNewFederation`/`getFormatVersion`,
`BridgeSerializationUtils.deserializeFederationAccordingToVersion`,
`FederationFactory` (per-type format versions).

**rustock**: `bridge/federation.rs::save_new_federation_multikey` now reads the
existing `newFederationFormatVersion` cell (default 1000 when absent) and
re-writes that same value. Ground-truth test
`federation_format_version_cell_encodings`; verified by both roots of
#4,652,783 matching the mainnet header.

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
`lastRetiredFederationP2SHScript` is the retiring fed's *members* P2SH script —
pre-RSKIP377 this is `getP2SHScript()` (its own type's full redeem), but from
RSKIP377 (fingerroot500, #5,468,000) on, an ERP federation contributes
`ErpFederation.getDefaultP2SHScript()` (the standard / default multisig branch),
not the full ERP P2SH (see §53b).

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

## §53 RSKIP186: `updateFederationCreationBlockHeights` promotes `next`→`active` once the new federation reaches its activation age

After a federation change commits, rskj records
`nextFederationCreationBlockHeight` (= the new federation's creation block) at
handover. Every subsequent `updateCollections` then calls
`FederationSupportImpl.updateFederationCreationBlockHeights`
(`BridgeSupport.updateCollections` line 1050), which — once the new federation
is at least `getFederationActivationAge(activations)` blocks old — does a
**one-time** promotion:

```java
if (currentBlockHeight < nextFederationCreationBlockHeight + activationAge) return;
provider.setActiveFederationCreationBlockHeight(nextFederationCreationBlockHeight);
provider.clearNextFederationCreationBlockHeight(); // saves null -> deletes the cell
```

This is **receipts-invisible** (pure state): no event, no gas change. It rewrites
two Bridge cells — `activeFedCreationBlockHeight` gets set
(`serializeLong = RLP.encodeBigInteger`) and `nextFedCreationBlockHeight` is
deleted. A from-scratch client that skips it forks on the state root at the exact
block the promotion fires, with gas and receipts still matching.

**Mainnet groundtruth (#4,671,284).** The first real federation change committed
at #4,652,781, writing `nextFedCreationBlockHeight = 4_652_781`. Pre-RSKIP383
(fingerroot500) the federation activation age is the legacy `18_500`, so the
threshold is `4_652_781 + 18_500 = 4_671_281`; the first `updateCollections`
at/after it is **#4,671,284** (which is also the first funds-migration block,
since `fundsMigrationAgeBegin = 0`). Before this fix rustock ran the migration
correctly (receipts matched, the migration BTC tx hash in `release_requested`
was byte-identical) but never promoted the creation-height cells, so the state
root forked at #4,671,284 with everything else matching. After implementing the
promotion, both roots match the mainnet header
(`state 0x9c742c96…`, `receipts 0x2912df20…`).

A storage-decode trap surfaced here: the `next` cell holds a *full* RLP encoding
(`rlp_encode_u64` → `0x83 46 fe ed`), so it must be read with `rlp_decode_uint`
(strips the RLP length prefix), **not** `rlp_decode_u64` (which reads raw content
bytes of an already-extracted list element and would return `0x8346feed`).

**rustock.** `crates/execution/src/bridge/governance.rs`
`update_federation_creation_block_heights` (+ `get_next_federation_creation_block_height`),
called from `peg.rs::update_collections` after the confirmed-pegout phase
(rskj order). Clearing `next` stores `&[]`, which `RawStorage::put` maps to a leaf
deletion (matching rskj's null-save). Test
`federation_creation_height_promotion_threshold_4671284`; verified by the
#4,671,284 header roots via `examples/replay_block`.

## §53b RSKIP377: `lastRetiredFederationP2SHScript` is the ERP federation's *default-branch* P2SH (#5,527,682, fingerroot500)

On a federation handover rskj persists the retiring federation's
`lastRetiredFederationP2SHScript` (RSKIP186). The script written is the retiring
fed's *members* P2SH script, computed by
`FederationSupportImpl.getFederationMembersP2SHScript`:

```java
private static Script getFederationMembersP2SHScript(ActivationConfig.ForBlock activations, Federation federation) {
    if (!activations.isActive(RSKIP377)) return federation.getP2SHScript();
    if (!(federation instanceof ErpFederation)) return federation.getP2SHScript();
    // when the federation also has erp keys, the members p2sh script is the default p2sh script
    return ((ErpFederation) federation).getDefaultP2SHScript();
}
```

`ErpFederation.getDefaultP2SHScript()` is the P2SH of the *default redeem script*
— the standard N-of-M multisig branch extracted from the ERP redeem
(`extractStandardRedeemScriptChunks`), NOT the full ERP/CSV-wrapped redeem. So
from RSKIP377 (fingerroot500, #5,468,000) on, the retired-fed P2SH cell stores
the standard-branch hash160, whereas before it stored the full ERP hash160. The
two hash160s differ, so a from-scratch client that always stores
`getP2SHScript()` forks the state trie at the `lastRetiredFedP2SHScript` leaf.

Source: `../rskj/.../federation/FederationSupportImpl.java`
`saveLastRetiredFederationScript` / `getFederationMembersP2SHScript` (lines
755–778); `../rskj/.../federation/ErpFederation.java` `getDefaultP2SHScript` /
`getDefaultRedeemScript` (lines 59–118); `rskip377 = fingerroot500` in
`reference.conf`.

**rustock.** `crates/execution/src/bridge/governance.rs`
`commit_pending_federation`: when `has_rskip377(block_number)` and the retiring
fed's stored format version is ERP (`old_format >= 2000`), the stored
`lastRetiredFederationP2SHScript` is built from
`build_federation_redeem_script(&old_keys, ..)` (the standard branch) rather than
the full ERP `old_redeem`. Gate `hardfork.rs::has_rskip377` (Fingerroot500).
Regression: `peg.rs::tests::rskip377_last_retired_fed_uses_default_branch_p2sh`;
verified by the #5,527,682 state root (`0xa8a232eb…`) via `examples/diff_state`
(0 diverging leaves) and `examples/replay_block` (state + receipts roots match).

## Per-input flyover redeem script in peg-out / migration tx sizing (#4,671,312)

**Consensus-critical implementation quirk.** When the Bridge builds a peg-out or
funds-migration BTC transaction, rskj's spend wallet
(`BridgeUtils.getFederationSpendWallet` / `getRetiringFederationWallet` →
`FlyoverCompatibleBtcWalletWithStorage`) resolves the redeem script **per input**,
not per transaction. A flyover UTXO (one paid into a flyover-federation P2SH,
registered via `registerFastBridgeBtcTransaction`, RSKIP176) is spent with the
*flyover redeem* `PUSH32(derivationHash) OP_DROP <fedRedeem>` — 34 bytes longer
than the plain federation redeem. bitcoinj's fee sizing
(`Wallet.calculateFee` → `estimateBytesForSigning` →
`Script.getNumberOfBytesRequiredToSpend` = `numSigs * SIG_SIZE(75) +
redeemScript.getProgram().length`) and the `USE_OP_ZERO` placeholder scriptSig
both use that input's own redeem. The inner-multisig `numSigs`
(`getNumberOfSignaturesRequiredToSpend`) is unchanged (7 for a 7-of-13 fed): it
is the first `OP_1..OP_16` opcode found in the redeem, *after* the
`PUSH32 OP_DROP` prefix.

A from-scratch client that applies one redeem to every input computes a wrong
unsigned txid (changes the placeholder scriptSig of the flyover input) and a fee
that is 34 bytes (× feePerKb) too low — forking both the stored peg-out tx and
the `release_requested` btcTxHash event topic. This bit the final
funds-migration batch at mainnet #4,671,312 (49 inputs, input #38
`e45ac5168027dc91…:1` a flyover UTXO): rskj txid
`0x99fd3ef49673538e60321a0dca5b5b3ee74b43e9788d98dfe7caed9f429b6d75`, output
17,371,806,971, fee 744,225. The analogous #4,671,284 batch did not fork because
it had >50 standard UTXOs and was capped to 50 standard inputs (RSKIP294).

rskj refs: `BridgeUtils.getFederationsSpendWallet`,
`FlyoverCompatibleBtcWallet.findRedeemDataFromScriptHash` (lookup by output P2SH
hash → `FlyoverFederationInformation{derivationHash, federationRedeemScriptHash}`
→ `getDestinationFederation(redeemHash)` over active+retiring →
`FlyoverRedeemScriptBuilderImpl.of(derivationHash, fedRedeem)`), bitcoinj
`Script.getNumberOfBytesRequiredToSpend`.

**rustock.** `crates/execution/src/bridge/peg.rs`: `resolve_flyover_input_redeems`
reads the stored `fastBridgeFederationInformation-<hex(p2shHash)>` cell
(`get_flyover_federation_information`), matches the stored fed redeem hash against
the active/retiring federation redeems, and rebuilds the flyover redeem
(`flyover_redeem_script`). Both migration (`process_funds_migration`) and regular
peg-out (`update_collections`) pass a per-input `redeem_for` closure to
`complete_pegout_tx` (`release_tx.rs`), which sizes and builds each input's
placeholder scriptSig with its own redeem. `redeem_script_threshold` now finds the
inner `OP_m` opcode (handles flyover/ERP wrappers). Verified: #4,671,312 replays to
`state 0x66b85d7f…`, `receipts 0x2e962f21…`. Test
`flyover_input_sizes_and_signs_with_its_own_redeem` (release_tx.rs).

## Live federation redeem script follows the STORED format version (#4,677,229)

**rskj.** A `Federation` carries a *format version*
(`FederationFormatVersion`: 1000 STANDARD_MULTISIG, 2000 NON_STANDARD_ERP,
3000 P2SH_ERP, 4000 P2SH_P2WSH_ERP). On load,
`BridgeSerializationUtils.deserializeFederationAccordingToVersion` picks the
federation class — and therefore the redeem-script builder — purely from the
stored version, NOT from the current block's activations. So a NON_STANDARD_ERP
federation that outlives RSKIP353 still produces its non-standard ERP redeem
script (and P2SH address); a STANDARD_MULTISIG retiring federation alive during a
migration still uses a plain N-of-M redeem. `getActiveFederation()` /
`getRetiringFederation()` → `Federation.getRedeemScript()` are what
`registerBtcTransaction` (`getNoSpendWalletForLiveFederations`) uses to decide
which outputs pay a federation (peg-in / migration change UTXO) and which inputs
make a tx a peg-out. The NON_STANDARD_ERP builder is itself activation-selected at
*creation* time (`NonStandardErpRedeemScriptBuilderFactory`: testnet pre-RSKIP284
hardcoded, pre-RSKIP293 CSV-unsigned-BE, else generic) — mainnet is always the
non-testnet branch.

This is consensus-load-bearing and receipts-invisible: at mainnet #4,677,229 a
`registerBtcTransaction` migration tx (50 retiring-fed inputs → 1 change output to
the active ERP fed `3DsneJha6CY6X9gU2M9uEc4nSdbYECB4Gh`) registers the change UTXO
into `newFederationBtcUTXOs` only if the active fed's P2SH is reconstructed
correctly. No gas/log/receipt changes — only the `newFederationBtcUTXOs` storage
cell — so the bug surfaces purely as a state-root fork.

rskj refs:
`co.rsk.peg.federation.FederationStorageProviderImpl.getNewFederation/getOldFederation`,
`BridgeSerializationUtils.deserializeFederationAccordingToVersion`,
`co.rsk.peg.federation.FederationFactory`,
`co.rsk.peg.bitcoin.NonStandardErpRedeemScriptBuilderFactory`,
`BridgeSupport.registerBtcTransaction` / `getNoSpendWalletForLiveFederations`.

**rustock.** `crates/execution/src/bridge/peg.rs`: `register_btc_transaction`
previously built both live federation scripts with the plain
`build_federation_redeem_script`, which is wrong for an ERP active federation. Now
`active_federation_keys_and_redeem` / `retiring_federation_keys_and_redeem` read
each federation's `*FederationFormatVersion` cell
(`federation_format_version`, defaulting to 1000 when absent) and dispatch through
`federation_redeem_for_format` (1000 → plain, 2000 → non-standard ERP, 3000/4000 →
P2SH-ERP template). Verified: #4,677,229 replays to state root
`0x093eddb7c21c44d33beb6a0407cdc63759916f82d7e486d69068dfeffff3d1bf`. Test
`federation_redeem_for_format_groundtruth` (peg.rs). KNOWN FOLLOW-UP: the flyover
path (`registerFastBridgeBtcTransaction`, peg.rs ~l.1009) still builds the active
fed redeem with the plain builder — same latent bug, not yet reproduced in sync.

## Spending an ERP federation input: extra OP_0 in the placeholder scriptSig (#4,677,503)

**rskj.** bitcoinj-thin `Script.createEmptyInputScript` builds a P2SH multisig
input placeholder as `OP_0 <OP_0 × m> <redeemScript>`, but when the redeem is an
ERP type (`RedeemScriptParser.hasErpFormat()` — the `OP_NOTIF <default multisig>
OP_ELSE <csv> OP_CSV OP_DROP <emergency multisig> OP_ENDIF` template, optionally
behind a flyover `PUSH32 <hash> OP_DROP` prefix) it inserts an extra `OP_0`
*before* the redeem-script push (`...number(OP_0).addChunk(redeemScript)`). That
`OP_0` is the value `OP_NOTIF` pops to select the default-federation branch. The
peg-out/migration unsigned BTC txid is computed over the tx with these
USE_OP_ZERO placeholders, so a missing flag forks the txid. The fee estimate is
*unaffected*: `Script.getNumberOfBytesRequiredToSpend` = `numSigs·SIG_SIZE +
redeemScript.getProgram().length` and never counts the extra flag byte.

Consensus-load-bearing and only reachable once the active federation is itself an
ERP federation AND a peg-out/migration spends its UTXOs. At mainnet #4,677,503 a
regular peg-out (`updateCollections`) spent the active NON_STANDARD_ERP
federation's UTXOs; rustock's plain-multisig placeholder gave a wrong `release_requested`
btcTxHash (forking both the receipts root via the event and the state root via the
stored `pegoutsWaitingForConfirmations` tx). #4,671,312's migration only *output*
to the ERP fed (a P2SH hash, no scriptSig) and *spent* the plain retiring fed, so
this placeholder path was never exercised until now.

rskj refs: bitcoinj-thin `co.rsk.bitcoinj.script.Script.createEmptyInputScript` /
`isErpType`, `RedeemScriptParserFactory`, `BitcoinUtils.setSpendingBaseScriptLegacy`.

**rustock.** `crates/execution/src/bridge/`: (1) `peg.rs` `update_collections`
peg-out path now resolves the spending federation redeem via
`active_federation_keys_and_redeem` / `retiring_federation_keys_and_redeem` (the
format-version-aware helpers from §the previous fix) instead of the plain
`build_federation_redeem_script`; (2) `release_tx.rs` `placeholder_scriptsig` adds
the extra `OP_0` when `is_erp_redeem` (first opcode `OP_NOTIF`, after an optional
flyover prefix). Verified: #4,677,503 replays to state root
`0x872214f8…` and receipts root `0x40a521c8…`. Test
`erp_placeholder_inserts_op0_before_redeem` (release_tx.rs). FOLLOW-UP: the
`addSignature` path (`update_script_with_signature` / `has_enough_signatures`)
does not yet account for the ERP flag `OP_0` sitting in the signature region —
latent until a federation actually signs an ERP-fed peg-out in a later block.

## Signing an ERP federation peg-out: the OP_NOTIF flag in addSignature (#4,681,515)

**rskj.** `BridgeUtils.countInputScriptSigMissingSignatures` counts unfilled
`OP_0` signature placeholders in `scriptSig[1 .. size - countValuesToSubstract]`,
where `countValuesToSubstract(redeem)` is **1** for a plain redeem (skip the
redeem push) and **2** for an ERP redeem (skip the redeem push AND the trailing
`OP_NOTIF` flag `OP_0`). `hasEnoughSignatures` is true when every input has zero
missing. Signature insertion (`Script.getSigInsertionIndex` /
`ScriptBuilder.updateScriptWithSignature`) keys against
`RedeemScriptParser.getPubKeys()` / `getM()`, which for an ERP redeem expose only
the DEFAULT-federation multisig (the keys before `OP_ELSE`), not the emergency
keys. So a normal peg-out spend reaches "fully signed" after the default-M
signatures land, and `release_btc` is emitted on exactly that `addSignature` call.

Consensus + receipts load-bearing: at mainnet #4,681,515 several federators sign
an ERP-fed peg-out (`releaseRskTxHash` 0x107ed6ef…) across the block. rustock
counted the trailing flag `OP_0` as a missing signature and indexed signatures
against all keys (default + emergency), so it reached threshold two
`addSignature` calls late — emitting `add_signature`/`release_btc` on the wrong
transactions (forking the receipts root) and storing a differently-signed tx in
`pegoutsWaitingForSignatures` (forking the state root).

rskj refs: `BridgeUtils.countInputScriptSigMissingSignatures` /
`countValuesToSubstract` / `hasEnoughSignatures`, bitcoinj-thin
`Script.getSigInsertionIndex` / `getNumberOfSignaturesRequiredToSpend` over the
ERP `RedeemScriptParser`.

**rustock.** `crates/execution/src/bridge/release_tx.rs`: `has_enough_signatures`
and `update_script_with_signature` reserve a 2-chunk suffix (flag + redeem) for
ERP via `input_redeem_is_erp`; `sig_insertion_index` and the
`apply_signatures_to_tx` membership check use new `spending_redeem_keys` (default
keys only — stops before `OP_ELSE`). Verified: #4,681,515 replays to state root
`0x5bb9b0e6…` and receipts root `0xfa93e32b…`. Test
`erp_signing_ignores_op_notif_flag`. This closes the addSignature follow-up noted
in the previous section.

## Special-case funds-migration window end, RSKIP357/374 (#5,009,384)

The funds-migration window is `[activationAge + begin, activationAge + end)`; once
the active federation's age passes the end, `processFundsMigration` calls
`clearRetiredFederation()` (`setOldFederation(null)` — deletes the `oldFederation`
cell, sets `oldFederationFormatVersion = 1000`), a state change with no event.

rskj `FederationConstants.getFundsMigrationAgeSinceActivationEnd(activations)`
returns a **special-case** value while `RSKIP357` is active and `RSKIP374` is not —
i.e. on mainnet between **hop401 (#4,976,300)** and **fingerroot500 (#5,468,000)** —
of **172,800** instead of the normal **10,585** (`FederationMainNetConstants`).
rustock had this as a TODO and used 10,585 unconditionally, so its migration window
ended at age 29,085 (block creation + 29,085) instead of age 191,300. At #5,009,384
the active federation (committed #4,980,299) reached age 29,085, so rustock cleared
the retiring federation (#4,652,781) one window too early — deleting the
`oldFederation` cell and rewriting the version cell — while rskj, still inside the
extended window, left them untouched. Receipts matched (the clear emits nothing);
only the state root forked.

This was subtle to localize precisely because rskj's *latest* source reads as if it
always clears at age ≥ `activationAge + 10585`; the consensus-load-bearing detail is
that `getFundsMigrationAgeSinceActivationEnd` is **activation-gated** and returns the
much larger special-case value for exactly the hop401..fingerroot500 window.

rustock now: `has_rskip357` (hop401 height, per-chain) and `has_rskip374`
(fingerroot500) in `hardfork.rs`, a `special_case_funds_migration_age_end` field in
`BridgeConstants` (mainnet 172,800; testnet 900; regtest 150), and
`process_funds_migration` selects the special-case end when
`has_rskip357 && !has_rskip374`. Verified: #5,009,384 and the whole
#5,009,384..#5,010,600 range replay to matching state+receipts roots. Tests
`test_special_case_funds_migration_window_mainnet`. rskj source:
`FederationConstants.getFundsMigrationAgeSinceActivationEnd`,
`FederationSupportImpl.{getMigrationAgeEnd,isActiveFederationPastMigrationAge,
clearRetiredFederation}`, `BridgeSupport.processFundsMigration`.

## Funds migration spending an ERP retiring federation (#4,998,800)

The ERP-spend fix (#4,677,503) corrected the regular peg-out path
(`processPegoutRequests`) to build the active federation's per-input redeem from
its STORED format version. The **funds-migration** path
(`process_funds_migration` / rskj `BridgeSupport.processFundsMigration` →
`createMigrationTransaction`) spends the **retiring** federation and was still
using the plain multisig builder (`build_federation_redeem_script(&retiring_keys,
threshold)`). This stayed dormant while the retiring federation was a pre-ERP
standard multisig (e.g. the #4,671,312 migration), but at #4,998,800 the retiring
federation is itself a NON_STANDARD_ERP federation: the wrong (plain) per-input
placeholder scriptSig produced a different unsigned migration txid
(`0xd2ec2005…` vs rskj `0x1887b401…`, the `release_requested` topic3), forking
both the receipts root (the event) and the state root (the queued
`pegoutsWaitingForConfirmations` entry). The migrated amount matched, confirming
the divergence was purely the redeem/serialization.

rustock now resolves the retiring federation's spending redeem through
`retiring_federation_keys_and_redeem` (= `getRetiringFederation().getRedeemScript()`,
format-aware: plain / NON_STANDARD_ERP / P2SH-ERP / P2SH-P2WSH-ERP) exactly like
the peg-out path. Verified: #4,998,800 replays to state root `0xae6c0b36…` and
receipts root `0x4c2615f0…`, and the migration txid now equals `0x1887b401…`.
Tests `erp_retiring_federation_migration_redeem_is_not_plain`,
`federation_redeem_for_format_groundtruth`. rskj source:
`co.rsk.peg.BridgeSupport.{processFundsMigration,createMigrationTransaction,
getRetiringFederationWallet}`, `Federation.getRedeemScript()`.

## Classifying a migration that spends the LAST RETIRED federation (#4,683,511)

`registerBtcTransaction` must classify each btc tx exactly as rskj's
`PegUtils.getTransactionType` → `PegUtilsLegacy.getTransactionType` (the legacy
path, pre-RSKIP379 / before the pegout-tx-index grace period) does, because the
chosen `PegTxType` decides the action: `PEGIN` runs `registerPegIn` (credits /
refunds, emits events), `PEGOUT_OR_MIGRATION` runs `registerNewUtxos` (books the
change UTXOs, emits nothing), `UNKNOWN` does nothing (no state change, not even
marking the tx processed).

rskj's legacy classification order (`PegUtilsLegacy.java`):

1. **`txIsFromOldFederation`** (RSKIP199) — any input spends the *hardcoded* old
   federation address (`FederationMainNetConstants.oldFederationAddress =
   "35JUi1FxabGdhygLhnNUEFG4AgvpNMgxK1"`, hash160 `279d4b44…`). Unconditional
   `PEGOUT_OR_MIGRATION`, checked *before* peg-in.
2. **`isValidPegInTx`** → `PEGIN`. Returns false (i.e. *not* a peg-in) when an
   input spends an active fed's P2SH, the `lastRetiredFederationP2SHScript`, or an
   input's standard redeem matches an active fed — so a release/migration never
   leaks into the peg-in path.
3. **`isMigrationTx`** → `PEGOUT_OR_MIGRATION`. `moveFromRetiringOrRetired`: an
   input's *standard* redeem P2SH matches the `lastRetiredFederationP2SHScript`
   **or** the retiring fed's standard P2SH; **and** `moveToActive`:
   `isValidPegInTx` for the active-fed-only wallet (an output funds the active
   federation, all such outputs ≥ minimum pegin under RSKIP293).
4. **`isPegOutTx(liveFederations)`** → `PEGOUT_OR_MIGRATION`. An input's standard
   redeem P2SH matches the active or retiring fed's standard P2SH.
5. else `UNKNOWN`.

Two rskj-implementation details are load-bearing:

- **`extractStandardRedeemScriptFromInput`** — `isPegOutTx`/`isMigrationTx`
  compare against each fed's *standard* (default-branch) redeem, not the full
  redeem. An input spending an ERP or flyover fed carries the wrapped redeem in
  its scriptSig; rskj reduces it via `RedeemScriptParser.extractStandardRedeemScriptChunks()`
  (drop the flyover `PUSH32 OP_DROP` prefix and the `OP_NOTIF…OP_ELSE…OP_ENDIF`
  ERP wrapping, keeping the default `OP_m <keys> OP_n OP_CHECKMULTISIG`). By
  contrast `txIsFromOldFederation` hashes the *full* redeem (`scriptCorrectlySpendsTx`).
- **`getLastRetiredFederationP2SHScript`** (RSKIP186) — a separate storage cell
  (`lastRetiredFedP2SHScript`, `serializeScript = RLP([program])`) written on
  every federation handover (`FederationSupportImpl.saveLastRetiredFederationScript`).
  A tx spending the most-recently-retired federation (which is neither active nor
  retiring) is a migration *only* through this cell.

The #4,683,511 bug: rustock's classifier only knew the active + retiring feds and
used an exact full-redeem equality, so a migration spending the prior **7-of-13
pre-ERP retired federation** (standard P2SH `596cff92…`) and paying the active
5-of-9 ERP fed fell through to the peg-in path and wrongly emitted a
`rejected_pegin` (reason 2, `LEGACY_PEGIN_MULTISIG_SENDER`) + `release_requested`
refund. rskj emitted nothing (`registerNewUtxos`).

rustock now (`peg.rs` `register_btc_transaction`): adds the hardcoded
`old_federation_address_hash160` to `BridgeConstants`; reads the
`LAST_RETIRED_FEDERATION_P2SH_SCRIPT_KEY` cell; reduces each input to its standard
redeem hash160 via `spending_redeem_keys` + `redeem_script_threshold` +
`build_federation_redeem_script`; and replicates the (1)/(3)/(4) `PEGOUT_OR_MIGRATION`
sub-cases (`tx_from_old_fed`, `is_migration` with `move_to_active`,
`spends_live_fed`). Verified: #4,683,511 replays to state root `0x1ff86cce…` and
receipts root `0x775e9e9f…`. Tests
`retired_federation_input_reduces_to_its_standard_p2sh`,
`mainnet_old_federation_address_hash160`.

rskj sources: `co.rsk.peg.PegUtilsLegacy.{getTransactionType,txIsFromOldFederation,
isValidPegInTx,isMigrationTx,isPegOutTx}`, `co.rsk.peg.PegUtils.getTransactionType`,
`co.rsk.peg.federation.FederationStorageProviderImpl.getLastRetiredFederationP2SHScript`,
`co.rsk.peg.federation.FederationSupportImpl.saveLastRetiredFederationScript`.

### Amount-0 peg-in: empty live-fed output set is a valid peg-in (#5,171,600)

`PegUtilsLegacy.isValidPegInTx` decides the minimum-value gate with
`isAnyUTXOAmountBelowMinimum` once **RSKIP293** is active (before it, the legacy
`valueSentToMe.isLessThan(minimum)` total comparison). `isAnyUTXOAmountBelowMinimum`
is `btcTx.getWalletOutputs(wallet).stream().anyMatch(o -> o.getValue() < min)` —
and `anyMatch` over an **empty** stream is `false`. So a tx whose outputs pay
**no live federation** is *not* below minimum, `isValidPegInTx` returns `true`,
and `getTransactionType` classifies it `PEGIN`. `registerBtcTransaction` →
`legacyRegisterPegin` → `processPegInVersionLegacy` then runs with
`computeTotalAmountSent == 0`: `executePegIn` calls `transferTo(dest, 0)` (which
**creates and persists** the destination account — RSK keeps empty touched
accounts, no EIP-161 cleanup), logs `pegin_btc(receiver, amount=0,
protocolVersion=0)`, and `registerNewUtxos` marks the btc tx processed
(`btcTxHashAP-<txid>` = block height). Pre-RSKIP293 a 0 total is below minimum, so
the same tx is `UNKNOWN` and ignored.

This surfaces at mainnet **#5,171,600**: tx[0] (`updateCollections`) completes the
funds-migration window and clears the retiring federation (`85aaffda…` becomes
`lastRetired`); tx[2] (`registerBtcTransaction`, btc tx `d0b25a69…`) then pays
only that now-retired federation 100 000 sat. With the retiring fed gone the
live-fed output set is empty → amount-0 peg-in: `pegin_btc(receiver `06adf228…`,
amount 0)`, account `06adf228…` materialized with balance 0, txid marked
processed.

rustock previously short-circuited `if total_value == 0 { return }` (ignored) and
gated on the *total* (`total_value < min`). It now mirrors rskj
(`peg.rs::pegin_below_minimum`): per-UTXO under RSKIP293, total before it, with an
empty set not below minimum; and an amount-0 peg-in materializes the destination
via `load_account` + `touch_account` (both the legacy and v1 credit paths).
Verified: #5,171,600 replays to state root `0x49eb6920…` and receipts root
`0xf27f4e5d…`, and #5,171,600..#5,172,000 all match. Test
`empty_live_outputs_are_not_below_minimum_under_rskip293`.

rskj sources: `co.rsk.peg.PegUtilsLegacy.{isValidPegInTx,isAnyUTXOAmountBelowMinimum}`,
`co.rsk.peg.BridgeSupport.{registerBtcTransaction,registerPegIn,legacyRegisterPegin,
processPegInVersionLegacy,executePegIn,registerNewUtxos,transferTo}`,
`co.rsk.peg.BridgeStorageProvider.getStorageKeyForBtcTxHashAlreadyProcessed`.

### RSKIP326: promoting a confirmed peg-out logs `pegout_confirmed` (#5,469,495)

`BridgeSupport.processConfirmedPegouts` (`BridgeSupport.java` l.1588-1620) takes
the next peg-out with enough BTC confirmations out of
`pegoutsWaitingForConfirmations`, inserts it into `pegoutsWaitingForSignatures`,
and — **only when `activations.isActive(ConsensusRule.RSKIP326)`** — emits
`eventLogger.logPegoutConfirmed(confirmedPegout.getBtcTransaction().getHash(),
confirmedPegout.getPegoutCreationRskBlockNumber())`. RSKIP326 activates at
**fingerroot500** (`reference.conf`: `rskip326 = fingerroot500`, mainnet
#5,468,000). The event (`BridgeEvents.PEGOUT_CONFIRMED`) is
`pegout_confirmed(bytes32 indexed btcTxHash, uint256
pegoutCreationRskBlockNumber)`: topic0 =
`keccak256("pegout_confirmed(bytes32,uint256)")` =
`0xc287f602476eeef8a547a3b82e79045c827c51362ff153f728b6d839bad099ef`, topic1 =
`btcTxHash.getBytes()` (the confirmed pegout BTC tx's `Sha256Hash`, big-endian
display order), data = the RSK block number at which the pegout was created
(`BridgeEventLoggerImpl.logPegoutConfirmed`, `BridgeEventLoggerImpl.java`
l.290-301).

This surfaces at mainnet **#5,469,495**, the first fingerroot500 block whose
`updateCollections` (tx[1], Bridge `0x…01000006`) promotes a confirmed pegout
(created at #5,465,490 = `0x536592`). rskj's tx[1] receipt has **two** logs —
`release_request_received` then `pegout_confirmed` — but rustock only emitted the
first, so the receipts root diverged (state root matched, since promotion state
is unchanged). rustock now mirrors rskj: after inserting into the
waiting-for-signatures set, `peg.rs::process_confirmed_pegouts` emits
`log_pegout_confirmed` (`events.rs`) when `has_rskip326(block_number)` holds. The
btcTxHash uses `btc_txid_event_bytes` (display-order `getHash()`) over the entry's
deserialized `btc_tx_raw`. Verified: #5,469,495 replays to receipts root
`0xb90b67bb…` (== header) with state root unchanged `0xd97a4083…`. Test
`pegout_confirmed_matches_mainnet_5469495`.

rskj sources: `co.rsk.peg.BridgeSupport.processConfirmedPegouts`,
`co.rsk.peg.utils.BridgeEventLoggerImpl.logPegoutConfirmed`,
`co.rsk.peg.BridgeEvents.PEGOUT_CONFIRMED`,
`org.ethereum.config.blockchain.upgrades.ConsensusRule.RSKIP326`.

### Peg-out fee-minimum sizing: RSKIP271 size formula + active-federation redeem (#5,927,135)

`BridgeSupport.requestRelease` (`BridgeSupport.java` l.954-1011) rejects a
peg-out below `max(minimumPegoutTxValue, requireFundsForFee)`, where
`requireFundsForFee = feePerKB * getRegularPegoutTxSize(activations,
getActiveFederation()) / 1000`, grown by
`minimumPegoutValuePercentageToReceiveAfterFee`. Two consensus-critical inputs to
that size estimate were wrong in rustock:

1. **RSKIP271 changed the size formula.** `BridgeUtils.getRegularPegoutTxSize`
   (`BridgeUtils.java` l.625-672) dispatches on `RSKIP271`: pre-271 it uses
   `BridgeUtilsLegacy.calculatePegoutTxSize` (an analytic script-sig-chunk
   approximation); post-271 it uses `calculateLegacyTxSize`, the **exact**
   `BtcTransaction.bitcoinSerialize()` length of a 2-in/2-out legacy tx whose
   inputs carry the redeem script as their scriptSig and whose outputs are the
   23-byte P2SH-to-federation script, plus `numberOfSignaturesRequired *
   inputsCount * 72`. (Mainnet federations are never segwit at the heights
   rustock handles, so only the legacy branch applies.) rustock only ever
   implemented the pre-271 path, so it computed a *smaller* size — hence a
   smaller fee minimum.
2. **The redeem script must be the ACTIVE federation's actual (ERP) redeem.**
   rskj passes `getActiveFederation()`, whose `getRedeemScript()` is
   format-aware; post-fingerroot500 the active federation is a P2SH-ERP
   federation with a much larger redeem than a plain N-of-M multisig. rustock was
   rebuilding a plain multisig redeem from the keys, again undersizing.

Net effect at mainnet **#5,927,135** (fingerroot500 active, RSKIP271 long
active): tx[0] is a 459,876-satoshi peg-out. rskj's correct
`requireFundsForFee` exceeds 459,876, so the value is **below** the minimum and
rskj rejects it with `FEE_ABOVE_VALUE` — refunding the (satoshi-truncated) value
to the sender, emitting `release_request_rejected`, and leaving
`releaseRequestQueueWithTxHash` empty (`0xc0`). rustock's undersized estimate put
the minimum below 459,876, so it *accepted* the peg-out: it enqueued the request,
emitted `release_request_received`, and kept the value in the Bridge. That
diverged three leaves (sender balance, Bridge balance, the release queue) plus
the receipts root.

Fix (`peg.rs`): `regular_pegout_tx_size` now takes the redeem script + required
signatures + the `RSKIP271` flag and emits the exact post-271
`bitcoinSerialize()` length (legacy branch); `require_funds_for_fee` threads
those through; `release_btc` sources the redeem from
`active_federation_keys_and_redeem` (format-aware, == rskj
`getActiveFederation().getRedeemScript()`). Verified: #5,927,135 replays to state
root `0xd3dedc66…` and receipts root `0x9f865614…` (both == header), zero
diverging leaves. Ground truth ported in `regular_pegout_tx_size_matches_rskj`
(rskj `BridgeUtilsTest.testCalculatePegoutTxSize_2Inputs_2Outputs` = 2058 bytes).

rskj sources: `co.rsk.peg.BridgeSupport.requestRelease`,
`co.rsk.peg.BridgeUtils.getRegularPegoutTxSize` /
`calculatePegoutTxSize` / `calculateLegacyTxSize`,
`co.rsk.peg.BridgeUtilsLegacy.calculatePegoutTxSize`,
`org.ethereum.config.blockchain.upgrades.ConsensusRule.RSKIP271`.

## Flyover (RSKIP176) peg-in: RSKIP293 retiring-federation path (hop400)

rskj `BridgeSupport.registerFlyoverBtcTransaction`
(`../rskj/rskj-core/src/main/java/co/rsk/peg/BridgeSupport.java:2712-2899`) builds
the flyover federation information for the ACTIVE federation always, and — when
RSKIP293 is active AND a retiring federation exists — ALSO for the RETIRING
federation (`createFlyoverFederationInformation(hash, retiringFed)`,
lines 2786-2801, 2975-2989). The retiring fed's flyover redeem is
`PUSH(derivationHash) OP_DROP <retiringFed.getRedeemScript()>` — i.e. the
FORMAT-AWARE redeem (an ERP retiring fed gets its ERP redeem), and the output
script is a plain P2SH for every federation format except P2SH-P2WSH-ERP
(`PegUtils.getFlyoverFederationOutputScript`, `PegUtils.java:350-356`).

Consensus-load-bearing details rustock matches in
`crates/execution/src/bridge/peg.rs` `register_fast_bridge_btc_transaction`:

- **Value gate over BOTH feds.** `validateFlyoverPeginValue` /
  `getAmountSentToAddresses` (`BridgeUtils.java:148-214`) sum the outputs paying
  ANY flyover address (active + retiring under RSKIP293). A zero total returns
  `-304` (`UNPROCESSABLE_TX_VALUE_ZERO_ERROR`). Under RSKIP293 it then rejects
  the tx with `-305` (`UNPROCESSABLE_TX_UTXO_AMOUNT_SENT_BELOW_MINIMUM_ERROR`) if
  ANY flyover UTXO is strictly below `getMinimumPeginTxValue`
  (`PegUtils.allUTXOsToFedAreAboveMinimumPeginValue` → pre-RSKIP379
  `PegUtilsLegacy.isAnyUTXOAmountBelowMinimum`, `PegUtilsLegacy.java:362-371` —
  the path that applies at hop400, since RSKIP379/fingerroot500 is later). An
  EMPTY flyover-output set is NOT below minimum (`anyMatch` over an empty stream
  is false), but the separate total==0 gate (`-304`) covers a no-output tx.
- **UTXO registration.** Active flyover UTXOs go to the active federation set
  (`getActiveFederationBtcUTXOs`); retiring flyover UTXOs go to the retiring
  (OLD) set (`getRetiringFederationBtcUTXOs` →
  `FederationSupportImpl.java:296-302` → `OLD_FEDERATION_BTC_UTXOS_KEY`). rskj
  only persists the retiring data when `utxosForRetiringFed` is NON-empty
  (`BridgeSupport.java:2868-2891`); rustock guards the retiring branch the same
  way (`btc_tx.output.iter().any(|o| o.script_pubkey == retiring_flyover_script)`).
- **Flyover federation information storage.** Both active and retiring use the
  SAME key scheme: `setFlyoverFederationInformation` /
  `setFlyoverRetiringFederationInformation` both call
  `saveFlyoverFederationInformation` keyed by `fastBridgeFederationInformation-`
  + hex(ITS flyover-redeem hash160) (`BridgeStorageProvider.java:461-499`,
  `:826`). rustock reuses `set_flyover_federation_information` for both, passing
  the retiring fed's own flyover P2SH hash.
- **markFlyoverDerivationHashAsUsed twice.** Both
  `saveFlyoverActiveFederationDataInStorage` and
  `saveFlyoverRetiringFederationDataInStorage` call
  `markFlyoverDerivationHashAsUsed(btcTxHashWithoutWitness, derivationHash)`
  (`BridgeSupport.java:3020-3040`). It is idempotent (writes a single TRUE byte
  under the same key), but rustock issues the call in both branches to mirror
  rskj exactly.
- **Locking-cap rejection refund spans BOTH feds.**
  `generateFlyoverRejectionReleaseWithWalletProvider` builds ONE empty-wallet
  refund over a `FlyoverCompatibleBtcWalletWithMultipleScripts` containing both
  flyover feds (`BridgeSupport.java:2825-2845, 2991-3011`), so each input is
  signed/sized with its OWN flyover redeem. rustock resolves per-input redeems
  and falls back to the shared single-redeem `release_tx::build_empty_wallet_to`
  when uniform, else `build_flyover_empty_wallet_multi` (a per-input-redeem
  mirror of bitcoinj `buildEmptyWalletTo`).

- **Active-fed flyover redeem is FORMAT-AWARE (fixed at #5,831,167).**
  `createFlyoverFederationInformation(hash)` derives the active flyover P2SH from
  `getActiveFederation().getRedeemScript()` (`BridgeSupport.java:2971-2989`), which
  follows the fed's STORED format version. At fingerroot500 the active fed is a
  P2SH-ERP federation (RSKIP353), so the flyover redeem must wrap the ERP redeem,
  not a plain multisig. rustock previously built the active flyover redeem with
  `build_federation_redeem_script` (standard multisig); the resulting P2SH
  `5f4fb7…` did not match the address the BTC tx paid (`69206b97…`), so
  `getAmountSentToAddresses` summed 0, `registerFastBridgeBtcTransaction` returned
  `UNPROCESSABLE_VALUE_ZERO` (-304) instead of the locked amount, and the calling
  LiquidityBridgeContract took the failure branch — over-charging 6,817 gas
  (216,145 vs the header's 209,328). Fixed by switching the active path to
  `active_federation_keys_and_redeem` (format-aware, the same builder the retiring
  path already used). rustock `bridge/peg.rs::register_fast_bridge_btc_transaction`;
  regression `flyover_active_p2sh_uses_erp_redeem_5831167`.

---

## §54 RSKIP415: the `add_signature` event's `federatorRskAddress` topic derives from the federation member's RSK key, not its BTC key (arrowhead600, #6,223,700)

**Symptom**: full-mainnet sync halted at **#6,223,704** with a receipts-root
mismatch while the state root and total gas matched exactly. The first
`addSignature` Bridge call after arrowhead600 (#6,223,700) produced an
`add_signature(bytes32 indexed releaseRskTxHash, address indexed
federatorRskAddress, bytes federatorBtcPublicKey)` log whose second topic
diverged: rustock emitted `0xa50367d690e4bf2707398c62d71d4878c356290f`, the
canonical receipt had `0xb6ffeeaa2eecaaf865d5539b85976d5892f59ab5`.

**rskj behavior**: `BridgeEventLoggerImpl.logAddSignature` resolves the federator
RSK address via `getFederatorRskPublicKey(member)`:

```java
private ECKey getFederatorRskPublicKey(FederationMember m) {
    if (!shouldUseRskPublicKey()) {                       // pre-RSKIP415
        return ECKey.fromPublicOnly(m.getBtcPublicKey().getPubKey());
    }
    return m.getRskPublicKey();                            // post-RSKIP415
}
private boolean shouldUseRskPublicKey() {
    return activations.isActive(ConsensusRule.RSKIP415);
}
```

Before RSKIP415 the topic address is keccak(uncompressed BTC pubkey)[12..];
after, it is keccak(uncompressed **RSK** pubkey)[12..]. A `FederationMember`
carries distinct btc/rsk/mst keys (RSKIP123 multikey format), so for members
whose RSK key differs from their BTC key the two addresses differ. The event
*data* (the federator BTC public key) is unchanged across the fork. RSKIP415 is
gated at `arrowhead600` in `reference.conf` (`rskip415 = arrowhead600`), which is
why the divergence appears 4 blocks after activation, at the first post-fork
`addSignature`.

**rskj source**: `co.rsk.peg.utils.BridgeEventLoggerImpl#getFederatorRskPublicKey`
/ `#logAddSignatureInSolidityFormat`, `co.rsk.peg.BridgeEvents.ADD_SIGNATURE`,
`org.ethereum.config.blockchain.upgrades.ConsensusRule.RSKIP415`,
`reference.conf` (`rskip415 = arrowhead600`).

**rustock**: `crates/execution/src/hardfork.rs` (`has_rskip415` → Arrowhead600);
`crates/execution/src/bridge/peg.rs` (`add_signature` precompile: new helper
`federator_rsk_key_for_btc` looks up the signing member in the active then
retiring federation and returns its stored RSK key; the emission picks the RSK
key when `has_rskip415` and the BTC key otherwise — legacy single-key members
have rsk == btc, so pre-fork behavior is unchanged). The event *data* always
carries the BTC public key. Test:
`bridge::federation::tests::rskip415_add_signature_federator_address_groundtruth_6223704`
(BTC key 02a95f…c8cbdb → 0xa50367… ≠ canonical 0xb6ffeeaa…). Verified by
replaying #6,223,704: receipts root now matches
`0xca1927a8…817c58` and state root still matches `0xe82eca71…45aa9`; blocks
#6,223,704–#6,223,707 replay clean.

## §55 RSKIP415: REMASC's federation payout pays each federator's RSK-key address, not its BTC-key address (arrowhead600, #6,223,708)

**Symptom**: with §54 fixed, the next divergence was a **state-root** mismatch at
**#6,223,708** (gas 0, receipts matched) — a near-empty block whose only state
change was REMASC's per-block federation fee payout. The fees were credited to
the wrong RSK addresses.

**rskj behavior**: REMASC distributes the federation's cut across federator RSK
addresses obtained from `RemascFederationProvider.getFederatorAddress(n)`, which —
exactly like §54 — switches key type on RSKIP415:

```java
public RskAddress getFederatorAddress(int n) {
    if (!activations.isActive(ConsensusRule.RSKIP415)) {
        return getRskAddressFromBtcKey(n);   // keccak(uncompressed BTC pubkey)
    }
    return getRskAddressFromRskKey(n);       // keccak(uncompressed RSK pubkey)
}
```

The activation is gated on the **execution** block, not the matured/processing
block REMASC rewards: `Remasc.activations = activationConfig.forBlock(execution
Block.getNumber())` (`Remasc.java:89`), and that `ForBlock` is what the
`RemascFederationProvider` consults. The *which* federation is still resolved at
the processing (matured) height. For members whose RSK key differs from their BTC
key, the payout addresses change at the fork.

**rskj source**: `co.rsk.remasc.RemascFederationProvider#getFederatorAddress` /
`#getRskAddressFromBtcKey` / `#getRskAddressFromRskKey`,
`co.rsk.remasc.Remasc` (`activations = activationConfig.forBlock(executionBlock
.getNumber())`, `payToFederation`), `ConsensusRule.RSKIP415`,
`reference.conf` (`rskip415 = arrowhead600`).

**rustock**: `crates/execution/src/bridge/federation.rs` (`StoredFederation::
rsk_keys()` — the RSK field of each member; legacy single-key members have
rsk == btc); `crates/execution/src/bridge/peg.rs` (`federation_keys_or_genesis`
gains a `want_rsk` flag selecting `rsk_keys()` vs `btc_keys()`);
`crates/execution/src/remasc.rs` (`federation_rsk_addresses` /
`pay_to_federation` thread the **execution** block number `current_number` and
pass `has_rskip415(current_number)` as `want_rsk`, while the federation is still
resolved at `processing_block_number`). The `add_signature` membership check (§54
path) passes `want_rsk = false` — it only needs the BTC keys. Test:
`bridge::federation::tests::rsk_keys_selects_rsk_field_and_legacy_equals_btc`.
Verified by replaying #6,223,708: state root now matches
`0x6a4ed424…f3fb8f`; blocks #6,223,704–#6,223,776 replay clean (next blocker at
#6,223,777, unrelated).

## Bridge `receiveHeader` gas: must include the `data.length * 2` cost (#6,223,762)

rskj computes the Bridge precompile's `requiredGas` once, in
`Bridge.getGasForData(data)`, as `functionCost + data.length * 2` for **every**
parsed method (the per-byte data cost is added uniformly, not per-method):

```java
// co.rsk.peg.Bridge#getGasForData (Bridge.java:296-321)
functionCost = bridgeParsedData.bridgeMethod.getCost(this, activations, args);
int dataCost = data == null ? 0 : data.length * 2;
totalCost   = functionCost + dataCost;
```

For `receiveHeader(bytes)` the `functionCost` is the fixed `10_600`
(`BridgeMethods.RECEIVE_HEADER`), so the precompile cost is
`10_600 + 2 * data.length`.

**Consensus-critical implementation quirk.** rustock's `execute_bridge`
correctly pre-computes this total in `bridge_call_gas_cost`
(`functionCost + 2 * input.len()`) and passes it to `execute_method` as
`gas_cost`. Every method handler used that `gas_cost` as its
`PrecompileOutput` gas — **except** `receive_header`, which discarded the
argument and hardcoded the bare `10_600` function cost, dropping the
`data.length * 2` term. A from-scratch reading of the per-method cost table
(which lists `receiveHeader = 10_600`) without applying the uniform per-byte
add reproduces this exact undercharge.

Mainnet #6,223,762 tx[2] (a CALL to `0x82494f…449d9`, selector `0x89b1b965`,
which forwards a 164-byte `receiveHeader(bytes)` payload to the Bridge) exposed
it: rskj charges the precompile `10_600 + 2*164 = 10_928`, rustock charged
`10_600`, undercharging by **328 gas**. The tx's `gasUsed` was therefore 35_228
instead of 35_556 (its gas limit), and the 328 × gasPrice fee that should have
gone to REMASC instead stayed with the sender — forking the state root.

**rskj source**: `co.rsk.peg.Bridge#getGasForData` (Bridge.java:296-321),
`co.rsk.peg.BridgeMethods.RECEIVE_HEADER` (fixed cost 10_600).

**rustock**: `crates/execution/src/bridge/btc_chain.rs` (`receive_header` now
takes the caller-computed `gas_cost` instead of hardcoding 10_600);
`crates/execution/src/bridge/mod.rs` (`execute_method` passes `gas_cost` to
`receive_header`, matching every other method). Test:
`bridge::tests::receive_header_gas_includes_data_cost`. Verified by replaying
#6,223,762: tx[2] gasUsed = 35_556, state root and receipts root both match
`0x06bf9670…6dd5` / `0x7562cb6f…72dc`.

## Bridge `receiveHeaders` is a void method — empty return data (RSKIP417 era)

`receiveHeaders(bytes[])` is declared with **no outputs**
(`BridgeMethods.RECEIVE_HEADERS` output array is `{}`, executor is
`BridgeMethodExecutorVoid`). `Bridge.execute` therefore returns the *void
value* — `null` before RSKIP417 and `EMPTY_BYTE_ARRAY` after
(`Bridge.calculateVoidReturnValue` / `shouldReturnNullOnVoidMethods =
!RSKIP417`). Both give the caller `RETURNDATASIZE == 0`
(`Program.getReturnDataBufferSizeI` maps null → 0).

rustock's `receive_headers` returned a 32-byte ABI int (the processed-header
count). A calling contract that ABI-decodes the return then sees 32 bytes
where rskj sees 0, taking a different code path. Mainnet **#6,223,768 tx[0]**
(relay `0x82494fb1…449d9` forwards `receiveHeaders`) OOG'd in rustock vs
SUCCESS in rskj because of the extra returned word.

**rskj source**: `co.rsk.peg.BridgeMethods.RECEIVE_HEADERS` (void),
`co.rsk.peg.Bridge#execute` / `#calculateVoidReturnValue` (Bridge.java:417-486),
`Program#getReturnDataBufferSizeI` (returns 0 for null).
**rustock**: `crates/execution/src/bridge/btc_chain.rs` (`receive_headers`
returns `Bytes::new()`).

## Bridge `receiveHeader` result codes must match rskj exactly

rskj `BridgeSupport.receiveHeader` returns specific integers a caller branches
on: success `0`, `RECEIVE_HEADER_CALLED_TOO_SOON = -1`,
`RECEIVE_HEADER_BLOCK_TOO_OLD = -2`,
`RECEIVE_HEADER_CANT_FOUND_PREVIOUS_BLOCK = -3`,
`RECEIVE_HEADER_BLOCK_PREVIOUSLY_SAVED = -4`,
`RECEIVE_HEADER_UNEXPECTED_EXCEPTION = -99` (BridgeSupport.java:96-100, 227-270).
rustock previously used a different, incompatible set (`SUCCESS = 1`,
`ALREADY_KNOWN = -1`, `TOO_SOON = -2`, a fabricated `INVALID_POW = -5`) and was
missing the block-too-old (`maxDepthBlockchainAccepted`) and
`cannotProcessNextBlock` checks. The check order also differs: rskj tests
already-saved **before** the time window.

**rskj source**: `co.rsk.peg.BridgeSupport#receiveHeader` /
`#cannotProcessNextBlock` (BridgeSupport.java:227-279).
**rustock**: `crates/execution/src/bridge/btc_chain.rs` (`receive_header`
constants + reordered checks). Test:
`bridge::tests::receive_header_result_codes_match_rskj`.


## Bridge ABI `bytes[]` / dynamic-bytes decoding must not panic on bad input

A malformed Bridge call can supply ABI offsets/lengths that don't fit in a
`usize`. rustock's `parse_bytes_array` and `read_dynamic_bytes`
(`crates/execution/src/bridge/peg.rs`) used `U256::to::<usize>()`, which panics
on overflow. Mainnet **#6,223,783 tx[3]** forwards malformed `addSignature`
calldata whose `signatures` array offset lands in the middle of the federator
key, yielding a `~uint256::MAX` element count → panic. rskj's Solidity decoder
rejects such inputs gracefully; rustock now treats any out-of-range length as a
parse failure (empty result), matching that behavior.

**rustock**: `crates/execution/src/bridge/peg.rs` (`parse_bytes_array` and
`read_dynamic_bytes` use checked `usize::try_from`). Tests:
`bridge::tests::parse_bytes_array_rejects_oversized_count_without_panic`,
`bridge::tests::read_dynamic_bytes_rejects_oversized_length`.

## Bridge federation-only authorization (`activeAndRetiringFederationOnly`)

`updateCollections` (always) and `receiveHeaders` (when not public, i.e.
post-RSKIP200 — `receiveHeadersIsPublic = RSKIP124 && !RSKIP200`) wrap their
executor in `Bridge.activeAndRetiringFederationOnly`, which throws a
`VMException` unless the call's sender is a member of the **active or retiring**
federation (`BridgeUtils.isFromFederateMember`, comparing the sender's RSK
address against each member's `getRskPublicKey().getAddress()`). The "sender"
is the immediate caller of the Bridge precompile (rskj builds the precompile's
`internalTx` with `senderAddress = getOwnerRskAddress()`), so a **relay contract
forwarding the call is checked by its own address**, not the original EOA. On
rejection, `Program.executePrecompiledAndHandleError` rolls back (no state
change, no events) and the CALL returns 0 while charging the full `requiredGas`.

rustock had no such check, so a non-federation caller's `updateCollections` ran
and emitted the `update_collections` event. Mainnet **#6,223,774 tx[1]**
(relay `0x82494fb1…449d9`, not a federation member) must emit **zero** logs.

**rskj source**: `co.rsk.peg.Bridge#activeAndRetiringFederationOnly`,
`#validateCallMessageType`; `co.rsk.peg.BridgeMethods.UPDATE_COLLECTIONS` /
`.RECEIVE_HEADERS`; `BridgeUtils#isFromFederateMember`;
`Program#callToPrecompiledAddress` (internalTx sender = owner).
**rustock**: `crates/execution/src/bridge/mod.rs` (`execute_method`
federation-only gate), `crates/execution/src/bridge/peg.rs`
(`is_sender_active_or_retiring_fed_member`),
`crates/execution/src/hardfork.rs` (`has_rskip200`). Tests:
`executor::tests::update_collections_burns_dusty_change_surplus` (member),
`executor::tests::update_collections_rejected_for_non_federation_sender`.


## §59 Bridge parseData ABI-decodes all args: a malformed payload is a parse failure (#6,223,797)

rskj computes a Bridge call's `requiredGas` in `Bridge.getGasForData`
(Bridge.java:303-322): it calls `parseData(data)`, which ABI-**decodes every
argument** via `CallTransaction.Function.decode` (CallTransaction.java:409) and,
on **any decode exception**, returns `null` (Bridge.java:344-347). A `null`
parse result is charged the flat `RELEASE_BTC` cost — **23_000, with no
`data.length*2` term** — and `Bridge.execute` turns it into a
`BridgeIllegalArgumentException` throw (post-RSKIP88). The Solidity decoders
throw whenever a read runs past the payload: `Utils.safeCopyOfRange` /
`validateArrayAllegedSize` raise when `data.length < offset + size`
(`SolidityType.java`, `Utils.java`), `IntType.decodeInt` special-cases an empty
payload as `0`, and offsets/lengths come from `BigInteger.intValue()`
(low-32-bit signed).

**Consensus-critical implementation quirk.** A client that parses each
argument lazily inside its method handler — and computes gas from the matched
method's own cost — never observes the decode failure: it charges the full
method cost (with the per-byte data term) instead of the flat 23_000, and
executes the method instead of throwing. Mainnet **#6,223,797 tx[3]** exposes
this: a relay (`0x8dd4b03b…`) forwards `receiveHeaders(bytes[])` whose `bytes[]`
head offset is `0xa0` (160) into a 60-byte argument tail. rskj's decode throws
→ parse failure → `requiredGas = 23_000` → the internal CALL consumes 23_000
(refunding the surplus, leaving the relay 87 gas to finish its post-call path
and RETURN successfully). rustock matched the selector to `receiveHeaders`,
computed `25_000 + 2*64 = 25_128`, found `25_128 > 23_087` forwarded, and
treated it as out-of-gas — the relay OOG'd (tx status flipped true→false),
forking the receipts root.

**rustock**: `crates/execution/src/bridge/mod.rs` — `abi_args_decode_ok`
replicates rskj's decoder bound checks (`abi_decode_int` / `abi_decode_value_ok`
mirror `IntType.decodeInt` / `safeCopyOfRange` / `DynamicArrayType.decode` /
`BytesType.decode`); `execute_bridge` adds a `.filter(|m| abi_args_decode_ok(…))`
so a matched-but-undecodable method falls into the parse-failure branch, and
that branch's internal-call (depth>1) arm now returns the
`INTERNAL_BRIDGE_THROW_MARKER` carrying the flat 23_000 (consume `requiredGas`,
push zero, refund the surplus, caller continues) instead of consuming all the
forwarded gas. The depth-1 arm keeps the invisible-exception semantics. Also
relevant: the Bridge insufficient-gas path (`requiredGas > forwarded`, §-this)
now mirrors rskj `Program.callToPrecompiledAddress` (Program.java:1567-1573):
for an internal call it pushes zero and the caller continues
(`INSUFFICIENT_GAS_MARKER`) rather than propagating OOG. Tests:
`bridge::tests::abi_decode_rejects_out_of_bounds_array_offset`,
`bridge::tests::abi_decode_accepts_wellformed_array`. Verified by replaying
#6,223,797: tx[3] status=true, state and receipts roots match; exec-head→
#6,223,811 replays clean.

## §60 Bridge validateCallMessageType: reject DELEGATECALL/CALLCODE (and STATICCALL for tx methods) (#6,223,812)

After charging `requiredGas`, rskj `Bridge.execute` runs `validateCall` →
`validateCallMessageType` (Bridge.java:446-456), which throws
`BridgeIllegalArgumentException` when a method is reached via a call type it does
not accept. Each `BridgeMethods` entry carries a `callTypeVerifier`
(BridgeMethods.java:1002-1067): the **default is `RESTRICTED_TO_CALL`** (only
`MsgType.CALL`); the read-only getters add `ALLOW_STATIC_CALL` (CALL or
STATICCALL). **No method accepts `DELEGATECALL` or `CALLCODE`.** The throw is
caught by `executePrecompiledAndHandleError`, which consumes the method's
`requiredGas`, pushes zero (the CALL returns 0) and refunds the surplus.

**Consensus-critical implementation quirk.** A client that simply dispatches the
matched method regardless of the EVM call type runs it and returns its output,
so the caller observes a non-empty `RETURNDATASIZE` (and any state changes)
where rskj observed an empty, failed CALL. Mainnet **#6,223,812 tx[0]**: a relay
(`0x84e59b00…`) reaches the Bridge via **DELEGATECALL** (`f4`) of
`receiveHeader`; rskj rejects it (`RETURNDATASIZE == 0`), so the relay takes its
"call failed" branch and RETURNs successfully. rustock executed `receiveHeader`,
returned the 32-byte `int256` result, so `RETURNDATASIZE == 32`, the relay took
the other branch, and tx[0]'s status flipped (true→false), forking the receipts
root.

**rustock**: `crates/execution/src/bridge/mod.rs` — `BridgeCallKind`
(Call/StaticCall/DelegateOrCallCode, mapped from revm `CallScheme` in
`run_bridge`), `method_allows_static_call` (the rskj `ALLOW_STATIC_CALL` getter
list), and `execute_bridge` rejects an unaccepted call type after computing
`gas_cost` — depth>1 via `INTERNAL_BRIDGE_THROW_MARKER` (consume `requiredGas`,
CALL returns 0, refund surplus), depth-1 via the invisible-exception marker. The
direct-transaction path (`executor.rs`) always passes `BridgeCallKind::Call`.
Test: `bridge::tests::call_type_acceptance_matches_rskj`. Verified by replaying
#6,223,812: tx[0] status=true, state and receipts roots match; exec-head→
#6,223,899 replays clean.

## §61 Bridge validateLocalCall: a local-only getter rejects any on-chain call (#6,223,900)

rskj `Bridge.execute` runs `validateCall` (Bridge.java:426) which, **before**
`validateCallMessageType`, runs `validateLocalCall` (Bridge.java:431). Post-RSKIP88,
when the call is **not a local call** (`!isLocalCall()`) and the method
`onlyAllowsLocalCalls`, it throws `BridgeIllegalArgumentException`. `isLocalCall()`
is `rskTx.isLocalCallTransaction()` (Bridge.java:1646) — **true only for the
synthetic transaction `eth_call` builds**; every transaction and every on-chain
`CALL`/`STATICCALL` during block execution is non-local. So a **local-only**
Bridge getter invoked on-chain *always* throws here. The throw is not caught by
the inner `try` around `executeBridgeMethod` (it sits at Bridge.java:405, outside
407-414), so it propagates to the outer `catch` → `VMException`, which consumes
the method's `requiredGas` (`getGasForData` = functionCost + data.length·2) and
the CALL returns **empty** (`RETURNDATASIZE == 0`).

`BridgeMethods.onlyAllowsLocalCalls` (BridgeMethods.java:1107) is a fixed
`true`/`false` per method (`fixedPermission`) except
`getBtcBlockchainBestChainHeight`, whose
`getBtcBlockchainBestChainHeightOnlyAllowsLocalCalls` (Bridge.java:700) returns
`!RSKIP220` — local-only before Iris300, tx-callable after.

**Consensus-critical implementation quirk.** A from-scratch client that dispatches
a getter whenever its selector/ABI/gas check out will *execute* it on-chain and
return its encoded value, so the caller sees non-empty `RETURNDATASIZE` where rskj
saw an empty, "failed" CALL — even though **both spend the identical
`requiredGas`** (the method never runs in rskj, but `requiredGas` is charged
either way), making the divergence invisible to a gas-only check. Mainnet
**#6,223,900 tx[4]**: a relay (`0x395911ee…`) plain-`CALL`s
`getFederationAddress()` (local-only). rskj empties it (`RETURNDATASIZE == 0`), so
the relay takes its early-return branch and the tx succeeds (`gasUsed 34304`).
rustock executed the getter and returned 1056 bytes, so the relay took the
"process return data" branch and ultimately reverted consuming all 34709 gas —
flipping tx[4] status and forking both roots.

**rustock**: `crates/execution/src/bridge/mod.rs` —
`method_only_allows_local_calls(permission, hardfork_cfg, block_number)` mirrors
the rskj permission (LocalOnly → always; DynamicRskip220 → `< Iris300`;
TransactionCallable → never). `execute_bridge` checks it **after** computing
`gas_cost` and **before** the `validateCallMessageType` check (rskj's
`validateCall` order), returning the depth-aware bridge-throw marker (depth>1 →
`INTERNAL_BRIDGE_THROW_MARKER`, depth-1 → invisible-exception), each recording
exactly `requiredGas`. Block execution never sets a local-call flag (the only
`execute_bridge` callers are the direct-tx path in `executor.rs` and internal
CALLs in `precompiles.rs`); a future `eth_call`-to-Bridge path would need to mark
the call local. Test: `bridge::tests::local_call_gating_matches_rskj`. Verified by
replaying #6,223,900: tx[4] status=true gasUsed=34304, state and receipts roots
match; exec-head #6,223,703 → #6,223,910 replays clean.

## §62 Bridge releaseBtc: contract caller → CALLER_CONTRACT, and value is the CALL endowment (#6,223,933, #6,223,939)

`BridgeSupport.releaseBtc(Transaction rskTx)` (BridgeSupport.java:882) is the
Bridge's peg-out entry point (reached by an empty-data call or the `releaseBtc()`
selector, parseData → `BridgeMethods.RELEASE_BTC`). It has two implementation
quirks that make consensus depend on the *caller kind* and the *call endowment*,
not on the top-level transaction:

1. **Contract callers are rejected (CALLER_CONTRACT).** Before any min-value
   logic, `releaseBtc` checks `BridgeUtils.isContractTx(rskTx)` (BridgeSupport.java:891).
   `isContractTx` is `rskTx.getClass() == InternalTransaction.class` (BridgeUtils.java:434):
   true exactly when the Bridge was reached via a CALL from contract code, since
   `Program.callToPrecompiledAddress` wraps every Bridge invocation in a freshly
   constructed `InternalTransaction` (Program.java:1530, sender =
   `getOwnerRskAddress()` = the *immediate calling contract*), whereas a top-level
   transaction to the Bridge keeps the real signed `Transaction`. A BTC address
   cannot be derived from a contract, so:
   - post-RSKIP185 (iris300): `emitRejectEvent(pegoutValueInWeis, senderAddress,
     CALLER_CONTRACT)` — emits `release_request_rejected(sender, amount, reason=2)`
     and **returns without refunding** (note: only the LOW_AMOUNT / FEE_ABOVE_VALUE
     path in `requestRelease` refunds via `refundAndEmitRejectEvent`; the
     CALLER_CONTRACT path does **not**);
   - pre-RSKIP185: throws `Program.OutOfGasException` (consume all gas).
   The reject `senderAddress` is `rskTx.getSender()` = the immediate caller (the
   contract), **not** the tx origin. `RejectedPegoutReason`: LOW_AMOUNT=1,
   CALLER_CONTRACT=2, FEE_ABOVE_VALUE=3 (RejectedPegoutReason.java).

2. **The peg-out value is the CALL's endowment, not the tx value.** `releaseBtc`
   reads `rskTx.getValue()`. For an internal call that is `msg.getEndowment()` —
   the RBTC the calling contract forwarded to the Bridge in *this* CALL — which
   can differ from the outer transaction's value. The reject/queue amount and the
   satoshi conversion all use this per-call value.

**rustock**: `bridge::peg::release_btc` (crates/execution/src/bridge/peg.rs) now (1)
rejects with CALLER_CONTRACT when the Bridge is reached at journal depth > 1
(rskj's `isContractTx`; `call_depth = ctx.journal().depth()`, 1 = top-level), using
the immediate `caller` as the event sender and **not** refunding; and (2) takes the
actual call value (`CallInputs::call_value()`, threaded `run_bridge → execute_bridge
→ execute_method → release_btc`) instead of the top-level `ctx.tx().value()`. The
top-level direct-call path (executor.rs) passes `tx.value` and depth 1, so
depth-1 behavior is unchanged. Test:
`bridge::events::tests::solidity_release_request_rejected_caller_contract_mainnet_6223933`.
Verified: #6,223,933 tx[2] (tx value = endowment = 10000 sat) and #6,223,939 tx[0]
(tx value 0, endowment 10000 sat) both reject with CALLER_CONTRACT(2), sender =
contract 0x4309efcc, no refund; exec-head #6,223,932 → #6,223,950 replays clean
with exact state and receipts roots.

## §63 RSKIP379 inverts the empty-fed-output peg-in: an amount-0 peg-in is rejected as INVALID_AMOUNT (#6,223,964)

**CONSENSUS-CRITICAL IMPLEMENTATION QUIRK.** The minimum-value gate for a peg-in
flips its empty-set behavior at RSKIP379 (Arrowhead600, mainnet #6,223,700), and the
flip turns on whether the code is written as `allMatch` (vacuously true on empty) or
with an explicit `isEmpty()` guard.

- **Pre-RSKIP379** (`PegUtilsLegacy.isValidPegInTx` → `isAnyUTXOAmountBelowMinimum`,
  RSKIP293): "below minimum" is `btcTx.getWalletOutputs(fedWallet).stream().anyMatch(v <
  min)`. `anyMatch` over an **empty** stream is `false`, so a tx that pays *no* live
  federation output is **not** below minimum → a valid amount-0 peg-in (see §… /
  #5,171,600: `pegin_btc(amount=0)` + `transferTo(dest,0)` creating the destination
  account + mark processed).
- **Post-RSKIP379** (`PegUtils.evaluatePegin` → `allUTXOsToFedAreAboveMinimumPeginValue`,
  PegUtils.java:67): the method **explicitly** special-cases empty —
  `List<TransactionOutput> fedUtxos = btcTx.getWalletOutputs(fedWallet); if
  (fedUtxos.isEmpty()) return false;` then `fedUtxos.stream().allMatch(v >= min)`. An
  empty fed-output set is therefore **not** all-above-minimum, so `!allUTXOs…` is true
  and `evaluatePegin` returns `(PeginProcessAction.NO_REFUND, INVALID_AMOUNT)`
  (PegUtils.java:211-213). A from-scratch client that wrote this as a plain
  `allMatch` (vacuously true on empty) would treat the amount-0 tx as valid and fork.

For the NO_REFUND/INVALID_AMOUNT result, `BridgeSupport.handleNonRefundablePegin`
(BridgeSupport.java:543) emits **two** Bridge events and credits/creates nothing:
`eventLogger.logRejectedPegin(btcTx, RejectedPeginReason.INVALID_AMOUNT)` →
`rejected_pegin(bytes32,int256)` reason **5**, then maps `INVALID_AMOUNT →
NonRefundablePeginReason.INVALID_AMOUNT` (BridgeSupport.java:562) and
`eventLogger.logNonRefundablePegin(btcTx, …)` → `unrefundable_pegin(bytes32,int256)`
reason **3**. The tx is marked processed **only** when
`shouldMarkRejectedPeginAsProcessed()` = `RSKIP459 && !RSKIP551` (lovell700..vetiver900) —
so at Arrowhead600 it is **not** marked processed (no `btcTxHashesAlreadyProcessed`
leaf). `RejectedPeginReason.INVALID_AMOUNT=5`; `NonRefundablePeginReason.INVALID_AMOUNT=3`.

**rustock**: `bridge::peg::register_btc_transaction` now computes `below_min` with
RSKIP379 semantics (`live_output_values.is_empty() || any(v < min)`) and, when it
fires post-RSKIP379, emits `log_rejected_pegin(…, 5)` + the new
`log_unrefundable_pegin(…, 3)` (`bridge::events`), marking processed only via the
existing `should_mark_rejected_pegin_as_processed` (RSKIP459 && !RSKIP551). Pre-RSKIP379
the legacy `pegin_below_minimum` path and its silent UNKNOWN-type ignore are unchanged.
New `RskHardforkConfig::has_rskip379` (>= Arrowhead600). Tests:
`bridge::events::tests::unrefundable_pegin_topic_and_reasons_mainnet_6223964` (topic0 =
`0x35be155c…` + reason values). Verified: #6,223,964 tx[1] (empty fed outputs, amount 0)
emits `rejected_pegin(5)` + `unrefundable_pegin(3)` and writes no destination account /
no processed marker; exec-head #6,223,963 → #6,223,965 replays clean with exact state
and receipts roots.

## §64 RSKIP379 pegout sig-hash index, and the sigHash toString() byte order (#6,226,520)

**CONSENSUS-CRITICAL IMPLEMENTATION QUIRK (byte order).** RSKIP379 (Arrowhead600)
adds a pegout-transaction index: every time a pegout is created,
`BridgeSupport.settleReleaseRequest` → `savePegoutTxSigHash(releaseTransaction)`
(BridgeSupport.java:1381,1407) stores a marker so the pegout's first-input signature
hash can later be recognized. The index entry is:
- **Key**: `BridgeStorageProvider.getStorageKeyForPegoutTxSigHash` =
  `PEGOUT_TX_SIG_HASH.getCompoundKey("-", sigHash.toString())` =
  `DataWord.fromLongString("pegoutTxSigHash-" + sigHash.toString())` (keccak256).
- **Value**: `new byte[]{TRUE_VALUE}` = a single `0x01` byte (BridgeStorageProvider.java:588).
- **sigHash**: `BitcoinUtils.getSigHashForPegoutIndex(pegoutTx)` (BitcoinUtils.java:28) =
  the first input's **legacy** `hashForSignature(0, redeemScript, SigHash.ALL, false)`
  over the tx-without-signatures, where `redeemScript` is extracted from input 0
  (`extractRedeemScriptFromInput`). For a freshly-built pegout the inputs are spent
  from the active federation, so this is the active fed's redeem script.

The quirk is the **byte order of `sigHash.toString()`**. A BTC txid's
`getHash().toString()` is bitcoinj `Sha256Hash.wrapReversed(...)` → DISPLAY order
(reversed). But a `hashForSignature` result is `Sha256Hash.twiceOf(...)`
(BtcTransaction bytecode offsets 397/722 in bitcoinj-thin 0.14.4-rsk-18) → stored in
**INTERNAL** order, and `Sha256Hash.toString()` is a plain `HEX.encode(bytes)` with no
further reversal. So the compound-key identifier is the sigHash in **internal** byte
order, *not* reversed — the opposite of every txid-keyed Bridge cell. A from-scratch
client that reused its txid-string helper (reverse-then-hex) here would key the wrong
slot and fork. Only RSKIP271-era batch pegouts reach this (RSKIP271 ≪ RSKIP379, so when
RSKIP379 is active the batch path is the only one taken).

**rustock**: `bridge::peg::save_pegout_tx_sig_hash` stores `[0x01]` at
`compound_key(PEGOUT_TX_SIG_HASH_KEY, "-", to_hex(sig_hash))` — `to_hex` directly, **not**
`btc_hash_hex_display` (which reverses). The sigHash is
`release_tx::legacy_sighash_all(&built.tx, 0, redeem_of_input_0)` (rust-bitcoin's
`legacy_signature_hash`, whose `to_byte_array()` is the same internal order as bitcoinj
`twiceOf`), computed in the batch path before `settle` consumes the built tx, gated on
`has_rskip379`. Test:
`bridge::storage::tests::compound_key_pegout_tx_sig_hash_mainnet_6226520` pins the
groundtruth (sigHash `1220…2595` → DataWord `0x904714d8…`, and asserts the reversed-hex
form does NOT match). Verified: exec-head #6,226,519 → #6,226,521 replays clean with
exact state and receipts roots (the index leaf rustock previously omitted now matches).

## §66 RSKIP379 evaluatePegin: an undetermined-sender legacy peg-in is rejected with two events (#6,677,786)

Companion to §63. The RSKIP379 (Arrowhead600) `PegUtils.evaluatePegin` refactor
also changed how a **legacy (v0) peg-in with an undetermined sender** is handled.
`PegUtils.evaluateLegacyPegin` (PegUtils.java:247) switches on the sender BTC
address type; the `default` arm — the sender type could not be determined (no
`BtcLockSender`) — returns `(PeginProcessAction.NO_REFUND,
RejectedPeginReason.LEGACY_PEGIN_UNDETERMINED_SENDER)`. `BridgeSupport
.handleNonRefundablePegin` then emits **two** events and credits/refunds nothing:
`rejected_pegin(LEGACY_PEGIN_UNDETERMINED_SENDER=3)`, then maps it (protocolVersion 0)
to `NonRefundablePeginReason.LEGACY_PEGIN_UNDETERMINED_SENDER` and emits
`unrefundable_pegin(…=1)`. It marks the tx processed only when
`RSKIP459 && !RSKIP551` (not active at Arrowhead600/631). Pre-RSKIP379 the legacy
path aborted silently when the sender could not be determined (no events).

mainnet #6,677,786 tx[2]: a `registerBtcTransaction` whose peg-in has an
undetermined sender. rustock's v0 path returned silently (the `sender is None`
branch), emitting no events; rskj emitted `rejected_pegin(3)` + `unrefundable_pegin(1)`.
State matched (no credit/refund/processed-marker either way), so it was a
receipts-only divergence.

**rustock**: `bridge::peg::register_btc_transaction`'s undetermined-sender branch
(`let Some(sender) = sender else { … }`) now, post-RSKIP379, emits
`log_rejected_pegin(…, 3)` + `log_unrefundable_pegin(…, 1)` and marks processed only
via `should_mark_rejected_pegin_as_processed`. Pre-RSKIP379 behavior (silent abort)
is unchanged. Test:
`bridge::events::tests::legacy_pegin_undetermined_sender_reasons_mainnet_6677786`.
Verified: exec-head #6,677,785 → #6,677,787 replays clean; #6,677,786 tx[2] emits the
two events with exact state and receipts roots. (Still-latent post-RSKIP379
evaluatePegin arms — LEGACY_PEGIN_MULTISIG_SENDER and PEGIN_V1_INVALID_PAYLOAD
refund/no-refund — remain noted in LESSONS.)

## §67 RSKIP376 makes funds-migration txs version 2, and migrations save the pegout sig-hash (#7,069,808)

Two coupled divergences on the first federation funds migration after Arrowhead600.

**(a) Migration tx version.** `ReleaseTransactionBuilder.setDefaultTxConfig`
(ReleaseTransactionBuilder.java:195-203) sets the BTC tx version to 2 once RSKIP201
is active. But `buildMigrationTransaction` (:132-140) forces it back to version 1
**unless RSKIP376 is active** (`if (!activations.isActive(RSKIP376)) sr.tx.setVersion(BTC_TX_VERSION_1);`).
So from RSKIP376 (Arrowhead600, mainnet #6,223,700) on, migration txs are version 2
like every other pegout; before, they alone stayed version 1. Regular batched pegouts
(`buildBatchedPegouts`) never had the override, so they were already version 2 — only
the migration path was wrong. The version field is part of the BTC tx preimage, so a
wrong version produces a wrong unsigned migration txid and forks the
`releaseTransactionSetWithTxHash` entry.

**(b) Migration sig-hash index.** `migrateFunds` (BridgeSupport.java:1322) routes
through `settleReleaseRequest`, which calls `savePegoutTxSigHash`
(BridgeSupport.java:1381) for **every** release — migrations included — under RSKIP379.
rustock had only wired `save_pegout_tx_sig_hash` into the batched-pegout path (§64), so
each migration tx left a missing `pegoutTxSigHash-<sigHash>` = 0x01 leaf.

mainnet #7,069,808 (updateCollections, two migration txs of 50 and 17 UTXOs): rustock
built them as version 1 (txids 0de25d8e… / 615921cd…); rskj built version 2
(7befa0dd… / d2ca62b5…) — confirmed byte-identical except the 4-byte version field
(flipping rustock's serialization 01→02 reproduces rskj's exact txids). State **and**
receipts roots both forked (the set entry plus two absent sig-hash leaves).

**rustock**: `bridge::peg::process_funds_migration` now selects
`migration_tx_version = if has_rskip376 { 2 } else { 1 }` (new `RskHardforkConfig::has_rskip376`,
Arrowhead600), and, post-RSKIP379, calls `save_pegout_tx_sig_hash` on the built migration
tx using the legacy sighash of input 0 (`legacy_sighash_all(&built.tx, 0, redeem0)` over
the now-version-2 tx). Tests: `hardfork::tests::test_rskip376_mainnet`. Verified:
exec-head #7,069,807 → replay #7,069,808–#7,069,820 all match state and receipts roots
exactly; both migration txids become 7befa0dd…/d2ca62b5… with the two sig-hash leaves present.

## §70 RSKIP428 pegout_transaction_created event (#7,338,403)

RSKIP428 (lovell700) adds a Bridge event emitted for every settled release:
`pegout_transaction_created(bytes32 indexed btcTxHash, bytes utxoOutpointValues)`
(topic0 `0x9ee5d520…`). rskj `BridgeSupport.settleReleaseRequest` calls
`processReleaseTransactionInfo` right after `logReleaseRequested`, so the event lands
between `release_requested` and (for batches) `batch_pegout_created`
(BridgeSupport.java:1383,1439-1446). rustock emitted only the surrounding three events,
so the first post-lovell batched pegout (#7,338,403 tx[1], an updateCollections) had a
receipts-root mismatch (state matched — logs only).

- `btcTxHash` = the unsigned pegout tx's `getHash().getBytes()` — the same internal
  byte order as `release_requested` (rustock `btc_txid_event_bytes`).
- data = ABI dynamic `bytes` whose payload is `UtxoUtils.encodeOutpointValues`: each
  spent input's value (in input order) as a bitcoinj `VarInt` (1 byte < 0xFD, else a
  0xFD/0xFE/0xFF tag + 2/4/8 little-endian bytes), concatenated.
- RSKIP305 (`setReleaseOutpointsValues` storage) is reed800, NOT yet active at
  lovell700 — so only the event fires here, which is why state matched.

**rustock**: new `bridge::events::log_pegout_transaction_created` (with an
`encode_varint` helper) is called from the shared pegout `settle` closure (batch +
individual) and the migration settle path, gated on the new
`RskHardforkConfig::has_rskip428` (Lovell700), immediately after `release_requested`.
The rejection-release paths do NOT emit it (rskj `generateRejectionRelease` does not go
through `settleReleaseRequest`). Tests:
`bridge::events::tests::pegout_transaction_created_topic_and_varint_mainnet_7338403`.
Verified: exec-head #7,338,402 → replay #7,338,403–#7,342,000 match state and receipts
roots exactly; 556 tests pass.

## §92 Migration/peg-out classification matches a segwit fed in BOTH P2SH forms (#8,569,377)

`registerBtcTransaction`'s peg-out/migration classification recognizes an input as spending
a federation by comparing the input's STANDARD redeem against each federation's stored P2SH
hash. rskj `PegUtilsLegacy.isPegOutTx` builds **both** `createP2SHOutputScript(stdRedeem)`
and (post-RSKIP305) `createP2SHP2WSHOutputScript(stdRedeem)` for the input and matches
either against each federation's `getFederationStandardP2SHScript` =
`ErpFederation.getDefaultP2SHScript()` — which is the **P2SH-P2WSH** witness-program script
for a segwit (format ≥ 4000) federation (§91). rustock only computed the legacy
`hash160(stdRedeem)`, so a migration spending the **retired segwit federation** (whose
`lastRetiredFederationP2SHScript` is the witness-program hash after §91) was not recognized
as a migration — its output to the active federation was never registered as a UTXO
(`newFederationBtcUTXOs` diverged by one entry). The input is now matched if either its
legacy hash or its `federation_output_hash160(stdRedeem, 4000)` equals the federation's
stored hash (gated on RSKIP305); since the input's standard redeem equals the federation's,
this matches whichever form the federation stored. Applied to the active, retiring, and
retired comparisons. Verified: replay #8,569,377 matches state+receipts roots exactly; 568
tests pass.

## §91 `lastRetiredFederationP2SHScript` for a SEGWIT retiring federation (#8,530,373)

When a federation retires, rskj persists `getLastRetiredFederationP2SHScript`. From
RSKIP377 this is the retiring `ErpFederation.getDefaultP2SHScript()` =
`getOutputScript(getDefaultRedeemScript())` (ErpFederation.java:113-127): the **default**
(standard multisig) redeem, wrapped as **P2SH-P2WSH** (`createP2SHP2WSHOutputScript`,
`OP_HASH160 hash160(OP_0 PUSH32 sha256(redeem)) OP_EQUAL`) when the federation's format is
P2SH-P2WSH-ERP (4000), and as plain P2SH (`createP2SHOutputScript`) otherwise. rustock
always took the plain `hash160(defaultRedeem)`, so a retiring segwit federation stored the
wrong `lastRetiredFedP2SHScript` hash. Fixed both handover sites in `governance.rs` to use
`federation_output_hash160(defaultRedeem, oldFormat)`, which yields the witness-program
hash for format ≥ 4000 and the plain hash below it. Verified: replay #8,530,373 matches
state+receipts roots exactly; 568 tests pass.

## §90 RSKIP419 SVP spend tx output to a SEGWIT active federation (#8,524,411)

The SVP **spend** transaction (`BridgeSupport.createSvpSpendTransaction`) spends the two
fund-tx outputs (proposed federation P2SH + flyover P2SH) into a single output paying the
**active** federation. Its inputs were already built segwit-aware (the proposed federation
is P2SH-P2WSH, so `addSpendingFederationBaseScript` uses the witness-program scriptSig +
base witness for format ≥ 4000), but the single output still used the legacy
`hash160(activeRedeem)` for the active federation script. When the active federation is
itself segwit (the rotation in progress at this height), that output must be the
witness-program hash `federation_output_hash160(activeRedeem, 4000)`. The wrong output
script changed the unsigned spend-tx bytes, so `svpSpendTxHashUnsigned`,
`svpSpendTxWaitingForSignatures`, and the derived `pegoutTxSigHash` / outpoint-values all
diverged. Fixed `create_svp_spend_transaction` to derive the active-federation output
script from its format (same one-liner as §89's change address). Verified: replay
#8,524,411 matches state+receipts roots exactly; 568 tests pass.

## §89 RSKIP419 SVP fund tx for a SEGWIT active federation (#8,517,969)

The RSKIP419 SVP fund transaction (`ReleaseTransactionBuilder.buildSvpFundTransaction`,
`Wallet.completeTx` with `recipientsPayFees=false`) spends the **active** federation's
UTXOs, pays two fixed outputs (the proposed federation P2SH and its flyover P2SH), and
sends the change back to the active federation's own address. At the reed800 SVP
(#8,052,200) the active federation was still pre-segwit, so a legacy build was correct.
A later powpeg rotation (#8,517,969) runs the SVP while the active federation is itself
**P2SH-P2WSH (format ≥ 4000)**, which makes three things segwit-dependent that rustock's
`complete_recipients_dont_pay_fees_tx` / `build_svp_fund_transaction` still did the legacy
way:

1. **Change address** — must be `federation_output_hash160(activeRedeem, 4000)` (the
   witness-program hash, `OP_HASH160 hash160(0x0020||sha256(redeem)) OP_EQUAL`), not the
   plain `hash160(redeem)`. rustock sent change to the legacy P2SH.
2. **Fee / size** — bitcoinj `calculateTxSize` weights a segwit-compatible send: `baseSize
   = serialize(emptyScriptSigTx) + inputs*36`, `vsize = (baseSize + signing + 3*baseSize)/4`.
   rustock used the legacy `baseSize + signing`, charging a larger fee (less change).
3. **Input placeholders** — segwit inputs carry the witness-program scriptSig + base
   witness, not the legacy `placeholder_scriptsig`; this changes the serialized fund tx
   bytes stored in `releaseTransactionSet`.
4. **`savePegoutTxSigHash` (RSKIP379)** — the redeem for input 0 comes from the **witness**
   (last item) for a segwit input, and `getSigHashForPegoutIndex` is taken over the
   segwit serialization (§73), not `legacy_sighash_all` over a scriptSig-extracted redeem.

rustock now mirrors `complete_pegout_tx`'s `is_segwit` handling in
`complete_recipients_dont_pay_fees_tx`, derives the change script and `is_segwit` from
the active federation format in `build_svp_fund_transaction`, and computes the fund tx's
sighash via `first_input_sig_hash` with the witness-borne redeem. Verified: replay
#8,517,969 matches state+receipts roots exactly; 568 tests pass.

## §88 Bridge `byte[]` returns ABI-encode even when empty — rskj's 96-byte empty `bytes` (#8,417,579)

`Bridge.execute` always ABI-encodes a method's `byte[]` result via
`encodeOutputs` (`Bridge.java:418`). The encoder is
`SolidityType.BytesType.encode` (`SolidityType.java:296`), which sizes the data
section as `new byte[((bb.length - 1) / 32 + 1) * 32]` using Java's truncating
integer division. For an **empty** array `(0 - 1) / 32 == -1 / 32 == 0` (Java
truncates toward zero), so `+ 1` still allocates **one** 32-byte zero word: an
empty `bytes` return is `offset(0x20) + length(0) + one zero word` = **96
bytes**, not 64.

`getBtcBlockchainBlockHeaderByHeight(height)` for a height above the BTC chain
head makes `getStoredBlockAtMainChainHeight` throw (`depth < 0`); `Bridge`
catches it (`Bridge.java:1434-1437`) and returns `EMPTY_BYTE_ARRAY`, which then
goes through the 96-byte encoding above. rustock had two bugs here: the
not-found path returned zero-length data (`Bytes::new()`) instead of an
ABI-encoded empty `bytes`, and its `encode_abi_bytes` padded an empty array to
64 bytes. Both forked the **caller** at mainnet #8,417,579: contract
`0xba5666…` STATICCALLs the Bridge, copies the reply with `RETURNDATACOPY`, and
its ABI bounds-check (`SLT`) reverts on a 0-byte reply but proceeds on the
64-byte data section — changing `RETURNDATASIZE` and downstream memory
expansion (tx[0] gas 34401 vs 34912).

rustock (`bridge/btc_chain.rs` `get_block_header_by_height` /
`get_parent_block_header_by_hash` now always `encode_abi_bytes` their result;
`encode_abi_bytes` sizes the data section with the same `((len-1)/32+1)*32`
truncating expression). The identical quirk was already handled in
`precompiles.rs::abi_encode_bytes` (getCoinbaseAddress, #1,669,062) but had not
been propagated to the sibling encoders `bridge/getters.rs::abi_encode_bytes`
and `bridge/events.rs::abi_single_dynamic`, both fixed here for the same latent
divergence. Verified: replay #8,417,579 matches state+receipts roots exactly;
567 tests pass.

## §87 RSKIP305 (reed800): resolve flyover redeem for a segwit fed's UTXOs (#8,160,028)

A peg-out spending a segwit federation may mix plain and **flyover** UTXOs. To spend a flyover
UTXO each input needs its flyover redeem (`PUSH32 <derivationHash> OP_DROP <fedRedeem>`), found
by matching the stored `fedRedeemScriptHash` against the destination federation. That stored
hash is `federation.getP2SHScript().getPubKeyHash()` — the **P2SH-P2WSH** witness-program hash
for a format-4000 fed — but `resolve_flyover_input_redeems` compared it only to the candidate's
plain `redeem_script_hash160`, so segwit flyover UTXOs failed to resolve and were spent with the
plain active redeem (wrong witness-program scriptSig + witness redeem). The match now accepts
either the plain P2SH hash or `federation_output_hash160(r, 4000)`. Verified: replay #8,160,028
matches state+receipts roots exactly; 563 tests pass.

## §86 RSKIP305 (reed800): classify a segwit peg-out when registering it (#8,160,027)

When a segwit peg-out tx is later registered (`registerBtcTransaction`), it must be classified
PEGOUT/MIGRATION so `registerNewUtxos` records its change output (back to the active fed) as a
new UTXO. rskj `extractRedeemScriptFromInput` reads the input's redeem from the **witness** for
a segwit input (the scriptSig is only the witness-program push). rustock's classification
(`isPegOutTx` / `txIsFromOldFederation` / `isMigrationTx`) read the redeem from the scriptSig
only, so a segwit peg-out's inputs hashed to the program push, not the fed → not classified as a
peg-out → its change UTXO was never registered (one missing `newFederationBtcUTXOs` entry). The
three input-redeem checks now read the witness last item for segwit inputs. Verified: replay
#8,160,027 matches state+receipts roots exactly; 563 tests pass.

## §85 RSKIP305 (reed800): sign a segwit peg-out via addSignature (#8,157,776)

A federator signing a regular segwit peg-out goes through `addSignature` → `processSigning`
(not the SVP path). `apply_signatures_to_tx` is already witness-aware, but the regular path
passed empty `prev_values`, so the BIP-143 sighash used value 0, signature verification
failed, and no signature was inserted (the tx stayed at its base witness in `rskTxsWaitingFS`).
The regular path now loads the per-input values from `releasesOutpointsValues` (keyed by the
peg-out's witness-stripped hash, saved at creation) and passes them through, exactly like the
SVP signing path. Verified: replay #8,157,776 matches state+receipts roots exactly; 563 tests
pass.

## §84 RSKIP305 (reed800): flyover peg-in to the segwit federation (#8,153,938)

A flyover peg-in (`registerFastBridgeBtcTransaction`) to a P2SH-P2WSH active/retiring
federation pays a P2SH-P2WSH **flyover** address. rskj `createFlyoverFederationInformation`
stores `federation.getP2SHScript().getPubKeyHash()` and
`getFlyoverFederationOutputScript(flyoverRedeem, format).getPubKeyHash()`, both of which are
the witness-program hash for format 4000. rustock derived plain P2SH hashes, so the BTC tx's
flyover output never matched → zero value sent → the call returned an error and the calling
contract reverted (computed gas 104,762 vs header 142,571 at #8,153,938). Both the active and
retiring flyover federation P2SH hashes (and the matched output script) now use
`federation_output_hash160(redeem, format)`. Verified: replay #8,153,938 matches
state+receipts roots exactly; 563 tests pass.

## §83 RSKIP305 (reed800): spend the segwit active federation — segwit pegouts (#8,153,771)

Once the P2SH-P2WSH federation is active and has UTXOs, regular peg-outs spend it with
**segwit** inputs. Four pieces had to become format-aware:

1. **UTXO registration / peg-in matching** (`registerNewUtxos`, `register_btc_transaction`):
   the active/retiring federation is recognized at its **P2SH-P2WSH** address
   (`getActiveFederationAddress` is format-aware), so the output-script used to match
   funding outputs is `federation_output_hash160(redeem, format)`. Without this the
   migrated UTXO is never registered (the symptom at #8,153,771: the migration UTXO is
   registered *and* spent within the same block, so the UTXO-set leaf still matched while
   the peg-out was silently never built).
2. **Change output**: peg-out change returns to the active federation's P2SH-P2WSH address.
3. **Segwit inputs + fee** (`complete_pegout_tx`, `is_segwit`): each input's scriptSig is
   the witness-program push and the redeem + sig placeholders go in the witness
   (`segwit_base_input`); the fee uses bitcoinj `Wallet.calculateTxSize`'s segwit branch
   `vsize = (baseSize + signing + 3*baseSize)/4` with `baseSize += inputs*36`. The migration
   path is segwit when the *retiring* federation is format 4000.
4. **pegoutTxSigHash** — see below.

**Consensus-critical rskj quirk (`getSigHashForPegoutIndex`).** The peg-out is indexed by
`hashForSignature(0, redeem, ALL, false)` of the signatures-stripped tx. For a *segwit*
peg-out this is NOT a witness-stripped legacy sighash: bitcoinj clears the input scriptSigs
(input 0 → redeem) but leaves the base **witnesses** in place, and
`BtcTransaction.bitcoinSerializeToStream` emits the witness bytes whenever `hasWitness()`.
So the sighash preimage is the **segwit serialization** (marker/flag + witnesses) + the
4-byte LE SIGHASH_ALL, double-SHA256 — a non-standard "legacy hash over segwit bytes".
rust-bitcoin's `legacy_signature_hash` strips the witness, so `first_input_sig_hash` builds
the preimage manually for witness-bearing txs. Verified: replay #8,153,771 matches
state+receipts roots exactly; test `segwit_pegout_uses_witness_inputs_and_smaller_fee`;
563 tests pass.

## §82 RSKIP305 (reed800): migration destination is the segwit active fed's P2SH-P2WSH address (#8,147,324)

~40,320 blocks after its commit (§78), the first reed800 P2SH-P2WSH proposed federation
**activates** as the new active federation (#8,147,322). `migrateFunds` then sends the
retiring (old, legacy) federation's funds to `getActiveFederationAddress()`, which for a
format-4000 federation is its **P2SH-P2WSH** address. The migration tx therefore has
legacy inputs (spending the old federation) but a P2SH-P2WSH output. rustock derived a
plain P2SH output (`hash160(redeem)`); fixed to `federation_output_hash160(new_redeem,
new_format)` with the new federation's stored format version (so format 4000 →
`hash160(0x0020 ‖ sha256(redeem))`). Verified: replay #8,147,324 matches state+receipts
roots exactly; 562 tests pass. (Pegouts that *spend* the segwit active federation — segwit
inputs — will be handled when first hit, once it has spendable UTXOs.)

## §81 RSKIP305 (reed800): segwit SVP spend-tx signing (BIP143) (#8,117,400)

Federators sign the segwit SVP spend tx via `addSignature` → `addSvpSpendTxSignatures`
→ `processSigning`. For a P2SH-P2WSH (witness) input rskj diverges from the legacy path:

- **sigHash** (`generateInputSigHash`): a witness input uses the BIP-143 segwit v0
  sighash (`hashForWitnessSignature`) with the redeem as the witness script and the
  spent value taken from `releaseOutpointsValues(tx.getHash())[i]` — the per-input
  values we persisted when the spend tx was created. rust-bitcoin's
  `SighashCache::p2wsh_signature_hash(i, redeem, value, All)`.
- **redeem extraction**: from the **witness** (last push), not the scriptSig (which
  is just the witness-program push).
- **signature insertion** (`signInput` → `updateWitnessWithSignature`): the signature
  goes into the **witness** stack, not the scriptSig. The base ERP witness is
  `[dummy, ε×threshold, OP_NOTIF-flag, redeem]`; a signature is inserted among the
  `threshold` sig slots in redeem-key order, exactly as the legacy
  `getScriptSigWithSignature` does on scriptSig chunks (mirrored as
  `witness_update_with_signature` / `witness_sig_insertion_index` /
  `witness_input_signed_by`, with the redeem + ERP flag as a 2-item suffix).
- **fully-signed check** (`countMissingSignatures` / `has_enough_signatures`): a witness
  input is complete when every sig slot between the dummy and the flag+redeem suffix is
  filled.

rustock: `apply_signatures_to_tx` now branches per input on `!witness.is_empty()`;
`segwit_sighash_all`, `load_release_outpoints_values`, and the `witness_*` helpers in
release_tx.rs. Verified: replay #8,117,400 (first federator's signature) matches
state+receipts roots exactly; tests `witness_update_with_signature_erp_first_sig`; 562
tests pass.

## §80 RSKIP305 (reed800): segwit SVP spend transaction (#8,113,398)

When the proposed federation is format 4000 (P2SH-P2WSH), `createSvpSpendTransaction`
spends the two SVP fund-tx outputs via **segwit** (rskj `addSpendingFederationBaseScript`
→ `setSpendingBaseScriptSegwit`):

- **scriptSig** per input = `buildSegwitScriptSig(redeem)` = a single push of the
  witness program `OP_0 PUSH32 sha256(redeem)` (i.e. `0x22 0x0020 ‖ sha256(redeem)`,
  35 bytes). NOT the legacy redeem placeholder.
- **witness** per input = `createBaseWitnessThatSpendsFromErpRedeemScript(redeem)`:
  the CHECKMULTISIG dummy (empty) + `threshold` empty signature placeholders + the
  OP_NOTIF default-branch flag (empty) + the redeem script. For threshold 5 that is
  8 stack items (7 empty + redeem).
- The tx serializes in segwit form (marker/flag + witnesses); `svpSpendTxHashUnsigned`
  and the `releasesOutpointsValues` key both use the **witness-stripped** txid
  (`getMultiSigTransactionHashWithoutSignatures` → `tx.getHash()` for a witness tx),
  which rust-bitcoin's `compute_txid()` already returns.

The fee uses `calculateSegwitTxSize` (BIP141 weight/4) instead of the legacy size:
`baseSize = bitcoinSerialize(inputless tx with N P2SH outputs) + inputs*36`,
`signingSize = threshold*inputs*72`, `totalSize = baseSize + signingSize +
inputs*redeem.len()`, `txWeight = totalSize + 3*baseSize`, `vsize = txWeight/4`.

**Consensus-critical rust-bitcoin quirk:** bitcoinj's `bitcoinSerialize()` writes a
witness-less tx in legacy form, but rust-bitcoin force-tags a **0-input** tx with the
segwit marker/flag (to avoid the parse ambiguity with the marker byte), adding 2
bytes. `calculateTxBaseSize` builds an input-less tx, so `consensus::serialize(&tx).len()`
returns 44 where bitcoinj returns 42 — inflating vsize by 2 (522→524) and the fee by
16 sat. We use `tx.base_size()` (the witness-stripped length, no marker) to match.
rustock: `pegout_tx_size_segwit` / `segwit_base_input` in peg.rs. Verified: replay
#8,113,398 matches state+receipts roots exactly; tests
`svp_spend_segwit_tx_size_8113398`, `svp_spend_segwit_base_input_layout`; 561 tests pass.

## §79 RSKIP305 (reed800): segwit SVP fund/spend tx outputs + sigHash redeem (#8,107,003)

The block after the format-4000 commit (§78), `updateCollections` builds the SVP
fund transaction for the proposed federation. Two divergences from the pre-reed800
SVP path, both because the proposed fed is now segwit (format 4000):

1. **Output scripts.** The fund tx pays the proposed fed and its flyover variant.
   rskj derives those outputs from `PegUtils.getFlyoverFederationOutputScript` /
   the proposed fed's own output script, which for format 4000 is P2SH-P2WSH. We
   now compute `federation_output_hash160(redeem, proposed_format)` (proposed_format
   from `governance::federation_format_version(creation_block)` = 4000) in both
   `build_svp_fund_transaction` and `create_svp_spend_transaction`. The ERP redeem
   itself is identical to format 3000; only the output hash160 (witness program)
   changes.

2. **pegoutTxSigHash redeem.** `savePegoutTxSigHash` (RSKIP379) indexes the release
   by the legacy sighash of input 0. rskj's `BitcoinUtils.getFirstInputSigHash`
   extracts the redeem **from the first input's scriptSig**, so a flyover-resolved
   input is sighashed with its flyover redeem — not the plain active-fed redeem.
   The pre-segwit SVP path hard-coded `active_redeem`; it now extracts the redeem
   from `built.tx.input[0].script_sig` (falling back to the active redeem), matching
   the regular migration/pegout path. (The fund tx still spends the legacy format-3000
   active fed, so the sighash is legacy; only the redeem selection was wrong.)

Verified: exec-head #8,107,002 → replay #8,107,003 matches state and receipts roots
exactly; 559 tests pass.

## §78 RSKIP305 (reed800): P2SH-P2WSH federation address in commit_federation (#8,107,002)

reed800 (RSKIP305) makes a newly committed federation **format 4000
(P2SH-P2WSH-ERP)** — a segwit federation. The ERP redeem script is unchanged from
format 3000, but the federation's ADDRESS/output script becomes P2SH-P2WSH:
`createP2SHP2WSHOutputScript(redeem)` = `createP2SHOutputScript(OP_0 PUSH32
sha256(redeem))`, i.e. the P2SH hash is `hash160(0x0020 || sha256(redeem))` rather
than `hash160(redeem)`.

The first federation change after reed800 (#8,107,002) committed a format-4000
proposed federation. State matched (the stored proposed fed is keys + format-version
cell), but the `commit_federation` event's NEW-fed address derived a plain P2SH
address instead of P2SH-P2WSH. `federation_output_hash160(redeem, format)` now
returns the witness-program hash for format ≥ 4000; the commit event uses it for
both feds (the retiring fed is still format 3000 → P2SH, unchanged). Verified:
#8,107,002 matches state+receipts roots exactly. (This is the first slice of the
broader RSKIP305 segwit-federation feature — the SVP for this proposed fed, and
later its pegouts, are segwit; tracked in TODO-segwit-fed-rskip305.md.)

## §77 RSKIP305 (reed800): persist releasesOutpointsValues per settled release (#8,052,418)

reed800 (#8,052,200) activates RSKIP305. In `processReleaseTransactionInfo` —
called from `settleReleaseRequest` for every settled release (batched/individual
pegout, migration, SVP fund, SVP spend) — right after the RSKIP428
`pegout_transaction_created` event, rskj now also persists the release's spent-input
values: `provider.setReleaseOutpointsValues(btcTxHash, outpointsValues)`. The cell
key is `releasesOutpointsValues-<btcTxHash>` (display-order hex,
`Sha256Hash.toString()`); the value is the bitcoinj VarInt concatenation
(`serializeOutpointsValues` = `UtxoUtils.encodeOutpointValues`, the SAME bytes the
`pegout_transaction_created` event carries as its dynamic `bytes`). This is a pure,
receipts-invisible state write — rustock emitted the event but never wrote the cell,
so from reed800 on every settled release left a missing leaf.

mainnet #8,052,418: a settled release wrote `releasesOutpointsValues-<hash>` =
`fe55cb0700fefa949800` (two VarInt outpoint values). `save_release_outpoints_values`
(gated on `has_rskip305`) is now called right after each
`log_pegout_transaction_created`. Verified: #8,052,418 matches state+receipts roots
exactly; 559 tests pass.

## §76 RSKIP427: rejected peg-out refunds the FULL wei, not satoshi-truncated (#8,010,127)

A peg-out below the minimum is refunded to the sender. rskj
`refundAndEmitRejectEvent` chooses the refund value by fork:
```java
Coin refundValue = activations.isActive(RSKIP427) ?
    releaseRequestedValueInWeis :                         // full wei (lovell700+)
    Coin.fromBitcoin(releaseRequestedValueInWeis.toBitcoin()); // satoshi-truncated
```
Pre-RSKIP427 the refund was the wei value truncated to satoshi granularity, so the
sub-satoshi remainder stayed in the Bridge. From RSKIP427 (lovell700) the full wei
value is refunded. rustock always truncated, so post-lovell700 it kept the
remainder — a receipts-invisible balance fork (the `release_request_rejected`
event amount was already correct).

mainnet #8,010,127 tx[0]: a plain value transfer to the Bridge (empty calldata →
`RELEASE_BTC`) of 3,403,534,349,191,903 wei = 340,353.43… sat, below the 400,000-sat
minimum → rejected → refund. rustock refunded 340,353×10^10 and kept the
4,349,191,903-wei (0.43 sat) remainder; rskj refunded the whole amount. Fix: gate
the refund on `has_rskip427` (full `call_value_wei` post-427, truncated before).
Verified: #8,010,127 matches state+receipts roots exactly.

## §74 RSKIP419 SVP — commit→proposed federation + SVP fund tx (#7,740,878, #7,740,882)

RSKIP419 (lovell700) changes the federation-change flow. Pre-419 `commitFederation`
immediately rotated the active/retiring federations (`legacyCommitPendingFederation`).
From 419 it instead stores a **proposed** federation that must pass a Sign Validation
Protocol (SVP) before promotion. `commit_pending_federation`
(`bridge/governance.rs`) now branches on `has_rskip419`:
- **proposed path**: store `proposedFederation` (multikey serialization) +
  `proposedFederationFormatVersion`; clear the pending federation; leave the
  active/retiring federations and their UTXOs untouched. The `commit_federation`
  event is byte-identical to the legacy path (retiring = active fed, voted = built
  fed, same activation height) — which is why the commit block's *receipts* matched
  even before the fix; only the *state* (which cells were written) diverged.
- Creation time: `getFederationCreationTime` switches `Instant.ofEpochMilli` →
  `ofEpochSecond` at 419, so the proposed fed's stored creation-time (a millis
  field) is the block timestamp × 1000.

First powpeg rotation after lovell700 was mainnet #7,740,878 (proposed fed format
3000 = P2SH-ERP), the first place the new flow triggers.

The SVP fund transaction is created on the next `updateCollections` after the
commit (`updateSvpState` → `processSvpFundTransactionUnsigned`, #7,740,882). It is
a `recipientsPayFees=false` BTC tx with two fixed outputs of
`svpFundTxOutputsValue` (= `minimumPegoutTxValue × 2` = 800,000) — one to the
proposed federation P2SH, one to its flyover variant (flyover prefix = the 32-byte
value 1) — plus change to the active federation. `complete_recipients_dont_pay_fees_tx`
(`bridge/release_tx.rs`) replicates bitcoinj `Wallet.completeTx` with fixed
recipients and the change output absorbing the size fee. Then `settleReleaseRequest`
runs exactly as for a peg-out (removeSpentUtxos, addPegoutToPegoutsWaitingForConfirmations,
savePegoutTxSigHash, `release_requested` with amount = 2×outputsValue,
`pegout_transaction_created`). rskj refs: FederationSupportImpl.java:658-753,
BridgeSupport.java:1060-1169; ReleaseTransactionBuilder.java:123-130. Verified:
#7,740,878 and #7,740,882 match state+receipts roots; sync runs 6,400 blocks past.
(Registration of the signed fund tx, the SVP spend tx, and the proposed-fed
handover follow in a later change.)

## §75 RSKIP419 SVP — fund-tx registration + spend-tx creation (#7,747,283)

Continuation of §74. Once the signed SVP fund tx is mined and registered, three
things happen — two of them in the SAME block (#7,747,283):
- **registerSvpFundTx** (in `register_btc_transaction`): rskj's
  `PegUtils.getTransactionType` checks the SVP cases BEFORE the pegin/pegout
  classification — a tx whose *signature-stripped* txid (each input's scriptSig
  rebuilt as the redeem placeholder, `getMultiSigTransactionHashWithoutSignatures`)
  equals `svpFundTxHashUnsigned`. The matched tx is handled by `registerNewUtxos`
  (register the change UTXO to the active fed — identical to rustock's existing
  pegout path) plus, if the SVP window is still open, `setSvpFundTxSigned` +
  `clearSvpFundTxHashUnsigned`. **Consensus quirk**: the active federation here is
  an *ERP* federation, so the fund-tx input redeem ends in OP_ENDIF, not
  OP_CHECKMULTISIG. rskj's signature-stripping still accepts it and rebuilds the
  ERP placeholder (the extra OP_0 selecting the OP_NOTIF default branch) — so the
  classifier must NOT reject ERP inputs (an early version did and missed the
  match). `multisig_txid_without_signatures` rebuilds the placeholder for whatever
  redeem each input carries (`placeholder_scriptsig` handles the ERP OP_0).
- **processSvpSpendTransactionUnsigned** (in the same block's `updateCollections`,
  since `svpFundTxSigned` is now set): build the spend tx (version 2, two inputs
  spending the fund tx's proposed-fed and flyover-proposed-fed outputs with their
  redeem placeholders, one output to the active fed worth `2*outputsValue - fees`),
  store `svpSpendTxHashUnsigned` + `svpSpendTxWaitingForSignatures`
  (RLP[rskTxHash, btcTx]), clear `svpFundTxSigned`, and log `release_requested`
  (amount = output[0]) + `pegout_transaction_created`. The fee is
  `calculatePegoutTxSize(proposed, 2 in, 1 out) * 12/10 * feePerKb / 1000`
  (`calculateLegacyTxSize`: serialized tx with the federation redeem as each input
  scriptSig + `threshold * inputs * 72` signing bytes).

Storage formats: `svpFundTxSigned`/`svpSpendTxWaitingForSignatures` values use
`serializeBtcTransaction` = `RLP.encodeElement(tx.bitcoinSerialize())`;
`svpSpendTxHashUnsigned` = `RLP.encodeElement(hash.getBytes())` (display order).
rskj refs: BridgeSupport.java:436-464, 1171-1242; PegUtils.java:118-198;
BitcoinUtils.java:158-243. `commit_proposed_federation` (bridge/governance.rs) is
the handover invoked when the spend tx is later registered (registerSvpSpendTx).
Verified: #7,747,283 matches state+receipts roots exactly; 559 tests pass.

