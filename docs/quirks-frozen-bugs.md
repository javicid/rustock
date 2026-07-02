# Accidental rskj Code Paths Frozen into Consensus

Behaviors that **are visible in rskj's source** but were clearly never a design
decision — unconditional writes, missed resets, omitted merges, exception paths
that still mutate state — and that hardened into consensus because historical
mainnet blocks depend on them. Some were later corrected by an RSKIP (the
pre/post pairs are kept together here: §26 → §37 / RSKIP171, §16 → RSKIP150).

Part of the rskj compatibility catalogue; section numbers (§N) are historical
and shared across the whole catalogue — the index in
[`java-compatibility.md`](./java-compatibility.md) maps every § to its file.

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

### 51b. Witness-commitment validation: extract the embedded commitment, hash `reversed(witnessMerkleRoot)`, and THROW on mismatch

After the PMT/merkle-root checks pass, rskj calls
`validateWitnessInformation` (`BridgeSupport.java` l.2557-2587):

```java
BtcTransaction btcTx = new BtcTransaction(networkParameters, btcTxSerialized);
btcTx.verify();
validateWitnessInformation(btcTx, witnessMerkleRoot, witnessReservedValue);
// validateWitnessInformation:
Optional<Sha256Hash> expectedWitnessCommitment = findWitnessCommitment(coinbaseTransaction, activations);
Sha256Hash calculatedWitnessCommitment =
    Sha256Hash.twiceOf(witnessMerkleRoot.getReversedBytes(), witnessReservedValue);
if (expectedWitnessCommitment.isEmpty() ||
    !expectedWitnessCommitment.get().equals(calculatedWitnessCommitment)) {
    throw new BridgeIllegalArgumentException(...);   // NOT a no-op return
}
```

Two consensus-load-bearing details:

1. **Byte-order reversal.** The `witnessMerkleRoot` ABI arg arrives in INTERNAL
   byte order (decoded via bitcoinj `Sha256Hash.wrap`). The commitment preimage
   is `SHA256d(witnessMerkleRoot.getReversedBytes() ‖ witnessReservedValue)` —
   the 32-byte root MUST be reversed to display order before hashing. A
   from-scratch client that hashed the arg un-reversed computes the wrong
   commitment and forks. (rustock previously discarded the computed hash AND
   used the un-reversed root — a latent double bug.)

2. **Commitment extraction & selection rule.** `BitcoinUtils.findWitnessCommitment`
   (`rskj-core/.../peg/bitcoin/BitcoinUtils.java` l.300-357) scans the coinbase
   outputs for a scriptPubKey of the form `OP_RETURN(0x6a) <push 0x24=36>
   aa21a9ed <32-byte commitment>` (header `WITNESS_COMMITMENT_HEADER = aa21a9ed`,
   `MINIMUM_WITNESS_COMMITMENT_SIZE = 38`). Per BIP141, if several such outputs
   exist the LAST one wins, so rskj iterates `Lists.reverse(tx.getOutputs())`
   and returns the first match; the 32-byte hash starts at offset 6.

3. **Mismatch/absence THROWS** (unlike 51's no-op `return` paths).
   `validateWitnessInformation` throws `BridgeIllegalArgumentException`, which
   `Bridge.execute` wraps in a `VMException` (§50): the tx summary is marked
   failed and the sender is billed only `requiredGas`. So a malformed-commitment
   `registerBtcCoinbaseTransaction` stores NOTHING. A client that stored coinbase
   info unconditionally after the merkle-root check (rustock's prior latent bug)
   would diverge on the FIRST such tx mined into a block.

Pre-RSKIP460 rskj parses `output.getScriptPubKey().getProgram()` (which throws
`ScriptException` on a non-standard scriptPubKey); post-RSKIP460 it reads raw
`getScriptBytes()`. For a well-formed witness-commitment output the two are
byte-identical, and RSKIP460 is not active over the current sync range.

**rustock:** `register_btc_coinbase_transaction` (`tx.rs`) now deserializes the
coinbase tx, calls the new `find_witness_commitment` helper (mirrors the reversed
output scan + offset-6 extraction), hashes `reversed(witness_merkle_root) ‖
witness_reserved_value`, and `return Err(PrecompileError::other(...))` (a method
throw → §50 wrapper → VMException) when the commitment is absent or unequal;
otherwise it stores. Tests
`register_btc_coinbase_witness_commitment_positive` / `_negative` /
`find_witness_commitment_takes_last` use the exact coinbase tx and witness root
from rskj `BridgeSupportTest.registerBtcCoinbaseTransaction`.

## §65 A nested CREATE/CREATE2 constructor's gas refund is discarded (#6,362,186)

**CONSENSUS-CRITICAL IMPLEMENTATION QUIRK.** rskj propagates a child frame's
`ProgramResult` to its parent differently for CALL vs CREATE:
- **CALL** (`Program.callToAddressInner`, Program.java:957) runs
  `getResult().merge(childResult)`, and `ProgramResult.merge` carries
  `internalTransactions`, `deleteAccounts`, `logInfos`, **`futureRefund`**, and
  `deductedRefund`.
- **CREATE/CREATE2** (`Program.finalizeContractCreation`, Program.java:765 — the
  success path of the internal create opcode) merges **only**
  `getResult().addDeleteAccounts(...)` and `getResult().addLogInfos(...)`. It
  **never** propagates the constructor's `futureRefund`.

So any gas refund accrued inside a constructor — its own `SSTORE` clears
(`REFUND_SSTORE` = 15000, Petersburg metering, see §…/`rsk_sstore`) plus any
refunds its sub-calls merged up into the constructor's result — is **silently
discarded** when the contract is created via the CREATE/CREATE2 opcode. A
from-scratch client that simply propagated the child frame's refund counter (as
canonical EVM and revm do) would over-refund and fork. The top-level create
*transaction* is unaffected: `TransactionExecutor.create` reads the constructor
program's `futureRefund` directly (the constructor IS the tx's program), so its
refund counts.

mainnet #6,362,186 tx[3]: a contract is CREATE'd (depth 7) whose constructor sets
storage slot 0 to an address then clears it back to 0 (a reentrancy-guard /
transient pattern; the slot was 0 at tx start). revm granted the 15000
`SSTORE`-clear refund for that nested-create clear; rskj did not — so rustock's
gasUsed was 1,182,343 vs the header's 1,197,343 (exactly 15000 less). Because
rskj's `CLEAR_SSTORE` and `RESET_SSTORE` both cost 5000, the misclassification is
invisible in the per-opcode gas trajectory (the trace stayed in lockstep); only
the post-execution refund diverged.

**rustock**: `RskHandler::run_exec_loop` (crates/execution/src/rsk_handler.rs), just
before `frame_return_result` merges a finished frame into its caller, zeroes the
gas refund of a `FrameResult::Create` whose frame depth is > 0 (a nested create;
the top-level create tx is depth 0 and keeps its refund) via
`outcome.result.gas.set_refund(0)`. Revert/halt creates already discard the
refund, so only the success path matters. Test:
`executor::tests::nested_create_constructor_refund_is_dropped_rskj` (a factory whose
nested-CREATE constructor sets-then-clears a slot must cost MORE than a set-only
constructor — clearing adds 5000 and earns no 15000 refund; without the fix it
costs ~10000 less). Verified: exec-head #6,362,185 → #6,362,188 replays clean;
#6,362,186 tx[3] gas_used = 1,197,343 with exact state and receipts roots.

