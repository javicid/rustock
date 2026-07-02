# Deliberate RSK Design Divergences from Canonical Ethereum

Non-canonical but **intentional** RSK behavior: per-RSKIP fork policy instead
of whole Ethereum forks, fork-independent `GasCost` constants, frontier-forever
account semantics (trie existence, never EIP-161 emptiness), REMASC fee routing,
and Bridge/peg semantics. A from-scratch client could implement these correctly
from reading rskj source and the RSKIPs — unlike the latent artifacts in
[`quirks-java-artifacts.md`](./quirks-java-artifacts.md).

Part of the rskj compatibility catalogue; section numbers (§N) are historical
and shared across the whole catalogue — the index in
[`java-compatibility.md`](./java-compatibility.md) maps every § to its file.

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

## 52. Flyover response codes are FULL 256-bit two's-complement int256 (and the 21-byte address gate)

`registerFastBridgeBtcTransaction` returns a signed `int256` "flyover response
code" (rskj `FlyoverTxResponseCodes`: REFUNDED_USER -100, REFUNDED_LP -200,
UNPROCESSABLE_* -300..-305, GENERIC_ERROR -900) or, on success, the locked
amount in wei. rskj returns `BigInteger.valueOf(code)`, which the ABI encoder
serializes as a **full 256-bit two's-complement** word — every negative code
has all 31 high bytes `0xff` (e.g. -900 = `0xffff…fc7c`, 64 hex digits).

**The bug (mainnet #5,967,453).** rustock's `flyover_code_output` computed
`U256::from(code as i128 as u128)`. For a negative code `code as i128 as u128`
is the **128-bit** two's complement (`2^128 - |code|`), which `U256::from` then
**zero-extends** to 256 bits — so -900 became `0x0000…0000fffffffffffffffffffffffffffffc7c`
(only 32 trailing f's), i.e. `2^128 - 900`, not `2^256 - 900`. The calling
LiquidityBridgeContract detects GENERIC_ERROR with `bridgeResponse + 900 == 0`:
with the correct value `(2^256-900)+900` wraps at bit 256 to `0`; with the buggy
value `(2^128-900)+900 = 2^128` (non-zero), so the LBC took the wrong JUMPI
branch, did NOT revert, and ran an extra 51,580 gas (computed 194,449 vs header
142,869). Fixed by building the full 256-bit two's complement
(`U256::ZERO.wrapping_sub(U256::from(code.unsigned_abs()))` for negatives).

**Coupled gate: the 21-byte BTC-address length check.** For this block to reach
GENERIC_ERROR in the first place, rustock also had to reject the malformed input
the way rskj does. rskj parses the two BTC addresses in the **ABI layer**
(`Bridge.registerFlyoverBtcTransaction`, `Bridge.java:1359-1399`) via
`BridgeUtils.deserializeBtcAddressWithVersion` — **before**
`bridgeSupport.registerFlyoverBtcTransaction`'s isContractTx/sender/validations
checks — inside a `try/catch(Exception)` that returns `GENERIC_ERROR`. Post-RSKIP284
(hop400) that deserializer REQUIRES exactly 21 bytes (`[version || 20-byte
hash160]`, `BridgeUtils.java:603-623`) and throws `BridgeIllegalArgumentException:
Invalid address, expected 21 bytes long array` otherwise; pre-RSKIP284 the legacy
path (`BridgeUtilsLegacy.deserializeBtcAddressWithVersionLegacy`) only needs ≥21
bytes (a shorter array throws `ArrayIndexOutOfBoundsException` in its `arraycopy`).
The block's `userRefundAddress` arg was **33 bytes**, so rskj returned GENERIC_ERROR
(-900); rustock's lenient parser proceeded to the confirmations check and returned
UNPROCESSABLE_VALIDATIONS (-303). Even with the encoding fix, -303 (`+900 = 597`,
nonzero) would still mis-branch the LBC — both fixes are required.

**rskj source**: `co.rsk.peg.Bridge#registerFlyoverBtcTransaction`
(arg parse + `try/catch → FlyoverTxResponseCodes.GENERIC_ERROR`),
`co.rsk.peg.BridgeUtils#deserializeBtcAddressWithVersion` (21-byte gate),
`co.rsk.peg.BridgeUtilsLegacy#deserializeBtcAddressWithVersionLegacy` (≥21
legacy), `co.rsk.peg.FlyoverTxResponseCodes`.

**rustock**: `crates/execution/src/bridge/peg.rs` — `flyover_code_output`
(full-256-bit encoding) and the address-length gate in
`register_fast_bridge_btc_transaction` (placed right after ABI parse, before the
call-depth/caller checks, gated on `has_rskip284`). Test:
`flyover_code_output_full_256bit_twos_complement`. Verified by replaying
#5,967,453: tx[0] reverts (status=false) at gasUsed 142,869, state and receipts
roots match the header.

---

## 53. Arrowhead600 takes ONLY EIP-2028 from Istanbul — SLOAD/BALANCE/EXTCODEHASH/SSTORE keep Petersburg prices

RSK activates EVM features per-RSKIP, not by importing whole Ethereum forks. At
arrowhead600 (mainnet #6,223,700) the only EVM gas change is **RSKIP400** =
EIP-2028: non-zero calldata byte cost drops from 68 to 16
(`Transaction.getTxNonZeroDataCost` → `GasCost.TX_NO_ZERO_DATA_EIP2028`, gated on
`ConsensusRule.RSKIP400`). RSK did **not** adopt the rest of Istanbul:

- **EIP-1884** repricing — rskj `GasCost` is a class of `static final` constants,
  fork-independent: `SLOAD = 200` (Istanbul would be 800), `BALANCE = 400` (700),
  `EXT_CODE_HASH = 400` (700). They never change across forks.
- **EIP-2200** SSTORE net gas metering — rskj `VM.doSSTORE` keeps the Petersburg
  rules forever: `oldValue == null && new != 0` → `SET_SSTORE` (20000);
  `old != null && new == 0` → `CLEAR_SSTORE` (5000) + `REFUND_SSTORE` (15000)
  refund; otherwise → `RESET_SSTORE` (5000). There is **no** `gasleft <= 2300`
  reentrancy sentry.

**The bug (mainnet #6,223,700, the arrowhead600 activation block).** rustock
mapped arrowhead600 → revm `SpecId::ISTANBUL`, which is correct for the calldata
intrinsic (revm keys `calculate_initial_tx_gas_for_tx` off the SpecId) but ALSO
pulls in EIP-1884 (SLOAD 800, BALANCE 700) and EIP-2200 SSTORE metering + the
reentrancy sentry. The block over-charged by +51,576 gas: tx[2] (an SLOAD-heavy
contract call) was charged 800/SLOAD instead of 200 and ran out of gas where
rskj succeeded, and the full block intrinsic was still 68/byte because the
calldata reduction had been wired through a `gas_params` override that revm's
intrinsic path ignores. Computed 287,919 vs header 236,343.

**The fix.** Keep arrowhead600 (and arrowhead631) mapped to `ISTANBUL` so the
RSKIP400 calldata reduction lands in revm's intrinsic, then pin the
Istanbul EVM-gas changes RSK never took back to rskj's values:

- `rsk_instructions::install` re-points **SLOAD** to revm's pre-Berlin
  `host::sload` with static gas **200** and **BALANCE** to `host::balance` with
  static gas **400** (EXTCODEHASH was already pinned to 400). These are no-ops
  pre-arrowhead (PETERSBURG already prices them so) and ALSO fix lovell700+
  (SHANGHAI), which has the same EIP-1884 over-charge.
- A custom **`rsk_sstore`** instruction replicates `VM.doSSTORE`: it skips the
  EIP-2200 reentrancy sentry and calls revm's `sstore_dynamic_gas` /
  `sstore_refund` with `is_istanbul = false` (whose branch is byte-for-byte the
  Petersburg metering). `make_cfg_env` pins the SSTORE `gas_params`
  (`sstore_static` 5000, `sstore_set_without_load_cost` 15000,
  `sstore_reset_without_cold_load_cost` 0, refunds 15000/0) so the ISTANBUL/
  SHANGHAI table's net-metering split (static 800, …) is overridden away.

**rskj source**: `org.ethereum.vm.GasCost` (`SLOAD`, `BALANCE`, `EXT_CODE_HASH`,
`SET_SSTORE`/`CLEAR_SSTORE`/`RESET_SSTORE`/`REFUND_SSTORE`,
`TX_NO_ZERO_DATA_EIP2028`), `org.ethereum.vm.VM#doSSTORE` (Petersburg metering,
no sentry), `org.ethereum.core.Transaction#getTxNonZeroDataCost` (RSKIP400),
`reference.conf` (`rskip400 = arrowhead600`).

**rustock**: `crates/execution/src/hardfork.rs` (`upgrade_to_spec_id`:
Arrowhead600/631 → ISTANBUL, with the rationale comment),
`crates/execution/src/rsk_instructions.rs` (`install` SLOAD/BALANCE static-gas
overrides + `rsk_sstore`), `crates/execution/src/executor.rs` (`make_cfg_env`
SSTORE gas_params pin). Tests:
`test_rskip400_calldata_reduction_at_arrowhead_activation` (16 vs 68/byte at the
activation boundary) and the updated `test_cfg_env_gas_params_follow_spec`.
Verified by replaying #6,223,700: tx[0..3] gasUsed 57073/56232/123038/0 match the
canonical receipts, total 236,343 == header, state and receipts roots match.

## §68 lovell700 maps to SHANGHAI but RSK adopted none of Berlin/London's EVM gas changes (#7,338,024)

rustock maps lovell700+ to revm's SHANGHAI spec (the closest spec carrying PUSH0,
the only Shanghai EVM feature RSK uses; MCOPY/TLOAD/TSTORE are installed separately).
But SHANGHAI implies Berlin and London, and revm's instruction/handler bodies gate
several gas behaviours on `is_enabled_in(BERLIN)` / `is_enabled_in(LONDON)`. RSK's
`GasCost` is fork-independent and RSK never adopted EIP-2929, EIP-3529, or EIP-1559,
so three SHANGHAI behaviours had to be neutralised. All three are no-ops for the
pre-lovell specs (<= ISTANBUL) already validated, since the underlying gas params are
0 / the spec branch is not taken there — they only change lovell700+. All three first
surfaced at the lovell700 activation block #7,338,024.

**(a) EIP-2929 warm/cold access (Berlin).** revm's `host::sload`,
`berlin_load_account!` (BALANCE/EXTCODE*), and the CALL helpers add a cold-access
surcharge — read from `GasParams::cold_storage_additional_cost()` /
`cold_account_additional_cost()` — on the first touch of a slot/account when spec >=
BERLIN. RSK charges a flat SLOAD=200, account access=400/static at every fork, no
cold surcharge. `make_cfg_env` now zeros `cold_account_additional_cost`,
`cold_storage_additional_cost`, and `cold_storage_cost`. (These are 0 for every spec
< BERLIN, so the override is a no-op pre-lovell.) At #7,338,024 two cold SLOADs were
each over-charged 2000 gas (cold 2200 vs flat 200), inflating tx[0] gas_used 58749 ->
62749. Test: `executor::tests::test_cfg_env_no_eip2929_cold_access_cost`.

**(b) EIP-1559 base-fee burn (London).** revm's `post_execution::reward_beneficiary`
pays the beneficiary only the priority fee (`effective_gas_price - basefee`) at LONDON+,
burning the base fee. RSK has no EIP-1559: the WHOLE `gasUsed * gasPrice` goes to
REMASC (the block beneficiary). rustock maps RSK's per-block `minimumGasPrice` to
revm's `basefee`, so revm burned `minimumGasPrice * gasUsed`. `RskHandler::reward_beneficiary`
now credits the beneficiary the full `effective_gas_price * (gas.spent() - gas.refunded())`
in the normal path (no base-fee subtraction); pre-LONDON specs already did exactly
this, so it is identical pre-lovell. At #7,338,024 REMASC was short by basefee
23696000 * gasUsed 58749 = 1,392,116,304,000 wei (the only diverging state leaf once
gas was fixed).

**(c) EIP-3529 refund reduction (London) — latent.** revm's `post_execution::refund`
caps the gas refund at `gas_used/5` and uses the reduced 4800 SSTORE-clear refund at
LONDON+. RSK keeps the Frontier `gas_used/2` cap and the 15000 clear refund forever.
`RskHandler::refund` now always calls `set_final_refund(false)` (the /2 cap); the
15000 clear refund is already pinned in `make_cfg_env`. This did not bite #7,338,024
(its tx accrued no refund) but is the same root cause, fixed proactively: a tx whose
SSTORE-clear refund exceeds gas_used/5 but not gas_used/2 would otherwise be
over-charged. Pre-LONDON specs already pass `false`, so it is identical pre-lovell.

Verified: exec-head #7,338,023 -> replay #7,338,024–#7,338,200 all match state and
receipts roots exactly; 554 tests pass.

## §69 lovell700 TLOAD/TSTORE/MCOPY opcodes (RSKIP446/445) installed despite the SHANGHAI mapping (#7,338,135)

Companion to §68's spec-mapping trap. RSK adopted EIP-1153 transient storage
(TLOAD 0x5c / TSTORE 0x5d, RSKIP446) and EIP-5656 (MCOPY 0x5e, RSKIP445) at lovell700.
These are Ethereum **Cancun** opcodes, but rustock maps lovell700 to SHANGHAI (< CANCUN),
so revm's stock instruction bodies begin with `check!(CANCUN)` and treat the bytes as
invalid — halting the frame and consuming all gas. The first mainnet contract to use
one (a TSTORE in tx[11] of #7,338,135) therefore reverted in rustock while rskj ran it
to success, forking the receipts root (and would have forked state on any persisted
write).

rskj gas (fork-independent `GasCost`): `TLOAD = TSTORE = 100`; `MCOPY` = VERY_LOW (3)
base + `computeMemoryCopyGas` (3 per 32-byte word + memory-expansion), i.e. EIP-1153 /
EIP-5656 exactly. `doTSTORE` raises a modification exception inside a static call.

**rustock**: `rsk_instructions::install` now installs unchecked `rsk_tload` /
`rsk_tstore` (static gas 100) and `rsk_mcopy` (static gas 3, body charges
`mcopy_cost(len)` + `resize_memory`) when the new `has_rskip446` / `has_rskip445`
(Lovell700) flags are set — the same "install ahead of the revm spec gate" pattern
used for PUSH0 at arrowhead600 (§…). The bodies mirror revm's
`host::tload`/`host::tstore`/`memory::mcopy` minus the CANCUN check; transient storage
itself is revm's journal-backed `Host::tload`/`tstore` (cleared per transaction).
Tests: `hardfork::tests::test_rskip445_rskip446_mainnet`. Verified: exec-head
#7,338,134 → replay #7,338,135–#7,339,000 all match state and receipts roots exactly.

## §71 EIP-3529 also zeroed the SELFDESTRUCT refund — RSK keeps 24000 (#7,388,594)

The third EIP-3529 piece, completing §68(c). EIP-3529 (London) made TWO refund changes
besides the gas_used/5 cap: it reduced the SSTORE-clear refund (handled in §68 by
pinning `sstore_clearing_slot_refund` = 15000) AND it **zeroed the SELFDESTRUCT
refund**. revm sets `selfdestruct_refund` = 24000 by default but `= 0` at LONDON+
(gas_params.rs). lovell700 maps to SHANGHAI (>= LONDON), so rustock's `rsk_selfdestruct`
recorded a 0 refund. RSK keeps `GasCost.SUICIDE_REFUND` = 24000 at every fork.

mainnet #7,388,594 tx[1] (a contract-creation tx whose constructor SELFDESTRUCTs):
rskj gas_used 1,078,721, rustock 1,102,721 (+24000 — exactly the unrefunded
SELFDESTRUCT). `make_cfg_env` now also pins `GasId::selfdestruct_refund()` = 24000
alongside the SSTORE refund pins. Equals the pre-London default, so a no-op pre-lovell.
Test: `executor::tests::test_cfg_env_selfdestruct_refund_kept`. Verified: exec-head
#7,388,593 → replay #7,388,594–#7,390,000 match state and receipts roots exactly; 557
tests pass.

## §72 EIP-2929: also zero warm_storage_read_cost (cold SELFDESTRUCT beneficiary) (#7,403,649)

Follow-up to §68(a). Zeroing the two `cold_*_additional_cost` params removed the
EIP-2929 surcharge for SLOAD/BALANCE/EXTCODE*/CALL, but SELFDESTRUCT computes its
cold-beneficiary cost as `selfdestruct_cold_cost() = cold_account_additional_cost +
warm_storage_read_cost` (revm gas_params). With only the former zeroed, a SELFDESTRUCT
to a **cold** beneficiary still cost `warm_storage_read_cost` = 100 at SHANGHAI, which
RSK never charges (`GasCost.SUICIDE` is a flat 5000, plus 25000 only for a brand-new
beneficiary).

mainnet #7,403,649 tx[2] (a contract-creation whose constructor SELFDESTRUCTs to a cold
address): rskj gas 37,806, rustock 37,906 (+100). `make_cfg_env` now also zeros
`GasId::warm_storage_read_cost()`. Every other consumer takes its base from a
statically-overridden gas value (SLOAD 200, BALANCE 400, CALL static, SSTORE 5000), and
it is 0 for specs < BERLIN, so this is a no-op pre-lovell. Test extends
`executor::tests::test_cfg_env_no_eip2929_cold_access_cost` (asserts
`selfdestruct_cold_cost() == 0`). Verified: exec-head #7,403,648 → replay
#7,403,649–#7,408,000 match state and receipts roots exactly; 557 tests pass.

## §73 EIP-2929 dropped EXTCODECOPY's flat base — re-pin it to 700 (#7,515,160)

Sibling to §72, but on the *static* side rather than gas_params. rskj
`GasCost.EXT_CODE_COPY` is a flat **700** at every fork (EIP-150 TANGERINE,
never repriced). revm builds the EXTCODECOPY base from its
instruction-table static gas, which `instruction_table_gas_changes_spec`
(revm-interpreter-34.0.0/src/instructions.rs:101,122) sets to 700 at
TANGERINE but **drops to `WARM_STORAGE_READ_COST` at BERLIN** — the remainder
moving into a cold-account surcharge that EIP-2929 charges separately. lovell700
maps to SHANGHAI (≥ BERLIN), so revm's stock EXTCODECOPY static became
`WARM_STORAGE_READ_COST` (100) and, with the cold surcharge pinned to 0 by §72,
EXTCODECOPY undercharged by 600 (700 − 100). Unlike SLOAD/BALANCE/EXTCODESIZE/CALL
(all explicitly re-installed in `rsk_instructions::install`), EXTCODECOPY had no
override, so it inherited the spec table.

mainnet #7,515,160 tx[0] (a CREATE/CREATE2 sequence; the deployed contract at
`0x00000a96386d6ddea78a246abd914e59386aa688` runs EXTCODECOPY at pc 0x1b): header
gas 1,976,590 vs computed 1,975,990 (−600). `rsk_instructions::install` now
re-installs `opcode::EXTCODECOPY` with revm's stock `host::extcodecopy` body and
an explicit static gas of 700 (`EXT_CODE_COPY_GAS`). The body still adds the
per-word copy cost (3/word) + memory-expansion + cold-account surcharge (0), so
total = 700 + copy + memexp = rskj's `EXT_CODE_COPY`. Pre-Berlin the stock static
was already 700, so this is behavior-preserving there too. Test
`executor::tests::test_extcodecopy_flat_700_at_lovell700` (EXTCODECOPY(self,0,0,0)
at #7,338,024 = 21,712, isolating the 700 base). Verified: exec-head #7,515,159 →
replay #7,515,160 + #7,515,161/200, #7,516,000, #7,520,000 match state and receipts
roots exactly; 558 tests pass.

