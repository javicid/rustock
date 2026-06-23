//! rskj-compatible CALL-family instruction overrides.
//!
//! rskj's VM (org.ethereum.vm.VM/Program) never adopted Ethereum's CALL gas
//! forwarding rules, at any era:
//!
//! - `calleeGas = min(remainingGas, requestedGas + STIPEND_CALL)` — the 2300
//!   stipend on value transfers is ADDED to the requested gas and CHARGED to
//!   the caller (canonical EVM conjures the stipend for free, so an unused
//!   stipend effectively refunds 2300 to the caller — mainnet block #356,285
//!   exposed the 2300 difference on a `transfer()` to an EOA).
//! - There is no EIP-150 63/64 retention: a request larger than the remaining
//!   gas is capped at the remaining gas instead of erroring or retaining 1/64.
//! - `NEW_ACCT_CALL` (25,000) is charged for op CALL whenever the callee does
//!   not exist, regardless of value and era (frontier style; EIP-161's
//!   value>0 condition never applied).
//!
//! CREATE/CREATE2 forward all remaining gas in rskj (`Program.createContract`
//! spends `getRemainingGas()` into the child); that is handled by overriding
//! the `call_stipend_reduction` gas param (see `make_cfg_env`) rather than a
//! custom instruction.

use revm::bytecode::opcode;
use revm::handler::instructions::EthInstructions;
use revm::interpreter::instructions::contract::load_account_delegated_handle_error;
use revm::interpreter::interpreter_types::{InputsTr, InterpreterTypes, LoopControl, MemoryTr, RuntimeFlag, StackTr};
use revm::interpreter::{
    CallInput, CallInputs, CallScheme, CallValue, FrameInput, Host, Instruction,
    InstructionContext, InstructionResult, InterpreterAction,
};
use revm::context_interface::host::LoadError;
use revm::primitives::{Address, B256, U256};

/// rskj `GasCost.CALL`: static cost of every CALL-family opcode.
const CALL_STATIC_GAS: u64 = 700;

/// rskj `GasCost.EXT_CODE_SIZE` (== revm's pre-Berlin EXTCODESIZE), EIP-150.
const EXT_CODE_SIZE_GAS: u64 = 700;

/// rskj `GasCost.SLOAD`: fork-independent (RSK never took EIP-1884's 800).
const SLOAD_GAS: u64 = 200;

/// rskj `GasCost.BALANCE`: fork-independent (RSK never took EIP-1884's 700).
const BALANCE_GAS: u64 = 400;

/// rskj `GasCost.SUICIDE`: static cost of SELFDESTRUCT (EIP-150 onward, which
/// is always active for RSK eras). Mirrors revm's TANGERINE+ static gas.
const SUICIDE_STATIC_GAS: u64 = 5000;

thread_local! {
    /// Addresses for which EXTCODESIZE must report `2^256-1` (rskj RSKIP90:
    /// `VM.doCODESIZE` returns `DataWord.MAX_VALUE` for any active precompile).
    /// Set by `install` for the block being executed (single-threaded).
    static EXTCODESIZE_MAX_PRECOMPILES: core::cell::RefCell<Vec<Address>> =
        const { core::cell::RefCell::new(Vec::new()) };
    /// Active precompiles for which EXTCODEHASH must report `keccak256("")`
    /// (rskj `VM.doEXTCODEHASH` precompile branch). Set by `install`.
    static EXTCODEHASH_PRECOMPILES: core::cell::RefCell<Vec<Address>> =
        const { core::cell::RefCell::new(Vec::new()) };
    /// The block's real miner address (`header.getCoinbase()`), pushed by the
    /// COINBASE opcode. rustock sets `block.beneficiary = REMASC_ADDR` so revm
    /// routes gas fees to REMASC; that would make COINBASE return REMASC, but
    /// rskj's `OpCode.COINBASE` returns the actual miner. Set by `install`.
    static REAL_COINBASE: core::cell::Cell<Address> =
        const { core::cell::Cell::new(Address::ZERO) };
}

/// Install the rskj-semantics CALL family into an instruction table.
///
/// `extcodehash_enabled` reflects RSKIP140 (papyrus): the spec is PETERSBURG
/// from wasabi on (for the RSKIP120 shift opcodes and RSKIP125 CREATE2), but
/// EXTCODEHASH only activates at papyrus — so before that it must throw an
/// invalid-opcode exception (consuming all gas), matching rskj's VM.
pub fn install<WIRE, HOST>(
    instructions: &mut EthInstructions<WIRE, HOST>,
    extcodehash_enabled: bool,
    istanbul_opcodes_enabled: bool,
    push0_enabled: bool,
    transient_storage_enabled: bool,
    mcopy_enabled: bool,
    extcodesize_max_precompiles: &[Address],
    extcodehash_precompiles: &[Address],
    real_coinbase: Address,
) where
    WIRE: InterpreterTypes,
    HOST: Host,
{
    // RSKIP446 (lovell700): transient storage TLOAD/TSTORE (0x5c/0x5d,
    // EIP-1153, rskj `GasCost.TLOAD`/`TSTORE` = 100 each). RSKIP445 (lovell700):
    // MCOPY (0x5e, EIP-5656, VERY_LOW base + per-word copy + memory expansion).
    // revm gates all three on the CANCUN spec, but lovell700 maps to SHANGHAI,
    // so install unchecked versions (same pattern as PUSH0 at arrowhead600).
    if transient_storage_enabled {
        instructions.insert_instruction(
            opcode::TLOAD,
            Instruction::new(rsk_tload::<WIRE, HOST>, 100),
        );
        instructions.insert_instruction(
            opcode::TSTORE,
            Instruction::new(rsk_tstore::<WIRE, HOST>, 100),
        );
    }
    if mcopy_enabled {
        instructions.insert_instruction(
            opcode::MCOPY,
            Instruction::new(rsk_mcopy::<WIRE, HOST>, 3),
        );
    }
    // RSKIP398 (arrowhead600): PUSH0 (0x5f, rskj `OpCode.PUSH0` BASE_TIER = 2 gas)
    // pushes a zero word. rskj enables it at arrowhead600 but rustock maps that to
    // ISTANBUL (for RSKIP400 calldata), where revm's stock PUSH0 halts NotActivated
    // (it gates on SHANGHAI). Install an unchecked PUSH0 from arrowhead600 onward.
    if push0_enabled {
        instructions.insert_instruction(
            opcode::PUSH0,
            Instruction::new(rsk_push0::<WIRE, HOST>, 2),
        );
    }
    if !extcodehash_enabled {
        instructions.insert_instruction(
            opcode::EXTCODEHASH,
            Instruction::new(invalid_opcode::<WIRE, HOST>, 0),
        );
    } else {
        // rskj `VM.doEXTCODEHASH` keys on trie existence and special-cases
        // active precompiles to `keccak256("")` — see `rsk_extcodehash`.
        EXTCODEHASH_PRECOMPILES
            .with(|p| *p.borrow_mut() = extcodehash_precompiles.to_vec());
        instructions.insert_instruction(
            opcode::EXTCODEHASH,
            Instruction::new(rsk_extcodehash::<WIRE, HOST>, 400),
        );
    }
    // RSKIP152 CHAINID / RSKIP151 SELFBALANCE (papyrus200): the spec stays
    // PETERSBURG (RSK never adopted the Istanbul gas repricings), so revm's
    // spec-checked impls would throw NotActivated — install uncheck-ed
    // versions with rskj's tier costs (CHAINID BASE=2, SELFBALANCE LOW=5).
    if istanbul_opcodes_enabled {
        instructions.insert_instruction(
            opcode::CHAINID,
            Instruction::new(rsk_chainid::<WIRE, HOST>, 2),
        );
        instructions.insert_instruction(
            opcode::SELFBALANCE,
            Instruction::new(rsk_selfbalance::<WIRE, HOST>, 5),
        );
    } else {
        // Pre-papyrus rskj throws invalid-opcode (all frame gas consumed);
        // revm's spec-checked impls would halt NotActivated returning the
        // remaining gas instead.
        instructions.insert_instruction(
            opcode::CHAINID,
            Instruction::new(invalid_opcode::<WIRE, HOST>, 0),
        );
        instructions.insert_instruction(
            opcode::SELFBALANCE,
            Instruction::new(invalid_opcode::<WIRE, HOST>, 0),
        );
    }
    // rskj's `GasCost` constants are fork-independent (`static final`), so RSK
    // never adopted EIP-1884's Istanbul repricing of SLOAD (200→800) and BALANCE
    // (400→700). Arrowhead600+ maps to revm's ISTANBUL (for the RSKIP400 calldata
    // reduction, which is keyed off the SpecId), so revm's default table would
    // charge the bumped Istanbul prices. Pin both back to rskj's `GasCost.SLOAD`
    // (200) and `GasCost.BALANCE` (400). Pre-Istanbul specs already use these
    // values, so the override is a no-op there; at SHANGHAI (lovell700+) it also
    // corrects the same EIP-1884 over-charge. The instruction bodies are revm's
    // own pre-Berlin SLOAD/BALANCE (RSK never reaches Berlin), which charge
    // everything via the static gas we set here. (Mainnet #6,223,700.)
    instructions.insert_instruction(
        opcode::SLOAD,
        Instruction::new(
            revm::interpreter::instructions::host::sload::<WIRE, HOST>,
            SLOAD_GAS,
        ),
    );
    instructions.insert_instruction(
        opcode::BALANCE,
        Instruction::new(
            revm::interpreter::instructions::host::balance::<WIRE, HOST>,
            BALANCE_GAS,
        ),
    );

    // rskj `VM.doSSTORE` keeps Petersburg metering forever (SET=20000,
    // RESET=CLEAR=5000, REFUND=15000) and has no EIP-2200 reentrancy sentry. Under
    // the ISTANBUL/SHANGHAI specs revm's stock SSTORE applies EIP-2200 net metering
    // and the `gasleft <= stipend` sentry — both consensus divergences for RSK. Use
    // a Petersburg-semantics SSTORE (the gas_params it reads are pinned to rskj's
    // values in make_cfg_env). Static gas 0 here: the cost is charged inside.
    instructions.insert_instruction(
        opcode::SSTORE,
        Instruction::new(rsk_sstore::<WIRE, HOST>, 0),
    );

    // RSKIP90: EXTCODESIZE of an active precompile reports 2^256-1.
    EXTCODESIZE_MAX_PRECOMPILES
        .with(|p| *p.borrow_mut() = extcodesize_max_precompiles.to_vec());
    instructions.insert_instruction(
        opcode::EXTCODESIZE,
        Instruction::new(rsk_extcodesize::<WIRE, HOST>, EXT_CODE_SIZE_GAS),
    );
    instructions.insert_instruction(
        opcode::CALL,
        Instruction::new(rsk_call::<WIRE, HOST>, CALL_STATIC_GAS),
    );
    instructions.insert_instruction(
        opcode::CALLCODE,
        Instruction::new(rsk_call_code::<WIRE, HOST>, CALL_STATIC_GAS),
    );
    instructions.insert_instruction(
        opcode::DELEGATECALL,
        Instruction::new(rsk_delegate_call::<WIRE, HOST>, CALL_STATIC_GAS),
    );
    instructions.insert_instruction(
        opcode::STATICCALL,
        Instruction::new(rsk_static_call::<WIRE, HOST>, CALL_STATIC_GAS),
    );
    instructions.insert_instruction(
        opcode::SELFDESTRUCT,
        Instruction::new(rsk_selfdestruct::<WIRE, HOST>, SUICIDE_STATIC_GAS),
    );

    // rskj `OpCode.COINBASE` returns the block's real miner; rustock keeps
    // `block.beneficiary = REMASC_ADDR` (for gas-fee routing) so the default
    // COINBASE would return REMASC. Push the real coinbase instead.
    REAL_COINBASE.with(|c| c.set(real_coinbase));
    instructions.insert_instruction(
        opcode::COINBASE,
        Instruction::new(rsk_coinbase::<WIRE, HOST>, 2),
    );

    // Divergence-hunt diagnostic (env-gated, temporary): log pc/op/gas for
    // EVERY opcode. The wrapper re-dispatches to the default PETERSBURG
    // table, except for the rsk-custom opcodes which dispatch to the local
    // overrides installed above.
    if std::env::var_os("RUSTOCK_TRACE_ALL_OPS").is_some() {
        EXTCODEHASH_ENABLED.with(|f| f.set(extcodehash_enabled));
        ISTANBUL_OPCODES_ENABLED.with(|f| f.set(istanbul_opcodes_enabled));
        PUSH0_ENABLED.with(|f| f.set(push0_enabled));
        let default_table = revm::interpreter::instructions::instruction_table_gas_changes_spec::<
            WIRE,
            HOST,
        >(revm::primitives::hardfork::SpecId::PETERSBURG);
        for op in 0u16..=255 {
            let op = op as u8;
            let static_gas = match op {
                opcode::EXTCODESIZE | opcode::CALL | opcode::CALLCODE
                | opcode::DELEGATECALL | opcode::STATICCALL => CALL_STATIC_GAS,
                opcode::EXTCODEHASH if !extcodehash_enabled => 0,
                opcode::CHAINID if istanbul_opcodes_enabled => 2,
                opcode::SELFBALANCE if istanbul_opcodes_enabled => 5,
                opcode::PUSH0 if push0_enabled => 2,
                _ => default_table[op as usize].static_gas(),
            };
            instructions.insert_instruction(
                op,
                Instruction::new(traced_all::<WIRE, HOST>, static_gas),
            );
        }
        return;
    }

    // Divergence-hunt diagnostics (env-gated): log the inputs of opcodes
    // whose gas charge can dwarf the remaining gas, to locate the exact
    // OOG-with-gas-remaining halt site.
    if std::env::var_os("RUSTOCK_TRACE_OPS").is_some() {
        instructions.insert_instruction(
            opcode::KECCAK256,
            Instruction::new(traced_keccak::<WIRE, HOST>, 30),
        );
        instructions.insert_instruction(
            opcode::CODECOPY,
            Instruction::new(traced_codecopy::<WIRE, HOST>, 3),
        );
        instructions.insert_instruction(
            opcode::RETURN,
            Instruction::new(traced_return::<WIRE, HOST>, 0),
        );
        instructions.insert_instruction(
            opcode::EXP,
            Instruction::new(traced_exp::<WIRE, HOST>, 10),
        );
    }
}

/// An opcode that is not yet activated at this block height: rskj throws an
/// invalid-opcode exception, which halts the frame and consumes all gas.
fn invalid_opcode<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    context.interpreter.halt(InstructionResult::OpcodeNotFound);
}

/// `keccak256("")`, the code hash rskj reports for an existing-but-codeless
/// account and for active precompiles (`Keccak256Helper.keccak256(EMPTY)`).
pub(crate) const KECCAK_EMPTY: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

/// EXTCODEHASH with rskj's `VM.doEXTCODEHASH` / `getCodeHashStandard`
/// semantics, which key on TRIE EXISTENCE (RSK never adopted EIP-161/1052
/// emptiness):
///   - active precompile  -> `keccak256("")` (rskj special-cases precompiles);
///   - account absent from the trie -> `0`;
///   - account present but not a contract (no code) -> `keccak256("")`;
///   - contract -> its code hash.
/// revm's stock EXTCODEHASH instead returns `0` whenever `AccountInfo::is_empty()`
/// (EIP-161: balance==0 && nonce==0 && no code), so an existing-but-empty
/// account (e.g. a zero-balance EOA that a prior tx created via a 0-value call)
/// would wrongly hash to `0` instead of `keccak256("")` — block #3,631,998 tx[1]
/// exposed this (+11 gas, divergent revert branch). `is_empty` here is the
/// host's flag (`true` only when `Database::basic` returned `None`, i.e. the
/// trie has no node — see the HOMESTEAD journal pin in `RskHandler`), which is
/// exactly rskj's `isExist`.
fn rsk_extcodehash<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let Some(([], top)) = context.interpreter.stack.popn_top::<0>() else {
        context.interpreter.halt_underflow();
        return;
    };
    let addr = Address::from_word(B256::from(*top));

    if EXTCODEHASH_PRECOMPILES.with(|p| p.borrow().contains(&addr)) {
        *top = KECCAK_EMPTY.into();
        return;
    }

    let Ok(load) = context.host.load_account_info_skip_cold_load(addr, false, false) else {
        context.interpreter.halt_fatal();
        return;
    };
    // `is_empty` is the host's trie-existence flag (rskj `isExist`): absent ->
    // 0; present-but-codeless -> keccak256(""); contract -> its code hash.
    let result = if load.is_empty {
        B256::ZERO
    } else if load.account.is_empty_code_hash() || load.account.code_hash.is_zero() {
        KECCAK_EMPTY
    } else {
        load.account.code_hash
    };
    *top = result.into();
}

/// CHAINID without revm's ISTANBUL spec check (RSKIP152 activates it at
/// papyrus200 while the spec stays PETERSBURG).
fn rsk_chainid<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if !context.interpreter.stack.push(context.host.chain_id()) {
        context.interpreter.halt_overflow();
    }
}

/// PUSH0 (RSKIP398, arrowhead600) without revm's SHANGHAI spec check: pushes a
/// zero word. rskj `VM.doPUSH0`. Static gas (2, BASE_TIER) is charged by the
/// instruction table entry installed in `install`.
fn rsk_push0<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if !context.interpreter.stack.push(U256::ZERO) {
        context.interpreter.halt_overflow();
    }
}

/// RSKIP446 TLOAD (0x5c, EIP-1153): push the transient-storage value at the
/// popped key (zero if unset). Flat 100 gas (charged by the static table). Same
/// body as revm's `host::tload` minus the CANCUN spec gate.
fn rsk_tload<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let Some([key]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let value = context.host.tload(context.interpreter.input.target_address(), key);
    if !context.interpreter.stack.push(value) {
        context.interpreter.halt_overflow();
    }
}

/// RSKIP446 TSTORE (0x5d, EIP-1153): write value at key in transient storage.
/// Reverts inside a static call (rskj `doTSTORE` modificationException). Flat
/// 100 gas. Same body as revm's `host::tstore` minus the CANCUN spec gate.
fn rsk_tstore<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if context.interpreter.runtime_flag.is_static() {
        context
            .interpreter
            .halt(InstructionResult::StateChangeDuringStaticCall);
        return;
    }
    let Some([key, value]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    context
        .host
        .tstore(context.interpreter.input.target_address(), key, value);
}

/// RSKIP445 MCOPY (0x5e, EIP-5656): copy `len` bytes within memory from `src`
/// to `dst`. Cost = VERY_LOW (3, static table) + 3 per word + memory expansion,
/// matching rskj `doMCOPY` (VERY_LOW + computeMemoryCopyGas). Same body as
/// revm's `memory::mcopy` minus the CANCUN spec gate.
fn rsk_mcopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let Some([dst, src, len]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let Ok(len) = usize::try_from(len) else {
        context.interpreter.halt(InstructionResult::InvalidOperandOOG);
        return;
    };
    if !context
        .interpreter
        .gas
        .record_cost(context.host.gas_params().mcopy_cost(len))
    {
        context.interpreter.halt_oog();
        return;
    }
    if len == 0 {
        return;
    }
    let (Ok(dst), Ok(src)) = (usize::try_from(dst), usize::try_from(src)) else {
        context.interpreter.halt(InstructionResult::InvalidOperandOOG);
        return;
    };
    let gas_params = context.host.gas_params();
    if !context
        .interpreter
        .resize_memory(&gas_params, core::cmp::max(dst, src), len)
    {
        return;
    }
    context.interpreter.memory.copy(dst, src, len);
}

/// COINBASE returning rskj's real miner address (`header.getCoinbase()`)
/// rather than revm's `block.beneficiary` (which rustock pins to REMASC_ADDR
/// so gas fees route to the REMASC contract). See `REAL_COINBASE`.
fn rsk_coinbase<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let coinbase = REAL_COINBASE.with(|c| c.get());
    if !context.interpreter.stack.push(U256::from_be_bytes(coinbase.into_word().0)) {
        context.interpreter.halt_overflow();
    }
}

/// SELFBALANCE without revm's ISTANBUL spec check (RSKIP151, papyrus200).
fn rsk_selfbalance<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let Some(balance) = context.host.balance(context.interpreter.input.target_address()) else {
        context.interpreter.halt_fatal();
        return;
    };
    if !context.interpreter.stack.push(balance.data) {
        context.interpreter.halt_overflow();
    }
}

/// EXTCODESIZE with rskj's RSKIP90 quirk: the code size of an active precompile
/// is reported as `2^256-1` (`VM.doCODESIZE` → `DataWord.MAX_VALUE`), so a proxy
/// guarding `extcodesize(precompile) != 0` works. All other addresses fall
/// through to revm's standard EXTCODESIZE.
fn rsk_extcodesize<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    let addr = {
        let Some(([], top)) = context.interpreter.stack.popn_top::<0>() else {
            context.interpreter.halt_underflow();
            return;
        };
        Address::from_word(B256::from(*top))
    };
    let is_precompile = EXTCODESIZE_MAX_PRECOMPILES.with(|p| p.borrow().contains(&addr));
    if is_precompile {
        if let Some(([], top)) = context.interpreter.stack.popn_top::<0>() {
            *top = U256::MAX;
        }
    } else {
        revm::interpreter::instructions::host::extcodesize(context);
    }
}

macro_rules! traced_op {
    ($name:ident, $label:literal, $peek:literal, $delegate:path) => {
        fn $name<WIRE: InterpreterTypes, H: Host + ?Sized>(
            context: InstructionContext<'_, H, WIRE>,
        ) {
            let data = context.interpreter.stack.data();
            let vals: Vec<String> = data
                .iter()
                .rev()
                .take($peek)
                .map(|v| format!("{:x}", v))
                .collect();
            tracing::debug!(
                "OP {} stack_top={:?} gas_remaining={}",
                $label,
                vals,
                context.interpreter.gas.remaining()
            );
            $delegate(context)
        }
    };
}

thread_local! {
    /// RSKIP140 flag for the all-ops tracer's EXTCODEHASH dispatch.
    static EXTCODEHASH_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
    /// RSKIP151/152 flag for the all-ops tracer's CHAINID/SELFBALANCE dispatch.
    static ISTANBUL_OPCODES_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
    /// RSKIP398 flag for the all-ops tracer's PUSH0 dispatch.
    static PUSH0_ENABLED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// All-ops tracer: log pc/opcode/gas (post-static-charge), then dispatch to
/// the real implementation (custom rsk op or default PETERSBURG table).
fn traced_all<WIRE: InterpreterTypes, HOST: Host>(
    context: InstructionContext<'_, HOST, WIRE>,
) {
    use revm::interpreter::interpreter_types::{InputsTr, Jumps, LegacyBytecode};
    let pc = context.interpreter.bytecode.pc().saturating_sub(1);
    // step() already advanced pc by 1, so the executing opcode is at pc-1.
    let op = context
        .interpreter
        .bytecode
        .bytecode_slice()
        .get(pc)
        .copied()
        .unwrap_or(opcode::STOP);
    tracing::debug!(
        "OPTRACE addr={} pc={pc:04x} op={:02x} {} gas={}",
        context.interpreter.input.target_address(),
        op,
        revm::bytecode::opcode::OpCode::new(op).map(|o| o.as_str()).unwrap_or("?"),
        context.interpreter.gas.remaining(),
    );
    // NOTE: addr= field added for the per-opcode trace oracle (rskj diff).
    match op {
        opcode::EXTCODESIZE => rsk_extcodesize(context),
        opcode::CALL => rsk_call(context),
        opcode::CALLCODE => rsk_call_code(context),
        opcode::DELEGATECALL => rsk_delegate_call(context),
        opcode::STATICCALL => rsk_static_call(context),
        opcode::SELFDESTRUCT => rsk_selfdestruct(context),
        opcode::EXTCODEHASH if !EXTCODEHASH_ENABLED.with(|f| f.get()) => {
            invalid_opcode(context)
        }
        opcode::EXTCODEHASH => rsk_extcodehash(context),
        opcode::CHAINID => {
            if ISTANBUL_OPCODES_ENABLED.with(|f| f.get()) {
                rsk_chainid(context)
            } else {
                invalid_opcode(context)
            }
        }
        opcode::SELFBALANCE => {
            if ISTANBUL_OPCODES_ENABLED.with(|f| f.get()) {
                rsk_selfbalance(context)
            } else {
                invalid_opcode(context)
            }
        }
        opcode::PUSH0 => {
            if PUSH0_ENABLED.with(|f| f.get()) {
                rsk_push0(context)
            } else {
                invalid_opcode(context)
            }
        }
        _ => {
            let table = revm::interpreter::instructions::instruction_table_gas_changes_spec::<
                WIRE,
                HOST,
            >(revm::primitives::hardfork::SpecId::PETERSBURG);
            table[op as usize].execute(context)
        }
    }
}

traced_op!(traced_keccak, "KECCAK256", 2, revm::interpreter::instructions::system::keccak256);
traced_op!(traced_codecopy, "CODECOPY", 3, revm::interpreter::instructions::system::codecopy);
traced_op!(traced_return, "RETURN", 2, revm::interpreter::instructions::control::ret);
traced_op!(traced_exp, "EXP", 2, revm::interpreter::instructions::arithmetic::exp);

/// revm's `get_memory_input_and_out_ranges`, except the OUT range keeps the
/// REAL offset when outSize == 0 (revm substitutes a usize::MAX sentinel).
/// Pre-RSKIP150 the handler writes a successful precompile's full output at
/// rskj's actual outOffs (`Program.memorySave`), so the offset must survive
/// zero-size out regions.
fn rsk_memory_input_and_out_ranges<WIRE: InterpreterTypes>(
    interpreter: &mut revm::interpreter::Interpreter<WIRE>,
    gas_params: &revm::context_interface::cfg::GasParams,
) -> Option<(core::ops::Range<usize>, core::ops::Range<usize>)> {
    let Some([in_offset, in_len, out_offset, out_len]) = interpreter.stack.popn() else {
        interpreter.halt_underflow();
        return None;
    };

    let mut in_range = rsk_call_memory_range(interpreter, gas_params, in_offset, in_len)?;
    if !in_range.is_empty() {
        let off = interpreter.memory.local_memory_offset();
        in_range = in_range.start.saturating_add(off)..in_range.end.saturating_add(off);
    }
    let out_range = rsk_call_memory_range(interpreter, gas_params, out_offset, out_len)?;
    Some((in_range, out_range))
}

fn rsk_call_memory_range<WIRE: InterpreterTypes>(
    interpreter: &mut revm::interpreter::Interpreter<WIRE>,
    gas_params: &revm::context_interface::cfg::GasParams,
    offset: U256,
    len: U256,
) -> Option<core::ops::Range<usize>> {
    let Ok(len) = usize::try_from(len) else {
        interpreter.halt(InstructionResult::InvalidOperandOOG);
        return None;
    };
    let offset = if len != 0 {
        let Ok(offset) = usize::try_from(offset) else {
            interpreter.halt(InstructionResult::InvalidOperandOOG);
            return None;
        };
        if !interpreter.resize_memory(gas_params, offset, len) {
            return None;
        }
        offset
    } else {
        // Zero-size region: keep the true offset when it fits, falling back
        // to revm's usize::MAX sentinel (which disables the pre-RSKIP150
        // unbounded write) for pathological offsets.
        usize::try_from(offset).unwrap_or(usize::MAX)
    };
    Some(offset..offset.saturating_add(len))
}

/// rskj `VM.getMessageCall` gas math, shared by the four call opcodes.
///
/// Assumes the base costs (static 700, memory expansion, value transfer,
/// new-account) are already charged. Charges and returns the callee gas:
/// `min(remaining, requested + stipend)`, stipend only on value transfers.
fn rsk_callee_gas<WIRE, H>(
    context: &mut InstructionContext<'_, H, WIRE>,
    requested: u64,
    has_transfer: bool,
) -> Option<u64>
where
    WIRE: InterpreterTypes,
    H: Host + ?Sized,
{
    let stipend = if has_transfer {
        context.host.gas_params().call_stipend()
    } else {
        0
    };
    let remaining = context.interpreter.gas.remaining();
    // rskj notEnoughSpendingGas: the caller must at least cover the stipend.
    if remaining < stipend {
        context.interpreter.halt_oog();
        return None;
    }
    let callee_gas = core::cmp::min(remaining, requested.saturating_add(stipend));
    if !context.interpreter.gas.record_cost(callee_gas) {
        context.interpreter.halt_oog();
        return None;
    }
    Some(callee_gas)
}

/// Pops the value, charges VT_CALL, loads the callee (charging new-account
/// for op CALL) and computes the callee gas. Returns
/// `(gas_limit, bytecode, code_hash)`.
fn rsk_call_gas_common<WIRE, H>(
    context: &mut InstructionContext<'_, H, WIRE>,
    to: Address,
    requested: u64,
    value: U256,
    charge_new_account: bool,
) -> Option<(u64, revm::state::Bytecode, B256)>
where
    WIRE: InterpreterTypes,
    H: Host + ?Sized,
{
    let has_transfer = !value.is_zero();

    // rskj computeCallGas: VT_CALL when transferring value.
    if has_transfer {
        let vt = context.host.gas_params().transfer_value_cost();
        if !context.interpreter.gas.record_cost(vt) {
            context.interpreter.halt_oog();
            return None;
        }
    }

    // rskj charges NEW_ACCT_CALL for op CALL whenever the callee does not
    // exist, regardless of value: passing transfers_value=true makes revm's
    // new_account_cost unconditional on emptiness.
    // (Approximation: revm reports EIP-161 emptiness, rskj checks trie
    // existence; they differ only for existing-but-empty accounts.)
    let (cost, bytecode, code_hash) =
        load_account_delegated_handle_error(context, to, true, charge_new_account)?;
    if !context.interpreter.gas.record_cost(cost) {
        context.interpreter.halt_oog();
        return None;
    }

    let gas_limit = rsk_callee_gas(context, requested, has_transfer)?;
    Some((gas_limit, bytecode, code_hash))
}

/// CALL with rskj gas semantics.
pub fn rsk_call<WIRE: InterpreterTypes, H: Host + ?Sized>(
    mut context: InstructionContext<'_, H, WIRE>,
) {
    let Some([local_gas_limit, to, value]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let to = Address::from_word(B256::from(to));
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);
    let has_transfer = !value.is_zero();

    if context.interpreter.runtime_flag.is_static() && has_transfer {
        context
            .interpreter
            .halt(InstructionResult::CallNotAllowedInsideStatic);
        return;
    }

    let Some((input, return_memory_offset)) =
        rsk_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
    else {
        return;
    };

    let Some((gas_limit, bytecode, bytecode_hash)) =
        rsk_call_gas_common(&mut context, to, local_gas_limit, value, true)
    else {
        return;
    };

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address: to,
                caller: context.interpreter.input.target_address(),
                bytecode_address: to,
                known_bytecode: Some((bytecode_hash, bytecode)),
                value: CallValue::Transfer(value),
                scheme: CallScheme::Call,
                is_static: context.interpreter.runtime_flag.is_static(),
                return_memory_offset,
            },
        ))));
}

/// SELFDESTRUCT with rskj gas semantics.
///
/// rskj `VM.doSUICIDE` adds `NEW_ACCT_SUICIDE` (25,000) whenever the
/// beneficiary does not exist (`!track.isExist`), with NO condition on the
/// suiciding contract's balance. revm's stock `selfdestruct` instead gates the
/// top-up on `had_value && !target_exists` once Spurious Dragon is active
/// (EIP-161), which is always the case for RSK eras (spec >= Byzantium) — so a
/// zero-balance contract self-destructing to an absent beneficiary would skip
/// the 25,000 charge and diverge. This override drops the value condition,
/// matching rskj frontier-style suicide gas. Everything else (base 5,000 via
/// static gas, cold cost, refund) mirrors revm's instruction.
pub fn rsk_selfdestruct<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if context.interpreter.runtime_flag.is_static() {
        context
            .interpreter
            .halt(InstructionResult::StateChangeDuringStaticCall);
        return;
    }
    let Some([target]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let target = Address::from_word(B256::from(target));

    let cold_load_gas = context.host.gas_params().selfdestruct_cold_cost();
    let skip_cold_load = context.interpreter.gas.remaining() < cold_load_gas;
    let res = match context.host.selfdestruct(
        context.interpreter.input.target_address(),
        target,
        skip_cold_load,
    ) {
        Ok(res) => res,
        Err(LoadError::ColdLoadSkipped) => return context.interpreter.halt_oog(),
        Err(LoadError::DBError) => return context.interpreter.halt_fatal(),
    };

    // rskj charges NEW_ACCT_SUICIDE on beneficiary non-existence regardless of
    // value (no `had_value &&` gate, unlike revm's EIP-161 path).
    let should_charge_topup = !res.target_exists;

    let cost = context
        .host
        .gas_params()
        .selfdestruct_cost(should_charge_topup, res.is_cold);
    if !context.interpreter.gas.record_cost(cost) {
        context.interpreter.halt_oog();
        return;
    }

    if !res.previously_destroyed {
        context
            .interpreter
            .gas
            .record_refund(context.host.gas_params().selfdestruct_refund());
    }

    context.interpreter.halt(InstructionResult::SelfDestruct);
}

/// SSTORE with rskj's fork-independent Petersburg metering (`VM.doSSTORE`).
///
/// RSK never adopted EIP-2200: there is no `gasleft <= stipend` reentrancy
/// sentry, and the dynamic cost/refund use the pre-Istanbul rules — present-zero
/// → non-zero charges SET, every other write charges RESET, and clearing a
/// non-zero slot to zero refunds CLEAR. The required gas_params are pinned to
/// rskj's `GasCost` values (SET=20000 split as static 5000 + 15000, RESET=5000
/// + 0, REFUND=15000) in `make_cfg_env`. This mirrors revm's `host::sstore`
/// with the ISTANBUL branches forced off. (Mainnet #6,223,700, arrowhead600.)
fn rsk_sstore<WIRE: InterpreterTypes, H: Host + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if context.interpreter.runtime_flag.is_static() {
        context
            .interpreter
            .halt(InstructionResult::StateChangeDuringStaticCall);
        return;
    }
    let Some([index, value]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };

    // Static SSTORE cost (rskj `GasCost.RESET_SSTORE`/`CLEAR_SSTORE` = 5000),
    // charged before the store, matching revm's `host::sstore` ordering.
    let static_gas = context.host.gas_params().sstore_static_gas();
    if !context.interpreter.gas.record_cost(static_gas) {
        context.interpreter.halt_oog();
        return;
    }

    let target = context.interpreter.input.target_address();
    let Some(state_load) = context.host.sstore(target, index, value) else {
        context.interpreter.halt_fatal();
        return;
    };

    // Pre-Istanbul (Petersburg) dynamic cost: `is_istanbul = false`.
    let dynamic = context
        .host
        .gas_params()
        .sstore_dynamic_gas(false, &state_load.data, state_load.is_cold);
    if !context.interpreter.gas.record_cost(dynamic) {
        context.interpreter.halt_oog();
        return;
    }

    context
        .interpreter
        .gas
        .record_refund(context.host.gas_params().sstore_refund(false, &state_load.data));
}

/// CALLCODE with rskj gas semantics (no new-account charge).
pub fn rsk_call_code<WIRE: InterpreterTypes, H: Host + ?Sized>(
    mut context: InstructionContext<'_, H, WIRE>,
) {
    let Some([local_gas_limit, to, value]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let to = Address::from_word(B256::from(to));
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);

    let Some((input, return_memory_offset)) =
        rsk_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
    else {
        return;
    };

    let Some((gas_limit, bytecode, bytecode_hash)) =
        rsk_call_gas_common(&mut context, to, local_gas_limit, value, false)
    else {
        return;
    };

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address: context.interpreter.input.target_address(),
                caller: context.interpreter.input.target_address(),
                bytecode_address: to,
                known_bytecode: Some((bytecode_hash, bytecode)),
                value: CallValue::Transfer(value),
                scheme: CallScheme::CallCode,
                is_static: context.interpreter.runtime_flag.is_static(),
                return_memory_offset,
            },
        ))));
}

/// DELEGATECALL with rskj gas semantics (zero value: no stipend, no VT).
pub fn rsk_delegate_call<WIRE: InterpreterTypes, H: Host + ?Sized>(
    mut context: InstructionContext<'_, H, WIRE>,
) {
    let Some([local_gas_limit, to]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let to = Address::from_word(B256::from(to));
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);

    let Some((input, return_memory_offset)) =
        rsk_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
    else {
        return;
    };

    let Some((gas_limit, bytecode, bytecode_hash)) =
        rsk_call_gas_common(&mut context, to, local_gas_limit, U256::ZERO, false)
    else {
        return;
    };

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address: context.interpreter.input.target_address(),
                caller: context.interpreter.input.caller_address(),
                bytecode_address: to,
                known_bytecode: Some((bytecode_hash, bytecode)),
                value: CallValue::Apparent(context.interpreter.input.call_value()),
                scheme: CallScheme::DelegateCall,
                is_static: context.interpreter.runtime_flag.is_static(),
                return_memory_offset,
            },
        ))));
}

/// STATICCALL with rskj gas semantics (zero value: no stipend, no VT).
pub fn rsk_static_call<WIRE: InterpreterTypes, H: Host + ?Sized>(
    mut context: InstructionContext<'_, H, WIRE>,
) {
    let Some([local_gas_limit, to]) = context.interpreter.stack.popn() else {
        context.interpreter.halt_underflow();
        return;
    };
    let to = Address::from_word(B256::from(to));
    let local_gas_limit = u64::try_from(local_gas_limit).unwrap_or(u64::MAX);

    let Some((input, return_memory_offset)) =
        rsk_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
    else {
        return;
    };

    if std::env::var_os("RUSTOCK_TRACE_OPS").is_some() {
        let bytes = context.interpreter.memory.slice(input.clone());
        tracing::debug!("STATICCALL to={to} input=0x{}", alloy_primitives::hex::encode(&*bytes));
    }

    let Some((gas_limit, bytecode, bytecode_hash)) =
        rsk_call_gas_common(&mut context, to, local_gas_limit, U256::ZERO, false)
    else {
        return;
    };

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Call(Box::new(
            CallInputs {
                input: CallInput::SharedBuffer(input),
                gas_limit,
                target_address: to,
                caller: context.interpreter.input.target_address(),
                bytecode_address: to,
                known_bytecode: Some((bytecode_hash, bytecode)),
                value: CallValue::Transfer(U256::ZERO),
                scheme: CallScheme::StaticCall,
                is_static: true,
                return_memory_offset,
            },
        ))));
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::context_interface::cfg::GasParams;
    use revm::interpreter::interpreter::EthInterpreter;
    use revm::interpreter::Interpreter;

    /// Pre-RSKIP150 the handler writes a precompile's full output at the
    /// CALL's real outOffs even when outSize == 0, so the range must keep
    /// the true offset (revm substitutes usize::MAX for zero-size regions).
    #[test]
    fn zero_size_call_range_keeps_real_offset() {
        let mut interp = Interpreter::<EthInterpreter>::default();
        let params = GasParams::default();

        let r = rsk_call_memory_range(&mut interp, &params, U256::from(0x80), U256::ZERO)
            .expect("range");
        assert_eq!(r, 0x80..0x80);

        // Offsets that don't fit usize fall back to revm's sentinel.
        let r = rsk_call_memory_range(&mut interp, &params, U256::MAX, U256::ZERO)
            .expect("range");
        assert_eq!(r.start, usize::MAX);
        assert!(r.is_empty());
    }
}
