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
use revm::interpreter::instructions::contract::{
    get_memory_input_and_out_ranges, load_account_delegated_handle_error,
};
use revm::interpreter::interpreter_types::{InputsTr, InterpreterTypes, LoopControl, MemoryTr, RuntimeFlag, StackTr};
use revm::interpreter::{
    CallInput, CallInputs, CallScheme, CallValue, FrameInput, Host, Instruction,
    InstructionContext, InstructionResult, InterpreterAction,
};
use revm::primitives::{Address, B256, U256};

/// rskj `GasCost.CALL`: static cost of every CALL-family opcode.
const CALL_STATIC_GAS: u64 = 700;

/// rskj `GasCost.EXT_CODE_SIZE` (== revm's pre-Berlin EXTCODESIZE), EIP-150.
const EXT_CODE_SIZE_GAS: u64 = 700;

thread_local! {
    /// Addresses for which EXTCODESIZE must report `2^256-1` (rskj RSKIP90:
    /// `VM.doCODESIZE` returns `DataWord.MAX_VALUE` for any active precompile).
    /// Set by `install` for the block being executed (single-threaded).
    static EXTCODESIZE_MAX_PRECOMPILES: core::cell::RefCell<Vec<Address>> =
        const { core::cell::RefCell::new(Vec::new()) };
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
    extcodesize_max_precompiles: &[Address],
) where
    WIRE: InterpreterTypes,
    HOST: Host,
{
    if !extcodehash_enabled {
        instructions.insert_instruction(
            opcode::EXTCODEHASH,
            Instruction::new(invalid_opcode::<WIRE, HOST>, 0),
        );
    }
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

traced_op!(traced_keccak, "KECCAK256", 2, revm::interpreter::instructions::system::keccak256);
traced_op!(traced_codecopy, "CODECOPY", 3, revm::interpreter::instructions::system::codecopy);
traced_op!(traced_return, "RETURN", 2, revm::interpreter::instructions::control::ret);
traced_op!(traced_exp, "EXP", 2, revm::interpreter::instructions::arithmetic::exp);

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
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
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
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
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
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
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
        get_memory_input_and_out_ranges(context.interpreter, context.host.gas_params())
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
