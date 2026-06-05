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
use revm::interpreter::interpreter_types::{InputsTr, InterpreterTypes, LoopControl, RuntimeFlag, StackTr};
use revm::interpreter::{
    CallInput, CallInputs, CallScheme, CallValue, FrameInput, Host, Instruction,
    InstructionContext, InstructionResult, InterpreterAction,
};
use revm::primitives::{Address, B256, U256};

/// rskj `GasCost.CALL`: static cost of every CALL-family opcode.
const CALL_STATIC_GAS: u64 = 700;

/// Install the rskj-semantics CALL family into an instruction table.
pub fn install<WIRE, HOST>(instructions: &mut EthInstructions<WIRE, HOST>)
where
    WIRE: InterpreterTypes,
    HOST: Host,
{
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
