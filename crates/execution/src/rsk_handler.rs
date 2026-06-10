//! rskj-compatible transaction handler.
//!
//! rskj never adopted EIP-158/EIP-161 account semantics: accounts are never
//! state-cleared, `addBalance(0)` CREATES trie nodes (even for zero-value
//! internal calls), and "account exists" means "present in the trie"
//! regardless of its values. revm couples those semantics to the same SpecId
//! that selects opcodes and gas tables, so running BYZANTIUM+ for the
//! instruction set silently brings spurious-dragon account rules with it —
//! mainnet #466,503 OOG'd in rustock because every internal ecrecover call
//! was charged the 25,000 new-account cost, while rskj charges it only until
//! the first call creates the 0x…01 account node.
//!
//! `RskHandler` is `MainnetHandler` with three changes:
//! - after the default `load_accounts` synchronizes the journal spec from the
//!   config, it pins the JOURNAL spec back to HOMESTEAD. The journal spec only
//!   governs account semantics (existence-based emptiness, no state clearing);
//!   the interpreter and gas tables keep the per-era spec from `CfgEnv`.
//! - created contracts keep nonce 0 (no EIP-161). revm seeds them with
//!   nonce 1 from SPURIOUS_DRAGON using the per-era `CfgEnv` spec, which
//!   shifts every address such a contract later derives via CREATE —
//!   mainnet #892,228 paid dividends to wallets created at
//!   keccak(rlp([contract, nonce])) and every recipient came out one nonce
//!   ahead of rskj's.
//! - before RSKIP453 (lovell700), an INTERNAL create whose constructor ran
//!   successfully always succeeds (rskj Program.finalizeContractCreation):
//!   if the code deposit is unpayable or the code exceeds the 0x6000 max
//!   size, the contract is left with EMPTY code, the constructor's state
//!   stays committed and the address is pushed — instead of EIP-2's
//!   out-of-gas. Mainnet #1,071,481 deploys an RNS Deed whose 944,800 gas
//!   deposit can't fit in the 600,000 tx limit; rskj deploys it codeless
//!   and the auction proceeds. Top-level deploy transactions are NOT
//!   affected (rskj TransactionExecutor.createContract throws, like EIP-2).

use revm::context::result::HaltReason;
use revm::context_interface::journaled_state::account::JournaledAccountTr;
use revm::context_interface::{Cfg, ContextTr, JournalTr};
use revm::handler::instructions::InstructionProvider;
use revm::handler::{
    ContextTrDbError, CreateFrame, EthFrame, EvmTr, EvmTrError, FrameData, FrameInitOrResult,
    FrameResult, Handler, ItemOrResult, PrecompileProvider,
};
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::interpreter_action::FrameInit;
use revm::interpreter::{CallOutcome, CreateOutcome, InstructionResult, InterpreterAction};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address, Bytes, U256};
use revm::state::EvmState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// `MainnetHandler` with rskj's eternal-frontier account semantics
/// (see module docs).
#[derive(Debug, Clone)]
pub struct RskHandler<CTX, ERROR, FRAME> {
    /// Pre-RSKIP453 (lovell700): internal creates with an unpayable code
    /// deposit deploy with empty code instead of failing.
    empty_create_on_unpayable_deposit: bool,
    /// Post-RSKIP125 (wasabi): a contract created by the CREATE/CREATE2
    /// *opcode* has its nonce bumped to 1 (`Program.createContract`). A
    /// top-level CREATE *transaction* never bumps it (`TransactionExecutor
    /// .create`), so this only applies to internal create frames.
    rskip125_active: bool,
    /// Shared with `RskPrecompileProvider`: set when a direct Bridge call
    /// hits rskj's invisible-exception path (parse failure post-RSKIP88).
    /// rskj marks the execution summary failed, so the sender gets NO
    /// leftover refund and REMASC receives gasLimit * gasPrice — while the
    /// receipt stays SUCCESS with only the spent gas (mainnet #764,123:
    /// receipt 47,408 gas, fee charged for the full 1,000,000 limit).
    invisible_exception: Arc<AtomicBool>,
    /// Pre-RSKIP150 (twoToThree, mainnet 2_018_000): rskj's
    /// `Program.callToPrecompiledAddress` saves a successful precompile's
    /// FULL output to the caller's memory at outOffs (`memorySave`, NOT
    /// limited by the CALL's outSize), silently extending memory without
    /// charging gas — so the caller's later memory expansions are measured
    /// from the extended size (mainnet #1,661,324: a Solidity 0.5 proxy
    /// calls BlockHeaderContract with outSize=0; rskj's RETURNDATACOPY then
    /// pays no expansion). `Some` holds the block's active precompile
    /// addresses; `None` disables the quirk (RSKIP150 active).
    pre_rskip150_precompiles: Option<Vec<Address>>,
    /// Active precompile addresses at this block, used to replicate rskj's
    /// returnDataBuffer semantics: `Program.callToAddress` resets the
    /// caller's buffer only inside `executeCode` (callee HAS code) and
    /// `callToPrecompiledAddress`; a call that executes nothing — empty-code
    /// callee, depth limit, insufficient endowment — leaves the PREVIOUS
    /// call's return data in place, where canonical EVM (EIP-211) clears it.
    active_precompiles: Vec<Address>,
    _phantom: core::marker::PhantomData<(CTX, ERROR, FRAME)>,
}

impl<CTX, ERROR, FRAME> RskHandler<CTX, ERROR, FRAME> {
    pub fn new(
        empty_create_on_unpayable_deposit: bool,
        invisible_exception: Arc<AtomicBool>,
    ) -> Self {
        Self::with_rskip125(
            empty_create_on_unpayable_deposit,
            false,
            invisible_exception,
            None,
            Vec::new(),
        )
    }

    pub fn with_rskip125(
        empty_create_on_unpayable_deposit: bool,
        rskip125_active: bool,
        invisible_exception: Arc<AtomicBool>,
        pre_rskip150_precompiles: Option<Vec<Address>>,
        active_precompiles: Vec<Address>,
    ) -> Self {
        Self {
            empty_create_on_unpayable_deposit,
            rskip125_active,
            invisible_exception,
            pre_rskip150_precompiles,
            active_precompiles,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<CTX, ERROR, FRAME> Default for RskHandler<CTX, ERROR, FRAME> {
    fn default() -> Self {
        Self::new(false, Arc::default())
    }
}

impl<EVM, ERROR> Handler for RskHandler<EVM, ERROR, EthFrame<EthInterpreter>>
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
        Instructions: InstructionProvider<
            Context = <EVM as EvmTr>::Context,
            InterpreterTypes = EthInterpreter,
        >,
        Precompiles: PrecompileProvider<<EVM as EvmTr>::Context>,
    >,
    ERROR: EvmTrError<EVM>,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = HaltReason;

    fn load_accounts(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        // Clear any stale invisible-exception flag from a previous tx.
        self.invisible_exception.store(false, Ordering::Relaxed);
        revm::handler::pre_execution::load_accounts::<EVM, ERROR>(evm)?;
        // The default sets the journal spec from CfgEnv; pin it back to
        // rskj's eternal frontier account semantics.
        evm.ctx().journal_mut().set_spec_id(SpecId::HOMESTEAD);
        Ok(())
    }

    /// rskj invisible exception: the sender gets NO leftover/refund back —
    /// the full upfront gasLimit * gasPrice deduction stands
    /// (TransactionExecutionSummary leftover/refund are zero when failed).
    fn reimburse_caller(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
    ) -> Result<(), Self::Error> {
        if self.invisible_exception.load(Ordering::Relaxed) {
            return Ok(());
        }
        revm::handler::post_execution::reimburse_caller(
            evm.ctx(),
            exec_result.gas(),
            U256::ZERO,
        )
        .map_err(From::from)
    }

    /// rskj invisible exception: REMASC (the block beneficiary) receives
    /// the FULL gasLimit * gasPrice (TransactionExecutionSummary.getFee
    /// returns calcCost(gasLimit) when failed).
    fn reward_beneficiary(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut FrameResult,
    ) -> Result<(), Self::Error> {
        if !self.invisible_exception.load(Ordering::Relaxed) {
            return revm::handler::post_execution::reward_beneficiary(
                evm.ctx(),
                exec_result.gas(),
            )
            .map_err(From::from);
        }
        use revm::context_interface::journaled_state::account::JournaledAccountTr;
        use revm::context_interface::{Block, Transaction};
        let ctx = evm.ctx();
        let basefee = ctx.block().basefee() as u128;
        let gas_limit = ctx.tx().gas_limit();
        let fee = ctx.tx().effective_gas_price(basefee) * gas_limit as u128;
        let beneficiary = ctx.block().beneficiary();
        ctx.journal_mut()
            .load_account_mut(beneficiary)
            .map_err(|e| ERROR::from(e))?
            .incr_balance(U256::from(fee));
        Ok(())
    }

    /// The mainnet exec loop with two additions:
    /// - immediately after a CREATE frame is initialized, reset the created
    ///   account's nonce to 0 (rskj has no EIP-161; revm seeds it to 1 from
    ///   the per-era CfgEnv spec). Must happen before the constructor runs —
    ///   addresses the new contract derives via CREATE depend on its nonce.
    /// - frames run through `rsk_frame_run`, which applies the pre-RSKIP453
    ///   empty-deploy quirk to internal creates.
    fn run_exec_loop(
        &mut self,
        evm: &mut Self::Evm,
        first_frame_input: FrameInit,
    ) -> Result<FrameResult, Self::Error> {
        let res = evm.frame_init(first_frame_input)?;
        if let ItemOrResult::Result(frame_result) = res {
            return Ok(frame_result);
        }
        // Top-level CREATE transaction: rskj's TransactionExecutor.create never
        // bumps the nonce (even post-RSKIP125), so it stays 0.
        set_created_contract_nonce(evm, 0);

        loop {
            let call_or_result = rsk_frame_run(evm, self.empty_create_on_unpayable_deposit)?;

            // Pre-RSKIP150 unbounded precompile output write, applied to the
            // caller after `frame_return_result` (see field docs).
            let mut unbounded_output: Option<(usize, Bytes)> = None;
            // rskj returnDataBuffer preservation: the caller's previous
            // return data, restored after `frame_return_result` when rskj
            // would not have touched the buffer (see field docs).
            let mut preserved_return_buffer: Option<Bytes> = None;

            let result = match call_or_result {
                ItemOrResult::Item(init) => {
                    if *TRACE_FRAMES {
                        trace_frame_init(&init);
                    }
                    let callee = match &init.frame_input {
                        revm::interpreter::interpreter_action::FrameInput::Call(c) => {
                            Some(c.bytecode_address)
                        }
                        _ => None,
                    };
                    match evm.frame_init(init)? {
                        ItemOrResult::Item(_) => {
                            // Internal CREATE/CREATE2 opcode: post-RSKIP125
                            // (wasabi) rskj's Program.createContract bumps the
                            // created contract's nonce to 1; before, it is 0.
                            let nonce = u64::from(self.rskip125_active);
                            set_created_contract_nonce(evm, nonce);
                            continue;
                        }
                        // Do not pop the frame since no new frame was created:
                        // this is how a CALL to a precompile, an empty-code
                        // account, or a failed pre-check (depth/endowment)
                        // resolves.
                        ItemOrResult::Result(result) => {
                            if let (Some(precompiles), Some(callee), FrameResult::Call(outcome)) =
                                (&self.pre_rskip150_precompiles, callee, &result)
                            {
                                if precompiles.contains(&callee)
                                    && outcome.instruction_result().is_ok()
                                    && outcome.result.output.len() > outcome.memory_length()
                                {
                                    unbounded_output = Some((
                                        outcome.memory_start(),
                                        outcome.result.output.clone(),
                                    ));
                                }
                            }
                            // rskj: only executed code and precompile calls
                            // reset the caller's returnDataBuffer; a CALL
                            // resolved without running anything keeps the
                            // previous buffer (mainnet #2,669,886: RETURNDATASIZE
                            // after a value transfer to an empty account still
                            // reports the prior call's 32-byte output).
                            // For CREATE only the pre-checks (depth/endowment)
                            // return before rskj's reset.
                            let rskj_preserves = match &result {
                                FrameResult::Call(_) => callee
                                    .is_some_and(|c| !self.active_precompiles.contains(&c)),
                                FrameResult::Create(outcome) => matches!(
                                    outcome.instruction_result(),
                                    InstructionResult::CallTooDeep
                                        | InstructionResult::OutOfFunds
                                ),
                            };
                            if rskj_preserves {
                                use revm::interpreter::interpreter_types::ReturnData;
                                preserved_return_buffer = Some(
                                    evm.frame_stack()
                                        .get()
                                        .interpreter
                                        .return_data
                                        .buffer()
                                        .clone(),
                                );
                            }
                            result
                        }
                    }
                }
                ItemOrResult::Result(result) => result,
            };
            if *TRACE_FRAMES {
                tracing::debug!(
                    "FRAME RESULT {:?} gas_remaining={} gas_spent={}",
                    result.instruction_result(),
                    result.gas().remaining(),
                    result.gas().spent(),
                );
            }

            if let Some(result) = evm.frame_return_result(result)? {
                return Ok(result);
            }
            if let Some((mem_start, output)) = unbounded_output {
                write_unbounded_precompile_output(evm, mem_start, &output);
            }
            if let Some(buffer) = preserved_return_buffer {
                use revm::interpreter::interpreter_types::ReturnData;
                // Undo revm's insert_call_outcome buffer clear (EIP-211).
                evm.frame_stack().get().interpreter.return_data.set_buffer(buffer);
            }
        }
    }
}

/// `EvmTr::frame_run` with the create-return path replaced by
/// `rsk_return_create` (same shape as revm's default implementation).
fn rsk_frame_run<EVM>(
    evm: &mut EVM,
    empty_create_on_unpayable_deposit: bool,
) -> Result<FrameInitOrResult<EthFrame<EthInterpreter>>, ContextTrDbError<EVM::Context>>
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
        Instructions: InstructionProvider<
            Context = <EVM as EvmTr>::Context,
            InterpreterTypes = EthInterpreter,
        >,
    >,
{
    let (ctx, instructions, _precompiles, frame_stack) = evm.all_mut();
    let frame = frame_stack.get();

    let action = frame
        .interpreter
        .run_plain(instructions.instruction_table(), ctx);

    let mut interpreter_result = match action {
        InterpreterAction::NewFrame(frame_input) => {
            return Ok(ItemOrResult::Item(FrameInit {
                frame_input,
                depth: frame.depth + 1,
                memory: frame.interpreter.memory.new_child_context(),
            }));
        }
        InterpreterAction::Return(result) => result,
    };

    let result = match &frame.data {
        FrameData::Call(call) => {
            if interpreter_result.result.is_ok() {
                ctx.journal_mut().checkpoint_commit();
            } else {
                ctx.journal_mut().checkpoint_revert(frame.checkpoint);
            }
            ItemOrResult::Result(FrameResult::Call(CallOutcome::new(
                interpreter_result,
                call.return_memory_range.clone(),
            )))
        }
        FrameData::Create(create) => {
            // The empty-deploy quirk applies only to INTERNAL creates
            // (depth > 0); top-level deploy transactions fail like EIP-2
            // in rskj too.
            if empty_create_on_unpayable_deposit && frame.depth > 0 {
                rsk_return_create(
                    ctx,
                    frame.checkpoint,
                    &mut interpreter_result,
                    create.created_address,
                );
            } else {
                let (cfg, journal) = ctx.cfg_journal_mut();
                revm::handler::return_create(
                    journal,
                    cfg,
                    frame.checkpoint,
                    &mut interpreter_result,
                    create.created_address,
                );
            }
            ItemOrResult::Result(FrameResult::Create(CreateOutcome::new(
                interpreter_result,
                Some(create.created_address),
            )))
        }
    };
    frame.set_finished(true);
    Ok(result)
}

/// rskj `Program.finalizeContractCreation` before RSKIP453: a constructor
/// that ran successfully always deploys. An unpayable code deposit or
/// over-max-size code (0x6000, rskj Constants.MAX_CONTRACT_SIZE) leaves the
/// contract with EMPTY code — without charging the deposit — while the
/// constructor's state changes stay committed and the address is returned.
fn rsk_return_create<CTX: ContextTr>(
    ctx: &mut CTX,
    checkpoint: revm::context_interface::journaled_state::JournalCheckpoint,
    interpreter_result: &mut revm::interpreter::InterpreterResult,
    address: Address,
) {
    let (cfg, journal) = ctx.cfg_journal_mut();
    if !interpreter_result.result.is_ok() {
        journal.checkpoint_revert(checkpoint);
        return;
    }

    let code_len = interpreter_result.output.len();
    let oversize = code_len > cfg.max_code_size();
    let deposit = cfg.gas_params().code_deposit_cost(code_len);
    // Short-circuit keeps the deposit uncharged in the oversize case, like
    // rskj (the exception set by either check skips spendGas + saveCode).
    if oversize || !interpreter_result.gas.record_cost(deposit) {
        interpreter_result.output = Bytes::new();
    }

    journal.checkpoint_commit();
    journal.set_code(
        address,
        revm::state::Bytecode::new_legacy(interpreter_result.output.clone()),
    );
    interpreter_result.result = InstructionResult::Return;
}

/// Divergence-hunt diagnostic (env-gated): log every sub-frame's input and
/// result during execution.
static TRACE_FRAMES: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var_os("RUSTOCK_TRACE_FRAMES").is_some());

fn trace_frame_init(init: &FrameInit) {
    use revm::interpreter::interpreter_action::FrameInput;
    match &init.frame_input {
        FrameInput::Call(c) => tracing::debug!(
            "FRAME CALL depth={} target={} caller={} scheme={:?} gas_limit={} input_len={}",
            init.depth,
            c.target_address,
            c.caller,
            c.scheme,
            c.gas_limit,
            c.input.len(),
        ),
        FrameInput::Create(c) => tracing::debug!(
            "FRAME CREATE depth={} caller={} scheme={:?} gas_limit={}",
            init.depth,
            c.caller(),
            c.scheme(),
            c.gas_limit(),
        ),
        FrameInput::Empty => {}
    }
}

/// If the top (just-initialized) frame is a CREATE frame, reset the created
/// account's nonce to 0. On revert the AccountCreated journal entry discards
/// the account wholesale, so no extra journaling is needed.
/// Pre-RSKIP150 `Program.memorySave(outOffs, out)`: write a successful
/// precompile's FULL output into the caller's memory, extending it
/// word-aligned WITHOUT charging gas (rskj `Memory.extend` grows the
/// gas-visible softSize for free on this path). The extended size is
/// recorded in the caller's `MemoryGas` so later expansions are priced
/// from it, exactly like rskj's `calcMemGas(oldMemSize, ...)`.
fn write_unbounded_precompile_output<EVM>(evm: &mut EVM, mem_start: usize, output: &[u8])
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
    >,
{
    let gas_params = evm.ctx().cfg().gas_params().clone();
    let frame = evm.frame_stack().get();
    let interpreter = &mut frame.interpreter;
    let Some(end) = mem_start.checked_add(output.len()) else {
        return;
    };
    let new_words = end.div_ceil(32);
    if new_words > interpreter.gas.memory().words_num {
        interpreter.memory.resize(new_words * 32);
        let cost = gas_params.memory_cost(new_words);
        // Record the new size as already paid for; nothing is charged.
        let _ = interpreter.gas.memory_mut().set_words_num(new_words, cost);
    }
    interpreter.memory.set(mem_start, output);
}

fn set_created_contract_nonce<EVM>(evm: &mut EVM, nonce: u64)
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
    >,
{
    let FrameData::Create(CreateFrame { created_address }) = evm.frame_stack().get().data else {
        return;
    };
    if let Ok(mut acc) = evm.ctx().journal_mut().load_account_mut(created_address) {
        acc.set_nonce(nonce);
    }
}
