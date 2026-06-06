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
//! `RskHandler` is `MainnetHandler` with two changes:
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

use revm::context::result::HaltReason;
use revm::context_interface::journaled_state::account::JournaledAccountTr;
use revm::context_interface::{ContextTr, JournalTr};
use revm::handler::{
    CreateFrame, EthFrame, EvmTr, EvmTrError, FrameData, FrameResult, Handler, ItemOrResult,
    PrecompileProvider,
};
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::interpreter_action::FrameInit;
use revm::primitives::hardfork::SpecId;
use revm::state::EvmState;

/// `MainnetHandler` with rskj's eternal-frontier account semantics
/// (see module docs).
#[derive(Debug, Clone)]
pub struct RskHandler<CTX, ERROR, FRAME> {
    _phantom: core::marker::PhantomData<(CTX, ERROR, FRAME)>,
}

impl<CTX, ERROR, FRAME> Default for RskHandler<CTX, ERROR, FRAME> {
    fn default() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<EVM, ERROR> Handler for RskHandler<EVM, ERROR, EthFrame<EthInterpreter>>
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
        Precompiles: PrecompileProvider<<EVM as EvmTr>::Context>,
    >,
    ERROR: EvmTrError<EVM>,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = HaltReason;

    fn load_accounts(&self, evm: &mut Self::Evm) -> Result<(), Self::Error> {
        revm::handler::pre_execution::load_accounts::<EVM, ERROR>(evm)?;
        // The default sets the journal spec from CfgEnv; pin it back to
        // rskj's eternal frontier account semantics.
        evm.ctx().journal_mut().set_spec_id(SpecId::HOMESTEAD);
        Ok(())
    }

    /// The mainnet exec loop with one addition: immediately after a CREATE
    /// frame is initialized, reset the created account's nonce to 0 (rskj has
    /// no EIP-161; revm seeds it to 1 from the per-era CfgEnv spec). Must
    /// happen before the constructor runs — addresses the new contract
    /// derives via CREATE depend on its current nonce.
    fn run_exec_loop(
        &mut self,
        evm: &mut Self::Evm,
        first_frame_input: FrameInit,
    ) -> Result<FrameResult, Self::Error> {
        let res = evm.frame_init(first_frame_input)?;
        if let ItemOrResult::Result(frame_result) = res {
            return Ok(frame_result);
        }
        zero_created_contract_nonce(evm);

        loop {
            let call_or_result = evm.frame_run()?;

            let result = match call_or_result {
                ItemOrResult::Item(init) => match evm.frame_init(init)? {
                    ItemOrResult::Item(_) => {
                        zero_created_contract_nonce(evm);
                        continue;
                    }
                    // Do not pop the frame since no new frame was created
                    ItemOrResult::Result(result) => result,
                },
                ItemOrResult::Result(result) => result,
            };

            if let Some(result) = evm.frame_return_result(result)? {
                return Ok(result);
            }
        }
    }
}

/// If the top (just-initialized) frame is a CREATE frame, reset the created
/// account's nonce to 0. On revert the AccountCreated journal entry discards
/// the account wholesale, so no extra journaling is needed.
fn zero_created_contract_nonce<EVM>(evm: &mut EVM)
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
        acc.set_nonce(0);
    }
}
