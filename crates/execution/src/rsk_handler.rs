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
//! `RskHandler` is `MainnetHandler` with one change: after the default
//! `load_accounts` synchronizes the journal spec from the config, it pins the
//! JOURNAL spec back to HOMESTEAD. The journal spec only governs account
//! semantics (existence-based emptiness, no state clearing); the interpreter
//! and gas tables keep the per-era spec from `CfgEnv`.

use revm::context::result::HaltReason;
use revm::context_interface::{ContextTr, JournalTr};
use revm::handler::evm::FrameTr;
use revm::handler::{EvmTr, EvmTrError, FrameResult, Handler, PrecompileProvider};
use revm::interpreter::interpreter_action::FrameInit;
use revm::primitives::hardfork::SpecId;
use revm::state::EvmState;

/// `MainnetHandler` with the journal pinned to pre-spurious-dragon account
/// semantics (see module docs).
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

impl<EVM, ERROR, FRAME> Handler for RskHandler<EVM, ERROR, FRAME>
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = FRAME,
        Precompiles: PrecompileProvider<<EVM as EvmTr>::Context>,
    >,
    ERROR: EvmTrError<EVM>,
    FRAME: FrameTr<FrameResult = FrameResult, FrameInit = FrameInit>,
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
}
