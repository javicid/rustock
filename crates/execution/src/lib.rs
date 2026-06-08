pub mod bridge;
pub mod database;
pub mod env;
pub mod executor;
pub mod hardfork;
pub mod precompiles;
pub mod processor;
pub mod raw_storage;
pub mod remasc;
pub mod rsk_handler;
pub mod rsk_instructions;
pub mod state;

/// `ContextTr` with the RSK chain extension (raw-bytes storage overlay).
/// Bridge and REMASC code is generic over this instead of plain `ContextTr`.
pub trait RskContextTr:
    revm::context_interface::ContextTr<Chain = raw_storage::RskChainExt>
{
}
impl<T: revm::context_interface::ContextTr<Chain = raw_storage::RskChainExt>> RskContextTr for T {}

pub use database::RskDatabase;
pub use raw_storage::{RawStorage, RskChainExt};
pub use executor::{BlockExecutionResult, ExecutionError, RskExecutor, TxExecutionResult};
pub use hardfork::{RskHardforkConfig, RskNetworkUpgrade, RSK_MAINNET_CHAIN_ID};
pub use precompiles::{
    rsk_precompiles, is_rsk_precompile,
    BRIDGE_ADDR, REMASC_ADDR,
};
pub use processor::{BlockProcessor, ProcessError, ProcessedBlock};
pub use remasc::RemascConfig;
pub use state::apply_state_changes;
