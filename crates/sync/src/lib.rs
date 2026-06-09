mod events;
mod handler;
mod manager;
mod progress;
mod service;
mod state;
mod tracker;
pub mod tx_relay;
pub mod txpool;

// Re-exports for external consumers
pub use events::SyncEvent;
pub use handler::SyncHandler;
pub use manager::SyncManager;
pub use service::{ExternalBlockSource, SyncService};
pub use state::SyncState;
pub use tracker::PeerChunkTracker;
pub use tx_relay::TxRelay;
pub use txpool::TransactionPool;

#[cfg(test)]
pub use rustock_core::types::header::Header;
#[cfg(test)]
pub use rustock_core::validation::HeaderVerifier;
#[cfg(test)]
pub use rustock_networking::protocol::BlockIdentifier;
#[cfg(test)]
pub use rustock_storage::BlockStore;
#[cfg(test)]
pub use std::sync::Arc;
#[cfg(test)]
pub use std::time::{Duration, Instant};
#[cfg(test)]
pub use tokio::sync::mpsc;

#[cfg(test)]
mod tests;
