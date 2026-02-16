use rustock_core::validation::HeaderVerifier;
use rustock_core::types::header::Header;
use rustock_storage::BlockStore;
use rustock_networking::protocol::{
    BlockHeadersQuery, BlockHeadersRequest, P2pMessage, RskMessage, RskSubMessage,
};
use alloy_primitives::{B256, U256};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, debug};

/// Maximum skeleton chunks to process per round (rskj default: 20).
pub(crate) const MAX_SKELETON_CHUNKS: usize = 20;

/// Validates and stores headers.
pub struct SyncManager {
    pub store: Arc<BlockStore>,
    verifier: Arc<HeaderVerifier>,
    pub peer_store: Arc<rustock_networking::peers::PeerStore>,
}

impl SyncManager {
    pub fn new(
        store: Arc<BlockStore>,
        verifier: Arc<HeaderVerifier>,
        peer_store: Arc<rustock_networking::peers::PeerStore>,
    ) -> Self {
        Self {
            store,
            verifier,
            peer_store,
        }
    }

    /// Handles a batch of headers received from a peer.
    /// RSK peers return headers in descending order (from requested hash toward genesis).
    /// We reverse them, validate, and store in a single atomic RocksDB WriteBatch.
    pub fn handle_headers_response(&self, mut headers: Vec<Header>) -> Result<()> {
        if headers.is_empty() {
            debug!(target: "rustock::sync", "Received empty headers response");
            return Ok(());
        }

        // RSK returns headers in descending order; reverse for ascending processing
        if headers.len() > 1 && headers[0].number > headers[headers.len() - 1].number {
            headers.reverse();
        }

        let first_num = headers.first().map(|h| h.number).unwrap_or(0);
        let last_num = headers.last().map(|h| h.number).unwrap_or(0);
        info!(
            target: "rustock::sync",
            "Processing {} headers (#{} -> #{})",
            headers.len(),
            first_num,
            last_num
        );

        // Read current head TD once (instead of per-header)
        let current_head_hash = self.store.get_head()?;
        let current_td = match current_head_hash {
            Some(h) => self.store.get_total_difficulty(h)?.unwrap_or_default(),
            None => U256::ZERO,
        };

        // Local cache for headers validated in this batch but not yet committed.
        // Needed so that header N+1 can find header N as its parent.
        let mut pending: HashMap<B256, (&Header, U256)> = HashMap::new();
        let mut validated: Vec<(&Header, U256)> = Vec::with_capacity(headers.len());
        let mut skipped = 0u64;

        for header in &headers {
            let hash = header.hash();

            // Skip if we already have it (in store or pending batch)
            if pending.contains_key(&hash) || self.store.get_header(hash)?.is_some() {
                continue;
            }

            // Look up parent: first in pending batch, then in store
            let parent_from_pending = pending.get(&header.parent_hash).map(|(h, _)| *h);
            let parent_from_store;
            let parent: Option<&Header> = if let Some(p) = parent_from_pending {
                Some(p)
            } else {
                parent_from_store = self.store.get_header(header.parent_hash)?;
                parent_from_store.as_ref()
            };

            // When we have the parent, run full verification and reject on failure.
            if let Some(p) = parent {
                if let Err(e) = self.verifier.verify(header, Some(p)) {
                    debug!(
                        target: "rustock::sync",
                        "Header #{} ({:?}) failed verification, skipping: {:?}",
                        header.number, hash, e
                    );
                    skipped += 1;
                    continue;
                }
            }

            // Compute total difficulty: check pending batch first, then store
            let parent_td = if parent.is_some() {
                if let Some((_, td)) = pending.get(&header.parent_hash) {
                    *td
                } else {
                    self.store
                        .get_total_difficulty(header.parent_hash)?
                        .unwrap_or_default()
                }
            } else {
                U256::ZERO
            };
            let new_td = parent_td + header.difficulty;

            pending.insert(hash, (header, new_td));
            validated.push((header, new_td));
        }

        let stored = validated.len() as u64;

        // Commit all validated headers in a single atomic batch
        self.store.store_headers_batch(&validated, current_head_hash, current_td)?;

        if skipped > 0 {
            info!(
                target: "rustock::sync",
                "Stored {} headers (#{} -> #{}), rejected {} invalid",
                stored, first_num, last_num, skipped
            );
        } else {
            info!(
                target: "rustock::sync",
                "Stored {} headers (#{} -> #{})",
                stored, first_num, last_num
            );
        }
        Ok(())
    }

    /// Helper to create a headers request message.
    pub fn create_headers_request(&self, start_hash: B256, count: u32) -> P2pMessage {
        let req = BlockHeadersRequest {
            id: rand::random(),
            query: BlockHeadersQuery {
                hash: start_hash,
                count,
            },
        };
        P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)))
    }
}
