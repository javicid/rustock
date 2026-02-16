use rustock_core::validation::HeaderVerifier;
use rustock_core::types::header::Header;
use rustock_storage::BlockStore;
use rustock_networking::protocol::{
    BlockHeadersQuery, BlockHeadersRequest, P2pMessage, RskMessage, RskSubMessage,
};
use alloy_primitives::B256;
use anyhow::Result;
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
    /// We reverse them and store sequentially.
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

        let mut stored = 0u64;
        let mut skipped = 0u64;

        for header in &headers {
            let hash = header.hash();

            // Skip if we already have it
            if self.store.get_header(hash)?.is_some() {
                continue;
            }

            // During initial sync we may receive headers whose parents we haven't
            // downloaded yet (e.g. the lowest block in a backward batch).  Store
            // them tentatively so we can link them later.  Only the very first
            // header in each ascending batch should hit this path.
            let parent = self.store.get_header(header.parent_hash)?;

            // When we have the parent, run full verification and reject on failure.
            if let Some(ref p) = parent {
                if let Err(e) = self.verifier.verify(header, Some(p)) {
                    debug!(
                        target: "rustock::sync",
                        "Header #{} ({:?}) failed verification, skipping: {:?}",
                        header.number,
                        hash,
                        e
                    );
                    skipped += 1;
                    continue;
                }
            }

            // Compute total difficulty.
            // For the parent TD lookup, use the hash that was used to find the parent
            // in the store (header.parent_hash), NOT parent.hash() — they may differ
            // for the genesis block whose canonical hash comes from Java's non-standard
            // RLP encoding.
            let parent_td = match &parent {
                Some(_) => self
                    .store
                    .get_total_difficulty(header.parent_hash)?
                    .unwrap_or_default(),
                None => alloy_primitives::U256::ZERO,
            };
            let new_td = parent_td + header.difficulty;

            // Store header and update head if this is the highest-TD block
            let current_head_hash = self.store.get_head()?;
            let current_td = match current_head_hash {
                Some(h) => self
                    .store
                    .get_total_difficulty(h)?
                    .unwrap_or_default(),
                None => alloy_primitives::U256::ZERO,
            };

            if new_td > current_td {
                self.store.update_head(header, new_td)?;
            } else {
                self.store.put_header(header)?;
                self.store.put_total_difficulty(hash, new_td)?;
            }
            stored += 1;
        }

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
