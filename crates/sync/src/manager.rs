use rustock_core::validation::HeaderVerifier;
use rustock_core::types::header::Header;
use rustock_storage::BlockStore;
use rustock_networking::protocol::{
    BlockHeadersQuery, BlockHeadersRequest, P2pMessage, RskMessage, RskSubMessage,
};
use alloy_primitives::{B256, U256};
use anyhow::Result;
// HashMap no longer needed — sequential TD propagation replaces hash-based parent lookup
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

        // Track the previous header's TD by position for sequential propagation.
        // Java's RLP encoding may differ from our canonical encoding, so
        // header.hash() can produce a different value than what the next
        // header's parent_hash field contains.  Hash-based parent lookup in
        // `pending` would then fail.  Since headers in a chunk are always in
        // ascending block-number order and form a chain, we propagate TD by
        // position: header[i+1]'s parent TD is header[i]'s TD.
        let mut prev_in_chunk: Option<(&Header, U256)> = None;
        let mut validated: Vec<(&Header, U256)> = Vec::with_capacity(headers.len());
        let mut skipped = 0u64;
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for header in &headers {
            // Skip duplicates within this batch (by block number)
            if !seen.insert(header.number) {
                continue;
            }

            let hash = header.hash();
            let already_stored = self.store.get_header(hash)?.is_some();

            // Determine parent header and TD:
            // 1) Sequential from the previous header in this chunk (most common)
            // 2) Fall back to store lookup by parent_hash (for the first header)
            #[allow(unused_assignments)]
            let mut parent_from_store: Option<Header> = None;
            let parent_ref: Option<&Header>;
            let parent_td: U256;

            if let Some((prev_hdr, prev_td)) = prev_in_chunk {
                if header.number == prev_hdr.number + 1 {
                    parent_ref = Some(prev_hdr);
                    parent_td = prev_td;
                } else {
                    // Non-sequential — fall back to store lookup
                    parent_from_store = self.store.get_header(header.parent_hash)?;
                    if parent_from_store.is_some() {
                        parent_ref = parent_from_store.as_ref();
                        parent_td = self.store
                            .get_total_difficulty(header.parent_hash)?
                            .unwrap_or_default();
                    } else if header.number > 0 {
                        let parent_number = header.number - 1;
                        if let Some(canonical_hash) = self.store.get_canonical_hash(parent_number)? {
                            parent_from_store = self.store.get_header(canonical_hash)?;
                            parent_ref = parent_from_store.as_ref();
                            parent_td = if parent_ref.is_some() {
                                self.store.get_total_difficulty(canonical_hash)?.unwrap_or_default()
                            } else {
                                U256::ZERO
                            };
                        } else {
                            parent_ref = None;
                            parent_td = U256::ZERO;
                        }
                    } else {
                        parent_ref = None;
                        parent_td = U256::ZERO;
                    }
                }
            } else {
                // First header in the chunk — look up parent from store.
                // Try by parent_hash first; if not found (Java non-canonical RLP
                // hash mismatch), fall back to canonical number → hash lookup.
                parent_from_store = self.store.get_header(header.parent_hash)?;
                if parent_from_store.is_some() {
                    parent_ref = parent_from_store.as_ref();
                    parent_td = self.store
                        .get_total_difficulty(header.parent_hash)?
                        .unwrap_or_default();
                } else if header.number > 0 {
                    // Fall back: look up parent by block number
                    let parent_number = header.number - 1;
                    if let Some(canonical_hash) = self.store.get_canonical_hash(parent_number)? {
                        parent_from_store = self.store.get_header(canonical_hash)?;
                        parent_ref = parent_from_store.as_ref();
                        parent_td = if parent_ref.is_some() {
                            self.store.get_total_difficulty(canonical_hash)?.unwrap_or_default()
                        } else {
                            U256::ZERO
                        };
                    } else {
                        parent_ref = None;
                        parent_td = U256::ZERO;
                    }
                } else {
                    parent_ref = None;
                    parent_td = U256::ZERO;
                }
            }

            let new_td = parent_td + header.difficulty;

            // For NEW headers with a known parent, run full verification.
            // Already-stored headers skip verification (they were validated on first store).
            if !already_stored {
                if let Some(p) = parent_ref {
                    if let Err(e) = self.verifier.verify(header, Some(p)) {
                        info!(
                            target: "rustock::sync",
                            "Header #{} ({:?}) failed verification: {:?}",
                            header.number, hash, e
                        );
                        skipped += 1;
                        // Still propagate TD to the next header in the chunk
                        prev_in_chunk = Some((header, new_td));
                        continue;
                    }
                }
            }

            prev_in_chunk = Some((header, new_td));
            validated.push((header, new_td));
        }

        let stored = validated.len() as u64;

        // Commit all validated headers in a single atomic batch
        let _new_head = self.store.store_headers_batch(&validated, current_head_hash, current_td)?;

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
