mod events;
mod handler;
mod manager;
mod service;
mod state;

// Re-exports for external consumers
pub use events::SyncEvent;
pub use handler::SyncHandler;
pub use manager::SyncManager;
pub use service::SyncService;
pub use state::SyncState;
pub use state::PeerChunkTracker;

// Re-exports for tests (use super::*)
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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256, Bytes, B512};
    use tempfile::tempdir;

    fn dummy_header(number: u64, parent: B256, difficulty: U256) -> Header {
        Header {
            number,
            parent_hash: parent,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty,
            gas_limit: U256::from(8_000_000),
            gas_used: 0,
            timestamp: number * 15,
            extra_data: Bytes::default(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
        }
    }

    // -- SyncManager tests (validation logic) --------------------------------

    #[tokio::test]
    async fn test_sync_manager_processing() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new()
            .with_parent_rule(rustock_core::validation::BlockNumberRule)
            .with_parent_rule(rustock_core::validation::ParentHashRule));
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = SyncManager::new(store.clone(), verifier, peer_store);

        // 1. Valid sequential block
        let b1 = dummy_header(1, genesis_hash, U256::from(10));
        manager.handle_headers_response(vec![b1.clone()]).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(b1.hash()));
        assert_eq!(store.get_total_difficulty(b1.hash()).unwrap(), Some(U256::from(11)));

        // 2. Duplicate block (should be ignored)
        manager.handle_headers_response(vec![b1.clone()]).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(b1.hash()));

        // 3. Extension block
        let b2 = dummy_header(2, b1.hash(), U256::from(5));
        manager.handle_headers_response(vec![b2.clone()]).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(b2.hash()));

        // 4. Gap block (parent unknown) — stored with TD = difficulty only
        let b4 = dummy_header(4, B256::repeat_byte(0xee), U256::from(1));
        let b4_hash = b4.hash();
        manager.handle_headers_response(vec![b4]).unwrap();
        assert_eq!(store.get_head().unwrap(), Some(b2.hash()), "Head should not change");
        assert!(store.get_header(b4_hash).unwrap().is_some(), "Gap block should be stored");
        assert_eq!(store.get_total_difficulty(b4_hash).unwrap(), Some(U256::from(1)));
    }

    #[tokio::test]
    async fn test_invalid_header_rejected_when_parent_known() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new()
            .with_parent_rule(rustock_core::validation::BlockNumberRule)
            .with_parent_rule(rustock_core::validation::ParentHashRule));
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = SyncManager::new(store.clone(), verifier, peer_store);

        // Header claims parent is genesis but has wrong block number
        let bad = dummy_header(5, genesis_hash, U256::from(50));
        let bad_hash = bad.hash();
        manager.handle_headers_response(vec![bad]).unwrap();

        assert!(store.get_header(bad_hash).unwrap().is_none(), "Invalid header should be rejected");
        assert_eq!(store.get_head().unwrap(), Some(genesis_hash));
    }

    // -- SyncHandler tests (event forwarding) --------------------------------

    #[tokio::test]
    async fn test_sync_handler_forwards_headers() {
        use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
        use rustock_networking::protocol::P2pHandler;

        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handler = SyncHandler::new(manager, event_tx);

        let h0 = dummy_header(0, B256::ZERO, U256::from(10));
        let resp = rustock_networking::protocol::rsk::BlockHeadersResponse {
            id: 1,
            headers: vec![h0.clone()],
        };
        let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersResponse(resp)));

        let handler_resp = handler.handle_message(B512::ZERO, msg);
        assert!(handler_resp.is_none());

        // Event should be forwarded to the channel
        let event = event_rx.try_recv().unwrap();
        match event {
            SyncEvent::HeadersResponse { headers, .. } => {
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].number, 0);
            }
            _ => panic!("Expected HeadersResponse event"),
        }
    }

    #[tokio::test]
    async fn test_sync_handler_forwards_block_hash() {
        use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
        use rustock_networking::protocol::P2pHandler;
        use rustock_networking::protocol::rsk::BlockHashResponse;

        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handler = SyncHandler::new(manager, event_tx);

        let resp = BlockHashResponse { id: 5, hash: B256::repeat_byte(0xab) };
        let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashResponse(resp)));

        handler.handle_message(B512::ZERO, msg);

        match event_rx.try_recv().unwrap() {
            SyncEvent::BlockHashResponse { hash, .. } => {
                assert_eq!(hash, B256::repeat_byte(0xab));
            }
            _ => panic!("Expected BlockHashResponse event"),
        }
    }

    #[tokio::test]
    async fn test_sync_handler_forwards_skeleton() {
        use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
        use rustock_networking::protocol::P2pHandler;
        use rustock_networking::protocol::rsk::SkeletonResponse;

        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handler = SyncHandler::new(manager, event_tx);

        let resp = SkeletonResponse {
            id: 1,
            block_identifiers: vec![
                BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
                BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
            ],
        };
        let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonResponse(resp)));

        handler.handle_message(B512::ZERO, msg);

        match event_rx.try_recv().unwrap() {
            SyncEvent::SkeletonResponse { identifiers, .. } => {
                assert_eq!(identifiers.len(), 2);
                assert_eq!(identifiers[1].number, 192);
            }
            _ => panic!("Expected SkeletonResponse event"),
        }
    }

    // -- State machine tests -------------------------------------------------

    #[tokio::test]
    async fn test_connection_point_binary_search() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        // Store genesis only
        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        // Simulate: peer is at block 1000, we only have genesis
        let peer = B512::repeat_byte(0x01);
        service.state = SyncState::FindingConnectionPoint {
            peer,
            peer_best: 1000,
            start: 0,
            end: 1000,
        };

        // Probe at midpoint 500: we don't have this block hash
        service.on_block_hash_response(B256::repeat_byte(0xff)).await;
        // Range should narrow: start=0, end=500
        if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
            assert_eq!(*start, 0);
            assert_eq!(*end, 500);
        } else {
            panic!("Expected FindingConnectionPoint, got {:?}", service.state);
        }

        // Probe at 250: don't have it
        service.on_block_hash_response(B256::repeat_byte(0xfe)).await;
        if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
            assert_eq!(*start, 0);
            assert_eq!(*end, 250);
        } else {
            panic!("Expected FindingConnectionPoint");
        }

        // Probe at 125: don't have it
        service.on_block_hash_response(B256::repeat_byte(0xfd)).await;
        if let SyncState::FindingConnectionPoint { start, end, .. } = &service.state {
            assert_eq!(*start, 0);
            assert_eq!(*end, 125);
        } else {
            panic!("Expected FindingConnectionPoint");
        }

        // Continue narrowing... eventually probe at 1
        // Simulate finding genesis hash — we DO have block 0
        let genesis_hash = dummy_header(0, B256::ZERO, U256::from(1)).hash();

        // Set state to final narrowing: range [0, 1]
        service.state = SyncState::FindingConnectionPoint {
            peer,
            peer_best: 1000,
            start: 0,
            end: 1,
        };
        // Probe at 0: we have genesis
        service.on_block_hash_response(genesis_hash).await;
        // Connection point = 0, should transition to DownloadingSkeleton
        match &service.state {
            SyncState::DownloadingSkeleton { connection_point, .. } => {
                assert_eq!(*connection_point, 0);
            }
            _ => panic!("Expected DownloadingSkeleton, got {:?}", service.state),
        }

        drop(event_tx); // cleanup
    }

    #[tokio::test]
    async fn test_skeleton_to_headers_transition() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        let peer = B512::repeat_byte(0x01);
        service.state = SyncState::DownloadingSkeleton {
            peer,
            peer_best: 384,
            connection_point: 0,
        };

        // Receive skeleton: [0, 192, 384]
        let skeleton = vec![
            BlockIdentifier { hash: B256::repeat_byte(0x01), number: 0 },
            BlockIdentifier { hash: B256::repeat_byte(0x02), number: 192 },
            BlockIdentifier { hash: B256::repeat_byte(0x03), number: 384 },
        ];
        service.on_skeleton_response(skeleton).await;

        match &service.state {
            SyncState::DownloadingHeaders { tracker, skeleton, .. } => {
                assert_eq!(tracker.next_to_process, 1);
                assert_eq!(skeleton.len(), 3);
            }
            _ => panic!("Expected DownloadingHeaders, got {:?}", service.state),
        }

        drop(event_tx);
    }

    #[tokio::test]
    async fn test_empty_skeleton_returns_to_idle() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        let peer = B512::repeat_byte(0x01);
        service.state = SyncState::DownloadingSkeleton {
            peer,
            peer_best: 100,
            connection_point: 0,
        };

        // Skeleton with only 1 entry → too small → Idle
        service.on_skeleton_response(vec![
            BlockIdentifier { hash: B256::ZERO, number: 0 },
        ]).await;

        assert!(matches!(service.state, SyncState::Idle));

        drop(event_tx);
    }

    #[tokio::test]
    async fn test_headers_response_advances_chunks() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        // Build a small chain: genesis + 4 blocks
        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

        // Build headers
        let b1 = dummy_header(1, genesis_hash, U256::from(1));
        let b2 = dummy_header(2, b1.hash(), U256::from(1));
        let b3 = dummy_header(3, b2.hash(), U256::from(1));
        let b4 = dummy_header(4, b3.hash(), U256::from(1));

        // Skeleton: [0, 2, 4]
        let skeleton = vec![
            BlockIdentifier { hash: genesis_hash, number: 0 },
            BlockIdentifier { hash: b2.hash(), number: 2 },
            BlockIdentifier { hash: b4.hash(), number: 4 },
        ];

        let peer = B512::repeat_byte(0x01);
        // Register the peer so fill_pipeline can find it
        let (tx, _rx) = mpsc::unbounded_channel();
        peer_store.add_peer(peer, tx).await;

        let mut tracker = PeerChunkTracker::new(skeleton.len());
        // Simulate: chunk 1 assigned to peer, chunk 2 assigned to peer
        let c1 = tracker.next_assignment().unwrap();
        tracker.record_sent(peer, c1);
        let c2 = tracker.next_assignment().unwrap();
        tracker.record_sent(peer, c2);

        service.state = SyncState::DownloadingHeaders {
            peer_best: 4,
            skeleton: skeleton.clone(),
            connection_point: 0,
            tracker,
            pending_next_skeleton: None,
        };

        // Chunk 1: headers for blocks 1-2 (descending from b2)
        service.on_headers_response(peer, vec![b2.clone(), b1.clone()]).await;

        // Should still be in DownloadingHeaders (chunk 2 pending)
        match &service.state {
            SyncState::DownloadingHeaders { tracker, .. } => {
                assert_eq!(tracker.next_to_process, 2);
            }
            _ => panic!("Expected DownloadingHeaders with next_to_process=2, got {:?}", service.state),
        }

        // Chunk 2: headers for blocks 3-4 (descending from b4)
        service.on_headers_response(peer, vec![b4.clone(), b3.clone()]).await;

        // All chunks done and we're at peer_best → Idle
        assert!(matches!(service.state, SyncState::Idle),
            "Expected Idle after final chunk, got {:?}", service.state);

        // Verify all headers are stored
        assert!(store.get_header(b1.hash()).unwrap().is_some());
        assert!(store.get_header(b4.hash()).unwrap().is_some());

        drop(event_tx);
    }

    #[tokio::test]
    async fn test_try_start_sync_when_behind_peer() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

        let peer_id = B512::repeat_byte(0x01);
        let (tx, _rx) = mpsc::unbounded_channel();
        peer_store.add_peer(peer_id, tx).await;
        peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
            best_number: 1000,
            total_difficulty: U256::from(1000),
            ..Default::default()
        }).await;

        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        service.try_start_sync().await;

        match &service.state {
            SyncState::FindingConnectionPoint { peer_best, .. } => {
                assert_eq!(*peer_best, 1000);
            }
            _ => panic!("Expected FindingConnectionPoint, got {:?}", service.state),
        }

        drop(event_tx);
    }

    #[tokio::test]
    async fn test_try_start_sync_already_synced() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

        let peer_id = B512::repeat_byte(0x01);
        let (tx, _rx) = mpsc::unbounded_channel();
        peer_store.add_peer(peer_id, tx).await;
        peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
            best_number: 0,
            total_difficulty: U256::from(1),
            ..Default::default()
        }).await;

        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        service.try_start_sync().await;

        assert!(matches!(service.state, SyncState::Idle),
            "Expected Idle when already synced, got {:?}", service.state);

        drop(event_tx);
    }

    #[tokio::test]
    async fn test_timeout_resets_to_idle() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store, event_rx);

        let peer = B512::repeat_byte(0x01);
        service.state = SyncState::FindingConnectionPoint {
            peer,
            peer_best: 1000,
            start: 0,
            end: 1000,
        };
        service.last_progress = Instant::now() - Duration::from_secs(60);

        service.on_tick().await;

        assert!(matches!(service.state, SyncState::Idle),
            "Expected Idle after timeout, got {:?}", service.state);

        drop(event_tx);
    }

    #[tokio::test]
    async fn test_descending_headers_reversed() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = SyncManager::new(store.clone(), verifier, peer_store);

        let b1 = dummy_header(1, genesis_hash, U256::from(1));
        let b2 = dummy_header(2, b1.hash(), U256::from(1));
        let b3 = dummy_header(3, b2.hash(), U256::from(1));

        manager.handle_headers_response(vec![b3.clone(), b2.clone(), b1.clone()]).unwrap();

        assert!(store.get_header(b1.hash()).unwrap().is_some());
        assert!(store.get_header(b2.hash()).unwrap().is_some());
        assert!(store.get_header(b3.hash()).unwrap().is_some());
        assert_eq!(store.get_head().unwrap(), Some(b3.hash()));
    }

    #[tokio::test]
    async fn test_skeleton_round_transitions_to_next_skeleton() {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());

        let genesis = dummy_header(0, B256::ZERO, U256::from(1));
        let genesis_hash = genesis.hash();
        store.update_head(&genesis, U256::from(1)).unwrap();

        let b1 = dummy_header(1, genesis_hash, U256::from(1));
        let b2 = dummy_header(2, b1.hash(), U256::from(1));
        let b3 = dummy_header(3, b2.hash(), U256::from(1));
        let b4 = dummy_header(4, b3.hash(), U256::from(1));

        store.put_header(&b1).unwrap();
        store.put_header(&b2).unwrap();
        store.put_total_difficulty(b1.hash(), U256::from(2)).unwrap();
        store.put_total_difficulty(b2.hash(), U256::from(3)).unwrap();
        store.update_head(&b2, U256::from(3)).unwrap();

        let verifier = Arc::new(HeaderVerifier::new());
        let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
        let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

        let skeleton = vec![
            BlockIdentifier { hash: genesis_hash, number: 0 },
            BlockIdentifier { hash: b2.hash(), number: 2 },
            BlockIdentifier { hash: b4.hash(), number: 4 },
        ];
        let peer = B512::repeat_byte(0x01);
        // Register the peer so the service can find it for the next skeleton
        let (tx, _rx) = mpsc::unbounded_channel();
        peer_store.add_peer(peer, tx).await;
        peer_store.update_metadata(&peer, rustock_networking::peers::PeerMetadata {
            best_number: 10000,
            total_difficulty: U256::from(10000),
            ..Default::default()
        }).await;

        // Set up tracker: chunks 1 already processed, chunk 2 in flight
        let mut tracker = PeerChunkTracker::new(skeleton.len());
        tracker.next_to_assign = 3; // all assigned
        tracker.next_to_process = 2; // chunk 1 already done
        tracker.record_sent(peer, 2); // chunk 2 in flight from peer

        service.state = SyncState::DownloadingHeaders {
            peer_best: 10000,
            skeleton,
            connection_point: 0,
            tracker,
            pending_next_skeleton: None,
        };

        service.on_headers_response(peer, vec![b4.clone(), b3.clone()]).await;

        match &service.state {
            SyncState::DownloadingSkeleton { connection_point, .. } => {
                assert_eq!(*connection_point, 4, "Should request next skeleton from our head");
            }
            _ => panic!("Expected DownloadingSkeleton after completing last chunk, got {:?}", service.state),
        }

        drop(event_tx);
    }
}
