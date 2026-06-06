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
        cached_hash_for_merged_mining: None,
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
    assert_eq!(store.head().unwrap(), Some(b1.hash()));
    assert_eq!(store.total_difficulty(b1.hash()).unwrap(), Some(U256::from(11)));

    // 2. Duplicate block (should be ignored)
    manager.handle_headers_response(vec![b1.clone()]).unwrap();
    assert_eq!(store.head().unwrap(), Some(b1.hash()));

    // 3. Extension block
    let b2 = dummy_header(2, b1.hash(), U256::from(5));
    manager.handle_headers_response(vec![b2.clone()]).unwrap();
    assert_eq!(store.head().unwrap(), Some(b2.hash()));

    // 4. Gap block (parent unknown) — stored with TD = difficulty only
    let b4 = dummy_header(4, B256::repeat_byte(0xee), U256::from(1));
    let b4_hash = b4.hash();
    manager.handle_headers_response(vec![b4]).unwrap();
    assert_eq!(store.head().unwrap(), Some(b2.hash()), "Head should not change");
    assert!(store.header(b4_hash).unwrap().is_some(), "Gap block should be stored");
    assert_eq!(store.total_difficulty(b4_hash).unwrap(), Some(U256::from(1)));
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

    assert!(store.header(bad_hash).unwrap().is_none(), "Invalid header should be rejected");
    assert_eq!(store.head().unwrap(), Some(genesis_hash));
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

    let handler_resp = handler.handle_message(B512::ZERO, &msg);
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

    handler.handle_message(B512::ZERO, &msg);

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

    handler.handle_message(B512::ZERO, &msg);

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

    // Skeleton with only 1 entry → too small → Following
    service.on_skeleton_response(vec![
        BlockIdentifier { hash: B256::ZERO, number: 0 },
    ]).await;

    assert!(matches!(service.state, SyncState::Following));

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

    // All chunks done → transitions to DownloadingBodies (bodies not yet stored)
    assert!(matches!(service.state, SyncState::DownloadingBodies { .. }),
        "Expected DownloadingBodies after final chunk, got {:?}", service.state);

    // Verify all headers are stored
    assert!(store.header(b1.hash()).unwrap().is_some());
    assert!(store.header(b4.hash()).unwrap().is_some());

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
        SyncState::DownloadingSkeleton { peer_best, connection_point, .. } => {
            assert_eq!(*peer_best, 1000);
            assert_eq!(*connection_point, 0);
        }
        _ => panic!("Expected DownloadingSkeleton, got {:?}", service.state),
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

    assert!(matches!(service.state, SyncState::Following),
        "Expected Following when already synced, got {:?}", service.state);

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

    assert!(store.header(b1.hash()).unwrap().is_some());
    assert!(store.header(b2.hash()).unwrap().is_some());
    assert!(store.header(b3.hash()).unwrap().is_some());
    assert_eq!(store.head().unwrap(), Some(b3.hash()));
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

    // Headers complete → transitions to DownloadingBodies since bodies are missing
    match &service.state {
        SyncState::DownloadingBodies { peer_best, .. } => {
            assert_eq!(*peer_best, 10000);
        }
        _ => panic!("Expected DownloadingBodies after completing last chunk, got {:?}", service.state),
    }

    // Simulate body responses to complete the phase
    if let SyncState::DownloadingBodies { in_flight, .. } = &service.state {
        let req_ids: Vec<u64> = in_flight.keys().copied().collect();
        for req_id in req_ids {
            service.on_body_response(req_id, vec![], vec![]).await;
        }
    }

    // After all bodies downloaded, should continue to DownloadingSkeleton
    match &service.state {
        SyncState::DownloadingSkeleton { connection_point, .. } => {
            assert_eq!(*connection_point, 4, "Should request next skeleton from our head");
        }
        _ => panic!("Expected DownloadingSkeleton after body download, got {:?}", service.state),
    }

    drop(event_tx);
}

#[tokio::test]
async fn test_failed_body_send_stays_tracked_for_retry() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();
    let b1 = dummy_header(1, genesis.hash(), U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_header(&b2).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);

    // Peer whose session channel is closed: every send to it fails.
    let peer = B512::repeat_byte(0x01);
    let (tx, rx) = mpsc::unbounded_channel();
    peer_store.add_peer(peer, tx).await;
    drop(rx);

    let mut in_flight = std::collections::HashMap::new();
    in_flight.insert(7u64, 0usize); // b1's body request in flight
    service.state = SyncState::DownloadingBodies {
        peer_best: 10,
        pending_headers: vec![(b1.hash(), b1.clone()), (b2.hash(), b2.clone())],
        next_request: 1,
        in_flight,
    };

    // b1's body arrives; the service tops up with a request for b2, whose
    // send fails (dead peer). The request must stay tracked so the stalled
    // retry re-attempts it — dropping it would orphan b2 forever and the
    // batch could never complete.
    service.on_body_response(7, vec![], vec![]).await;

    match &service.state {
        SyncState::DownloadingBodies { in_flight, .. } => {
            assert_eq!(
                in_flight.len(),
                1,
                "request with failed send must remain in flight for retry"
            );
        }
        other => panic!("Expected DownloadingBodies, got {:?}", other),
    }
}

// -- PeerChunkTracker tests -----------------------------------------------

#[test]
fn test_tracker_new_starts_at_chunk_1() {
    let tracker = PeerChunkTracker::new(5);
    assert_eq!(tracker.next_to_assign, 1);
    assert_eq!(tracker.next_to_process, 1);
    assert_eq!(tracker.total_chunks, 5);
    assert!(!tracker.is_complete());
}

#[test]
fn test_tracker_assignment_sequence() {
    let mut tracker = PeerChunkTracker::new(4); // chunks 1, 2, 3

    assert_eq!(tracker.next_assignment(), Some(1));
    assert_eq!(tracker.next_assignment(), Some(2));
    assert_eq!(tracker.next_assignment(), Some(3));
    assert_eq!(tracker.next_assignment(), None); // all assigned
    assert_eq!(tracker.next_assignment(), None); // still None
}

#[test]
fn test_tracker_record_and_identify_response() {
    let mut tracker = PeerChunkTracker::new(5);
    let peer_a = B512::repeat_byte(0x0A);
    let peer_b = B512::repeat_byte(0x0B);

    tracker.record_sent(peer_a, 1);
    tracker.record_sent(peer_a, 2);
    tracker.record_sent(peer_b, 3);

    // Responses come back in FIFO order per peer
    assert_eq!(tracker.identify_response(&peer_a), Some(1));
    assert_eq!(tracker.identify_response(&peer_b), Some(3));
    assert_eq!(tracker.identify_response(&peer_a), Some(2));

    // No more in flight
    assert_eq!(tracker.identify_response(&peer_a), None);
    assert_eq!(tracker.identify_response(&peer_b), None);
}

#[test]
fn test_tracker_identify_unknown_peer() {
    let mut tracker = PeerChunkTracker::new(3);
    let unknown = B512::repeat_byte(0xFF);
    assert_eq!(tracker.identify_response(&unknown), None);
}

#[test]
fn test_tracker_drain_ready_in_order() {
    let mut tracker = PeerChunkTracker::new(5);
    // Simulate: chunks 1, 2, 3, 4 all buffered
    tracker.buffer_response(1, vec![]);
    tracker.buffer_response(2, vec![]);
    tracker.buffer_response(3, vec![]);
    tracker.buffer_response(4, vec![]);

    let ready = tracker.drain_ready();
    assert_eq!(ready.len(), 4);
    assert_eq!(ready[0].0, 1);
    assert_eq!(ready[1].0, 2);
    assert_eq!(ready[2].0, 3);
    assert_eq!(ready[3].0, 4);
    assert!(tracker.is_complete());
}

#[test]
fn test_tracker_drain_ready_out_of_order() {
    let mut tracker = PeerChunkTracker::new(5);

    // Chunk 3 arrives first — can't process yet
    tracker.buffer_response(3, vec![]);
    let ready = tracker.drain_ready();
    assert!(ready.is_empty());
    assert_eq!(tracker.next_to_process, 1);

    // Chunk 2 arrives — still can't process (waiting for 1)
    tracker.buffer_response(2, vec![]);
    let ready = tracker.drain_ready();
    assert!(ready.is_empty());

    // Chunk 1 arrives — now process 1, 2, 3 consecutively
    tracker.buffer_response(1, vec![]);
    let ready = tracker.drain_ready();
    assert_eq!(ready.len(), 3);
    assert_eq!(ready[0].0, 1);
    assert_eq!(ready[1].0, 2);
    assert_eq!(ready[2].0, 3);
    assert_eq!(tracker.next_to_process, 4);

    // Chunk 4 arrives — immediately ready
    tracker.buffer_response(4, vec![]);
    let ready = tracker.drain_ready();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].0, 4);
    assert!(tracker.is_complete());
}

#[test]
fn test_tracker_peer_capacity() {
    let mut tracker = PeerChunkTracker::new(20);
    let peer = B512::repeat_byte(0x01);

    // Fresh peer has full capacity
    assert_eq!(tracker.peer_capacity(&peer), 4); // PIPELINE_DEPTH

    // Fill up the pipeline
    tracker.record_sent(peer, 1);
    assert_eq!(tracker.peer_capacity(&peer), 3);
    tracker.record_sent(peer, 2);
    assert_eq!(tracker.peer_capacity(&peer), 2);
    tracker.record_sent(peer, 3);
    assert_eq!(tracker.peer_capacity(&peer), 1);
    tracker.record_sent(peer, 4);
    assert_eq!(tracker.peer_capacity(&peer), 0);

    // Completing a response frees capacity
    tracker.identify_response(&peer);
    assert_eq!(tracker.peer_capacity(&peer), 1);
}

#[test]
fn test_tracker_handle_peer_disconnect() {
    let mut tracker = PeerChunkTracker::new(10);
    let peer_a = B512::repeat_byte(0x0A);
    let peer_b = B512::repeat_byte(0x0B);

    // Assign chunks: peer_a gets 1,2,3 — peer_b gets 4,5,6
    for i in 1..=3 {
        tracker.record_sent(peer_a, i);
    }
    for i in 4..=6 {
        tracker.record_sent(peer_b, i);
    }
    tracker.next_to_assign = 7;

    // Chunk 1 already processed
    tracker.next_to_process = 2;

    // Peer A disconnects — chunks 2, 3 should be reassigned
    tracker.handle_peer_disconnect(&peer_a);

    // next_to_assign should be reset to min(2, 3) = 2
    assert_eq!(tracker.next_to_assign, 2);

    // peer_a should have no in-flight
    assert!(!tracker.in_flight.contains_key(&peer_a));

    // peer_b should be unaffected
    assert_eq!(tracker.in_flight.get(&peer_b).unwrap().len(), 3);
}

#[test]
fn test_tracker_disconnect_with_buffered_chunk() {
    let mut tracker = PeerChunkTracker::new(6);
    let peer = B512::repeat_byte(0x01);

    tracker.record_sent(peer, 1);
    tracker.record_sent(peer, 2);
    tracker.record_sent(peer, 3);
    tracker.next_to_assign = 4;

    // Chunk 2 already buffered (response received but not processed)
    tracker.buffer_response(2, vec![]);

    // Peer disconnects — only chunks 1 and 3 need reassignment (2 is buffered)
    tracker.handle_peer_disconnect(&peer);

    // next_to_assign should be 1 (the minimum un-buffered, un-processed chunk)
    assert_eq!(tracker.next_to_assign, 1);
}

#[test]
fn test_tracker_is_complete() {
    let mut tracker = PeerChunkTracker::new(3); // chunks 1, 2
    assert!(!tracker.is_complete());

    tracker.next_to_process = 2;
    assert!(!tracker.is_complete());

    tracker.next_to_process = 3;
    assert!(tracker.is_complete());
}

// -- Following mode / NewBlockHashes tests --------------------------------

#[tokio::test]
async fn test_small_gap_enters_following_mode() {
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
        best_number: 10, // only 10 blocks behind (< 24)
        total_difficulty: U256::from(10),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    service.try_start_sync().await;

    assert!(matches!(service.state, SyncState::Following),
        "Expected Following for small gap, got {:?}", service.state);
}

#[tokio::test]
async fn test_large_gap_enters_skeleton_sync() {
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
        best_number: 100, // 100 blocks behind (> 24)
        total_difficulty: U256::from(100),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    service.try_start_sync().await;

    assert!(matches!(service.state, SyncState::DownloadingSkeleton { .. }),
        "Expected DownloadingSkeleton for large gap, got {:?}", service.state);
}

#[tokio::test]
async fn test_new_block_hashes_ignored_during_sync() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    let peer = B512::repeat_byte(0x01);
    service.state = SyncState::DownloadingSkeleton {
        peer,
        peer_best: 1000,
        connection_point: 0,
    };

    // NewBlockHashes should be silently dropped
    service.on_new_block_hashes(peer, vec![
        BlockIdentifier { hash: B256::repeat_byte(0xaa), number: 1001 },
    ]).await;

    // State should be unchanged
    assert!(matches!(service.state, SyncState::DownloadingSkeleton { .. }),
        "State should remain DownloadingSkeleton, got {:?}", service.state);
}

#[tokio::test]
async fn test_new_block_hashes_processed_in_following_mode() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::unbounded_channel();
    peer_store.add_peer(peer, tx).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);
    service.state = SyncState::Following;

    // Announce a new block
    service.on_new_block_hashes(peer, vec![
        BlockIdentifier { hash: B256::repeat_byte(0xbb), number: 1 },
    ]).await;

    // Should have sent a headers request to the peer
    let msg = rx.try_recv();
    assert!(msg.is_ok(), "Expected a headers request message to be sent");

    // Peer metadata should be updated
    let best = peer_store.best_peer().await;
    assert!(best.is_some());
    let (_, meta) = best.unwrap();
    assert_eq!(meta.best_number, 1);
}

#[tokio::test]
async fn test_following_switches_to_sync_on_large_gap() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a small chain so our_height > 0 (check_follow_gap returns early at 0)
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_header(&b2).unwrap();
    store.put_total_difficulty(b1.hash(), U256::from(2)).unwrap();
    store.put_total_difficulty(b2.hash(), U256::from(3)).unwrap();
    store.update_head(&b2, U256::from(3)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::unbounded_channel();
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 200, // 198 blocks ahead (> 24)
        total_difficulty: U256::from(200),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    service.check_follow_gap().await;

    assert!(
        matches!(service.state, SyncState::DownloadingSkeleton { .. } | SyncState::FindingConnectionPoint { .. }),
        "Expected DownloadingSkeleton or FindingConnectionPoint after large gap in Following, got {:?}", service.state
    );
}

#[tokio::test]
async fn test_following_stays_when_gap_small() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a small chain so our_height > 0
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_total_difficulty(b1.hash(), U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_id = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::unbounded_channel();
    peer_store.add_peer(peer_id, tx).await;
    peer_store.update_metadata(&peer_id, rustock_networking::peers::PeerMetadata {
        best_number: 5, // only 4 blocks ahead (< 24)
        total_difficulty: U256::from(5),
        ..Default::default()
    }).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    service.check_follow_gap().await;

    assert!(matches!(service.state, SyncState::Following),
        "Expected Following to persist with small gap, got {:?}", service.state);
}

#[tokio::test]
async fn test_handler_forwards_new_block_hashes() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let blocks = vec![
        BlockIdentifier { hash: B256::repeat_byte(0x01), number: 100 },
        BlockIdentifier { hash: B256::repeat_byte(0x02), number: 101 },
    ];
    let msg = P2pMessage::RskMessage(RskMessage::new(
        RskSubMessage::NewBlockHashes(blocks),
    ));

    let resp = handler.handle_message(B512::repeat_byte(0xaa), &msg);
    assert!(resp.is_none());

    match event_rx.try_recv().unwrap() {
        SyncEvent::NewBlockHashes { peer, identifiers } => {
            assert_eq!(peer, B512::repeat_byte(0xaa));
            assert_eq!(identifiers.len(), 2);
            assert_eq!(identifiers[0].number, 100);
            assert_eq!(identifiers[1].number, 101);
        }
        other => panic!("Expected NewBlockHashes event, got {:?}", other),
    }
}

#[tokio::test]
async fn test_headers_response_in_following_mode() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    let peer = B512::repeat_byte(0x01);

    // Simulate receiving a headers response while in Following mode
    service.on_headers_response(peer, vec![b1]).await;

    // State should remain Following
    assert!(matches!(service.state, SyncState::Following),
        "Expected Following after headers response, got {:?}", service.state);

    // Header should be stored
    assert!(store.header(b1_hash).unwrap().is_some());
    assert_eq!(store.head().unwrap(), Some(b1_hash));
}

// -- Peer serving tests (BlockHeadersRequest, BlockHashRequest, SkeletonRequest) --

#[tokio::test]
async fn test_serve_block_hash_request() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BlockHashRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHashRequest { id: 42, height: 1 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)));

    let resp = handler.handle_message(B512::repeat_byte(0x01), &msg);
    assert!(resp.is_some(), "Should respond to BlockHashRequest");

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BlockHashResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 42);
            assert_eq!(r.hash, b1_hash);
        } else {
            panic!("Expected BlockHashResponse");
        }
    } else {
        panic!("Expected RskMessage response");
    }
}

#[tokio::test]
async fn test_serve_block_hash_request_unknown_height() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BlockHashRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHashRequest { id: 99, height: 9999 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond for unknown height");
}

#[tokio::test]
async fn test_serve_block_hash_request_height_zero() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BlockHashRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHashRequest { id: 1, height: 0 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond for height 0 (matches rskj)");
}

#[tokio::test]
async fn test_serve_headers_request_single() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHeadersRequest, BlockHeadersQuery};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHeadersRequest {
        id: 7,
        query: BlockHeadersQuery { hash: b1_hash, count: 1 },
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)));

    let resp = handler.handle_message(B512::repeat_byte(0x01), &msg);
    assert!(resp.is_some());

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BlockHeadersResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 7);
            assert_eq!(r.headers.len(), 1);
            assert_eq!(r.headers[0].number, 1);
        } else {
            panic!("Expected BlockHeadersResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_headers_request_chain_walk() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHeadersRequest, BlockHeadersQuery};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b2 = dummy_header(2, b1.hash(), U256::from(1));
    let b3 = dummy_header(3, b2.hash(), U256::from(1));
    store.put_header(&b1).unwrap();
    store.put_header(&b2).unwrap();
    store.put_header(&b3).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    // Request 3 headers starting from b3 (walking backwards)
    let req = BlockHeadersRequest {
        id: 10,
        query: BlockHeadersQuery { hash: b3.hash(), count: 3 },
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_some());

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BlockHeadersResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 10);
            assert_eq!(r.headers.len(), 3);
            // Headers are returned in descending order (b3, b2, b1)
            assert_eq!(r.headers[0].number, 3);
            assert_eq!(r.headers[1].number, 2);
            assert_eq!(r.headers[2].number, 1);
        } else {
            panic!("Expected BlockHeadersResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_headers_request_unknown_hash() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHeadersRequest, BlockHeadersQuery};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BlockHeadersRequest {
        id: 1,
        query: BlockHeadersQuery {
            hash: B256::repeat_byte(0xFF),
            count: 10,
        },
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond for unknown hash");
}

#[tokio::test]
async fn test_serve_headers_request_capped_count() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHeadersRequest, BlockHeadersQuery};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    store.put_header(&b1).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    // Request 1000 headers but we only have 2 (b1 + genesis)
    let req = BlockHeadersRequest {
        id: 1,
        query: BlockHeadersQuery { hash: b1.hash(), count: 1000 },
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_some());

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BlockHeadersResponse(r) = rsk_msg.sub_message {
            // Should only return what's available (capped at MAX_HEADERS_SERVE=192
            // and chain length = 2)
            assert_eq!(r.headers.len(), 2);
        } else {
            panic!("Expected BlockHeadersResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_skeleton_request() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::SkeletonRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a chain of 500 blocks
    let mut prev_hash = B256::ZERO;
    let mut td = U256::ZERO;
    for i in 0..=500u64 {
        let h = dummy_header(i, prev_hash, U256::from(1));
        let hash = h.hash();
        td += h.difficulty;
        store.put_header(&h).unwrap();
        store.put_canonical_hash(i, hash).unwrap();
        store.put_total_difficulty(hash, td).unwrap();
        if i == 500 {
            store.set_head(hash).unwrap();
        }
        prev_hash = hash;
    }

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = SkeletonRequest { id: 55, start_number: 0 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_some(), "Should respond to SkeletonRequest");

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::SkeletonResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 55);
            // Should have entries at 0, 192, 384, and best=500
            assert!(r.block_identifiers.len() >= 3);
            assert_eq!(r.block_identifiers[0].number, 0);
            assert_eq!(r.block_identifiers[1].number, 192);
            assert_eq!(r.block_identifiers[2].number, 384);
            // Last entry should be the best block (500)
            let last = r.block_identifiers.last().unwrap();
            assert_eq!(last.number, 500);
        } else {
            panic!("Expected SkeletonResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_skeleton_request_unknown_start() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::SkeletonRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = SkeletonRequest { id: 1, start_number: 99999 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond for unknown start number");
}

#[tokio::test]
async fn test_serve_skeleton_request_at_boundary() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::SkeletonRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build a chain of exactly 192 blocks (one skeleton step)
    let mut prev_hash = B256::ZERO;
    let mut td = U256::ZERO;
    for i in 0..=192u64 {
        let h = dummy_header(i, prev_hash, U256::from(1));
        let hash = h.hash();
        td += h.difficulty;
        store.put_header(&h).unwrap();
        store.put_canonical_hash(i, hash).unwrap();
        store.put_total_difficulty(hash, td).unwrap();
        if i == 192 {
            store.set_head(hash).unwrap();
        }
        prev_hash = hash;
    }

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = SkeletonRequest { id: 1, start_number: 0 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::SkeletonRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_some());

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::SkeletonResponse(r) = rsk_msg.sub_message {
            // Should have entries at 0 and 192
            assert_eq!(r.block_identifiers.len(), 2);
            assert_eq!(r.block_identifiers[0].number, 0);
            assert_eq!(r.block_identifiers[1].number, 192);
        } else {
            panic!("Expected SkeletonResponse");
        }
    }
}

#[tokio::test]
async fn test_serve_requests_dont_interfere_with_event_forwarding() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::{BlockHashRequest, BlockHeadersResponse as BHResp};

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    store.update_head(&genesis, U256::from(1)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);
    let peer = B512::repeat_byte(0x01);

    // 1. Serve a block hash request (returns response, no event)
    let req = BlockHashRequest { id: 1, height: 0 };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHashRequest(req)));
    let _resp = handler.handle_message(peer, &msg);
    assert!(event_rx.try_recv().is_err(), "Serving should not forward events");

    // 2. Forward a headers response (no response, forwards event)
    let headers_resp = BHResp { id: 2, headers: vec![genesis.clone()] };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BlockHeadersResponse(headers_resp)));
    let resp = handler.handle_message(peer, &msg);
    assert!(resp.is_none(), "Forwarding should not return a response");
    assert!(event_rx.try_recv().is_ok(), "Should forward the event");
}

// -- Reorg tests ----------------------------------------------------------

/// Like dummy_header but with extra_data to differentiate fork branches.
fn fork_header(number: u64, parent: B256, difficulty: U256, branch: u8) -> Header {
    let mut h = dummy_header(number, parent, difficulty);
    h.extra_data = Bytes::from(vec![branch]);
    h
}

#[tokio::test]
async fn test_new_block_hashes_reorg_candidate_triggers_request() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();
    store.put_total_difficulty(b1_hash, U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::unbounded_channel();
    peer_store.add_peer(peer, tx).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);
    service.state = SyncState::Following;

    // Announce a competing block at height 1 with a different hash
    let competing_hash = B256::repeat_byte(0xCC);
    service.on_new_block_hashes(peer, vec![
        BlockIdentifier { hash: competing_hash, number: 1 },
    ]).await;

    // Should have sent a headers request for the competing chain
    let msg = rx.try_recv();
    assert!(msg.is_ok(), "Should request headers for reorg candidate");
}

#[tokio::test]
async fn test_new_block_hashes_same_hash_ignored() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();
    store.put_total_difficulty(b1_hash, U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer = B512::repeat_byte(0x01);
    let (tx, mut rx) = mpsc::unbounded_channel();
    peer_store.add_peer(peer, tx).await;

    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store.clone(), event_rx);
    service.state = SyncState::Following;

    // Announce the SAME hash at height 1 — should be ignored
    service.on_new_block_hashes(peer, vec![
        BlockIdentifier { hash: b1_hash, number: 1 },
    ]).await;

    assert!(rx.try_recv().is_err(), "Should not request headers for same hash");
}

#[tokio::test]
async fn test_reorg_via_headers_response_higher_td() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build canonical chain: genesis -> 1A -> 2A
    let genesis = dummy_header(0, B256::ZERO, U256::from(10));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(10)).unwrap();

    let a1 = dummy_header(1, genesis_hash, U256::from(10));
    let a2 = dummy_header(2, a1.hash(), U256::from(10));
    store.put_header(&a1).unwrap();
    store.put_canonical_hash(1, a1.hash()).unwrap();
    store.put_total_difficulty(a1.hash(), U256::from(20)).unwrap();
    store.put_header(&a2).unwrap();
    store.put_canonical_hash(2, a2.hash()).unwrap();
    store.put_total_difficulty(a2.hash(), U256::from(30)).unwrap();
    store.update_head(&a2, U256::from(30)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    // Fork from genesis: 1B -> 2B with higher difficulty
    let b1 = fork_header(1, genesis_hash, U256::from(20), 0xBB);
    let b2 = fork_header(2, b1.hash(), U256::from(20), 0xBB);

    // Receive fork headers (descending order, like real peers send)
    let peer = B512::repeat_byte(0x01);
    service.on_headers_response(peer, vec![b2.clone(), b1.clone()]).await;

    // Fork B has TD = 10 + 20 + 20 = 50 vs chain A's TD = 30
    // Head should switch to fork B
    assert_eq!(store.head().unwrap(), Some(b2.hash()));
    assert_eq!(store.canonical_hash(1).unwrap(), Some(b1.hash()));
    assert_eq!(store.canonical_hash(2).unwrap(), Some(b2.hash()));
}

#[tokio::test]
async fn test_no_reorg_via_headers_response_lower_td() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    // Build canonical chain: genesis -> 1A -> 2A (high difficulty)
    let genesis = dummy_header(0, B256::ZERO, U256::from(10));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(10)).unwrap();

    let a1 = dummy_header(1, genesis_hash, U256::from(20));
    let a2 = dummy_header(2, a1.hash(), U256::from(20));
    store.put_header(&a1).unwrap();
    store.put_canonical_hash(1, a1.hash()).unwrap();
    store.put_total_difficulty(a1.hash(), U256::from(30)).unwrap();
    store.put_header(&a2).unwrap();
    store.put_canonical_hash(2, a2.hash()).unwrap();
    store.put_total_difficulty(a2.hash(), U256::from(50)).unwrap();
    store.update_head(&a2, U256::from(50)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);
    service.state = SyncState::Following;

    // Fork from genesis: 1B -> 2B with lower difficulty
    let b1 = fork_header(1, genesis_hash, U256::from(5), 0xBB);
    let b2 = fork_header(2, b1.hash(), U256::from(5), 0xBB);

    let peer = B512::repeat_byte(0x01);
    service.on_headers_response(peer, vec![b2.clone(), b1.clone()]).await;

    // Fork B has TD = 10 + 5 + 5 = 20 vs chain A's TD = 50
    // Head should NOT change
    assert_eq!(store.head().unwrap(), Some(a2.hash()));
    assert_eq!(store.canonical_hash(1).unwrap(), Some(a1.hash()));
    assert_eq!(store.canonical_hash(2).unwrap(), Some(a2.hash()));

    // Fork B headers should still be stored
    assert!(store.header(b1.hash()).unwrap().is_some());
    assert!(store.header(b2.hash()).unwrap().is_some());
}

// ========== Body download tests ==========

#[tokio::test]
async fn test_sync_handler_serves_body_request() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BodyRequest;
    use rustock_core::Transaction;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    // Store a body for genesis
    let tx = Transaction {
        nonce: 42,
        gas_price: U256::from(10),
        gas_limit: U256::from(21000),
        to: Bytes::from(vec![0x12; 20]),
        value: U256::from(100),
        input: Bytes::default(),
        v: 27,
        r: U256::from(88),
        s: U256::from(99),
        cached_rlp: None,
    };
    store.put_body(genesis_hash, &[tx], &[]).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BodyRequest { id: 33, hash: genesis_hash };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyRequest(req)));

    let resp = handler.handle_message(B512::repeat_byte(0x01), &msg);
    assert!(resp.is_some(), "Should respond to BodyRequest");

    if let Some(P2pMessage::RskMessage(rsk_msg)) = resp {
        if let RskSubMessage::BodyResponse(r) = rsk_msg.sub_message {
            assert_eq!(r.id, 33);
            assert_eq!(r.transactions.len(), 1);
            assert_eq!(r.transactions[0].nonce, 42);
            assert!(r.uncles.is_empty());
        } else {
            panic!("Expected BodyResponse");
        }
    } else {
        panic!("Expected RskMessage response");
    }
}

#[tokio::test]
async fn test_sync_handler_serves_body_request_not_found() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BodyRequest;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let req = BodyRequest { id: 1, hash: B256::repeat_byte(0xFF) };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyRequest(req)));

    let resp = handler.handle_message(B512::ZERO, &msg);
    assert!(resp.is_none(), "Should not respond when body not found");
}

#[tokio::test]
async fn test_sync_handler_forwards_body_response() {
    use rustock_networking::protocol::{P2pMessage, RskMessage, RskSubMessage};
    use rustock_networking::protocol::P2pHandler;
    use rustock_networking::protocol::rsk::BodyResponse;
    use crate::events::SyncEvent;

    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());
    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store));

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = SyncHandler::new(manager, event_tx);

    let resp = BodyResponse {
        id: 42,
        transactions: vec![],
        uncles: vec![],
    };
    let msg = P2pMessage::RskMessage(RskMessage::new(RskSubMessage::BodyResponse(resp)));

    let handler_resp = handler.handle_message(B512::repeat_byte(0x01), &msg);
    assert!(handler_resp.is_none());

    match event_rx.try_recv().unwrap() {
        SyncEvent::BodyResponse { id, transactions, uncles, .. } => {
            assert_eq!(id, 42);
            assert!(transactions.is_empty());
            assert!(uncles.is_empty());
        }
        other => panic!("Expected BodyResponse event, got {:?}", other),
    }
}

#[tokio::test]
async fn test_body_download_state_machine() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();
    store.put_total_difficulty(b1_hash, U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer = B512::repeat_byte(0x01);
    let (tx, _rx) = mpsc::unbounded_channel();
    peer_store.add_peer(peer, tx).await;

    let manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    // Trigger body download; peer_best=1 means we're at tip after downloading
    service.start_body_downloads(1).await;

    match &service.state {
        SyncState::DownloadingBodies { pending_headers, .. } => {
            assert_eq!(pending_headers.len(), 1);
            assert_eq!(pending_headers[0].0, b1_hash);
        }
        _ => panic!("Expected DownloadingBodies, got {:?}", service.state),
    }

    // Simulate receiving the body response
    if let SyncState::DownloadingBodies { in_flight, .. } = &service.state {
        let req_id = *in_flight.keys().next().unwrap();
        service.on_body_response(req_id, vec![], vec![]).await;
    }

    assert!(matches!(service.state, SyncState::Following),
        "Expected Following after all bodies downloaded, got {:?}", service.state);

    // Body should be stored
    let (txs, ommers) = store.body(b1_hash).unwrap().unwrap();
    assert!(txs.is_empty());
    assert!(ommers.is_empty());
}

#[tokio::test]
async fn test_body_download_all_bodies_present_skips() {
    let dir = tempdir().unwrap();
    let store = Arc::new(BlockStore::open(dir.path()).unwrap());

    let genesis = dummy_header(0, B256::ZERO, U256::from(1));
    let genesis_hash = genesis.hash();
    store.update_head(&genesis, U256::from(1)).unwrap();

    let b1 = dummy_header(1, genesis_hash, U256::from(1));
    let b1_hash = b1.hash();
    store.put_header(&b1).unwrap();
    store.put_canonical_hash(1, b1_hash).unwrap();
    store.put_total_difficulty(b1_hash, U256::from(2)).unwrap();
    store.update_head(&b1, U256::from(2)).unwrap();

    // Pre-store the body
    store.put_body(b1_hash, &[], &[]).unwrap();

    let verifier = Arc::new(HeaderVerifier::new());
    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let manager = Arc::new(SyncManager::new(store, verifier, peer_store.clone()));
    let (_event_tx, event_rx) = mpsc::unbounded_channel();
    let mut service = SyncService::new(manager, peer_store, event_rx);

    service.start_body_downloads(1).await;

    // Should skip directly to Following since all bodies are present
    assert!(matches!(service.state, SyncState::Following),
        "Expected Following when all bodies present, got {:?}", service.state);
}

// ========== TxRelay tests ==========

#[tokio::test]
async fn test_tx_relay_filters_duplicates() {
    use crate::tx_relay::TxRelay;
    use rustock_networking::protocol::rsk::{RskMessage, RskSubMessage};
    use rustock_networking::protocol::{P2pHandler, P2pMessage};
    use alloy_primitives::Bytes;
    use tokio::sync::mpsc;

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());

    let peer_a = alloy_primitives::B512::repeat_byte(0x0a);
    let peer_b = alloy_primitives::B512::repeat_byte(0x0b);
    let (_tx_a, _rx_a) = mpsc::unbounded_channel();
    let (tx_b, mut rx_b) = mpsc::unbounded_channel();
    peer_store.add_peer(peer_a, _tx_a).await;
    peer_store.add_peer(peer_b, tx_b).await;

    let relay = TxRelay::new(peer_store);
    let tx_data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);

    let msg = P2pMessage::RskMessage(RskMessage::new(
        RskSubMessage::Transactions(vec![tx_data.clone()]),
    ));
    relay.handle_message(peer_a, &msg);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(rx_b.try_recv().is_ok(), "peer B should receive the tx");

    relay.handle_message(peer_a, &msg);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(rx_b.try_recv().is_err(), "duplicate should be suppressed");
}

#[tokio::test]
async fn test_tx_relay_submit_transaction() {
    use crate::tx_relay::TxRelay;
    use alloy_primitives::Bytes;
    use tokio::sync::mpsc;

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let peer_a = alloy_primitives::B512::repeat_byte(0x0a);
    let (tx_a, mut rx_a) = mpsc::unbounded_channel();
    peer_store.add_peer(peer_a, tx_a).await;

    let relay = TxRelay::new(peer_store);
    let raw = Bytes::from(vec![0xca, 0xfe]);
    let hash = relay.submit_transaction(raw).await.unwrap();

    assert_ne!(hash, alloy_primitives::B256::ZERO);
    assert!(rx_a.try_recv().is_ok(), "peer should receive broadcast");
}
