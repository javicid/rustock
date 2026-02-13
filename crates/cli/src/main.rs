use clap::Parser;
use rustock_core::config::ChainConfig;
use rustock_core::validation::HeaderVerifier;
use rustock_core::types::header::Header;
use rustock_storage::BlockStore;
use rustock_networking::node::{Node, NodeConfig};
use rustock_sync::{SyncManager, SyncHandler, SyncService};
use std::sync::Arc;
use alloy_primitives::{B256, U256, Address, Bytes};
use anyhow::{Result, Context};
use tracing::{info, Level};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen for P2P connections
    #[arg(short, long, default_value_t = 30303)]
    port: u16,

    /// RPC Port (Not yet implemented)
    #[arg(long, default_value_t = 4444)]
    rpc_port: u16,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    data_dir: String,

    /// Network ID (30 for mainnet, 33 for regtest)
    #[arg(long, default_value = "30")]
    network_id: u64,

    /// Secret key for the P2P node (hex). If not provided, a random one will be used.
    #[arg(long)]
    secret_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize Logging
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_target(false)
        .init();

    let args = Args::parse();
    info!("Starting Rustock Light Client on port {}...", args.port);

    // 2. Initialize Storage
    let store = Arc::new(BlockStore::open(&args.data_dir)?);
    
    // 3. Setup Genesis (if empty)
    let genesis_hash = setup_genesis(&store, args.network_id)?;
    info!("Genesis Hash: {:?}", genesis_hash);

    // 4. Setup Consensus & Sync
    let config = match args.network_id {
        30 => ChainConfig::mainnet(),
        31 => ChainConfig::testnet(),
        _ => ChainConfig::regtest(),
    };
    let verifier = Arc::new(HeaderVerifier::default_rsk(config.clone()));
    
    // 5. Setup Networking
    let key_path = std::path::Path::new(&args.data_dir).join("node.key");
    
    let secret_key_bytes = if let Some(hex_key) = args.secret_key {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_key, &mut bytes).context("Invalid hex for secret key")?;
        bytes
    } else if key_path.exists() {
        let hex_key = std::fs::read_to_string(&key_path).context("Failed to read node.key")?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_key.trim(), &mut bytes).context("Invalid hex in node.key")?;
        info!("Loaded existing node identity from {:?}", key_path);
        bytes
    } else {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        
        // Save it for next time
        std::fs::create_dir_all(&args.data_dir).context("Failed to create data directory")?;
        std::fs::write(&key_path, hex::encode(bytes)).context("Failed to save node.key")?;
        
        info!("Generated and saved new node identity to {:?}", key_path);
        bytes
    };

    let signing_key = k256::ecdsa::SigningKey::from_slice(&secret_key_bytes)?;
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let node_id = alloy_primitives::B512::from_slice(&encoded_point.as_bytes()[1..]);
    
    let node_config = NodeConfig {
        client_id: "Rustock/0.1.0".to_string(),
        listen_port: args.port,
        id: node_id,
        chain_id: config.chain_id,
        network_id: config.network_id,
        genesis_hash,
        best_hash: genesis_hash,
        total_difficulty: U256::ZERO, // Will be updated from store later if needed
        bootnodes: get_bootnodes(config.chain_id as u64),
        secret_key: secret_key_bytes,
        discovery_port: args.port + 1,
        data_dir: args.data_dir.clone(),
    };

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let sync_manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    // Create event channel for sync handler → service communication
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let sync_handler = Arc::new(SyncHandler::new(sync_manager.clone(), event_tx));
    let sync_service = SyncService::new(sync_manager.clone(), peer_store.clone(), event_rx);

    let mut node = Node::with_peer_store(node_config, peer_store.clone());
    node.add_handler(sync_handler);

    // 6. Start Sync Service (skeleton-based forward sync)
    tokio::spawn(sync_service.start());

    // 7. Start Node
    node.start().await?;

    Ok(())
}

fn setup_genesis(store: &BlockStore, _network_id: u64) -> Result<B256> {
    if let Some(head) = store.get_head()? {
        return Ok(head);
    }

    // Well-known genesis hashes (from rskj reference)
    let known_genesis_hash: Option<B256> = match _network_id {
        30 => Some("0xf88529d4ab262c0f4d042e9d8d3f2472848eaafe1a9b7213f57617eb40a9f9e0".parse().unwrap()),
        31 => Some("0xcabb7fbe562a6e2e1a8d8df0f4f8b19c4a76c22fe1e6b9a1dc45a0e4d8e0e2c4".parse().unwrap()),
        _ => None,
    };

    // EMPTY_LIST_HASH = keccak256(RLP([])) = keccak256([0xc0])
    let empty_list_hash: B256 = "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".parse().unwrap();
    // EMPTY_TRIE_HASH = keccak256(RLP.encodeElement([])) = keccak256([0x80])
    let empty_trie_hash: B256 = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".parse().unwrap();

    let genesis = if _network_id == 30 {
        // RSK Mainnet (matching rskj rsk-mainnet.json)
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: empty_list_hash,
            beneficiary: "0x3333333333333333333333333333333333333333".parse().unwrap(),
            state_root: "0x9fa70f12726ac738640a86754741bb3f5680520ccc7e6ae9d95ace566a67fe01".parse().unwrap(),
            transactions_root: empty_trie_hash,
            receipts_root: empty_trie_hash,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(0x00100000), 
            number: 0,
            gas_limit: U256::from(0x67c280),
            gas_used: 0,
            timestamp: 0x5a4af5b0, // 1514862000 
            extra_data: Bytes::from_static(&hex_literal::hex!("486170707920426974636f696e20446179212030332f4a616e2f32303138202d2052534b20746563686e6f6c6f6779206174207468652073657276696365206f6620736f6369657479")),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(0x0AE85BC0),
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: Some(Bytes::from_static(&[0x00])),
            bitcoin_merged_mining_merkle_proof: Some(Bytes::from_static(&[0x00])),
            bitcoin_merged_mining_coinbase_transaction: Some(Bytes::from_static(&[0x00])),
        }
    } else if _network_id == 31 {
        // RSK Testnet (Orchid)
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: "0x45bce5168430c42b3d568331753f900a32457b4f3748697cbd8375ff4da72641".parse().unwrap(),
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(0x00100000), 
            number: 0,
            gas_limit: U256::from(0x4c4b40),
            gas_used: 0,
            timestamp: 0, 
            extra_data: Bytes::from_static(&hex_literal::hex!("434d272841")),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
        }
    } else {
        // Regtest / Default
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            extension_data: None,
            difficulty: U256::from(0x20000),
            number: 0,
            gas_limit: U256::from(10_000_000),
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::from("rustock-genesis"),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::ZERO,
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
        }
    };

    // Use the known genesis hash for mainnet/testnet (Java's GenesisHeader has special
    // RLP encoding for difficulty with leading zeros that differs from standard encoding).
    let hash = known_genesis_hash.unwrap_or_else(|| genesis.hash());
    store.put_header_with_hash(hash, &genesis)?;
    store.put_total_difficulty(hash, genesis.difficulty)?;
    store.put_canonical_hash(0, hash)?;
    store.set_head(hash)?;
    Ok(hash)
}

fn get_bootnodes(network_id: u64) -> Vec<String> {
    if network_id == 30 {
        // RSK Mainnet Snap-Capable & Standard Bootstrap Nodes
        vec![
            "enode://e3a25521354aa99424f5de89cdd2e36aa9b9a96d965d1f7f47d876be0cdbd29c7df327a74170f6a9ea44f54f6ab8ae0dae28e40bb89dbd572a617e2008cfc215@34.203.14.152:5050".to_string(), // Snapshot 1 (resolved)
            "enode://f0093935353f94c723a9b67d143ad62464aaf3c959dc05a87f00b637f9c734513493d53f7223633514ea33f2a685878620f0d002cabc05d7f37e6c152774d5da@18.130.226.64:5050".to_string(), // Snapshot 2 (resolved)
            "enode://668702f3d526e06b9b9409564f0b09426f84d693444053673c683b5443fa48a39a259c402120409a473a268a2bf62e3d3090ed596d07d1a296ba2925b4260aa7@48.246.52.203:50501".to_string(), // Bootnode 1
            "enode://277884485741f237f3f15c7e424263304d9c0205d933ca373302bc6e2468351540f2f7902d33406df77d3419515967b5ae1537243c5b96715f5c9e2b02005470@137.66.19.167:50501".to_string(), // Bootnode 2
        ]
    } else if network_id == 31 {
        // RSK Testnet Snap-Capable Bootstrap Nodes
        vec![
            "enode://137eb4328a7c2298e26dd15bba4796a7cc30b5097f8a14b384c8dc78caab49fac7a897c39a5a7e87838ac6dc1a80b94891d274a85ac76e7342d66e8a9ed26bf5@snapshot-sync-euw1-1.testnet.rskcomputing.net:50505".to_string(),
            "enode://fcbfbfce93671320d32ab36ab04ae1564a31892cba219f0a489337aad105dcfc0ebe7d7c2b109d1f4462e8e80588d8ef639b6f321cc1a3f51ec072bed3438105@snapshot-sync-usw2-1.testnet.rskcomputing.net:50505".to_string(),
        ]
    } else {
        vec![]
    }
}
