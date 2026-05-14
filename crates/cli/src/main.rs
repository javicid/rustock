use clap::Parser;
use rustock_core::config::ChainConfig;
use rustock_core::validation::HeaderVerifier;
use rustock_storage::BlockStore;
use rustock_networking::node::{Node, NodeConfig};
use rustock_sync::{SyncManager, SyncHandler, SyncService, TxRelay};
use rustock_trie::{AccountState, TrieKeySlice, TrieNode, TrieStore, account_key};
use std::sync::Arc;
use alloy_primitives::U256;
use anyhow::{Result, Context};
use tracing::info;
use tracing_subscriber::EnvFilter;

struct TxRelaySubmitter(Arc<TxRelay>);

#[async_trait::async_trait]
impl rustock_rpc::server::TxSubmitter for TxRelaySubmitter {
    async fn submit_transaction(&self, raw_tx: alloy_primitives::Bytes) -> Result<alloy_primitives::B256, String> {
        self.0.submit_transaction(raw_tx).await
    }
}

struct PoolAdapter(Arc<rustock_sync::TransactionPool>);

impl rustock_rpc::server::TxPoolReader for PoolAdapter {
    fn get_pending_tx(
        &self,
        hash: &alloy_primitives::B256,
    ) -> Option<(rustock_core::Transaction, alloy_primitives::Address, alloy_primitives::B256)> {
        let ptx = self.0.get(hash)?;
        Some((ptx.tx, ptx.sender, ptx.hash))
    }

    fn pending_nonce(&self, addr: &alloy_primitives::Address) -> Option<u64> {
        self.0.pending_nonce(addr)
    }

    fn pool_status(&self) -> (usize, usize) {
        self.0.status()
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen for P2P connections
    #[arg(short, long, default_value_t = 30303)]
    port: u16,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    data_dir: String,

    /// Network ID (30 for mainnet, 33 for regtest)
    #[arg(long, default_value = "30")]
    network_id: u64,

    /// Secret key for the P2P node (hex). If not provided, a random one will be used.
    #[arg(long)]
    secret_key: Option<String>,

    /// Log level: trace, debug, info, warn, error.
    /// Can also use RUST_LOG-style directives, e.g. "info,rustock_sync=debug".
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Log to stdout instead of a file. By default logs are written to
    /// <data-dir>/rustock.log with automatic daily rotation.
    #[arg(long, default_value_t = false)]
    log_to_stdout: bool,

    /// JSON-RPC server port
    #[arg(long, default_value_t = 4444)]
    rpc_port: u16,

    /// JSON-RPC server bind address
    #[arg(long, default_value = "127.0.0.1")]
    rpc_host: String,

    /// Disable the JSON-RPC server
    #[arg(long, default_value_t = false)]
    no_rpc: bool,

    /// External IP address to advertise to peers (e.g., 203.0.113.42).
    /// If not set, 127.0.0.1 is used.
    #[arg(long)]
    external_ip: Option<std::net::IpAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    std::fs::create_dir_all(&args.data_dir).context("Failed to create data directory")?;

    let _guard = if args.log_to_stdout {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
        None
    } else {
        let file_appender = tracing_appender::rolling::daily(&args.data_dir, "rustock.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(non_blocking)
            .init();

        let log_path = std::path::Path::new(&args.data_dir).join("rustock.log");
        eprintln!("Logging to {}", log_path.display());
        eprintln!("Use --log-to-stdout to log to the console instead.");
        eprintln!("Tail the log: tail -f {}", log_path.display());

        Some(guard)
    };

    info!("Starting Rustock on port {}...", args.port);

    let config = match args.network_id {
        30 => ChainConfig::mainnet(),
        31 => ChainConfig::testnet(),
        _ => ChainConfig::regtest(),
    };
    let config = Arc::new(config);

    let store = Arc::new(BlockStore::open(&args.data_dir)?);

    let genesis_hash = setup_genesis(&store, &config)?;
    info!("Genesis Hash: {:?}", genesis_hash);

    let verifier = Arc::new(HeaderVerifier::default_rsk(config.clone()));

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

        std::fs::create_dir_all(&args.data_dir).context("Failed to create data directory")?;
        std::fs::write(&key_path, hex::encode(bytes)).context("Failed to save node.key")?;

        info!("Generated and saved new node identity to {:?}", key_path);
        bytes
    };

    let signing_key = k256::ecdsa::SigningKey::from_slice(&secret_key_bytes)?;
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let node_id = alloy_primitives::B512::from_slice(&encoded_point.as_bytes()[1..]);

    let (best_hash, best_td, best_number) = if let Some(head_hash) = store.head()? {
        let td = store.total_difficulty(head_hash)?.unwrap_or(U256::ZERO);
        let number = store.header(head_hash)?
            .map(|h| h.number)
            .unwrap_or(0);
        (head_hash, td, number)
    } else {
        (genesis_hash, U256::ZERO, 0)
    };

    let node_config = NodeConfig {
        client_id: "Rustock/0.1.0".to_string(),
        listen_port: args.port,
        id: node_id,
        chain_id: config.chain_id,
        network_id: config.network_id,
        genesis_hash,
        best_hash,
        best_block_number: best_number,
        total_difficulty: best_td,
        bootnodes: config.bootnodes(),
        secret_key: secret_key_bytes,
        discovery_port: args.port + 1,
        data_dir: args.data_dir.clone(),
        external_ip: args.external_ip,
    };

    let peer_store = Arc::new(rustock_networking::peers::PeerStore::new());
    let sync_manager = Arc::new(SyncManager::new(store.clone(), verifier, peer_store.clone()));

    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let sync_handler = Arc::new(SyncHandler::new(sync_manager.clone(), event_tx));
    let trie_store_for_pool: Arc<dyn rustock_trie::TrieStore> =
        Arc::new(rustock_storage::RocksDbTrieStore::from_db(store.db().clone()));
    let pool = Arc::new(rustock_sync::TransactionPool::new(
        rustock_sync::txpool::PoolConfig::default(),
        config.chain_id.into(),
        store.clone(),
        trie_store_for_pool,
    ));

    let hardfork_cfg = rustock_execution::RskHardforkConfig::for_network(config.chain_id as u64);
    let block_processor = rustock_execution::BlockProcessor::new(
        hardfork_cfg.clone(),
        store.clone(),
    );
    info!("Block processor wired (hardfork config: {:?})", hardfork_cfg);

    let trie_store_for_exec: Arc<dyn rustock_trie::TrieStore> =
        Arc::new(rustock_storage::CachedTrieStore::with_defaults(store.db().clone()));

    let initial_state_root = load_or_build_state(&store, &config, trie_store_for_exec.as_ref())?;
    info!("Initial state root: {:?}", initial_state_root.compute_hash(trie_store_for_exec.as_ref()));

    let sync_service = SyncService::new(sync_manager.clone(), peer_store.clone(), event_rx)
        .with_tx_pool(pool.clone())
        .with_block_processor(block_processor, trie_store_for_exec, initial_state_root);
    let tx_relay = Arc::new(TxRelay::with_pool(peer_store.clone(), pool.clone()));

    let mut node = Node::with_peer_store(node_config, peer_store.clone());
    node.add_handler(sync_handler);
    node.add_handler(tx_relay.clone());

    tokio::spawn(sync_service.start());

    if !args.no_rpc {
        let trie_store: Arc<dyn rustock_trie::TrieStore> =
            Arc::new(rustock_storage::RocksDbTrieStore::from_db(store.db().clone()));

        let rpc_state = rustock_rpc::server::RpcState {
            store: store.clone(),
            peer_store: peer_store.clone(),
            config: config.clone(),
            tx_submitter: Some(Arc::new(TxRelaySubmitter(tx_relay.clone()))),
            trie_store: Some(trie_store),
            hardfork_cfg: Some(hardfork_cfg),
            filter_store: Arc::new(rustock_rpc::logs::FilterStore::new()),
            tx_pool: Some(Arc::new(PoolAdapter(pool.clone()))),
        };
        let rpc_host = args.rpc_host.clone();
        let rpc_port = args.rpc_port;
        tokio::spawn(async move {
            if let Err(e) = rustock_rpc::server::start_rpc_server(&rpc_host, rpc_port, rpc_state).await {
                tracing::error!("RPC server error: {}", e);
            }
        });
    }

    node.start().await?;

    Ok(())
}

/// Try to resume from persisted state, falling back to genesis if unavailable.
///
/// On restart, loads the state root from the last processed block's header
/// and reconstructs the trie root from disk. Children resolve lazily via
/// `NodeRef::Hash` lookups against the trie store.
fn load_or_build_state(
    store: &BlockStore,
    config: &ChainConfig,
    trie_store: &dyn TrieStore,
) -> Result<TrieNode> {
    if let Some(head_hash) = store.head()? {
        if let Some(header) = store.header(head_hash)? {
            if header.number > 0 {
                let state_root = header.state_root;
                if let Some(data) = trie_store.get(state_root.as_slice()) {
                    let root = TrieNode::from_message(&data, trie_store);
                    let verified = root.compute_hash(trie_store);
                    if verified == state_root {
                        info!(
                            "Resuming from block #{} (state root: {:?})",
                            header.number, state_root
                        );
                        return Ok(root);
                    }
                    tracing::warn!(
                        "State root verification failed: computed={verified:?}, \
                         expected={state_root:?}. Rebuilding from genesis."
                    );
                } else {
                    tracing::warn!(
                        "State root {:?} not found in trie store for block #{}. \
                         Rebuilding from genesis.",
                        state_root, header.number
                    );
                }
            }
        }
    }

    build_genesis_state(config, trie_store)
}

/// Build the genesis state trie from the chain config's alloc entries.
///
/// Each alloc entry becomes an account in the Unitrie. RSKj's mainnet
/// genesis only includes the Bridge balance (no storage). The genesis
/// header state root uses a pre-RSKIP126 format that doesn't match
/// our Unitrie hash, so we skip the comparison.
fn build_genesis_state(config: &ChainConfig, trie_store: &dyn TrieStore) -> Result<TrieNode> {
    let alloc = config.genesis_alloc();
    if alloc.is_empty() {
        return Ok(TrieNode::empty());
    }

    let mut root = TrieNode::empty();

    for entry in &alloc {
        let key_bytes = account_key(&entry.address);
        let key = TrieKeySlice::from_key(&key_bytes);
        let acct = AccountState::new(entry.nonce, entry.balance);
        root = root.put(&key, &acct.encode(), trie_store);
    }

    let computed = root.compute_hash(trie_store);
    info!("Genesis Unitrie hash: {computed:?}");

    root.save(trie_store, true);
    Ok(root)
}

fn setup_genesis(store: &BlockStore, config: &ChainConfig) -> Result<alloy_primitives::B256> {
    if let Some(genesis) = store.canonical_hash(0)? {
        return Ok(genesis);
    }

    let genesis = config.genesis_header();
    let hash = config.known_genesis_hash().unwrap_or_else(|| genesis.hash());

    store.put_header_with_hash(hash, &genesis)?;
    store.put_total_difficulty(hash, genesis.difficulty)?;
    store.put_canonical_hash(0, hash)?;
    store.set_head(hash)?;
    Ok(hash)
}
