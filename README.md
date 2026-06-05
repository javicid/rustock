# Rustock

> [!WARNING]
> ## ⚠️ Experimental AI-assisted prototype — DO NOT use in production
>
> Rustock is a **prototype** implemented in an **AI-assisted manner**. It should **never be used in production**. The code has **not been reviewed in depth** and has **not been security audited**. It **may — and will — break and contain bugs**.
>
> **Use at your own risk.**

A Rootstock (RSK) light client implementation in Rust. Rustock syncs and validates block headers from the RSK network using Bitcoin merged mining proofs, follows the chain tip in real time, and exposes an rskj-compatible JSON-RPC interface.

## Features

- **Header sync**: Skeleton-based bulk sync with parallel chunk downloads across multiple peers, followed by real-time tip following via `NewBlockHashes`.
- **Consensus validation**: Full verification of Bitcoin merged mining (AuxPow) proofs, difficulty adjustment, gas limits, timestamps, and all RSK consensus rules including activation-height-gated RSKIPs.
- **Chain reorganization**: Detects competing forks, compares total difficulty, and rewrites canonical chain pointers when a heavier fork is found.
- **P2P networking**: Full RLPx encryption (inbound and outbound), Kademlia-based UDP discovery, peer exchange, and persistent node tables.
- **Transaction relay**: Receives transaction messages from peers, deduplicates via an LRU cache, and rebroadcasts to all other connected peers.
- **Serving peers**: Responds to `BlockHeadersRequest`, `BlockHashRequest`, and `SkeletonRequest` messages from other nodes.
- **JSON-RPC server**: rskj-compatible HTTP API with `eth`, `net`, `web3`, `rpc`, and `rsk` modules.
- **Storage**: RocksDB-backed persistence for headers, total difficulty, and canonical chain mappings.

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (edition 2021)
- RocksDB system libraries (usually handled automatically by `rust-rocksdb`)

### Building

```bash
cargo build --workspace --release
```

### Running

Start the light client on RSK Mainnet (default):

```bash
cargo run -p rustock-cli --release -- --port 30303 --data-dir ./data --log-to-stdout
```

Logs are written to `<data-dir>/rustock.log` by default (with daily rotation). Use `--log-to-stdout` for console output.

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `30303` | P2P listen port |
| `--data-dir` | `./data` | Data directory for RocksDB and logs |
| `--network-id` | `30` | Network ID (`30` = mainnet, `31` = testnet) |
| `--secret-key` | auto-generated | Hex-encoded secp256k1 private key |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`, or RUST_LOG-style directives |
| `--log-to-stdout` | `false` | Log to console instead of file |
| `--rpc-port` | `4444` | JSON-RPC HTTP port |
| `--rpc-host` | `127.0.0.1` | JSON-RPC bind address |
| `--no-rpc` | `false` | Disable the JSON-RPC server |
| `--external-ip` | none | External IP to advertise in discovery (e.g. `203.0.113.42`) |

### Testing

```bash
cargo test --workspace
```

195 tests covering consensus validation, RLP encoding, P2P handshakes, sync state machines, storage, RPC methods, transaction relay, and chain reorganizations.

## JSON-RPC API

The RPC server is compatible with rskj's JSON-RPC 2.0 interface. Supported methods:

**Fully implemented** (using local header data):

- `eth_blockNumber`, `eth_chainId`, `eth_syncing`, `eth_protocolVersion`
- `eth_gasPrice`, `eth_mining`, `eth_hashrate`, `eth_accounts`, `eth_coinbase`
- `eth_getBlockByHash`, `eth_getBlockByNumber`
- `eth_getBlockTransactionCountByHash`, `eth_getBlockTransactionCountByNumber`
- `eth_getUncleCountByBlockHash`, `eth_getUncleCountByBlockNumber`
- `eth_sendRawTransaction` (broadcasts to connected peers)
- `net_version`, `net_peerCount`, `net_listening`, `net_peerList`
- `web3_clientVersion`, `web3_sha3`
- `rpc_modules`
- `rsk_protocolVersion`, `rsk_getRawBlockHeaderByHash`, `rsk_getRawBlockHeaderByNumber`

**Unsupported** (returns error -- requires state, bodies, or receipts not available in a header-only client):

- `eth_getBalance`, `eth_getStorageAt`, `eth_getCode`, `eth_getTransactionCount`
- `eth_call`, `eth_estimateGas`
- `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getLogs`
- `eth_newFilter`, `eth_getFilterChanges`, `eth_getFilterLogs`
- `debug_*`, `trace_*`, `personal_*`, `txpool_*`

## Project Structure

```
crates/
  cli/          Main entry point, CLI argument parsing
  core/         Base types (Header, Block, Transaction), consensus rules, chain config
  networking/   P2P protocol (RLPx, discovery, sessions, peer management)
  rpc/          JSON-RPC HTTP server (axum-based)
  storage/      RocksDB persistence for headers and chain state
  sync/         Sync state machine, header validation pipeline, transaction relay
```

## Limitations and Future Work

Rustock is a **header-only** light client. It validates and stores block headers but does not download block bodies, execute transactions, or maintain world state. This means:

- **No state queries**: Methods like `eth_getBalance`, `eth_call`, and `eth_getStorageAt` cannot be answered locally. These require Merkle state proofs verified against the header's `state_root`.
- **No receipt/log queries**: `eth_getTransactionReceipt` and `eth_getLogs` require receipt proofs verified against the header's `receipts_root`.
- **No transaction validation**: The node relays transactions without validating them (no nonce checking, gas estimation, or balance verification).

### What would be needed

Enabling state and receipt queries in a trustless way requires changes in **rskj** (the RSK full node):

1. **`eth_getProof` support**: rskj does not currently implement [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186) (`eth_getProof`), which provides Merkle Patricia trie proofs for account state and storage. RSK's Unitrie architecture would need an adapted proof format.

2. **LES-style P2P protocol**: There is no Light Ethereum Subprotocol (LES) equivalent in the RSK P2P protocol. A light client proof-serving protocol would allow requesting proofs over P2P instead of relying on trusted RPC endpoints.

3. **Receipt proofs via RPC** (partially available): rskj already exposes `rsk_getTransactionReceiptNodesByHash` which provides receipt trie nodes. This could be used to build receipt inclusion proofs, but requires an RPC connection to a trusted full node.

These limitations are inherent to RSK's current protocol design, not to this implementation. If rskj adds proof-serving capabilities in the future, Rustock can be extended to support trustless state and receipt verification.

## License

MIT
