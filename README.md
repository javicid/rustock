# Rustock

A Rootstock (RSK) full node implementation in Rust. Rustock syncs and validates blocks from the RSK network using Bitcoin merged mining proofs, executes every transaction against an RSK-compatible Unitrie world state, follows the chain tip in real time, and exposes an rskj-compatible JSON-RPC interface with full state, call, and log support.

> **Alpha software.** This project has been primarily coded by AI and has not yet undergone human code review or any security audit. Use at your own risk and do not rely on it for production workloads or anything involving real funds.

## Features

- **Full block sync**: Skeleton-based bulk header sync with parallel chunk downloads across multiple peers, followed by block body downloads and real-time tip following via `NewBlockHashes`.
- **EVM execution**: REVM-based block execution pipeline that reproduces RSK semantics — transaction validation, gas accounting, state transitions, receipt generation, and per-block REMASC reward distribution.
- **Unitrie world state**: A from-scratch implementation of RSK's Unitrie (radix-2 binary trie with shared paths and embedded values), including `eth_getProof`-friendly node access, key mapping for accounts/code/storage, and RocksDB-backed persistence with a write cache.
- **All RSK precompiles**: secp256k1 recovery, block header introspection, HD wallet utilities, the BTC–RSK Bridge (two-way peg, federation management, BTC SPV header chain, governance), and REMASC.
- **Consensus validation**: Full verification of Bitcoin merged mining (AuxPow) proofs, difficulty adjustment, gas limits, timestamps, and all RSK consensus rules including activation-height-gated RSKIPs.
- **Chain reorganization**: Detects competing forks, compares total difficulty, and rewrites canonical chain pointers when a heavier fork is found.
- **Transaction pool**: Validates pending transactions against the live state (nonce, balance, intrinsic gas, chain ID), tracks pending nonces per sender, and exposes status to the RPC layer.
- **P2P networking**: Full RLPx encryption (inbound and outbound), Kademlia-based UDP discovery, peer exchange, and persistent node tables.
- **Transaction relay**: Receives transaction messages from peers, validates and admits them to the pool, and rebroadcasts to all other connected peers.
- **Serving peers**: Responds to `BlockHeadersRequest`, `BlockHashRequest`, `SkeletonRequest`, and `BodyRequest` messages from other nodes.
- **JSON-RPC server**: rskj-compatible HTTP API with `eth`, `net`, `web3`, `rpc`, and `rsk` modules — including state queries, `eth_call` / `eth_estimateGas`, transaction and receipt lookups, log filtering, and persistent filters.
- **Storage**: RocksDB-backed persistence for headers, bodies, receipts, total difficulty, canonical chain mappings, and Unitrie nodes.

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (edition 2021)
- RocksDB system libraries (usually handled automatically by `rust-rocksdb`)

### Building

```bash
cargo build --workspace --release
```

### Running

Start the full node on RSK Mainnet (default):

```bash
cargo run -p rustock-cli --release -- --port 30303 --data-dir ./data --log-to-stdout
```

Logs are written to `<data-dir>/rustock.log` by default (with daily rotation). Use `--log-to-stdout` for console output.

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `30303` | P2P listen port |
| `--data-dir` | `./data` | Data directory for RocksDB and logs |
| `--network-id` | `30` | Network ID (`30` = mainnet, `31` = testnet, anything else = regtest) |
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

786 tests covering consensus validation, RLP encoding, P2P handshakes, sync state machines, storage, the Unitrie, EVM execution, every RSK precompile (including the full Bridge surface and REMASC), the transaction pool, RPC methods, transaction relay, and chain reorganizations.

## JSON-RPC API

The RPC server is compatible with rskj's JSON-RPC 2.0 interface. Supported methods:

**Chain and node info:**

- `eth_blockNumber`, `eth_chainId`, `eth_syncing`, `eth_protocolVersion`
- `eth_gasPrice`, `eth_mining`, `eth_hashrate`, `eth_accounts`, `eth_coinbase`
- `eth_getBlockByHash`, `eth_getBlockByNumber`
- `eth_getBlockTransactionCountByHash`, `eth_getBlockTransactionCountByNumber`
- `eth_getUncleCountByBlockHash`, `eth_getUncleCountByBlockNumber`
- `net_version`, `net_peerCount`, `net_listening`, `net_peerList`
- `web3_clientVersion`, `web3_sha3`
- `rpc_modules`
- `rsk_protocolVersion`, `rsk_getRawBlockHeaderByHash`, `rsk_getRawBlockHeaderByNumber`

**State queries** (served from the local Unitrie at any historical block):

- `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`

**Execution:**

- `eth_call`, `eth_estimateGas` (run against a forked state with full precompile and Bridge support)

**Transactions and receipts:**

- `eth_sendRawTransaction` (validates against the pool and broadcasts to peers)
- `eth_getTransactionByHash`, `eth_getTransactionByBlockHashAndIndex`, `eth_getTransactionByBlockNumberAndIndex`
- `eth_getTransactionReceipt`

**Logs and filters:**

- `eth_getLogs`
- `eth_newFilter`, `eth_newBlockFilter`, `eth_newPendingTransactionFilter`
- `eth_getFilterChanges`, `eth_getFilterLogs`, `eth_uninstallFilter`

**Pool:**

- `txpool_status`

**Unsupported** (returns error): mining (`eth_sendTransaction`, `eth_sign`, compilers), and the `debug_*`, `trace_*`, `personal_*`, `evm_*`, `mnr_*`, `db_*`, `sco_*` namespaces.

## Project Structure

```
crates/
  cli/          Main entry point, CLI argument parsing, genesis bootstrap
  core/         Base types (Header, Block, Transaction, Receipt), consensus rules, chain config
  trie/         RSK Unitrie: nodes, paths, account encoding, key mapping
  execution/    EVM executor, block processor, all RSK precompiles, BTC–RSK Bridge, REMASC
  storage/      RocksDB persistence for headers, bodies, receipts, and trie nodes (with write cache)
  networking/   P2P protocol (RLPx, discovery, sessions, peer management)
  sync/         Sync state machine, header + body pipeline, transaction pool, transaction relay
  rpc/          JSON-RPC HTTP server (axum-based) with state, call, log, and filter support
```

## Limitations and Future Work

Rustock executes blocks and maintains full state, but it is not yet feature-complete relative to rskj. Notable gaps:

- **No mining or block production.** Rustock validates and replays blocks produced by other nodes; it does not propose blocks, perform merged mining, or expose the mining JSON-RPC namespace.
- **No archive mode.** The trie store keeps every node it writes (so historical state is queryable as long as the underlying nodes have not been pruned), but there is no explicit archive-vs-pruning policy and no snap/state-sync support — initial sync executes every block from genesis.
- **Local-only Bridge methods are partial.** The 32 transaction-callable Bridge methods are implemented for consensus; many of the 37 local-only getters used by `eth_call` against the Bridge precompile are still being filled in.
- **No tracing or debug RPCs.** `debug_*` and `trace_*` are not implemented.
- **No wallet / account management.** `eth_sendTransaction`, `eth_sign`, and the `personal_*` namespace are intentionally not supported — sign transactions externally and submit them via `eth_sendRawTransaction`.

## License

MIT
