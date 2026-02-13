# Rustock

A Rootstock (RSK) light client implementation in Rust.

## Features (Milestone 1)
- **P2P Networking**: Connects to the RSK network using the sub-protocol.
- **Node Discovery**: Implements Kademlia-based UDP discovery with RSK modifications.
- **Sync Mechanism**: Periodically requests and validates block headers from peers.
- **Consensus Validation**: Verifies Bitcoin Merged Mining proofs (AuxPow) and RSK consensus rules.
- **Storage**: Optimized RocksDB storage for headers and total difficulty tracking.

## Getting Started

### Prerequisites
- [Rust](https://rustup.rs/) (edition 2021)
- [RocksDB](https://rocksdb.org/) dependencies (usually handled by `rust-rocksdb`)

### Building
```bash
cargo build --workspace
```

### Running
To start a light client on the default RSK Regtest (network ID 33):
```bash
cargo run -p rustock-cli -- --port 30303 --data-dir ./data
```

To connect to a specific network:
```bash
cargo run -p rustock-cli -- --network-id 33 --port 30303
```

## Project Structure
- `crates/core`: Base types (Header, Block), consensus, and validation logic.
- `crates/storage`: RocksDB integration for persistsing blockchain data.
- `crates/networking`: P2P protocol, Discovery service, and session management.
- `crates/sync`: Synchronization logic and background services.
- `crates/cli`: Main entry point for the node.
