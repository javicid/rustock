# Rustock Implementation Plan

This document outlines the step-by-step plan to implement a Rootstock (RSK) light client in Rust. The goal is to have a node capable of connecting to the RSK network, downloading block headers, and verifying them.

**NOTE:** This is a port from the Java Rootstock node under the rskj folder. 

## Current State
- **Core Types:** `Header`, `Block` structs matching RSK/rskj.
- **Networking (RLPx):** **Functional**. Full ECIES handshake (Initiator & Responder) and framing implemented. Supports P2P keep-alive.
- **RSK Protocol:** `RskMessage` protocol (Status, BlockHeaders) implemented with correct multiplexing.
- **Storage:** `BlockStore` using RocksDB.
- **Validation:** `HeaderVerifier` with **Merged Mining (AuxPow)** proof verification.
- **Discovery (UDP):** **Functional**. Connects to real RSK bootnodes.
- **Sequential Sync:** **Functional**. Syncs headers from best peer, persists state, and resumes on restart.

---

## Phase 1: MVP (Completed)
*Goal: A client that connects to peers, completes handshakes, and synchronously downloads/verifies headers from genesis to head with persistence.*

### 1. Networking Infrastructure (DONE)
- [x] Implement **RLPx/ECIES Transport layer** (Encryption & MAC).
- [x] Implement **P2P Handshake** (Hello/Disconnect/Ping/Pong).
- [x] Implement **RSK Sub-protocol Handshake** (Status negotiation).

### 2. Core Sync & Persistence (DONE)
- [x] Load network-specific genesis headers.
- [x] Persist discovered peers.
- [x] **Sync Progress Persistence**: Save and restore the current chain head (best block) across restarts.
- [x] **Basic Sequential Sync**: Wire the `SyncManager` to the `PeerSession` to download headers from the best peer and verify them sequentially.
- [x] **Genesis to Head Validation**: Ensure the client can sync from genesis and correctly verify the entire chain of headers.

---

## Phase 2: Refinement & Improvements (Pending)
*Goal: Optimize performance, reliability, and observability.*

### 3. Sync Logic Optimization
- [ ] **Parallel Header Downloading**: Request headers from multiple peers simultaneously.
- [ ] **Checkpoint Support**: Hardcode trusted recent block hashes to "snap" sync to the current state.
- [ ] **Snappy Compression**: Implement RLPx-level Snappy compression (useful for large block bodies/headers lists).

### 4. Peer & Resource Management
- [ ] **Peer Reputation Tracking**: Track "bad" peers (those sending invalid headers or timing out) and ban them.
- [ ] **Dynamic Connection Management**: Proactively maintain a target number of healthy peers.
- [ ] **Clean Shutdown**: Ensure DB handles are closed and peers are notified on exit.

### 5. API & Observability
- [ ] **Basic JSON-RPC**: Implement `eth_blockNumber` and `eth_getBlockByNumber`.
- [ ] **Dashboard**: Simple CLI or Web dashboard to monitor sync progress, peer count, and validation speed.

---

## Definition of Done & Wrap-up
After completing each implementation task, the following wrap-up subtasks **must** be performed:

1. **Pass all tests and fix all warnings**: Zero warnings in `cargo check`, zero failures in `cargo test`.
2. **Comprehensive Testing**: Ensure edge cases and happy paths are covered.
3. **Rustification & Refactoring**: Idiomatic Rust while maintaining `rskj` protocol compatibility. **Crucial** Do not break protocol compatibility with rskj.
4. **Final Verification**: Final automated check of all benchmarks/tests.
5. **Documentation**: Update code docs and this roadmap.
