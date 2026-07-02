# Rustock sync speedups: pipelining & parallelism

This note describes the concurrency improvements rustock's forward (long) sync
makes over rskj, and sketches how each could be ported back to rskj. All code
references are to `crates/sync/src/service.rs` and `tracker.rs` unless noted.

The high-level shape is the same as rskj's skeleton sync: find a connection
point, pull a skeleton (every Nth header), download the in-between header
chunks, then download bodies and execute. The speedups are in *how much of that
runs at once*.

---

## 1. Multi-peer parallel header download

**rustock.** Header chunks are spread across *every* connected peer, with up to
`PIPELINE_DEPTH = 4` chunk requests in flight per peer (`tracker.rs`). A
`PeerChunkTracker` assigns chunks (`next_assignment`), records which peer holds
which chunk, buffers out-of-order responses, and drains them back into strict
order before they touch the store (`drain_ready`, `buffer_response`). Responses
are matched to chunks *by content* (`identify_chunk_by_content`), not by arrival
order, so reordering across peers is safe. `fill_pipeline` tops every peer up to
its capacity each round.

**rskj today.** `DownloadingHeadersSyncState` extends
`BaseSelectedPeerSyncState` and drives `ChunksDownloadHelper`, which requests
**one chunk at a time from a single selected peer** (`sendBlockHeadersRequest`
→ wait → `getNextChunk`). Header download is effectively serial and
single-peer; total throughput is bounded by one peer's latency.

**How to port.**
- Generalize `DownloadingHeadersSyncState` off `BaseSelectedPeerSyncState` to a
  multi-peer state (like `DownloadingBodiesSyncState` already is).
- Replace `ChunksDownloadHelper`'s single-cursor model with a tracker analogous
  to `PeerChunkTracker`: a `next_to_assign` cursor, a per-peer in-flight map
  capped at a configurable depth, a buffer keyed by chunk index, and a
  `drainReady()` that releases consecutive chunks in order.
- Match responses to chunks by the chunk's expected last-header hash (rskj
  already validates `chunk.get(0).getHash()` against the `ChunkDescriptor`),
  not by FIFO, so out-of-order peer replies can be accepted.
- `SyncEventsHandler.sendBlockHeadersRequest` already targets a `Peer`, so the
  wire layer needs no change — only the state machine that decides *who* gets
  *which* chunk and *how many at once*.

---

## 2. Overlapping skeleton pre-fetch

**rustock.** Once the last chunk of the current skeleton has been *assigned*
(not yet fully processed), `maybe_prefetch_skeleton` requests the *next*
skeleton from the connection point at the current skeleton's tail, stashing it
in `pending_next_skeleton`. The round boundary therefore doesn't cost a
skeleton round-trip — the next skeleton is usually already in hand when the
current chunks finish. The request is de-duplicated via `last_prefetch_start`.

**rskj today.** Skeleton requests are strictly sequential with the chunk
download they bound: a new skeleton is requested only after the previous round
fully completes, so every ~`maxSkeletonChunks * chunkSize` blocks the pipeline
pays a full skeleton RTT.

**How to port.**
- Add a `pendingNextSkeleton` slot to the headers sync state.
- When `chunksDownloadHelper.hasNextChunk()` becomes false but the round isn't
  complete, fire a `sendSkeletonRequest` for `lastSkeletonHeight` and hold the
  response.
- On round completion, if a pre-fetched skeleton is present, transition
  straight into it instead of issuing a fresh request.

---

## 3. Pipelined execution off the event loop (the big one)

**rustock.** Execution of a downloaded batch is moved onto a blocking thread
with `tokio::task::spawn_blocking` (`spawn_execution` →
`process_downloaded_blocks`), while the async event loop keeps downloading the
*next* batch. The depth is capped at "one executing, at most one downloading":

- `finish_batch` either spawns execution and immediately calls
  `continue_after_bodies` to start downloading N+1, or — if a batch is still
  executing — **parks** the finished batch in `pending_exec` and stops
  downloading (no N+2).
- `poll_execution` (run at the top of every `on_tick`) reaps a finished job,
  advances the committed state root / `exec_head`, then starts the parked batch
  and resumes downloading.
- Safety rests on disjoint key spaces: execution owns the trie/state; concurrent
  download only writes headers and bodies (independent column families) and
  network state, so they can't race. A lineage guard in
  `process_downloaded_blocks` halts rather than executing on the wrong parent.

This overlaps the two dominant costs of sync — network I/O (download) and CPU
(EVM + trie) — instead of alternating between them.

**rskj today.** In `DownloadingBodiesSyncState`, blocks are connected/executed
on the message-handling path as bodies arrive (`BlockSyncService` →
`NodeBlockProcessor`). Download and execution share the same thread of control,
so heavy execution back-pressures body downloading and vice versa. (rskj does
have `AsyncNodeBlockProcessor`, but it's for the relay/processing path, not a
download↔execute pipeline during long sync.)

**How to port.**
- Introduce a single-threaded executor (or reuse `AsyncNodeBlockProcessor`'s
  worker) that owns block *connection* during long sync. `DownloadingBodies`
  hands a completed, ordered batch to it via a bounded queue and continues
  requesting the next batch's bodies.
- Enforce the one-ahead cap with a queue of capacity 1 (or a permit/semaphore):
  the body state blocks on enqueue when the executor is busy and a batch is
  already parked — this is exactly rustock's `pending_exec` invariant.
- The executor advances the persisted `exec_head` and best-block on commit;
  body download advances only its own cursor. Keep them as two cursors, as
  rustock does (`last_body_height` for download vs `exec_head` for execution).
- Failure handling: on an execution error, reset the download cursor to the
  executed head and drop the parked batch (rustock's `halt_after_exec_failure`),
  mirroring rskj's "treat as invalid and stop."
- This requires storage writes from download and execution to be safe to
  interleave. rskj's block store (headers/bodies) and the trie/repository are
  already separate stores, so the same disjoint-key-space argument applies;
  verify no shared mutable cache is written by both paths.

---

## 4. Smarter body-request scheduling

rskj already parallelizes *bodies* across peers (`DownloadingBodiesSyncState`
with `chunksBySegment` / `chunksBeingDownloaded`). rustock's gains here are in
load-balancing and fast recovery, all of which are localized policy changes:

- **Least-loaded, responsiveness-weighted assignment** (`pick_body_peer`,
  `peer_body_load`): each body goes to the least-loaded peer that is under a
  per-peer cap (`MAX_BODY_REQUESTS_PER_PEER = 16`) and under a timeout-strike
  limit (`BODY_PEER_STRIKE_LIMIT = 8`), with graceful fallbacks so a request is
  still placed while any peer has capacity. Window size scales with peer count
  (`(peers.len() * 8).clamp(8, 96)`).
- **Fast reclaim** (`retry_stale_body_requests`, `BODY_RECLAIM_TIMEOUT = 12s`,
  shorter than the 30s request timeout): a body not back quickly is re-sent to a
  *different* responsive peer; the slow peer takes a strike and stops getting
  work once it crosses the limit.
- **Idempotent application by request id** (`id_index` in `on_body_response`):
  the old request id stays mapped after a retry, so a late duplicate still
  applies harmlessly and is never re-fetched. This is what makes aggressive
  reclaim pure upside.
- **Header-chunk stall handling** (`check_disconnected_peers`,
  `stalled_peers`, `sidelined`): a peer holding header chunks that goes silent
  for `PEER_STALL_TIMEOUT` has its chunks reassigned and is sidelined for
  `PEER_SIDELINE_DURATION`, so one dead-but-connected peer can't wedge an
  in-order round.

**How to port.** These map onto rskj's existing per-peer body bookkeeping plus
its peer-scoring system:
- Replace round-robin/segment assignment with a least-loaded pick over
  `chunksBeingDownloaded`, gated by a per-peer cap and by `PeerScoring`
  (peers with recent `TIMEOUT_MESSAGE` events are already penalized — reuse that
  as the "strike" signal).
- Add a sub-`timeoutWaitingRequest` reclaim timer that re-issues a stalled body
  to another peer; make `BodyResponseMessage` handling idempotent by keying
  in-flight state on the original block hash so a duplicate response is a no-op.
- Apply the same stall-reassign + temporary sideline to the (now multi-peer)
  header state from §1.

---

## Where each change lives

| rustock | rskj module to change |
|---|---|
| `PeerChunkTracker`, `fill_pipeline`, `identify_chunk_by_content` | `DownloadingHeadersSyncState`, `ChunksDownloadHelper`, `ChunkTask` |
| `maybe_prefetch_skeleton`, `pending_next_skeleton` | `DownloadingHeadersSyncState` + `DownloadingSkeletonSyncState` |
| `spawn_execution` / `poll_execution` / `finish_batch` / `pending_exec` | `DownloadingBodiesSyncState` + a connection executor (cf. `AsyncNodeBlockProcessor`), `BlockSyncService` |
| `pick_body_peer`, `retry_stale_body_requests`, `id_index`, `body_peer_strikes` | `DownloadingBodiesSyncState`, `PeersInformation`/`PeerScoring`, `SyncConfiguration` (new tunables) |
| timeouts/caps (`BODY_RECLAIM_TIMEOUT`, `MAX_BODY_REQUESTS_PER_PEER`, `PEER_STALL_TIMEOUT`, depths) | `SyncConfiguration` |

## Ordering / consensus note

None of these change *what* is executed or in *what order* — execution remains
strictly sequential and parent-linked (`process_downloaded_blocks` lineage
guard, `drain_ready` in-order release, follow-mode `follow_buffer`). They only
change what runs *concurrently with* execution. Any rskj port must preserve the
same invariant: download may be parallel and out of order, but block connection
must stay in canonical order on a single executor.
