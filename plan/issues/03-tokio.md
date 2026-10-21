<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/3 (synchronized during PR #9). The issue is the source of truth; git rm this file when #3 closes or if it drifts. -->

# #3: Adopt tokio and convert the staged pipeline to async

Part of #1. **Blocked by** #2. Merge the pipeline implementation after #6 and the shared `ObjectStore`/in-process S3 mock seam are available. That implementation merge unlocks dependent work in #4/#7/#8; keep this issue open until #7's record-only performance evidence and #8's profiling validation satisfy the final acceptance criteria. Dependent implementations must not wait for this issue to close.

## Scope

Move the staged pipeline (discover → scan → redact → verify → upload → delete) from threads plus blocking calls onto tokio, without losing backpressure, resumability or the delete-safety rule.

### Runtime
- tokio features: `rt-multi-thread`, `macros`, `fs`, `io-util`, `sync`, `signal`, `time`.
  - `process` is enabled only for the optional `trufflehog` cross-check module, behind a cargo feature.
- Explicit runtime builder:
  - worker threads from config, defaulting to available parallelism
  - `max_blocking_threads` bounded from config

### Stages
- Each stage reads from a bounded `tokio::sync::mpsc` channel whose capacity comes from config. Per-stage concurrency is limited by semaphore permits acquired before receiving or spawning work, or by a fixed worker count, so upstream stages block when downstream ones are full. A `JoinSet` may track tasks but is not a concurrency limit.
- Discovery walks the configured roots on the blocking pool (`walkdir`) and feeds the first channel.
- CPU-bound work (scanning, redaction, gzip, sha256) runs through a crate-level bounded `spawn_blocking` wrapper, never directly on runtime workers.
- Per-file errors are recorded in state and the pipeline keeps going, as in the legacy version.

### State (SQLite)
- `rusqlite` is synchronous. A **single writer task** owns the connection and receives updates over a channel.
- It writes in batches, one transaction per N updates or T milliseconds, with WAL mode on. This replaces the per-update mutex.
- Resume reads happen once at startup. Persist expected upload evidence (source identity, key, compressed length, checksum type/value and metadata) durably before starting upload; regenerate identical gzip bytes or retain the budgeted spool if needed. Before re-uploading on resume, HEAD the expected key and verify that evidence using #5's checksum semantics. A matching object is reconciled to durable `uploaded` state and freshly verified before delete authorization; only an absent or definitively mismatched object is uploaded. Transient HEAD failures are errors, not evidence of absence. Property tests cover cancellation after remote commit but before the local uploaded-state commit.

### Cancellation and shutdown
- Use a `tokio_util::sync::CancellationToken`, cancelled on SIGINT or SIGTERM. On cancel:
  - stop feeding new files
  - drain the in-flight work
  - flush the state writer
  - abort any in-flight multipart uploads
- No delete happens without a `VerifiedUpload` value, so this holds even if cancellation lands mid-stage.
- A lock file in the work directory prevents two archivers from running at once.

### Lints and rules (see #2)
- clippy `await_holding_lock`, `large_futures`, `unused_async`.
- ast-grep: no blocking `std::fs` or `std::thread::sleep` in `async fn` bodies, and `spawn_blocking` only through the wrapper.

## Acceptance criteria

- [ ] End-to-end tests on a seeded synthetic corpus pass against the in-process S3 mock: every file reaches the terminal state its fixture expects.
- [ ] **Cancellation test:** interrupting at random points and resuming gives no data loss, no double upload and no delete without a verified upload. Run it as a property test over cancellation points.
- [ ] **Backpressure test:** with a slow mock S3, memory and in-flight item counts stay within the configured bounds.
- [ ] A test asserts that the hot-path process-spawn counter is 0 (counter exposed in test builds).
- [ ] The profiling build shows no blocking on runtime workers on the benchmark corpus (tokio-console or runtime metrics; see #8).
- [ ] The perf gate records the new numbers; see #7.
