<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/8 (synchronized during PR #9). The issue is the source of truth; git rm this file when #8 closes or if it drifts. -->

# #8: Optional profiling build (cargo feature `profiling`)

Part of #1. **Blocked by** #2. Profiling the pipeline starts after #3's implementation merges and the production S3 integration is available, not after #3 closes. This issue provides evidence for #3's final profiling acceptance, so issue closure cannot be its prerequisite.

## Scope

An **optional** profiling build for finding why throughput changed. It is off by default, never included in release artifacts, and never a dependency of the default build.

### Cargo feature `profiling`
- **Traces:** `tracing` spans per stage and per file, exported with `tracing-chrome` (view in Perfetto or `chrome://tracing`).
  - Span fields hold no file content, no finding values and no raw secrets (ast-grep rule).
  - Paths can optionally be hashed.
- **tokio-console:** via `console-subscriber`, which needs `RUSTFLAGS="--cfg tokio_unstable"` (the Task target sets it). Shows task poll times, busy workers and blocking on runtime threads.
- **Heap:** `dhat` replaces the global allocator under the feature, giving an allocation profile on the benchmark corpus.

### Task targets (quiet wrapper, outputs in gitignored `profiles/`)
- `task profile:cpu`: `samply` on macOS, `perf` plus `cargo flamegraph` on Linux.
- `task profile:trace`: Chrome trace JSON.
- `task profile:heap`: dhat JSON.
- `task profile:console`: runs with console-subscriber and prints how to attach.
- Profiling tools are installed through mise only when requested (`task doctor -- --profiling`), so the default setup stays lean.

### CI
- A build check for `--features profiling` so the feature doesn't rot. No profiling runs on PRs.
- An optional `workflow_dispatch` job profiles the benchmark corpus on the same fixed-size runner as the perf gate and uploads flamegraph and trace artifacts.

## Acceptance criteria

- [ ] Each `task profile:*` target produces its artifact on the synthetic benchmark corpus.
- [ ] `cargo tree -e features` (or an equivalent check) shows the default build pulls in no profiling crates.
- [ ] A test asserts that trace output from a corpus with planted secrets contains no secret bytes.
- [ ] The README has a short section on reading each artifact.
