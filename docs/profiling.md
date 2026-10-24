# Optional synthetic profiling

**Owner:** Maintainers · **Status:** Application integration prepared; end-to-end validation pending
**Last updated:** 2026-10-24 · **Links:** [issue 8](https://github.com/nigel-upstart/disk-archive/issues/8), [storage boundary](storage.md), [dependency admission](dependencies.md)

Profiling is diagnostic, not a throughput baseline or production acceptance. The default build
has no Chrome exporter, subscriber, console or DHAT dependency and starts no profiling resources.
`python3 scripts/profile-default.py` checks the default normal dependency trees. `profiling` opts
into traces; `profiling-heap` and `profiling-console` are separate application features. There is
no default subprocess backend and no runtime call to an external sampling tool.

## Synthetic tasks

Explicitly install optional tools with `task doctor -- --profiling`. This loads only the separate
`mise.profiling.toml` tool set when requested. Linux additionally needs a compatible `perf` and
permission to sample the caller's process; tooling never silently changes host kernel settings.
The manual CI job may configure those permissions on its disposable runner.

`task profile:trace`, `task profile:heap`, `task profile:console` and `task profile:cpu` build
`crates/archiver/examples/profile-corpus.rs` and bind the exact executable from strict Cargo JSON.
The driver uses the actual 488-rule native catalog, bounded application pipeline and `SdkStore`
injected with localhost `MockS3` and fake credentials. Its independent corpus has 32 synthetic
JSONL files with planted tokens, not a throughput baseline or a substitute pipeline. It checks
terminal deletion rows, independently downloads/decompresses each archive, checks source and gzip
identities and rejects surviving tokens. Numeric `run.json` is written only after verification
and shutdown. End-to-end artifacts have not yet been validated for this source revision.

The launcher removes ambient AWS/application environment, uses a temporary HOME and synthetic
roots, and never reads a real dotenv or credential provider chain. Output is private,
non-overwriting, and under gitignored `profiles/`. Do not pass production roots or credentials
to the driver. Console binds only `127.0.0.1:6669`; its real gRPC observer writes only numeric
task/poll/drop counters to `console.json`, without serializing task fields. A manual-only workflow
runs all four modes on `ubuntu-24.04` with isolated compiler configurations and a 120-minute
cold-build budget. It uploads only validated artifacts and numeric run receipts, never raw perf
capture, corpus, archive, Cargo build paths or failed/partial profiles.

Application initialization occurs **after** its dry-run early return. Even a profiling-enabled
dry run must perform no explicit output/lock/state/listener creation. Selecting a Cargo feature
does not initialize a session. The heap-feature global allocator is linked in that binary, but
collection starts only when its explicit post-dry-run `HeapSession` guard is constructed.
The feature-build CI compiles the actual app/example without profiling a workload on PRs and
runs a Linux syscall audit of the all-feature CLI's inert dry-run, with a real write/listener
positive control. Each selected profiler must leave zero mutable-resource attempts.

Explicit CLI selections are `--profile-trace PATH` (`profiling`), `--profile-heap PATH`
(`profiling-heap`) and `--profile-console` (`profiling-console`, explicit `tokio_unstable`).
Only one selection is accepted. No profiling environment filter or automatic output directory
is used by the application. Dry-run parses these options but never initializes their resources.

## Reading artifacts

Open `trace.json` in Perfetto or `chrome://tracing`. Stage spans use fixed labels and opaque
numeric file ordinals, never paths, source bytes, finding values, configuration or credentials.
Async instrumentation uses `skip_all` and enters/exits at poll boundaries; time between polls is
not counted as continuous CPU work. Compare stage overlap and long polls rather than treating
span duration as an instruction count. Flush with `Session::finish` so budget/output errors are
observable before declaring the artifact complete.

Open `heap.json` in DHAT's `dh_view.html` to inspect allocation sites, peak live allocation and
retained allocations. DHAT reports allocated memory, not operating-system RSS. CPU profiles use
`samply` on macOS (open the Firefox profiler JSON with samply) or `perf` plus flamegraph on Linux
(open `cpu.svg` locally). These caller-side tools can require OS permissions and add overhead;
they are never invoked by the archiver hot path. Linux CPU builds force Rust frame pointers and
sample user-space CPU-clock at 199 Hz with frame-pointer call chains, rather than persisting raw
DWARF stack-memory dumps. Native libraries without frame pointers may truncate those call chains;
this is a diagnostic tradeoff, not a complete native instruction profile. Attach
`tokio-console http://127.0.0.1:6669`
during `task profile:console` to inspect task polls and resource waits. Console fails with a
static error unless the build explicitly sets `RUSTFLAGS="--cfg tokio_unstable"`; its Task does so.

Artifacts can still contain compiler symbols and build-source locations. Treat them as sensitive
operational data, inspect them before sharing, and retain them only in the private repository's
short-lived manual CI artifacts. Profiling is not permission to publish repository history.

## Privacy and trust boundary

The Chrome subscriber accepts only fixed stage spans on the dedicated
`disk_archive_profiling::safe_stage` target, populated by the static `Stage`/`u64` helpers with
`skip_all`. It ignores `RUST_LOG`, all other first-party namespaces, SDK targets, events and broad
TRACE filters. Upstream tracing-chrome records OS thread names even
when argument capture is disabled, so raw exporter JSON remains in memory until an allowlist
rebuild replaces thread names, removes locations/unknown fields and retains only fixed stage
labels and numeric ordinals. Raw exporter metadata is never an intermediate disk artifact. The
raw buffer has a 16 MiB cap; overflow fails export closed. Pinned tracing-chrome 0.7.2 unwraps
writer errors in its background thread, so its in-memory sink always acknowledges writes/flushes,
including cap overflow or a poisoned buffer. `finish()` rejects poisoned, truncated or malformed
captures with a static error before writing any artifact bytes. It never treats partial raw JSON
as a complete trace. Final output write/flush failures also return a static error, not an unwind;
an empty or partially written sanitized file is **not** a successful artifact. The Task must fail,
and the manual workflow uploads only after a successful run and format validation.

Call `finish()` only after the owned pipeline and detached cleanup have drained, not through an
early `?` while source/root ownership is still needed. Capture failures do not propagate through
instrumented work. Unit fault injection covers actual Chrome cap overflow, partial capture,
zero/partial output writes and flush errors. The application-level detached-work/guard ordering
regressions cover initialization failure and dropping the caller during an in-flight upload;
the profiler is owned by the shielded pipeline, not its cancellable waiter. A callback budget
also stops admission after 65,536 upstream enter/exit callbacks, bounding total input to the
pinned exporter's unbounded channel. This is not a bound on allocator overhead or total process
RSS; the task corpus and pipeline queues are bounded separately.

DHAT normally records the process command line. Its pinned public memory-export method is used
to replace that field before writing JSON; no raw DHAT file is created. The wrapper deliberately
uses `ManuallyDrop` to avoid DHAT finishing twice after memory export, without unsafe code. This
API is documented upstream as testing-only and must be re-audited when upgrading; using it avoids
carrying a fork or persisting arbitrary command-line values. Console collects only an exact allowlist of pinned Tokio runtime targets,
not arbitrary namespace prefixes or SDK body/auth events; do not name tasks with input-derived
strings. The numeric gRPC receipt drops task names, fields, locations and raw protobuf.

Exporter tests run the real libraries, assert valid JSON, plant a private marker in a future,
SDK event, first-party event and OS thread name, and confirm its absence. Artifact validation
also rejects the known synthetic corpus markers. These tests are not pipeline profiling evidence,
not proof of scanner recall and not a formal information-flow theorem. Final integration evidence,
all-feature CI/review and the separate independent R delta audit remain required before completion.
