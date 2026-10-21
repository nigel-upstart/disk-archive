# Optional synthetic profiling

**Owner:** Maintainers · **Status:** In preparation; application integration pending G merge
**Last updated:** 2026-10-21 · **Links:** [issue 8](https://github.com/nigel-upstart/disk-archive/issues/8), [storage boundary](storage.md), [dependency admission](dependencies.md)

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

`task profile:trace`, `task profile:heap`, `task profile:console` and `task profile:cpu` are reserved
for the bounded synthetic driver using the actual application pipeline, native detector and
`SdkStore` injected with the localhost `MockS3`. Until that driver is integrated after G merges,
they fail clearly rather than substitute a toy workload. No end-to-end artifacts have been
produced yet. The launcher removes ambient AWS/application environment, uses a temporary HOME
and synthetic roots, and never reads a real dotenv or credential provider chain. Output is
private, non-overwriting, and under gitignored `profiles/`. Do not pass production roots or
credentials to the driver. Console binds only `127.0.0.1:6669` and uses a bounded synthetic run.

Application initialization belongs **after** its dry-run early return. Even a profiling-enabled
dry run must perform no explicit output/lock/state/listener creation. Selecting a Cargo feature
does not initialize a session. The heap-feature global allocator is linked in that binary, but
collection starts only when its explicit post-dry-run `HeapSession` guard is constructed.

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
regression remains pending integration after G releases ownership. This is not a bound on the
upstream exporter's channel, allocator overhead or total process RSS; the task corpus is bounded
separately.

DHAT normally records the process command line. Its pinned public memory-export method is used
to replace that field before writing JSON; no raw DHAT file is created. The wrapper deliberately
uses `ManuallyDrop` to avoid DHAT finishing twice after memory export, without unsafe code. This
API is documented upstream as testing-only and must be re-audited when upgrading; using it avoids
carrying a fork or persisting arbitrary command-line values. Console collects only Tokio/runtime
telemetry, not SDK body/auth events; do not name synthetic tasks with input-derived strings.

Exporter tests run the real libraries, assert valid JSON, plant a private marker in a future,
SDK event, first-party event and OS thread name, and confirm its absence. Artifact validation
also rejects the known synthetic corpus markers. These tests are not pipeline profiling evidence,
not proof of scanner recall and not a formal information-flow theorem. Final integration evidence,
all-feature CI/review and the separate independent R delta audit remain required before completion.
