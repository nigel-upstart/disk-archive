# Performance harness — implementation in progress

**Owner:** repository maintainer · **Status:** partial; private runs record-only
**Last updated:** 2026-10-24 · **Links:** issue #7, [temporary checkpoint](../plan/I.md)

## Measurements and corpus

The metrics foundation comes from actual merged main. A counter is an observation,
not a syscall tracer or an inferred zero. G owns actual snapshot/rewrite/spool
write-byte/lifetime instrumentation; I owns mock HTTP request/payload observation.
Until those adapters supply complete data, the harness must fail rather than report
unused byte/request/temp fields as measured zeros. The collector now consumes actual merged G/F source at `204034c3`, with no copied
development implementation or external path dependency. Actual Cargo validation
has passed the native pipeline with SQLite and the vetted SDK/local HTTP mock,
including independent verification of 89 archives and one unchanged blocked source.
Functional debug/coverage checks are not hosted release performance evidence.

The seeded generator produces 89 files / 7,029,003 bytes, capped at 8 MiB, with many
small records, near-1 MiB JSONL records, a 4 MiB multi-record file and synthetic
PEM/env plants. Revision `agent-jsonl-v2` puts spaces around GitHub plants so catalog
word boundaries remain valid. The independently generated manifest records offsets
and lengths, not findings. Existing directories are never overwritten. This is a
heuristic synthetic workload, not a production distribution. Known encoded secrets
must be safely removed or blocked/retained, never relabeled as throughput successes.

Criterion 0.8.2 and Gungraun 0.20.0 are exact development pins; plotting/Rayon defaults
are disabled. The core kernel calls real PlanBuilder/redaction and asserts actual replacements.
The new `components` feature registers the full 488-rule scanner over a fixed buffer
and a gzip/SHA256 primitive composition with the production library/settings. That
composition excludes storage admission, file I/O, CRC64 and SDK work; it is not full
UploadPreparer or E2E throughput. Native catalog setup/teardown is outside the scanner
measurement. Both harnesses use the same fixed buffers and explicit simulated cache
geometry. Both harnesses compile under strict all-target/all-feature Clippy. Native scanner
and gzip/hash functional controls pass under actual Cargo; real Criterion/Callgrind
measurements still require the hosted Linux job.
`task bench` runs Criterion; Callgrind belongs on Linux CI, not macOS arm64. No extra
release/profiling builds are required by default. Full hooks and review remain owed.

## Counter semantics

`process_spawns`, archive `bytes_uploaded` and normalized per-object `requests` are
semantic-exact counters, independent of hardware. Missing counters never become
zero. Process spawns must always be zero, including private/bootstrap runs. Payload
bytes must come from actual archive request bodies, including retry attempts, not
ExpectedUpload/header size guesses. Manifest/control bodies and wire framing have
separate advisory totals: variable operational metadata is not archive payload.

Request identities use independent corpus ordinals and semantic manifest chunk
indices, never completion order, upload IDs or manifest nonces. `counters.py` maps
observed object bindings one-to-one to stable `single|multipart/archive-N` and
`single/manifest-N` keys. Unknown requests, aliases and class contradictions fail;
normalization cannot discard an extra request.

The `transport` feature now provides a bounded outer HTTP proxy and compiles the
preserved AWS-chunk parser. It accepts only literal loopback HTTP destinations;
unknown routes and duplicate/aliased bindings cannot emit a result. Body fragments
are counted as actually received, with AWS chunk headers/trailers excluded from
payload bytes. `wire_body_bytes` counts HTTP body framing, not TCP/TLS/header bytes.
Connections, route maps, and parser buffers have fixed bounds. A complete report
requires the production store to drain, proxy tasks to join, and independent
bindings to cover every observed route. An interrupted/poisoned observation fails
rather than returning zero. Byte-sink HTTP tests validate this mechanism only.

The `sdk` feature wraps the vetted MockS3 and clones its fixed fake client config,
replacing only the endpoint. Actual Cargo single/retry/6 MiB incompressible multipart
and independent-download controls pass on merged G, including ordinary production
UploadPreparer counters. Earlier manually linked development receipts are historical,
not final evidence. The bounded E2E corpus produces single uploads; the separate
multipart functional control is not multipart E2E throughput evidence.

`collectors/pipeline.rs` now executes all 488 native rules, actual G bounded pipeline,
SQLite, source rewrite/delete, H preparation/SDK and the measuring proxy. It copies
only the bounded generated corpus into a new owned temporary directory. An explicit
encoded-secret fixture must remain byte-identical/Blocked with no upload intent.
Independent corpus offsets certify preserved bytes outside plants and valid redaction
markers inside them; actual downloads certify gzip/source hashes and native-clean
output. Manifest root/index/data contents, ordered digests and all-history rows are
checked independently before semantic chunk bindings are supplied to the observer.
No request-order identities or unknown/unverified objects can enter the receipt.

Fresh-process development runs verified 89 archives/deletions and one retained
encoded fixture. These are actual pipeline observations, not final merged/hosted
acceptance, a noise study or a baseline. The measured process includes fixture setup,
cold catalog initialization and independent verification; cold catalog initialization
is also reported separately. Do not call these warmed-pipeline-only timings. The
collector is registered behind the `pipeline` feature using workspace-relative
dependencies only, validated on actual merged G `204034c3`. It hashes its own
executable and rejects a supplied digest mismatch. No development source copy is used.
`audit.py` reuses G's canonical process parser and requires a real Linux fork/exec
canary plus zero process attempts for the exact measured binary; no macOS/skipped
success path. This audit has not been executed yet.

`peak_temp_bytes` remains in the report's historical `exact` bundle but is a
**resource high-water bound**, not semantic equality. It counts logical simultaneously
live bytes in invocation-created production snapshot/rewrite/staging/gzip temporaries,
not physical blocks, quota reservations, persistent SQLite/WAL/state, corpus/mock
fixtures or preexisting orphan spools. Its ceiling is the reviewed
baseline's `resource_ceilings.peak_temp_bytes`, or that baseline's recorded peak if
no separate envelope was approved. Lower peaks pass and never auto-tighten the
ceiling. A confirmation run may have a different peak within the envelope; a peak
above it still fails. Confirmation must preserve true semantic counters.

## Comparison and bootstrap safety

A statistical regression needs the seeded 95% bootstrap interval of the new median
entirely above the tolerance-adjusted old median, then one confirming rerun. The
comparison CLI exits **75** while confirmation is required, never success. Instruction
and cache regressions never rerun. Policy controls bounded bootstrap rounds and
minimum sample count. Tolerances remain provisional until the hosted noise study.

CPU/nproc mismatch makes statistical metrics explicitly advisory with `gated=false`;
the summary never claims they passed a gate. Compiler/LLVM/flags/profile/target,
Valgrind/Gungraun/cache configuration or rules/corpus/workload mismatch requires an
explicitly reviewed refresh and fails public checks. CI never raises or captures a baseline automatically.

Public runs with no baseline **fail**, including a PR that deletes one. The only
exception is `--first-public-bootstrap`: a hosted Linux, public-main manual dispatch
with explicit `first_public_bootstrap` input, clean measured HEAD equal to reviewed
`origin/main`, full Git history and no baseline JSON anywhere in main's history.
It remains record-only and writes no baseline. Private runs remain record-only;
hosted visibility comes from the event, so omitting `--public` cannot downgrade a
public PR. The initial committed baseline follows the history audit/publication,
with explicit review/approval, never a private-run ceiling.

`task bench:gate -- --current <report> --baseline <reviewed-baseline> --decision
<fresh-output>` compares collected metadata. `--summary` appends a status/gating
 table; input aliases/hard links and existing decision outputs are refused.
The draft `.github/workflows/perf.yml` runs on `ubuntu-24.04` with complete source
history. `bench/build.py` selects exact Cargo-emitted executables; `kernels.py`
collects real Callgrind output in an owned temporary directory and retains only
numeric events. `run.py` binds those receipts to the same clean source/toolchain
and binaries, requires the positive strace canary, then gathers ten fresh-process
pipeline resource samples. A timing regression triggers one new resource population;
deterministic kernels are never rerun. Only sanitized metadata is uploaded, not
corpora, archives, local build-path receipts, raw strace or Callgrind profiles.
Missing observations/public baselines fail closed; no workflow fallback weakens
public enforcement. Hosted PRs read ceilings from the immutable reviewed base tree,
never from a ceiling raised in their own diff. This workflow has NOT yet been hosted
executed. GitHub returns 403 for required branch checks on this private personal
repository without a paid upgrade/publication. Neither is authorized; required-check
activation therefore remains an explicit external blocker, not a passing claim.

Local explicit commands are `task bench:build -- --receipt target/perf-build.json`,
`task bench:kernels -- --build target/perf-build.json --output target/perf-kernels.json`
and `task bench:collect -- --build target/perf-build.json --kernels target/perf-kernels.json
--output target/perf`. Complete collection requires Linux, Valgrind and strace; macOS
can use the advisory comparison CLI, not a skipped-success full collection.

Actual merged-G Cargo validation has passed 160 Rust tests (zero skips), including
SDK/multipart and native controls, plus the normal and instrumented 89+1 collector.
All 73 Python controls pass; injected orchestration controls are NOT hosted noise
or genuine regression-injection evidence. Current instrumented coverage is 94.65%
(6,330/6,688 lines), with the collector included rather than excluded. The first full
check exposed an unsupported report-only CLI argument; that command was corrected
without changing the all-feature test stage, exclusions or 90% floor. A complete
passing rerun, full hooks/CI/review, real hosted Linux/Valgrind/resource runs,
required-check activation, baseline approval/ratchet wiring, ten unchanged-main
hosted noise runs and the throwaway regression PR remain pending.
Unit controls do not satisfy those acceptance criteria or close issue #7.
