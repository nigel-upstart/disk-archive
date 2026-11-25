# Async shell and embedding contract

**Owner:** Maintainers · **Status:** Implementation contract · **Updated:** 2026-10-21
**Links:** [design](../../docs/design.md), [issue 3](https://github.com/nigel-upstart/disk-archive/issues/3)

## Execution and ownership

The CLI selects metadata-only `--dry-run` before building a runtime, scanner, credential
provider, work directory, lock, database or temporary file. It reports eligibility and leaves
redaction/verification explicitly unknown. Individual I/O failures or overlong keys are counted
as retained entries/subtrees while other entries continue; this is not a fabricated census of
unreadable files. Global depth, identity and byte caps still fail closed, never silently truncate.
`--env-file`, `--limit` and `--workers` are strict;
unknown, duplicated or malformed options fail without printing operational values.

Mutable runs require `--quiescent`. Every writer must honor exclusive advisory locks on the
configured root directories, including writes through already-open descriptors and descendant
paths. Roots cannot overlap each other or the work directory. Roots, descendant parents and
sources must belong to the effective user and exclude group/world writes. Every path component
is opened without following symlinks; source files must have exactly one link. These restrictions
and final hash/stat comparisons do **not** make unlink atomic against an uncooperative writer.
Without the cooperative protocol, use dry-run or retain files outside the mutable pipeline.

The private work directory has a versioned format marker and a persistent process-lock file.
A nonempty unmarked directory is rejected before opening any database; no automatic adoption
or migration of legacy runtime state exists. Configuration remains in the gitignored dotenv
file; the CLI has no personal source/work/destination defaults.

## Bounds and durable ordering

Four bounded channels connect discovery, combined scan/redact/whole-output verification,
preparation, upload/HEAD and deletion. Resume HEAD/readmission runs in preparation, never in an
upload consumer that could wait on disk held by its own prepared queue. Each processing stage has a fixed worker population;
there is no task per discovered file. CPU permits are acquired before spawning and owned by
the actual blocking closures. Discovery and SQLite have separate bounded blocking slots so
a full discovery channel cannot monopolize the last CPU permit. The CLI reserves at least
`cpu_jobs + 2` blocking threads. `--queue-capacity` bounds each channel. Worker concurrency
uses configured `WORKERS` or `--workers`, defaulting to available parallelism (at most 256,
fallback 1).

The CLI limits each original/rewrite to 64 MiB. Core and scanner line/finding/work limits also
apply; a partial scan/output never authorizes upload. The native scanner's `UnsupportedEncoding`
also maps to persisted `Blocked`: supported recoverable encoded carriers never reach archive
PUTs unchanged. Bounded JSON/percent provenance can admit a literal secret beside unrelated
escapes only when the unchanged sensitive bytes map to the same actual raw native secret
capture, under a newline-restart-safe rule with non-artificial match boundaries. Normal
redaction and whole-output verification still apply, including the whole-line fallback if a
redaction marker itself matches URI syntax. Encoded copies, changed sensitive bytes, opaque
decoding and ambiguous source proofs still block; general encoded-offset redaction remains
[issue 18](https://github.com/nigel-upstart/disk-archive/issues/18).
The real 488-rule/HTTP test covers JSON Unicode, percent, base64, UTF-16LE/BE,
base64-of-UTF16, and literal-plus-encoded mixtures, preserving every original byte. Anonymous snapshot/output files consume
at most two file-size budgets per executing scan worker. Storage separately bounds gzip spool
reservations and transport buffers. These are logical quotas, not a total RSS guarantee.
A final rewrite uses a reserved `.disk-archive-` temporary basename and atomic rename, restoring
original mtime/atime before replacement. Later normal content reads can advance atime; ctime
necessarily changes and is bound into the new source identity. Discovery skips reserved names.

One WAL writer batches state with FULL-synchronous transactions. Its durable acknowledgement
precedes every remote upload. Rows contain detector names/counts and bounded expected evidence,
never matched values. Paths use lossless hex; expected JSON is embedded as JSON rather than an
array of byte numbers. Legacy array-encoded metadata remains readable. Each encoded row must fit
one store payload before its upload-intent commit can be acknowledged.

Startup map construction stays on the SQLite blocking lane, capped at 64 MiB/100,000 outstanding
upload-intent rows. Deleted tombstones and all rows with an explicit null expectation are excluded
from that map and queried by indexed selected key on demand. Thus externally pruned Blocked/Error/
Skipped history cannot exhaust the pending-work cap. No-intent rows retain their original status
and remain in manifests; absence never becomes a false claim of verified upload or deletion.
Reappearing no-intent sources can be scanned again. Indexed keys must equal record keys.
Deleted records are immutable even if a caller bypasses discovery; reappearing generations
remain unchanged and increment `namespace_conflicts` instead of rewriting Deleted to Error.
Discovery retains at most 100,000 deduplicated key/identity pairs and 64 MiB of key bytes.
Caps fail closed, never silently truncate. These serialized-byte/cardinality limits are not RSS
measurements, and the pending-work cap is not a lifetime archive limit.
An outstanding intent outside the currently selected roots is counted as retained without
changing its row, reading/unlinking that source, or blocking unrelated roots. Bucket/key namespace
mismatches still fail the run. A matching resumed object requires fresh checksum-enabled HEAD
and a fresh kernel token. Only genuine `NotFound` or definitive integrity mismatch permits another upload attempt;
transport failures retain the intent. Source changes also retain intent and never reuse its
capability. Keys encode the full root-qualified absolute path without its initial slash,
preserving dots and distinguishing roots. Write-once keys deliberately retain a new generation
at an already-used path; rotate to a disjoint namespace rather than overwrite old evidence.
G does not persist post-upload version/ETag receipt selectors. Restart HEAD verifies the latest
object afresh against expected checksums under write-once `If-None-Match` and exclusive remote
namespace ownership (no competing overwrites/deletes). It does not claim pinned-version restart
verification; real-S3 conditional-write acceptance remains in storage's external acceptance work.

## Verification boundary

Only the dependency-free synchronous kernels are proved with the separately pinned Verus
compiler. Storage projects independently parsed HEAD facts into the kernel; it does not echo
expected fields as remote evidence. The shell still trusts the tested scanner, gzip/checksum and
SDK adapters, filesystem/OS behavior and cooperative source/remote namespace assumptions.
Persisted rows, manifests and matching path strings cannot mint a deletion capability. A fresh
verified upload token plus a fresh descriptor/path identity check is required at the only unlink
stage. Neither these proofs nor passing integration tests prove the entire async shell.

## All-history manifest protocol

Every normal run streams the complete state history into independent JSON-array data pages,
each at most the actual store's 1 MiB payload limit including delimiters. This preserves the legacy
all-history manifest contract: PUT bytes per run are O(lifetime history), and retained manifest
storage is O(runs × history) for repeated similarly sized histories. Paging bounds memory and
individual payloads, not total traffic or storage. Incremental manifests are deferred; I/J must
include history size in performance observations rather than claim constant-cost runs.
At most 512 data-part
descriptors are buffered in an index page. Consecutive data/index ordinals are unsigned 64-bit
counts, not an all-history vector or a lifetime row-count ceiling.

The final root is `disk-archive-manifest-v2`, with `rows`, `data_parts`, `index_pages`, and
`index_chain_sha256`. For root key `K`, data objects are
`K.parts/part-<20-digit zero-based ordinal>.json`; index objects are
`K.parts/index-<20-digit zero-based ordinal>.json`. Index format `disk-archive-index-v1` contains
part names, row counts and SHA-256 byte arrays. The root's ordered index digest hashes each
index's u64 big-endian byte length followed by its exact JSON bytes. Consumers verify the index
chain, then each referenced data digest and row count to reconstruct the full snapshot.

The small root is published LAST, only after every page succeeds. Earlier failures leave
uncommitted pages without initiating a root. The final root request itself can have an unknown
remote commit outcome on cancellation/response loss. Neither pages nor roots grant deletion authority.
Metadata encoding/hashing stays on the writer/CPU lanes. Keys reserve suffix/ordinal space before
source mutation. The real SDK/HTTP regression streams 600 rows across multiple data/index pages
and independently downloads/checks every page, rather than weakening the mock's payload cap.

## Shutdown, recovery and benchmarks

Signal cancellation stops discovery, drains workers/CPU jobs and storage abort cleanup, and
flushes SQLite before releasing ownership. Dropping a library waiter cancels a shielded owner
task rather than releasing its locks early; the executor must remain alive for graceful cleanup.
Process/runtime destruction is a crash. Resume reconciles both remote/local upload commit gaps
and an already-absent source after unlink/local-state commit failure, without unlinking a newly
appearing replacement. A terminal manifest is initiated only after normal completion with no
observed cancellation. Cancellation during an in-flight manifest request can have an unknown
remote commit outcome; manifests never grant deletion authority.

`pipeline::{run, Options, Services, Report}` is the embedding/performance seam. `ScanEngine`
provides object-safe borrowed findings; its gateway checks complete EOF, byte/finding counts
and callback poisoning. The CLI always supplies the native scanner. A benchmark-only alternative
must meet the same scan contract; scanner-only comparisons are not full legacy E2E equivalence.
A `Services` store is one-shot: construct a new SDK store for each run; draining permanently
closes its upload admission tracker. The shared counters outlive all worker/store cleanup.
`run` binds the same `Arc<Counters>` to scan temporaries and `UploadPreparer::with_counters`.
Anonymous snapshots, rewrite/fallback outputs, named rename staging, and gzip spools count
actual successful append bytes, including partial writes before errors. Leases overlap across
stages and survive retained descriptors, detached work, and SDK payload owners; rename staging
stops being temporary when promoted to the source inode. Cleanup failure poisons the observation
rather than emitting a plausible zero. Poisoning also denies subsequent append I/O for that run:
continuing after unconfirmed cleanup could accumulate unobserved temporary files beyond the
accounted bound. Later files are retained, and the completed run returns a static error; earlier
verified uploads/deletions remain durable, not rolled back. This is intentional fail-closed
resource behavior, not a performance optimization. The exact synthetic rewrite peak and retained-spool,
changed-source, cancellation, and cleanup-failure tests exercise these production paths.

`peak_temp_bytes` measures the maximum simultaneously live **logical bytes in invocation-created
temporary files**, not physical filesystem blocks, rounded disk reservations, RSS, SQLite state,
or preexisting crash spools. Existing spools are separately quota-accounted before processing.
Use a fresh synthetic work root for comparable end-to-end measurements; this counter is not an
environment disk-footprint audit. Transport request/payload counters must be observed by the
HTTP fixture, never inferred from input sizes, compressed lengths, or this temporary-byte peak.
These operation counters require no profiling crate, tracing subscriber, listener, or output file.

Explicit gateway counters have a positive increment canary. They do not replace an OS audit:
`tests/audit_processes.py --binary <pipeline-test-binary>` runs the actual synthetic native/HTTP
test under Linux strace, excludes thread clones and the initial harness exec, and rejects any
other process attempt. A separate real fork-plus-exec canary must observe two process attempts
before the hot-path trace is accepted. `--self-test` validates the parser. No unsupported-platform skipped pass
exists. Exact S3 request counts belong to the actual HTTP mock, not the unit store model.

Registry admission: Tokio/Tokio-util provide scheduling and cancellation; rusqlite uses only
bundled native SQLite (no extensions/default WASM backend); rustix supplies safe descriptor-relative
filesystem calls; walkdir supplies bounded-handle traversal; SHA-256, serde and tempfile provide
bounded evidence/state/private staging. Git scanner/transfer-manager dependencies remain owned
and admitted by their respective crates. The dependency-free verified crate is unchanged.
