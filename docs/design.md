# Archiver design and safety boundary

**Owner:** Maintainers · **Status:** Accepted direction; reference APIs, not production implementation
**Last updated:** 2026-10-21 · **Links:** [decisions](adr/001-rust-and-verus.md), [dependency policy](dependencies.md)

## Scope and architecture

The archiver moves old session logs through discovery, secret scanning, redaction, verification,
gzip upload, remote verification, and local deletion. The Rust port preserves the sanitized
Python reference's observable behavior except for deliberate safety changes: injective S3 keys,
change-nothing dry-run, fail-closed verification, and source-bound delete authority. No stage
operates against production roots during development. Real S3 smoke tests require a separate
approval and synthetic inputs. The repository remains private until a full-history audit; this
document is not authorization to publish it.

The synchronous, dependency-free `disk-archive-verified` crate contains reference functions for
age comparison, key encoding, literal needle replacement, PEM state, lifecycle transitions, and
upload/delete capabilities. They are **unproved reference implementations** in wave one. The
separate `proofs/feasibility.rs` establishes that the pinned verifier works; it does not prove the
reference crate or the entire archiver. Wave two replaces or annotates the actual kernels with
specifications and proofs. A disconnected proof of a similar algorithm cannot satisfy that work.

`crates/core` owns configuration, scanner adapters, finding lifetime management, and the streaming
redactor. `crates/archiver` owns CLI, Tokio scheduling, filesystem adapters, SQLite, and the S3
`ObjectStore` implementation. Kernel inputs are explicit values rather than environment, clocks,
paths opened internally, or SDK responses. This makes the proof boundary small and testable.
The async shell remains trusted for accurate evidence, I/O ordering, and resource confinement.

## Configuration and change-nothing dry-run

Application settings use only `DISK_ARCHIVE_*`, loaded in order from explicit `--env-file`, the
XDG configuration location, then the working-directory `.env`. Selecting a file does not create
it. The later config implementation must specify how already-set environment values override
file values, reject malformed settings, and refuse missing bucket or prefix. Neither destination
has a default. AWS credentials and TLS trust use explicitly approved SDK provider configuration;
they are not application settings. Never enable `credentials-process`, including through
transitive feature unification. No production bucket, profile, account ID, or source root is
embedded in code, examples, fixtures, or defaults.

Dry-run is a separate read-only execution path, selected **before** constructing mutable
resources. It does not open/create SQLite, make a work directory, take/create a lock, write logs
to disk, create temporary files, redact, upload, update state, or delete. It can inspect metadata
and report eligibility and planned operations to the caller's existing output stream. It does
not instantiate an AWS client or credential chain. Reading a file can affect filesystem atime,
so strict change-nothing dry-run performs metadata-only discovery and does not scan file content.
It reports that redaction and verification outcomes are unknown rather than pretending they ran.
Tests compare the directory tree, contents, mtimes, database absence, work/lock absence, and mock
network calls before and after dry-run. A separate read-only content-inspection command is not
part of this contract. See [ADR 004](adr/004-dry-run.md).

## Discovery and source ownership

Discover all regular files directly in configured all-file roots, plus recursive `*.jsonl` files
in JSONL roots. Reject symlinks, duplicate identities, and paths outside the selected root. The
shell uses no-follow opens and compares opened-file metadata with discovery metadata; it repeats
the age check before scanning. `age::is_older_than` compares normalized Unix timestamps using i128
nanosecond arithmetic. Cutoff equality, future mtimes, and invalid nanoseconds fail closed. The
adapter computes days-to-seconds with checked arithmetic before calling the kernel.

Files may be replaced or mutated after discovery. Discovery path, inode, mtime, or restored
mtime alone cannot establish content identity. `SourceIdentity` binds device, inode, size, mtime,
ctime, and SHA-256 of the post-redaction bytes. Scan and gzip operate on a stable snapshot of
those bytes, not two independently reopened paths. A changed source is rediscovered, never
silently deleted because an older snapshot was uploaded. Exclude archiver-owned temporary files
from discovery; retain original timestamps when an atomic redaction replacement succeeds.

There is no portable atomic "unlink only if path still names this inode" syscall. A final
lstat/hash followed by unlink still has a race against an uncooperative writer. Therefore the
production delete adapter must enforce a source/path ownership protocol for quiescent roots,
including an exclusive namespace guard held from final identity validation through unlink.
An archiver lock excludes another archiver but not arbitrary writers. Roots without enforceable
ownership cannot support automatic deletion; fail closed or retain local files. Wave three must
implement and test this adapter obligation before enabling deletion. The kernel proves only
identity/evidence comparisons, not filesystem race freedom or hash collision resistance.

## Bounded execution and cancellation

Use separate limits for discovered paths, active files, scanner work, compression, upload parts,
and pending database messages. Acquire a permit **before** spawning CPU/blocking work, and keep
it owned by the blocking closure until work really ends; cancelling a JoinHandle does not stop
`spawn_blocking`. `JoinSet` tracks tasks but does not impose a bound. A single SQLite writer
serializes durable updates through a bounded channel. Discovery pauses when downstream is full.

Per-file byte, line, finding, and needle budgets are explicit configuration with conservative
limits. An overlong line, memory budget exhaustion, scan interruption, or partial result blocks
that file instead of accepting an incomplete scan. Scanner callbacks feed a bounded accumulator;
production must not collect a whole file's unbounded findings. The Kingfisher high-level vector
API used by the standalone feasibility check is not the final bounded production adapter.
Cross-chunk and multiline matching semantics must be established before streaming integration;
a fixed overlap is not a general solution for unbounded regex matches.

Cancellation stops discovery, waits for CPU workers that still own permits, aborts outstanding
multipart uploads, and flushes terminal/retriable status updates before closing the state writer.
It never advances to deletion on a cancelled, unknown, or partially verified upload. Later-run
reconciliation handles an upload that completed remotely before cancellation became observable.

## Scanning and redaction contract

Prefer the focused Kingfisher library at an immutable git revision, not the CLI and not live
provider validation. The native source-build/API spike is isolated under `spikes/kingfisher`.
It uses synthetic data, compiles custom and embedded rules, and disables validator features.
Adoption still requires bounded output, no-network, cancellation, planted-corpus parity, benign
false-positive checks, and finding-lifetime tests. [ADR 005](adr/005-scanner.md) records those
criteria; native build complexity alone is not grounds to abandon the preferred library.

`needles::FindingRaw` borrows UTF-8 strings. Submit raw and raw-v2 as separate entries, preserving
finding order. The reference ignores values shorter than six Unicode scalar values, builds raw
and Python-style JSON-escaped forms, includes sufficiently long multiline pieces (12 scalars),
preserves the first label for duplicate needles, and uses stable longest-byte-first ordering.
Only safe detector identifiers can enter replacement markers. Production calls
`replace_all_bounded(line, needles, max_bytes)`, which checks the input copy and every extension
before allocation, including intermediate marker amplification. Budget failure blocks the file;
it never returns partial successful output. The budget is per logical buffer, not a resident-memory
claim: old/new buffers coexist and allocators add overhead. The unbounded API is reference/test
only. Sequential replacements preserve legacy behavior, including replacement markers which can themselves match another needle.
Never log finding values, captures, input lines, needles, or secret-bearing error messages.

For each line, first resume any active PEM block, then apply literal replacements. Core replaces
inline private-key spans with the legacy marker (the inline gap is at most 20,000 bytes and does
not cross LF), applies unmatched BEGIN handling using `pem::begin`, and processes the legacy
environment-assignment pattern. `PemState` retains multiline state and discards content through
the first END. Inline matching and environment assignment regexes belong to core, not the pure
state primitive. Use the sanitized Python goldens for ordering and boundary parity.

Run `guard_line` **after every other transformation**. If a supplied literal needle remains,
drop the line; emit the line marker only if that marker is also safe, otherwise emit empty
bytes. Even newline could be part of a needle, so newline is not an unconditional safe fallback.
The future postcondition is per-line: no supplied literal occurs in the emitted line. Joining
lines can create a cross-boundary needle, and the supplied set does not cover undiscovered
secrets. The mandatory whole-output detector re-scan therefore remains part of acceptance. On
remaining findings, drop offending lines and re-scan once more; anything still detected is
`blocked`, never uploaded or deleted. Empty/truncated/error scans cannot masquerade as clean.

Secret ownership belongs to the adapter: short-lived values, zeroizing buffers where supported,
no serialization of raw findings, and explicit review of upstream copies. The reference kernel attempts ordinary `fill(0)` on owned NeedleSet fields and bounded-replacement
intermediate buffers when dropped, but the compiler may erase those writes. This does not wipe
spare capacity, construction temporaries, allocator copies or borrowed inputs, and is not a formal
or allocator-level zeroization guarantee. Full graph lifetime tests
and bounded-memory instrumentation remain wave-two scanner work, not claims from the spike.

## Upload evidence, state, and deletion

Use `aws-sdk-s3`, `aws-config`, and the pinned git transfer manager behind `ObjectStore`; no CLI
subprocess backend. Compression and hashing are bounded CPU work. The adapter computes exact
original and gzip sizes/hashes from the same snapshot. Upload SSE AES256 and the expected
original-size/original-hash/gzip-hash metadata. Persist expected evidence and destination before
upload begins so a crash after remote commit but before local state commit is reconcilable.

HEAD must match configured bucket/key, gzip Content-Length, original metadata, and encryption.
Metadata echoing a claimed SHA-256 is not independent remote content verification. Multipart
SHA256 COMPOSITE is not SHA-256 of concatenated gzip bytes. The store adapter must validate the
appropriate full-object checksum (for example CRC64NVME against locally computed bytes), or
read back and hash the object, before supplying whole-gzip `gz_sha256` evidence. ETag is never
used as a content hash. Versioning/conditional operations must keep verification bound to the
object that was uploaded; do not race another writer in the same key namespace.

`verify_upload` checks explicit expected and observed fields and constructs a private,
non-cloneable `VerifiedUpload`. `authorize_delete` consumes it and compares a freshly computed
source identity, producing a private `DeletePermit` only on equality. The unlink adapter must
consume this permit under the source guard described above. The kernel cannot authenticate
caller-supplied evidence, perform stat/hash, select a bucket, or guarantee remote retention.
Durable `FileState` transitions describe progress, not authority: an `uploaded` row cannot mint
a token. Restart reconstructs expected evidence and re-verifies remote and source state. After
unlink succeeds, persist `deleted`; after a crash in that gap reconcile an absent source without
attempting to delete a newly created replacement.

SQLite stores detector names/counts, status and bounded provenance, never finding values.
A final manifest includes state rows only on non-dry runs; review paths and metadata as sensitive
operational data even though they are not credentials. Errors are retried via fresh discovery,
not by jumping directly from an old state to deletion.

## Verification, rollout, and open integration work

The stable workspace pin is independent of Verus's Rust pin. The verified crate has no normal,
build, or dev dependencies. `scripts/verus-install.sh` installs checksummed Verus and dedicated
rustup under the XDG data directory without changing profiles. `scripts/verus-verify.sh` fails
when missing, proves the small feasibility functions, rejects a deliberately false postcondition,
and compiles/tests reference APIs with the pinned compiler. CI must install before verification.
This is an evidence-based **go** for Verus, not completion of wave-two proofs.

Wave two adds specs/proofs to the actual production-called kernels, tests adapters against these
APIs, and closes scanner resource/privacy gaps. Wave three first establishes an S3 mock seam,
then integrates filesystem, state and transport adapters with fault injection at every durable
boundary. Golden parity and no-write dry-run tests precede real input use. Independent review
covers delete safety, redaction and cancellation. Performance baselines are recorded only on the
fixed public runner after the history audit and publication approval; instruction baselines must
share compiler fingerprints. Roll back by disabling the Rust entry point and retaining local
files; this PR installs no production entry point and migrates no legacy state or archives.
