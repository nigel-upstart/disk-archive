# Migration and recovery

**Owner:** Maintainers · **Status:** Preparation draft; blocked on final integrated validation
**Last updated:** 2026-10-24 · **Links:** [usage](usage.md), [storage integrity](storage.md), [key decision](adr/003-key-layout.md), [verification boundary](design.md)

Behavior below was reconciled with merged G `204034c3`, especially its
[ownership contract](../crates/archiver/README.md), `work.rs`, `pipeline.rs` and `manifest.rs`.
Commands and performance/profiling integration are not yet validated by this guide.

## Cut over without adopting Python runtime state

This is a fresh Rust deployment, not an in-place upgrade. Do not point Rust at the Python
installation, environment, database, logs, temporary archives or work directory. Development
workers must never operate on the live Python archiver or its files. An operator-approved
cutover happens only after integrated validation; no production installation or cloud test is
performed by preparing this guide.

The operator first stops the old Python job and eligible writers, including automatic restart
mechanisms, **before any normal Rust invocation**. Record the cutover privately without copying
paths, configuration or runtime data into this repository. Preserve the old installation and
its state unchanged for operator-managed recovery; do not copy its database into Rust.

Choose a new private Rust work directory, outside every source root and separate from Python
state, and allocate a disjoint destination namespace. The Rust state database lives inside the
Rust work directory, not in a separate configurable state path. Its `state.sqlite`, WAL/SHM,
`format` marker and persistent `run.lock` belong together. The parent directory must already
exist; the CLI can create the final work directory with private permissions. An existing work
directory must be owner-private and empty or already carry the recognized Rust format. A
nonempty unmarked directory is rejected before opening a database. Never add a marker to
legacy or unknown files to force adoption.

Review local configuration and metadata-only dry-run first. After the operator establishes
quiescence and exclusive local/remote ownership, start with a small candidate limit. Review
retained/conflict counts and independently authorized synthetic acceptance receipts before
expanding scope. Dry-run is not proof that upload or deletion will work. Existing cloud objects
and production roots are outside development validation.

## Keys are immutable, root-qualified and machine-dependent

Legacy lookup stripped leading dots from home-relative paths, allowing distinct paths to
collide. Rust uses injective `prefix/v1/...gz` percent encoding for a fixed prefix. In the merged
pipeline the key domain is the **full root-qualified absolute source path with the initial
slash removed**, not merely a basename or home-relative path. Dots are preserved; roots are
distinguished. Encoded local path components can disclose machine/user layout to object-store
readers, and moving the same file to another absolute root changes its key. Protect keys and
manifests as sensitive operational metadata even though finding values are excluded.

Old and new objects can coexist under separately allocated buckets or genuinely disjoint key
spaces. Different prefix strings alone do not prove disjointness: nested prefixes can collide
with encoded path components. Never reuse a legacy namespace or allow another uploader to
write/delete within Rust's namespace. This guide does not migrate, rename or delete old objects.

Archive writes are create-only (`If-None-Match: *`). A new generation at a path with Deleted
history is retained, not silently overwritten; the immutable row remains intact and
`namespace_conflicts` increments. A changed source with an outstanding upload intent also stays
local without erasing that intent; this is retention, not necessarily a conflict-counter increment. Allocate a disjoint namespace for a reviewed new
generation and reconcile pending work before changing configuration. Do not clear tombstones
or delete an existing object just to bypass the conflict.

The metadata names `orig-size` and `orig-sha256` mean the **post-redaction, pre-gzip bytes**,
not the pre-redaction secret-bearing input. `sha256` is the complete gzip-byte digest. S3's
additional CRC64NVME/full-object or multipart-composite checksum is separate evidence; an ETag
is not a content hash. Checksums and metadata must match before a fresh kernel upload capability
can authorize source-bound deletion. See storage documentation for the trusted adapter boundary.

## Resume and source-retained failures

On SIGINT/SIGTERM, allow graceful shutdown: stop discovery, drain actual workers and storage
cleanup, flush SQLite, then release ownership. Do not remove the persistent lock file to
"unlock" a running process. Runtime destruction or forced termination is a crash, not proof
that cleanup completed. Keep writers stopped while reconciling and resuming.

Resume with the same reviewed configuration and Rust state/work location. Expected upload
evidence was durably recorded before remote upload; it is not deletion authority. Resume uses
a fresh checksum-enabled HEAD and fresh source checks. Only genuine absence or definitive
integrity mismatch permits a new upload attempt; transient HEAD/credential/TLS failures are
not absence. A changed source retains its intent and never reuses an old capability. Recovery
also handles an already-absent source after an unlink/local-commit gap without unlinking a new
replacement. Pending intents outside the currently selected roots are retained without reading
or unlinking those sources; namespace/bucket mismatch still fails the run. Keep the complete
state/work set intact rather than rebuilding a partial database from manifest rows.

Version/ETag selectors from an upload are not persisted by the current pipeline. Restart checks
the latest object against expected evidence under write-once and exclusive namespace ownership;
it does not promise pinned-version restart verification. Keep competing overwrites/deletes out
of the namespace. Real-S3 conditional-write/version acceptance remains separately authorized work.

| Condition | Safe operator response |
| --- | --- |
| Scan/redaction/verification budget, incomplete output, `UnsupportedEncoding` | Retain the source. Investigate using synthetic reproductions; never upload the blocked original or weaken the privacy floor. |
| Recoverable encoded secret | Require proven safe redaction or blocking/source retention, including JSON Unicode, URL encodings, base64, UTF-16LE/BE and base64-of-UTF16. Documented scanner limitations are not permission to upload it. |
| Source changed, root insecure, symlink or hardlink | Retain; restore the ownership contract before a fresh attempt. Do not force deletion. |
| Remote mismatch, transport, credentials or CA failure | Retain; fix the cause and require fresh verification. Never mark an object verified by editing SQLite. |
| Namespace conflict | Preserve both old evidence and the local generation; plan a disjoint namespace. |
| Work lock/format or leftover-spool budget failure | Stop and reconcile ownership/artifacts privately. Never delete unknown files automatically. |

Preexisting `archive-*.gz` crash spools are charged against the same disk quota and are not
automatically removed. A filename is not evidence that deleting a spool is safe. Reconcile
artifacts against durable state and remote evidence under exclusive ownership before any
operator-managed reclamation; then restart quota accounting. Do not touch Python artifacts.
The merged application's `peak_temp_bytes` counts maximum simultaneously live logical bytes in
invocation-created temporary files, not physical blocks, SQLite, preexisting disk footprint or
an RSS bound. Failed cleanup poisons observation and later temporary writes; it is not a zero
measurement. Performance collectors must observe actual transport rather than infer it from this
counter; their integrated acceptance is still pending.

Rollback means stopping further normal Rust operation and retaining sources/state. Redaction
and successful deletions cannot be undone by switching binaries. Do not restart Python on
overlapping roots while Rust still owns them or cleanup is draining. Any restoration/download
workflow needs separate validation; there is no documented automatic restore command here.

## All-history manifest v2 reconstruction

A completed normal run streams **all state history**, including Deleted tombstones, into
bounded JSON-array data pages. The startup resume map includes only outstanding work; its
caps are not a lifetime history limit. Paging bounds individual payloads and buffered memory,
**not total work**: every run transfers O(lifetime history) manifest bytes, with O(runs × history)
storage across similarly sized snapshots. Include history size in performance interpretation.
Manifests contain operational paths/evidence, never raw finding values. Store them privately.

For final root key `K`, data pages are `K.parts/part-<20-digit zero-based ordinal>.json`;
index pages are `K.parts/index-<20-digit zero-based ordinal>.json`. Each data page fits the
store's 1 MiB payload cap, and each index contains at most 512 data descriptors. The root format
is `disk-archive-manifest-v2`, with `rows`, `data_parts`, `index_pages` and
`index_chain_sha256`; indices use `disk-archive-index-v1`.

To reconstruct a snapshot, read the root, then indices in ordinal order. Verify the root's
ordered chain digest by hashing each index's u64 big-endian byte length followed by its exact
JSON bytes. For each referenced data page verify its SHA-256 and row count before decoding;
check cumulative counts against the root. Do not reinterpret hashes over reformatted JSON or
assume a single legacy JSON array contains the whole history. No recovery CLI implementing this
procedure is claimed here.

The root is initiated **last**, only after all pages succeed. Earlier failure can leave pages
without a committed root; do not treat such pages as a complete snapshot. Cancellation or
response loss during the final root request can have an unknown remote commit outcome. Neither
manifest pages nor roots authorize deletion; SQLite rows also cannot mint upload capabilities.
A manifest failure after file processing does not undo already completed deletes.

## Acceptance and visibility boundaries

Synthetic SDK/HTTP tests are not real-S3 or corporate-proxy acceptance. Performance stays
record-only while the repository is private; the first reviewed gating baseline follows
publication. Profiling evidence and actual command receipts must come from their implementation
owners, not this draft. Final independent cross-vendor review of integrated performance/profiling/
documentation remains open; earlier phase reviews and merged G CI do not supply that approval. Full-history secret/configuration/author auditing and **separate owner
approval** are prerequisites to any public visibility change. Neither this guide nor autonomous
reviewed-merge approval authorizes publication.
