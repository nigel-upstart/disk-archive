# Storage integrity and operations

**Owner:** Maintainers · **Status:** Implementation under review · **Last updated:** 2026-10-21
**Links:** [issue 4](https://github.com/nigel-upstart/disk-archive/issues/4), [issue 5](https://github.com/nigel-upstart/disk-archive/issues/5), [dependencies](dependencies.md)

The storage crate never deletes source files. The archiver supplies an already-open regular file,
its post-scan identity, and a kernel-generated destination. Preparation checks identity and the
original SHA256 before and after deterministic gzip compression. It reserves spool disk quota
before opening a private temporary file. The work directory must already exist with private
permissions. Persist `ExpectedUpload` before submitting the prepared upload. Persisted records
are expectations, not deletion capabilities.

The budgeted spool is intentional: S3 metadata must contain the complete gzip SHA256 before
upload initiation, and restart verification needs durable checksum expectations. CPU permits
are acquired before blocking work and stay inside the worker even if its caller disappears.
Prepared spools retain their disk reservations through background upload/abort cleanup. Disk
reservation is a configured quota, not a claim about free filesystem space. Oversized conservative
reservations fail before CPU admission; compressors never acquire more disk quota mid-stream.
A two-file regression uses CPU capacity one and a single-spool quota to prove a waiting preparation
cannot starve the first upload's real final-hash/kernel authorization step.

Under the exclusive Rust work-directory lock, `account_existing_spools` charges preexisting
`archive-*.gz` files against the same quota once across all preparer clones. Preparation invokes
this lazily if startup did not. Per-file sizes round up to quota units; symlinks, non-regular entries
and over-budget leftovers fail closed. Requests larger than total quota minus the permanent
leftover reservation return `Budget` before waiting; only temporary live-upload contention waits.
Full-orphan and partial-remainder timeout regressions cover this resume/backpressure boundary.
No leftover is deleted automatically. Reconcile crash
artifacts explicitly before reclaiming their quota; restart the preparer after that reconciliation.

One shared SDK client supplies adaptive retries (eight attempts), explicit connect/attempt/overall
timeouts and stalled-stream protection. Profiles, shared files, environment, SSO and role providers
remain available; credential-process is deliberately unsupported and excluded by the resolved
feature gate. Authenticate SSO outside the archiver with `aws sso login`. No storage subprocess
backend exists. The shell resolves configuration before constructing this client and must exit
dry-run before constructing preparers, directories, credentials or network clients.

TLS uses AWS-LC/rustls and native OS roots. `DISK_ARCHIVE_CA_BUNDLE` adds a bounded PEM bundle
without disabling native trust or hostname validation; `AWS_CA_BUNDLE` is the read-only fallback.
An explicit app setting wins over the fallback. Relative bundle paths resolve against the selected
configuration cwd. Synthetic TLS tests cover an untrusted private CA, explicit trust, wrong hostname
and malformed bundles. Corporate macOS-keychain/interception acceptance is **not yet performed**.

Single PUT sends a precomputed full-object CRC64NVME or SHA256 header. Multipart uses the pinned
preview transfer manager and its shared payload pool. CRC64NVME is full-object; multipart SHA256
is `base64(SHA256(concatenated ordered binary part digests))-part_count`, type `COMPOSITE`.
Whole-gzip SHA256 remains separate metadata. Geometry is fixed and bounded to 10000 parts; the
store rejects a prepared upload whose threshold/part size differs from its own configuration.

Every upload requests AES256 and write-once `If-None-Match: *`. A version/ETag-selected,
checksum-enabled HEAD must match actual checksum algorithm, type and value, compressed length,
all expected metadata and AES256 before the real verified kernel can mint `VerifiedUpload`.
Restart performs that same fresh verification. The archiver must still revalidate the current
source and consume the kernel's deletion permit under exclusive source/remote namespace ownership.
ETags are selectors, never content hashes. After independently checking the additional checksum's
algorithm, type and value, the adapter projects `RemoteEvidence` from observed HEAD facts: the
request-bound key (S3 does not echo keys), actual Content-Length, canonical unsigned `orig-size`,
strictly decoded 32-byte lowercase hex `sha256`/`orig-sha256`, and whether observed SSE is AES256.
It never substitutes expected fields or constant encryption truth. Helper regressions bypass the
adapter's redundant key/length/metadata/SSE prechecks and show the real kernel rejecting each
projected mismatch; existing HTTP HEAD-fault tests cover the adapter separately.

This projection is tested Rust, not a Verus theorem. Binding checksum and metadata to the same
object trusts authenticated S3/TLS, the request/response adapter, preparation and exclusive namespace
ownership. CRC64NVME is not collision-resistant, and multipart composite SHA256 is not whole-object
SHA256. Their verification gates use of the observed whole-gzip SHA256 metadata; it does not
cryptographically derive or prove that digest from the remote bytes. Metadata echo alone is
insufficient, and the kernel's equality theorem does not remove these assumptions.

Store clones share one transfer scheduler and one payload admission pool. Single PUT conservatively
reserves and buffers its entire body in that pool; an object larger than available configured
capacity fails closed. Multipart payloads backpressure at the shared ceiling. Serialized manifest
writes are bounded to one MiB and charged to the same pool. Reference-counted single-PUT/manifest
bodies retain their reservation (and the single-PUT spool) until the last transport frame drops. These are payload limits, **not a total-RSS guarantee**: TLS, SDK,
allocator and preparation overhead are additional. Hyper can retain a cancelled body frame until
its connection retires; that memory stays charged and is not recycled past the budget. A cancelled
run must drain, retain its source on any error, then discard the store rather than assume zero RSS.

Caller cancellation or future-drop signals a shielded owner of the transfer handle. That owner
explicitly aborts known multipart uploads and retains the spool until cleanup. Stop submitting work
before `drain()`. Failed aborts are surfaced by drain. Create-MPU response loss, process crashes and
commit-unknown completion still require reconciliation and an operator-managed bucket lifecycle
rule with `AbortIncompleteMultipartUpload` after **one day** (or a shorter approved retention).
Do not grant deletion authority from an unknown outcome.

The synthetic fixture runs actual HTTP and SigV4 against the unmodified pinned upstream mock.
Its proxy corrects the mock's incorrect composite HEAD type label from the stored checksum suffix;
it never fabricates checksums or metadata. The mock supplies an SSE default, ignores version and
If-Match selectors, lacks multipart listing, and does not consume streamed single-PUT checksum
trailers. Tests therefore send explicit single-PUT checksum headers, independently corrupt HEAD
facts, and observe successful server abort responses. These tests do not establish real-S3
conditional-write/version behavior, cloud TLS, crash cleanup or production RSS/performance.

## External acceptance still required

Use only a dedicated synthetic test prefix in a separately authorized bucket. Verify empty/small
and multiple-part uploads under both policies, exact HEAD checksum type/value, metadata, AES256,
version/ETag selectors, conditional-write rejection, cancellation/abort and the lifecycle rule.
Repeat through the corporate proxy with native trust and then an explicit bundle. Delete only
synthetic objects after inspecting results. No live-AWS acceptance was run for this implementation;
issues 4/5 and the performance acceptance remain open until their external evidence is recorded.
