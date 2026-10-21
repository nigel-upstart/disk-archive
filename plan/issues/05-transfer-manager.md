<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/5 (synchronized during PR #9). The issue is the source of truth; git rm this file when #5 closes or if it drifts. -->

# #5: Streaming multipart uploads via aws-s3-transfer-manager-rs (developer preview) with end-to-end integrity

Part of #1. **Blocked by** #4.

## Scope

Large archives need multipart uploads. AWS documents a 5 GB single-PUT limit; choose a conservative single-part threshold strictly below 5,000,000,000 bytes (decimal units). Use the AWS S3 Transfer Manager for Rust instead of hand-rolling multipart.

### Dependency
- Package `aws-sdk-s3-transfer-manager` from `https://github.com/awslabs/aws-s3-transfer-manager-rs`.
  - It is a **developer preview** and not published on crates.io. Depending on the preview repo is an accepted risk.
- Pin it to an immutable `rev` in `Cargo.toml` and allow exactly that git source in cargo-deny (see #2).
- Dependabot/Renovate won't bump git revisions. Add a checklist item to `docs/dependencies.md` for periodic manual bumps, and a scheduled CI job that builds against upstream `main` (non-blocking) to spot breakage early.
- Keep the transfer manager behind the `ObjectStore` trait, so moving to a published release or a hand-rolled multipart fallback only changes one module.

### Streaming
- Preferred pipeline: read → gzip → sha256 → upload as a stream, with no temp file:
  - gzip with `flate2` on the blocking pool, or `async-compression` with tokio
  - sha256 of the gzip stream computed on the fly
  - upload via the transfer manager's streaming input
- If the transfer manager needs a known length or a seekable body for some path, fall back to a temp file in the work directory, limited by a configured temp-disk budget.

### Integrity before delete
- Request S3 additional checksums: full-object `CRC64NVME` if supported end-to-end, otherwise `SHA256`.
- Also keep the legacy-compatible user metadata: `sha256` of the gzip bytes and `orig-size`.
- After the upload completes, call `HeadObject` with `ChecksumMode::Enabled`. Produce a `VerifiedUpload` only if all three hold:
  - `ContentLength` matches
  - the checksum matches
  - the metadata matches
- Server-side encryption is `AES256`.

### Failure and cancellation
- Abort the multipart upload on error or cancellation, and test this.
- Document a bucket lifecycle rule that aborts incomplete multipart uploads after N days (README; operator responsibility).

### Tuning knobs (config, with benchmarked defaults)
- Multipart threshold and part size.
- Per-object part concurrency.
- A **global in-flight bytes budget**, so memory stays bounded however many files are in flight.

## Acceptance criteria

- [ ] Tests against the mock cover an empty file, a small file below the threshold, and a large file above the threshold with several parts.
- [ ] A test where the mock returns a checksum mismatch produces no `VerifiedUpload` and no delete.
- [ ] A cancel-mid-upload test leaves no orphaned parts on the mock (multipart aborted).
- [ ] Peak memory stays within the in-flight budget on the benchmark corpus; the perf gate tracks it.
- [ ] Mock gaps (e.g. checksum algorithms the mock doesn't support) are listed, and those cases are covered by the documented real-S3 smoke run.
