<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/1 as opened. The issue is the source of truth; git rm this file when #1 closes or if it drifts. -->

# #1: Epic: async in-process data plane for throughput (tokio + AWS SDK + in-process scanning)

## Why

The legacy Python archiver starts a `trufflehog` process two or three times per file (scan, verify, and a re-scan when residue is found) and makes blocking boto3 calls from 30 threads per stage.

Observed on a 35.6-minute window of a real legacy run (30 workers per stage):

| Metric | Value |
| --- | --- |
| Files completed (scanned → redacted → verified → uploaded → deleted) | 5,002 |
| Original bytes completed | 13.75 GiB |
| Throughput | ≈2.3 files/s, ≈6.6 MiB/s |
| Queue depth: scan / redact / verify | saturated (30/30) for most of the run |
| Queue depth: upload / delete | 0 for most of the run |

The bottleneck is per-file process spawning and the context switching that comes with it, not S3. This epic tracks moving the hot path in-process and async.

## Goals

- **Zero subprocesses in the hot path:** discover, scan, redact, verify, compress, hash, upload, head and delete all run in-process. Tests assert this.
- **Async I/O on tokio.** CPU-bound work (scanning, redaction, gzip, sha256) runs on a bounded blocking pool so it never blocks runtime workers.
- **S3 via the AWS SDK for Rust** plus `aws-s3-transfer-manager-rs`. The transfer manager is in developer preview; depending on it through a pinned git revision is accepted.
- **An in-process Rust secret scanner** replaces the `trufflehog` subprocess. `trufflehog` stays only as an optional cross-check.
- **A permanent performance regression gate** on GitHub-hosted runners, plus an optional profiling build.
- **CycloneDX SBOM** for the resulting dependency tree.

## Non-goals

- **An AWS CLI v2 backend.** It was dropped in favor of the SDK because of process-spawn overhead.
- **Verus verification of async code.** Proofs stay on the synchronous, dependency-free kernels in `crates/verified`. The async shell is covered by tests, lints and the perf gate.

## Safety rules that must not regress

- Only a value of the `VerifiedUpload` type allows a delete. It can only be produced after S3 confirms the object's size, checksum and metadata.
- Secret values stay in memory only. They are never logged, persisted, traced or sent anywhere. The scanner never validates credentials over the network.
- Cancelling at any point (SIGINT/SIGTERM) must never delete a file that has no verified copy in S3.

## Sub-issues

- [ ] #2 Supply-chain and toolchain policy, including the CycloneDX SBOM (lands first)
- [ ] #3 tokio runtime and async staged pipeline
- [ ] #4 S3 client via `aws-sdk-s3` and `aws-config`
- [ ] #5 Streaming multipart uploads via `aws-s3-transfer-manager-rs`
- [ ] #6 In-process Rust secret scanner replacing the `trufflehog` subprocess
- [ ] #7 Permanent performance regression gate on fixed-size GitHub-hosted runners
- [ ] #8 Optional profiling build

## Exit criteria

- [ ] Every sub-issue is closed.
- [ ] The hot-path process-spawn counter is 0 on the benchmark corpus.
- [ ] The perf gate is a required check and green, with the initial baseline recorded after the repository goes public.
- [ ] End-to-end throughput on the benchmark corpus beats the legacy-equivalent configuration (the `trufflehog` cross-check backend with the same worker counts). The margin is recorded in the baseline PR.
