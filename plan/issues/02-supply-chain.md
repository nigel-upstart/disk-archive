<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/2 (synchronized during PR #9). The issue is the source of truth; git rm this file when #2 closes or if it drifts. -->

# #2: Supply-chain and toolchain policy for the async/AWS/scanner dependency tree (incl. CycloneDX SBOM)

Part of #1. **Land this before or together with** the first PR that adds tokio, the AWS SDK, the transfer manager or the scanner, so the new dependency tree goes through the policy checks from the start.

## Scope

### Toolchain split (Verus vs. workspace)
- `aws-config`, `aws-sdk-s3` and `aws-smithy-*` declare `rust-version = 1.94.1`. Verus pins its own Rust toolchain, which may be older.
- Rule:
  - Verus verifies **only** `crates/verified`, which has no third-party dependencies, using its pinned toolchain.
  - The rest of the workspace builds with the repo's stable pin in `rust-toolchain.toml`.
- Enforce this in CI with separate jobs, and add an ast-grep or `cargo metadata` check that `crates/verified` has no dependencies.

### cargo-deny
- **`[sources]`:** allow git sources only for these two, each pinned exclusively to a full immutable commit `rev` (never a branch or tag). CI rejects missing revisions and all branch/tag selectors, including on these approved sources:
  - `https://github.com/awslabs/aws-s3-transfer-manager-rs` (developer preview, not on crates.io)
  - `https://github.com/mongodb/kingfisher`, only if #6 picks it
- **`[licenses]`:** allowlist built from `cargo deny list` once the dependencies are in. Expect Apache-2.0, MIT, ISC, BSD-3-Clause and Unicode-3.0, plus the composite expression on `aws-lc-sys`. Anything new fails CI until it is reviewed.
- **`[bans]`:** deny duplicate versions, with explicit `skip` entries for known duplicates in the AWS/hyper tree. Each skip carries a comment explaining why.
- **`[advisories]`:** fail on unmaintained or vulnerable crates, and allow an exception only with an expiry comment.

### Native build prerequisites
- `aws-lc-sys` (the default rustls crypto provider) and `kingfisher-vectorscan` (a C/C++ Hyperscan fork, only if Kingfisher is chosen) need a C/C++ toolchain, and possibly cmake.
- Evaluate `aws-smithy-http-client`'s `rustls-ring` feature as a way to avoid the aws-lc build, and record the decision in an ADR.
- `task doctor` checks for the prerequisites and prints install hints.

### CycloneDX SBOM
- Generate a CycloneDX SBOM with `cargo-cyclonedx` (0.5.9 when this was written; pin it via mise).
  - JSON format, all workspace members, `--target all` or the release targets.
  - Output goes to `target/sbom/`, which is gitignored and never committed.
- `task sbom` builds it. `task check` validates it with `cyclonedx-cli validate`, pinned via mise or run in a container. On failure it prints a quiet-wrapper summary.
- CI:
  - Every PR generates and validates the SBOM, and uploads it as a workflow artifact.
  - Release tags attach the SBOM to the GitHub release and produce an attestation with `actions/attest-sbom`.
    - Pin the action by commit SHA with a `# vX.Y.Z` comment. Look up the current version with `gh` at implementation time; do not assume one.
- Optional, as a follow-up: feed the SBOM to a vulnerability scanner (e.g. `osv-scanner --sbom`) as a second opinion next to cargo-deny's advisories.

### Lints for the async tree
- Deny these clippy lints: `await_holding_lock`, `await_holding_refcell_ref`, `large_futures`, `unused_async`.
- ast-grep rules:
  - No `std::process::Command` or `tokio::process` outside the optional `trufflehog` cross-check module.
  - No `std::fs::*`, `std::thread::sleep` or `Handle::block_on` inside `async fn` bodies.
  - `spawn_blocking` only through the crate's bounded wrapper.

### Build health (advisory metrics, reported by the perf job)
- Clean release build time and incremental build time on the GitHub-hosted runner.
- Release binary size, and `cargo tree --duplicates` count.

## Acceptance criteria

- [ ] `task check` and CI are green with the new dependencies, and `cargo deny check` passes with the reviewed allowlist.
- [ ] The Verus job and the workspace build use separate toolchains, and CI fails if `crates/verified` gains a dependency.
- [ ] A CycloneDX JSON SBOM is generated and validated on every PR and uploaded as an artifact. Releases attach it with an attestation.
- [ ] The ADR records the crypto-provider choice and the native build prerequisites.
- [ ] Every git dependency is pinned to an immutable revision, with an upstream-tracking note in `docs/dependencies.md`.
