# Dependency and toolchain policy

**Owner:** Maintainers · **Status:** Active · **Last updated:** 2026-10-21
**Links:** [crypto/native ADR](adr/006-crypto-provider.md), [scanner ADR](adr/005-scanner.md)

Prefer registry dependencies with a committed lockfile. Git dependencies require a full immutable
40-hex commit revision, never a tag or branch. Record repository, revision, purpose, feature set,
license/provenance and upgrade tracking here before adding one. Update cargo-deny allowlists and
resolved feature checks in the same production-dependency PR. An immutable revision is reproducible,
not automatically trustworthy: review upstream changes and advisories before upgrading.

## Git tracking

| Dependency | Upstream | Revision | Scope |
| --- | --- | --- | --- |
| AWS S3 transfer manager + synthetic mock | https://github.com/awslabs/aws-s3-transfer-manager-rs | `dc391970cd36e0d6d6ed044dcb3351b26131e9be` | Preview 0.3.1; Apache-2.0; manifest-only audited local patch |
| Kingfisher scanner/core/rules | https://github.com/mongodb/kingfisher | `c0a65103432434b2e4f502d519ed25566faa282e` | Standalone feasibility only; scanner 2.0.0, core 1.0.4, rules 2.0.0; no validator features |

The spike locks registry transitive packages, including published Vectorscan/sys 0.1.1. Kingfisher
scanner/core use Apache-2.0; rules declare Apache-2.0 AND MIT. Audit the full graph and embedded
catalog notices before production adoption. Changes to detection catalogs require planted/benign
corpus comparison, not only compilation. The transfer manager revision above is admitted only with the exact root path patches and
source-hash receipt in `vendor/transfer-manager/provenance.json`. Its original source, license and
notice are retained; no Rust source is modified. The workspace manifest removes omitted auxiliary
members and disables aws-config defaults while retaining HTTPS, Tokio and SSO. The resolved graph
still forbids credentials-process; this patch is not a general override escape.

Review the preview pin monthly: inspect upstream source changes and advisories, regenerate and
review the source receipt, recheck features/licenses/duplicate APIs, run HTTP/checksum/abort/TLS
regressions and full checks. Do not replace immutable revisions with moving main. A non-blocking
upstream compatibility workflow must remain separate from production admission; its output is
not permission to update the admitted source automatically.

The pinned preview graph currently pulls `hickory-proto 0.25.2` through aws-smithy-dns.
RUSTSEC-2026-0118 and RUSTSEC-2026-0119 remain **blocking**, with no vulnerability waiver.
The adapter supplies its shared SDK client, disabling the preview's custom runtime HTTP/DNS
transport, and DNSSEC features are not selected; that reachability observation is not a passing
cargo-deny result. A reviewed upstream/pin change or explicit security-policy decision is needed
before merge. Exact duplicate-API and foldhash-Zlib allowances in deny.toml are scoped separately
to issue 5 and expire 2026-11-21; they do not exempt these vulnerabilities.

## Separate compiler and verifier pins

The workspace stable pin belongs to the normal build. `tools/verus.env` pins Verus
0.2026.10.18.7d82994, its Rust 1.99.1 and rustup 1.29.1, with release-asset SHA-256 values for
macOS arm64 and Linux x86_64. Installer downloads are checked before execution/extraction and live
under `DISK_ARCHIVE_TOOLS_DIR` or the XDG data directory. Installers are development tooling only,
never runtime configuration. They do not modify shell profiles or the workspace compiler pin.

`crates/verified` has zero normal/build/dev dependencies; validate that from Cargo metadata as
well as the manifest. The Verus release includes its own trusted vstd and solver, distinct from
Cargo dependencies. Upgrades must re-run the positive proof, negative control, pinned-compiler
reference tests, and eventually all production-connected proofs. No missing-verifier success path.

## Native and crypto prerequisites

Use C/C++17-capable compiler, make, CMake, Boost headers, Ragel and pkg-config. macOS:
`brew install cmake boost ragel pkgconf` plus Xcode Command Line Tools. Ubuntu:
`apt-get install build-essential cmake libboost-dev ragel pkg-config`. Force Vectorscan source
builds via `build-from-source` and set `VECTORSCAN_OFFLINE=1` to prevent its archive fetch.
Cargo dependency fetches are separate; `cargo --offline` and that environment variable do not
sandbox all build scripts. Cache dependencies ahead of an actually network-denied build test.

Select AWS-LC for rustls, not an additional ring provider, unless a reviewed compatibility
exception requires it. Detection-only Kingfisher rules already depend on AWS-LC. Audit resolved
features when integrating: validation, credential subprocess providers, unsolicited network
behavior and duplicated crypto providers must not arrive through transitive defaults.

## Required production admission evidence

Run cargo-deny, unused-dependency checks, the immutable-git policy and feature-graph checks.
Generate and validate CycloneDX for every workspace member; attest release SBOMs. Standalone
spikes are deliberately outside the production workspace/SBOM and are not a backdoor to runtime
use. Adding a spike dependency to the application requires updating its allowlists, licenses,
SBOM, feature checks and tests in that same PR. Track upstream security fixes through normal
dependency-update PRs; do not equate a frozen lockfile with a maintenance plan.
