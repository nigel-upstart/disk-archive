# Dependency and toolchain policy

**Owner:** Maintainers · **Status:** Active · **Last updated:** 2026-10-23
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
| Kingfisher scanner/core/rules | https://github.com/mongodb/kingfisher | `c0a65103432434b2e4f502d519ed25566faa282e` | `crates/scanner` integration under validation; scanner 2.0.0, core 1.0.4, rules 2.0.0; no validator features |

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

The preview graph's `aws-smithy-dns 0.2.3` otherwise selects vulnerable Hickory 0.25.
The approved minimal registry-source patch upgrades to Hickory 0.26.3 (the patched 0.26 line,
including the approved 0.26.1 security fix) and adapts only runtime-provider, nameserver,
cache-size and fallible-builder APIs. No advisory is ignored. The published archive identity
is SHA-256 `3aec766384ece7e3e9ac462683a81a0c3803a1169900e071355d33c194d71fab`;
`vendor/aws-smithy-dns/provenance.json` records original and patched hashes, and
`compatibility.patch` records every change. Original manifests/source and Apache-2.0 license
are retained. Policy pins the receipt and exact path override; it rejects source, patch,
receipt, extra-file and symlink changes. Upgrade tracking belongs to issue 5: check monthly
for an upstream Smithy release supporting patched Hickory and remove this patch when available.
Exact duplicate-API and foldhash-Zlib allowances in deny.toml expire 2026-11-21; these are
not vulnerability waivers. The macOS-only core-foundation duplicate is required by Hickory's
system-configuration DNS integration versus rustls-native-certs' security-framework ABI.

## Reviewed scanner exceptions (issue #17)

Owner: repository maintainer. All exceptions expire **2026-11-21**; the real
supply-chain hook checks expiry, exact crate versions and attribution. PR #13
reviews admission; #17 tracks upstream removal. Duplicate bans remain enabled:
only incompatible, exact-version transitive APIs listed in deny.toml are skipped.
The lockfile pins both versions; new versions are not implicitly approved.
The merged SDK/scanner graph additionally needs exact `untrusted 0.7.1` alongside
0.9.0: Kingfisher's AWS-LC parser and SDK rustls-webpki require incompatible APIs.
This is an issue #17 duplicate allowance, not an advisory waiver.

Unmaintained anymap2 is reached through Liquid (validation templates are not
executed); term_size through tokei (terminal rendering is not called);
unsafe-libyaml through serde_yaml (only immutable embedded catalog YAML is parsed
by builtin startup, never file/input YAML). These are maintenance exceptions,
not vulnerability waivers. There is no safe semver update for these edges;
replacing an upstream parser is a separate reviewed dependency change.

License exceptions are exact-package scoped: CC0-1.0 for bip39/bitcoin_hashes/
hex-conservative; permissive Zlib for foldhash/zlib-rs; permissive BSL-1.0 for
xxhash-rust; MPL-2.0 for unmodified colored. Preserve MPL notices and supply that
crate's source with binary distribution; file-level obligations do not relicense
the application's MIT source. libfuzzer-sys 0.4.13 additionally uses permissive
NCSA and belongs only to the isolated fuzz workspace. Preserve all upstream
notices when distributing. No license category is globally disabled.

The isolated fuzz workspace has its own committed lockfile and cargo-deny gate.
CI installs cargo-fuzz 0.13.2 and nightly-2026-10-20, distinct from the workspace
and Verus compilers. The explicit comparison tool uses TruffleHog 3.99.2 release
archives with checked SHA-256 (Linux x86_64/macOS arm64); it is test tooling only,
not a production dependency, and credential verification/update checks are off.

## SQLite state-writer admission

The async shell uses registry `rusqlite 0.41.1` with defaults disabled and only
`libsqlite3-sys`/`bundled` enabled. The lockfile admits `libsqlite3-sys 0.39.1`,
`fallible-iterator 0.3.0`, `fallible-streaming-iterator 0.1.9` and the native build
helper `vcpkg 0.2.15`; existing registry identities and immutable Git pins remain
unchanged. Bundled SQLite avoids an ambient system-library version dependency;
loadable extensions and the default alternate backends are not enabled. One bounded
blocking writer owns the connection. Re-run license/advisory/feature checks,
SQLite durability/resume regressions and every workspace SBOM on upgrades. No new
advisory, license or duplicate-version exception is introduced for this layer.

The SQLite security update for
[RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459) upgrades
only `rusqlite` and `libsqlite3-sys`. The latter bundles SQLite 3.54.1, above the
patched floor of 3.54.0 for mismatched database/WAL page sizes exposing stale
page-cache memory. Upstream's current
[rusqlite 0.41.1 release](https://github.com/rusqlite/rusqlite/releases/tag/v0.41.1)
and the registry crate's bundled SQLite version were checked for this change.
No system-SQLite substitution, SQLCipher feature, advisory exception, or runtime
state migration is introduced. Keep the bundled SQLite floor patched on future
upgrades and rerun state durability/resume and complete supply-chain gates.

## October 2026 security patch floor

The archiver and storage require Tokio >=1.54.1 and the workspace lockfile pins
1.54.1: [RUSTSEC-2026-0384](https://rustsec.org/advisories/RUSTSEC-2026-0384)
affects 1.54.0's multi-threaded Interval timer with a data race/use-after-free.
Both workspace and isolated fuzz lockfiles pin ctutils 0.4.4 for
[RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385), which fixes
non-constant-time masks and u128 comparisons. The patched, non-yanked registry
releases and advisory ranges were checked on 2026-10-23. These are precise
security updates only; all other registry, immutable Git and vendor identities
are retained, with no advisory exception. Keep both graphs on patched versions
and rerun admission, runtime regressions and full gates on future upgrades.

[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387) (crypto-bigint
<0.7.6 timing variability) reached the graph only through `aws-sigv4`'s optional
SigV4A signer (`p256`/`ecdsa`, plus a direct crypto-bigint 0.5 dependency with no
patched 0.5 release; aws-sigv4 1.6.3 still requires it). The vendored transfer-manager
workspace manifest enabled `aws-sdk-s3/sigv4a`; the archiver never uses SigV4A
(multi-region access points). The admitted manifest patch now also removes that
feature (`scripts/policy.py` and `vendor/transfer-manager/provenance.json`), so the
SigV4A crypto stack is absent from the lockfile. No advisory exception is added.
Re-enabling SigV4A requires a patched signer stack first.

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

## CI build-artifact reuse

CI uses actions/cache v6.1.0 at
55cc8345863c7cc4c66a329aec7e433d2d1c52a9 (upstream release checked with gh).
Exact keys include OS/architecture, ref, compiler/native-tool/CPU fingerprint,
workspace or nightly-ASan profile, lockfile, toolchain/manifest and native build
inputs. A fallback may omit only the final full-lock digest: compiler, native
closure (locked Vectorscan/sys and all recursive build dependencies, including
checksums/git identities), CPU, flags, profile and native manifests/build scripts
remain identical. Restore prefixes name only the current ref and reviewed main;
no arbitrary feature/PR ref can supply a fallback. Fork PRs neither restore nor
save. Native closure ambiguity/missing identities fail instead of broadening keys.
Rust-only lock churn can reuse native artifacts; all Rust fingerprints and gates
still run. Workspace debug/coverage and nightly ASan remain separate.

Only registry archives/index, public dependency git databases and selected
compiled dependency/native directories are cached. Runtime fixture/log/trace/
SBOM/credential directories and generated fuzz corpora are excluded; build log
files are excluded too. Nightly fuzz artifacts use a separate key and paths.
Every hit still runs unchanged gates. A hit is reuse evidence, not a fresh build
or runtime-performance measurement; retain the first uncached CI result as cold
build proof. This saves native rebuild time, not scanner runtime.

## Required production admission evidence

Run cargo-deny, unused-dependency checks, the immutable-git policy and feature-graph checks.
Generate and validate CycloneDX for every workspace member; attest release SBOMs. Standalone
spikes are deliberately outside the production workspace/SBOM and are not a backdoor to runtime
use. Adding a spike dependency to the application requires updating its allowlists, licenses,
SBOM, feature checks and tests in that same PR. Track upstream security fixes through normal
dependency-update PRs; do not equate a frozen lockfile with a maintenance plan.
