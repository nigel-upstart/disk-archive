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
| Kingfisher scanner/core/rules | https://github.com/mongodb/kingfisher | `c0a65103432434b2e4f502d519ed25566faa282e` | `crates/scanner` integration under validation; scanner 2.0.0, core 1.0.4, rules 2.0.0; no validator features |

The spike locks registry transitive packages, including published Vectorscan/sys 0.1.1. Kingfisher
scanner/core use Apache-2.0; rules declare Apache-2.0 AND MIT. Audit the full graph and embedded
catalog notices before production adoption. Changes to detection catalogs require planted/benign
corpus comparison, not only compilation. The transfer manager will receive its own immutable
revision entry when the S3 adapter introduces it; no moving revision is preapproved.

## Reviewed scanner exceptions (issue #17)

Owner: repository maintainer. All exceptions expire **2026-11-21**; the real
supply-chain hook checks expiry, exact crate versions and attribution. PR #13
reviews admission; #17 tracks upstream removal. Duplicate bans remain enabled:
only incompatible, exact-version transitive APIs listed in deny.toml are skipped.
The lockfile pins both versions; new versions are not implicitly approved.

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
