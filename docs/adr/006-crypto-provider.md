# 006 — Standardize on AWS-LC for rustls and build native scanner dependencies

**Status:** Accepted direction; feature-graph enforcement pending integration · **Owners:** Maintainers
**Last updated:** 2026-10-21 · **Links:** [dependency policy](../dependencies.md),
[supply-chain issue](https://github.com/nigel-upstart/disk-archive/issues/2)

## Context & Problem Statement

The SDK and scanner introduce native dependencies and configurable TLS providers. Enabling
several providers implicitly can lead to ambiguous rustls initialization and unnecessary build
surface. Disabling scanner validation does not eliminate all crypto: Kingfisher's rules crate
uses AWS-LC for offline rule filters even in detection-only builds.

## Options Considered

Select rustls-ring, select rustls-AWS-LC, or accept feature-unified defaults without review.
Ring is credible but would not remove the scanner's mandatory AWS-LC dependency. Unexamined
defaults risk multiple providers and prohibited credential subprocess features.

## Decision

Use rustls with AWS-LC for the application's TLS connections; do not add ring by preference.
Select an explicit provider when application code owns rustls configuration and audit the
resolved feature graph when SDK/scanner adapters land. A feature declaration is not proof that
transitive defaults preserve this policy. If a later dependency requires ring, review the graph
and document a narrow compatibility exception rather than blanket-banning or silently adding it.

Build the native scanner source using supported C/C++ tools. On macOS install Command Line
Tools plus CMake, Boost, Ragel and pkg-config; on Ubuntu use build-essential, cmake, libboost-dev,
ragel and pkg-config. Vectorscan's native source and crypto implementation are dependency code,
not an exception permitting unsafe Rust in this repository's application or kernel code.

## Consequences

The provider choice aligns with a dependency already present instead of adding a second crypto
implementation merely to express a preference. It accepts AWS-LC's C build requirements and the
maintenance/security update burden of both AWS-LC and Vectorscan. No FIPS claim follows from
selecting AWS-LC; no FIPS requirement has been specified.

The standalone spike pins the Kingfisher git revision and Vectorscan release, commits its lockfile,
and forces vendored native source builds. Runtime no-network behavior remains independently
tested; source-build/offline flags do not sandbox every Cargo build script. Workspace cargo-deny,
SBOM, license/provenance review and advisory updates remain required when these dependencies
become production dependencies. Native test success on one host does not assert Linux/Windows
portability or establish cryptographic correctness.
