# Kingfisher native embedding feasibility

**Owner:** Maintainers · **Status:** Source build in progress; production integration pending
**Last updated:** 2026-10-21 · **Links:** [selection ADR](../../docs/adr/005-scanner.md),
[dependency policy](../../docs/dependencies.md)

This is a standalone consumer, not a workspace member and not a CLI subprocess. It pins
Kingfisher to `c0a65103432434b2e4f502d519ed25566faa282e` with default features disabled,
and unifies `kingfisher-vectorscan =0.1.1`'s `build-from-source` feature. Cargo follows the
scanner's path dependencies within the pinned git source, retaining focused core/rules crates.
The committed lockfile pins their registry dependency graph.

## Reproduce

Install C/C++ compiler, make, CMake, Boost headers, Ragel and pkg-config (see dependency policy).
From this directory, with Rust 1.99+:

```sh
VECTORSCAN_OFFLINE=1 CARGO_BUILD_JOBS=4 cargo run --locked
```

On Homebrew hosts where Boost discovery needs assistance, additionally set
`BOOST_ROOT="$(brew --prefix boost)"`. This compiles vendored Vectorscan C++ and AWS-LC;
it intentionally does not use a downloaded native binary. First Cargo fetch still needs
network access unless its git/registry cache is populated. Build scripts are not sandboxed by
`VECTORSCAN_OFFLINE`.

The program tests a synthetic custom rule, repeated scanning (dedup disabled), benign input,
and the embedded catalog. It prints only a rule count and pass summary, never finding values.
It has no provider validation/revocation code or runtime inputs. Production scanner no-network,
zeroization, bounded-callback, cancellation and planted/benign parity tests remain separate
acceptance gates; the vector-returning high-level API here does not satisfy them by itself.

## Evidence

Local host: macOS arm64, Rust 1.99.0, Apple Clang 21, CMake 4.4.4, Boost 1.92.0, Ragel 6.11.
Native C++ compilation has started successfully with four jobs. Final runtime/catalog result
will be recorded when the source build completes; this checkpoint does not claim a passing run.
No library fallback has been selected. See the ADR for the remaining API integration gaps.
