# 005 — Prefer the pinned Kingfisher embedding crates; gate production integration

**Status:** Accepted selection criteria; integration pending · **Owners:** Maintainers
**Last updated:** 2026-10-21 · **Links:** [spike](../../spikes/kingfisher/README.md),
[scanner issue](https://github.com/nigel-upstart/disk-archive/issues/6)

## Context & Problem Statement

Secret detection must execute in-process without provider validation, secret-bearing subprocess
output or uncontrolled whole-file accumulation. Kingfisher now exposes separately versioned
core, rules and scanner crates, so evaluating only the CLI's dependency graph would overstate
the embedding burden. Native C++ prerequisites are an accepted build cost.

## Options Considered

Use the focused Kingfisher scanner from an immutable git commit; copy its rules into a smaller
custom engine; or retain an external scanner as primary. The first preserves upstream detection
semantics. Copying rules increases maintenance/provenance burden. A subprocess primary does not
meet the selected architecture; trufflehog remains an optional parity cross-check only.

## Decision

Evaluate `kingfisher-scanner` 2.0.0 at
`c0a65103432434b2e4f502d519ed25566faa282e`, with default features disabled and no validation
features. Build published Vectorscan 0.1.1 from its vendored source rather than relying on a
build-script archive download. Install the C/C++ compiler, CMake, Boost headers, Ragel, make and
pkg-config. The standalone pinned-git consumer tests custom synthetic findings, repeated scans,
benign input and embedded-catalog compilation. It neither validates nor revokes credentials.

Do not adopt the spike's vector-returning API unchanged in production. Wave two must demonstrate
bounded callbacks/accumulation, cross-boundary matching, fail-closed budgets, cancellation,
no-network behavior, zeroizing finding ownership, synthetic planted-corpus recall and benign
false-positive constraints. Where upstream lacks the necessary interface, first extend/fork
the focused library at a reviewed immutable revision.

## Consequences

This avoids premature fallback merely because the library needs a native build. It also avoids
claiming feasibility establishes memory or detector completeness. The high-level API currently
returns `Vec<Finding>`; borrowed/mapped input does not make its output bounded or zeroizing.
The lower-level pool exposes callbacks but does not alone reproduce all high-level confirmation
semantics. Those are explicit integration gaps.

Only demonstrated infeasibility after native/toolchain/API work permits the in-house
RegexSet/aho-corasick fallback. That decision needs a new ADR with concrete evidence, vendored
rule provenance/licenses and the same parity/privacy/resource gates. The MIT repository license
does not replace upstream dependency and rule-catalog notices.
