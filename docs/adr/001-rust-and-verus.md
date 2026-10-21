# 001 — Rust with Verus for synchronous safety kernels

**Status:** Accepted · **Owners:** Maintainers · **Last updated:** 2026-10-21
**Links:** [design](../design.md), [verification boundary](002-verification-boundary.md)

## Context & Problem Statement

The Python archiver can delete the last local copy after upload. The port needs explicit
source/evidence invariants and a faster concurrent data plane without making network I/O part
of a theorem prover's execution model. The AWS SDK and native scanner also impose compiler
and build requirements independent of formal verification.

## Options Considered

Rust plus Verus supports ownership and specification-oriented proofs for small deterministic
functions. Rust plus Kani offers bounded model checking with a different proof envelope.
A Go rewrite simplifies some scheduling choices but is not the selected fallback and does not
provide the chosen kernel verification approach. Keeping Python alone avoids a port but does
not satisfy the Rust data-plane objective.

## Decision

Use Rust for the implementation and Verus for dependency-free synchronous kernels. The
normal workspace uses B's stable pin; Verus independently pins Rust **1.99.1** for release
**0.2026.10.18.7d82994**. No global rustup replacement or shell-profile changes are required.
The isolated installer supports macOS arm64 and Linux x86_64 with pinned asset digests.
The initial feasibility run proved two small functions with zero errors. The production-source
gate now verifies 51 obligations with zero errors, rejects seven executable semantic mutations,
and compiles/tests the same APIs with the Verus-pinned ordinary Rust compiler.

Proceed with Verus. Use Rust plus Kani only if actual production-kernel proof work establishes
a concrete Verus limitation which cannot be addressed within the stated boundary. A broken
installer or a compiler-pin conflict is not sufficient evidence: fix the isolated tooling first.

## Consequences

Rust ownership helps express non-cloneable capabilities, but cannot establish that caller-supplied
HEAD or filesystem evidence is true. The toolchain split avoids forcing SDK dependencies through
Verus. It costs an additional compiler cache and separate CI installation; upgrades require
re-running positive and negative proof controls. A successful toy proof is a feasibility result,
not formal verification of the archiver. Production-called annotated functions now have connected
proofs; the [design inventory](../design.md#proof-inventory-and-exclusions) lists precise contracts
and excludes unannotated helpers and I/O adapters from the proof claim.
