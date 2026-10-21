# 002 — Prove pure comparisons and transformations, trust explicit adapters

**Status:** Accepted · **Owners:** Maintainers · **Last updated:** 2026-10-21
**Links:** [design](../design.md), [reference crate](../../crates/verified/src/lib.rs)

## Context & Problem Statement

Deletion, key collisions and redaction have small deterministic cores. Filesystem ownership,
remote checksum authenticity, scanner completeness, cancellation and crash consistency do not.
Claiming one broad theorem would conceal the trusted assumptions rather than reduce them.

## Options Considered

Proving the entire async stack would include the SDK, SQLite, native scanner and platform
filesystem semantics. Proving a separate mathematical sketch is tractable but risks becoming
decorative. Testing alone covers integrations but does not give universal arithmetic or encoding
properties. A small production-connected kernel separates these concerns.

## Decision

Keep `crates/verified` free of all normal, build and dev dependencies. Prove the actual functions
called by core/adapters: strict age cutoff arithmetic, relative-path encoding injectivity,
literal-needle output guards, PEM state transitions, legal state progression and source/evidence
comparisons for deletion. The ordinary Rust reference APIs in this wave are unproved; the
feasibility file is intentionally labelled as disconnected scaffolding for the verifier.

The later proof must cover the production function or a checked extraction consumed by it.
No `assume`, `admit` or external-body escape may silently bridge proof and implementation.
Runtime inputs stay validated: normalized timestamps, valid paths, nonempty needles, trusted
hash/stat/HEAD adapters, and bounded resource budgets.

## Consequences

The literal postcondition means no **supplied** needle occurs in each emitted line, not that a
detector found every secret or that concatenating lines cannot create a cross-boundary match.
Whole-output re-scanning remains mandatory. `VerifiedUpload` binds exact source identity and
remote evidence; consuming it yields a delete permit only after a fresh identity comparison.
Persisted state never grants delete authority.

The shell still owes source ownership through unlink, no-follow opens, stable snapshots,
correct hashing, remote-object binding and durable ordering. A stat/unlink race against arbitrary
writers is outside the theorem and must not be advertised as solved by a token. Integration
tests, fuzzing, fault injection and independent review cover this boundary; they supplement
rather than substitute for the kernel proofs.
