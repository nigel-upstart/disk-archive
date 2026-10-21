# Restart status — temporary implementation coordination

**Owner:** repository maintainer · **Status:** active, not acceptance evidence
**Last updated:** 2026-10-21 · **Links:** [plan](PLAN.md), [issues](issues/), GitHub PRs/issues

GitHub issues are authoritative. This file preserves broad ownership across restarts;
local `/tmp/disk-archive-coordination/*.md` files hold detailed checkpoints. Delete
this file with `plan/` in the private cleanup before the full-history audit/publication.

## Merged layers

| PR | Layer |
| --- | --- |
| #9 | Temporary plan and authoritative-issue mirrors |
| #10 | Strict workspace, real hooks, CI and CycloneDX scaffolding |
| #11 | Sanitized legacy reference and synthetic golden fixtures |
| #12 | Design contracts, reference kernels, isolated native/proof spikes |
| #14 | Hook Git-environment isolation without bypassing gates |
| #15 | Bounded read-only configuration, streaming redactor and actual golden parity |
| #16 | Production-connected Verus proofs and negative controls |

Main includes these layers. Re-read actual PR bodies and merge commits: a merged
layer does not imply future integration/performance acceptance is complete.

## Active ownership (maximum three workers)

| Worker | Existing checkout / branch | Scope and next handoff |
| --- | --- | --- |
| F | `/tmp/disk-archive-F`, `feat/native-scanner`, draft PR #13 | Finish all scanner CI/privacy/resource/fuzz/review gates. Then own I in the preserved `/tmp/disk-archive-I`, `feat/perf-gate` prototype. Bounded F wait time may advance I sequentially without a fourth worker. |
| H | `/tmp/disk-archive-H`, `feat/sdk-store` | Actual SDK/transfer-manager store, HTTP/TLS mocks, checksum/cancellation/recovery and dependency admission. |
| G | `/tmp/disk-archive-G`, `feat/async-pipeline` | Archiver/CLI, bounded pipeline, durable state, snapshot/deletion safety, actual F/H integration. |

All three currently use `openai-codex/gpt-6.1-sol` at **high** effort. These tasks
combine terminal-heavy native/dependency work with cross-crate security invariants;
that complexity warrants high effort rather than the plan's initial median-task
estimate. Use the router's available fallback, `anthropic/claude-opus-5-5` at high,
if the primary is unavailable; preserve task ownership and checkpoints across a
provider switch. Never launch a duplicate worker to work around a transient error.

F's immutable scanner API/catalog is Send+Sync; share one compiled catalog across
bounded workers. Scratch/cache is per call. Raw-byte detection does not decode
opaque JSON-Unicode/base64/percent encodings (#18). Issue #6 stays open for I's
throughput/instruction evidence; its mirror remains after implementation merge.
H/G own their interfaces; coordinate rather than editing another worker's files.

## Mandatory resume procedure

Before mutating anything, inspect `git worktree list`, every listed implementation
branch's committed and **uncommitted** state, and actual active agent sessions.
Read the corresponding local checkpoints, current GitHub issue/PR bodies, latest
head CI jobs, completed review output and **all paginated review threads**. A stale
note, missing requested-reviewer entry or empty first page is not completion proof.
Recover an existing checkout; do not recreate its library or overwrite dirty work.

Keep at most three workers and four local build jobs per worker. Avoid duplicate
release/profiling/native builds under disk pressure; use GitHub runners for costly
extra work. Never clean another worker's generated output. Run `task doctor` first,
then actual hooks/full `task check`; no bypass, skipped-proof substitution, paid
review credits or weakening gates. Merge unattended only after the real review
loop and every required current-head check is green. Keep PR #13 draft until its
scanner gates actually pass. No live AWS, production input/state or running legacy
archiver operations are authorized.

## Remaining work and final handoff

I resumes its preserved metrics prototype, then builds microkernels, seeded corpus,
comparators and permanent record-only CI. End-to-end evidence must await actual
G/H, not a surrogate. J adds optional profiling; R performs independent cross-vendor
read-only review; K completes usage/migration docs and private plan cleanup; Z audits
the entire history/configuration before explicit publication approval. The initial
performance baseline is recorded **after publication**, not before (#7).

Actual local `.env` configuration remains pending the final handoff. Keep personal
values only in that gitignored file, placeholders in tracked examples, and use a
separate Rust work directory from the running legacy archiver. This status file
contains no personal configuration and grants no runtime-operation authority.
