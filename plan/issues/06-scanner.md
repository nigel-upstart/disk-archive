<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/6 (synchronized during PR #9). The issue is the source of truth; git rm this file when #6 closes or if it drifts. -->

# #6: Replace the trufflehog subprocess with an in-process Rust secret scanner

Part of #1. **Blocked by** #2. It can be developed in parallel with #4 and #5.

## Why

In the legacy run the scan, redact and verify queues stayed saturated while the upload queue sat empty. Starting a `trufflehog` process two or three times per file is the dominant cost. An in-process Rust scanner removes those spawns entirely and makes the verify re-scan cheap.

## Candidates (as of opening this issue)

| Option | Language / license | Status | Notes |
| --- | --- | --- | --- |
| **mongodb/kingfisher** | Rust, Apache-2.0 | Active (v2.14.0 released 2026-10-20) | Prefer the versioned `kingfisher-scanner` embedding crate, with `kingfisher-core` and `kingfisher-rules` as needed. Use a git dependency pinned to an immutable commit; confirm crate versions, API stability, and `kingfisher-vectorscan` C/C++ prerequisites during the spike. Do not depend on the full `kingfisher-bin` application, which enables validation. |
| praetorian-inc/noseyparker | Rust, Apache-2.0 | **Archived** | Not a candidate. |
| sirwart/ripsecrets | Rust, MIT | Active, small | Narrow rule set aimed at pre-commit hooks. Too limited as the primary detector. |
| In-house engine | Rust | — | `aho-corasick` keyword prefilter plus `regex::bytes::RegexSet` over a vendored rule set (Kingfisher rules under Apache-2.0 with NOTICE, or gitleaks rules under MIT). `RegexSet` only selects rule indexes; a second pass with per-rule byte `Regex` (or a span-capable matcher) extracts `Finding.byte_range` and `Finding.raw`. Include both passes in the streaming and perf design. Pure Rust, no C++ toolchain, easy to fuzz. |

## Plan

1. **Spike Kingfisher as a library:** can we scan a byte buffer or reader with validation turned off and get the rule ID, line and offsets, and raw match back? Check build time and the native prerequisites on macOS arm64 and on the GitHub-hosted Linux runner.
2. If the library API or build is unsuitable, build the **in-house engine** over vendored Kingfisher rules, keeping a rule-sync script and NOTICE attribution.
3. Record the decision in an ADR.

## Requirements

- **API:** `scan(reader, consume_finding)` emits `Finding { rule_id, line, byte_range, raw }` incrementally through a bounded callback or channel. It is synchronous and CPU-bound and runs on the bounded blocking pool. Consumers must consume or redact each chunk's findings before reading more input; never accumulate all findings or raw values for a whole file.
- **Streaming:** multi-GB files are scanned with bounded memory. Chunked rules declare a finite maximum match length and retain at least that much overlap, with absolute offsets and duplicate suppression. Rules without a finite maximum need a bounded stateful matcher; otherwise scanner configuration fails closed rather than silently omitting a rule. Boundary-spanning fixtures cover each matcher strategy. Memory mapping alone is not a bounded-memory guarantee.
- **No network, ever:** exclude network-capable validation features at build time. For Kingfisher use `default-features = false`, omit `validation` and every `validation-*` compatibility alias, and check the resolved feature graph for accidental enablement. Keep the cross-check backend behind its separate explicit opt-in feature. A test also asserts the scanner makes no network calls.
- **Secret hygiene:**
  - raw values are wiped with `zeroize` after redaction
  - they never go into logs, traces or state (ast-grep rule)
  - only rule IDs and counts are persisted
- **Verify stage:** the re-scan happens in-process. Safe skip: if the first scan found nothing **and** redaction made 0 changes, the bytes are unchanged and the re-scan can be skipped. This needs a test and, ideally, a Verus lemma on the kernel's "unchanged" witness.
- **`trufflehog` stays optional:** a `--cross-check trufflehog` backend behind a cargo feature. It is used in CI parity tests and as an opt-in second opinion, never in the hot path.

## Detection parity

- **Planted corpus:** a seeded synthetic corpus with fake secrets covering the detector families seen in agent and terminal logs (cloud keys, GitHub/GitLab tokens, Slack, JWTs, private keys, env-var assignments, DB URLs). Maintain an independent expected-finding manifest for every planted secret (family and location), and require complete detection for every family by the in-process scanner plus the redactor's extra rules. The pinned `trufflehog` comparison (`--no-verification`) is a parity report, not ground truth; shared misses cannot pass the manifest gate.
- **False-positive bound:** each detector family must produce zero unexpected findings on curated benign fixtures (ordinary prose, code, URLs, and non-secret configuration). Report per-family false-positive counts alongside recall; regression tests must reject broad matches that would cause unrelated redaction or line deletion.
- **Local-only coverage report:** a script maps the detector **names and counts** in an existing legacy state DB to the new rule IDs. No values are read, and the output is never committed.
- The regex rules in the legacy redactor (env-var assignments and PEM blocks) stay as an extra layer next to the scanner.

## Implementation checkpoint (PR #13)

Native Kingfisher v2.20.0 is pinned to 98b67a0211b9818169cb0c3923619c00dd95c98b.
All 502 rules compile, with bounded lazy-DFA admission and callback confirmation.
The Send+Sync catalog is shared across workers; per-call scratch/cache stays local.
Defaults align with core's 1 MiB physical record, with explicit fail-closed caps.
Independent direct plants plus core env rules, benign fixtures, practical JSONL
bounds, zeroization and real core redaction/rescan tests pass locally. Mandatory
Linux syscall and cargo-fuzz gates run in CI; do not infer their result from this note.

Pinned TH 3.99.2 comparison reports direct synthetic cloud/JWT/private-key/env
misses separately; native/core handle these direct plants. Bounded preflight
rescans JSON-Unicode, percent, UTF8/base64 and raw/base64 UTF16LE/BE carriers with
the same catalog. Confirmed decoded secrets block/retain instead of inventing raw
offsets. Budgets fail closed; issue #18 retains offset-aware redaction follow-up.
ADR007 states probe limits, not universal decoder completeness.

**Issue #6 remains open:** throughput and instruction-count acceptance is explicitly
pending the separately assigned issue #7 perf harness. Implementation merge must
not close this issue or remove this mirror.

## Acceptance criteria

- [ ] The ADR names the chosen scanner, its pinned revision and its native build prerequisites.
- [ ] Hot-path spawn count is 0. The independent manifest gate detects every planted secret per family; the pinned, no-verification `trufflehog` comparison is reported separately.
- [ ] A fuzz target (cargo-fuzz) runs the scanner and redactor on arbitrary bytes with no panics and no input bytes leaking into logs.
- [ ] A no-network test and a zeroize test pass.
- [ ] The perf gate shows scan throughput (MiB/s) and instruction counts for the scanner kernel on the fixed corpus.
