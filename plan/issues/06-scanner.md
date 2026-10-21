<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/6 as opened. The issue is the source of truth; git rm this file when #6 closes or if it drifts. -->

# #6: Replace the trufflehog subprocess with an in-process Rust secret scanner

Part of #1. **Blocked by** #2. It can be developed in parallel with #4 and #5.

## Why

In the legacy run the scan, redact and verify queues stayed saturated while the upload queue sat empty. Starting a `trufflehog` process two or three times per file is the dominant cost. An in-process Rust scanner removes those spawns entirely and makes the verify re-scan cheap.

## Candidates (as of opening this issue)

| Option | Language / license | Status | Notes |
| --- | --- | --- | --- |
| **mongodb/kingfisher** | Rust, Apache-2.0 | Active (v2.14.0 released 2026-10-20) | The `kingfisher-bin` package exposes a `kingfisher` lib target (`src/lib.rs`). Uses `kingfisher-vectorscan`, a Hyperscan fork that needs a C/C++ build. Not on crates.io under that name (crates.io `kingfisher` 0.1.2 is unrelated), so use a git dependency pinned to a tag. The library API is likely not semver-stable. |
| praetorian-inc/noseyparker | Rust, Apache-2.0 | **Archived** | Not a candidate. |
| sirwart/ripsecrets | Rust, MIT | Active, small | Narrow rule set aimed at pre-commit hooks. Too limited as the primary detector. |
| In-house engine | Rust | — | `aho-corasick` keyword prefilter plus `regex::bytes::RegexSet` over a vendored rule set (Kingfisher rules under Apache-2.0 with NOTICE, or gitleaks rules under MIT). Pure Rust, no C++ toolchain, easy to fuzz. |

## Plan

1. **Spike Kingfisher as a library:** can we scan a byte buffer or reader with validation turned off and get the rule ID, line and offsets, and raw match back? Check build time and the native prerequisites on macOS arm64 and on the GitHub-hosted Linux runner.
2. If the library API or build is unsuitable, build the **in-house engine** over vendored Kingfisher rules, keeping a rule-sync script and NOTICE attribution.
3. Record the decision in an ADR.

## Requirements

- **API:** `scan(reader) -> Vec<Finding { rule_id, line, byte_range, raw }>`. It is synchronous and CPU-bound and runs on the bounded blocking pool.
- **Streaming:** multi-GB files are scanned in chunks with overlap of at least the maximum rule match length (or memory-mapped), so memory stays bounded.
- **No network, ever:** credential validation and live checks are disabled at compile time where possible. A test asserts the scanner makes no network calls.
- **Secret hygiene:**
  - raw values are wiped with `zeroize` after redaction
  - they never go into logs, traces or state (ast-grep rule)
  - only rule IDs and counts are persisted
- **Verify stage:** the re-scan happens in-process. Safe skip: if the first scan found nothing **and** redaction made 0 changes, the bytes are unchanged and the re-scan can be skipped. This needs a test and, ideally, a Verus lemma on the kernel's "unchanged" witness.
- **`trufflehog` stays optional:** a `--cross-check trufflehog` backend behind a cargo feature. It is used in CI parity tests and as an opt-in second opinion, never in the hot path.

## Detection parity

- **Planted corpus:** a seeded synthetic corpus with fake secrets covering the detector families seen in agent and terminal logs (cloud keys, GitHub/GitLab tokens, Slack, JWTs, private keys, env-var assignments, DB URLs). Recall must be ≥ `trufflehog` (pinned version, `--no-verification`) for every family.
- **Local-only coverage report:** a script maps the detector **names and counts** in an existing legacy state DB to the new rule IDs. No values are read, and the output is never committed.
- The regex rules in the legacy redactor (env-var assignments and PEM blocks) stay as an extra layer next to the scanner.

## Acceptance criteria

- [ ] The ADR names the chosen scanner, its pinned revision and its native build prerequisites.
- [ ] Hot-path spawn count is 0. The parity tests show recall ≥ `trufflehog` per detector family on the planted corpus.
- [ ] A fuzz target (cargo-fuzz) runs the scanner and redactor on arbitrary bytes with no panics and no input bytes leaking into logs.
- [ ] A no-network test and a zeroize test pass.
- [ ] The perf gate shows scan throughput (MiB/s) and instruction counts for the scanner kernel on the fixed corpus.
