<!-- Mirror of https://github.com/nigel-upstart/disk-archive/issues/7 (synchronized during PR #9). The issue is the source of truth; git rm this file when #7 closes or if it drifts. -->

# #7: Permanent performance regression gate on fixed-size GitHub-hosted runners

Part of #1. Micro-benchmarks can start as soon as the kernels exist. End-to-end metrics depend on the implementations from #3, #4, #5 and #6, not on #3's issue closure. Record-only results help complete #3's acceptance; this issue stays open for the post-publication baseline.

## Goal

A **permanent** performance test: the first values recorded become a ceiling that later changes may not confidently exceed. It runs on a **fixed-size GitHub-hosted runner** (no bubblewrap or other sandbox; the runner itself is the fixed-resource environment).

## Environment

- A dedicated `perf` workflow job on a pinned runner image (e.g. `ubuntu-24.04`, never `-latest`). It is a required check on PRs.
- Every result carries an **environment fingerprint:** runner image version, `nproc`, total memory, CPU model, kernel, `rustc` version, and the scanner rules revision.
  - **Time-based** metrics gate only against a baseline with the same CPU model and `nproc`. On a mismatch they are reported as advisory.
  - **Instruction counts and cache estimates** gate only with a matching compiler toolchain fingerprint (rustc/LLVM version and build flags/profile). A mismatch requires an explicit reviewed baseline refresh before those metrics can gate; CI never refreshes automatically.
  - **Exact behavioral counters** gate regardless of the hardware fingerprint.
- GitHub-hosted runner sizes differ between private and public repositories, so the **initial baseline is captured after the repository goes public**. Until then the job runs record-only.

## Metrics

1. **Deterministic, hard gate with tight tolerance (~1–2%):** instruction counts and cache estimates via `gungraun` (Callgrind, Linux only) for these kernels:
   - redaction (needle build plus line rewrite)
   - scanner over a fixed buffer
   - gzip plus sha256 over a fixed buffer
   - trufflehog/JSON finding parsing, if still present
2. **Deterministic counters, exact gate:**
   - hot-path process spawns (must be 0)
   - S3 requests per object (by size class)
   - bytes uploaded
   - peak temp-disk bytes
3. **Statistical gate:** end-to-end **wall time** and **CPU time (user + sys)**, plus **peak RSS** and voluntary/involuntary **context switches** (`getrusage`). These are measured over N runs on a seeded synthetic corpus against the in-process S3 mock.
   - **Fail only when confidently regressed:** the 95% bootstrap CI of the new median must lie entirely above `baseline_median × (1 + tolerance)`. Tolerances are set per metric in `bench/policy.toml`.
   - If a time metric fails, the job reruns that metric once before failing, to rule out noisy neighbors. Deterministic metrics are never rerun.

## Baselines

- `bench/baseline/<fingerprint>.json` is committed with the raw samples, the summary statistics and the commit it came from.
- **CI never raises a baseline.** A deliberate regression needs a PR labelled `perf-baseline-change` with a written justification and CODEOWNERS approval.
- **Ratchet down:** when a metric improves beyond tolerance, the job posts a suggestion and `task bench:ratchet` opens the tightening PR. Lower baselines are accepted after review.

## Corpus

- A deterministic, seeded generator (`bench/corpus`) produces jsonl and log files whose size distribution mirrors real agent and terminal logs: many small files plus a few large ones.
  - The total is capped to fit runner disk and time budgets.
  - It includes planted fake secrets and PEM blocks.
- The corpus is generated at runtime and never committed. The generator version is part of the fingerprint.

## Local developer loop

- `task bench`: criterion benchmarks with confidence intervals, for quick feedback.
- `task bench:gate`: the same comparison logic. On macOS it is advisory only (the fingerprint won't match, and Valgrind doesn't support macOS arm64, so `gungraun` runs in CI only).
- Every gate result is summarized in one line through the quiet wrapper; full output goes to `.task-logs/`.

## Acceptance criteria

- [ ] The `perf` job exists, is a required check, and writes a summary table to the job summary.
- [ ] **Self-test:** a throwaway PR that injects a regression (extra allocation per line, an artificial sleep, a re-introduced subprocess) fails the gate on the matching metric.
- [ ] **Noise study:** 10 reruns on unchanged `main` produce zero false failures. Record the tolerances that came out of it in `bench/policy.toml`.
- [ ] The initial baseline is committed after the visibility flip, including a legacy-equivalent comparison run (`trufflehog` cross-check backend, same worker counts).
