# Implementation plan (temporary — see [README](README.md) for lifecycle rules)

## Goal

Port the legacy Python session-log archiver to Rust. The pipeline is: discover old logs → scan
for secrets → redact in place → re-scan to verify → compress and upload to S3 → verify the S3
object → delete the local file. The port adds formally verified safety kernels, strict static
analysis enforced by hooks and CI, and a measurably faster async data plane. The repository
starts private and becomes **public** only after a history audit.

## Locked decisions

| Topic | Decision |
| --- | --- |
| Language | **Rust + Verus.** Fallback if Verus proves impractical: **Rust + Kani** (not Go). |
| Verification scope | Verus proves only the synchronous kernels in `crates/verified`, which has **no third-party dependencies** and is built with the Verus-pinned toolchain. The async shell is covered by tests, lints, fuzzing, and the perf gate. |
| Async and I/O | tokio, with CPU-bound work on a bounded blocking pool (#3). |
| S3 | `aws-sdk-s3` + `aws-config` (#4), and `aws-s3-transfer-manager-rs` as a pinned git dependency. It is a developer preview, and that risk is accepted (#5). **No AWS CLI subprocess backend.** |
| Secret scanning | An in-process Rust scanner (#6). Try the Kingfisher library first; if that fails, build an in-house `RegexSet` + `aho-corasick` engine over vendored rules. `trufflehog` remains only as an optional cross-check. |
| S3 keys | **Fix the legacy collision.** Legacy keys strip every leading `.` from the home-relative path, so `~/.x/f` and `~/x/f` map to the same key. The new layout must be injective, and Verus must prove it. Old and new archives may coexist under different buckets or prefixes; migrating later is fine. |
| `--dry-run` | **Changes nothing**: no in-place redaction, upload, or delete. It reports what would happen. |
| Config | Application-specific settings use only `DISK_ARCHIVE_*` env vars and `.env` (gitignored). Standard AWS credential/profile/region providers and the `AWS_CA_BUNDLE` fallback remain supported per #4, except `credential_process` is excluded. `.env.example` holds placeholders only. Bucket and prefix are required and have no defaults, so the tool refuses to run without them. Lookup order: `--env-file` → `$XDG_CONFIG_HOME/disk-archive/.env` → `./.env`. |
| License | MIT. |
| Commit identity | GitHub noreply address, set in repo-local git config. |
| GitHub Actions | Pin by commit SHA with a `# vX.Y.Z` comment. Check current versions with `gh` and never assume one. |
| Perf testing | A permanent regression gate on a fixed-size GitHub-hosted runner, with no sandbox. The first baseline is recorded **after** the repo goes public (#7). |
| Profiling | An optional `profiling` cargo feature (#8). |
| SBOM | CycloneDX via `cargo-cyclonedx`, validated in CI and attested on release (#2). |

## Legacy behavior to preserve (unless a decision above changes it)

- **Discovery:** all files directly in the "all-files" roots, plus `*.jsonl` found recursively in
  the "jsonl" roots. Regular files only (no symlinks), with mtime older than `min_age_days`. Age is
  re-checked before scanning.
- **Redaction:** streamed line by line with bounded memory.
  - Each finding's raw value is replaced with `[REDACTED-<detector>]`. Replacement also covers the
    JSON-escaped form and multi-line pieces of at least 12 characters, longest match first.
  - Inline PEM private-key blocks and multi-line PEM state are handled.
  - Env-var assignments whose names contain TOKEN, SECRET, PASSWORD, API_KEY, and similar get
    their values replaced.
  - Original timestamps are preserved.
- **Verify stage:** re-scan. If findings remain, drop the offending lines and re-scan once more.
  Anything still remaining marks the file `blocked`: it is not uploaded and not deleted.
- **Upload:** gzip, then upload with `sha256` and `orig-size` metadata and SSE `AES256`. Verify
  with HEAD (length and metadata) before deleting.
- **State:** SQLite, resumable. Statuses: `discovered|scanned|redacted|verified|uploaded|deleted|blocked|error|skipped`.
  Only detector names and counts are stored, never secret values. Files in `error` are retried on
  the next run.
- **Manifest:** a JSON manifest of all state rows is uploaded at the end of a non-dry run.
- **Expected outputs:** golden files generated from the legacy redactor on **synthetic** inputs
  pin these semantics for the Rust port.

## Target layout (to be refined in `docs/design.md`)

```
crates/verified/   Verus kernels: state transitions + VerifiedUpload token, key encoding, needle replacement, PEM line state, age cutoff
crates/core/       config, finding model, streaming redactor using the kernels, scanner integration
crates/storage/    source-bound SDK/TM adapter, bounded gzip spools, actual-checksum HEAD verification, synthetic HTTP/SigV4 fixture
crates/archiver/   bin: tokio pipeline, SQLite state writer, CLI
bench/             corpus generator, criterion + gungraun benches, perf-gate policy/baselines
legacy/python/     sanitized legacy reference — temporary, removed once parity is proven
plan/              this directory — temporary
```

## Quality gates (enforced by lefthook; CI mirrors pre-push as the backstop)

- **pre-commit (fast):**
  - rustfmt, clippy (`-D warnings`; pedantic, plus `unwrap_used`, `expect_used`, `panic`,
    `indexing_slicing`, `print_stdout`, `dbg_macro`, `todo`; `unsafe_code` forbidden), ast-grep
    rules with rule tests, typos, taplo, shellcheck + shfmt
  - gitleaks on staged files, **a `.env` value guard** (fails if any value from the local `.env`
    appears in staged content), block `.env` and large files
- **pre-push (full):** everything above, plus nextest, a coverage threshold, cargo-deny,
  cargo-machete, Verus verification, golden-parity tests, actionlint + zizmor, and SBOM
  generation + validation.
- **ast-grep rules:**
  - subprocesses only in the optional `trufflehog` cross-check module
  - `remove_file` only in the delete stage, which requires `VerifiedUpload`
  - `std::env::var` only in the config module
  - no logging or tracing of finding values
  - no `assume` / `admit` / `external_body` in Verus code except an allowlist
  - no blocking calls inside `async fn`
  - no hard-coded `s3://` literals
- **Quiet wrappers:** a minimal `scripts/quiet-run.sh`, written for this repo. It logs to
  `.task-logs/`, preserves the exit code, supports `TASK_OUTPUT_VERBOSE=1`, and shows failure
  context. Task targets: `setup`, `doctor`, `fmt`, `lint`, `test`, `verify`, `bench`, `sbom`,
  `check`, `clean`.
- **`AGENTS.md`** (with a `CLAUDE.md` symlink) tells agents to run `task doctor` first and
  `task check` before claiming done. It forbids `--no-verify` / `LEFTHOOK=0`, and forbids lint
  suppressions without an ast-grep-checked justification comment. It requires every PR to pass
  `/skill:pr-review-loop` and to update or delete the relevant `plan/` entries.

## Work breakdown and sequencing

- At most **3 subagents run in parallel**.
- Each builder subagent runs `/skill:pr-review-loop` on its own PR until it is green (CI passing,
  no unresolved review threads).
- The orchestrator merges PRs in order and deletes the finished rows below in the merging PR.
- CodeRabbit CLI reviews are staggered to stay inside rate limits; Copilot is the fallback.

Model and effort choices follow the pi router policy (archetype → primary, with fallback in
parentheses). Use the `anthropic/` and `openai-codex/` providers, not Bedrock, for these models.

| Wave | ID | Work | Issues | Archetype | Model @ effort (fallback) | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 2 | F | In-process scanner: Kingfisher library spike → ADR → integration (or the in-house fallback), no-network and zeroize tests, fuzz target, planted-corpus parity versus `trufflehog` | #6 | terminal_heavy_implementation | `openai-codex/gpt-6.1-sol` @ high (`anthropic/claude-opus-5-5` @ high) | todo |
| 3 | G | tokio pipeline, single SQLite writer task, cancellation and lock file, CLI (`--limit`, change-nothing `--dry-run`, `--workers`), manifest, end-to-end tests | #3 | median_repository_implementation | `anthropic/claude-opus-5-5` @ medium (`gpt-6.1-sol` @ high) | todo |
| 3 | I | Perf harness: seeded corpus generator, criterion + gungraun benches, deterministic counters, statistical gate logic, record-only `perf` job | #7 (part) | terminal_heavy_implementation | `openai-codex/gpt-6.1-sol` @ high (`anthropic/claude-opus-5-5` @ high) | todo |
| 4 | R | Independent read-only review, from a different vendor, of the delete-safety, redaction, and cancellation rules across the data plane; findings posted to the open PRs or new issues | — | code_review | `openai-codex/gpt-6-astra` @ high (`gpt-6.1-sol` @ medium) | todo |
| 4 | J | Optional `profiling` feature and `task profile:*` targets | #8 | deliberate_tool_workflow | `openai-codex/gpt-6.1-sol` @ medium (`gpt-5.6-terra` @ high) | todo |
| 4 | K | README usage, migration notes (old and new key layouts), final `AGENTS.md`, remove `legacy/python/` once parity is proven, remove `plan/` items that are done | — | deliberate_tool_workflow | `openai-codex/gpt-6.1-sol` @ medium (`gpt-5.6-terra` @ high) | todo |
| 5 | Z | Pre-publish audit (read-only): gitleaks + trufflehog over the **entire history**, a history search for every local `.env` value and for account IDs and emails, commit-author check, confirmation that no state DBs, logs, archives, or `.env` files were ever committed, review of repo settings | — | highest_risk_advisory | `anthropic/claude-opus-5-5` @ max (`gpt-6-astra` @ high → `gpt-6.1-sol` @ max) | todo |

H implementation lives in `crates/storage` and [docs/storage.md](../docs/storage.md).
Issues #4/#5 retain external real-S3, corporate-proxy and performance acceptance; implementation
merge is not issue closure. Approved audited vendor patches are tracked in
[docs/dependencies.md](../docs/dependencies.md), not a general dependency-policy exemption.

### Dependencies between waves

- **Wave 1:** merge A → B → P.
- **Wave 2:** starts once B and P are merged. D, E, and F own separate crates. D tests against
  P's reference kernels while E replaces them with verified versions.
- **Wave 3:** starts once D and E are merged. H first lands the `ObjectStore` test interface and
  in-process S3 mock seam so G can test without waiting for H's production SDK integration.
  F must be merged before G's end-to-end tests use the in-process scanner. G's implementation
  merge unlocks H's production integration and later profiling; it does **not** close #3.
  Keep #3's final profiling/performance acceptance open until I/J supply the evidence. Issues
  #4/#7/#8 do not require #3 to close before their implementation can proceed.
- **Wave 4:** starts once G and H are merged. I/J results complete #3's remaining acceptance;
  #7 stays open for its post-publication baseline.
- **Before publication:** delete `plan/` in a private cleanup PR before or as part of audit Z.
  Do not wait for epic #1 or #7 to close; their remaining baseline/closure work lives in GitHub.
- **Wave 5, after cleanup and audit Z:** with the owner's explicit approval:
  - `gh repo edit --visibility public --accept-visibility-change-consequences`
  - enable secret scanning and push protection
  - add a branch ruleset that requires CI, including `perf`
  - **record the initial perf baseline** (the last item of #7)
- **Real-S3 smoke test (needs the owner's approval, any time after H):** synthetic roots, a
  dedicated test prefix, and never the real log roots while another archiver is running against
  them.

## Risks

- The Verus toolchain pin may conflict with the AWS SDK's MSRV (1.94.1). The toolchain split
  in #2 mitigates this.
- Kingfisher's library API is binary-first and may not be stable; it also needs a C++ build. The
  in-house engine is the fallback.
- `aws-s3-transfer-manager-rs` is a developer preview with a git-only dependency, kept behind the
  `ObjectStore` trait.
- GitHub-hosted runners are noisy. Gate on deterministic metrics first, and fail time metrics only
  on a confident regression.
- Running three review loops at once can hit the CodeRabbit CLI rate limit. Stagger them and fall
  back to Copilot.
