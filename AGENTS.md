# Working on disk-archive

- Run `task doctor` first. Install pinned tools with `task setup`; Rust uses
  `rust-toolchain.toml`. Native builds need C/C++, CMake, and pkg-config.
- Run `task check` before claiming completion. Missing tools or skipped proof/parity
  implementation are not a passing verification claim. CI mirrors the full hook.
- Never bypass hooks (including `--no-verify` or `LEFTHOOK=0`). Do not add lint
  suppressions without an immediately preceding `// LINT-JUSTIFICATION: ...`
  comment explaining the concrete reason (at least 20 characters).
- Rust unsafe code is forbidden. Keep `crates/verified` free of dependencies and
  verify it only with its separately pinned Verus toolchain. Do not silently
  substitute a workspace build for proof checking.
- All user-specific configuration belongs in gitignored `.env`; tracked
  `.env.example` contains placeholders only. Never log finding values, credentials,
  or runtime state. Never operate on the running Python archiver or its files.
- Every PR must complete `/skill:pr-review-loop`: prefer included CodeRabbit CLI
  reviews; fall back to Copilot only when necessary. No paid reviews. All CI must
  pass, all findings must be evaluated, and all review threads resolved before merge.
- GitHub issues are authoritative. Remove completed/drifted `plan/` entries;
  move lasting decisions into docs. Do not introduce dependencies without the
  supply-chain gates and immutable git revisions with upstream tracking notes.
- GitHub Actions use immutable SHAs with friendly version comments. Recheck the
  current upstream release before changing pins. Personal-repository permissions
  apply; do not change another organization's allowlist for this repository.
