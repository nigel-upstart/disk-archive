# Remaining implementation work (temporary)

**Owner:** Maintainers · **Status:** Restart aid, not completion evidence
**Last updated:** 2026-10-24 · **Links:** [lifecycle](README.md), [authoritative issues](https://github.com/nigel-upstart/disk-archive/issues), [durable design](../docs/design.md)

Only unfinished work belongs here. Configuration/redaction, native scanning, storage,
metrics, synchronous production-source proofs and the async pipeline are merged. Their
implementation does not close dependent acceptance. Do not recreate copied issue specifications.

## Remaining blockers

| Work | Remaining acceptance | Authoritative issue |
| --- | --- | --- |
| Performance | Integrate the actual collectors and validate hosted measurements, noise and real-regression controls. Private runs remain record-only; the first enforcing baseline follows publication. | [7](https://github.com/nigel-upstart/disk-archive/issues/7), [3](https://github.com/nigel-upstart/disk-archive/issues/3) |
| Profiling | Integrate actual application instrumentation; validate documented commands and synthetic artifacts. Helper tests are not end-to-end profile evidence. | [8](https://github.com/nigel-upstart/disk-archive/issues/8), [3](https://github.com/nigel-upstart/disk-archive/issues/3) |
| Operator docs / reference retirement | Finish draft usage/migration/recovery after performance/profiling merge and command validation. Preserve all 16 frozen goldens/provenance; freshly pass the real Rust comparison before deleting the sanitized reference. | [epic](https://github.com/nigel-upstart/disk-archive/issues/1) |
| Encoded redaction | Offset-aware decoded redaction remains follow-up work. Unsupported carriers retain sources and can accumulate a session-JSON backlog; merged blocking controls are not universal scanner completeness. | [18](https://github.com/nigel-upstart/disk-archive/issues/18) |
| Independent safety review | Final integrated cross-vendor review remains open. Genuine earlier Anthropic reviews do not supply final approval; later OpenAI-routed reviews must not be labeled Anthropic. | [epic](https://github.com/nigel-upstart/disk-archive/issues/1) |
| Storage external acceptance | Separately authorized synthetic real-S3 conditional-write/checksum/version/cancellation and corporate-proxy tests; no production roots. | [4](https://github.com/nigel-upstart/disk-archive/issues/4), [5](https://github.com/nigel-upstart/disk-archive/issues/5) |
| Supply chain | Final dependency graph, expiring exceptions, complete gates/SBOM/attestation and acceptance evidence. | [2](https://github.com/nigel-upstart/disk-archive/issues/2), [17](https://github.com/nigel-upstart/disk-archive/issues/17) |
| History/configuration audit | Entire history, decoded fixtures, author identity, settings and forbidden runtime/configuration artifacts; value-free findings. Staged scanning and safety reviews do not replace this audit. | [epic](https://github.com/nigel-upstart/disk-archive/issues/1) |
| Publication / baseline | Separate owner approval after audit, then public security/required-check activation and a reviewed public-runner baseline. No publication approval exists. Final plan removal follows audit/public-baseline activation. | [7](https://github.com/nigel-upstart/disk-archive/issues/7), [epic](https://github.com/nigel-upstart/disk-archive/issues/1) |

At most three workers may be active; current assignments prohibit children. Coordinate shared
gates/manifests/tasks and build-cache windows. Never operate on live Python processes, source,
environments, databases, logs, archives or roots. GitHub issues, not this table, are authoritative.
Do not close unfinished integration issues merely because their implementation PR merged.

Every PR needs real hooks, `task check`, green CI and the complete review loop: authenticated
included CodeRabbit CLI first, immediate Copilot fallback on rate limit, no paid credits or
bypasses. Final documentation integration follows actual performance/profiling merges and
command validation. Local disk constraints do not turn skipped checks into passes.

## Durable contracts

Use [design/proof scope](../docs/design.md), [ADRs](../docs/adr/001-rust-and-verus.md),
[application ownership/manifest protocol](../crates/archiver/README.md),
[storage](../docs/storage.md) and [dependency tracking](../docs/dependencies.md).
[Usage](../docs/usage.md) and [migration/recovery](../docs/migration-recovery.md) remain drafts.
Review permission is not permission for production operations, real-S3 acceptance or publication.
