# 007 — Native Kingfisher callbacks with fail-closed streaming budgets

**Status:** Implementation under validation (not an issue #6 completion claim)
**Owners:** Maintainers · **Last updated:** 2026-10-21

## Decision

Use Kingfisher's pinned git embedding crates at
`c0a65103432434b2e4f502d519ed25566faa282e`, with default features disabled and
no credential validation features. Keep the catalog in the dependency, not a
copied rules directory. Native prerequisites and provenance follow
[005](005-scanner.md) and [dependencies](../dependencies.md).

The production adapter uses the native block-scanner callback to populate a
bounded rule-selection bitset, then Kingfisher's compiled byte regexes and capture
selector to confirm findings. It never calls the SDK's whole-input vector API.
Native callback events are capped at 1,048,576 per window; a terminated search is
an error, not a clean result. No raw matches are collected by the native callback.

The synchronous reader/callback API borrows UTF-8 values from one fixed zeroizing
window. A matched invalid-UTF-8 value blocks rather than being lossily converted.
Findings have no Debug, Clone or serialization implementation. Errors contain
static codes, never underlying I/O messages or input. Rule IDs and counts alone
may be persisted. The separate `redaction_label()` maps catalog ID slashes to
hyphens for the verified needle kernel; duplicate labels reject configuration.

## Resource and boundary contract

Defaults: 64 KiB reads, 64 KiB maximum **full expression** span (not just the
secret capture), 32 KiB physical lines excluding LF, 65,536 findings per input.
Configured read/match limits cannot exceed 1 MiB; rule count is at most 1,024.
Any budget excess blocks the entire file. Partial callbacks never authorize
upload or deletion. Consumers must additionally bound any copied redaction plan.
Cancellation can be enforced by the reader between bounded reads, or by returning
a consumer error; an interrupted I/O error means retry, not cancellation.

Finite expressions must declare a maximum within the match budget. Unbounded
line-local expressions use Kingfisher's line-restart certificate plus the line
budget. Other unbounded expressions require a bounded stateful **prefix guard**:
a combined anchored DFA tracks live expression starts, merging equal states by
the oldest start. A live prefix older than the retained window blocks even if it
never becomes a full match. This is deliberately conservative. The guard does
not detect or emit secrets; native Kingfisher remains the detector. DFA/compiler
limits are 64 MiB final DFA, 128 MiB determinization and 4,096 live states.
Unsupported guards reject scanner configuration; no rule is silently omitted.

Overlap includes the full expression bound, one delayed DFA acceptance byte and
assertion lookahead. One preceding byte is retained so window starts cannot
fabricate `^`, `\A` or word boundaries. Findings are owned by their full-match
start frontier, and per-rule nonoverlapping endpoints prevent duplicates.
Offsets are absolute bytes, lines are one-based. Repeated scans have no content
deduplication, so verification cannot hide a previously observed finding.

## Privacy boundary and outstanding evidence

The adapter makes no owned copies of finding values. Its input allocation never
reallocates after receiving data; discarded tails are wiped at compaction and
`Zeroizing` wipes on every exit, including consumer/read errors. The prefix
guard's single lookbehind byte is also wiped. This is not a claim about opaque
native scratch, allocator pages, CPU registers, upstream internals, or caller
buffers. Synthetic live-allocation tests must not dereference freed memory.

The adapter currently reports conservative syntax matches: upstream online
validation, path/context/dependency suppression and lossy capture-map/filter
construction are not enabled. Independent planted and benign manifests, feature
graph checks, runtime no-network audit, scanner/redactor fuzzing, throughput and
instruction counts remain release gates, not assumptions. Full-catalog startup
and bounded-rule feasibility are being measured before this ADR is finalized.
