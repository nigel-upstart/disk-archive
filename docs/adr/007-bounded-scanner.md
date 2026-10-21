# 007 — Native Kingfisher detection with bounded streaming admission

**Status:** Implementation under validation (not an issue #6 completion claim)
**Owners:** Maintainers · **Last updated:** 2026-10-21

## Decision

Use Kingfisher's git embedding crates at
`c0a65103432434b2e4f502d519ed25566faa282e`, with default features disabled and
no credential validation features. The catalog stays in that dependency, not a
copied rules directory. Native prerequisites follow [005](005-scanner.md) and
[dependencies](../dependencies.md). No fallback detector or reduced catalog is
selected.

Native block callbacks select a bounded rule bitset; Kingfisher's compiled byte
regexes and capture selector confirm findings. The SDK's whole-input finding
vector is never called. Callback events are capped at 1,048,576 per window;
termination is an error, not a clean result. No raw matches are collected by FFI.

The synchronous reader/callback API borrows UTF-8 values from one fixed zeroizing
window. Matched invalid UTF-8 blocks rather than being lossily converted. Findings
have no Debug, Clone or serialization implementation. Errors contain static codes,
never underlying I/O messages or input. Only rule IDs and counts may be persisted.
`redaction_label()` maps slash IDs to hyphens; IDs over 64 bytes use a rule
fingerprint label. Collisions reject startup. Consumers bound their copied plans.
`Scanner` is compile-time asserted `Send + Sync`: construct one catalog and share
it across bounded workers (for example `Arc<Scanner>`). Native scratch, guard
cache, windows and counters belong to each scan call; no compile-per-file path is
needed. The catalog integration test shares one compiled instance across threads.

## Budgets and boundary contract

Defaults: reads 64 KiB, maximum **full expression** span 1 MiB, physical lines
1 MiB minus one byte excluding LF (aligned with core's 1 MiB including LF),
findings 65,536 per input. The fixed input allocation is 1,114,115 bytes per call. Configured read/match limits cannot
exceed 1 MiB; rules cannot exceed 1,024. Any error blocks the entire input. Partial
callbacks never authorize upload or deletion. The reader may enforce cancellation
between bounded reads; consumers may reject findings. Interrupted I/O means retry.

Finite expressions must declare a maximum within the match budget. Unbounded
line-local expressions use Kingfisher's line-restart certificate and the line
budget. All other unbounded expressions require a bounded, exact-language prefix
monitor provided by `regex-automata` (already transitive through Rust regex).
It is solely a resource-admission guard: it never selects rules, emits findings,
uses a copied catalog, or replaces native Kingfisher detection/confirmation.

The guard uses the original confirmation expressions, Unicode-disabled byte
syntax and UTF-8-disabled NFA semantics, matching Kingfisher's rule builder flags.
Each pattern has its own anchored leftmost-first start; a completed nongreedy
record cannot keep an all-matches suffix alive forever or suppress another rule.
Library-extracted first-byte prefixes only reduce start creation conservatively;
infinite/empty prefixes start on every byte. Every live start advances through
library DFA states. Equal states have
identical futures, so retain the oldest start. A live prefix older than overlap
blocks even if it never forms a complete match. This conservative refusal avoids
silently forgetting a potential giant match or changing greedy-match selection.

NFA construction has a 16 MiB budget, lazy DFA cache 64 MiB, active states 4,096.
These are library heap-accounting budgets, not an exact process-RSS bound;
fixed allocator/native/library overhead remains. **Cache clearing is forbidden**
and every transition checks the clear count before any retained ID is reused.
Cache exhaustion blocks; there is no reset or unbounded growth. Thus memory does
not accumulate with file length. Lookbehind's single input byte is zeroized.

Overlap includes the full expression bound, delayed DFA acceptance and assertion
lookahead. One preceding byte prevents fabricating `^`, `\A` or word boundaries.
Full-match start frontiers and per-rule nonoverlapping endpoints deduplicate
windows. Offsets are absolute bytes; lines are one-based. EOF transitions are
checked before success. Repeated scans never deduplicate prior content away.

## Evidence for the guard choice

The initial eager dense guard exceeded a 64 MiB limit for the combined 45
multiline/unbounded expressions. Individual `betterleaks.azure-tenant-id` and
`betterleaks.canva-client-id` also return `DFAExceededSizeLimit`.

Native streaming was then tested with a narrow safe wrapper-constructor patch
selecting `STREAM | SOM_LARGE` and `SOM_LEFTMOST` patterns. Exact compilation
returns `HyperscanCompile("Pattern is too large.", 1)` for
`betterleaks.aws-session-token`. A repetition-relaxed sentinel advances further
but returns the same native error at index 11, `betterleaks.curl-auth-user`.
Upstream's block database also starts with default byte flags, not UTF8/UCP;
adding those flags would not establish equivalent matching semantics.

Do not broaden away curl line/context constraints, omit these detectors, or
switch native detection off. The temporary wrapper/relaxed-sentinel experiment
was removed rather than vendored indefinitely. A lazy exact guard avoids eager
determinization, leaves all detection expressions intact, and has explicit
exhaustion behavior. Unsupported future rules still fail admission visibly.

## Privacy boundary and outstanding release evidence

The wrapper does not copy finding values. Its input allocation never reallocates
after receiving data; discarded tails are wiped at compaction and Zeroizing wipes
on every exit. This is not an allocator-wide claim about opaque native scratch,
registers, upstream internals or caller buffers. Tests inspect live allocations,
never freed memory. No user callback executes inside native FFI.

Matching conservatively reports syntax: online validation, high-level path/context/
dependency suppression and lossy capture-map/filter construction are not enabled.
No implicit decoder is enabled: opaque JSON Unicode escapes, percent-encoded
credentials and base64 strings are not generally detected. Tests pin these gaps;
the optional TruffleHog comparison reports the same encoded variants separately.
A successful raw-byte scan does not certify decoded representations absent. The
caller must not treat this as an equivalent replacement for all TH decoders.
Core can replace JSON-escaped variants of a value found elsewhere, but that does
not discover an exclusively encoded value. Broader decoding needs a separate
bounded expansion/offset policy, not a silent catalog or hot-path change.

The full 488-rule planted/benign test checks cloud, GitHub, GitLab, Slack, JWT,
private-key and database spans independently. Actual core integration additionally
checks an env-assignment plant, removes every planted value and rescans clean.
Curated prose, code, URLs, configuration, curl and Unicode have zero findings.
Full-catalog 100 KiB and near-1 MiB tool-result JSONL records also scan without
findings using bounded memory. These are resource/usability tests, not throughput
evidence or a claim that production records never exceed the configurable cap.
Streaming tests cover all read splits, sliding frontiers, anchors, EOF exact/over
budgets, UTF-8 splits, nongreedy repeated records, per-rule guard priority and
cache exhaustion. Tests inspect zeroization and forbid Debug findings.

Resolved feature checks and actual syscall/no-network and full-catalog/core fuzz
CI gates are mandatory, not implied by successful unit tests. The opt-in pinned
TruffleHog report contains only names/counts; synthetic placeholders need not be
accepted by its detector filters, so misses do not weaken the independent manifest
gate. Its defaults skip the synthetic cloud/JWT/invalid-key plants; native scanner
and core detect/remove them independently. No production state DB is accessed.
The local-only detector-name/count coverage report is deferred until requested by
the owner with a safe metadata-only snapshot (never the running archiver files).

Issue #6 stays open for scan throughput/instruction evidence from issue #7.
Implementation merge does not claim that future performance acceptance is met.
