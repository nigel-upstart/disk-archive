# Core contracts

`Config::load` is read-only. Process `DISK_ARCHIVE_*` settings override the selected
file; file selection is explicit `--env-file`, existing absolute
`$XDG_CONFIG_HOME/disk-archive/.env`, then `cwd/.env`. Missing explicit files,
unreadable selected files, duplicates, unknown settings and invalid values fail
closed. No files/directories/locks/databases are created. Settings in `.env` are
one `KEY=value` per line; blank lines and full-line `#` comments are allowed.
Single/double quotes delimit literal values, not shell strings. No interpolation,
export, escapes, inline comments or multiline values. Global environment is never
modified. Standard AWS credentials stay with the SDK provider chain.

Required: `DISK_ARCHIVE_BUCKET`, `DISK_ARCHIVE_PREFIX`. Optional:

| Suffix after `DISK_ARCHIVE_` | Default / contract |
| --- | --- |
| `AWS_PROFILE`, `REGION` | absent: SDK provider chain |
| `CA_BUNDLE` | absent; read-only `AWS_CA_BUNDLE` fallback, relative paths resolve against cwd |
| `ROOTS_ALL_FILES`, `ROOTS_JSONL` | empty list when absent; `;`-separated paths when set |
| `WORK_DIR` | absent; real execution must require it in shell |
| `MIN_AGE_DAYS` | 30; checked conversion to seconds, 0 allowed |
| `WORKERS` | available parallelism capped at 256, fallback 1; explicit values 1–256 |
| `MAX_LINE_BYTES` | 1 MiB; max 16 MiB |
| `MAX_OUTPUT_LINE_BYTES` | 4 MiB; max 64 MiB (includes intermediates) |
| `MAX_FINDINGS` | 256 raw variants; max 4096 |
| `MAX_FINDING_BYTES` | 256 KiB total raw UTF-8; max 1 MiB |
| `MAX_DERIVED_NEEDLES` | 256 conservative candidates; max 1024 |
| `MAX_LITERAL_COPY_BYTES` | 64 MiB literal copy traffic per line; max 1 GiB |
| `MAX_DROP_LINES` | 4096; max 65536 |

All budgets are positive. Empty optional values are invalid. Relative setting
paths resolve against supplied absolute cwd. Paths containing `;` cannot be represented in
root lists. No personal roots, work directory or destination defaults exist.

## Redaction and scanner seam

Feed `&FindingRaw { label, raw }` into `PlanBuilder::push` from F's bounded
scanner callback; feed raw-v2 separately in original order. Never accumulate an
unbounded whole-file `Vec<Finding>`. A failed callback poisons the builder even if
a caller accidentally ignores the error. Stop scanning on budget exhaustion and
block the file. Before kernel construction, derived candidates are conservatively
counted as two full forms plus raw line pieces (all controls count as delimiters;
short/duplicate pieces still consume budget). JSON ensure_ascii has no physical
line delimiters, so its only piece duplicates its full form. This caps quadratic
kernel deduplication and the number of replacement passes, not just stored bytes.
The literal intermediate cap is additionally reduced to copy_budget/(candidates+1):
one initial copy plus one rebuild per needle cannot exceed the logical literal
copy-traffic budget. An input/output exceeding that reduced cap blocks. This is
not a CPU-instruction/time theorem or a budget for regex work/comparison lengths.
Labels are safe ASCII, at most 64 bytes. Raw accumulator, physical-line and core-owned intermediate
buffers use `zeroize`. The standard-library reader buffer is not zeroized; the
dependency-free kernel attempts best-effort Drop wiping only, which may be
optimized away and does **not** promise allocator-level zeroization. No raw-bearing type implements Debug
or serialization; errors contain static categories, never source or I/O details.

`RedactionPlan::redact(Read, Write)` buffers one bounded physical line and bounded
intermediate transformations. Ordering matches Python: explicit drops, active PEM
resume, kernel literals (raw/JSON forms/multiline pieces), inline PEM, unmatched
BEGIN, env assignments, then mandatory kernel literal guard. The final guard is an
intentional security improvement over legacy marker-collision behavior. The
count reports replacements, plus separate final-guard dropped-line telemetry.
Binary input, CRLF and absence of a final newline are supported.

An error invalidates **all** partial output. Never upload/replace from that sink.
Success is not verification: rescan the complete output, drop offending lines on
one fallback pass, then rescan again; still-detected, partial or failed scans are
blocked. Whole-output scanning is essential for cross-line needles and detector
completeness. Core grants no upload/delete token. G owns stable source snapshots,
timestamp restoration and atomic replacement, and selects metadata-only dry-run
before constructing writable resources. Config loading alone is not an end-to-end
dry-run test.

`age` and `key` are direct reexports of production kernel APIs. Checked day
conversion is in config; strict cutoff arithmetic and injective percent-encoded
`prefix/v1/...gz` keys are not reimplemented here. Production-kernel Verus proofs
remain E's responsibility.

## Tests

`cargo test -p disk-archive-core --test golden golden_parity` consumes all 16 shared
synthetic Python fixtures and checks bytes and counts. The Python generator also
checks timestamp restoration; Rust core does no filesystem rewriting. Generated,
deterministic property sweeps exercise literal escaping, chunk boundaries, key
injectivity/round trips, cutoff extremes, budget exhaustion, marker collisions,
and value-free I/O failures. They are reproducible without ambient input or
production credentials. Full shell/scanner integration remains G/F work.
