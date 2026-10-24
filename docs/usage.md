# Rust archiver usage

**Owner:** Maintainers · **Status:** Preparation draft; not an operational release guide
**Last updated:** 2026-10-24 · **Links:** [migration and recovery](migration-recovery.md), [core configuration](../crates/core/README.md), [storage](storage.md)

This draft describes the merged G CLI at `204034c3` ([application contract](../crates/archiver/README.md)),
not a validated installation. Do not use it on real roots yet. Finalization requires actual
performance/profiling integration and command validation against that merged source. No cloud,
profiling or benchmark acceptance is established here; no profiling/performance command is
specified ahead of its owner.

## Configuration

Bucket and prefix are mandatory; neither has an identifying default. Source roots and work
location also have no personal defaults. Keep all actual settings in a gitignored `.env`,
never in tracked files, Git history, issue/PR text, command transcripts or diagnostic artifacts.
[`.env.example`](../.env.example) is a placeholder template, not runnable configuration.
Do not put AWS credentials in it.

The read-only loader selects **one** file: explicit `--env-file PATH`; otherwise an existing
`$XDG_CONFIG_HOME/disk-archive/.env`; otherwise an existing `./.env`. A nonempty XDG base must
be absolute. There is no implicit home-directory fallback. Process `DISK_ARCHIVE_*` variables
override the selected file; the files are not merged. Missing explicit or unreadable selected
files fail closed. Relative setting paths resolve against the invocation's working directory,
not the env file's directory. No configuration directory is created during lookup.

Use one `KEY=value` per line. Full-line comments and blank lines are allowed; quoted values
are literal. There is no shell expansion, interpolation, `export`, multiline syntax or inline
comment syntax. Duplicate file keys, unknown app settings, empty optional settings and invalid
values are errors. See the core configuration table for redaction budgets.

| Setting | Operator meaning |
| --- | --- |
| `DISK_ARCHIVE_BUCKET`, `DISK_ARCHIVE_PREFIX` | Required destination and exclusively owned, disjoint object namespace. |
| `DISK_ARCHIVE_ROOTS_ALL_FILES` | Semicolon-separated directories; direct regular files only. |
| `DISK_ARCHIVE_ROOTS_JSONL` | Semicolon-separated directories; recursive `*.jsonl` candidates. |
| `DISK_ARCHIVE_WORK_DIR` | Required for normal operation; private Rust work/state directory outside all source roots. |
| `DISK_ARCHIVE_MIN_AGE_DAYS` | Default 30; strict older-than cutoff, rechecked before processing. |
| `DISK_ARCHIVE_WORKERS` | Default available parallelism capped at 256, fallback 1; CLI `--workers` overrides it. |
| `DISK_ARCHIVE_AWS_PROFILE`, `DISK_ARCHIVE_REGION` | Optional SDK provider selection, not credentials. |
| `DISK_ARCHIVE_CA_BUNDLE` | Additional PEM trust roots; takes precedence over the read-only `AWS_CA_BUNDLE` fallback. |

The native SDK supports environment/shared-file, SSO and role providers, but **not
`credential_process`**. A profile that depends on it cannot be used. SSO authentication is an
explicit operator action outside the archiver (`aws sso login --profile '<profile>'`); it is
not part of dry-run. Native OS roots remain enabled with a CA bundle, and hostname verification
is never disabled. Corporate proxy/keychain acceptance remains separate. Ambient
`AWS_ENDPOINT_URL*` settings are rejected; production endpoint/TLS bypass flags do not exist.

## Metadata-only dry-run

Once the merged CLI is validated, these are the intended invocations for an already-built
binary (angle-bracket arguments are placeholders, not values to paste unchanged):

```sh
disk-archive --help
disk-archive --env-file '<local-env-file>' --dry-run --limit 10
```

Dry-run performs no explicit writes or network operations: no state DB, work directory, lock,
temporary archive or profile file. It returns before runtime, scanner, SDK or credential-provider
initialization and does not read source content. It reports metadata eligibility and retained entries/subtrees;
`redaction=unknown verification=unknown` means those stages did **not** run. It cannot establish
secret cleanliness or predict compression. Filesystem metadata behavior and unrelated readers
remain environmental assumptions; see [ADR 004](adr/004-dry-run.md).

Do not wrap dry-run in output redirection to a new file and call that a no-write system test.
Use an already-built executable when testing the contract: Cargo itself can write build files.
Profiling-enabled builds must preserve the same early return without creating exporters,
listeners or profile artifacts. Profiling commands belong to the separately validated profiling
implementation; none is asserted to work here yet.

## Normal operation: destructive, cooperative ownership required

**Before any normal Rust start, the operator must stop the old Python archiver job and every
eligible writer.** Disable automatic restarts for the cutover. This instruction is not authority
for development workers to inspect, stop or modify production processes or files.

`--quiescent` is an attestation, not a mechanism that freezes writers. Every writer must honor
exclusive advisory locks on the configured root directories, including writes through existing
descriptors or descendant paths. Keep writers stopped unless that protocol is enforced. A work
lock excludes another Rust invocation, not arbitrary writers. Without cooperative ownership,
use metadata-only dry-run; automatic deletion is not safe.

Roots cannot overlap each other or the work directory. Root/descendant directories and files
must belong to the effective user and exclude group/world writes. Every absolute root component
and source-parent component is opened without following symlinks; symlinks, special sources and
multiply linked source files are rejected. Root descriptors/locks stay held through cleanup and
unlink. A fresh upload capability is bound to the source device/inode, size, mtime, ctime and
SHA-256; deletion rehashes the descriptor and compares the pathname's fresh stat before unlink
and parent fsync. These checks do not make unlink atomic against an uncooperative writer or
ancestor namespace changes. Keep that namespace stable; never disable checks to force admission.

The intended small cutover invocation, only after validation and operator approval, is:

```sh
disk-archive --env-file '<local-env-file>' --quiescent --limit 1 --workers 1
```

Normal operation can redact/replace local files before uploading and deleting them. Successful
redaction restores mtime/atime at replacement; later reads may advance atime and ctime changes.
The candidate limit is not a promise of that many successful deletions. `--limit 0` is **not**
dry-run: mutable setup and manifest publication can still occur. Options are strict: unknown,
duplicate, malformed and missing values fail without printing operational values.

`--workers` accepts 1–256; `--queue-capacity` accepts 1–1024. The CLI requires
`--blocking-threads` to be at least workers + 2 (and at most 512). Smaller queues do not remove
per-file scan limits. Defaults are queue capacity = workers and blocking threads = workers + 2.
The merged CLI caps each source/rewrite at 64 MiB; over-budget,
partial, interrupted or unsupported-encoding scans retain the source rather than upload an
unverified result. `UnsupportedEncoding` is a source-retained block, not a successful redaction
or proof of universal scanner completeness. A literal secret in a session-JSON carrier with
escapes can block the entire file; this backlog remains local pending offset-aware redaction
([issue #18](https://github.com/nigel-upstart/disk-archive/issues/18)). Do not upload blocked originals.
The native scanner is in-process and does no credential validation. Optional
TruffleHog comparison is a separate cross-check, never the production hot path or ground truth;
this CLI does not advertise a `--cross-check` option.

Observe `deleted`, `retained` and `namespace_conflicts`, not just the exit status. Keep reports
value-free. Use [recovery](migration-recovery.md) for cancellation, conflicts and retained files.
The 51 synchronous production-source obligations carry Verus proof claims; the async application
and its filesystem, SDK and privacy adapters are tested/reviewed code, not a whole-application theorem.

## Validation still required

The invocation forms above were reconciled with merged `cli.rs`, `main.rs` and configuration
source, not executed in this preparation checkpoint. After performance/profiling merge, validate
help, configuration rejection and metadata-only dry-run using an already-built binary in an
isolated synthetic environment with no ambient credentials or personal configuration. Validate
the normal command only against synthetic roots and the approved loopback SDK fixture, never
by pasting it against live roots or S3. Final hooks, `task check`, CI and independent integrated
review remain required; preparation does not supply those receipts.
