# disk-archive

Owner: disk-archive maintainers · Status: implementation in progress · Updated: 2026-10-24

A Rust port of a session-log archiver: discover old files, scan and redact secrets,
verify redaction, compress and upload to S3, verify the object, then delete locally.
The Rust application is not ready for use. Do not run it on real session roots yet.

## Safety contract

The merged pipeline requires verified upload before deletion, injective S3 object keys,
and a metadata-only `--dry-run` with no explicit writes or network initialization.
Normal operation requires cooperative quiescent ownership; these checks do not make
unlink atomic against uncooperative writers. Secret values must never enter logs or state.
The legacy reference does **not** satisfy all these guarantees; its CLI is disabled.

Encoded-secret preflight conservatively blocks and retains files when decoded
redaction is unavailable. A literal secret sharing a JSONL carrier with common
escapes (such as `\\n` or `\\"`) can therefore retain the entire file rather than
redact it; retained files accumulate until offset-aware decoded redaction lands
in [issue #18](https://github.com/nigel-upstart/disk-archive/issues/18). Literal
presence never exempts an encoded copy. NUL-bearing remainders stay one bounded
carrier through EOF; UTF-16 expansion can exhaust its decoded-output budget near
683 KiB, below the 1 MiB allocation ceiling. See [ADR 007](docs/adr/007-bounded-scanner.md).

This repository must remain **private** until a full-history secret/configuration
and author audit is complete and the owner explicitly approves publication.
Never commit `.env`, runtime state, logs, archives, or actual session content.

## Configuration

[`.env.example`](.env.example) contains placeholders only. The Rust configuration uses
`DISK_ARCHIVE_*` environment variables and gitignored env files. Bucket and prefix
are required, with no defaults. The read-only loader selects one file: `--env-file`, then an existing
`$XDG_CONFIG_HOME/disk-archive/.env`, then an existing `./.env`; process app settings override it.
See [core configuration](crates/core/README.md) for the implemented syntax and limits.
This is not yet a runnable setup guide.

## Operator documentation (preparation only)

Draft [usage/configuration](docs/usage.md) and [migration/recovery](docs/migration-recovery.md)
guides describe merged pipeline behavior. They are not authorization to run on real
roots; final command validation waits for actual performance and profiling integration.
Before any normal Rust start, the operator must stop the old Python job and eligible writers.
Development workers must not stop or operate on them.

## Development

The [temporary plan](plan/PLAN.md) tracks sequencing; [GitHub issues](https://github.com/nigel-upstart/disk-archive/issues)
are authoritative. Workspace tooling, core configuration/redaction, synchronous production-source
Verus proofs, storage integrity adapters and the async pipeline are merged. Performance/profiling
integration and final independent cross-vendor review remain open. Only the 51 annotated
synchronous production-source obligations are verified, not the whole async application.
Every PR must complete the review loop before merge.

For now, the stdlib-only synthetic redaction parity check is:

```sh
python3 -B legacy/python/tests/golden.py --check
python3 -B scripts/frozen-oracle.py
```

See [`legacy/python/README.md`](legacy/python/README.md) for reference provenance,
limitations, fixtures, and the optional pytest command. The lasting [frozen-oracle provenance](docs/redaction-oracle.md)
explains the copied fixtures and real Rust comparison. Integrity-only checking is not Rust
parity; reference retirement is pending a fresh Rust test. No AWS calls or production
files are involved in these checks.

## License

[MIT](LICENSE).
