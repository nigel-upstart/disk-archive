# disk-archive

Owner: disk-archive maintainers · Status: implementation in progress · Updated: 2026-11-25

The Rust application is under development to replace the Python session-log
archiver. It discovers old files, scans and redacts secrets, verifies redaction,
compresses and uploads to S3, verifies the object, then deletes the local file.
Continue developing and testing Rust until it has working parity with the Python
archiver, including the deliberate safety improvements below. Python is a fallback
while Rust reaches that point, not the target for new archiver development.

The Rust CLI can be built and tested on synthetic inputs, but is not ready to run
on real session roots. The sanitized Python copy in this repository is a test
reference, not a runnable fallback: its CLI is disabled. Do not operate on a
running Python archiver or its files while developing the Rust app.

## Safety contract

The Rust app requires verified upload before deletion, injective S3 object keys,
and a change-nothing `--dry-run`. Secret values must never enter logs or state.
The legacy reference does **not** satisfy all these guarantees; its CLI is disabled.

Encoded-secret preflight conservatively blocks and retains files when decoded
redaction is unavailable. A literal secret sharing a JSONL carrier with common
escapes (such as `\\n` or `\\"`) can therefore retain the entire file rather than
redact it; retained files accumulate until offset-aware decoded redaction lands
in [issue #18](https://github.com/nigel-upstart/disk-archive/issues/18). Literal
presence never exempts an encoded copy. NUL-bearing remainders stay one bounded
carrier through EOF; UTF-16 expansion can exhaust its decoded-output budget near
683 KiB, below the 1 MiB allocation ceiling. See [ADR 007](docs/adr/007-bounded-scanner.md).

Never commit `.env`, runtime state, logs, archives, or actual session content.

## Configuration

[`.env.example`](.env.example) contains placeholders only. The Rust app uses
`DISK_ARCHIVE_*` environment variables and gitignored env files. Bucket and prefix
are required, with no defaults. Env-file lookup is `--env-file`, then
`$XDG_CONFIG_HOME/disk-archive/.env`, then `./.env`. See the
[configuration contract](crates/core/README.md) for supported settings. This is
not a production setup or migration guide.

## Development

The [temporary plan](plan/PLAN.md) tracks sequencing; [GitHub issues](https://github.com/nigel-upstart/disk-archive/issues)
are authoritative. Parity is broader than matching redactor output: it also
requires confidence in discovery, scanning, verification, upload, recovery, and
deletion behavior, with the safety changes above. Real-S3 acceptance and migration
guidance remain work to complete before use on real session roots. Every PR must
complete the review loop before merge.

For a local CLI smoke test, first install the pinned development tools and native
prerequisites described by `task doctor`, then run:

```sh
cargo build --locked -p disk-archive --bin disk-archive
python3 crates/archiver/tests/cli.py --binary target/debug/disk-archive
```

The CLI tests use temporary synthetic files and configuration, verify that dry-run
does not modify them, and make no AWS calls. They do not establish full parity.

The stdlib-only synthetic redaction parity check is:

```sh
python3 legacy/python/tests/golden.py --check
```

See [`legacy/python/README.md`](legacy/python/README.md) for reference provenance,
limitations, fixtures, and the optional pytest command. No AWS calls or production
files are involved in the parity check.

## License

[MIT](LICENSE).
