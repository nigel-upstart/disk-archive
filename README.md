# disk-archive

An agent session-log archiver: discover old files, scan and redact secrets,
verify redaction, compress and upload to S3, verify the object, then delete locally.

The Rust application is under development to replace the Python archiver. Continue
developing and testing Rust until it has working parity with Python, including the
deliberate safety improvements. Python is a fallback during that transition, not
the target for new archiver development. The sanitized Python copy in this
repository is a test reference, not a runnable fallback: its CLI is disabled.

Use the tool at your own risk. It is under active development, so keep backups
and be cautious until you have confidence in it. Redaction is hard.

## Safety contract

Encoded-secret preflight conservatively blocks and retains files when decoded
redaction is unavailable. A literal secret sharing a JSONL carrier with common
escapes (such as `\\n` or `\\"`) can therefore retain the entire file rather than
redact it; retained files accumulate until offset-aware decoded redaction lands
in [issue #18](https://github.com/nigel-upstart/disk-archive/issues/18). Literal
presence never exempts an encoded copy. NUL-bearing remainders stay one bounded
carrier through EOF; UTF-16 expansion can exhaust its decoded-output budget near
683 KiB, below the 1 MiB allocation ceiling. See [ADR 007](docs/adr/007-bounded-scanner.md).

## Configuration

[`.env.example`](.env.example) contains placeholders only. The Rust app uses
`DISK_ARCHIVE_*` environment variables and gitignored env files. Bucket and prefix
are required, with no defaults. Env-file lookup is `--env-file`, then
`$XDG_CONFIG_HOME/disk-archive/.env`, then `./.env`. See the
[configuration contract](crates/core/README.md) for supported settings. This is
not a production setup or migration guide.

## Development

[GitHub issues](https://github.com/nigel-upstart/disk-archive/issues) are authoritative.
Parity is broader than matching redactor output: it also requires confidence in
discovery, scanning, verification, upload, recovery, and deletion behavior, with
the intended safety improvements. Real-S3 acceptance and migration guidance remain
work to complete.

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
