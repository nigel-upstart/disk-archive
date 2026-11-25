# disk-archive

An agent session-log archiver: discover old files, scan and redact secrets,
verify redaction, compress and upload to S3, verify the object, then delete locally.
Use at your own risk, under active development so backup and be cautious when using 
until you build confidnece on the tool. Redaction is hard.

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

[`.env.example`](.env.example) contains placeholders only. The Rust port will use
`DISK_ARCHIVE_*` environment variables and gitignored env files. Bucket and prefix
are required, with no defaults. Env-file lookup is `--env-file`, then
`$XDG_CONFIG_HOME/disk-archive/.env`, then `./.env`. Parsing and the final optional
settings will land with the config module; this is not a runnable setup guide.

## Development

[GitHub issues](https://github.com/nigel-upstart/disk-archive/issues) are authoritative.

The stdlib-only synthetic redaction parity check is:

```sh
python3 legacy/python/tests/golden.py --check
```

See [`legacy/python/README.md`](legacy/python/README.md) for reference provenance,
limitations, fixtures, and the optional pytest command. No AWS calls or production
files are involved in the parity check.

## License

[MIT](LICENSE).
