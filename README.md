# disk-archive

Owner: disk-archive maintainers · Status: implementation in progress · Updated: 2026-10-21

A Rust port of a session-log archiver: discover old files, scan and redact secrets,
verify redaction, compress and upload to S3, verify the object, then delete locally.
The Rust application is not ready for use. Do not run it on real session roots yet.

## Safety contract

The port will require verified upload before deletion, injective S3 object keys,
and a change-nothing `--dry-run`. Secret values must never enter logs or state.
The legacy reference does **not** satisfy all these guarantees; its CLI is disabled.

This repository must remain **private** until a full-history secret/configuration
and author audit is complete and the owner explicitly approves publication.
Never commit `.env`, runtime state, logs, archives, or actual session content.

## Configuration

[`.env.example`](.env.example) contains placeholders only. The Rust port will use
`DISK_ARCHIVE_*` environment variables and gitignored env files. Bucket and prefix
are required, with no defaults. Env-file lookup is `--env-file`, then
`$XDG_CONFIG_HOME/disk-archive/.env`, then `./.env`. Parsing and the final optional
settings will land with the config module; this is not a runnable setup guide.

## Development

The [temporary plan](plan/PLAN.md) tracks sequencing; [GitHub issues](https://github.com/nigel-upstart/disk-archive/issues)
are authoritative. Build tooling, verified kernels, usage, and migration guidance
will land in subsequent PRs. Every PR must complete the review loop before merge.

For now, the stdlib-only synthetic redaction parity check is:

```sh
python3 legacy/python/tests/golden.py --check
```

See [`legacy/python/README.md`](legacy/python/README.md) for reference provenance,
limitations, fixtures, and the optional pytest command. No AWS calls or production
files are involved in the parity check.

## License

[MIT](LICENSE).
