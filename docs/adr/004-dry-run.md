# 004 — Dry-run performs metadata-only planning without mutable resources

**Status:** Accepted · **Owners:** Maintainers · **Last updated:** 2026-10-21
**Links:** [design](../design.md), [CLI work](https://github.com/nigel-upstart/disk-archive/issues/3)

## Context & Problem Statement

A dry-run is often implemented by guarding only upload and delete. That still permits in-place
redaction, state-database creation, locks, temporary archives, log files and credential-provider
side effects. Here the contract is stronger: dry-run changes nothing. Even content reads can
update filesystem atime, which makes scanning during a literal no-change run misleading.

## Options Considered

Running the entire pipeline and suppressing final actions exercises more logic but allows
side effects before the guard. Opening SQLite read-only prevents database writes but still
couples planning to mutable setup. A separate metadata-only planning branch limits visibility
but permits a much smaller, auditable no-write surface.

## Decision

Select the dry-run branch immediately after read-only argument/config parsing, before work
directory, database, lock, logger-file, scanner, temporary-file or AWS-client construction.
Report candidate eligibility and intended stages using metadata only and the caller's existing
output stream. Do not read source content, perform redaction, upload, delete, write state,
produce a manifest or initialize credential providers. Report redaction and verification as
unknown, not successful. Explicit config selection must not create configuration directories.

## Consequences

The report answers which old regular files would be considered, not what the scanner would
find or how much compressed output would result. This is a deliberate reduction in dry-run
information to honor the stronger side-effect contract. A future content-inspection command
would need a separate name and an explicit atime caveat; it cannot weaken `--dry-run`.

Integration tests must cover an initially absent state/work directory, an existing database,
invalid/missing config, inaccessible roots, symlinks, and cancellation. They compare contents,
tree entries and timestamps, and assert no mock network requests or write-adapter calls.
Diagnostics may use stderr already opened by the caller, but the archiver must not create a
log file for them. Filesystem metadata APIs and external readers remain environment assumptions;
no claim is made that the archiver controls unrelated processes modifying the same tree.
