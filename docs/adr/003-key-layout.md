# 003 — Canonical versioned percent-encoded S3 keys

**Status:** Accepted · **Owners:** Maintainers · **Last updated:** 2026-10-21
**Links:** [design](../design.md), [key reference](../../crates/verified/src/key.rs)

## Context & Problem Statement

The legacy mapping strips leading dots from a home-relative path. Distinct inputs `.x/f` and
`x/f` therefore collide. Upload verification cannot repair an overwritten archive caused by
that mapping. Arbitrary Unix path bytes and percent signs also need an unambiguous representation
without Unicode normalization or lossy decoding.

## Options Considered

Preserving legacy keys keeps lookup compatibility but knowingly retains collisions. Hash-only
keys avoid path encoding yet hide structure and shift injectivity claims onto collision resistance.
Canonical byte encoding retains readable hierarchy and provides a straightforward inverse.

## Decision

For one configured namespace, encode keys as `prefix/v1/<encoded-root-qualified-path>.gz`.
The shell supplies the normalized absolute source pathname with ONLY its initial filesystem
slash removed, not a home-relative path or basename. Thus distinct configured roots remain
distinct without inventing root IDs; `.codex/x` and `codex/x` retain their dots. The pure encoder
still accepts validated relative bytes, now relative to the filesystem root. Preserve
slashes between validated components. Leave ASCII alphanumerics, hyphen, underscore and dot
unchanged; encode every other byte as uppercase `%HH`, including literal percent and non-UTF8.
Reject empty paths/components, absolute paths, NUL, and components exactly `.` or `..`.
Do not strip dots, normalize Unicode, collapse slashes or truncate keys. Enforce S3's 1024-byte
limit on the complete encoded key including prefix, version and gzip suffix. Prefixes are
explicit nonempty printable ASCII paths with no empty/dot components or trailing slash.

The inverse accepts only canonical encodings by decoding and re-encoding. Wave two proves
`decode(encode(path)) == path` for accepted paths, implying injectivity **for a fixed prefix**.
It does not prove global uniqueness across arbitrary operator-selected namespaces.

## Consequences

Dotfiles, percent-looking names, gzip-looking source names and invalid UTF-8 remain distinct.
Path length expansion is visible and fails closed rather than silently changing identity.
The namespace includes a format version so a future scheme cannot be mistaken for this one.

This deliberately breaks legacy lookup layout. Existing and new archives must use separately
managed buckets/prefixes until an explicit migration is approved; automatically reusing an
overlapping legacy namespace is unsafe. Root selection supplies the full root-qualified path,
not just a basename. This deliberately exposes local usernames/root layout in keys and makes
keys machine/path-dependent. Keys and manifests are sensitive operational metadata, not public
filenames; no such user-specific values belong in repository configuration. An opaque,
host-independent root-ID layout would require a separately versioned design and migration.

Cross-root identity and concurrent-writer exclusion remain adapter/configuration responsibilities.
Write-once uploads refuse a new generation at an already archived path; terminal Deleted history
is preserved and the shell reports a namespace conflict. Operators choose a disjoint namespace
rather than silently overwriting old archive evidence. Encoding alone cannot prevent two
archivers uploading the same logical path at different times.
