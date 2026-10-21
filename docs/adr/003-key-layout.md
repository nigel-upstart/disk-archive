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

For one configured namespace, encode keys as `prefix/v1/<encoded-relative-path>.gz`. Preserve
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
overlapping legacy namespace is unsafe. Root selection must provide a unique home-relative
source path, not just a basename. Cross-root identity and concurrent-writer exclusion remain
adapter/configuration responsibilities; encoding cannot prevent two archivers uploading the
same logical path at different times.
