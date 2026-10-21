# plan/ — temporary implementation notes

> **These files are temporary.** They exist so that implementation can resume after a session
> restart. They are **not** long-term documentation.

## Lifecycle rules

1. **Delete as you go.** A PR that completes a row in [`PLAN.md`](PLAN.md) deletes that row in
   the same PR. A PR that closes a GitHub issue runs `git rm` on its mirror in [`issues/`](issues/).
2. **Delete on drift.** If a file here no longer matches what was decided (in the GitHub issue, an
   ADR, or the code), fix it in the same PR or `git rm` it. Never leave stale guidance behind.
3. **Durable decisions move out.** Anything that should outlive implementation goes into
   `docs/adr/`, `docs/design.md`, `AGENTS.md`, or `README.md` before its plan entry is deleted.
4. **The directory goes away before publication.** Delete `plan/` entirely before or as part of
   the final private pre-publish cleanup/audit. Do not wait for epic #1 to close: its #7 baseline
   intentionally follows publication. Keep all remaining work in the authoritative GitHub issues.
5. **No user-specific values.** The repository will be public. Bucket names, profiles, account IDs,
   emails, and home-directory paths belong only in a local, gitignored `.env`.

## GitHub issues are the source of truth

The files in `issues/` mirror GitHub issues #1–#8 and are synchronized when their requirements change. If an issue and its
mirror disagree, the issue wins, and the mirror should be fixed or deleted.

## Resuming after a restart

```sh
gh issue list -R nigel-upstart/disk-archive --state open
gh pr list    -R nigel-upstart/disk-archive --state open
git fetch --all --prune && git log --oneline origin/main | head
```

Then open `PLAN.md`, find the earliest wave with open rows, check each open PR's review-loop
status, and continue from there. Every change must pass `/skill:pr-review-loop` before it is
considered green.
