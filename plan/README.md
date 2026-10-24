# plan/ — temporary implementation notes

> **These files are temporary.** They exist so that implementation can resume after a session
> restart. They are **not** long-term documentation.

## Lifecycle rules

1. **Delete as you go.** A PR that completes a row in [`PLAN.md`](PLAN.md) deletes that row in
   the same implementation PR, not a separate status-only push.
2. **Delete on drift.** Fix or delete stale guidance in the same PR. Copied issue specifications
   have been removed; authoritative GitHub issues and the concise remaining-blocker table replace them.
3. **Durable decisions move out.** Anything that should outlive implementation goes into
   `docs/adr/`, `docs/design.md`, `AGENTS.md`, or `README.md` before its plan entry is deleted.
4. **Final removal follows audit/public-baseline activation.** Keep unfinished audit, approval
   and public-baseline blockers accurate until those stages complete, then delete `plan/`.
   The repository stays private until the full-history audit and separate owner publication
   approval. Private performance runs are record-only; issue #7's first gating baseline follows
   publication. Lasting acceptance tracking remains in GitHub, not this directory.
5. **No user-specific values.** The repository will be public. Bucket names, profiles, account IDs,
   emails, and home-directory paths belong only in a local, gitignored `.env`.

## GitHub issues are the source of truth

[GitHub issues](https://github.com/nigel-upstart/disk-archive/issues) hold requirements and
acceptance evidence. Do not recreate local mirrors; summarize only unfinished sequencing blockers
in `PLAN.md` and link to the authoritative issue.

## Resuming after a restart

Use current GitHub issues/PRs and actual worktree status rather than a stale ownership mirror.
Inspect preserved branches and uncommitted changes before creating a worker or modifying a branch.

```sh
gh issue list -R nigel-upstart/disk-archive --state open
gh pr list    -R nigel-upstart/disk-archive --state open
git fetch --all --prune && git log --oneline origin/main | head
```

Then open `PLAN.md`, find the earliest wave with open rows, check each open PR's review-loop
status, and continue from there. Every change must pass `/skill:pr-review-loop` before it is
considered green.
