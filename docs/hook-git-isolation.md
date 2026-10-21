# Hook repository isolation

**Owner:** Maintainers · **Status:** Accepted · **Last updated:** 2026-10-21
**Links:** [hook wrapper](../scripts/hook-run.sh), [regressions](../scripts/tests/test_hook_env.py)

## Decision

Both Lefthook entries execute the unchanged full gates through `scripts/hook-run.sh`.
The wrapper asks Git for `rev-parse --local-env-vars`, unsets every returned variable
in its own process, then execs the requested command. It retains working directory,
non-Git environment, exit status, and all checks. Enumeration failure is fatal. A partial commit's temporary index is resolved
before cleanup and carried under a private non-Git variable. Only the staged
secret-guard subprocess restores GIT_INDEX_FILE, so it scans the intended commit,
not the default index; unrelated tools never receive that selector.
Scratch Git fixture subprocesses also receive an explicitly isolated environment,
so invoking their tests outside the wrapper cannot select the caller's repository.
This is repository selection isolation, not a hook bypass or a secret filter.

## Incident and evidence

On 2026-10-21, core commit `dc79188` passed pre-commit and its actual pre-push
`task check`. During that push, the linked core branch's reflog recorded reset to
HEAD at 10:12:59Z and reset to FETCH_HEAD at 10:13:00Z. The shared configuration
changed to `core.bare=true`; the remote branch resolved to the older `b724690`
even though push output reported the intended commit. Files and `dc79188` remained
available. Recovery set `core.bare=false` and mixed-reset only the core branch to
`dc79188`, preserving worktree contents. Other worktrees were not reset.

The regression reproduces this mechanism using real installed Lefthook pre-push
hooks in disposable linked worktrees. Unwrapped fixture `git init`, advisory-cache
fetch/reset and bare-cache initialization inherit the hook's GIT_DIR: the source
HEAD, index and shared configuration change. With the wrapper, the same operations
complete in their intended scratch repositories and source HEAD, configuration,
index, staged/unstaged files and primary worktree remain byte-for-byte unchanged.
A real partial-commit regression also confirms a sentinel present only in the
temporary commit index is rejected without exposing its value or changing source
state. No network, production inputs or live repository reset is used for reproduction.
This establishes the inherited-selector failure mechanism; without a process trace
it does not attribute each original command to a specific third-party tool.

## Operational constraints

Install hooks normally with `task setup`. Each worktree must contain the wrapper
and updated Lefthook configuration before pushing. Never disable hooks to work
around environment contamination. On Homebrew, export matching LLVM_COV and
LLVM_PROFDATA in the shell running Git, not just a preceding `task check` command.
After any suspected corruption, preserve commits and worktree files first; obtain
coordination before changing another worker's branch, index or configuration.
