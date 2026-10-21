#!/usr/bin/env bash
# Git exports repository-local variables to hooks. Child tools may operate on OTHER
# repositories (advisory databases, dependency clones, synthetic test fixtures).
# Do not let their git -C/init/fetch/reset accidentally select this repository.
set -euo pipefail

if (($# == 0)); then
	printf 'hook-run: command required\n' >&2
	exit 2
fi
# Partial commits use a temporary index. Preserve its identity under a NON-Git
# name, restored only inside this repository's staged secret guards, never tools
# which may initialize/fetch other repositories. Ignore any preexisting proxy.
unset _DISK_ARCHIVE_HOOK_INDEX_FILE
if [[ -n ${GIT_INDEX_FILE-} ]]; then
	_DISK_ARCHIVE_HOOK_INDEX_FILE=$(git rev-parse --path-format=absolute --git-path index)
	export _DISK_ARCHIVE_HOOK_INDEX_FILE
fi
# Capture first: a failed enumeration must not silently run a contaminated command.
git_local_vars=$(git rev-parse --local-env-vars)
while IFS= read -r name; do
	if [[ -n $name ]]; then
		unset "$name"
	fi
done <<<"$git_local_vars"

# Run the exact requested gates, preserving status and the hook's working directory.
exec "$@"
