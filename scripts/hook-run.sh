#!/usr/bin/env bash
# Git exports repository-local variables to hooks. Child tools may operate on OTHER
# repositories (advisory databases, dependency clones, synthetic test fixtures).
# Do not let their git -C/init/fetch/reset accidentally select this repository.
set -euo pipefail

if (($# == 0)); then
	printf 'hook-run: command required\n' >&2
	exit 2
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
