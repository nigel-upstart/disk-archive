#!/usr/bin/env bash
# Run a tool without echoing arguments (which may contain credentials).
set -u
umask 077
pattern=""
if [[ ${1:-} == --success-pattern ]]; then
	pattern=${2:?missing success pattern}
	shift 2
fi
[[ ${1:-} == -- ]] && shift
if (($# == 0)); then
	printf 'usage: quiet-run.sh [--success-pattern REGEX] -- COMMAND [ARGS...]\n' >&2
	exit 2
fi
retention=${TASK_OUTPUT_LOG_RETENTION:-50}
if [[ ! $retention =~ ^[1-9][0-9]*$ ]]; then
	printf 'TASK_OUTPUT_LOG_RETENTION must be a positive integer\n' >&2
	exit 2
fi
log_dir=.task-logs
if [[ -L $log_dir ]]; then
	printf 'refusing symlink log directory\n' >&2
	exit 2
fi
mkdir -p "$log_dir" || exit 2
chmod 700 "$log_dir" || exit 2
log=$(mktemp "$log_dir/run-XXXXXX") || exit 2
# No command line is recorded: credential flags and positional values stay private.
"$@" >"$log" 2>&1
status=$?
if [[ ${TASK_OUTPUT_VERBOSE:-0} == 1 ]]; then
	tail -n +1 "$log"
elif ((status != 0)); then
	printf '%s failed (exit %s); log: %s\n' "${1##*/}" "$status" "$log" >&2
	tail -n 60 "$log" >&2
elif [[ -n $pattern ]]; then
	grep -E -- "$pattern" "$log" || true
fi
# Retain newest logs only; never follow symlinks or remove unrelated files.
python3 - "$log_dir" "$retention" <<'PY'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
logs = sorted(
    (p for p in root.glob("run-*") if p.is_file() and not p.is_symlink()),
    key=lambda p: p.stat().st_mtime_ns,
    reverse=True,
)
for path in logs[int(sys.argv[2]):]:
    path.unlink()
PY
exit "$status"
