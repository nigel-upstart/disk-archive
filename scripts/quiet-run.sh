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
active=$(mktemp "$log_dir/active-XXXXXX") || exit 2
log=$log_dir/run-${active##*-}
# Active logs remain outside retention until command output has been displayed.
# No command line is recorded: credential flags and positional values stay private.
"$@" >"$active" 2>&1
status=$?
if [[ ${TASK_OUTPUT_VERBOSE:-0} == 1 ]]; then
	tail -n +1 "$active"
elif ((status != 0)); then
	tail -n 60 "$active" >&2
elif [[ -n $pattern ]]; then
	grep -E -- "$pattern" "$active" || true
fi
# Serialize publication/pruning; active logs can never be a cleanup candidate.
python3 - "$log_dir" "$retention" "$active" "$log" <<'PY'
import fcntl
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
with (root / ".retention.lock").open("a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    completed = pathlib.Path(sys.argv[4])
    pathlib.Path(sys.argv[3]).rename(completed)
    completed.touch()
    logs = sorted(
        (p for p in root.glob("run-*") if p.is_file() and not p.is_symlink()),
        key=lambda p: p.stat().st_mtime_ns,
        reverse=True,
    )
    for path in logs[int(sys.argv[2]):]:
        path.unlink()
PY
if [[ ${TASK_OUTPUT_VERBOSE:-0} != 1 ]] && ((status != 0)); then
	printf '%s failed (exit %s); log: %s\n' "${1##*/}" "$status" "$log" >&2
fi
exit "$status"
