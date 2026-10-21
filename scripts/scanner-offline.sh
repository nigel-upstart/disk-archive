#!/usr/bin/env bash
# Synthetic planted catalog only. Never point this test at runtime logs/state.
set -euo pipefail
mkdir -p target
cargo test -p disk-archive-scanner --test catalog --locked --no-run --message-format json >target/scanner-test-build.json
binary=$(
	python3 - <<'PY'
import json
from pathlib import Path
artifacts = [json.loads(line) for line in Path('target/scanner-test-build.json').read_text().splitlines()]
paths = [item['executable'] for item in artifacts if item.get('reason') == 'compiler-artifact' and item.get('executable') and item.get('target', {}).get('name') == 'catalog']
if len(paths) != 1:
    raise SystemExit('expected one scanner catalog test binary')
print(paths[0])
PY
)
case $(uname -s) in
Linux)
	command -v strace >/dev/null
	# Separate namespace prevents egress; syscall trace also rejects attempted
	# network calls, not merely successful connections. CI has passwordless sudo.
	sudo -n unshare --net -- strace -f -qq -e trace=network,execve,execveat -e raw=all -o "${PWD}/target/scanner-network.trace" "$binary" --exact planted_and_benign_catalog
	python3 - <<'PY'
from pathlib import Path
lines = Path('target/scanner-network.trace').read_text().splitlines()
# The audited binary itself is exec'd once by strace. No descendant execs or
# network calls are permitted. raw=all records pointers, never argv/input bytes.
if len(lines) != 1 or ' execve(' not in lines[0] or not lines[0].endswith(' = 0'):
    raise SystemExit('scanner network/process audit failed (raw-pointer trace under target)')
print('Native scanner syscall audit: network=0; hot-path subprocess execs=0')
PY
	;;
Darwin)
	# Local denial smoke; the Linux syscall audit is the stronger CI gate.
	/usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network*)' "$binary" --exact planted_and_benign_catalog
	;;
*)
	printf 'unsupported platform for mandatory scanner network audit\n' >&2
	exit 1
	;;
esac
