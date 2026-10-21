#!/usr/bin/env bash
# Optional caller-side tools only. The archiver hot path never spawns them.
set -euo pipefail
mode=${1:?profile mode required}
case "$mode" in cpu | trace | heap | console) ;; *)
	printf 'Unknown profile mode\n' >&2
	exit 2
	;;
esac
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
if [[ ! -f crates/archiver/examples/profile-corpus.rs ]]; then
	printf 'The real G/H synthetic profile driver is not integrated yet; no surrogate run is available.\n' >&2
	exit 1
fi
features=profiling
if [[ $mode == heap ]]; then features=profiling-heap; fi
if [[ $mode == console ]]; then
	features=profiling-console
	# Console is intentionally a distinct, explicitly unstable build.
	export RUSTFLAGS="${RUSTFLAGS:-} --cfg tokio_unstable"
fi
# Native dependencies share the ordinary debug cache. No duplicate release profile.
cargo build --locked -p disk-archive --example profile-corpus --features "$features"
target_dir=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
binary="$target_dir/debug/examples/profile-corpus"
umask 077
mkdir -p profiles
run_dir=$(mktemp -d "$root/profiles/$mode-XXXXXXXX")
mkdir "$run_dir/home"
# Deliberately no AWS_*, DISK_ARCHIVE_*, XDG_*, RUST_LOG or ambient HOME/dotenv.
# The driver takes only a mode/output directory and constructs synthetic roots,
# native scanner and the real SdkStore injected with H's localhost MockS3 client.
clean=(env -i "PATH=$PATH" "HOME=$run_dir/home" "TMPDIR=$run_dir/home")
case "$mode" in
trace | heap)
	"${clean[@]}" "$binary" "$mode" "$run_dir"
	python3 scripts/profile-validate.py "$mode" "$run_dir/$mode.json"
	;;
console)
	printf 'Attach with: tokio-console http://127.0.0.1:6669 (synthetic run, bounded to 30 seconds)\n'
	"${clean[@]}" "$binary" console "$run_dir"
	;;
cpu)
	case $(uname -s) in
	Darwin)
		mise -E profiling exec -- samply record --save-only -o "$run_dir/cpu.json" -- "${clean[@]}" "$binary" cpu "$run_dir"
		python3 scripts/profile-validate.py cpu "$run_dir/cpu.json"
		;;
	Linux)
		# perf permissions must be configured explicitly by the caller/CI runner.
		mise -E profiling exec -- flamegraph -o "$run_dir/cpu.svg" -- "${clean[@]}" "$binary" cpu "$run_dir"
		python3 scripts/profile-validate.py svg "$run_dir/cpu.svg"
		;;
	*)
		printf 'CPU profiling supports macOS samply or Linux perf/flamegraph only.\n' >&2
		exit 1
		;;
	esac
	;;
esac
printf 'Synthetic profile completed under profiles/; inspect artifacts locally before sharing.\n'
