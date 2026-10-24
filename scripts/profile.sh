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
features=profiling
if [[ $mode == heap ]]; then features=profiling-heap; fi
if [[ $mode == console ]]; then
	features=profiling-console
	# Console is intentionally a distinct, explicitly unstable build.
	export RUSTFLAGS="${RUSTFLAGS:-} --cfg tokio_unstable"
fi
if [[ $mode == cpu && $(uname -s) == Linux ]]; then
	# Frame-pointer sampling records addresses, not raw DWARF stack-memory dumps.
	export RUSTFLAGS="${RUSTFLAGS:-} -C force-frame-pointers=yes"
fi
umask 077
if [[ -L profiles ]]; then
	printf 'Refusing symlink profile output directory.\n' >&2
	exit 1
fi
mkdir -p profiles
run_dir=$(mktemp -d "$root/profiles/$mode-XXXXXXXX")
mkdir "$run_dir/home"
# Cargo JSON, never a stale unsuffixed executable or a guessed target directory.
binary=$(python3 scripts/profile-build.py --features "$features" --receipt "$run_dir/build.json")
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
	printf 'Attach with: tokio-console http://127.0.0.1:6669 (synthetic pipeline plus a 3-second attach period)\n'
	"${clean[@]}" "$binary" console "$run_dir"
	python3 scripts/profile-validate.py console "$run_dir/console.json"
	;;
cpu)
	case $(uname -s) in
	Darwin)
		mise -E profiling exec -- samply record --save-only -o "$run_dir/cpu.json" -- "${clean[@]}" "$binary" cpu "$run_dir"
		python3 scripts/profile-validate.py cpu "$run_dir/cpu.json"
		;;
	Linux)
		# perf permissions must be configured explicitly by the caller/CI runner.
		(cd "$run_dir" && mise -E profiling exec -- flamegraph --cmd 'record -e cpu-clock:u -F 199 --call-graph fp' -o cpu.svg -- "${clean[@]}" "$binary" cpu "$run_dir")
		python3 scripts/profile-validate.py svg "$run_dir/cpu.svg"
		;;
	*)
		printf 'CPU profiling supports macOS samply or Linux perf/flamegraph only.\n' >&2
		exit 1
		;;
	esac
	;;
esac
python3 scripts/profile-validate.py run "$run_dir/run.json"
printf 'Synthetic profile completed under profiles/; inspect artifacts locally before sharing.\n'
