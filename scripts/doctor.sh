#!/usr/bin/env bash
set -euo pipefail
missing=0
for tool in cargo rustc rustfmt cargo-clippy task lefthook ast-grep typos taplo shellcheck shfmt gitleaks cargo-nextest cargo-llvm-cov cargo-deny cargo-machete cargo-cyclonedx cyclonedx actionlint zizmor python3 cc c++ cmake pkg-config ragel; do
	if ! command -v "$tool" >/dev/null; then
		printf 'Missing %s\n' "$tool" >&2
		missing=1
	fi
done
if ((missing)); then
	printf 'Run mise install. Install native prerequisites: macOS: brew install cmake boost ragel pkgconf; Ubuntu: apt-get install build-essential cmake libboost-dev ragel pkg-config. Install the pinned Rust toolchain with rustup.\n' >&2
	exit 1
fi
boost_args=()
if [[ -n "${BOOST_ROOT:-}" ]]; then
	boost_args+=("-I$BOOST_ROOT/include")
elif command -v brew >/dev/null && boost_root="$(brew --prefix boost 2>/dev/null)"; then
	boost_args+=("-I$boost_root/include")
fi
if ! printf '#include <boost/version.hpp>\n' | c++ "${boost_args[@]}" -E -x c++ - >/dev/null 2>&1; then
	printf 'Missing Boost headers; install boost/libboost-dev or set BOOST_ROOT.\n' >&2
	exit 1
fi
python3 scripts/policy.py toolchain
if ! cargo llvm-cov show-env --sh >/dev/null 2>&1; then
	printf 'Missing matching LLVM coverage tools. Install rustup component llvm-tools-preview, or set LLVM_COV and LLVM_PROFDATA to tools matching rustc -vV.\n' >&2
	exit 1
fi
printf 'Tooling ready. Verus has a separate pin; task verify checks its integration status.\n'
