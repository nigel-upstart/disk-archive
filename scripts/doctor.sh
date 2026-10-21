#!/usr/bin/env bash
set -euo pipefail
missing=0
for tool in cargo rustc rustfmt cargo-clippy task lefthook ast-grep typos taplo shellcheck shfmt gitleaks cargo-nextest cargo-llvm-cov cargo-deny cargo-machete cargo-cyclonedx cyclonedx actionlint zizmor python3 cc c++ cmake pkg-config; do
	if ! command -v "$tool" >/dev/null; then
		printf 'Missing %s\n' "$tool" >&2
		missing=1
	fi
done
if ((missing)); then
	printf 'Run mise install. Install native prerequisites: macOS: brew install cmake pkgconf; Ubuntu: apt-get install build-essential cmake pkg-config. Install the pinned Rust toolchain with rustup.\n' >&2
	exit 1
fi
python3 scripts/policy.py toolchain
printf 'Tooling ready. Verus has a separate pin; task verify checks its integration status.\n'
