#!/usr/bin/env bash
# Hash only public compiler/native inputs; never dump environment or credentials.
set -euo pipefail
case ${1:?workspace or fuzz required} in
workspace) compiler=(rustc) ;;
fuzz) compiler=(rustc +nightly-2026-10-20) ;;
*) exit 2 ;;
esac
digest=$(
	{
		"${compiler[@]}" -vV
		cargo --version
		cc --version
		c++ --version
		cmake --version
		LC_ALL=C lscpu | awk -F: '/^(Architecture|Vendor ID|Model name|Flags):/ {gsub(/[[:space:]]+/, " ", $2); print $1 ":" $2}'
		printf '%s\n' "${RUSTFLAGS-}" "${CFLAGS-}" "${CXXFLAGS-}" "${VECTORSCAN_OFFLINE-}"
	} | sha256sum | cut -d ' ' -f 1
)
printf 'digest=%s\n' "$digest" >>"${GITHUB_OUTPUT:?GitHub output file required}"
