#!/usr/bin/env bash
# Hash only public compiler/native inputs; never dump environment or credentials.
set -euo pipefail
# The first uncached Linux check exhausted disk during the second (coverage)
# native build. Reclaim only the unused Android SDK on GitHub-hosted runners;
# never touch repository artifacts, Rust/native prerequisites or self-hosted hosts.
# Kept outside the key inputs: reclaiming unrelated disk changes no build flags.
if [[ ${GITHUB_ACTIONS-} == true && ${RUNNER_ENVIRONMENT-} == github-hosted && ${RUNNER_OS-} == Linux && -d /usr/local/lib/android ]]; then
	sudo -n rm -rf -- /usr/local/lib/android
fi
case ${1:?workspace or fuzz required} in
workspace)
	compiler=(rustc)
	lock=Cargo.lock
	;;
fuzz)
	compiler=(rustc +nightly-2026-10-20)
	lock=fuzz/Cargo.lock
	;;
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
		printf '%s\n' "${RUSTFLAGS-}" "${CARGO_ENCODED_RUSTFLAGS-}" "${CFLAGS-}" "${CXXFLAGS-}" "${VECTORSCAN_OFFLINE-}"
	} | sha256sum | cut -d ' ' -f 1
)
printf 'digest=%s\n' "$digest" >>"${GITHUB_OUTPUT:?GitHub output file required}"
native=$(python3 scripts/ci-cache-native.py "$lock")
printf 'native=%s\n' "$native" >>"$GITHUB_OUTPUT"
