#!/usr/bin/env bash
# Hash only public compiler/native inputs; never dump environment or credentials.
set -euo pipefail
mode=${1:?workspace, fuzz or perf required}
# The full CI check needs room for two native builds (debug and coverage).
# Perf only builds one release target tree. Avoid the slow SDK cleanup there
# when at least 16 GiB are free; a failed disk probe still reclaims space.
# Only these fixed SDKs on hosted Linux may be reclaimed, not repo artifacts.
if [[ ${GITHUB_ACTIONS-} == true && ${RUNNER_ENVIRONMENT-} == github-hosted && ${RUNNER_OS-} == Linux ]]; then
	if [[ $mode != perf ]] || ! df -Pk . | awk 'NR == 2 && $4 >= 16 * 1024 * 1024 {ok = 1} END {exit !ok}'; then
		sudo -n rm -rf -- /usr/local/lib/android /usr/share/dotnet /usr/local/.ghcup
	fi
fi
case $mode in
workspace | perf)
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
