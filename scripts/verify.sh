#!/usr/bin/env bash
set -euo pipefail
python3 scripts/policy.py workspace
if [[ -f scripts/verus-verify.sh ]]; then
	exec bash scripts/verus-verify.sh
fi
if [[ -d crates/verified ]]; then
	printf 'verified crate exists but scripts/verus-verify.sh is missing\n' >&2
	exit 1
fi
printf 'No verified crate yet: scaffolding only, not a proof result (P/E integration pending).\n'
