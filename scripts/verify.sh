#!/usr/bin/env bash
set -euo pipefail
python3 scripts/policy.py workspace
# Missing installer/source/verifier is an error, never a scaffolding success.
exec bash scripts/verus-verify.sh
