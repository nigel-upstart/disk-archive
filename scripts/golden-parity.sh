#!/usr/bin/env bash
# Both sides consume the same invented fixtures; never regenerate expectations here.
set -euo pipefail
python3 -B legacy/python/tests/golden.py --check
cargo test --locked -p disk-archive-core --test golden golden_parity
