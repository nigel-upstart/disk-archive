#!/usr/bin/env bash
# Frozen fixture integrity plus actual Rust bytes/counts; never regenerate expectations here.
set -euo pipefail
python3 -B scripts/frozen-oracle.py
# Retain the live sanitized check until the relocated Rust comparison freshly passes.
python3 -B legacy/python/tests/golden.py --check
cargo test --locked -p disk-archive-core --test golden golden_parity
