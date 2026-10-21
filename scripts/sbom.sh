#!/usr/bin/env bash
set -euo pipefail
# cargo-cyclonedx emits one document per workspace member beside its Cargo.toml.
# Refuse leftovers so validation cannot silently accept a stale document.
python3 scripts/policy.py workspace
mkdir -p target/sbom
rm -f target/sbom/*.cdx.json
cargo cyclonedx --format json --all --all-features --target all --spec-version 1.5 --override-filename disk-archive-bom
python3 - <<'PY'
import json
import pathlib
import shutil
import subprocess
metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"]))
members = set(metadata["workspace_members"])
for package in metadata["packages"]:
    if package["id"] not in members:
        continue
    source = pathlib.Path(package["manifest_path"]).parent / "disk-archive-bom.json"
    target = pathlib.Path("target/sbom") / (package["name"] + ".cdx.json")
    shutil.move(source, target)
PY
for bom in target/sbom/*.cdx.json; do
	cyclonedx validate --input-file "$bom" --input-format json --input-version v1_5 --fail-on-errors
done
