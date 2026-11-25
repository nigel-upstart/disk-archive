#!/usr/bin/env bash
set -euo pipefail

binary=${1:?release binary required}
archive=${2:?output archive required}
rules_manifest=$(cargo metadata --locked --offline --format-version 1 --filter-platform x86_64-unknown-linux-gnu |
	python3 -c '
import json
import sys

rules = [package["manifest_path"] for package in json.load(sys.stdin)["packages"]
         if package["name"] == "kingfisher-rules"]
if len(rules) != 1:
    sys.exit("expected one Kingfisher rules package")
print(rules[0])
')
rules=$(dirname "$rules_manifest")
kingfisher=$(cd "$rules/../.." && pwd)

bundle=$(mktemp -d)
trap 'rm -rf "$bundle"' EXIT
notices=$bundle/licenses/kingfisher
mkdir -p "$notices"
install -m 0755 "$binary" "$bundle/disk-archive"
cp LICENSE "$bundle/LICENSE"
cp "$kingfisher/LICENSE" "$kingfisher/NOTICE" "$notices/"
cp "$kingfisher/crates/kingfisher-core/data/tokei-LICENSE-MIT" "$notices/"
cp "$rules/generated/NOTICES.txt" "$notices/builtin-rules-NOTICES.txt"
cp "$rules/data/wordfreq-LICENSE.txt" "$rules/data/wordfreq-NOTICE.md" "$notices/"
tar -czf "$archive" -C "$bundle" disk-archive LICENSE licenses
