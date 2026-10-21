#!/usr/bin/env bash
# Explicit optional comparison tool, never an application/backend dependency.
set -euo pipefail
mkdir -p target/scanner-tools
case $(uname -s)-$(uname -m) in
Linux-x86_64)
	platform=linux_amd64
	expected=3c7b0d1dc4278294269bfdd7594bca8bb28c78da0a4a06ad202ded37b48deca4
	;;
Darwin-arm64)
	platform=darwin_arm64
	expected=b612143d840b4c75d41fe40436c5932efead001951283f18c87013c4145e1675
	;;
*)
	printf 'unsupported pinned comparison platform\n' >&2
	exit 1
	;;
esac
archive=target/scanner-tools/trufflehog.tar.gz
if [[ ! -f $archive ]]; then
	curl --fail --location --silent --show-error "https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.2/trufflehog_3.99.2_${platform}.tar.gz" -o "$archive"
fi
python3 - "$archive" "$expected" <<'PY'
import hashlib
from pathlib import Path
import sys
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('pinned comparison archive checksum mismatch')
PY
tar -xzf "$archive" -C target/scanner-tools trufflehog
cargo run -p disk-archive-scanner --example export_fixtures --locked
python3 scripts/scanner-parity.py "${PWD}/target/scanner-tools/trufflehog"
