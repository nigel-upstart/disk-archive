"""Generate/check synthetic legacy outputs without importing the archive pipeline."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from session_archiver.redactor import redact_file  # noqa: E402
from session_archiver.scanner import Finding  # noqa: E402

FIXTURES = ROOT / "fixtures" / "redactor"
TIMES_NS = (1_600_000_000_000_000_000, 1_600_000_100_000_000_000)


def render() -> dict:
    cases = json.loads((FIXTURES / "cases.json").read_text())
    results = []
    ids: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="disk-archive-golden-") as directory:
        for case in cases["cases"]:
            if case["id"] in ids:
                raise ValueError("Duplicate golden ID")
            ids.add(case["id"])
            # Never derive paths from case IDs or other fixture content.
            path = Path(directory) / f"input-{len(results)}.bin"
            path.write_bytes(bytes.fromhex(case["input_hex"]))
            os.utime(path, ns=TIMES_NS)
            before = path.stat()
            # Make the source stat deterministic and spy on the real restoration:
            # host indexers can read temp files and race any later atime observation.
            # Legacy restores float seconds, not nanoseconds; do not claim more.
            with (
                patch.object(Path, "stat", return_value=before),
                patch("session_archiver.redactor.os.utime", wraps=os.utime) as restore,
            ):
                count = redact_file(
                    path,
                    [Finding(**finding) for finding in case["findings"]],
                    drop_lines=set(case["drop_lines"]),
                )
                restore.assert_called_once_with(path, (before.st_atime, before.st_mtime))
            if path.stat().st_mtime_ns != before.st_mtime_ns:
                raise AssertionError(f"mtime changed: {case['id']}")
            results.append({"id": case["id"], "output_hex": path.read_bytes().hex(), "replacements": count})
    return {"schema_version": 1, "cases": results}


def check() -> int:
    actual = render()
    expected = json.loads((FIXTURES / "expected.json").read_text())
    if actual != expected:
        raise AssertionError("Golden mismatch: review legacy changes; do not regenerate blindly")
    return len(actual["cases"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        result = render()
        (FIXTURES / "expected.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"Generated {len(result['cases'])} synthetic redactor goldens")
    else:
        print(f"Checked {check()} synthetic redactor goldens (including timestamps)")


if __name__ == "__main__":
    main()
