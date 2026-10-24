"""Run real Gungraun/Callgrind and retain only complete numeric microbenchmark events."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from assemble import CACHE_EVENTS, KERNELS, digest, unsigned
from audit import binary_digest
from build import load as load_build
from callgrind import instruction_cache_counts
from fingerprint import collect as fingerprint

FUNCTIONS = {
    "redaction": "core_needle_build_and_rewrite",
    "scanner": "scanner_fixed_buffer",
    "gzip_sha256": "gzip_sha256_fixed_buffer",
}


def counts(directory: Path) -> dict[str, list[dict]]:
    """Require one fresh full-cache dump per single-threaded kernel, no glob-first selection."""
    files = list(directory.rglob("callgrind.*.out"))
    if set(FUNCTIONS) != set(KERNELS) or len(files) != len(KERNELS):
        raise ValueError("exactly one fresh Callgrind output per kernel required")
    result, consumed = {}, set()
    for kernel, function in FUNCTIONS.items():
        matches = [path for path in files if path.name.startswith(f"callgrind.{function}.")]
        if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
            raise ValueError("missing, aliased or ambiguous kernel output")
        path = matches[0]
        identity = (path.stat().st_dev, path.stat().st_ino)
        if identity in consumed:
            raise ValueError("kernel observations must be independent dumps")
        consumed.add(identity)
        events = instruction_cache_counts(path)
        if events["Ir"] <= 0:
            raise ValueError("kernel instructions were not observed")
        result[kernel] = [events]
    return result


def load(path: Path, environment: dict) -> dict:
    value = json.loads(path.read_text())
    if set(value) != {"schema", "fingerprint", "binary_sha256", "kernels"} or value["schema"] != 1 or value["fingerprint"] != environment:
        raise ValueError("kernel observations must match measured source, tools and build")
    digest(value["binary_sha256"])
    observed = value["kernels"]
    if not isinstance(observed, dict) or set(observed) != set(KERNELS):
        raise ValueError("complete kernel observation set required")
    for entries in observed.values():
        if not isinstance(entries, list) or len(entries) != 1 or set(entries[0]) != set(CACHE_EVENTS):
            raise ValueError("one complete actual cache-event sample per kernel required")
        for event, count in entries[0].items():
            if unsigned(count) == 0 and event == "Ir":
                raise ValueError("kernel instructions absent")
    return value


def collect(build: Path, output: Path) -> None:
    if sys.platform != "linux" or output.exists():
        raise ValueError("Linux real Valgrind and new kernel receipt required")
    root = Path(__file__).resolve().parents[1]
    environment = fingerprint(root, profile="release")
    binary = load_build(build, environment)["callgrind"]
    before = binary_digest(binary)
    with tempfile.TemporaryDirectory(prefix="disk-archive-kernels-") as owned:
        temporary = Path(owned)
        # Neither profiles (which contain paths) nor raw tool output become artifacts.
        settings = dict(os.environ, GUNGRAUN_HOME=str(temporary))
        subprocess.run([str(binary), "--output-format=json"], cwd=root, env=settings, check=True, timeout=1200,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        observed = counts(temporary)
    if fingerprint(root, profile="release") != environment or binary_digest(binary) != before:
        raise ValueError("kernel binary/source/environment changed")
    with output.open("x") as stream:
        stream.write(json.dumps(dict(schema=1, fingerprint=environment, binary_sha256=before, kernels=observed), sort_keys=True) + "\n")
    print("Callgrind: all three microbenchmarks; all seven instruction/cache events observed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    collect(args.build, args.output)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        sys.exit("performance kernel collection failed; missing/invalid observation diagnostics suppressed")
