"""Build actual registered benchmark targets, retaining Cargo's exact executable paths.

The local receipt contains build paths and must NOT be uploaded. Public performance
artifacts contain only validated numeric observations and immutable binary digests.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from audit import binary_digest
from fingerprint import collect

TARGETS = {"perf-pipeline", "callgrind", "criterion"}


def artifacts(messages: str) -> dict[str, dict]:
    result = {}
    for line in messages.splitlines():
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact" or message.get("executable") is None:
            continue
        name = message["target"]["name"]
        if name not in TARGETS:
            continue
        if name in result:
            raise ValueError("ambiguous Cargo executable target")
        path = Path(message["executable"]).resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("Cargo executable is not available")
        result[name] = {"path": str(path), "sha256": binary_digest(path)}
    if set(result) != TARGETS:
        raise ValueError("all actual registered benchmark executables required")
    return result


def load(path: Path, environment: dict) -> dict[str, Path]:
    value = json.loads(path.read_text())
    if set(value) != {"schema", "fingerprint", "executables"} or value["schema"] != 1 or value["fingerprint"] != environment or environment["source_dirty"]:
        raise ValueError("build must match clean measured source, tools and flags")
    targets = value["executables"]
    if not isinstance(targets, dict) or set(targets) != TARGETS:
        raise ValueError("complete actual build receipt required")
    result = {}
    identities = set()
    for name, entry in targets.items():
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ValueError("invalid executable receipt")
        executable = Path(entry["path"]).resolve(strict=True)
        identity = (executable.stat().st_dev, executable.stat().st_ino)
        if not executable.is_file() or not os.access(executable, os.X_OK) or identity in identities or binary_digest(executable) != entry["sha256"]:
            raise ValueError("compiled executable changed or aliases another target")
        identities.add(identity)
        result[name] = executable
    return result


def build(output: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    environment = collect(root, profile="release")
    if environment["source_dirty"] or output.exists():
        raise ValueError("clean source and new build receipt required")
    command = ["cargo", "build", "--release", "-p", "disk-archive-benchmarks", "--features", "pipeline", "--locked",
               "--bin", "perf-pipeline", "--bench", "criterion", "--bench", "callgrind", "--message-format=json"]
    process = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3600, check=True)
    executables = artifacts(process.stdout)
    if collect(root, profile="release") != environment:
        raise ValueError("build source/environment changed")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        stream.write(json.dumps(dict(schema=1, fingerprint=environment, executables=executables), sort_keys=True) + "\n")
    print("Performance build: actual collector and both microbenchmark targets compiled")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--criterion", action="store_true")
    args = parser.parse_args()
    if args.criterion:
        root = Path(__file__).resolve().parents[1]
        targets = load(args.receipt, collect(root, profile="release"))
        subprocess.run([str(targets["criterion"]), "--bench"], cwd=root, check=True, timeout=600,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Criterion: all fixed-buffer microbenchmarks completed")
    else:
        build(args.receipt)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        sys.exit("performance build failed; diagnostics suppressed")
