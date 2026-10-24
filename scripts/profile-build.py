"""Build the actual synthetic example and select only its exact Cargo JSON executable."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def executable(messages: str) -> Path:
    paths = set()
    finished = []
    for line in messages.splitlines():
        item = json.loads(line)
        if not isinstance(item, dict) or not isinstance(item.get("reason"), str):
            raise ValueError("invalid Cargo message")
        if item["reason"] == "build-finished":
            finished.append(item.get("success"))
        if item["reason"] != "compiler-artifact":
            continue
        target, profile = item.get("target"), item.get("profile")
        if not isinstance(target, dict) or not isinstance(profile, dict):
            raise ValueError("invalid Cargo artifact")
        if target.get("name") == "profile-corpus" and target.get("kind") == ["example"] and profile.get("test") is False:
            path = item.get("executable")
            if not isinstance(path, str) or not path:
                raise ValueError("profiling executable missing")
            paths.add(Path(path))
    if finished != [True] or len(paths) != 1:
        raise ValueError("synthetic profiling executable was not uniquely identified")
    return paths.pop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", required=True, choices=["profiling", "profiling-heap", "profiling-console"])
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    command = ["cargo", "build", "--locked", "-p", "disk-archive", "--example", "profile-corpus",
               "--features", args.features, "--message-format=json"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode:
        # Compiler diagnostics are source-only; never run a workload during build.
        sys.stderr.write(completed.stderr)
        raise ValueError("synthetic profiling example did not build")
    binary = executable(completed.stdout).resolve(strict=True)
    receipt = {"command": command, "binary": str(binary),
               "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
               "clean": not bool(subprocess.check_output(["git", "status", "--porcelain"]))}
    with args.receipt.open("x") as output:
        json.dump(receipt, output, sort_keys=True)
    print(binary)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("Synthetic profiling build failed", file=sys.stderr)
        sys.exit(1)
