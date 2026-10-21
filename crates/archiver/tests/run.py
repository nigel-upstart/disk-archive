#!/usr/bin/env python3
"""Run real-binary synthetic CLI controls; --audit additionally requires Linux strace.

Cargo JSON supplies executable paths, including when CARGO_TARGET_DIR is overridden.
Build output is never used as scan evidence or as an excuse for a skipped test.
"""

import argparse
import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[3]
TESTS = pathlib.Path(__file__).resolve().parent


def executable(arguments, target):
    completed = subprocess.run(["cargo", *arguments, "--locked", "--message-format=json"],
        cwd=ROOT, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise RuntimeError("required archiver test executable failed to build")
    paths = {
        message["executable"]
        for line in completed.stdout.splitlines()
        if (message := json.loads(line)).get("reason") == "compiler-artifact"
        and message.get("executable") and message["target"]["name"] == target
    }
    if len(paths) != 1:
        raise RuntimeError("required archiver executable was not uniquely identified")
    return paths.pop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true")
    args = parser.parse_args()
    if args.audit:
        binary = executable(["test", "-p", "disk-archive", "--test", "pipeline", "--no-run"], "pipeline")
        subprocess.run([sys.executable, "-B", str(TESTS / "audit_processes.py"),
                        "--binary", binary], cwd=ROOT, check=True)
    else:
        binary = executable(["build", "-p", "disk-archive", "--bin", "disk-archive"], "disk-archive")
        subprocess.run([sys.executable, "-B", str(TESTS / "cli.py"),
                        "--binary", binary], cwd=ROOT, check=True)
        subprocess.run([sys.executable, "-B", str(TESTS / "audit_processes.py"),
                        "--self-test"], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
