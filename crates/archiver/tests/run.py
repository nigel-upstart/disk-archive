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


def executable(arguments, target, kind="bin"):
    completed = subprocess.run(["cargo", *arguments, "--message-format=json"],
        cwd=ROOT, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise RuntimeError("required archiver test executable failed to build")
    paths = [
        message["executable"]
        for line in completed.stdout.splitlines()
        if (message := json.loads(line)).get("reason") == "compiler-artifact"
        and message.get("executable") and message.get("target", {}).get("name") == target
        and message.get("target", {}).get("kind") == [kind]
        and (kind != "test" or message.get("profile", {}).get("test") is True)
    ]
    if len(paths) != 1:
        raise RuntimeError("required archiver executable was not uniquely identified")
    return paths.pop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("--profiling", action="store_true")
    parser.add_argument("--dry-run-audit", action="store_true")
    args = parser.parse_args()
    if args.audit:
        # Reuse task check's workspace/all-features graph, not a narrower SDK/native build.
        binary = executable(["test", "--workspace", "--all-features", "--locked", "--no-run"], "pipeline", "test")
        subprocess.run([sys.executable, "-B", str(TESTS / "audit_processes.py"),
                        "--binary", binary], cwd=ROOT, check=True)
    else:
        features = ["--all-features"] if args.profiling else []
        binary = executable(["build", "-p", "disk-archive", "--bin", "disk-archive", "--locked", *features], "disk-archive")
        subprocess.run([sys.executable, "-B", str(TESTS / "cli.py"),
                        "--binary", binary, *(["--profiling"] if args.profiling else [])], cwd=ROOT, check=True)
        subprocess.run([sys.executable, "-B", str(TESTS / "audit_processes.py"),
                        "--self-test"], cwd=ROOT, check=True)
        if args.dry_run_audit:
            if not args.profiling:
                raise ValueError("dry-run audit requires all profiling features")
            subprocess.run([sys.executable, "-B", str(ROOT / "scripts/profile-dry-run.py"),
                            "--binary", binary], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
