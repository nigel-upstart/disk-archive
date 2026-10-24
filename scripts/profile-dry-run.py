"""Linux syscall audit of the real all-feature CLI dry-run on synthetic roots only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

MUTATIONS = {"creat", "mkdir", "mkdirat", "unlink", "unlinkat", "rename", "renameat", "renameat2", "rmdir", "truncate", "ftruncate", "symlink", "symlinkat", "link", "linkat"}
RESOURCES = {"socket", "socketpair", "bind", "listen", "connect", "flock", "clone", "clone3", "fork", "vfork"}
CALL = re.compile(r"^\d+\s+(\w+)\(")


def forbidden(trace: str) -> int:
    count = 0
    executions = 0
    for line in trace.splitlines():
        match = CALL.match(line)
        if not match:
            if re.fullmatch(r"\d+\s+(?:\+\+\+ exited with \d+ \+\+\+|--- SIG[^\n]+ ---)", line):
                continue
            raise ValueError("incomplete or unknown dry-run syscall record")
        if "unfinished ..." in line:
            raise ValueError("incomplete dry-run syscall record")
        name = match[1]
        if name in {"execve", "execveat"}:
            executions += 1
            if executions > 1:
                count += 1
        elif name in MUTATIONS | RESOURCES:
            count += 1
        elif name in {"open", "openat", "openat2"} and re.search(r"\b(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_TMPFILE)\b", line):
            count += 1
        elif name in {"fcntl", "fcntl64"} and re.search(r"F_(OFD_)?SETLK(W)?\b", line):
            count += 1
        elif name in {"open", "openat", "openat2"} and any(token in line for token in ("state.sqlite", "trace.json", "heap.json", "credential-canary")):
            count += 1
    if executions == 0:
        raise ValueError("dry-run tracer did not observe the real executable")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        raise ValueError("Linux strace is required, not a skipped pass")
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="synthetic-profile-dry-run-") as directory:
        base = Path(directory).resolve()
        root = base / "source"
        root.mkdir(mode=0o700)
        (root / "input.jsonl").write_bytes(b"untouched synthetic input\n")
        credentials = base / "credential-canary"
        credentials.write_bytes(b"must not load providers")
        trace = base / "syscalls"
        prefix = ["strace", "-f", "-qq", "-s", "4096", "-e", "trace=%file,%network,%process,flock,fcntl", "-o", str(trace)]
        env = {"PATH": os.defpath, "HOME": str(base),
               "DISK_ARCHIVE_BUCKET": "synthetic-archive", "DISK_ARCHIVE_PREFIX": "synthetic",
               "DISK_ARCHIVE_ROOTS_ALL_FILES": str(root), "DISK_ARCHIVE_WORK_DIR": str(base / "work"),
               "DISK_ARCHIVE_MIN_AGE_DAYS": "0", "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
               "AWS_CONFIG_FILE": str(credentials), "AWS_PROFILE": "must-not-load", "RUST_LOG": "trace"}
        # Actual positive control proves the tracer/parser sees writes and a listener.
        canary = "import socket; open('positive','w').close(); s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); s.close()"
        subprocess.run([*prefix, sys.executable, "-I", "-S", "-c", canary], cwd=base,
                       env=env, check=True, capture_output=True, timeout=30)
        if forbidden(trace.read_text()) < 4:
            raise ValueError("real dry-run resource canary was not observed")
        (base / "positive").unlink()
        results = []
        for selection in [("--profile-trace", str(base / "trace.json")),
                          ("--profile-heap", str(base / "heap.json")), ("--profile-console",)]:
            completed = subprocess.run([*prefix, str(binary), "--dry-run", *selection], cwd=base,
                                       env=env, capture_output=True, text=True, timeout=30, check=False)
            if completed.returncode or completed.stderr or "redaction=unknown verification=unknown" not in completed.stdout:
                raise ValueError("real feature-enabled dry-run failed")
            count = forbidden(trace.read_text())
            if count:
                raise ValueError("feature-enabled dry-run attempted a mutable resource")
            if set(base.iterdir()) != {root, credentials, trace}:
                raise ValueError("feature-enabled dry-run changed synthetic tree")
            results.append(count)
    print(json.dumps({"profile_modes": len(results), "forbidden_resource_attempts": results, "positive_control": True}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Synthetic profiling dry-run audit failed", file=sys.stderr)
        sys.exit(1)
