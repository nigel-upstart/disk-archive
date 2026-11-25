"""Linux process audit for the exact synthetic benchmark executable, not a counter canary.

The canonical G parser is reused after G's actual merge. Missing parser/strace or
unsupported platforms fail closed. Raw strace is temporary and never an artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile


def binary_digest(binary: Path) -> str:
    with binary.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def audit(binary: Path, arguments: list[str], *, timeout: float = 600) -> dict:
    if sys.platform != "linux" or not 0 < timeout <= 600:
        raise ValueError("Linux and bounded audit timeout required")
    binary = binary.resolve(strict=True)
    if not binary.is_file() or not isinstance(arguments, list) or any(not isinstance(arg, str) for arg in arguments):
        raise ValueError("explicit benchmark binary and arguments required")
    before = binary_digest(binary)
    root = Path(__file__).resolve().parents[1]
    # Do not carry a second divergent process parser or substitute a gateway count.
    parser = runpy.run_path(str(root / "crates/archiver/tests/audit_processes.py"))["count_process_attempts"]
    with tempfile.TemporaryDirectory(prefix="disk-archive-perf-audit-") as temporary:
        trace = Path(temporary) / "process.trace"
        command = ["strace", "-f", "-qq", "-v", "-s", "0", "-e", "trace=clone,clone3,fork,vfork,execve,execveat", "-o", str(trace)]
        canary = (
            "import os,sys; pid=os.fork(); "
            "os.execv(sys.executable,[sys.executable,'-I','-S','-c','pass']) "
            "if pid==0 else sys.exit(os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]))"
        )
        subprocess.run(command + [sys.executable, "-I", "-S", "-c", canary], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        positive = parser(trace.read_text())["process_attempts"]
        if positive != 2:
            raise ValueError("real fork/exec tracer canary was not observed")
        trace.unlink()
        subprocess.run(command + [str(binary), *arguments], check=True, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        result = parser(trace.read_text())
        if set(result) != {"process_attempts", "thread_attempts"} or any(type(value) is not int or value < 0 for value in result.values()):
            raise ValueError("complete process audit observations required")
        if result["process_attempts"] != 0:
            raise ValueError("hot-path process attempt observed")
    after = binary_digest(binary)
    if before != after:
        raise ValueError("audited binary changed")
    return dict(result, canary_process_attempts=positive, binary_sha256=after)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.receipt.exists():
        raise ValueError("audit receipt already exists")
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    result = audit(args.binary, arguments)
    with args.receipt.open("x") as output:
        output.write(json.dumps(result, sort_keys=True) + "\n")
    print("Performance process audit: zero attempts; real fork/exec canary observed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        sys.exit("performance process audit failed; diagnostics suppressed")
