"""Execute the registered REAL collector in full tests and instrumented coverage.

This is functional merged-source validation, not release/hosted performance evidence.
All synthetic files/receipts and child output remain in an owned temporary directory.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from assemble import digest, unsigned
from audit import binary_digest
from corpus import write as corpus
from run import arguments


def executable(messages: str) -> Path:
    candidates = []
    for line in messages.splitlines():
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact" and message.get("executable") is not None and message["target"]["name"] == "perf-pipeline" and message["profile"]["test"] is False:
            candidates.append(Path(message["executable"]).resolve(strict=True))
    if len(candidates) != 1 or not candidates[0].is_file():
        raise ValueError("one actual non-test-profile collector executable required")
    return candidates[0]


def validate(receipt: dict) -> None:
    if receipt["schema"] != 1 or receipt["complete"] is not True:
        raise ValueError("actual complete collector receipt required")
    digest(receipt["binary_sha256"])
    counts, info = receipt["exact"], receipt["advisory"]
    if counts["process_spawns"] != 0 or unsigned(counts["peak_temp_bytes"]) == 0 or unsigned(counts["bytes_uploaded"]) == 0 or not counts["requests"]:
        raise ValueError("all real production observations required")
    if (info["verified_archives"], info["verified_retained"], info["history_rows"]) != (89, 1, 90):
        raise ValueError("complete independent corpus/output/history verification required")


def diagnostic(stage: str, binary_bytes: int | None, exit_status: int | None) -> str:
    """Allowlisted phase/numeric diagnostics only; never exception text, argv or child output."""
    if stage not in {"fixture", "cargo-build", "artifact-selection", "binary-identity", "collector-execution", "instrumented-execution", "receipt-validation"}:
        raise ValueError("unknown functional check phase")
    if binary_bytes is not None:
        unsigned(binary_bytes)
    if exit_status is not None and type(exit_status) is not int:
        raise ValueError("numeric child exit status required")
    return "Actual collector diagnostic: " + json.dumps(dict(stage=stage, binary_bytes=binary_bytes, exit_status=exit_status), sort_keys=True)


def check(*, coverage: bool = False) -> None:
    root = Path(__file__).resolve().parents[1]
    stage, binary_bytes = "fixture", None
    try:
        with tempfile.TemporaryDirectory(prefix="disk-archive-collector-check-") as owned:
            temporary = Path(owned)
            inputs, output = temporary / "corpus", temporary / "receipt.json"
            corpus(inputs)
            if coverage:
                stage = "instrumented-execution"
                command = ["cargo", "llvm-cov", "run", "--no-report", "--all-features", "--locked", "-p", "disk-archive-benchmarks",
                           "--bin", "perf-pipeline", "--", "--corpus", str(inputs), "--output", str(output)]
            else:
                stage = "cargo-build"
                built = subprocess.run(["cargo", "build", "--workspace", "--all-features", "--locked", "--bins", "--message-format=json"],
                                       cwd=root, check=True, capture_output=True, text=True, timeout=1200)
                stage = "artifact-selection"
                binary = executable(built.stdout)
                binary_bytes = binary.stat().st_size
                stage = "binary-identity"
                command = arguments(binary, inputs, output, binary_digest(binary))
                stage = "collector-execution"
            subprocess.run(command, cwd=root, check=True, timeout=1200, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stage = "receipt-validation"
            validate(json.loads(output.read_text()))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        status = error.returncode if isinstance(error, subprocess.CalledProcessError) else None
        print(diagnostic(stage, binary_bytes, status), file=sys.stderr)
        raise
    print("Actual collector check: 89 verified archives, one encoded source retained, complete HTTP/resource observations")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage", action="store_true")
    args = parser.parse_args()
    try:
        check(coverage=args.coverage)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        sys.exit("actual collector validation failed; diagnostics suppressed")
