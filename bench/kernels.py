"""Run real Gungraun/Callgrind and retain only complete numeric microbenchmark events.

Counts come from Gungraun's own versioned JSON summaries (schema v7), not from
parsing Callgrind profile files.
"""
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
from fingerprint import collect as fingerprint

FUNCTIONS = {
    "redaction": "core_needle_build_and_rewrite",
    "scanner": "scanner_fixed_buffer",
    "gzip_sha256": "gzip_sha256_fixed_buffer",
}
# Gungraun 0.20.0's machine-readable summary format; any other version fails closed.
SUMMARY_VERSION = "7"
MAX_SUMMARY_BYTES = 4 * 1024 * 1024


def metric(metrics: object, event: str) -> int:
    """One fresh integer observation; comparisons, floats and absent values never pass."""
    entry = metrics.get(event) if isinstance(metrics, dict) else None
    values = entry.get("values") if isinstance(entry, dict) else None
    if not isinstance(values, dict) or set(values) != {"new"}:
        raise ValueError("exactly one fresh Callgrind value per cache event required")
    value = values["new"]
    if type(value) is not int or value < 0:
        raise ValueError("Callgrind counts must be unsigned integers")
    return value


def events(summary: object) -> tuple[str, dict[str, int]]:
    """Validate one Gungraun summary for a fresh single-part library Callgrind run."""
    if not isinstance(summary, dict) or summary.get("version") != SUMMARY_VERSION:
        raise ValueError("unsupported Gungraun summary version")
    if summary.get("kind") != "LibraryBenchmark" or summary.get("baselines") != [None, None]:
        raise ValueError("fresh library benchmark summary required")
    profiles = summary.get("profiles")
    if not isinstance(profiles, list) or len(profiles) != 1 or not isinstance(profiles[0], dict):
        raise ValueError("exactly one tool profile required")
    profile = profiles[0]
    data = profile.get("data")
    if profile.get("tool") != "Callgrind" or not isinstance(data, dict):
        raise ValueError("Callgrind profile required")
    parts, total = data.get("parts"), data.get("total")
    if not isinstance(parts, list) or len(parts) != 1 or not isinstance(total, dict):
        raise ValueError("exactly one single-threaded Callgrind part required")
    function = summary.get("function_name")
    if not isinstance(function, str):
        raise ValueError("benchmark function name required")
    metrics = total.get("metrics")
    observed = {event: metric(metrics, event) for event in CACHE_EVENTS}
    if observed["Ir"] <= 0:
        raise ValueError("kernel instructions were not observed")
    return function, observed


def counts(stdout: bytes) -> dict[str, list[dict]]:
    """Require exactly one valid summary per registered kernel from Gungraun's JSON lines."""
    if set(FUNCTIONS) != set(KERNELS) or len(stdout) > MAX_SUMMARY_BYTES:
        raise ValueError("bounded summary output for registered kernels required")
    names = {function: kernel for kernel, function in FUNCTIONS.items()}
    result: dict[str, list[dict]] = {}
    for line in stdout.decode().splitlines():
        if not line.strip():
            continue
        function, observed = events(json.loads(line))
        kernel = names.get(function)
        if kernel is None or kernel in result:
            raise ValueError("unknown or duplicate kernel summary")
        result[kernel] = [observed]
    if set(result) != set(KERNELS):
        raise ValueError("exactly one summary per kernel required")
    return result


def summary_matches(stdout: bytes) -> dict[str, int]:
    """Value-free per-kernel summary counts for diagnostics; never raw output."""
    matches = dict.fromkeys(FUNCTIONS, 0)
    for line in stdout[:MAX_SUMMARY_BYTES].decode(errors="replace").splitlines():
        try:
            function = json.loads(line).get("function_name")
        except (ValueError, AttributeError):
            continue
        for kernel, name in FUNCTIONS.items():
            matches[kernel] += function == name
    return matches


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


def failure_category(stderr: bytes) -> str:
    """Classify bounded tool diagnostics without forwarding any raw output or paths."""
    prefix = stderr[:8192].lower()
    for category, needles in (
        ("runner-arguments", (b"unexpected argument", b"unrecognized option")),
        ("unsupported-instruction", (b"unrecognised instruction", b"unsupported instruction")),
        ("execution-permission", (b"permission denied",)),
        ("runner-or-tool-not-found", (b"not installed", b"not found", b"no such file")),
        ("cargo-metadata", (b"cargo metadata",)),
        ("benchmark-panic", (b"panicked", b"panic")),
        ("tool-version", (b"version mismatch",)),
    ):
        if any(needle in prefix for needle in needles):
            return category
    return "tool-failed"


def collect(build: Path, output: Path) -> None:
    if sys.platform != "linux" or output.exists():
        raise ValueError("Linux real Valgrind and new kernel receipt required")
    root = Path(__file__).resolve().parents[1]
    environment = fingerprint(root, profile="release")
    binary = load_build(build, environment)["callgrind"]
    before = binary_digest(binary)
    with tempfile.TemporaryDirectory(prefix="disk-archive-kernels-") as owned:
        temporary = Path(owned)
        # Profiles and summaries contain paths/commands; only validated counts leave this scope.
        settings = dict(os.environ, GUNGRAUN_HOME=str(temporary))
        # Cargo bench normally supplies --bench. Without it this direct invocation
        # runs Gungraun's test mode, which succeeds without Valgrind or summaries.
        result = subprocess.run([str(binary), "--bench", "--output-format=json"], cwd=root, env=settings, check=False, timeout=1200,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Only fixed classifications and summary counts are reported;
        # tool output is never forwarded or written to a log/artifact.
        if result.returncode:
            print("Kernel diagnostic: " + json.dumps(dict(stage="callgrind-execution", exit_status=result.returncode,
                  kernel_summaries=summary_matches(result.stdout), category=failure_category(result.stderr)), sort_keys=True), file=sys.stderr)
            raise subprocess.CalledProcessError(result.returncode, "callgrind-tool")
        try:
            observed = counts(result.stdout)
        except (ValueError, UnicodeDecodeError):
            print("Kernel diagnostic: " + json.dumps(dict(stage="summary-extraction", summary_bytes=len(result.stdout),
                  kernel_summaries=summary_matches(result.stdout)), sort_keys=True), file=sys.stderr)
            raise
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
