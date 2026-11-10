"""Per-run process resource sampling; this is not an application spawn counter.

Each observation uses a fresh collector process, so RUSAGE_CHILDREN peak RSS and
context switches belong to one workload, not the maximum of earlier samples.
Application stdout/stderr is discarded, never forwarded, buffered or persisted.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
import resource
import subprocess
import sys
import time


def worker(command: list[str], timeout: float) -> dict[str, object]:
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise ValueError("explicit benchmark command required")
    start = time.perf_counter()
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    elapsed = time.perf_counter() - start
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    if result.returncode:
        raise ValueError("benchmark failed; output suppressed")
    # Never infer process_spawns, uploaded bytes, requests or temp disk from the
    # harness launch. G/H must provide those observed application counters.
    return {
        "wall": elapsed,
        "cpu_user": usage.ru_utime,
        "cpu_system": usage.ru_stime,
        # Issue #7 gates CPU time as user + system; components stay advisory.
        "cpu_total": usage.ru_utime + usage.ru_stime,
        "peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
        "voluntary_context_switches": usage.ru_nvcsw,
        "involuntary_context_switches": usage.ru_nivcsw,
        "includes_process_startup": True,
        "application_counters": None,
    }


def observe(command: list[str], *, timeout: float = 300) -> dict[str, object]:
    if not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise ValueError("benchmark timeout out of range")
    request = json.dumps({"command": command, "timeout": timeout}).encode()
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker"], input=request, capture_output=True, timeout=timeout + 10)
    if result.returncode:
        raise ValueError("benchmark collector failed; output suppressed")
    return json.loads(result.stdout)


if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["--worker"]:
            raise ValueError("collector is called through observe()")
        request = json.loads(sys.stdin.buffer.read(64 * 1024))
        print(json.dumps(worker(request["command"], request["timeout"]), sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        sys.exit("benchmark observation failed; output suppressed")
