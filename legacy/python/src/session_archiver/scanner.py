"""Per-file TruffleHog scan. Findings stay in memory; never logged or persisted raw."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    detector: str
    raw: str
    raw_v2: str
    line: int | None


def scan_file(path: Path, concurrency: int = 2) -> list[Finding]:
    proc = subprocess.run(
        [
            "trufflehog", "filesystem", "--json", "--no-verification", "--no-update",
            "--log-level=-1", f"--concurrency={concurrency}", str(path),
        ],
        capture_output=True, text=True, errors="replace", check=False,
    )
    if proc.returncode not in (0, 183):
        raise RuntimeError(f"trufflehog exited {proc.returncode}")
    findings: list[Finding] = []
    for line in proc.stdout.splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in r:
            continue
        fs = r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        findings.append(Finding(r.get("DetectorName", "unknown"), r.get("Raw") or "", r.get("RawV2") or "", fs.get("line")))
    return findings


def detector_counts(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.detector] = out.get(f.detector, 0) + 1
    return out
