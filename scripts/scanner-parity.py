"""Optional pinned TruffleHog comparison. Persist names/counts only, never results."""

from collections import Counter
import json
from pathlib import Path
import subprocess
import sys


def main() -> None:
    binary = sys.argv[1]
    version = subprocess.run([binary, "--version"], capture_output=True, check=True, text=True)
    if (version.stdout + version.stderr).strip() != "trufflehog 3.99.2":
        raise ValueError("comparison requires exactly TruffleHog 3.99.2")
    root = Path("target/scanner-fixtures")
    planted = (root / "planted.txt").read_bytes()
    manifest = [line.split("\t") for line in (root / "manifest.tsv").read_text().splitlines()[1:]]
    report = {"version": "3.99.2", "verification": False, "families": {}, "benign_detector_counts": {}}
    for name in ("planted", "benign"):
        command = [binary, "filesystem", "--no-update", "--no-verification", "--json", "--log-level=-1", "--concurrency=1", "--fail-on-scan-errors", str(root / (name + ".txt"))]
        # Results containing raw values remain only in this process, never files,
        # logs, exception text or CI artifacts. Do not echo subprocess errors.
        result = subprocess.run(command, capture_output=True, timeout=180)
        if result.returncode:
            raise ValueError("pinned comparison failed (output suppressed)")
        results = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        counts = Counter(item["DetectorName"] for item in results)
        if name == "benign":
            report["benign_detector_counts"] = dict(sorted(counts.items()))
            if counts:
                raise ValueError("pinned comparison produced unexpected benign findings")
        else:
            report["planted_detector_counts"] = dict(sorted(counts.items()))
            for family, rule, start, end in manifest:
                value = planted[int(start):int(end)]
                recalled = any(value in item.get("Raw", "").encode() for item in results)
                report["families"][family] = {"expected": 1, "trufflehog_recalled": int(recalled)}
    # TH is a comparison, not the independent manifest gate. Misses are reported.
    destination = Path("target/scanner-parity.json")
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, json.JSONDecodeError):
        sys.exit("scanner comparison failed; diagnostics suppressed to protect values")
