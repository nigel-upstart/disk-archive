"""Fail the hosted perf job before installing tools when its baseline gate cannot run."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from gate import effective_public, first_public_bootstrap_commit
from run import reviewed_baseline

MISSING = (
    "Performance gate: blocked-missing-baseline (no measurements run). "
    "For the first public baseline only, dispatch perf.yml on main with "
    "first_public_bootstrap=true, then have the resulting baseline reviewed separately."
)


def preflight(root: Path, *, first_public_bootstrap: bool, summary_path: Path) -> int:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("hosted workflow preflight only")
    public = effective_public(False)
    _, baseline = reviewed_baseline(root, None)
    if first_public_bootstrap:
        first_public_bootstrap_commit(root, public=public, baseline=baseline)
    elif public and baseline is None:
        with summary_path.open("a") as stream:
            stream.write(MISSING + "\n")
        print(MISSING)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first-public-bootstrap", action="store_true")
    args = parser.parse_args()
    return preflight(Path(__file__).resolve().parents[1], first_public_bootstrap=args.first_public_bootstrap,
                     summary_path=Path(os.environ["GITHUB_STEP_SUMMARY"]))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        sys.exit("Performance preflight failed: invalid baseline provenance or ineligible bootstrap dispatch.")
