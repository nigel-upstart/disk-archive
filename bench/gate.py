"""Metadata-only comparator CLI. Collection must use real kernels and G/H separately."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

from compare import compare

RERUN_REQUIRED = 75


def effective_public(explicit: bool) -> bool:
    """Hosted checks derive visibility from the event; omission of --public cannot downgrade them."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return explicit
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    private = event["repository"]["private"]
    if type(private) is not bool or (private and explicit):
        raise ValueError("repository visibility is missing or contradictory")
    return not private


def authorize_first_public_bootstrap(current: dict, *, public: bool, baseline: Path | None) -> None:
    """Only an explicit hosted public-main manual dispatch with NO baseline history."""
    required = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
    if not public or baseline is not None or any(os.environ.get(key) != value for key, value in required.items()):
        raise ValueError("bootstrap requires an explicit first public-main manual dispatch")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    manual = event.get("inputs", {}).get("first_public_bootstrap")
    if event["repository"].get("private") is not False or (manual != "true" and manual is not True):
        raise ValueError("bootstrap requires explicit public-repository dispatch input")
    root = Path(__file__).resolve().parents[1]
    if subprocess.check_output(["git", "rev-parse", "--is-shallow-repository"], cwd=root, text=True).strip() != "false":
        raise ValueError("complete baseline history is required for bootstrap")
    main = subprocess.check_output(["git", "rev-parse", "origin/main"], cwd=root, text=True).strip()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root, text=True)
    fingerprint = current["fingerprint"]
    if head != main or dirty.strip() or fingerprint.get("source_commit") != main or fingerprint.get("source_dirty") is not False:
        raise ValueError("bootstrap measurements must come from clean reviewed main")
    history = subprocess.check_output(["git", "log", "origin/main", "--format=%H", "--", ":(glob)bench/baseline/*.json"], cwd=root, text=True)
    if history.strip():
        raise ValueError("baseline history exists; deletion cannot reenable bootstrap")


def evaluate(current: Path, policy: Path, *, baseline: Path | None = None,
             public: bool = False, rerun: Path | None = None,
             first_public_bootstrap: bool = False) -> tuple[dict, int]:
    """No baseline writes, auto-refreshes, guessed counters or automatic repeated reruns."""
    current_data = json.loads(current.read_text())
    if first_public_bootstrap:
        authorize_first_public_bootstrap(current_data, public=public, baseline=baseline)
    decision = compare(
        current_data,
        json.loads(baseline.read_text()) if baseline is not None else None,
        tomllib.loads(policy.read_text()),
        public=public,
        rerun=json.loads(rerun.read_text()) if rerun is not None else None,
        first_public_bootstrap=first_public_bootstrap,
    )
    pending = [name for name, value in decision["metrics"].items() if value["status"] == "rerun-required"]
    decision["rerun_metrics"] = pending
    status = 1 if decision["fail"] else RERUN_REQUIRED if pending else 0
    return decision, status


def summary(decision: dict) -> str:
    """Names/status/counts only, not input values or configuration dumps."""
    lines = [f"## Performance gate ({decision['mode']})", "", "| Metric | Status | Gated | Median / observed |", "| --- | --- | --- | --- |"]
    for name, value in sorted(decision["metrics"].items()):
        # Policy supplies names, but reject Markdown/control injection rather than
        # echoing arbitrary JSON names into the GitHub job summary.
        if not name or any(not (char.isascii() and (char.isalnum() or char in "._-/")) for char in name):
            raise ValueError("invalid metric name")
        observed = value.get("new_median", value.get("observed", "—"))
        if isinstance(observed, float):
            observed = format(observed, ".6g")
        lines.append(f"| {name} | {value['status']} | {'yes' if value.get('gated') else 'NO'} | {observed} |")
    if not decision["metrics"]:
        lines.append("| baseline | no ceiling captured | NO | — |")
    if decision.get("refresh_required"):
        lines.extend(["", "A required baseline is missing or incompatible. An explicitly reviewed baseline refresh is required; CI never captures or raises one."])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("policy.toml"))
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--rerun", type=Path)
    parser.add_argument("--public", action="store_true")
    parser.add_argument("--first-public-bootstrap", action="store_true")
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    decision, status = evaluate(args.current, args.policy, baseline=args.baseline,
                                public=effective_public(args.public), rerun=args.rerun,
                                first_public_bootstrap=args.first_public_bootstrap)
    markdown = summary(decision)
    # These are decisions, not collection reports/baselines. Never overwrite a
    # baseline passed as input, even if a caller aliases the decision pathname.
    inputs = {path.resolve() for path in (args.current, args.policy, args.baseline, args.rerun) if path is not None}
    outputs = [path.resolve() for path in (args.decision, args.summary) if path is not None]
    if len(set(outputs)) != len(outputs) or inputs.intersection(outputs):
        raise ValueError("decision output aliases an input")
    if any(output.exists() and source.exists() and output.samefile(source) for output in outputs for source in inputs):
        raise ValueError("decision output hard-links an input")
    with args.decision.open("x") as output:
        output.write(json.dumps(decision, indent=2, sort_keys=True) + "\n")
    if args.summary is not None:
        with args.summary.open("a") as output:
            output.write(markdown)
    print(f"Performance gate: {decision['mode']}; failed={int(decision['fail'])}; rerun_metrics={len(decision['rerun_metrics'])}")
    return status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        sys.exit("performance gate failed; incomplete/invalid measurement diagnostics suppressed")
