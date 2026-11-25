"""Collect real native-pipeline resources, OS audit and strict Callgrind observations.

Only metadata receipts leave owned temporary directories. This command neither
builds substitutes nor creates/updates baselines. Linux failures are never skips.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

from assemble import assemble
from audit import audit, binary_digest
from build import load as load_build
from compare import compare, policy_options
from corpus import write as write_corpus
from fingerprint import collect as fingerprint
from gate import RERUN_REQUIRED, authorize_first_public_bootstrap, effective_public, summary
from kernels import load as load_kernels
from observe import observe


def arguments(binary: Path, corpus: Path, receipt: Path, digest: str) -> list[str]:
    return [str(binary), "--corpus", str(corpus), "--output", str(receipt), "--binary-sha256", digest]


def population(binary: Path, corpus: Path, temporary: Path, count: int, digest: str) -> tuple[list[dict], list[dict]]:
    resources, applications = [], []
    for index in range(count):
        receipt = temporary / f"application-{index:04}.json"
        resources.append(observe(arguments(binary, corpus, receipt, digest), timeout=600))
        applications.append(json.loads(receipt.read_text()))
    if binary_digest(binary) != digest:
        raise ValueError("measured binary changed")
    return resources, applications


def baseline_path(root: Path) -> Path | None:
    """No first-match or incompatible-baseline fallback, including deletion PRs."""
    candidates = sorted((root / "bench/baseline").glob("*.json"))
    if len(candidates) > 1:
        raise ValueError("select the reviewed baseline explicitly when multiple exist")
    return candidates[0] if candidates else None


def reviewed_baseline(root: Path, explicit: Path | None) -> tuple[dict | None, Path | None]:
    """Hosted PRs compare to their reviewed BASE tree, never to a ceiling they edit."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        path = explicit if explicit is not None else baseline_path(root)
        return (json.loads(path.read_text()) if path is not None else None), path
    if explicit is not None:
        raise ValueError("hosted baseline provenance cannot be replaced by a local pathname")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    is_pr = os.environ["GITHUB_EVENT_NAME"] == "pull_request"
    revision = event["pull_request"]["base"]["sha"] if is_pr else subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("immutable reviewed baseline tree required")
    names = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", revision, "--", "bench/baseline"], cwd=root, text=True).splitlines()
    candidates = [name for name in names if re.fullmatch(r"bench/baseline/[A-Za-z0-9._-]+\.json", name)]
    if len(candidates) > 1 or any(name.endswith(".json") and name not in candidates for name in names):
        raise ValueError("unambiguous reviewed baseline selection required")
    if is_pr:
        changed = subprocess.check_output(
            ["git", "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", revision, "HEAD", "--", ":(glob)bench/baseline/**/*.json"],
            cwd=root, text=True,
        )
        if changed.strip():
            raise ValueError("measured Git tree changes a baseline; separately approved activation required")
        directory = root / "bench/baseline"
        if directory.is_symlink():
            raise ValueError("reviewed baseline directory cannot be aliased")
        measured = sorted(directory.rglob("*.json"))
        if [path.relative_to(root).as_posix() for path in measured] != candidates or any(path.is_symlink() or not path.is_file() for path in measured):
            raise ValueError("baseline creation/deletion/rename requires separately approved activation")
    if not candidates:
        return None, None
    data = subprocess.check_output(["git", "show", f"{revision}:{candidates[0]}"], cwd=root, text=True)
    selected = root / candidates[0]
    # Until the separately approved publication/promotion workflow exists, a PR
    # cannot self-approve ANY edited ceiling, even if its measured code is faster.
    if is_pr and selected.read_text() != data:
        raise ValueError("baseline edits require separately reviewed refresh/ratchet activation")
    return json.loads(data), selected


def save(path: Path, value: dict) -> None:
    with path.open("x") as output:
        output.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run(build: Path, kernels: Path, output: Path, *, baseline: Path | None = None,
        first_public_bootstrap: bool = False, summary_path: Path | None = None) -> int:
    if sys.platform != "linux":
        raise ValueError("complete performance collection requires Linux; no skipped metrics")
    root = Path(__file__).resolve().parents[1]
    if output.exists():
        raise ValueError("fresh output directory required")
    policy = tomllib.loads((root / "bench/policy.toml").read_text())
    _, count = policy_options(policy)
    public = effective_public(False)
    previous, baseline = reviewed_baseline(root, baseline)
    environment = fingerprint(root, profile="release")
    build_environment = dict(environment)
    targets = load_build(build, environment)
    binary = targets["perf-pipeline"]
    digest = binary_digest(binary)
    kernel_receipt = load_kernels(kernels, environment)
    if kernel_receipt["binary_sha256"] != binary_digest(targets["callgrind"]):
        raise ValueError("kernel receipt is not from the actual compiled benchmark")
    measured_kernels = kernel_receipt["kernels"]
    environment.update(workers=2, cpu_jobs=2, queue_capacity=2, max_file_bytes=8 * 1_048_576,
                       worker_binary_sha256=digest)
    if summary_path is not None:
        inputs = [build, kernels, binary, root / "bench/policy.toml", *([baseline] if baseline is not None else [])]
        if summary_path.resolve().is_relative_to(output.resolve()) or any(summary_path.resolve() == path.resolve() or (summary_path.exists() and path.exists() and summary_path.samefile(path)) for path in inputs):
            raise ValueError("job summary aliases measurement inputs or outputs")
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="disk-archive-perf-") as owned:
        temporary = Path(owned)
        corpus = temporary / "corpus"
        write_corpus(corpus)
        audit_command = arguments(binary, corpus, temporary / "audit-application.json", digest)
        process_audit = audit(binary, audit_command[1:])
        resources, applications = population(binary, corpus, temporary, count, digest)
        current = assemble(environment, resources, applications, measured_kernels, process_audit, policy)
        current["observations"]["kernels"] = kernel_receipt
        if first_public_bootstrap:
            authorize_first_public_bootstrap(current, public=public, baseline=baseline)
        save(output / "current.json", current)
        decision = compare(current, previous, policy, public=public, first_public_bootstrap=first_public_bootstrap)
        pending = [name for name, value in decision["metrics"].items() if value["status"] == "rerun-required"]
        if pending and not decision["fail"]:
            # One new resource population only. Deterministic kernels/audit are NOT rerun.
            confirmation_dir = temporary / "confirmation"
            confirmation_dir.mkdir()
            resources, applications = population(binary, corpus, confirmation_dir, count, digest)
            confirmation = assemble(environment, resources, applications, measured_kernels, process_audit, policy)
            confirmation["observations"]["kernels"] = kernel_receipt
            save(output / "confirmation.json", confirmation)
            decision = compare(current, previous, policy, public=public, rerun=confirmation)
        if fingerprint(root, profile="release") != build_environment or binary_digest(binary) != digest or binary_digest(targets["callgrind"]) != kernel_receipt["binary_sha256"]:
            raise ValueError("measurement source/build changed during collection")
        decision["rerun_metrics"] = pending
        save(output / "decision.json", decision)
    markdown = summary(decision)
    (output / "summary.md").write_text(markdown)
    if summary_path is not None:
        with summary_path.open("a") as stream:
            stream.write(markdown)
    print(f"Performance collection: {decision['mode']}; samples={count}; failed={int(decision['fail'])}")
    unresolved = any(value["status"] == "rerun-required" for value in decision["metrics"].values())
    return 1 if decision["fail"] else RERUN_REQUIRED if unresolved else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--kernels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--first-public-bootstrap", action="store_true")
    args = parser.parse_args()
    summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"]) if "GITHUB_STEP_SUMMARY" in os.environ else None
    return run(args.build, args.kernels, args.output, baseline=args.baseline,
               first_public_bootstrap=args.first_public_bootstrap, summary_path=summary_path)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        sys.exit("performance collection failed; incomplete/invalid observation diagnostics suppressed")
