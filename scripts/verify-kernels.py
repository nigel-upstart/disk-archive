"""Verify actual runtime source and reject semantic mutations; no generated replacement code."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/verified/src"

# Each control changes executable production behavior, not its specification.
MUTATIONS = (
    ("age", "age.rs", "mtime.total_nanos() < now.total_nanos()", "mtime.total_nanos() <= now.total_nanos()"),
    ("key", "key.rs", "output.push(hex_digit(byte / 16));", "output.push(hex_digit(byte % 16));"),
    ("needle guard", "needles.rs", "if !needles.occurs_in(line) {", "if needles.occurs_in(line) {"),
    ("PEM state", "pem.rs", "self.inside = true;", "self.inside = false;"),
    ("source binding", "lifecycle.rs", "if !same_identity(&upload.source, current) {", "if false && !same_identity(&upload.source, current) {"),
    ("remote evidence", "lifecycle.rs", "|| !remote.sse_aes256", "|| false"),
    ("state graph", "lifecycle.rs", "| (Verified, Uploaded | Error)", "| (Verified, Uploaded | Deleted | Error)"),
)


def check_ghost_functions(text: str) -> None:
    """Erased Verus modules/blocks may not define executable replacement functions."""
    if re.search(r"(?<!spec )(?<!proof )\bfn\s", text):
        raise ValueError("executable code in an erased ghost block")


def check_erasure_policy(source: Path) -> None:
    """Only imports, ghost proofs and the ghost model module may be cfg-erased."""
    for path in source.glob("*.rs"):
        text = path.read_text()
        if re.search(r"#\s*\[cfg\([^\]]*verus_only[^\]]*\)\]", text):
            for match in re.finditer(r"#\s*\[cfg\(([^\]]*verus_only[^\]]*)\)\]", text):
                if match[1].strip() != "verus_only":
                    raise ValueError(f"noncanonical proof cfg in {path.name}")
                tail = text[match.end():].lstrip()
                if not tail.startswith(("use ", "proof!", "verus!", "pub mod key_model;")):
                    raise ValueError(f"runtime code conditionally erased in {path.name}")
                if tail.startswith("verus!"):
                    # These blocks use ordinary balanced braces, no brace-bearing literals.
                    start = tail.index("{")
                    depth = 1
                    end = start + 1
                    while end < len(tail) and depth:
                        depth += (tail[end] == "{") - (tail[end] == "}")
                        end += 1
                    if depth:
                        raise ValueError("unbalanced erased ghost block")
                    check_ghost_functions(tail[start:end])
        if re.search(r"\b(assume|admit|assume_specification|external_body)\b", text):
            raise ValueError(f"proof escape in {path.name}")
    # This cfg-gated module must contain ghost functions only, never exec replacements.
    check_ghost_functions((source / "key_model.rs").read_text())


def verify(verus: str, source: Path, work: Path) -> tuple[subprocess.CompletedProcess[str], dict]:
    result = subprocess.run(
        [verus, "--crate-type", "lib", "--crate-name", "disk_archive_verified",
         "--no-cheating", "--output-json", "--triggers-mode", "silent",
         "--log-dir", str(work / "logs"), str(source / "lib.rs")],
        cwd=work, text=True, capture_output=True, check=False, timeout=300,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"compiler/setup failure is not a proof result:\n{result.stderr}") from error
    return result, payload["verification-results"]


def run_suite(verus: str) -> None:
    """The only positive proof target is the runtime crate's actual lib.rs."""
    check_erasure_policy(SOURCE)
    with tempfile.TemporaryDirectory(prefix="disk-archive-kernels-") as temporary:
        work = Path(temporary)
        result, summary = verify(verus, SOURCE, work)
        if result.returncode or not summary["success"] or summary["errors"] or not summary["is-verifying-entire-crate"]:
            raise ValueError(f"production-source verification failed:\n{result.stderr}\n{summary}")
        # Prevent a missing/empty proof selection from being reported as completion.
        if summary["verified"] < 51:
            raise ValueError(f"proof inventory unexpectedly shrank: {summary}")
        print(f"Production-source Verus: {summary['verified']} verified, 0 errors (--no-cheating)")
        for name, filename, old, new in MUTATIONS:
            mutant = work / "mutant"
            shutil.copytree(SOURCE, mutant)
            path = mutant / filename
            text = path.read_text()
            if text.count(old) != 1:
                raise ValueError(f"mutation anchor drifted: {name}")
            path.write_text(text.replace(old, new))
            result, rejected = verify(verus, mutant, work)
            if not result.returncode or rejected["errors"] < 1 or rejected["encountered-vir-error"]:
                raise ValueError(f"semantic mutation not rejected by proof: {name}\n{result.stderr}")
            shutil.rmtree(mutant)
            print(f"Semantic negative control rejected: {name}")
        # Regression for cfg-based proof/runtime divergence; never run altered source.
        mutant = work / "erasure"
        shutil.copytree(SOURCE, mutant)
        path = mutant / "age.rs"
        path.write_text(path.read_text() + "\n#[cfg(verus_only)]\nfn hidden_runtime() {}\n")
        try:
            check_erasure_policy(mutant)
        except ValueError:
            print("Proof/runtime cfg-divergence negative control rejected")
        else:
            raise ValueError("cfg-divergence policy accepted an executable alternative")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: verify-kernels.py /path/to/pinned/verus")
        run_suite(str(Path(sys.argv[1]).resolve()))
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(f"kernel verification: {error}", file=sys.stderr)
        sys.exit(1)
