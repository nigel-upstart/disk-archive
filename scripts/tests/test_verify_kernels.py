"""Fail-closed proof-driver tests; actual solver controls run separately in task verify."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_kernels", ROOT / "scripts/verify-kernels.py")
kernels = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kernels)


def outcome(*, errors=0, verified=51, success=True, entire=True, vir=False, code=0):
    summary = {"errors": errors, "verified": verified, "success": success,
               "is-verifying-entire-crate": entire, "encountered-vir-error": vir}
    return subprocess.CompletedProcess([], code, "", ""), summary


class KernelGateTests(unittest.TestCase):
    def test_checked_in_erasure_policy(self):
        kernels.check_erasure_policy(kernels.SOURCE)

    def test_erasure_and_escape_regressions(self):
        additions = (
            "#[cfg(verus_only)] fn hidden_runtime() {}",
            "#[cfg(not(verus_only))] fn different_runtime() {}",
            "#[cfg(verus_only)] verus! { fn hidden_runtime() {} }",
            "#[cfg(verus_only)] verus! {",
            "#[cfg_attr(verus_only, verifier::external_body)] fn unchecked() {}",
            "fn unchecked() { assume(true); }",
            "fn unchecked() { admit(); }",
            "assume_specification! {}",
        )
        for addition in additions:
            with self.subTest(addition=addition), tempfile.TemporaryDirectory() as temporary:
                source = Path(temporary) / "src"
                shutil.copytree(kernels.SOURCE, source)
                path = source / "age.rs"
                path.write_text(path.read_text() + "\n" + addition)
                with self.assertRaises(ValueError):
                    kernels.check_erasure_policy(source)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "src"
            shutil.copytree(kernels.SOURCE, source)
            (source / "key_model.rs").write_text("fn alternate_encoder() {}")
            with self.assertRaises(ValueError):
                kernels.check_erasure_policy(source)

    def test_solver_command_targets_actual_source_without_cheating(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            result, summary = outcome()
            result.stdout = json.dumps({"verification-results": summary})
            with patch.object(kernels.subprocess, "run", return_value=result) as run:
                kernels.verify("pinned-verus", kernels.SOURCE, work)
            args = run.call_args.args[0]
            self.assertEqual(args[-1], str(kernels.SOURCE / "lib.rs"))
            self.assertIn("--no-cheating", args)
            self.assertNotIn("--verify-function", args)
            self.assertEqual(run.call_args.kwargs["cwd"], work)
            self.assertEqual(run.call_args.kwargs["timeout"], 300)

    def test_setup_or_compiler_failure_is_not_mutation_evidence(self):
        result = subprocess.CompletedProcess([], 1, "not JSON", "setup failed")
        with patch.object(kernels.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "not a proof result"):
                kernels.verify("verus", kernels.SOURCE, Path("unused"))

    def test_incomplete_positive_proof_fails(self):
        for result in (outcome(verified=50), outcome(entire=False), outcome(success=False),
                       outcome(errors=1), outcome(code=1)):
            with self.subTest(result=result), patch.object(kernels, "verify", return_value=result):
                with self.assertRaises(ValueError):
                    kernels.run_suite("verus")

    def test_mutations_require_proof_failures_not_translation_errors(self):
        for rejected in (outcome(), outcome(code=1), outcome(code=1, errors=1, vir=True)):
            with self.subTest(rejected=rejected), patch.object(kernels, "verify", side_effect=[outcome(), rejected]):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, "not rejected"):
                    kernels.run_suite("verus")

    def test_mutation_anchor_drift_fails(self):
        with patch.object(kernels, "MUTATIONS", (("drift", "age.rs", "missing anchor", "change"),)):
            with patch.object(kernels, "verify", return_value=outcome()):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, "anchor drifted"):
                    kernels.run_suite("verus")

    def test_all_controls_are_isolated_and_do_not_modify_runtime_source(self):
        before = {path: path.read_bytes() for path in kernels.SOURCE.glob("*.rs")}
        targets = []

        def solver(verus, source, work):
            targets.append(source)
            return outcome() if source == kernels.SOURCE else outcome(code=1, errors=1, success=False)

        with patch.object(kernels, "verify", side_effect=solver), contextlib.redirect_stdout(io.StringIO()) as output:
            kernels.run_suite("verus")
        self.assertEqual(len(targets), 1 + len(kernels.MUTATIONS))
        self.assertEqual(output.getvalue().count("Semantic negative control rejected:"), 7)
        self.assertIn("cfg-divergence negative control rejected", output.getvalue())
        self.assertEqual(before, {path: path.read_bytes() for path in kernels.SOURCE.glob("*.rs")})
        self.assertFalse(targets[-1].exists())


if __name__ == "__main__":
    unittest.main()
