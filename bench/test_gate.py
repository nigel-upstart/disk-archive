"""Synthetic CLI controls only; no hosted performance/noise evidence."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import gate
from test_compare import report


class GateTests(unittest.TestCase):
    def run_cli(self, arguments, environment=None):
        return subprocess.run(arguments, capture_output=True, text=True, env={**os.environ, "GITHUB_ACTIONS": "false", **(environment or {})})

    def bootstrap_environment(self, root, current):
        event = root / "event.json"
        event.write_text(json.dumps({"repository": {"private": False}, "inputs": {"first_public_bootstrap": "true"}}))
        data = json.loads(current.read_text())
        data["fingerprint"].update(source_commit="a" * 40, source_dirty=False)
        current.write_text(json.dumps(data))
        return {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_PATH": str(event), "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}

    def test_first_public_bootstrap_is_manual_and_history_cannot_be_deleted_away(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, baseline, policy = self.fixtures(root)
            baseline.unlink()
            environment = self.bootstrap_environment(root, current)
            with patch.dict(os.environ, environment), patch.object(gate.subprocess, "check_output", side_effect=["false\n", "a" * 40 + "\n", "a" * 40 + "\n", "", ""]) as git:
                decision, status = gate.evaluate(current, policy, public=True, first_public_bootstrap=True)
                self.assertEqual((decision["mode"], status), ("bootstrap-record-only", 0))
                self.assertEqual(git.call_args.args[0][-1], ":(glob)bench/baseline/**/*.json")
            self.assertFalse(baseline.exists())
            with patch.dict(os.environ, environment), patch.object(gate.subprocess, "check_output", side_effect=["false\n", "a" * 40 + "\n", "a" * 40 + "\n", "", "b" * 40 + "\n"]):
                with self.assertRaises(ValueError):
                    gate.evaluate(current, policy, public=True, first_public_bootstrap=True)
            with patch.dict(os.environ, environment), patch.object(gate.subprocess, "check_output", return_value="true\n"):
                with self.assertRaises(ValueError):
                    gate.evaluate(current, policy, public=True, first_public_bootstrap=True)
            for event_name in ("pull_request", "push", "schedule"):
                with patch.dict(os.environ, {**environment, "GITHUB_EVENT_NAME": event_name}), patch.object(gate.subprocess, "check_output") as git:
                    with self.assertRaises(ValueError):
                        gate.evaluate(current, policy, public=True, first_public_bootstrap=True)
                    git.assert_not_called()

    def test_hosted_public_pr_cannot_omit_visibility_flag_or_bootstrap_missing_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, baseline, policy = self.fixtures(root)
            baseline.unlink()
            environment = self.bootstrap_environment(root, current)
            environment["GITHUB_EVENT_NAME"] = "pull_request"
            decision = root / "decision.json"
            command = [sys.executable, str(Path(gate.__file__)), "--current", str(current), "--policy", str(policy)]
            result = self.run_cli(command + ["--decision", str(decision)], environment)
            self.assertEqual(result.returncode, 1)
            data = json.loads(decision.read_text())
            self.assertEqual(data["mode"], "blocked-missing-baseline")
            self.assertFalse(data["metrics"]["wall"]["gated"])
            illegal = root / "illegal.json"
            result = self.run_cli(command + ["--first-public-bootstrap", "--decision", str(illegal)], environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(illegal.exists())

    def test_policy_requires_real_kernel_events_and_all_resource_metrics(self):
        policy = tomllib.loads(Path(gate.__file__).with_name("policy.toml").read_text())
        expected = {f"{kernel}.{event}" for kernel in ("redaction", "scanner", "gzip_sha256") for event in ("Ir", "I1mr", "D1mr", "D1mw", "ILmr", "DLmr", "DLmw")}
        expected.update(("wall", "cpu_user", "cpu_system", "cpu_total", "peak_rss_bytes", "voluntary_context_switches", "involuntary_context_switches"))
        self.assertEqual(set(policy["metrics"]), expected)
        self.assertFalse(policy["noise_study_complete"])
        # Issue #7 gates CPU as user + system; components are advisory only.
        self.assertEqual(policy["metrics"]["cpu_total"]["kind"], "statistical")
        self.assertEqual({policy["metrics"][name]["kind"] for name in ("cpu_user", "cpu_system")}, {"advisory"})

    def fixtures(self, root):
        current = root / "current.json"
        baseline = root / "baseline.json"
        policy = root / "policy.toml"
        current.write_text(json.dumps(report()))
        baseline.write_text(json.dumps(report()))
        policy.write_text('[metrics.wall]\nkind="statistical"\ntolerance=0.10\n[metrics.instructions]\nkind="deterministic"\ntolerance=0.02\n')
        return current, baseline, policy

    def test_record_only_and_one_statistical_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary:
            current, baseline, policy = self.fixtures(Path(temporary))
            unchanged = baseline.read_bytes()
            decision, status = gate.evaluate(current, policy)
            self.assertEqual((decision["mode"], status), ("record-only", 0))
            data = report()
            data["samples"]["wall"] = [200.0] * 10
            current.write_text(json.dumps(data))
            decision, status = gate.evaluate(current, policy, baseline=baseline, public=True)
            self.assertEqual(status, 75)
            self.assertEqual(decision["rerun_metrics"], ["wall"])
            decision, status = gate.evaluate(current, policy, baseline=baseline, public=True, rerun=current)
            self.assertEqual(status, 1)
            decision, status = gate.evaluate(current, policy, baseline=baseline, public=True, rerun=baseline)
            self.assertEqual(status, 0)
            self.assertEqual(baseline.read_bytes(), unchanged)

    def test_deterministic_failure_never_requests_rerun(self):
        with tempfile.TemporaryDirectory() as temporary:
            current, baseline, policy = self.fixtures(Path(temporary))
            data = report()
            data["samples"]["instructions"] = [2000] * 10
            current.write_text(json.dumps(data))
            decision, status = gate.evaluate(current, policy, baseline=baseline, public=True)
            self.assertEqual(status, 1)
            self.assertEqual(decision["rerun_metrics"], [])

    def test_cli_summary_and_baseline_alias_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, baseline, policy = self.fixtures(root)
            decision, summary = root / "decision.json", root / "summary.md"
            prefix = [sys.executable, str(Path(gate.__file__)), "--current", str(current), "--policy", str(policy), "--baseline", str(baseline)]
            original = baseline.read_bytes()
            result = self.run_cli(prefix + ["--decision", str(decision), "--summary", str(summary)])
            self.assertEqual(result.returncode, 0)
            self.assertIn("| instructions | unchanged |", summary.read_text())
            self.assertEqual(baseline.read_bytes(), original)
            result = self.run_cli(prefix + ["--decision", str(baseline)])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(baseline.read_bytes(), original)
            hardlink = root / "alias.json"
            hardlink.hardlink_to(baseline)
            result = self.run_cli(prefix + ["--decision", str(hardlink)])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(baseline.read_bytes(), original)

    def test_summary_rejects_arbitrary_names(self):
        decision = {"mode": "record-only", "metrics": {"bad\nname": {"status": "unchanged"}}}
        with self.assertRaises(ValueError):
            gate.summary(decision)

    def test_invalid_report_diagnostics_never_echo_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current, _, policy = self.fixtures(root)
            data = copy.deepcopy(report())
            del data["exact"]["requests"]
            data["untrusted"] = "synthetic-value-must-not-escape"
            current.write_text(json.dumps(data))
            result = self.run_cli([sys.executable, str(Path(gate.__file__)), "--current", str(current), "--policy", str(policy), "--decision", str(root / "decision.json")])
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(data["untrusted"], result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
