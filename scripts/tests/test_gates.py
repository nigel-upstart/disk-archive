"""Synthetic-only tests for the tooling gates; never inspect runtime data."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("policy", ROOT / "scripts/policy.py")
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class PolicyTests(unittest.TestCase):
    def test_dotenv_literals_and_comments(self):
        self.assertEqual(policy.dotenv_values("# comment\nexport KEY='synthetic value' # note\nOTHER=literal # note\nEMPTY="), ["synthetic value", "literal"])

    def test_dotenv_rejects_ambiguous_or_executable_values(self):
        for content in ('KEY="${HOME}"', "KEY=$(id)", 'KEY="unterminated', "bad line", 'KEY="a\\nb"'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                policy.dotenv_values(content)

    def test_secret_value_is_not_in_diagnostic(self):
        with self.assertRaises(ValueError) as caught:
            policy.check_content("fixture.txt", b"unique-synthetic-sentinel", ["unique-synthetic-sentinel"])
        self.assertNotIn("unique-synthetic-sentinel", str(caught.exception))

    def test_forbidden_paths_and_size(self):
        for name in (".env", "sub/.env.local", "sub/.env/a"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.check_content(name, b"", [])
        policy.check_content(".env.example", b"KEY=placeholder", [])
        with self.assertRaises(ValueError):
            policy.check_content("large", b"a" * (policy.MAX_FILE_BYTES + 1), [])

    def test_manifest_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "Cargo.toml"
            for selector in ('branch="main"', 'tag="v1"', 'rev="1234"'):
                path.write_text('[dependencies]\nx={git="https://github.com/mongodb/kingfisher",' + selector + '}')
                with self.assertRaises(ValueError):
                    policy.check_manifest(path)
            verified = root / "verified/Cargo.toml"
            verified.parent.mkdir()
            for section in ("dependencies", "dev-dependencies", "build-dependencies", "target.'cfg(unix)'.dependencies"):
                verified.write_text(f'[{section}]\nx="1"')
                with self.assertRaises(ValueError):
                    policy.check_manifest(verified)
            verified.write_text('[package]\nname="verified"')
            policy.check_manifest(verified)

    def test_staged_guard_checks_index_not_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet", temporary], check=True)
            (root / ".env").write_text("KEY=unique-synthetic-sentinel")
            (root / "fixture").write_text("unique-synthetic-sentinel")
            subprocess.run(["git", "-C", temporary, "add", "fixture"], check=True)
            (root / "fixture").write_text("now harmless")
            result = subprocess.run(["python3", str(ROOT / "scripts/policy.py"), "staged"], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("unique-synthetic-sentinel", result.stderr)
            subprocess.run(["git", "-C", temporary, "add", "fixture"], check=True)
            subprocess.run(["python3", str(ROOT / "scripts/policy.py"), "staged"], cwd=root, check=True)

    def test_metadata_checks_only_verified_package(self):
        metadata = {"packages": [], "resolve": {"nodes": []}}
        with patch.object(policy.pathlib.Path, "glob", return_value=[]), patch.object(policy, "check_manifest"), patch.object(policy.pathlib.Path, "exists", return_value=False), patch.object(policy.subprocess, "check_output", return_value=json.dumps(metadata).encode()):
            policy.check_workspace()


class QuietTests(unittest.TestCase):
    def run_quiet(self, root, *args, **environment):
        env = {**os.environ, "TASK_OUTPUT_VERBOSE": "0", **environment}
        return subprocess.run(["bash", str(ROOT / "scripts/quiet-run.sh"), *args], cwd=root, env=env, capture_output=True, text=True)

    def test_success_is_quiet_failure_preserves_status_and_context(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.run_quiet(root, "--", "bash", "-c", "echo synthetic-output")
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
            result = self.run_quiet(root, "--", "bash", "-c", "echo context; exit 17")
            self.assertEqual(result.returncode, 17)
            self.assertIn("context", result.stderr)
            logs = list((Path(root) / ".task-logs").glob("run-*"))
            self.assertEqual(len(logs), 2)
            self.assertEqual(logs[0].stat().st_mode & 0o777, 0o600)

    def test_verbose_pattern_retention_and_invalid_input(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.run_quiet(root, "--success-pattern", "keep", "--", "printf", "keep\ndrop\n")
            self.assertEqual(result.stdout, "keep\n")
            result = self.run_quiet(root, "--", "printf", "verbose", TASK_OUTPUT_VERBOSE="1", TASK_OUTPUT_LOG_RETENTION="1")
            self.assertEqual(result.stdout, "verbose")
            self.assertEqual(len(list((Path(root) / ".task-logs").glob("run-*"))), 1)
            result = self.run_quiet(root, "--", "true", TASK_OUTPUT_LOG_RETENTION="0")
            self.assertEqual(result.returncode, 2)

    def test_refuses_symlink_log_directory(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / ".task-logs").symlink_to(root)
            self.assertEqual(self.run_quiet(root, "--", "true").returncode, 2)


class RulePathTests(unittest.TestCase):
    def test_exceptions_are_path_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "rules/policy", root / "rules/policy")
            (root / "sgconfig.yml").write_text("ruleDirs: [rules/policy]\n")
            samples = {
                "crates/core/src/config.rs": 'fn f() { std::env::var("KEY"); }',
                "crates/core/src/other.rs": 'fn f() { std::env::var("KEY"); }',
            }
            for name, content in samples.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            result = subprocess.run(["ast-grep", "scan", "--json=compact"], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            matches = json.loads(result.stdout)
            self.assertEqual({match["file"] for match in matches}, {"crates/core/src/other.rs"})


if __name__ == "__main__":
    unittest.main()
