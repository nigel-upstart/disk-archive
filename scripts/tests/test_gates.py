"""Synthetic-only tests for the tooling gates; never inspect runtime data."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
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

    def test_short_values_are_intentionally_not_exempted(self):
        for value in ("1", "true", "dev"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.check_content("fixture.txt", value.encode(), policy.dotenv_values("KEY=" + value))

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
            verified.write_text('[package]\nname="verified"\n[lints]\nworkspace=true')
            policy.check_manifest(verified)
            path.write_text('[package]\nname="unlinted"')
            with self.assertRaises(ValueError):
                policy.check_manifest(path)

    def test_unused_git_overrides_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Cargo.toml"
            for section, name in (("patch.crates-io", "unused"), ("replace", "unused:1.0.0")):
                for selector in ('branch="main"', 'tag="v1"', 'rev="1234"'):
                    path.write_text('[' + section + ']\n"' + name + '"={git="https://github.com/mongodb/kingfisher",' + selector + '}')
                    with self.subTest(section=section, selector=selector), self.assertRaises(ValueError):
                        policy.check_manifest(path)

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

    def test_metadata_forbids_credentials_process(self):
        metadata = {"packages": [{"id": "aws", "name": "aws-config", "source": None}], "resolve": {"nodes": [{"id": "aws", "features": ["credentials-process"]}]}}
        with patch.object(policy.pathlib.Path, "glob", return_value=[]), patch.object(policy, "check_manifest"), patch.object(policy.pathlib.Path, "exists", return_value=False), patch.object(policy.subprocess, "check_output", return_value=json.dumps(metadata).encode()) as metadata_call:
            with self.assertRaisesRegex(ValueError, "credentials-process"):
                policy.check_workspace()
            self.assertIn("--all-features", metadata_call.call_args.args[0])

    def test_metadata_checks_only_verified_package(self):
        metadata = {"packages": [], "resolve": {"nodes": []}}
        isolated = {"packages": [{"manifest_path": "/unrelated/Cargo.toml", "dependencies": ["allowed"]}, {"manifest_path": str(Path("crates/verified/Cargo.toml").resolve()), "dependencies": []}]}
        with patch.object(policy.pathlib.Path, "glob", return_value=[]), patch.object(policy, "check_manifest"), patch.object(policy.pathlib.Path, "exists", return_value=True), patch.object(policy.subprocess, "check_output", side_effect=[json.dumps(metadata).encode(), json.dumps(isolated).encode()]):
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

    def test_concurrent_retention_preserves_active_failure_context(self):
        with tempfile.TemporaryDirectory() as root:
            env = {**os.environ, "TASK_OUTPUT_VERBOSE": "0", "TASK_OUTPUT_LOG_RETENTION": "1"}
            command = ["bash", str(ROOT / "scripts/quiet-run.sh"), "--"]
            slow = subprocess.Popen(command + ["bash", "-c", "echo slow-context; touch ready; while [[ ! -f release ]]; do sleep 0.01; done; exit 17"], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 10
                while not (Path(root) / "ready").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue((Path(root) / "ready").exists())
                fast = [subprocess.Popen(command + ["true"], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
                for process in fast:
                    out, err = process.communicate(timeout=10)
                    self.assertEqual((process.returncode, out, err), (0, "", ""))
                self.assertEqual(len(list((Path(root) / ".task-logs").glob("active-*"))), 1)
            finally:
                (Path(root) / "release").touch()
                out, err = slow.communicate(timeout=10)
            self.assertEqual(slow.returncode, 17)
            self.assertIn("slow-context", err)
            self.assertNotIn("No such file", err)
            self.assertEqual(len(list((Path(root) / ".task-logs").glob("run-*"))), 1)
            self.assertFalse(list((Path(root) / ".task-logs").glob("active-*")))

    def test_refuses_symlink_log_directory(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / ".task-logs").symlink_to(root)
            self.assertEqual(self.run_quiet(root, "--", "true").returncode, 2)


class SbomTests(unittest.TestCase):
    def test_stale_member_output_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            for name in ("policy.py", "sbom.sh"):
                shutil.copy(ROOT / "scripts" / name, root / "scripts" / name)
            (root / "Cargo.toml").write_text("[workspace]\n")
            member = root / "crates/test/Cargo.toml"
            member.parent.mkdir(parents=True)
            member.write_text("")
            source = member.parent / "disk-archive-bom.json"
            source.write_text('{"stale":true}')
            binary = root / "bin"
            binary.mkdir()
            metadata = {"workspace_members": ["test"], "packages": [{"id": "test", "name": "test", "manifest_path": str(member), "source": None}], "resolve": {"nodes": []}}
            (binary / "cargo").write_text(
                "#!/usr/bin/env python3\nimport json, os, pathlib, sys\n"
                + "if sys.argv[1] == 'metadata': print(" + repr(json.dumps(metadata)) + ")\n"
                + "elif os.environ.get('FAKE_GENERATE') == '1': pathlib.Path(" + repr(str(source)) + ").write_text('{\"fresh\":true}')\n"
            )
            (binary / "cyclonedx").write_text("#!/usr/bin/env bash\nexit 0\n")
            for path in binary.iterdir():
                path.chmod(0o700)
            env = {**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"], "FAKE_GENERATE": "0"}
            command = ["bash", "scripts/sbom.sh"]
            result = subprocess.run(command, cwd=root, env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(source.exists())
            self.assertFalse((root / "target/sbom/test.cdx.json").exists())
            result = subprocess.run(command, cwd=root, env={**env, "FAKE_GENERATE": "1"}, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((root / "target/sbom/test.cdx.json").read_text()), {"fresh": True})


class SecretScanTests(unittest.TestCase):
    def test_pem_grammar_exception_is_exact_and_path_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy(ROOT / ".gitleaks.toml", root / ".gitleaks.toml")
            path = root / "crates/verified/src/pem.rs"
            path.parent.mkdir(parents=True)
            content = (ROOT / "crates/verified/src/pem.rs").read_text()
            path.write_text(content)
            command = ["gitleaks", "dir", ".", "--redact", "--no-banner"]
            self.assertEqual(subprocess.run(command, cwd=root, capture_output=True).returncode, 0)
            path.write_text(content.replace("is_some()", "is_none()"))
            self.assertNotEqual(subprocess.run(command, cwd=root, capture_output=True).returncode, 0)
            path.unlink()
            (root / "other.rs").write_text(content)
            self.assertNotEqual(subprocess.run(command, cwd=root, capture_output=True).returncode, 0)

    def test_exact_allowlist_requires_both_content_and_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy(ROOT / ".gitleaks.toml", root / ".gitleaks.toml")
            path = root / "legacy/python/tests/test_redactor.py"
            path.parent.mkdir(parents=True)
            # Build the assignment at runtime so this negative scanner test is
            # not itself a literal credential-shaped source-code finding.
            name = "_".join(("JIRA", "TOKEN"))
            allowed = name + "=" + "abc123def456 "
            path.write_text(allowed)
            command = ["gitleaks", "dir", ".", "--redact", "--no-banner"]
            result = subprocess.run(command, cwd=root, capture_output=True)
            self.assertEqual(result.returncode, 0)
            path.write_text(allowed + "\n" + name + "=" + "q1w2e3r4t5y6u7i8o9p0 ")
            self.assertNotEqual(subprocess.run(command, cwd=root, capture_output=True).returncode, 0)
            path.unlink()
            (root / "other.txt").write_text(allowed)
            self.assertNotEqual(subprocess.run(command, cwd=root, capture_output=True).returncode, 0)


class RulePathTests(unittest.TestCase):
    def test_exceptions_are_path_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "rules/policy", root / "rules/policy")
            (root / "sgconfig.yml").write_text("ruleDirs: [rules/policy]\n")
            samples = {
                "crates/core/src/config.rs": 'fn f() { std::env::var("KEY"); }',
                "crates/core/src/other.rs": 'fn f() { std::env::var("KEY"); }',
                "crates/archiver/src/delete.rs": 'fn delete(path: PathBuf) { unlink(path); }',
            }
            for name, content in samples.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            result = subprocess.run(["ast-grep", "scan", "--json=compact"], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            matches = json.loads(result.stdout)
            self.assertEqual({match["file"] for match in matches}, {"crates/core/src/other.rs", "crates/archiver/src/delete.rs"})
            self.assertEqual([match["ruleId"] for match in matches if match["file"].endswith("delete.rs")], ["delete-requires-token"])


if __name__ == "__main__":
    unittest.main()
