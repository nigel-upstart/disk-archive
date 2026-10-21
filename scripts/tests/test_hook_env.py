"""Reproduce hook Git-selector corruption ONLY inside disposable scratch worktrees."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_gates import isolated_git_environment

ROOT = Path(__file__).resolve().parents[2]

# These are the same kinds of Git operations used by fixture setup and advisory
# cache refresh. No network or production repository is involved. Do not claim
# which third-party tool issued the original operations without a process trace.
PROBE = r'''
import json, os, pathlib, subprocess, sys
fixture, remote, cache, report = sys.argv[1:]
local = subprocess.check_output(["git", "rev-parse", "--local-env-vars"], text=True).splitlines()
pathlib.Path(report).write_text(json.dumps({k: os.environ[k] for k in local if k in os.environ}))
subprocess.run(["git", "init", "--quiet", fixture], check=True)
subprocess.run(["git", "-C", fixture, "fetch", "--quiet", remote, "HEAD"], check=True)
subprocess.run(["git", "-C", fixture, "reset", "--hard", "FETCH_HEAD"], check=True)
subprocess.run(["git", "init", "--quiet", "--bare", cache], check=True)
'''


class HookEnvironmentTests(unittest.TestCase):
    def git(self, cwd, *args):
        return subprocess.check_output(["git", "-C", str(cwd), *args], env=self.env, stderr=subprocess.PIPE)

    def repo(self, path):
        subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(path)], env=self.env, check=True)
        self.git(path, "config", "user.name", "Synthetic Test")
        self.git(path, "config", "user.email", "test@example.invalid")
        (path / "tracked").write_text(path.name)
        self.git(path, "add", "tracked")
        self.git(path, "commit", "--quiet", "-m", "synthetic fixture")

    def snapshot(self, path):
        index = Path(self.git(path, "rev-parse", "--git-path", "index").decode().strip())
        if not index.is_absolute():
            index = path / index
        common = Path(self.git(path, "rev-parse", "--git-common-dir").decode().strip())
        if not common.is_absolute():
            common = path / common
        return {
            "head": self.git(path, "rev-parse", "HEAD"),
            "config": (common / "config").read_bytes(),
            "index": index.read_bytes(),
            "files": {p.relative_to(path).as_posix(): p.read_bytes() for p in path.rglob("*")
                      if p.is_file() and ".git" not in p.relative_to(path).parts},
        }

    def exercise(self, wrapped):
        self.env = isolated_git_environment()
        lefthook = shutil.which("lefthook")
        self.assertIsNotNone(lefthook, "mandatory lefthook must be installed")
        with tempfile.TemporaryDirectory(prefix="disk-archive-hook-test-") as directory:
            root = Path(directory)
            source, linked, advisory = (root / n for n in ("source", "linked", "advisory"))
            self.repo(source)
            self.repo(advisory)
            self.git(source, "worktree", "add", "--quiet", "-b", "topic", str(linked))
            remote = root / "remote.git"
            subprocess.run(["git", "init", "--quiet", "--bare", str(remote)], env=self.env, check=True)
            self.git(source, "remote", "add", "origin", str(remote))
            probe, report = root / "probe.py", root / "report.json"
            probe.write_text(PROBE)
            command = ["python3", str(probe), str(root / "fixture"), str(advisory), str(root / "cache.git"), str(report)]
            if wrapped:
                command = ["bash", str(ROOT / "scripts/hook-run.sh"), *command]
            config = "pre-push:\n  commands:\n    probe:\n      run: " + json.dumps(shlex.join(command)) + "\n"
            (source / "lefthook.yml").write_text(config)
            (linked / "lefthook.yml").write_text(config)
            subprocess.run([lefthook, "install"], cwd=linked, env=self.env, check=True, capture_output=True)
            hooks = source / ".git/hooks/pre-push"
            self.assertTrue(hooks.is_file() and os.access(hooks, os.X_OK))
            (linked / "tracked").write_text("unstaged change must survive")
            (linked / "staged").write_text("staged change must survive")
            self.git(linked, "add", "staged")
            before = self.snapshot(linked)
            primary_before = self.snapshot(source)
            # Real Git -> installed Lefthook pre-push -> probe (not a direct wrapper invocation).
            result = subprocess.run(["git", "push", "origin", "topic"], cwd=linked, env=self.env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            after = self.snapshot(linked)
            observed_env = json.loads(report.read_text())
            if wrapped:
                self.assertEqual(observed_env, {})
                self.assertEqual(before, after)
                self.assertEqual(primary_before, self.snapshot(source))
                self.assertEqual(self.git(source, "config", "core.bare").strip(), b"false")
                self.assertTrue((root / "cache.git/HEAD").is_file())
                self.assertEqual(self.git(root / "fixture", "rev-parse", "HEAD"), self.git(advisory, "rev-parse", "HEAD"))
            else:
                self.assertIn("GIT_DIR", observed_env)
                self.assertNotEqual(before["head"], after["head"])
                self.assertNotEqual(before["index"], after["index"])
                self.assertNotEqual(before["config"], after["config"])
                self.assertEqual(self.git(source, "config", "core.bare").strip(), b"true")

    def test_unwrapped_actual_hook_reproduces_selector_corruption_in_scratch(self):
        self.exercise(wrapped=False)

    def test_wrapper_keeps_source_head_config_index_and_worktrees_unchanged(self):
        self.exercise(wrapped=True)

    def test_fixture_subprocesses_are_isolated_even_without_wrapper(self):
        self.env = isolated_git_environment()
        with tempfile.TemporaryDirectory(prefix="disk-archive-fixture-env-") as directory:
            source = Path(directory) / "source"
            self.repo(source)
            before = self.snapshot(source)
            contaminated = {**self.env, "GIT_DIR": str(source / ".git"),
                            "GIT_WORK_TREE": str(source), "GIT_INDEX_FILE": str(source / ".git/index")}
            result = subprocess.run(
                ["python3", "-B", "-m", "unittest", "test_gates.PolicyTests.test_staged_guard_checks_index_not_worktree"],
                cwd=ROOT / "scripts/tests", env=contaminated, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(before, self.snapshot(source))

    def test_partial_commit_secret_guard_uses_temporary_commit_index(self):
        self.env = isolated_git_environment()
        lefthook = shutil.which("lefthook")
        self.assertIsNotNone(lefthook)
        with tempfile.TemporaryDirectory(prefix="disk-archive-partial-index-") as directory:
            source = Path(directory) / "source"
            self.repo(source)
            (source / "scripts").mkdir()
            shutil.copy(ROOT / "scripts/policy.py", source / "scripts/policy.py")
            shutil.copy(ROOT / ".gitleaks.toml", source / ".gitleaks.toml")
            command = ["bash", str(ROOT / "scripts/hook-run.sh"), "bash", str(ROOT / "scripts/gates.sh"), "secrets"]
            config = "pre-commit:\n  commands:\n    guards:\n      run: " + json.dumps(shlex.join(command)) + "\n"
            (source / "lefthook.yml").write_text(config)
            subprocess.run([lefthook, "install"], cwd=source, env=self.env, check=True, capture_output=True)
            # Default index is harmless; only the temporary `commit --only` index
            # contains the sentinel. Clearing GIT_INDEX_FILE without a scoped proxy
            # would silently scan the wrong index and permit this commit.
            sentinel = "unique-synthetic-partial-index-sentinel"
            (source / ".env").write_text("KEY=" + sentinel)
            (source / "tracked").write_text(sentinel)
            before = self.snapshot(source)
            result = subprocess.run(["git", "commit", "--only", "tracked", "-m", "must reject"],
                                    cwd=source, env=self.env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(sentinel.encode(), result.stdout + result.stderr)
            self.assertEqual(before, self.snapshot(source))

    def test_wrapper_preserves_failure_and_requires_command(self):
        env = isolated_git_environment()
        run = lambda args: subprocess.run(["bash", str(ROOT / "scripts/hook-run.sh"), *args], cwd=ROOT, env=env, capture_output=True)
        self.assertEqual(run([]).returncode, 2)
        self.assertEqual(run(["bash", "-c", "exit 17"]).returncode, 17)
        self.assertEqual(run(["true"]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
