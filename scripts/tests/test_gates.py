"""Synthetic-only tests for the tooling gates; never inspect runtime data."""

import copy
import datetime
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
NATIVE_SPEC = importlib.util.spec_from_file_location("cache_native", ROOT / "scripts/ci-cache-native.py")
cache_native = importlib.util.module_from_spec(NATIVE_SPEC)
NATIVE_SPEC.loader.exec_module(cache_native)


def isolated_git_environment():
    """Scratch Git must never inherit the hook caller's repository selectors."""
    names = subprocess.check_output(["git", "rev-parse", "--local-env-vars"], text=True).splitlines()
    return {key: value for key, value in os.environ.items() if key not in names}


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
            git_env = isolated_git_environment()
            subprocess.run(["git", "init", "--quiet", temporary], check=True, env=git_env)
            (root / ".env").write_text("KEY=unique-synthetic-sentinel")
            (root / "fixture").write_text("unique-synthetic-sentinel")
            subprocess.run(["git", "-C", temporary, "add", "fixture"], check=True, env=git_env)
            (root / "fixture").write_text("now harmless")
            result = subprocess.run(["python3", str(ROOT / "scripts/policy.py"), "staged"], cwd=root, capture_output=True, text=True, env=git_env)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("unique-synthetic-sentinel", result.stderr)
            subprocess.run(["git", "-C", temporary, "add", "fixture"], check=True, env=git_env)
            subprocess.run(["python3", str(ROOT / "scripts/policy.py"), "staged"], cwd=root, check=True, env=git_env)

    def test_dependency_exceptions_expire_and_require_attribution(self):
        text = """
[advisories]
ignore = [
  { id = "RUSTSEC-0000-0000", reason = "Owner: maintainer; #17; expires 2026-11-21; synthetic fixture" },
]
"""
        policy.check_exceptions(text, datetime.date(2026, 10, 21))
        with self.assertRaisesRegex(ValueError, "expired"):
            policy.check_exceptions(text, datetime.date(2026, 11, 21))
        for malformed in (
            '[advisories]\nignore=["RUSTSEC-0000-0000"]',
            '[bans]\nskip=[{crate="broad",reason="Owner: maintainer; #17; expires 2026-11-21"}]',
            '[advisories]\nignore=[{id="RUSTSEC-0000-0000",reason="expires 2026-11-21"}]',
        ):
            with self.assertRaises(ValueError):
                policy.check_exceptions(malformed, datetime.date(2026, 10, 21))

    def test_scanner_validation_aliases_and_opt_ins_fail_closed(self):
        policy.check_scanner_features("kingfisher-scanner", [])
        policy.check_scanner_features("kingfisher-scanner", ["default"])
        for feature in ("validation", "validation-aws", "validation-http", "git", "archives", "context", "future-network-feature"):
            with self.subTest(feature=feature), self.assertRaises(ValueError):
                policy.check_scanner_features("kingfisher-scanner", [feature])
        policy.check_scanner_features("unrelated", ["validation"])

    def test_metadata_forbids_credentials_process(self):
        metadata = {"packages": [{"id": "aws", "name": "aws-config", "source": None}], "resolve": {"nodes": [{"id": "aws", "features": ["credentials-process"]}]}}
        with patch.object(policy.pathlib.Path, "glob", return_value=[]), patch.object(policy, "check_manifest"), patch.object(policy.pathlib.Path, "exists", return_value=False), patch.object(policy.subprocess, "check_output", return_value=json.dumps(metadata).encode()) as metadata_call:
            with self.assertRaisesRegex(ValueError, "credentials-process"):
                policy.check_workspace()
            self.assertIn("--all-features", metadata_call.call_args.args[0])

    def test_metadata_checks_only_verified_package(self):
        metadata = {"packages": [], "resolve": {"nodes": []}}
        isolated = {"packages": [{"manifest_path": "/unrelated/Cargo.toml", "dependencies": ["allowed"]}, {"manifest_path": str(Path("crates/verified/Cargo.toml").resolve()), "dependencies": []}]}
        with patch.object(policy.pathlib.Path, "glob", return_value=[]), patch.object(policy, "check_manifest"), patch.object(policy, "check_vendor"), patch.object(policy.pathlib.Path, "exists", return_value=True), patch.object(policy.subprocess, "check_output", side_effect=[json.dumps(metadata).encode(), json.dumps(isolated).encode()]):
            policy.check_workspace()


class CacheKeyTests(unittest.TestCase):
    def test_native_closure_allows_only_unrelated_lock_churn(self):
        lock = {"package": [
            {"name": "kingfisher-vectorscan", "version": "0.1.1", "checksum": "wrapper", "dependencies": ["kingfisher-vectorscan-sys"]},
            {"name": "kingfisher-vectorscan-sys", "version": "0.1.1", "checksum": "native", "dependencies": ["cc"]},
            {"name": "cc", "version": "1.0.0", "checksum": "build", "dependencies": ["shlex"]},
            {"name": "shlex", "version": "1.0.0", "checksum": "transitive"},
            {"name": "application-only", "version": "1.0.0", "checksum": "unrelated"},
        ]}
        original = cache_native.fingerprint(lock)
        lock["package"][-1]["checksum"] = "changed"
        self.assertEqual(original, cache_native.fingerprint(lock))
        disambiguated = copy.deepcopy(lock)
        disambiguated["package"].append({"name": "cc", "version": "2.0.0", "checksum": "unrelated-new-API"})
        disambiguated["package"][1]["dependencies"] = ["cc 1.0.0"]
        self.assertEqual(original, cache_native.fingerprint(disambiguated))
        for index in range(4):
            changed = copy.deepcopy(lock)
            changed["package"][index]["checksum"] += "change"
            self.assertNotEqual(original, cache_native.fingerprint(changed))
        for broken in [{"package": []}, {"package": lock["package"] + [lock["package"][2]]}, {"package": lock["package"][:3]}]:
            with self.assertRaises(ValueError):
                cache_native.fingerprint(broken)

    def test_fallback_is_ref_scoped_and_keeps_native_compatibility_inputs(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        blocks = workflow.split("restore-keys: |\n")[1:]
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            lines = block.splitlines()[:2]
            self.assertIn("${{ github.ref }}", lines[0])
            self.assertIn("refs/heads/main", lines[1])
            for line in lines:
                self.assertIn("outputs.digest", line)
                self.assertIn("outputs.native", line)
                self.assertIn("hashFiles(", line)
                self.assertNotIn("Cargo.lock", line)
                self.assertIn("CMakeLists.txt", line)
                self.assertIn("crates/scanner/Cargo.toml", line)

    def test_sdk_reclamation_is_hosted_linux_only_and_has_fixed_roots(self):
        script = (ROOT / "scripts/ci-cache-key.sh").read_text()
        reclaim, separator, _ = script.partition("case $mode in")
        self.assertTrue(separator)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            calls = root / "sudo-args"
            sudo = binary / "sudo"
            sudo.write_text("#!/bin/sh\nprintf '%s\\n' CALL \"$@\" >> \"$MOCK_SUDO_ARGS\"\n")
            sudo.chmod(0o700)
            df = binary / "df"
            df.write_text("#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\nsynthetic 0 0 %s 0%% /\\n' \"$MOCK_FREE_KIB\"\nexit \"$MOCK_DF_STATUS\"\n")
            df.chmod(0o700)
            names = ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS")
            environment = {key: value for key, value in os.environ.items() if key not in names}
            environment.update(PATH=str(binary) + os.pathsep + os.environ["PATH"],
                               MOCK_SUDO_ARGS=str(calls))
            hosted = dict(zip(names, ("true", "github-hosted", "Linux")))
            invalid = [{}]
            for name, values in [("GITHUB_ACTIONS", (None, "false", "1")),
                                 ("RUNNER_ENVIRONMENT", (None, "self-hosted")),
                                 ("RUNNER_OS", (None, "macOS", "Windows"))]:
                for value in values:
                    case = hosted.copy()
                    if value is None:
                        del case[name]
                    else:
                        case[name] = value
                    invalid.append(case)
            for case in invalid:
                with self.subTest(environment=case):
                    calls.unlink(missing_ok=True)
                    subprocess.run(["bash", "-c", reclaim, "reclaim", "workspace"],
                                   env={**environment, **case}, cwd=root, check=True)
                    self.assertFalse(calls.exists())
            threshold = 16 * 1024 * 1024
            for mode, free, status, deletes in [("workspace", threshold, 0, True),
                                                   ("fuzz", threshold, 0, True),
                                                   ("perf", threshold, 0, False),
                                                   ("perf", threshold - 1, 0, True),
                                                   ("perf", threshold, 1, True)]:
                with self.subTest(mode=mode, free=free, status=status):
                    calls.unlink(missing_ok=True)
                    subprocess.run(["bash", "-c", reclaim, "reclaim", mode], cwd=root, check=True,
                                   env={**environment, **hosted, "MOCK_FREE_KIB": str(free), "MOCK_DF_STATUS": str(status)})
                    self.assertEqual(calls.exists(), deletes)
                    if deletes:
                        self.assertEqual(calls.read_text().splitlines(), [
                            "CALL", "-n", "rm", "-rf", "--", "/usr/local/lib/android",
                            "/usr/share/dotnet", "/usr/local/.ghcup",
                        ])

    def test_dynamic_cpu_fields_do_not_break_safe_cache_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            for name in ("rustc", "cargo", "cc", "c++", "cmake"):
                path = binary / name
                path.write_text("#!/bin/sh\nprintf 'pinned-compiler\\n'\n")
                path.chmod(0o700)
            cpu = binary / "lscpu"
            cpu.write_text("#!/bin/sh\nprintf 'Architecture: x86_64\\nVendor ID: GenuineIntel\\nModel name: fixed\\nFlags: %s\\nCPU MHz: %s\\n' \"$MOCK_FLAGS\" \"$MOCK_MHZ\"\n")
            cpu.chmod(0o700)
            sha = binary / "sha256sum"
            sha.write_text("#!/usr/bin/env python3\nimport hashlib,sys\nprint(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\n")
            sha.chmod(0o700)
            output = root / "output"
            environment = {**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"], "GITHUB_OUTPUT": str(output), "MOCK_FLAGS": "avx2 sse4_2"}
            def digest(mhz, flags):
                output.write_text("")
                subprocess.run(["bash", str(ROOT / "scripts/ci-cache-key.sh"), "workspace"], env={**environment, "MOCK_MHZ": mhz, "MOCK_FLAGS": flags}, cwd=ROOT, check=True)
                return output.read_text()
            self.assertEqual(digest("1000", "avx2 sse4_2"), digest("3200", "avx2 sse4_2"))
            self.assertNotEqual(digest("1000", "avx2 sse4_2"), digest("1000", "sse4_2"))


class AuditBuildTests(unittest.TestCase):
    GRAPH = ["test", "--workspace", "--all-features", "--locked", "--no-run", "--message-format=json"]

    @staticmethod
    def artifact(target, executable="/synthetic/custom-target/test-binary", kind="test"):
        return {"reason": "compiler-artifact", "target": {"name": target, "kind": [kind]},
                "profile": {"test": kind == "test"}, "executable": executable}

    def scanner_build(self, messages, status=0):
        # Execute the actual build/selection prefix, never a mocked syscall audit.
        script, separator, _ = (ROOT / "scripts/scanner-offline.sh").read_text().partition("case $(uname -s) in")
        self.assertTrue(separator)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.mkdir()
            cargo = binary / "cargo"
            cargo.write_text("#!/usr/bin/env python3\nimport json, os, pathlib, sys\n"
                             "pathlib.Path('arguments.json').write_text(json.dumps(sys.argv[1:]))\n"
                             "print(os.environ['MOCK_MESSAGES'])\n"
                             "raise SystemExit(int(os.environ['MOCK_STATUS']))\n")
            cargo.chmod(0o700)
            (root / "target").mkdir()
            (root / "target/scanner-test-build.json").write_text(json.dumps(self.artifact("catalog", "/stale")))
            env = {**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                   "MOCK_MESSAGES": "\n".join(json.dumps(message) for message in messages),
                   "MOCK_STATUS": str(status)}
            result = subprocess.run(["bash", "-c", script + '\nprintf "%s\\n" "$binary"\n'],
                                    cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(json.loads((root / "arguments.json").read_text()), self.GRAPH)
            return result

    def archiver_run(self, messages, status=0, audit=True):
        spec = importlib.util.spec_from_file_location("archiver_runner", ROOT / "crates/archiver/tests/run.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        completed = subprocess.CompletedProcess([], status, "\n".join(json.dumps(message) for message in messages))
        expected = self.GRAPH if audit else ["build", "-p", "disk-archive", "--bin", "disk-archive", "--locked", "--message-format=json"]
        with patch.object(runner.sys, "argv", ["run.py", *(["--audit"] if audit else [])]), patch.object(runner.subprocess, "run", return_value=completed) as run:
            try:
                runner.main()
            except RuntimeError:
                self.assertEqual(run.call_count, 1)  # No audit/CLI launch after a bad build.
                raise
            finally:
                self.assertEqual(run.call_args_list[0].args[0], ["cargo", *expected])
                self.assertEqual(run.call_args_list[0].kwargs["cwd"], ROOT)
            calls = run.call_args_list
        return calls

    def test_scanner_matches_workspace_graph_and_selects_test_executable(self):
        good = self.artifact("catalog")
        result = self.scanner_build([{"reason": "build-finished", "success": True},
                                     self.artifact("unrelated"), self.artifact("catalog", kind="bin"), good])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), good["executable"])

    def test_scanner_rejects_failed_missing_and_ambiguous_builds(self):
        good = self.artifact("catalog")
        for messages, status in [([good], 17), ([], 0), ([self.artifact("catalog", kind="bin")], 0),
                                 ([good, good], 0), ([good, self.artifact("catalog", "/other")], 0),
                                 ([self.artifact("catalog", None)], 0), ([{**good, "profile": {"test": False}}], 0)]:
            with self.subTest(messages=messages, status=status):
                result = self.scanner_build(messages, status)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_archiver_audit_matches_workspace_graph_and_selects_test_executable(self):
        good = self.artifact("pipeline")
        calls = self.archiver_run([self.artifact("other"), self.artifact("pipeline", kind="bin"), good])
        self.assertEqual(len(calls), 2)
        self.assertIn("audit_processes.py", calls[1].args[0][2])
        self.assertEqual(calls[1].args[0][-2:], ["--binary", good["executable"]])
        self.assertTrue(calls[1].kwargs["check"])

    def test_archiver_rejects_failed_missing_and_ambiguous_builds(self):
        good = self.artifact("pipeline")
        for messages, status in [([good], 17), ([], 0), ([self.artifact("pipeline", kind="bin")], 0),
                                 ([good, good], 0), ([good, self.artifact("pipeline", "/other")], 0),
                                 ([self.artifact("pipeline", None)], 0), ([{**good, "profile": {"test": False}}], 0)]:
            with self.subTest(messages=messages, status=status), self.assertRaises(RuntimeError):
                self.archiver_run(messages, status)

    def test_regular_cli_build_graph_is_preserved(self):
        good = self.artifact("disk-archive", kind="bin")
        calls = self.archiver_run([good], audit=False)
        self.assertEqual(len(calls), 3)
        self.assertIn("cli.py", calls[1].args[0][2])
        self.assertEqual(calls[1].args[0][-2:], ["--binary", good["executable"]])
        self.assertEqual(calls[2].args[0][-1], "--self-test")


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
