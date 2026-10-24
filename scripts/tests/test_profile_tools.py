"""Fail-closed controls for Cargo selection and the Linux profiling dry-run auditor."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load("profile-build")
auditor = load("profile-dry-run")
EXEC = '123 execve("/synthetic/binary", ["binary"], 0x123) = 0\n'


class BuildTests(unittest.TestCase):
    def artifact(self, path="/synthetic/exact-example"):
        return {"reason": "compiler-artifact", "target": {"name": "profile-corpus", "kind": ["example"]},
                "profile": {"test": False}, "executable": path}

    def select(self, items):
        return builder.executable("\n".join(json.dumps(item) for item in items))

    def test_exact_successful_example_only(self):
        artifact = self.artifact()
        self.assertEqual(self.select([artifact, artifact, {"reason": "build-finished", "success": True}]),
                         Path("/synthetic/exact-example"))

    def test_missing_failed_ambiguous_or_wrong_kind_rejected(self):
        done = {"reason": "build-finished", "success": True}
        artifact = self.artifact()
        for items in ([artifact], [done], [artifact, {**done, "success": False}],
                      [artifact, self.artifact("/synthetic/other"), done],
                      [{**artifact, "target": {"name": "profile-corpus", "kind": ["bin"]}}, done],
                      [{**artifact, "profile": {"test": True}}, done], [artifact, done, done],
                      [None, done], [{**artifact, "executable": None}, done]):
            with self.subTest(items=items), self.assertRaises(ValueError):
                self.select(items)
        with self.assertRaises(ValueError):
            builder.executable("not JSON")


class DryRunAuditTests(unittest.TestCase):
    def test_only_reads_and_initial_exec_allowed(self):
        self.assertEqual(auditor.forbidden(EXEC + '123 openat(AT_FDCWD, "source", O_RDONLY|O_CLOEXEC) = 3\n123 +++ exited with 0 +++'), 0)

    def test_every_resource_attempt_counts_even_failed(self):
        for syscall in ('mkdir("work", 0700) = -1 EACCES', 'socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM',
                        'openat(AT_FDCWD, "tmp", O_RDWR|O_CREAT, 0600) = -1 EACCES',
                        'openat2(AT_FDCWD, "tmp", {flags=O_TMPFILE|O_RDWR}, 24) = -1 EACCES',
                        'flock(3, LOCK_EX|LOCK_NB) = -1 EAGAIN', 'fcntl(3, F_SETLKW, {}) = 0',
                        'clone(child_stack=NULL, flags=0) = 124',
                        'openat(AT_FDCWD, "credential-canary", O_RDONLY) = 3',
                        'execve("/other", [], 0x123) = 0'):
            with self.subTest(syscall=syscall):
                self.assertEqual(auditor.forbidden(EXEC + '123 ' + syscall), 1)

    def test_unknown_incomplete_and_missing_exec_fail_closed(self):
        for trace in ('', 'not a trace', '123 +++ exited with 0 +++',
                      EXEC + '123 clone( <unfinished ...>', EXEC + '123 <... clone resumed>) = 1'):
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                auditor.forbidden(trace)


if __name__ == "__main__":
    unittest.main()
