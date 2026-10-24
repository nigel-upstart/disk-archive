#!/usr/bin/env python3
"""Real-binary CLI invariants on a private synthetic tree; never use ambient configuration."""

import argparse
import os
import pathlib
import subprocess
import tempfile
import time
import unittest


BINARY = None


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="synthetic-archive-cli-")
        self.addCleanup(self.directory.cleanup)
        self.base = pathlib.Path(self.directory.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir(mode=0o700)
        self.source = self.root / "source.jsonl"
        self.source.write_bytes(b"synthetic untouched input\n")
        # Let asynchronous new-file inspection settle before setting the atime sentinel.
        # A no-archiver control reproduced that inspection on the local macOS host.
        time.sleep(0.25)
        os.utime(self.source, ns=(1_000_000_000, 2_000_000_000))
        self.work = self.base / "work"
        self.env = {
            "PATH": os.defpath,
            "HOME": str(self.base),
            "DISK_ARCHIVE_BUCKET": "synthetic-archive",
            "DISK_ARCHIVE_PREFIX": "synthetic",
            "DISK_ARCHIVE_WORK_DIR": str(self.work),
            "DISK_ARCHIVE_ROOTS_ALL_FILES": str(self.root),
            "DISK_ARCHIVE_MIN_AGE_DAYS": "0",
            "DISK_ARCHIVE_WORKERS": "1",
        }

    def run_cli(self, *args):
        return subprocess.run([str(BINARY), *args], cwd=self.base, env=self.env,
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, check=False)

    def assert_static_failure(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Error: Configuration\n")
        self.assertFalse(self.work.exists())
        self.assertEqual(set(self.root.iterdir()), {self.source})

    def test_atime_sentinel_detects_a_real_content_read(self):
        before = self.source.stat().st_atime_ns
        self.source.read_bytes()
        self.assertNotEqual(self.source.stat().st_atime_ns, before)

    def test_dry_run_is_metadata_only_and_does_not_initialize_work(self):
        before = self.source.stat()
        result = self.run_cli("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "eligible=1 retained=0 redaction=unknown verification=unknown\n")
        self.assertEqual(result.stderr, "")
        after = self.source.stat()
        self.assertEqual((before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns))
        self.assertFalse(self.work.exists())
        self.assertEqual(set(self.root.iterdir()), {self.source})
        self.assertEqual(self.source.read_bytes(), b"synthetic untouched input\n")

    def test_dry_run_never_opens_existing_state_or_creates_locks(self):
        self.work.mkdir(mode=0o700)
        state = self.work / "state.sqlite"
        state.write_bytes(b"synthetic sentinel, deliberately not SQLite")
        time.sleep(0.25)
        os.utime(state, ns=(1_000_000_000, 2_000_000_000))
        before = state.stat()
        result = self.run_cli("--dry-run", "--limit", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "eligible=0 retained=0 redaction=unknown verification=unknown\n")
        after = state.stat()
        self.assertEqual((before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns))
        self.assertEqual(set(self.work.iterdir()), {state})
        self.assertEqual(state.read_bytes(), b"synthetic sentinel, deliberately not SQLite")

    def test_missing_quiescence_is_rejected_before_mutable_setup(self):
        self.assert_static_failure(self.run_cli())

    def test_invalid_mutable_configuration_fails_before_catalog_or_provider_setup(self):
        original = self.env.copy()
        del self.env["DISK_ARCHIVE_WORK_DIR"]
        self.assert_static_failure(self.run_cli("--quiescent"))
        self.env = original
        del self.env["DISK_ARCHIVE_ROOTS_ALL_FILES"]
        self.assert_static_failure(self.run_cli("--quiescent"))

    def test_malformed_arguments_and_missing_explicit_env_are_value_free(self):
        for args in [("--workers", "0"), ("--dry-run", "--unknown"),
                     ("--help", "-h"), ("--env-file", str(self.base / "missing"))]:
            with self.subTest(args=args):
                self.assert_static_failure(self.run_cli(*args))

    def test_env_file_does_not_consume_options_as_paths(self):
        for option in ["--dry-run", "--quiescent", "--help", "-h", "--env-file",
                       "--limit", "--workers", "--queue-capacity", "--blocking-threads",
                       "--unknown"]:
            with self.subTest(option=option):
                (self.base / option).write_text("# synthetic dotenv\n")
                # Help keeps the old parser safely away from mutable setup while
                # exposing its acceptance of the preceding option as a filename.
                self.assert_static_failure(self.run_cli("--env-file", option, "--help"))
        for args in [("--env-file",), ("--env-file", ""),
                     ("--dry-run", "--env-file")]:
            with self.subTest(args=args):
                self.assert_static_failure(self.run_cli(*args))

    def test_explicit_option_like_env_path_preserves_dry_run(self):
        (self.base / "--dry-run").write_text("# synthetic dotenv\n")
        before = self.source.stat()
        result = self.run_cli("--env-file", "./--dry-run", "--dry-run", "--limit", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "eligible=0 retained=0 redaction=unknown verification=unknown\n")
        self.assertEqual(result.stderr, "")
        after = self.source.stat()
        self.assertEqual((before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns))
        self.assertFalse(self.work.exists())
        self.assertEqual(set(self.root.iterdir()), {self.source})

    def test_help_does_not_load_configuration(self):
        self.env = {"PATH": os.defpath, "HOME": str(self.base)}
        result = self.run_cli("--help", "--env-file", str(self.base / "missing"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--dry-run inspects metadata only", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertFalse(self.work.exists())


def main():
    global BINARY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    BINARY = parser.parse_args().binary.resolve(strict=True)
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(CliTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
