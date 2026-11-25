"""Audit wrapper controls with injected tracer/parser, NOT real Linux audit evidence."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from audit import audit, binary_digest


class AuditTests(unittest.TestCase):
    def run_injected(self, *, positive=2, process=0, mutate=False):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "synthetic-binary"
            binary.write_bytes(b"public synthetic executable stand-in")
            initial = binary_digest(binary)
            calls = []

            def trace(command, **kwargs):
                calls.append(command)
                self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                output = Path(command[command.index("-o") + 1])
                output.write_text("canary" if len(calls) == 1 else "workload")
                if mutate and len(calls) == 2:
                    binary.write_bytes(b"changed synthetic binary")

            def parse(trace):
                return {"process_attempts": positive if trace == "canary" else process, "thread_attempts": 4}

            with patch("audit.sys.platform", "linux"), patch("audit.runpy.run_path", return_value={"count_process_attempts": parse}), patch("audit.subprocess.run", side_effect=trace):
                result = audit(binary, ["--synthetic-fixture"], timeout=60)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[-1][-2:], [str(binary.resolve()), "--synthetic-fixture"])
            self.assertEqual(result["binary_sha256"], initial)
            return result

    def test_exact_binary_is_traced_after_positive_canary(self):
        result = self.run_injected()
        self.assertEqual(result["process_attempts"], 0)
        self.assertEqual(result["canary_process_attempts"], 2)

    def test_missing_positive_canary_never_certifies_zero(self):
        with self.assertRaises(ValueError):
            self.run_injected(positive=0)

    def test_process_attempt_and_binary_change_refused(self):
        for args in [{"process": 1}, {"mutate": True}]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.run_injected(**args)

    def test_non_linux_never_skips_to_success(self):
        with patch("audit.sys.platform", "darwin"), self.assertRaises(ValueError):
            audit(Path("unread"), [])

    def test_missing_canonical_parser_and_tracer_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "binary"
            binary.write_bytes(b"stand-in")
            with patch("audit.sys.platform", "linux"), patch("audit.runpy.run_path", side_effect=FileNotFoundError), self.assertRaises(FileNotFoundError):
                audit(binary, [])
            with patch("audit.sys.platform", "linux"), patch("audit.runpy.run_path", return_value={"count_process_attempts": lambda _: {}}), patch("audit.subprocess.run", side_effect=FileNotFoundError), self.assertRaises(FileNotFoundError):
                audit(binary, [])


if __name__ == "__main__":
    unittest.main()
