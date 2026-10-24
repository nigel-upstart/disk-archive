"""Frozen-oracle controls use only copied repository fixtures and synthetic mutations."""

import copy
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
SPEC = importlib.util.spec_from_file_location("frozen_oracle", ROOT / "scripts/frozen-oracle.py")
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)


class FrozenOracleTests(unittest.TestCase):
    def documents(self):
        return [json.loads((oracle.FIXTURES / name).read_bytes()) for name in oracle.SHA256]

    def test_all_16_exact_frozen_cases(self):
        self.assertEqual(oracle.check(), 16)

    def test_missing_or_changed_bytes_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            shutil.copytree(oracle.FIXTURES, directory, dirs_exist_ok=True)
            path = directory / "expected.json"
            original = path.read_bytes()
            for content in (original + b"\n", original[:-1], b"{}"):
                path.write_bytes(content)
                with self.subTest(length=len(content)), self.assertRaises(ValueError):
                    oracle.check(directory)
            path.unlink()
            with self.assertRaises(OSError):
                oracle.check(directory)

    def test_schema_count_ids_order_and_byte_fields_fail_closed(self):
        cases, expected = self.documents()
        mutations = [
            lambda a, b: a.update(schema_version=2),
            lambda a, b: a["cases"].pop(),
            lambda a, b: b["cases"].pop(),
            lambda a, b: a["cases"][0].update(id=a["cases"][1]["id"]),
            lambda a, b: b["cases"].reverse(),
            lambda a, b: a["cases"][0].update(input_hex="0"),
            lambda a, b: b["cases"][0].update(output_hex="zz"),
            lambda a, b: b["cases"][0].update(replacements=-1),
            lambda a, b: b["cases"][0].update(replacements=True),
            lambda a, b: a["cases"][0].update(drop_lines=[0]),
            lambda a, b: a["cases"][0]["findings"][0].update(raw=None),
        ]
        for number, mutate in enumerate(mutations):
            inputs, outputs = copy.deepcopy(cases), copy.deepcopy(expected)
            mutate(inputs, outputs)
            with self.subTest(mutation=number), self.assertRaises(ValueError):
                oracle.validate(inputs, outputs)

    def test_failure_does_not_echo_content(self):
        output = io.StringIO()
        with patch.object(oracle, "check", side_effect=ValueError("synthetic-private-sentinel")), patch("sys.stderr", output):
            self.assertEqual(oracle.main(), 1)
        self.assertNotIn("synthetic-private-sentinel", output.getvalue())

    def test_decoded_hex_allowances_require_exact_content_and_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            shutil.copy(ROOT / ".gitleaks.toml", directory / ".gitleaks.toml")
            content = (oracle.FIXTURES / "cases.json").read_bytes()
            # Deliberately not a key; build delimiters at runtime to avoid a source finding.
            pem = ("-----BEGIN " + "PRIVATE KEY-----\n" + "synthetic-only-body-" * 8 + "\n-----END " + "PRIVATE KEY-----\n").encode()
            command = ["gitleaks", "dir", ".", "--redact", "--no-banner"]
            for name in ("fixtures/redactor/cases.json", "legacy/python/fixtures/redactor/cases.json"):
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                self.assertEqual(subprocess.run(command, cwd=directory, capture_output=True).returncode, 0)
                changed = content.replace(b"synthetic-body".hex().encode(), b"altered-body".hex().encode())
                self.assertNotEqual(changed, content)
                path.write_bytes(changed)
                self.assertNotEqual(subprocess.run(command, cwd=directory, capture_output=True).returncode, 0)
                path.write_bytes(content + pem)
                self.assertNotEqual(subprocess.run(command, cwd=directory, capture_output=True).returncode, 0)
                path.unlink()
            (directory / "other.json").write_bytes(content)
            self.assertNotEqual(subprocess.run(command, cwd=directory, capture_output=True).returncode, 0)

    def test_gate_preserves_real_rust_byte_comparison_and_live_reference(self):
        gate = (ROOT / "scripts/golden-parity.sh").read_text()
        self.assertIn("python3 -B scripts/frozen-oracle.py", gate)
        self.assertIn("python3 -B legacy/python/tests/golden.py --check", gate)
        self.assertIn("cargo test --locked -p disk-archive-core --test golden golden_parity", gate)
        rust = (ROOT / "crates/core/tests/golden.rs").read_text()
        for name in oracle.SHA256:
            self.assertIn("../../../fixtures/redactor/" + name, rust)
        self.assertIn("assert_eq!(output, hex(&expected.output_hex)?", rust)
        self.assertIn("assert_eq!(report.replacements, expected.replacements", rust)


if __name__ == "__main__":
    unittest.main()
