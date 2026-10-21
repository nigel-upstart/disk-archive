"""Synthetic optional profiling validation controls; no production runtime access."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("profile_validate", ROOT / "scripts/profile-validate.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class ProfileTests(unittest.TestCase):
    def check(self, mode, value):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            path.write_text(json.dumps(value))
            validator.validate(mode, path)

    def test_trace_safe_fields(self):
        self.check("trace", [{"ph": "B", "ts": 1, "tid": 1, "name": "scan", "args": {"file_id": 1}}])
        for event in (
            {"ph": "B", "ts": 1, "tid": 1, "name": "raw path", "args": {"file_id": 1}},
            {"ph": "B", "ts": 1, "tid": 1, "name": "scan", "args": {"file_id": "raw path"}},
            {"ph": "B", "ts": 1, "tid": 1, "name": "scan", "args": {"file_id": 1, "body": "hidden"}},
            {"ph": "B", "ts": 1, "tid": 1, "name": "scan", "args": {"file_id": 1}, ".file": "raw path"},
            {"ph": "M", "args": {"name": "input-derived-thread"}},
        ):
            with self.subTest(event=event), self.assertRaises(ValueError):
                self.check("trace", [event])

    def test_planted_private_markers_never_pass(self):
        for marker in validator.CANARIES:
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                self.check("cpu", {"meta": {"bad": marker.decode()}, "threads": [{"samples": {"stack": [0]}}]})

    def test_heap_command_is_fixed(self):
        self.check("heap", {"dhatFileVersion": 2, "mode": "rust-heap", "cmd": "disk-archive synthetic profile", "pps": [{}]})
        with self.assertRaises(ValueError):
            self.check("heap", {"dhatFileVersion": 2, "mode": "rust-heap", "cmd": "arbitrary command", "pps": [{}]})

    def test_cpu_requires_schema_and_samples(self):
        self.check("cpu", {"meta": {}, "threads": [{"samples": {"stack": [0]}}]})
        with self.assertRaises(ValueError):
            self.check("cpu", {"meta": {}, "threads": []})

    def test_empty_or_missing_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing"
            with self.assertRaises(ValueError):
                validator.validate("trace", path)
            path.touch()
            with self.assertRaises(ValueError):
                validator.validate("trace", path)


if __name__ == "__main__":
    unittest.main()
