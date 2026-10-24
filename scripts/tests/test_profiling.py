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

    def test_console_requires_real_numeric_poll_observations(self):
        self.check("console", {"schema": 1, "tasks": 2, "polls": 3, "dropped_events": 0})
        for field in ("tasks", "polls"):
            with self.assertRaises(ValueError):
                self.check("console", {"schema": 1, "tasks": 2, "polls": 3, "dropped_events": 0, field: 0})
        with self.assertRaises(ValueError):
            self.check("console", {"schema": 1, "tasks": 2, "polls": 3, "dropped_events": 0, "raw_task": "unsafe"})

    def test_pipeline_receipt_requires_actual_full_corpus(self):
        receipt = dict(schema=1, files=32, deleted=32, retained=0, rules=488,
                       verified_downloads=32, process_spawns=0, peak_temp_bytes=1234)
        self.check("run", receipt)
        for field in ("deleted", "rules", "verified_downloads", "peak_temp_bytes"):
            with self.assertRaises(ValueError):
                self.check("run", {**receipt, field: 0})

    def test_svg_requires_real_samples_and_decodes_private_entities(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cpu.svg"
            path.write_text('<svg xmlns="http://www.w3.org/2000/svg"><g><title>all (123 samples, 100%)</title></g></svg>')
            validator.validate("svg", path)
            path.write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
            with self.assertRaises(ValueError):
                validator.validate("svg", path)
            marker = ''.join('&#' + str(c) + ';' for c in validator.CANARIES[0])
            path.write_text('<svg xmlns="http://www.w3.org/2000/svg"><title>all (123 samples, 100%)</title><text>' + marker + '</text></svg>')
            with self.assertRaises(ValueError):
                validator.validate("svg", path)

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
