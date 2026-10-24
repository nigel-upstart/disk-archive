"""Synthetic fingerprint controls; no production files or user environment dump."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("perf_fingerprint", Path(__file__).with_name("fingerprint.py"))
fingerprint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fingerprint)


class FingerprintTests(unittest.TestCase):
    def test_only_build_flags_influence_the_digest_and_never_appear_in_it(self):
        first = fingerprint.flag_digest({"RUSTFLAGS": "--cfg synthetic-private-setting", "AWS_SECRET_ACCESS_KEY": "synthetic-never-record"})
        same = fingerprint.flag_digest({"RUSTFLAGS": "--cfg synthetic-private-setting", "AWS_SECRET_ACCESS_KEY": "different-ignored"})
        changed = fingerprint.flag_digest({"RUSTFLAGS": "-Copt-level=3"})
        self.assertEqual(first, same)
        self.assertNotEqual(first, changed)
        self.assertNotIn("synthetic-private-setting", first)
        self.assertEqual(len(first), 64)

    def test_rules_revision_must_be_an_immutable_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "crates/scanner/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            revision = "a" * 40
            manifest.write_text('[dependencies]\nkingfisher-scanner={rev="' + revision + '"}\n')
            self.assertEqual(fingerprint.rules_revision(root), revision)
            manifest.write_text('[dependencies]\nkingfisher-scanner={rev="main"}\n')
            with self.assertRaises(ValueError):
                fingerprint.rules_revision(root)


if __name__ == "__main__":
    unittest.main()
