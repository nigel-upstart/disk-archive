"""Synthetic fingerprint controls; no production files or user environment dump."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import unittest.mock

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

    def test_every_codegen_override_and_committed_profile_changes_the_digest(self):
        base = fingerprint.flag_digest({})
        for name in ("CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS", "CARGO_PROFILE_BENCH_PANIC", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CC"):
            self.assertNotEqual(fingerprint.flag_digest({name: "true"}), base, name)
        for name in ("CARGO_BUILD_JOBS", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "HOME"):
            self.assertEqual(fingerprint.flag_digest({name: "4"}), base, name)
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as home:
            root = Path(temporary)
            (root / "Cargo.toml").write_text('[workspace]\n[profile.release]\nlto = true\n')
            with unittest.mock.patch.dict(fingerprint.os.environ, {"CARGO_HOME": home}):
                first = fingerprint.build_configuration(root)
                (root / "Cargo.toml").write_text('[workspace]\n[profile.release]\nlto = true\noverflow-checks = true\n')
                profile = fingerprint.build_configuration(root)
                (root / ".cargo").mkdir()
                (root / ".cargo/config.toml").write_text('[build]\nrustflags = ["--cfg", "synthetic"]\n')
                config = fingerprint.build_configuration(root)
            self.assertEqual(len({first, profile, config}), 3)
            self.assertNotIn("synthetic", config)
            self.assertNotEqual(fingerprint.flag_digest({}, first), fingerprint.flag_digest({}, profile))

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
