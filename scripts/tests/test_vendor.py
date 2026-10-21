"""Audited source-patch admission regressions; uses only the checked-in upstream source."""

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("storage_policy", ROOT / "scripts/policy.py")
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class VendorPolicyTests(unittest.TestCase):
    def test_exact_admitted_source_and_manifest(self):
        policy.check_vendor()

    def test_no_source_manifest_receipt_or_symlink_escape(self):
        for mutation in ("source", "manifest", "receipt", "symlink", "extra"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                vendor = root / "vendor/transfer-manager"
                shutil.copytree(ROOT / "vendor/transfer-manager", vendor)
                if mutation == "source":
                    path = vendor / "aws-sdk-s3-transfer-manager/src/lib.rs"
                    path.write_bytes(path.read_bytes() + b"\n// synthetic tamper\n")
                elif mutation == "manifest":
                    path = vendor / "Cargo.toml"
                    path.write_text(path.read_text().replace("default-features = false", "default-features = true"))
                elif mutation == "receipt":
                    path = vendor / "provenance.json"
                    path.write_bytes(path.read_bytes() + b" ")
                elif mutation == "symlink":
                    (vendor / "synthetic-link").symlink_to(root / "does-not-exist")
                else:
                    (vendor / "extra.txt").write_text("synthetic")
                with self.assertRaises(ValueError):
                    policy.check_vendor(root)

    def test_path_patch_is_not_general_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "Cargo.toml"
            manifest.write_text('[patch."https://github.com/awslabs/aws-s3-transfer-manager-rs"]\naws-sdk-s3-transfer-manager={path="elsewhere"}\n')
            with self.assertRaisesRegex(ValueError, "unapproved path patch"):
                policy.check_manifest(manifest)
