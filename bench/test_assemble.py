"""Synthetic assembly controls, not measurements or a hosted noise study."""
from copy import deepcopy
from pathlib import Path
import tomllib
import unittest

from assemble import ADVISORY, CACHE_EVENTS, KERNELS, RESOURCES, assemble
from compare import compare


def inputs():
    policy = tomllib.loads(Path(__file__).with_name("policy.toml").read_text())
    fingerprint = dict(rustc="rustc-test", llvm="llvm-test", flags="a" * 64, profile="bench", target="test-target",
                       valgrind="valgrind-test", gungraun="gungraun-test", cache_configuration="cache-test",
                       cpu_model="test-cpu", nproc=4, corpus_revision="b" * 64, rules_revision="c" * 40,
                       source_commit="d" * 40, source_dirty=False, runner_image="test-image", runner_image_version="test-version",
                       memory_bytes=4096, kernel="test-kernel", workers=2, cpu_jobs=2, queue_capacity=2,
                       max_file_bytes=8 * 1024 * 1024, worker_binary_sha256="e" * 64)
    resources = [dict({name: index + 1 for name in RESOURCES}, includes_process_startup=True, application_counters=None) for index in range(10)]
    app = dict(schema=1, complete=True, binary_sha256="e" * 64,
               exact=dict(process_spawns=0, bytes_uploaded=100, peak_temp_bytes=200, requests={"single/archive-000001": 2, "single/manifest-000000": 1}),
               advisory=dict(zip(ADVISORY, [10, 0, 110, 2, 1, 1, 0.1], strict=True)))
    applications = [deepcopy(app) for _ in range(10)]
    kernels = {name: [dict.fromkeys(CACHE_EVENTS, 100)] for name in KERNELS}
    audit = dict(process_attempts=0, thread_attempts=10, canary_process_attempts=2, binary_sha256="e" * 64)
    return [fingerprint, resources, applications, kernels, audit, policy]


class AssemblyTests(unittest.TestCase):
    def test_complete_observations_compare_record_only_without_baseline(self):
        args = inputs()
        report = assemble(*args)
        decision = compare(report, None, args[-1])
        self.assertFalse(decision["fail"])
        self.assertEqual(decision["mode"], "record-only")
        self.assertEqual(len(report["samples"]), 27)
        self.assertEqual(report["observations"]["applications"], args[2])

    def test_resource_peak_variation_is_preserved_not_forged_equal(self):
        args = inputs()
        args[2][0]["exact"]["peak_temp_bytes"] = 400
        report = assemble(*args)
        self.assertEqual(report["exact"]["peak_temp_bytes"], 400)
        self.assertEqual(report["observations"]["applications"][-1]["exact"]["peak_temp_bytes"], 200)

    def test_semantic_variation_is_never_averaged_away(self):
        for name, value in [("process_spawns", 1), ("bytes_uploaded", 101), ("requests", {"single/archive-000001": 3})]:
            args = inputs()
            args[2][-1]["exact"][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                assemble(*args)

    def test_missing_required_observations_never_become_zero(self):
        for name in ["bytes_uploaded", "requests", "peak_temp_bytes"]:
            args = inputs()
            del args[2][0]["exact"][name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                assemble(*args)
        args = inputs()
        del args[3]["scanner"][0]["D1mr"]
        with self.assertRaises(ValueError):
            assemble(*args)

    def test_actual_process_canary_and_same_binary_required(self):
        for field, value in [("canary_process_attempts", 0), ("process_attempts", 1), ("binary_sha256", "f" * 64)]:
            args = inputs()
            args[4][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                assemble(*args)
        args = inputs()
        args[2][0]["binary_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            assemble(*args)

    def test_absent_zero_and_aliased_transport_counts_refused(self):
        for requests in [{}, {"raw-user-path": 1}, {"single/archive-000000": 0}]:
            args = inputs()
            args[2][0]["exact"]["requests"] = requests
            with self.subTest(requests=requests), self.assertRaises(ValueError):
                assemble(*args)

    def test_incomplete_or_different_population_is_not_a_report(self):
        args = inputs()
        args[2][0]["complete"] = False
        with self.assertRaises(ValueError):
            assemble(*args)
        args = inputs()
        args[1].pop()
        with self.assertRaises(ValueError):
            assemble(*args)
        args = inputs()
        args[2][0]["advisory"]["history_rows"] = 10
        with self.assertRaises(ValueError):
            assemble(*args)

    def test_no_unreviewed_metrics_or_arbitrary_sensitive_extra_fields(self):
        args = inputs()
        args[0]["unrecognized_configuration"] = "not-persisted"
        with self.assertRaises(ValueError):
            assemble(*args)
        args = inputs()
        args[2][0]["advisory"]["unrecognized_runtime_state"] = "not-persisted"
        with self.assertRaises(ValueError):
            assemble(*args)
        args = inputs()
        args[-1]["metrics"]["missing-event"] = {"kind": "deterministic", "tolerance": 0.02}
        with self.assertRaises(ValueError):
            assemble(*args)

    def test_input_receipts_are_not_mutated_or_aliased(self):
        args = inputs()
        before = deepcopy(args)
        report = assemble(*args)
        self.assertEqual(args, before)
        report["observations"]["applications"][0]["exact"]["bytes_uploaded"] = 999
        self.assertEqual(args, before)


if __name__ == "__main__":
    unittest.main()
