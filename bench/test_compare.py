"""Synthetic comparator controls; no generated runtime corpus or baseline files."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("perf_compare", Path(__file__).with_name("compare.py"))
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)


def report():
    return {
        "schema": 1,
        "fingerprint": {"cpu_model": "synthetic", "nproc": 4, "corpus_revision": "fixture-v1", "rules_revision": "fixture-rules", "rustc": "pinned", "llvm": "pinned", "flags": "", "profile": "release", "target": "synthetic", "valgrind": "synthetic", "gungraun": "synthetic", "cache_configuration": "synthetic"},
        "exact": {"process_spawns": 0, "bytes_uploaded": 100, "peak_temp_bytes": 50, "requests": {"single": 2}},
        "samples": {"wall": [100.0] * 10, "instructions": [1000] * 10},
    }


POLICY = {"metrics": {"wall": {"kind": "statistical", "tolerance": 0.1}, "instructions": {"kind": "deterministic", "tolerance": 0.02}}}


class ComparatorTests(unittest.TestCase):
    def test_absent_baseline_never_created(self):
        self.assertEqual(compare.compare(report(), None, POLICY)["mode"], "record-only")

    def test_record_only_still_requires_every_observed_counter(self):
        for name in report()["exact"]:
            current = report()
            del current["exact"][name]
            with self.assertRaises(ValueError):
                compare.compare(current, None, POLICY)
        for value in (None, True, -1, 1.5):
            current = report()
            current["exact"]["bytes_uploaded"] = value
            with self.assertRaises(ValueError):
                compare.compare(current, None, POLICY)
        for requests in (None, [], {"single": True}, {"single": -1}):
            current = report()
            current["exact"]["requests"] = requests
            with self.assertRaises(ValueError):
                compare.compare(current, None, POLICY)

    def test_record_only_validates_samples_and_reports_actual_values(self):
        decision = compare.compare(report(), None, POLICY)
        self.assertEqual(decision["metrics"]["wall"]["new_median"], 100)
        self.assertEqual(decision["metrics"]["bytes_uploaded"]["observed"], 100)
        current = report()
        del current["samples"]["instructions"]
        with self.assertRaises(KeyError):
            compare.compare(current, None, POLICY)
        current = report()
        current["samples"]["wall"] = [100] * 9
        with self.assertRaises(ValueError):
            compare.compare(current, None, POLICY)

    def test_bootstrap_policy_is_honored_and_bounded(self):
        policy = copy.deepcopy(POLICY)
        policy.update(bootstrap_rounds=1000, minimum_samples=20)
        current = report()
        current["samples"]["wall"] *= 2
        with patch.object(compare, "median_interval", wraps=compare.median_interval) as interval:
            compare.compare(current, None, policy)
            self.assertEqual(interval.call_args.kwargs["rounds"], 1000)
        for field, value in (("bootstrap_rounds", True), ("bootstrap_rounds", 999), ("bootstrap_rounds", 100001), ("minimum_samples", 9), ("minimum_samples", 1001)):
            invalid = {**policy, field: value}
            with self.assertRaises(ValueError):
                compare.compare(current, None, invalid)
        with self.assertRaises(ValueError):
            compare.compare(report(), None, policy)

    def test_public_missing_baseline_requires_explicit_first_bootstrap(self):
        decision = compare.compare(report(), None, POLICY, public=True)
        self.assertTrue(decision["fail"])
        self.assertEqual(decision["mode"], "blocked-missing-baseline")
        self.assertIn("missing-public-baseline", decision["refresh_required"])
        self.assertFalse(decision["metrics"]["wall"]["gated"])
        bootstrap = compare.compare(report(), None, POLICY, public=True, first_public_bootstrap=True)
        self.assertFalse(bootstrap["fail"])
        self.assertEqual(bootstrap["mode"], "bootstrap-record-only")
        self.assertFalse(bootstrap["metrics"]["instructions"]["gated"])
        for kwargs in ({"first_public_bootstrap": True}, {"public": True, "first_public_bootstrap": "true"}):
            with self.assertRaises(ValueError):
                compare.compare(report(), None, POLICY, **kwargs)
        with self.assertRaises(ValueError):
            compare.compare(report(), report(), POLICY, public=True, first_public_bootstrap=True)

    def test_resource_peak_uses_a_reviewed_upper_envelope_not_equality(self):
        baseline = report()
        current = report()
        current["exact"]["peak_temp_bytes"] = 40
        lower = compare.compare(current, baseline, POLICY, public=True)
        self.assertFalse(lower["fail"])
        self.assertEqual(lower["metrics"]["peak_temp_bytes"]["status"], "below-ceiling")
        current["exact"]["peak_temp_bytes"] = 55
        self.assertTrue(compare.compare(current, baseline, POLICY, public=True)["fail"])
        baseline["resource_ceilings"] = {"peak_temp_bytes": 60}
        envelope = compare.compare(current, baseline, POLICY, public=True)
        self.assertFalse(envelope["fail"])
        self.assertEqual(envelope["metrics"]["peak_temp_bytes"]["ceiling"], 60)
        self.assertEqual(baseline["exact"]["peak_temp_bytes"], 50)
        baseline["resource_ceilings"]["peak_temp_bytes"] = 49
        with self.assertRaises(ValueError):
            compare.compare(current, baseline, POLICY, public=True)

    def test_confirmation_peak_variation_is_not_semantic_mismatch(self):
        current = report()
        current["samples"]["wall"] = [200.0] * 10
        rerun = report()
        rerun["exact"]["peak_temp_bytes"] = 40
        cleared = compare.compare(current, report(), POLICY, public=True, rerun=rerun)
        self.assertFalse(cleared["fail"])
        self.assertNotIn("rerun_exact", cleared["metrics"])
        rerun["exact"]["peak_temp_bytes"] = 51
        exceeded = compare.compare(current, report(), POLICY, public=True, rerun=rerun)
        self.assertTrue(exceeded["fail"])
        self.assertEqual(exceeded["metrics"]["peak_temp_bytes"]["status"], "fail")

    def test_process_canary_fails_without_a_baseline(self):
        current = report()
        current["exact"]["process_spawns"] = 1
        self.assertTrue(compare.compare(current, None, POLICY)["fail"])

    def test_process_invariant_is_not_downgraded_by_private_baseline(self):
        current = report()
        current["exact"]["process_spawns"] = 1
        decision = compare.compare(current, report(), POLICY)
        self.assertTrue(decision["fail"])
        self.assertEqual(decision["metrics"]["process_spawns"]["status"], "fail")

    def test_same_measurement_and_private_regression(self):
        baseline = report()
        current = copy.deepcopy(baseline)
        current["samples"]["wall"] = [200.0] * 10
        decision = compare.compare(current, baseline, POLICY)
        self.assertFalse(decision["fail"])
        self.assertEqual(decision["metrics"]["wall"]["status"], "advisory-record-only")

    def test_deterministic_allocation_injection_fails_without_rerun(self):
        baseline = report()
        current = copy.deepcopy(baseline)
        current["samples"]["instructions"] = [1100] * 10
        decision = compare.compare(current, baseline, POLICY, public=True)
        self.assertTrue(decision["fail"])
        self.assertEqual(decision["metrics"]["instructions"]["status"], "fail")

    def test_statistical_sleep_injection_requires_one_confirmation(self):
        baseline = report()
        current = copy.deepcopy(baseline)
        current["samples"]["wall"] = [200.0] * 10
        first = compare.compare(current, baseline, POLICY, public=True)
        self.assertEqual(first["metrics"]["wall"]["status"], "rerun-required")
        self.assertFalse(first["fail"])
        confirmed = compare.compare(current, baseline, POLICY, public=True, rerun=current)
        self.assertTrue(confirmed["fail"])
        cleared = compare.compare(current, baseline, POLICY, public=True, rerun=baseline)
        self.assertEqual(cleared["metrics"]["wall"]["status"], "noise-cleared")

    def test_rerun_cannot_hide_a_process_or_request_regression(self):
        baseline = report()
        current = report()
        current["samples"]["wall"] = [200.0] * 10
        rerun = report()
        rerun["exact"]["process_spawns"] = 1
        decision = compare.compare(current, baseline, POLICY, public=True, rerun=rerun)
        self.assertTrue(decision["fail"])

    def test_missing_counter_does_not_pass_silently(self):
        current = report()
        del current["exact"]["bytes_uploaded"]
        with self.assertRaises(ValueError):
            compare.compare(current, report(), POLICY, public=True)

    def test_instruction_toolchain_mismatch_requires_reviewed_refresh(self):
        for field in compare.TOOLCHAIN:
            baseline = report()
            current = copy.deepcopy(baseline)
            current["samples"]["instructions"] = [2000] * 10
            current["fingerprint"][field] = "different"
            with self.subTest(field=field):
                decision = compare.compare(current, baseline, POLICY, public=True)
                self.assertTrue(decision["fail"])
                self.assertIn("refresh_required", decision)
                self.assertFalse(decision["metrics"]["instructions"]["gated"])
                self.assertEqual(decision["metrics"]["instructions"]["status"], "refresh-required-incompatible")

    def test_time_hardware_mismatch_does_not_skip_exact_counters(self):
        baseline = report()
        current = copy.deepcopy(baseline)
        current["fingerprint"]["cpu_model"] = "other"
        current["samples"]["wall"] = [200.0] * 10
        current["exact"]["requests"] = {"single": 3}
        decision = compare.compare(current, baseline, POLICY, public=True)
        self.assertTrue(decision["fail"])
        self.assertEqual(decision["metrics"]["wall"]["status"], "advisory-incompatible")
        self.assertFalse(decision["metrics"]["wall"]["gated"])
        self.assertTrue(decision["metrics"]["instructions"]["gated"])

    def test_cpu_mismatch_is_advisory_but_never_reported_as_gated(self):
        current = report()
        current["fingerprint"]["cpu_model"] = "different"
        current["samples"]["wall"] = [200] * 10
        decision = compare.compare(current, report(), POLICY, public=True)
        self.assertFalse(decision["fail"])
        self.assertFalse(decision["metrics"]["wall"]["gated"])
        self.assertIn("NOT gated", decision["metrics"]["wall"]["reason"])

    def test_semantic_corpus_change_requires_review_not_autorefresh(self):
        baseline = report()
        current = copy.deepcopy(baseline)
        current["fingerprint"]["corpus_revision"] = "changed"
        decision = compare.compare(current, baseline, POLICY, public=True)
        self.assertIn("refresh_required", decision)
        self.assertTrue(decision["fail"])
        self.assertEqual(baseline, report())

    def test_improvement_only_suggests_a_ratchet(self):
        baseline = report()
        current = copy.deepcopy(baseline)
        current["samples"]["instructions"] = [900] * 10
        self.assertEqual(compare.compare(current, baseline, POLICY, public=True)["metrics"]["instructions"]["status"], "ratchet-suggested")
        self.assertEqual(baseline, report())

    def test_bootstrap_is_reproducible_and_rejects_invalid_data(self):
        self.assertEqual(compare.median_interval(list(range(10))), compare.median_interval(list(range(10))))
        for values in ([float("nan")], [float("inf")], [-1], [True], []):
            with self.assertRaises(ValueError):
                compare.samples(values)
        with self.assertRaises(ValueError):
            compare.median_interval([1.0] * 9)

    def test_ten_identical_synthetic_controls_have_zero_false_failures(self):
        # Comparator unit control only, NOT the required ten hosted-runner runs.
        baseline = report()
        for _ in range(10):
            decision = compare.compare(report(), baseline, POLICY, public=True)
            self.assertFalse(decision["fail"])
            self.assertEqual(decision["metrics"]["wall"]["status"], "unchanged")


if __name__ == "__main__":
    unittest.main()
