"""Resource collector controls, not measurements of the archiver pipeline."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

SPEC = importlib.util.spec_from_file_location("perf_observe", Path(__file__).with_name("observe.py"))
observe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observe)


class ObservationTests(unittest.TestCase):
    def test_resource_sample_is_numeric_and_does_not_forge_app_counters(self):
        sample = observe.observe([sys.executable, "-c", "pass"], timeout=10)
        self.assertGreater(sample["wall"], 0)
        self.assertGreater(sample["peak_rss_bytes"], 0)
        self.assertAlmostEqual(sample["cpu_total"], sample["cpu_user"] + sample["cpu_system"])
        self.assertIsNone(sample["application_counters"])
        self.assertTrue(sample["includes_process_startup"])

    def test_child_output_is_not_forwarded_or_persisted(self):
        sample = observe.observe([sys.executable, "-c", "print('synthetic-private-output')"], timeout=10)
        self.assertNotIn("synthetic-private-output", json.dumps(sample))

    def test_failed_or_timed_out_child_has_static_error(self):
        for program, timeout in (("print('synthetic-private-output'); raise SystemExit(2)", 10), ("import time; time.sleep(1)", 0.05)):
            with self.assertRaises(ValueError) as caught:
                observe.observe([sys.executable, "-c", program], timeout=timeout)
            self.assertNotIn("synthetic-private-output", str(caught.exception))

    def test_timeout_limits(self):
        for timeout in (0, -1, float("inf"), 3601):
            with self.assertRaises(ValueError):
                observe.observe([sys.executable, "-c", "pass"], timeout=timeout)


if __name__ == "__main__":
    unittest.main()
