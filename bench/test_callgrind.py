"""Synthetic parser controls, not measured instruction/cache counts."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("perf_callgrind", Path(__file__).with_name("callgrind.py"))
callgrind = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(callgrind)


class CallgrindTests(unittest.TestCase):
    def test_prefers_total_over_inexact_header_summary(self):
        values = callgrind.parse("events: Ir Dr\nsummary: 200 100\ntotals: 190 90\n")
        self.assertEqual(values, {"Ir": 190, "Dr": 90})

    def test_missing_or_malformed_events_never_become_zero(self):
        for text in ("events: Ir\n", "events: Dr\nsummary: 10\n", "events: Ir Ir\nsummary: 1 2\n", "events: Ir Dr\nsummary: 1\n", "events: Ir\nsummary: -1\n", "events: Ir\nsummary: nan\n", "events: Ir\nsummary: 1\nsummary: 2\n"):
            with self.assertRaises(ValueError):
                callgrind.parse(text)

    def test_cache_events_are_required_not_estimated_from_instruction_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile"
            path.write_text("events: Ir\nsummary: 1000\n")
            with self.assertRaises(ValueError):
                callgrind.instruction_cache_counts(path)
            path.write_text("events: Ir I1mr D1mr D1mw ILmr DLmr DLmw\nsummary: 1000 1 2 3 4 5 6\n")
            counts = callgrind.instruction_cache_counts(path)
            self.assertEqual(counts["Ir"], 1000)
            self.assertEqual(counts["DLmw"], 6)


if __name__ == "__main__":
    unittest.main()
