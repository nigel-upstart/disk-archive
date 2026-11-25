"""Synthetic identity normalization controls, not fabricated transport observations."""
import unittest

from counters import normalize_requests


class CounterLayoutTests(unittest.TestCase):
    def test_run_specific_object_and_manifest_nonces_do_not_change_semantic_counts(self):
        normalized = []
        for nonce in ("first-run", "second-run"):
            archive, manifest = f"objects/{nonce}/source", f"manifests/{nonce}.json"
            normalized.append(normalize_requests({("multipart", archive): 6, ("single", manifest): 1}, {archive: 0}, {manifest: 0}))
        self.assertEqual(normalized[0], normalized[1])
        self.assertEqual(normalized[0], {"multipart/archive-000000": 6, "single/manifest-000000": 1})

    def test_completion_order_is_not_an_object_identifier(self):
        observed = {("single", "second"): 3, ("single", "first"): 2}
        self.assertEqual(normalize_requests(observed, {"first": 0, "second": 1}, {}), {"single/archive-000000": 2, "single/archive-000001": 3})

    def test_alias_unknown_and_class_inconsistency_cannot_erase_requests(self):
        for observed, objects, manifests in [
            ({("single", "missing"): 1}, {"known": 0}, {}),
            ({("single", "first"): 1}, {"first": 0, "second": 0}, {}),
            ({("single", "first"): 1}, {"first": 0}, {"first": 0}),
            ({("single", "first"): 1, ("multipart", "first"): 1}, {"first": 0}, {}),
            ({("multipart", "manifest"): 1}, {}, {"manifest": 0}),
            ({("single", "first"): True}, {"first": 0}, {}),
            ({("single", "first"): 2**64}, {"first": 0}, {}),
        ]:
            with self.assertRaises(ValueError):
                normalize_requests(observed, objects, manifests)

    def test_an_extra_transport_request_still_changes_the_counter(self):
        original = normalize_requests({("single", "first"): 2}, {"first": 0}, {})
        extra = normalize_requests({("single", "first"): 3}, {"first": 0}, {})
        self.assertNotEqual(original, extra)


if __name__ == "__main__":
    unittest.main()
