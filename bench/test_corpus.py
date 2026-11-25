"""Pure seeded-corpus checks; generated source bytes are never printed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("perf_corpus", Path(__file__).with_name("corpus.py"))
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


def digest(files):
    value = hashlib.sha256()
    for name, data in sorted(files.items()):
        value.update(name.encode())
        value.update(data)
    return value.hexdigest()


class CorpusTests(unittest.TestCase):
    def test_seed_geometry_and_manifest_are_independent_and_bounded(self):
        files, manifest = corpus.generate()
        self.assertEqual(len(files), 89)
        self.assertLessEqual(sum(map(len, files.values())), corpus.MAX_TOTAL)
        self.assertTrue(any(len(value) == 4 * corpus.MAX_RECORD for value in files.values()))
        self.assertTrue(any(len(value) == corpus.MAX_RECORD for value in files.values()))
        for name, data in files.items():
            if name.endswith(".jsonl"):
                for line in data.splitlines(keepends=True):
                    self.assertLessEqual(len(line), corpus.MAX_RECORD)
                    self.assertEqual(json.loads(line)["type"], "tool_result")
        self.assertEqual(len(manifest), len(files))
        for plant in manifest:
            data = files[plant["file"]]
            start, length = plant["offset"], plant["length"]
            self.assertLessEqual(start + length, len(data))
            self.assertTrue(length > 0)
            if plant["family"] == "github":
                self.assertEqual(data[start - 1:start], b" ")
                self.assertEqual(data[start + length:start + length + 1], b" ")
                self.assertEqual(data[start:start + 4], b"ghp_")
        self.assertEqual({plant["family"] for plant in manifest}, {"github", "private-key", "env"})

    def test_seed_reproduction_and_variation(self):
        first, _ = corpus.generate(488)
        second, _ = corpus.generate(488)
        changed, _ = corpus.generate(489)
        self.assertEqual(digest(first), digest(second))
        self.assertNotEqual(digest(first), digest(changed))

    def test_never_overwrite_an_existing_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "generated"
            metadata = corpus.write(root)
            self.assertEqual(metadata["files"], 89)
            self.assertTrue((root / "manifest.json").is_file())
            with self.assertRaises(FileExistsError):
                corpus.write(root)

    def test_record_bounds(self):
        for size in (0, 12, corpus.MAX_RECORD + 1):
            with self.assertRaises(ValueError):
                corpus.json_record(size)
        record, offset = corpus.json_record(100 * 1024, b"synthetic-only")
        self.assertEqual(len(record), 100 * 1024)
        self.assertEqual(offset, len(b'{"type":"tool_result","content":"') + (100 * 1024 - len(b'{"type":"tool_result","content":""}\n') - len(b"synthetic-only") - 2) // 2 + 1)


if __name__ == "__main__":
    unittest.main()
