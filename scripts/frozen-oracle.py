"""Check frozen Python-derived fixture integrity, not live Python or Rust parity."""

import hashlib
import json
from pathlib import Path
import sys

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/redactor"
SHA256 = {
    "cases.json": "f20c1b56661e6a06cda923b0e64562270db0c1b4addbf650ba6c7f45fffa8382",
    "expected.json": "58fc8274b6f97fdef7052e09f14b36f5e6abe7760fb2c5e875a0f24dc12429e8",
}
CASE_COUNT = 16


def validate(cases, expected):
    """Check schema, one-to-one ordered IDs and byte/count fields without rendering values."""
    if cases["schema_version"] != 1 or expected["schema_version"] != 1:
        raise ValueError("unsupported frozen-oracle schema")
    inputs, outputs = cases["cases"], expected["cases"]
    if len(inputs) != CASE_COUNT or len(outputs) != CASE_COUNT:
        raise ValueError("frozen-oracle case count changed")
    ids = [case["id"] for case in inputs]
    if any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != CASE_COUNT:
        raise ValueError("frozen-oracle IDs invalid")
    if ids != [case["id"] for case in outputs]:
        raise ValueError("frozen-oracle ID order changed")
    for case, output in zip(inputs, outputs, strict=True):
        for value in (case["input_hex"], output["output_hex"]):
            if not isinstance(value, str) or len(value) % 2 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("frozen-oracle byte encoding invalid")
        if type(output["replacements"]) is not int or output["replacements"] < 0:
            raise ValueError("frozen-oracle replacement count invalid")
        if any(type(line) is not int or line < 1 for line in case["drop_lines"]):
            raise ValueError("frozen-oracle line index invalid")
        for finding in case["findings"]:
            if any(not isinstance(finding[key], str) for key in ("detector", "raw", "raw_v2")):
                raise ValueError("frozen-oracle finding schema invalid")


def check(directory=FIXTURES):
    documents = {}
    for name, digest in SHA256.items():
        content = (directory / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("frozen-oracle SHA-256 mismatch")
        documents[name] = json.loads(content)
    validate(documents["cases.json"], documents["expected.json"])
    return CASE_COUNT


def main():
    try:
        count = check()
    except (OSError, ValueError, KeyError, TypeError):
        # Fixture/parser/I/O exceptions can contain finding values: never echo them.
        print("Frozen-oracle integrity check failed", file=sys.stderr)
        return 1
    print(f"Checked {count} frozen Python-derived cases (SHA-256/schema/IDs only; Rust comparison separate)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
