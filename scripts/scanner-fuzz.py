"""Bounded full-catalog fuzz run. Never forward fuzzer output or crash input."""
import base64
from pathlib import Path
import re
import subprocess
import sys

# Deterministic generated seeds exercise finding callbacks, env extras, PEM,
# multiline guards, arbitrary invalid UTF-8, and inputs spanning read windows.
corpus = Path("fuzz/corpus/scanner_redactor")
corpus.mkdir(parents=True, exist_ok=True)
mixed = "aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cF0iL"
seeds = [
    ("ghp_" + (mixed * 2)[:36] + "\n").encode(),
    ("SYNTHETIC_PASSWORD=" + mixed[::-1] + "\n").encode(),
    ("-----BEGIN PRIVATE KEY-----\n" + mixed * 3 + "\n-----END PRIVATE KEY-----\n").encode(),
    bytes(range(256)),
    b"ordinary\n" * 8192,
]
token = "ghp_" + (mixed * 2)[:36]
seeds.extend([
    "".join(f"\\u{ord(byte):04x}" for byte in token).encode(),
    "".join(f"%{ord(byte):02x}" for byte in token).encode(),
    base64.b64encode(token.encode()),
    base64.urlsafe_b64encode(b"\xfb\xff\xff " + token.encode() + b" ").rstrip(b"="),
])
wrapped = base64.b64encode(("x" * 48 + " " + token).encode())
seeds.extend([b"secret_" + base64.b64encode(token.encode()), b"\r\n".join(wrapped[start:start + 76] for start in range(0, len(wrapped), 76))])
for encoding in ("utf-16-le", "utf-16-be"):
    raw = token.encode(encoding)
    encoded = base64.b64encode(raw)
    seeds.extend([raw, encoded, b"\r\n".join(encoded[start:start + 76] for start in range(0, len(encoded), 76))])
for index, seed in enumerate(seeds):
    (corpus / str(index)).write_bytes(seed)

command = [
    "cargo", "+nightly-2026-10-20", "fuzz", "run", "scanner_redactor",
    "--", "-runs=1000", "-max_len=131072", "-seed=488",
    "-timeout=10", "-exact_artifact_path=/dev/null",
]
lock_path = Path("fuzz/Cargo.lock")
lock = lock_path.read_bytes()
result = subprocess.run(command, capture_output=True, timeout=2400)
if lock_path.read_bytes() != lock:
    sys.exit("fuzz run changed the pinned dependency graph")
if result.returncode:
    sys.exit("scanner/core fuzz failed; output suppressed to protect generated input")
if not re.search(rb"Done 1000 runs in [0-9]+ second", result.stderr):
    sys.exit("scanner/core fuzz did not complete requested runs")
print("Full 488-rule scanner/core arbitrary-byte fuzz: 1000 seeded runs completed; no panic.")
