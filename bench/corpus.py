"""Seeded bounded synthetic agent/tool-result corpus; never read user/runtime data."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import string

REVISION = "agent-jsonl-v2"
MAX_RECORD = 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
SIZES = (1024,) * 64 + (16 * 1024,) * 16 + (100 * 1024,) * 4 + (MAX_RECORD,) * 2 + (4 * MAX_RECORD,)


def json_record(size: int, plant: bytes = b"", generator: random.Random | None = None) -> tuple[bytes, int]:
    prefix = b'{"type":"tool_result","content":"'
    suffix = b'"}\n'
    available = size - len(prefix) - len(suffix)
    # Boundary-sensitive catalog rules must see the independent planted token,
    # not a token accidentally joined to filler words. Framing is not the secret.
    carrier = b" " + plant + b" " if plant else b""
    if available < len(carrier) or size > MAX_RECORD:
        raise ValueError("invalid bounded record geometry")
    before = (available - len(carrier)) // 2
    generator = generator or random.Random(size)
    words = (b"observed", b"public", b"result", b"source", b"module", b"format", b"line", b"branch", b"count", b"read", b"write")
    # Seeded word/number variation avoids benchmarking only an identical highly
    # compressible repeated string; it is still a heuristic, not a production trace.
    pieces = []
    length = 0
    while length < available:
        piece = generator.choice(words) + b" " + str(generator.randrange(1_000_000)).encode() + b" "
        pieces.append(piece)
        length += len(piece)
    filler = b"".join(pieces)[:available]
    data = prefix + filler[:before] + carrier + filler[before:available - len(carrier)] + suffix
    if len(data) != size:
        raise ValueError("synthetic record geometry mismatch")
    return data, len(prefix) + before + bool(plant)


def generate(seed: int = 488) -> tuple[dict[str, bytes], list[dict[str, object]]]:
    generator = random.Random(seed)
    files: dict[str, bytes] = {}
    manifest = []
    for index, size in enumerate(SIZES):
        name = f"agent-{index:03d}.jsonl"
        token = ("ghp_" + "".join(generator.choices(string.ascii_letters + string.digits, k=36))).encode()
        record_size = size if size <= MAX_RECORD else 64 * 1024
        first, offset = json_record(record_size, token, generator)
        data = bytearray(first)
        while len(data) < size:
            record, _ = json_record(min(record_size, size - len(data)), generator=generator)
            data.extend(record)
        files[name] = bytes(data)
        manifest.append({"file": name, "family": "github", "offset": offset, "length": len(token), "scope": "direct"})
    mixed = "".join(generator.choices(string.ascii_letters + string.digits, k=96)).encode()
    # Construct the synthetic delimiter at runtime; no key body lives in source.
    prefix = b"-----BEGIN " + b"PRIVATE KEY-----\n"
    files["terminal-pem.log"] = prefix + mixed + b"\n-----END PRIVATE KEY-----\n"
    manifest.append({"file": "terminal-pem.log", "family": "private-key", "offset": 0, "length": len(files["terminal-pem.log"]) - 1, "scope": "direct"})
    env_prefix = b"SYNTHETIC_PASSWORD="
    env_value = mixed[::-1]
    files["terminal-env.log"] = env_prefix + env_value + b"\n"
    manifest.append({"file": "terminal-env.log", "family": "env", "offset": len(env_prefix), "length": len(env_value), "scope": "core-extra"})
    if sum(map(len, files.values())) > MAX_TOTAL:
        raise ValueError("synthetic corpus disk cap exceeded")
    return files, manifest


def write(root: Path, seed: int = 488) -> dict[str, object]:
    """Create a fresh generated directory; never overwrite or inspect existing data."""
    files, manifest = generate(seed)
    root.mkdir(parents=True, exist_ok=False)
    inputs = root / "inputs"
    inputs.mkdir()
    digest = hashlib.sha256()
    for name, data in sorted(files.items()):
        (inputs / name).write_bytes(data)
        digest.update(name.encode())
        digest.update(hashlib.sha256(data).digest())
    metadata = {"revision": REVISION, "seed": seed, "files": len(files), "bytes": sum(map(len, files.values())), "sha256": digest.hexdigest(), "plants": manifest}
    (root / "manifest.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return metadata
