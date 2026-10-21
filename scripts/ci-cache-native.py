"""Fingerprint locked native compiler/build dependencies, not unrelated Rust graph churn."""

import hashlib
import json
from pathlib import Path
import sys
import tomllib


def fingerprint(lock: dict) -> str:
    """Hash the complete locked Vectorscan closure; ambiguous/missing identities fail closed."""
    packages = lock["package"]
    roots = [p for p in packages if p["name"] in ("kingfisher-vectorscan", "kingfisher-vectorscan-sys")]
    if {p["name"] for p in roots} != {"kingfisher-vectorscan", "kingfisher-vectorscan-sys"}:
        raise ValueError("missing native roots")
    visited = {}
    pending = list(roots)
    while pending:
        package = pending.pop()
        identity = (package["name"], package["version"], package.get("source", ""))
        if identity in visited:
            continue
        visited[identity] = package
        for dependency in package.get("dependencies", []):
            name, *rest = dependency.split(" ")
            matches = [p for p in packages if p["name"] == name
                       and (not rest or p["version"] == rest[0])
                       and (len(rest) < 2 or p.get("source", "") == rest[1][1:-1])]
            if len(matches) != 1:
                raise ValueError("ambiguous native dependency")
            pending.extend(matches)
    # Canonical package contents include registry checksums and immutable git sources.
    payload = json.dumps([visited[key] for key in sorted(visited)], sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


if __name__ == "__main__":
    try:
        print(fingerprint(tomllib.loads(Path(sys.argv[1]).read_text())))
    except (KeyError, ValueError, OSError, IndexError):
        sys.exit("native dependency fingerprint failed")
