"""Streaming, in-place redaction (line by line; bounded memory even for multi-GB logs)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .scanner import Finding

# Generic belt-and-suspenders patterns for env dumps / private keys that TruffleHog
# may not flag (e.g. vendor keys without a paired ID).
ENV_ASSIGN = re.compile(
    rb"((?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS|AUTH)[A-Z0-9_]*)=)"
    rb"(\"[^\"\n]{0,4096}\"|'[^'\n]{0,4096}'|[^\s\"']+)"
)
PEM_INLINE = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----.{0,20000}?-----END [A-Z ]*PRIVATE KEY-----"
)
PEM_BEGIN = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PEM_END = re.compile(rb"-----END [A-Z ]*PRIVATE KEY-----")


def _needles(findings: list[Finding]) -> list[tuple[bytes, bytes]]:
    seen: dict[bytes, bytes] = {}
    for f in findings:
        repl = f"[REDACTED-{f.detector}]".encode()
        for s in (f.raw, f.raw_v2):
            if len(s) < 6:
                continue
            for form in (s, json.dumps(s)[1:-1]):
                # multi-line secrets: also redact each sufficiently long line piece
                for piece in [form, *form.splitlines()]:
                    if len(piece) >= 12 or piece == form:
                        seen.setdefault(piece.encode(), repl)
    return sorted(seen.items(), key=lambda kv: -len(kv[0]))


def redact_file(
    path: Path, findings: list[Finding], drop_lines: set[int] | None = None
) -> int:
    """Rewrite `path` in place. Returns number of replacements."""
    needles = _needles(findings)
    drop_lines = drop_lines or set()
    tmp = path.with_name(path.name + ".redact.tmp")
    count = 0
    in_pem = False
    st = path.stat()
    with open(path, "rb") as fi, open(tmp, "wb") as fo:
        for lineno, line in enumerate(fi, 1):
            if lineno in drop_lines:
                fo.write(b"[REDACTED-LINE]\n")
                count += 1
                continue
            if in_pem:
                if PEM_END.search(line):
                    in_pem = False
                    line = PEM_END.split(line, 1)[1]
                else:
                    continue
            for needle, repl in needles:
                if needle in line:
                    count += line.count(needle)
                    line = line.replace(needle, repl)
            line, n = PEM_INLINE.subn(b"[REDACTED-PRIVATE-KEY]", line)
            count += n
            if PEM_BEGIN.search(line):
                head = PEM_BEGIN.split(line, 1)[0]
                line = head + b"[REDACTED-PRIVATE-KEY]\n"
                in_pem = True
                count += 1
            line, n = ENV_ASSIGN.subn(lambda m: m.group(1) + b"[REDACTED]", line)
            count += n
            fo.write(line)
    os.replace(tmp, path)
    os.utime(path, (st.st_atime, st.st_mtime))  # keep original timestamps
    return count
