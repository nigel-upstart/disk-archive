"""Strict numeric Callgrind event extraction; never substitute missing counts."""
from __future__ import annotations

from pathlib import Path


def parse(text: str) -> dict[str, int]:
    events = None
    summary = None
    totals = None
    for line in text.splitlines():
        if line.startswith("events:"):
            current = line.partition(":")[2].split()
            if events is not None and current != events:
                raise ValueError("Callgrind changed event layout")
            if not current or len(set(current)) != len(current):
                raise ValueError("Callgrind event layout invalid")
            events = current
        elif line.startswith("summary:"):
            if summary is not None:
                raise ValueError("multiple Callgrind summaries need explicit part selection")
            summary = line.partition(":")[2].split()
        elif line.startswith("totals:"):
            if totals is not None:
                raise ValueError("multiple Callgrind totals need explicit part selection")
            totals = line.partition(":")[2].split()
    values = totals if totals is not None else summary
    if events is None or values is None or len(events) != len(values):
        raise ValueError("Callgrind event/count geometry missing or inconsistent")
    if any(not value.isdecimal() for value in values):
        raise ValueError("Callgrind counts must be unsigned integers")
    result = dict(zip(events, map(int, values), strict=True))
    if "Ir" not in result:
        raise ValueError("Callgrind instruction count missing")
    return result


def instruction_cache_counts(path: Path) -> dict[str, int]:
    values = parse(path.read_text())
    required = ("Ir", "I1mr", "D1mr", "D1mw", "ILmr", "DLmr", "DLmw")
    if not all(name in values for name in required):
        raise ValueError("Callgrind cache simulation was not collected")
    return {name: values[name] for name in required}
