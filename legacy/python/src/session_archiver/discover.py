"""Find archive candidates: files untouched (mtime) for >= min_age_days."""
from __future__ import annotations

import os
import time
from collections.abc import Iterator
from pathlib import Path

from .config import Config


def _old_enough(p: Path, cutoff: float) -> os.stat_result | None:
    try:
        st = p.lstat()
    except OSError:
        return None
    if not p.is_file() or p.is_symlink() or st.st_mtime >= cutoff:
        return None
    return st


def discover(cfg: Config) -> Iterator[tuple[Path, os.stat_result]]:
    cutoff = time.time() - cfg.min_age_days * 86400
    for root in cfg.roots_all_files:
        if root.exists():
            for p in root.iterdir():
                if (st := _old_enough(p, cutoff)) is not None:
                    yield p, st
    for root in cfg.roots_jsonl:
        if root.exists():
            for p in root.rglob("*.jsonl"):
                if (st := _old_enough(p, cutoff)) is not None:
                    yield p, st
