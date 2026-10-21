"""Queue-based staged pipeline.

discover -> [scan] -> [redact] -> [verify(rescan)] -> [upload] -> [delete]

Each stage has its own worker pool (cfg.per_stage_workers) and a bounded input
queue of the same size, so at most ~workers*2 items are in flight per stage.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import redactor, scanner, uploader
from .config import Config
from .discover import discover
from .state import State

log = logging.getLogger("archiver")
_STOP = object()


@dataclass
class Item:
    path: Path
    size: int
    mtime: float
    findings: list[scanner.Finding] = field(default_factory=list)
    detectors: dict[str, int] = field(default_factory=dict)
    redactions: int = 0


class Stage:
    def __init__(self, name: str, fn: Callable[[Item], Item | None], workers: int, state: State, out: "Stage | None"):
        self.name, self.fn, self.state, self.out = name, fn, state, out
        self.q: queue.Queue = queue.Queue(maxsize=workers)
        self.threads = [threading.Thread(target=self._run, name=f"{name}-{i}", daemon=True) for i in range(workers)]
        self.done = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        for t in self.threads:
            t.start()

    def _run(self) -> None:
        while True:
            item = self.q.get()
            if item is _STOP:
                self.q.task_done()
                return
            try:
                res = self.fn(item)
                if res is not None and self.out is not None:
                    self.out.q.put(res)
            except Exception as e:  # noqa: BLE001 - recorded per file, pipeline continues
                self.state.update(str(item.path), "error", error=f"{self.name}: {type(e).__name__}: {str(e)[:200]}")
                log.warning("%s failed for one file: %s", self.name, type(e).__name__)
            finally:
                with self._lock:
                    self.done += 1
                self.q.task_done()

    def close(self) -> None:
        for _ in self.threads:
            self.q.put(_STOP)
        for t in self.threads:
            t.join()


def build(cfg: Config, state: State, dry_run: bool = False) -> list[Stage]:
    def still_old(item: Item) -> bool:
        st = item.path.stat()
        return st.st_mtime < time.time() - cfg.min_age_days * 86400

    def do_scan(item: Item) -> Item | None:
        if not still_old(item):
            state.update(str(item.path), "skipped", error="modified recently")
            return None
        item.findings = scanner.scan_file(item.path, cfg.trufflehog_concurrency)
        item.detectors = scanner.detector_counts(item.findings)
        state.update(str(item.path), "scanned", detectors=item.detectors)
        return item

    def do_redact(item: Item) -> Item:
        item.redactions = redactor.redact_file(item.path, item.findings)
        item.findings = []  # drop raw values ASAP
        state.update(str(item.path), "redacted", redactions=item.redactions)
        return item

    def do_verify(item: Item) -> Item | None:
        left = scanner.scan_file(item.path, cfg.trufflehog_concurrency)
        if left:
            lines = {f.line for f in left if isinstance(f.line, int)}
            item.redactions += redactor.redact_file(item.path, left, drop_lines=lines)
            left = scanner.scan_file(item.path, cfg.trufflehog_concurrency)
        if left:
            state.update(str(item.path), "blocked", error=f"{len(left)} findings remain after redaction")
            return None
        state.update(str(item.path), "verified", redactions=item.redactions)
        return item

    def do_upload(item: Item) -> Item | None:
        if dry_run:
            return None
        key, gz_size, sha = uploader.upload_verified(cfg, item.path)
        state.update(str(item.path), "uploaded", s3_key=key, gz_size=gz_size, gz_sha256=sha)
        return item

    def do_delete(item: Item) -> None:
        os.unlink(item.path)
        state.update(str(item.path), "deleted")

    n = cfg.per_stage_workers
    delete = Stage("delete", do_delete, n, state, None)
    upload = Stage("upload", do_upload, n, state, delete)
    verify = Stage("verify", do_verify, n, state, upload)
    redact = Stage("redact", do_redact, n, state, verify)
    scan = Stage("scan", do_scan, n, state, redact)
    return [scan, redact, verify, upload, delete]


def run(cfg: Config, limit: int | None = None, dry_run: bool = False) -> None:
    state = State(cfg.db_path)
    stages = build(cfg, state, dry_run)
    for s in stages:
        s.start()
    stop_progress = threading.Event()

    def progress() -> None:
        while not stop_progress.wait(30):
            log.info("progress %s | %s", " ".join(f"{s.name}={s.done}(q{s.q.qsize()})" for s in stages), _fmt(state.summary()))

    threading.Thread(target=progress, daemon=True).start()
    fed = 0
    for path, st in discover(cfg):
        status = state.upsert_discovered(str(path), st.st_size, st.st_mtime)
        if status not in ("discovered", "error"):
            continue  # resumable: skip already-handled files
        stages[0].q.put(Item(path, st.st_size, st.st_mtime))  # blocks when stage is full (backpressure)
        fed += 1
        if limit and fed >= limit:
            break
    for s in stages:  # close in order so upstream drains into downstream
        s.close()
    stop_progress.set()
    log.info("finished; fed=%d | %s", fed, _fmt(state.summary()))
    if not dry_run:
        import json
        rows = [dict(zip(["path", "size", "mtime", "status", "detectors", "redactions", "s3_key", "gz_size", "gz_sha256"], r)) for r in state.manifest_rows()]
        uploader.put_bytes(cfg, f"manifest-{time.strftime('%H%M%S')}.json", json.dumps(rows, indent=1).encode())


def _fmt(summary: dict[str, tuple[int, int]]) -> str:
    return ", ".join(f"{k}:{n}/{b / 2**30:.2f}GiB" for k, (n, b) in sorted(summary.items()))
