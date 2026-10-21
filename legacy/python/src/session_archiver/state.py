"""SQLite-backed per-file state so the job is resumable and auditable.

Never stores secret values: only detector names and counts.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
  path TEXT PRIMARY KEY,
  size INTEGER, mtime REAL,
  status TEXT NOT NULL,          -- discovered|scanned|redacted|verified|uploaded|deleted|blocked|error|skipped
  detectors TEXT,                -- JSON {detector: count}
  redactions INTEGER DEFAULT 0,
  s3_key TEXT, gz_size INTEGER, gz_sha256 TEXT,
  error TEXT, updated REAL
);
"""


class State:
    def __init__(self, path: Path) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)

    def upsert_discovered(self, path: str, size: int, mtime: float) -> str:
        with self._lock:
            row = self._db.execute("SELECT status FROM files WHERE path=?", (path,)).fetchone()
            if row:
                return row[0]
            self._db.execute(
                "INSERT INTO files(path,size,mtime,status,updated) VALUES(?,?,?,?,?)",
                (path, size, mtime, "discovered", time.time()),
            )
            return "discovered"

    def update(self, path: str, status: str, **fields) -> None:
        if "detectors" in fields and not isinstance(fields["detectors"], str):
            fields["detectors"] = json.dumps(fields["detectors"])
        cols = ", ".join(f"{k}=?" for k in fields)
        sql = f"UPDATE files SET status=?, updated=?{', ' + cols if cols else ''} WHERE path=?"
        with self._lock:
            self._db.execute(sql, (status, time.time(), *fields.values(), path))

    def summary(self) -> dict[str, tuple[int, int]]:
        with self._lock:
            rows = self._db.execute("SELECT status, COUNT(*), COALESCE(SUM(size),0) FROM files GROUP BY status")
            return {s: (n, b) for s, n, b in rows}

    def manifest_rows(self):
        with self._lock:
            return self._db.execute(
                "SELECT path,size,mtime,status,detectors,redactions,s3_key,gz_size,gz_sha256 FROM files"
            ).fetchall()
