"""Sanitized configuration shape; no production paths or upload destination."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Synthetic anchor only; callers must supply temporary paths in tests.
HOME = Path("/synthetic-home")


@dataclass(frozen=True)
class Config:
    work_dir: Path = Path("/synthetic-work")
    bucket: str = ""
    prefix: str = ""
    aws_profile: str = ""
    region: str = ""
    min_age_days: int = 30
    per_stage_workers: int = 30
    trufflehog_concurrency: int = 2
    roots_all_files: tuple[Path, ...] = ()
    roots_jsonl: tuple[Path, ...] = ()

    @property
    def db_path(self) -> Path:
        return self.work_dir / "state.sqlite"

    @property
    def tmp_dir(self) -> Path:
        return self.work_dir / "tmp"
