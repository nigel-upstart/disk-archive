from __future__ import annotations

import argparse
import logging

from .config import Config


def main() -> None:
    raise RuntimeError("Reference only: the legacy CLI is disabled; do not archive real data")
    from .pipeline import run  # unreachable reference: never load upload dependencies

    ap = argparse.ArgumentParser(description="Scan, redact, archive-to-S3, then delete old session/terminal logs")
    ap.add_argument("--limit", type=int, help="only feed N files (smoke test)")
    ap.add_argument("--dry-run", action="store_true", help="scan+redact+verify only; no upload/delete")
    ap.add_argument("--workers", type=int, default=30, help="workers per stage")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run(Config(per_stage_workers=a.workers), limit=a.limit, dry_run=a.dry_run)
