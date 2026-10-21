"""Compress -> upload -> verify against S3 (size + sha256 metadata)."""
from __future__ import annotations

import gzip
import hashlib
import shutil
import threading
from pathlib import Path

import truststore

truststore.inject_into_ssl()

import boto3  # noqa: E402
from botocore.config import Config as BotoConfig  # noqa: E402

from .config import HOME, Config  # noqa: E402

_local = threading.local()


def _client(cfg: Config):
    if not hasattr(_local, "s3"):
        sess = boto3.Session(profile_name=cfg.aws_profile, region_name=cfg.region)
        _local.s3 = sess.client("s3", config=BotoConfig(retries={"max_attempts": 8, "mode": "adaptive"}))
    return _local.s3


def key_for(cfg: Config, path: Path) -> str:
    rel = str(path.relative_to(HOME)).lstrip(".")
    return f"{cfg.prefix}{rel}.gz"


def upload_verified(cfg: Config, path: Path) -> tuple[str, int, str]:
    cfg.tmp_dir.mkdir(parents=True, exist_ok=True)
    gz = cfg.tmp_dir / (hashlib.sha1(str(path).encode()).hexdigest() + ".gz")
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fi, gzip.open(gz, "wb", compresslevel=6) as fo:
            shutil.copyfileobj(fi, fo, 1 << 20)
        with open(gz, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        sha, size, key = h.hexdigest(), gz.stat().st_size, key_for(cfg, path)
        s3 = _client(cfg)
        s3.upload_file(str(gz), cfg.bucket, key, ExtraArgs={
            "Metadata": {"sha256": sha, "orig-size": str(path.stat().st_size)},
            "ServerSideEncryption": "AES256",
        })
        head = s3.head_object(Bucket=cfg.bucket, Key=key)
        if head["ContentLength"] != size or head.get("Metadata", {}).get("sha256") != sha:
            raise RuntimeError("S3 verification mismatch")
        return key, size, sha
    finally:
        gz.unlink(missing_ok=True)


def put_bytes(cfg: Config, key: str, data: bytes) -> None:
    _client(cfg).put_object(Bucket=cfg.bucket, Key=cfg.prefix + key, Body=data, ServerSideEncryption="AES256")
