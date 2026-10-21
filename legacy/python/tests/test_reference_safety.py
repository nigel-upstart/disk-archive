"""Reference entry points stay inert; do not import or run the destructive pipeline."""
import sys

import pytest

from session_archiver import cli
from session_archiver.config import Config


def test_cli_disabled_before_upload_imports():
    assert "session_archiver.pipeline" not in sys.modules
    assert "session_archiver.uploader" not in sys.modules
    with pytest.raises(RuntimeError, match="Reference only"):
        cli.main()
    assert "session_archiver.pipeline" not in sys.modules
    assert "session_archiver.uploader" not in sys.modules


def test_config_has_no_destination_or_discovery_defaults():
    cfg = Config()
    assert (cfg.bucket, cfg.prefix, cfg.aws_profile, cfg.region) == ("", "", "", "")
    assert cfg.roots_all_files == ()
    assert cfg.roots_jsonl == ()
