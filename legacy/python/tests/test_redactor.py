from pathlib import Path
from session_archiver.redactor import redact_file
from session_archiver.scanner import Finding

def test_redacts_findings_env_and_pem(tmp_path: Path):
    p = tmp_path / "x.log"
    p.write_bytes(
        b"hello ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234 world\n"
        b"JIRA_TOKEN=abc123def456 DD_API_KEY=zzz other=ok\n"
        b'{"k":"-----BEGIN PRIVATE KEY-----\\nMIIfake\\n-----END PRIVATE KEY-----\\n"}\n'
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIBfake\nmore\n-----END RSA PRIVATE KEY-----\nafter\n"
        b"secret line\n"
    )
    n = redact_file(p, [Finding("Github", "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234", "", 1)], drop_lines={9})
    out = p.read_text()
    assert "ghp_FAKE" not in out and "[REDACTED-Github]" in out
    assert "abc123" not in out and "zzz" not in out and "other=ok" in out
    assert "MIIfake" not in out and "MIIBfake" not in out and "more" not in out
    assert "after" in out and "secret line" not in out
    assert n >= 5
