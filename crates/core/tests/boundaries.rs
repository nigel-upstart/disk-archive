//! Legacy regex byte semantics and finite-repeat boundaries, using invented bytes only.
use disk_archive_core::redaction::{FindingRaw, Limits, PlanBuilder};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn inline_pem_gap_and_binary_bytes() -> TestResult {
    let plan = PlanBuilder::new(Limits::default())
        .map_err(|_| "limits")?
        .finish([])
        .map_err(|_| "plan")?;
    for len in [0, 1, 19_999, 20_000, 20_001] {
        let mut input = concat!("prefix-----", "BEGIN PRIVATE KEY-----")
            .as_bytes()
            .to_vec();
        input.extend(std::iter::repeat_n(0xff, len));
        input.extend_from_slice(b"-----END PRIVATE KEY-----tail\nnext\n");
        let mut output = Vec::new();
        let report = plan
            .redact(input.as_slice(), &mut output)
            .map_err(|_| "redact")?;
        if len <= 20_000 {
            assert_eq!(output, b"prefix[REDACTED-PRIVATE-KEY]tail\nnext\n");
        } else {
            // Legacy unmatched-BEGIN behavior: suppress suffix and subsequent active lines.
            assert_eq!(output, b"prefix[REDACTED-PRIVATE-KEY]\n");
        }
        assert_eq!(report.replacements, 1);
    }
    Ok(())
}

#[test]
fn quoted_env_cutoff_ascii_whitespace_and_binary_values() -> TestResult {
    let plan = PlanBuilder::new(Limits::default())
        .map_err(|_| "limits")?
        .finish([])
        .map_err(|_| "plan")?;
    for len in [0, 1, 4095, 4096, 4097] {
        for quote in *b"'\"" {
            let mut input = b"APP_TOKEN=".to_vec();
            input.push(quote);
            input.extend(std::iter::repeat_n(b'x', len));
            input.extend_from_slice(&[quote, b'\n']);
            let mut out = Vec::new();
            let report = plan
                .redact(input.as_slice(), &mut out)
                .map_err(|_| "redact")?;
            if len <= 4096 {
                assert_eq!(out, b"APP_TOKEN=[REDACTED]\n");
                assert_eq!(report.replacements, 1);
            } else {
                assert_eq!(out, input);
                assert_eq!(report.replacements, 0);
            }
        }
    }
    let mut out = Vec::new();
    plan.redact(b"AUTH=\xff\xc2\xa0tail\x0bkeep\n".as_slice(), &mut out)
        .map_err(|_| "redact")?;
    // Byte regex: NBSP bytes are not whitespace; ASCII vertical tab is whitespace.
    assert_eq!(out, b"AUTH=[REDACTED]\x0bkeep\n");
    Ok(())
}

#[test]
fn python_ensure_ascii_unicode_and_crlf_piece_thresholds() -> TestResult {
    let mut builder = PlanBuilder::new(Limits::default()).map_err(|_| "limits")?;
    for raw in [
        "abé😀cd",
        "abcdefghijkl\r\nmnopqrstuvwx",
        "abcdefghijk\nshort",
    ] {
        builder
            .push(&FindingRaw {
                label: "Synthetic",
                raw,
            })
            .map_err(|_| "push")?;
    }
    let plan = builder.finish([]).map_err(|_| "plan")?;
    let mut out = Vec::new();
    plan.redact(
        b"ab\\u00e9\\ud83d\\ude00cd\nabcdefghijkl\r\nmnopqrstuvwx\nabcdefghijk\nshort\n".as_slice(),
        &mut out,
    )
    .map_err(|_| "redact")?;
    assert_eq!(
        out,
        b"[REDACTED-Synthetic]\n[REDACTED-Synthetic]\r\n[REDACTED-Synthetic]\nabcdefghijk\nshort\n"
    );
    Ok(())
}
