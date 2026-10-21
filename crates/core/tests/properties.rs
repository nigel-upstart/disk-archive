//! Deterministic, generated property sweeps: reproducible and independent of host randomness.
use std::collections::BTreeSet;
use std::io::{self, Read, Write};

use disk_archive_core::redaction::{FindingRaw, Limits, PlanBuilder, RedactError, RedactionPlan};
use disk_archive_core::{age, key};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn plan(raw: &str, label: &str, limits: Limits) -> Result<RedactionPlan, &'static str> {
    let mut b = PlanBuilder::new(limits).map_err(|_| "limits")?;
    b.push(&FindingRaw { label, raw }).map_err(|_| "push")?;
    b.finish([]).map_err(|_| "finish")
}

#[test]
fn generated_literal_and_escaped_values_leave_no_supplied_needle() -> TestResult {
    for n in 6..128 {
        for suffix in ["", "\"\\", "é😀", "\nabcdefghijkl"] {
            let raw = format!("{}{}", "z".repeat(n), suffix);
            let p = plan(&raw, "Synthetic", Limits::default())?;
            let escaped = serde_json::to_string(&raw)?;
            let escaped = escaped
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .ok_or("JSON")?;
            let input = format!("prefix {raw} / {escaped} suffix\n");
            let mut output = Vec::new();
            p.redact(input.as_bytes(), &mut output)
                .map_err(|_| "redact")?;
            let supplied =
                disk_archive_verified::needles::NeedleSet::from_findings(&[FindingRaw {
                    label: "Synthetic",
                    raw: &raw,
                }])
                .map_err(|_| "needles")?;
            assert!(!supplied.occurs_in(&output));
        }
    }
    Ok(())
}

#[test]
fn generated_keys_are_injective_and_round_trip() -> TestResult {
    let prefix = key::KeyPrefix::new(b"synthetic-tests").map_err(|_| "prefix")?;
    let mut keys = BTreeSet::new();
    for lead in ["", ".", "..", "%", "é"] {
        for n in 0..128 {
            let path = format!("{lead}x/{n}/file.jsonl");
            let encoded = key::encode_key(&prefix, path.as_bytes()).map_err(|_| "encode")?;
            assert_eq!(
                key::decode_rel(&prefix, &encoded).map_err(|_| "decode")?,
                path.as_bytes()
            );
            assert!(keys.insert(encoded));
        }
    }
    for path in [b"".as_slice(), b"../file", b"/file", b"x/./f", b"x\0y"] {
        assert!(key::encode_key(&prefix, path).is_err());
    }
    assert!(key::encode_key(&prefix, "x".repeat(1024).as_bytes()).is_err());
    Ok(())
}

#[test]
fn generated_cutoff_matches_i128_oracle_at_extremes() {
    for now_secs in [i64::MIN, -1, 0, 1, i64::MAX] {
        for mtime_secs in [i64::MIN, -1, 0, 1, i64::MAX] {
            for nanos in [0, 1, 999_999_999] {
                for min_age in [0, 1, 86_400, u64::MAX] {
                    let now = age::Timestamp {
                        secs: now_secs,
                        nanos,
                    };
                    let mtime = age::Timestamp {
                        secs: mtime_secs,
                        nanos: 0,
                    };
                    let diff = (i128::from(now_secs) - i128::from(mtime_secs)) * 1_000_000_000
                        + i128::from(nanos);
                    assert_eq!(
                        age::is_older_than(now, mtime, min_age),
                        diff > i128::from(min_age) * 1_000_000_000
                    );
                }
            }
        }
    }
    let invalid = age::Timestamp {
        secs: 0,
        nanos: 1_000_000_000,
    };
    assert!(!age::is_older_than(invalid, invalid, 0));
}

#[test]
fn final_guard_covers_env_pem_and_drop_markers() -> TestResult {
    for raw in ["REDACTED", "PRIVATE", "REDACTED-LINE"] {
        let p = plan(raw, "Synthetic", Limits::default())?;
        let mut out = Vec::new();
        let report = p.redact(b"API_TOKEN=made-up\n-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----tail\n".as_slice(), &mut out).map_err(|_| "redact")?;
        assert!(!out.windows(raw.len()).any(|w| w == raw.as_bytes()));
        if raw == "REDACTED" {
            assert!(report.guarded_lines > 0);
        }
    }
    let mut b = PlanBuilder::new(Limits::default()).map_err(|_| "limits")?;
    b.push(&FindingRaw {
        label: "Synthetic",
        raw: "REDACTED",
    })
    .map_err(|_| "push")?;
    let mut out = Vec::new();
    b.finish([1])
        .map_err(|_| "finish")?
        .redact(b"drop\n".as_slice(), &mut out)
        .map_err(|_| "redact")?;
    assert_eq!(out, [] as [u8; 0]);
    Ok(())
}

#[test]
fn budget_errors_poison_callbacks_and_drop_lists_are_bounded() -> TestResult {
    let limits = Limits {
        max_findings: 1,
        max_finding_bytes: 6,
        max_drop_lines: 1,
        ..Limits::default()
    };
    let mut b = PlanBuilder::new(limits).map_err(|_| "limits")?;
    assert_eq!(
        b.push(&FindingRaw {
            label: "ok",
            raw: "1234567"
        }),
        Err(RedactError::Budget)
    );
    assert!(b.finish([]).is_err());
    let mut b = PlanBuilder::new(limits).map_err(|_| "limits")?;
    b.push(&FindingRaw {
        label: "ok",
        raw: "123456",
    })
    .map_err(|_| "push")?;
    assert_eq!(
        b.push(&FindingRaw {
            label: "ok",
            raw: ""
        }),
        Err(RedactError::Budget)
    );
    assert!(b.finish([]).is_err());
    for label in ["", "invalid\nlabel", "bad]marker"] {
        let mut b = PlanBuilder::new(limits).map_err(|_| "limits")?;
        assert_eq!(
            b.push(&FindingRaw { label, raw: "" }),
            Err(RedactError::Invalid)
        );
        assert!(b.finish([]).is_err());
    }
    assert!(
        PlanBuilder::new(limits)
            .map_err(|_| "limits")?
            .finish([0])
            .is_err()
    );
    assert!(
        PlanBuilder::new(limits)
            .map_err(|_| "limits")?
            .finish([1, 1])
            .is_err()
    );
    assert!(
        PlanBuilder::new(Limits {
            max_line_bytes: 0,
            ..limits
        })
        .is_err()
    );
    Ok(())
}

struct Chunks<'a> {
    bytes: &'a [u8],
    size: usize,
}
impl Read for Chunks<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let len = self.size.min(self.bytes.len()).min(out.len());
        let bytes = self
            .bytes
            .get(..len)
            .ok_or_else(|| io::Error::other("range"))?;
        out.get_mut(..len)
            .ok_or_else(|| io::Error::other("range"))?
            .copy_from_slice(bytes);
        self.bytes = self
            .bytes
            .get(len..)
            .ok_or_else(|| io::Error::other("range"))?;
        Ok(len)
    }
}

#[test]
fn chunk_boundaries_and_exact_line_budgets() -> TestResult {
    let input = b"synthetic\r\nAPI_TOKEN=made-up\nlast";
    let p = plan("synthetic", "Test", Limits::default())?;
    let mut expected = Vec::new();
    p.redact(input.as_slice(), &mut expected)
        .map_err(|_| "redact")?;
    for size in 1..=input.len() {
        let mut out = Vec::new();
        p.redact(Chunks { bytes: input, size }, &mut out)
            .map_err(|_| "redact")?;
        assert_eq!(out, expected);
    }
    for len in 1..64 {
        let p = plan(
            "",
            "Test",
            Limits {
                max_line_bytes: len,
                ..Limits::default()
            },
        )?;
        assert!(p.redact(vec![b'x'; len].as_slice(), io::sink()).is_ok());
        assert_eq!(
            p.redact(vec![b'x'; len + 1].as_slice(), io::sink()),
            Err(RedactError::Budget)
        );
    }
    let p = plan(
        "abcdef",
        "long-label",
        Limits {
            max_output_line_bytes: 6,
            ..Limits::default()
        },
    )?;
    assert_eq!(
        p.redact(b"abcdef".as_slice(), io::sink()),
        Err(RedactError::Budget)
    );
    Ok(())
}

struct Broken;
impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("sensitive read detail"))
    }
}
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("sensitive write detail"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn io_failures_are_value_free_and_never_success() -> TestResult {
    let p = plan("", "Test", Limits::default())?;
    assert_eq!(p.redact(Broken, io::sink()), Err(RedactError::Read));
    assert_eq!(
        p.redact(b"keep".as_slice(), Broken),
        Err(RedactError::Write)
    );
    assert_eq!(format!("{:?}", RedactError::Read), "Read");
    Ok(())
}
