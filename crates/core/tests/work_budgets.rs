//! Derived expansion and literal copy-work limits fail before expensive kernel work.
use disk_archive_core::redaction::{FindingRaw, Limits, PlanBuilder, RedactError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn within_raw_budget_twenty_thousand_line_finding_is_rejected_before_construction() -> TestResult {
    let raw = (0..20_000)
        .map(|n| format!("{n:012}"))
        .collect::<Vec<_>>()
        .join("\n");
    let limits = Limits::default();
    assert_eq!(raw.len(), 259_999);
    assert!(raw.len() < limits.max_finding_bytes);
    let mut builder = PlanBuilder::new(limits).map_err(|_| "limits")?;
    assert_eq!(
        builder.push(&FindingRaw {
            label: "Synthetic",
            raw: &raw
        }),
        Err(RedactError::Budget)
    );
    // Ignoring the callback failure cannot allow the expensive finish/replace path.
    assert_eq!(builder.finish([]).err(), Some(RedactError::Budget));
    Ok(())
}

#[test]
fn full_escaped_multiline_and_duplicate_candidates_all_consume_budget() -> TestResult {
    for raw in ["abcdef", "abé😀cd", "abc\"def\\ghi"] {
        let limits = Limits {
            max_derived_needles: 3,
            ..Limits::default()
        };
        let mut builder = PlanBuilder::new(limits).map_err(|_| "limits")?;
        builder
            .push(&FindingRaw {
                label: "Synthetic",
                raw,
            })
            .map_err(|_| "push")?;
        // Duplicates cannot evade work accounting even if the kernel deduplicates.
        assert_eq!(
            builder.push(&FindingRaw {
                label: "Synthetic",
                raw
            }),
            Err(RedactError::Budget)
        );
        assert_eq!(builder.finish([]).err(), Some(RedactError::Budget));
    }
    for delimiter in [
        '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
        '\u{2029}',
    ] {
        let raw = format!("abcdefghijkl{delimiter}mnopqrstuvwx");
        let mut builder = PlanBuilder::new(Limits {
            max_derived_needles: 3,
            ..Limits::default()
        })
        .map_err(|_| "limits")?;
        assert_eq!(
            builder.push(&FindingRaw {
                label: "Synthetic",
                raw: &raw
            }),
            Err(RedactError::Budget)
        );
    }
    // Ignored short raw values generate no kernel needles.
    let mut builder = PlanBuilder::new(Limits {
        max_derived_needles: 1,
        ..Limits::default()
    })
    .map_err(|_| "limits")?;
    builder
        .push(&FindingRaw {
            label: "Synthetic",
            raw: "short",
        })
        .map_err(|_| "push")?;
    assert!(builder.finish([]).is_ok());
    for limits in [
        Limits {
            max_derived_needles: 0,
            ..Limits::default()
        },
        Limits {
            max_literal_copy_bytes: 0,
            ..Limits::default()
        },
    ] {
        assert_eq!(PlanBuilder::new(limits).err(), Some(RedactError::Invalid));
    }
    Ok(())
}

#[test]
fn reduced_literal_buffer_cap_bounds_copy_traffic_before_amplification() -> TestResult {
    for copy_budget in [59, 60] {
        // Three conservative candidates -> initial copy plus <=3 rebuilds.
        // 60/4=15 permits the marker, while 59/4=14 must block before append.
        let mut builder = PlanBuilder::new(Limits {
            max_literal_copy_bytes: copy_budget,
            ..Limits::default()
        })
        .map_err(|_| "limits")?;
        builder
            .push(&FindingRaw {
                label: "Test",
                raw: "abcdef",
            })
            .map_err(|_| "push")?;
        let plan = builder.finish([]).map_err(|_| "plan")?;
        let mut output = Vec::new();
        let result = plan.redact(b"abcdef".as_slice(), &mut output);
        if copy_budget == 60 {
            assert!(result.is_ok());
            assert_eq!(output, b"[REDACTED-Test]");
        } else {
            assert_eq!(result, Err(RedactError::Budget));
            assert_eq!(output, [] as [u8; 0]);
        }
        // No occurrence is needed for the old kernel to rebuild a whole line.
        assert_eq!(
            plan.redact(b"unchanged-sixteen".as_slice(), std::io::sink()),
            Err(RedactError::Budget)
        );
    }
    Ok(())
}
