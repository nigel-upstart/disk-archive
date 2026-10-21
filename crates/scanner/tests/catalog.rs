//! Independent synthetic planting manifest and curated benign fixtures.
use std::collections::BTreeMap;

use disk_archive_core::redaction::{FindingRaw, Limits as RedactionLimits, PlanBuilder};
use disk_archive_scanner::{Limits, ScanError, Scanner};
use zeroize::Zeroizing;
mod support;
use support::corpus;

#[test]
fn planted_and_benign_catalog() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::builtin(Limits::default())?;
    assert_eq!(scanner.rule_count(), 488);
    assert_eq!(scanner.input_buffer_bytes(), 1_114_115);
    let (input, manifest) = corpus();
    let mut detected = BTreeMap::<String, Vec<std::ops::Range<u64>>>::new();
    scanner.scan(input.as_slice(), |finding| {
        detected
            .entry(finding.rule_id().to_owned())
            .or_default()
            .push(finding.byte_range());
        Ok(())
    })?;
    for plant in manifest.iter().filter(|plant| plant.rule != "core.env") {
        let recalled = detected
            .get(plant.rule)
            .is_some_and(|spans| spans.contains(&plant.range));
        assert!(
            recalled,
            "planted family not fully detected: {}",
            plant.family
        );
    }
    for fixture in support::BENIGN {
        let summary = scanner.scan(fixture.as_bytes(), |_| Ok(()))?;
        assert_eq!(summary.findings, 0, "unexpected benign finding count");
    }
    // Practical tool-result JSONL, including a near-1 MiB physical record. This
    // exercises all 488 rules, not an easy-rule subset or a throughput claim.
    for size in [100 * 1024, 1024 * 1024] {
        let prefix = b"{\"type\":\"tool_result\",\"content\":\"";
        let suffix = b"\"}\n";
        let mut record = prefix.to_vec();
        record.extend(std::iter::repeat_n(
            b'x',
            size - prefix.len() - suffix.len(),
        ));
        record.extend_from_slice(suffix);
        assert_eq!(scanner.scan(record.as_slice(), |_| Ok(()))?.findings, 0);
    }
    // Known scope boundary: the wrapper does not decode opaque encoded values.
    // Pin these gaps explicitly rather than treating direct-only recall as parity.
    for (_, encoded) in support::encoding_variants()? {
        assert_eq!(scanner.scan(encoded.as_bytes(), |_| Ok(()))?.findings, 0);
    }
    // Verification is a fresh in-process scan, never content-deduplicated away.
    assert!(scanner.scan(input.as_slice(), |_| Ok(()))?.findings >= manifest.len() as u64);
    let mut builder =
        PlanBuilder::new(RedactionLimits::default()).map_err(|_| "redaction configuration")?;
    scanner.scan(input.as_slice(), |finding| {
        builder
            .push(&FindingRaw {
                label: finding.redaction_label(),
                raw: finding.raw(),
            })
            .map_err(|_| ScanError::Consumer)
    })?;
    let plan = builder.finish([]).map_err(|_| "redaction plan")?;
    let mut output = Zeroizing::new(Vec::new());
    assert!(
        plan.redact(input.as_slice(), &mut *output)
            .map_err(|_| "redaction failed")?
            .replacements
            > 0
    );
    // Assert each independent planted value disappeared, including env extras.
    for plant in &manifest {
        let value = input
            .get(usize::try_from(plant.range.start)?..usize::try_from(plant.range.end)?)
            .ok_or("invalid synthetic manifest")?;
        assert!(
            !output.windows(value.len()).any(|window| window == value),
            "planted family survived redaction: {}",
            plant.family
        );
    }
    assert_eq!(scanner.scan(output.as_slice(), |_| Ok(()))?.findings, 0);
    // One immutable catalog is shared, never compiled per file or per worker.
    std::thread::scope(|scope| {
        let handles: Vec<_> = support::BENIGN
            .iter()
            .take(2)
            .map(|fixture| {
                let scanner = &scanner;
                scope.spawn(move || scanner.scan(fixture.as_bytes(), |_| Ok(())))
            })
            .collect();
        for handle in handles {
            let summary = handle.join().map_err(|_| "catalog worker panicked")??;
            assert_eq!(summary.findings, 0);
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
