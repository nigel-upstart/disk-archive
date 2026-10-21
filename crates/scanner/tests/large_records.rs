//! Practical configured record bounds, independent of expensive catalog compilation.
use disk_archive_scanner::{Limits, ScanError, Scanner};
use kingfisher_rules::{Rule, RuleSyntax, RulesDatabase};

#[test]
fn dense_findings_have_exact_monotone_lines_at_default_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let database = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "fixture.dense",
        "Synthetic dense records",
        "x{15}",
    ))])?;
    let scanner = Scanner::new(database, Limits::default())?;
    let input = b"xxxxxxxxxxxxxxx\n".repeat(65_536);
    let mut count = 0_u64;
    let summary = scanner.scan(input.as_slice(), |finding| {
        assert_eq!(finding.line(), count + 1);
        assert_eq!(finding.byte_range(), count * 16..count * 16 + 15);
        count += 1;
        Ok(())
    })?;
    assert_eq!(count, 65_536);
    assert_eq!(summary.findings, count);
    Ok(())
}

#[test]
fn line_cursors_are_independent_for_each_rule() -> Result<(), Box<dyn std::error::Error>> {
    let database = RulesDatabase::from_rules(vec![
        Rule::new(RuleSyntax::new("fixture.x", "Synthetic x records", "x{4}")),
        Rule::new(RuleSyntax::new("fixture.y", "Synthetic y records", "y{4}")),
    ])?;
    let scanner = Scanner::new(database, Limits::default())?;
    let input = b"xxxx\nyyyy\n".repeat(1000);
    let mut x = 0_u64;
    let mut y = 0_u64;
    let summary = scanner.scan(input.as_slice(), |finding| {
        if finding.rule_id() == "fixture.x" {
            assert_eq!(finding.line(), 2 * x + 1);
            x += 1;
        } else {
            assert_eq!(finding.line(), 2 * y + 2);
            y += 1;
        }
        Ok(())
    })?;
    assert_eq!(summary.findings, 2000);
    assert_eq!((x, y), (1000, 1000));
    Ok(())
}

#[test]
fn practical_jsonl_records_keep_offsets_and_refuse_excess() -> Result<(), Box<dyn std::error::Error>>
{
    let database = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "fixture.large",
        "Synthetic large record",
        r"fixture_[A-Za-z0-9]{16}",
    ))])?;
    let limits = Limits::default();
    let scanner = Scanner::new(database, limits)?;
    let allocation = scanner.input_buffer_bytes();
    let token = b"fixture_abcd1234efgh5678";
    for size in [100 * 1024, 1024 * 1024] {
        let mut input = b"{\"tool_result\":\"".to_vec();
        // Plant over a 64 KiB read boundary, inside one realistic JSONL record.
        input.resize(65530, b'x');
        let start = input.len() as u64;
        input.extend_from_slice(token);
        input.resize(size - 3, b'x');
        input.extend_from_slice(b"\"}\n");
        let summary = scanner.scan(input.as_slice(), |finding| {
            assert_eq!(finding.byte_range(), start..start + token.len() as u64);
            assert_eq!(finding.line(), 1);
            Ok(())
        })?;
        assert_eq!(summary.findings, 1);
        assert_eq!(summary.bytes, size as u64);
        assert_eq!(scanner.input_buffer_bytes(), allocation);
    }
    let oversized = vec![b'x'; limits.line_bytes + 1];
    assert_eq!(
        scanner.scan(oversized.as_slice(), |_| Ok(())),
        Err(ScanError::LineTooLarge)
    );
    Ok(())
}
