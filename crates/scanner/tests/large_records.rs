//! Practical configured record bounds, independent of expensive catalog compilation.
use disk_archive_scanner::{Limits, ScanError, Scanner};
use kingfisher_rules::{Rule, RuleSyntax, RulesDatabase};

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
