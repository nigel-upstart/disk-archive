//! Synthetic-only boundary, privacy and budget tests.
use std::io::{self, Read};

use disk_archive_scanner::{Limits, ScanError, Scanner};
use kingfisher_rules::{Rule, RuleSyntax, RulesDatabase};

fn scanner(pattern: &str, chunk: usize) -> Result<Scanner, Box<dyn std::error::Error>> {
    let db = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "fixture.synthetic",
        "Synthetic only",
        pattern,
    ))])?;
    Ok(Scanner::new(
        db,
        Limits {
            chunk_bytes: chunk,
            match_bytes: 256,
            line_bytes: 128,
            findings: 20,
        },
    )?)
}

#[test]
fn every_chunk_boundary_has_exact_offsets_and_no_duplicates()
-> Result<(), Box<dyn std::error::Error>> {
    let input = b"heading\n demo_abcd1234efgh5678 and demo_1234abcd5678efgh\n";
    for chunk in 1..=input.len() {
        let scanner = scanner(r"\b(?P<TOKEN>demo_[a-z0-9]{16})\b", chunk)?;
        let mut locations = Vec::new();
        let summary = scanner.scan(&input[..], |finding| {
            assert_eq!(finding.line(), 2);
            assert_eq!(finding.rule_id(), "fixture.synthetic");
            assert!(finding.raw().starts_with("demo_"));
            locations.push(finding.byte_range());
            Ok(())
        })?;
        assert_eq!(summary.bytes, input.len() as u64);
        assert_eq!(locations, vec![9..30, 35..56]);
        // Verification must not be suppressed by content deduplication.
        assert_eq!(scanner.scan(&input[..], |_| Ok(()))?.findings, 2);
    }
    Ok(())
}

#[test]
fn long_input_slides_and_preserves_line_offsets() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(r"(?P<TOKEN>demo_[a-z0-9]{16})", 31)?;
    let mut input = b"ordinary line\n".repeat(1000);
    let offset = input.len() as u64;
    input.extend_from_slice(b"demo_abcd1234efgh5678\n");
    let result = scanner.scan(input.as_slice(), |finding| {
        assert_eq!(finding.line(), 1001);
        assert_eq!(finding.byte_range(), offset..offset + 21);
        Ok(())
    })?;
    assert_eq!(result.findings, 1);
    Ok(())
}

#[test]
fn secrets_cross_sliding_window_frontiers() -> Result<(), Box<dyn std::error::Error>> {
    for chunk in [1, 7, 31, 256] {
        let scanner = scanner(r"(?P<TOKEN>demo_[a-z0-9]{16})", chunk)?;
        for padding in 240..290 {
            let mut input = b"ordinary\n".repeat(padding);
            let offset = input.len() as u64;
            input.extend_from_slice(b"demo_abcd1234efgh5678\n");
            let mut count = 0;
            scanner.scan(input.as_slice(), |finding| {
                assert_eq!(finding.byte_range(), offset..offset + 21);
                assert_eq!(finding.line(), padding as u64 + 1);
                count += 1;
                Ok(())
            })?;
            assert_eq!(count, 1);
        }
    }
    Ok(())
}

#[test]
fn unbounded_multiline_rules_are_guarded_not_omitted() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(r"BEGIN(?P<TOKEN>[a-z\n]+)END", 7)?;
    let input = b"ordinary\nBEGINabcd\nefghEND\n";
    let mut found = 0;
    scanner.scan(&input[..], |finding| {
        assert_eq!(finding.line(), 2);
        assert!(finding.raw().bytes().eq(b"abcd\nefgh".iter().copied()));
        found += 1;
        Ok(())
    })?;
    assert_eq!(found, 1);
    let mut giant = b"BEGIN".to_vec();
    giant.extend_from_slice(&b"aaaa\n".repeat(100));
    giant.extend_from_slice(b"END");
    assert_eq!(
        scanner.scan(giant.as_slice(), |_| Ok(())),
        Err(ScanError::MatchTooLarge)
    );
    Ok(())
}

#[test]
fn completed_nongreedy_records_do_not_poison_later_windows()
-> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(r"BEGIN(?P<TOKEN>(?s:.+?))END", 31)?;
    let mut input = b"BEGINabcdEND\n".to_vec();
    input.extend_from_slice(&b"ordinary\n".repeat(1000));
    input.extend_from_slice(b"BEGINefghEND\n");
    assert_eq!(scanner.scan(input.as_slice(), |_| Ok(()))?.findings, 2);
    Ok(())
}

#[test]
fn guard_priority_is_independent_for_every_rule() -> Result<(), Box<dyn std::error::Error>> {
    let database = RulesDatabase::from_rules(vec![
        Rule::new(RuleSyntax::new(
            "fixture.short",
            "Synthetic short",
            r"BEGIN(?s:.+?)END",
        )),
        Rule::new(RuleSyntax::new(
            "fixture.long",
            "Synthetic long",
            r"BEGIN(?s:.+)SUFFIX",
        )),
    ])?;
    let scanner = Scanner::new(
        database,
        Limits {
            chunk_bytes: 31,
            match_bytes: 256,
            line_bytes: 128,
            findings: 20,
        },
    )?;
    let mut input = b"BEGINabcdEND\n".to_vec();
    input.extend_from_slice(&b"ordinary\n".repeat(100));
    input.extend_from_slice(b"SUFFIX\n");
    assert_eq!(
        scanner.scan(input.as_slice(), |_| Ok(())),
        Err(ScanError::MatchTooLarge)
    );
    Ok(())
}

#[test]
fn anchors_are_not_fabricated_at_window_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(r"\Asecret|(?m:^demo_[a-z]{4}$)|tail\z", 3)?;
    let mut input = b"benign\n".repeat(100);
    input.extend_from_slice(b"notsecret\ndemo_abcd\ntailnot\ntail");
    let mut count = 0;
    scanner.scan(input.as_slice(), |_| {
        count += 1;
        Ok(())
    })?;
    assert_eq!(count, 2);
    Ok(())
}

#[test]
fn budgets_io_utf8_and_consumer_errors_block() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(r"(?P<TOKEN>demo_[a-z0-9]{16})", 8)?;
    assert_eq!(
        scanner.scan(&b"x".repeat(129)[..], |_| Ok(())),
        Err(ScanError::LineTooLarge)
    );
    assert_eq!(
        scanner.scan(FailingReader, |_| Ok(())),
        Err(ScanError::Read)
    );
    assert_eq!(
        scanner.scan(&b"demo_abcd1234efgh5678"[..], |_| Err(ScanError::Consumer)),
        Err(ScanError::Consumer)
    );
    let repeated = b"demo_abcd1234efgh5678\n".repeat(21);
    assert_eq!(
        scanner.scan(repeated.as_slice(), |_| Ok(())),
        Err(ScanError::Budget)
    );
    let binary = crate::scanner(r"(?P<TOKEN>\xFF{4})", 2)?;
    assert_eq!(
        binary.scan(&[255; 4][..], |_| Ok(())),
        Err(ScanError::UnsupportedInput)
    );
    Ok(())
}

#[test]
fn utf8_codepoints_split_across_reads_and_windows() -> Result<(), Box<dyn std::error::Error>> {
    for chunk in 1..=8 {
        let scanner = scanner(r"BEGIN(?P<TOKEN>(?:秘密|\n)+)END", chunk)?;
        let mut input = b"ordinary\n".repeat(100);
        let offset = input.len() as u64 + 5;
        input.extend_from_slice("BEGIN秘密\n秘密END\n".as_bytes());
        let summary = scanner.scan(input.as_slice(), |finding| {
            assert_eq!(finding.line(), 101);
            assert_eq!(finding.byte_range(), offset..offset + 13);
            assert!(finding.raw().bytes().eq("秘密\n秘密".bytes()));
            Ok(())
        })?;
        assert_eq!(summary.findings, 1);
    }
    let scanner = crate::scanner("fixture_[a-z]{8}", 1)?;
    assert_eq!(scanner.scan(&b"\xff\n\x80\n"[..], |_| Ok(()))?.findings, 0);
    Ok(())
}

#[test]
fn eof_anchored_oversize_match_fails_at_close() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(r"BEGIN(?P<TOKEN>[a-z\n]+)\z", 7)?;
    let mut exact = b"BEGIN".to_vec();
    exact.extend_from_slice(&b"a\n".repeat(125));
    exact.push(b'a');
    assert_eq!(exact.len(), 256);
    assert_eq!(scanner.scan(exact.as_slice(), |_| Ok(()))?.findings, 1);
    exact.push(b'\n');
    assert_eq!(
        scanner.scan(exact.as_slice(), |_| Ok(())),
        Err(ScanError::MatchTooLarge)
    );
    Ok(())
}

struct FailingReader;
impl Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        // Underlying messages are never preserved by scanner errors.
        Err(io::Error::other("synthetic input must not escape"))
    }
}

#[test]
fn oversized_and_empty_rules_fail_configuration() {
    assert!(scanner("a{300}", 8).is_err());
    assert!(scanner("a*", 8).is_err());
}

#[test]
fn arbitrary_bytes_never_escape_errors() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(r"fixture_[A-Za-z0-9]{8}", 11)?;
    let bytes: Vec<u8> = (0..=255).cycle().take(4096).collect();
    let result = scanner.scan(bytes.as_slice(), |_| Ok(()));
    assert_eq!(result, Err(ScanError::LineTooLarge));
    let message = ScanError::Read.to_string();
    assert!(!message.contains("synthetic input"));
    Ok(())
}
