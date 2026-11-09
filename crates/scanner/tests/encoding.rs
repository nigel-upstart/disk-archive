//! Static fail-closed encoded-carrier controls, with no offset-redaction claim.
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use disk_archive_scanner::{Limits, ScanError, Scanner};
use kingfisher_rules::{Rule, RuleSyntax, RulesDatabase};

fn scanner(chunk: usize) -> Result<Scanner, Box<dyn std::error::Error>> {
    let db = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "fixture.encoding",
        "Synthetic encoding only",
        r"demo_[a-z0-9]{16}",
    ))])?;
    Ok(Scanner::new(
        db,
        Limits {
            chunk_bytes: chunk,
            ..Limits::default()
        },
    )?)
}

fn utf16(text: &str, little: bool) -> Vec<u8> {
    text.encode_utf16()
        .flat_map(|unit| {
            if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            }
        })
        .collect()
}

fn escaped(text: &str, json: bool) -> Result<Vec<u8>, std::fmt::Error> {
    use std::fmt::Write;
    let mut result = String::new();
    for byte in text.bytes() {
        if json {
            write!(&mut result, "\\u{byte:04x}")?;
        } else {
            write!(&mut result, "%{byte:02x}")?;
        }
    }
    Ok(result.into_bytes())
}

#[test]
fn encoded_only_secrets_block_at_every_read_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let secret = "demo_abcd1234efgh5678";
    let mut carriers = vec![
        STANDARD.encode(secret).into_bytes(),
        format!("PAYLOAD={}", STANDARD.encode(secret)).into_bytes(),
        format!("https://example.invalid/?value={}", STANDARD.encode(secret)).into_bytes(),
        URL_SAFE_NO_PAD.encode(secret).into_bytes(),
        escaped(secret, true)?,
        escaped(secret, false)?,
        STANDARD.encode(STANDARD.encode(secret)).into_bytes(),
        br"\u0064emo_abcd1234efgh5678".to_vec(),
        b"%64emo_abcd1234efgh5678".to_vec(),
    ];
    let mut binary = vec![0xfb, 0xff, 0xff, b' '];
    binary.extend_from_slice(secret.as_bytes());
    binary.push(b' ');
    assert!(std::str::from_utf8(&binary).is_err());
    let url_safe = URL_SAFE_NO_PAD.encode(&binary);
    assert!(url_safe.contains('-') && url_safe.contains('_'));
    carriers.push(url_safe.into_bytes());
    for little in [true, false] {
        let raw = utf16(secret, little);
        carriers.push(raw.clone());
        carriers.push(STANDARD.encode(&raw).into_bytes());
        let mut bom = if little {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        bom.extend_from_slice(&raw);
        carriers.push(bom);
        let mut prefix = b"prefix:".to_vec();
        prefix.extend_from_slice(&raw);
        carriers.push(prefix);
        // LF in UTF16LE/BE is not a carrier boundary. Include a secret on a
        // later line, including a trailing partial unit.
        let mut multiline = utf16(&format!("heading\n{secret}\n"), little);
        multiline.push(0xff);
        carriers.push(multiline);
    }
    for chunk in [1, 2, 3, 7, 64 * 1024] {
        let scanner = scanner(chunk)?;
        for carrier in &carriers {
            assert_eq!(
                scanner.scan(carrier.as_slice(), |_| Ok(())),
                Err(ScanError::UnsupportedEncoding)
            );
        }
    }
    Ok(())
}

fn wrapped(bytes: &[u8], width: usize, crlf: bool) -> Vec<u8> {
    let mut output = Vec::new();
    for line in bytes.chunks(width) {
        output.extend_from_slice(line);
        output.extend_from_slice(if crlf { b"\r\n" } else { b"\n" });
    }
    output
}

#[test]
fn wrapped_and_identifier_prefixed_carriers_do_not_certify_clean()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = "demo_abcd1234efgh5678";
    let text = format!("{} {secret} {}", "x".repeat(48), "z".repeat(20));
    for chunk in [1, 31, 64 * 1024] {
        let scanner = scanner(chunk)?;
        for width in [1, 4, 8, 64, 76] {
            for crlf in [false, true] {
                let carrier = wrapped(STANDARD.encode(&text).as_bytes(), width, crlf);
                assert_eq!(
                    scanner.scan(carrier.as_slice(), |_| Ok(())),
                    Err(ScanError::UnsupportedEncoding)
                );
            }
        }
        for prefix in 0..16 {
            for encoded in [STANDARD.encode(secret), URL_SAFE_NO_PAD.encode(secret)] {
                let carrier = format!("{}_{encoded}", "p".repeat(prefix));
                assert_eq!(
                    scanner.scan(carrier.as_bytes(), |_| Ok(())),
                    Err(ScanError::UnsupportedEncoding)
                );
            }
        }
        for little in [true, false] {
            let raw = utf16(&text, little);
            let carrier = wrapped(STANDARD.encode(&raw).as_bytes(), 76, true);
            assert_eq!(
                scanner.scan(carrier.as_slice(), |_| Ok(())),
                Err(ScanError::UnsupportedEncoding)
            );
        }
    }
    Ok(())
}

fn whitespace_wrapped(text: &str, case: usize) -> Vec<u8> {
    let encoded = STANDARD.encode(text);
    let mut output = if case == 1 {
        String::from("data: |\n")
    } else if case == 4 {
        String::from("{\"out\":\"")
    } else {
        String::new()
    };
    for (index, line) in encoded.as_bytes().chunks(76).enumerate() {
        output.push_str(match case {
            0 | 1 | 4 => " \t ",
            2 if index == 0 => "secret: ",
            _ => "",
        });
        for &byte in line {
            output.push(char::from(byte));
        }
        output.push_str(if case == 3 {
            " \t\n"
        } else if case == 4 {
            "\\n"
        } else {
            "\n"
        });
    }
    if case == 4 {
        output.push_str("\"}\n");
    }
    output.into_bytes()
}

fn assert_wrapped_blocked(case: usize) -> Result<(), Box<dyn std::error::Error>> {
    // The secret crosses decoded byte 57, so neither physical line suffices.
    let text = format!(
        "{} demo_abcd1234efgh5678 {}",
        "x".repeat(48),
        "z".repeat(20)
    );
    let carrier = whitespace_wrapped(&text, case);
    for chunk in [1, 2, 3, 7, 64 * 1024] {
        let scanner = scanner(chunk)?;
        assert_eq!(
            scanner.scan(carrier.as_slice(), |_| Ok(())),
            Err(ScanError::UnsupportedEncoding)
        );
    }
    Ok(())
}

#[test]
fn r2_indented_wrapping_blocks() -> Result<(), Box<dyn std::error::Error>> {
    assert_wrapped_blocked(0)
}

#[test]
fn r2_yaml_block_scalar_blocks() -> Result<(), Box<dyn std::error::Error>> {
    assert_wrapped_blocked(1)
}

#[test]
fn r2_first_line_prefix_blocks() -> Result<(), Box<dyn std::error::Error>> {
    assert_wrapped_blocked(2)
}

#[test]
fn r2_trailing_horizontal_space_blocks() -> Result<(), Box<dyn std::error::Error>> {
    assert_wrapped_blocked(3)
}

#[test]
fn r2_json_escaped_indentation_blocks() -> Result<(), Box<dyn std::error::Error>> {
    assert_wrapped_blocked(4)
}

#[test]
fn recursive_whitespace_wrapping_and_benign_controls() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(7)?;
    let secret = format!(
        "{} demo_abcd1234efgh5678 {}",
        "x".repeat(48),
        "z".repeat(20)
    );
    let benign = format!("{} public_documentation {}", "x".repeat(48), "z".repeat(20));
    for case in 0..5 {
        for (text, blocked) in [(&secret, true), (&benign, false)] {
            let raw = whitespace_wrapped(text, case);
            // Physical layout, Base64-of-layout, and percent-unescaped layout
            // must use the same joining rules, not only the raw reader path.
            let carriers = [
                raw.clone(),
                STANDARD.encode(&raw).into_bytes(),
                escaped(std::str::from_utf8(&raw)?, false)?,
            ];
            for carrier in carriers {
                let result = scanner.scan(carrier.as_slice(), |_| Ok(()));
                if blocked {
                    assert_eq!(result, Err(ScanError::UnsupportedEncoding));
                } else {
                    assert_eq!(result?.findings, 0);
                }
            }
        }
    }
    // Independent unpadded lines must still be checked even if their joined
    // decoding would shift the second carrier's secret.
    let carrier = format!("cA\n{}\n", STANDARD.encode("demo_abcd1234efgh5678"));
    assert_eq!(
        scanner.scan(carrier.as_bytes(), |_| Ok(())),
        Err(ScanError::UnsupportedEncoding)
    );
    Ok(())
}

#[test]
fn sticky_nul_remainder_obeys_effective_utf16_expansion_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(64 * 1024)?;
    for (size, blocked) in [
        (600 * 1024, false),
        (699_048, false),
        (699_054, true),
        (690 * 1024, true),
        (1000 * 1024, true),
    ] {
        let mut carrier = b"h\0\n".to_vec();
        carrier.resize(size, b'a');
        let result = scanner.scan(carrier.as_slice(), |_| Ok(()));
        if blocked {
            assert_eq!(result, Err(ScanError::Budget));
        } else {
            assert_eq!(result?.findings, 0);
        }
    }
    // Bare LF must NOT clear the sticky carrier: the NUL's whole remainder
    // stays bounded, even when later records look like ordinary JSONL.
    let ordinary = b"{\"k\": \"ordinary prose\"}\n".repeat(48_000);
    assert_eq!(scanner.scan(ordinary.as_slice(), |_| Ok(()))?.findings, 0);
    let mut with_nul = b"header\0\n".to_vec();
    with_nul.extend_from_slice(&ordinary);
    assert_eq!(
        scanner.scan(with_nul.as_slice(), |_| Ok(())),
        Err(ScanError::Budget)
    );
    Ok(())
}

#[test]
fn benign_encoded_values_are_not_blanket_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(7)?;
    for plain in [
        "ordinary documentation text",
        "秘密 λ and public configuration",
        "nonsecretabcdefgh",
    ] {
        let mut carriers = vec![
            plain.as_bytes().to_vec(),
            STANDARD.encode(plain).into_bytes(),
            URL_SAFE_NO_PAD.encode(plain).into_bytes(),
            escaped(plain, false)?,
        ];
        for little in [true, false] {
            let raw = utf16(plain, little);
            carriers.push(STANDARD.encode(&raw).into_bytes());
            carriers.push(raw);
        }
        for carrier in carriers {
            assert_eq!(scanner.scan(carrier.as_slice(), |_| Ok(()))?.findings, 0);
        }
    }
    let benign_binary = URL_SAFE_NO_PAD.encode(b"\xfb\xff\xff public documentation only");
    assert!(benign_binary.contains('-') && benign_binary.contains('_'));
    assert_eq!(
        scanner.scan(benign_binary.as_bytes(), |_| Ok(()))?.findings,
        0
    );
    assert_eq!(
        scanner
            .scan(&br"\uD83D\uDE00 public \u03bb"[..], |_| Ok(()))?
            .findings,
        0
    );
    assert_eq!(
        scanner
            .scan(&b"%%% invalid =base64=== only"[..], |_| Ok(()))?
            .findings,
        0
    );
    Ok(())
}

#[test]
fn depth_and_carrier_budgets_fail_closed_with_static_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(31)?;
    let mut carrier = b"ordinary public documentation".to_vec();
    for _ in 0..10 {
        carrier = STANDARD.encode(&carrier).into_bytes();
    }
    assert_eq!(
        scanner.scan(carrier.as_slice(), |_| Ok(())),
        Err(ScanError::Budget)
    );
    // A long run consisting ONLY of base64-alphabet lines is an ambiguous
    // encoded carrier, not ordinary prose: enforce the same 1 MiB carrier cap.
    let carrier = b"ordinary\n".repeat(150_000);
    assert_eq!(
        scanner.scan(carrier.as_slice(), |_| Ok(())),
        Err(ScanError::Budget)
    );
    let carrier = b"a\0\n".repeat(400_000);
    assert_eq!(
        scanner.scan(carrier.as_slice(), |_| Ok(())),
        Err(ScanError::Budget)
    );
    let error = scanner
        .scan(&br"\uD800"[..], |_| Ok(()))
        .err()
        .ok_or("expected static error")?;
    assert_eq!(error, ScanError::UnsupportedEncoding);
    assert!(!error.to_string().contains("D800"));
    Ok(())
}

fn nested_escapes(
    text: &str,
    json: bool,
    levels: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut carrier = String::from_utf8(escaped(text, json)?)?;
    for _ in 1..levels {
        carrier = if json {
            carrier.replace('\\', r"\u005c")
        } else {
            carrier.replace('%', "%25")
        };
    }
    Ok(carrier.into_bytes())
}

#[test]
fn inert_escape_markers_at_depth_limit_do_not_block() -> Result<(), Box<dyn std::error::Error>> {
    for json in [true, false] {
        let carrier = nested_escapes(r"\q%", json, 8)?;
        for chunk in [1, 31, 64 * 1024] {
            let summary = scanner(chunk)?.scan(carrier.as_slice(), |_| Ok(()))?;
            assert_eq!(summary.bytes, carrier.len() as u64);
            assert_eq!(summary.findings, 0);
        }
        // A ninth actual transformation still exceeds the bounded depth cap.
        let carrier = nested_escapes(r"\q%", json, 9)?;
        assert_eq!(
            scanner(31)?.scan(carrier.as_slice(), |_| Ok(())),
            Err(ScanError::Budget)
        );
    }
    Ok(())
}

#[test]
fn encoded_secrets_at_depth_limit_still_block() -> Result<(), Box<dyn std::error::Error>> {
    for json in [true, false] {
        let carrier = nested_escapes("demo_abcd1234efgh5678", json, 8)?;
        assert_eq!(
            scanner(31)?.scan(carrier.as_slice(), |_| Ok(())),
            Err(ScanError::UnsupportedEncoding)
        );
    }
    Ok(())
}

#[test]
fn ordinary_records_do_not_exhaust_a_lifetime_decode_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(64 * 1024)?;
    let input = b"ordinary prose\n".repeat(262_145);
    assert_eq!(scanner.scan(input.as_slice(), |_| Ok(()))?.findings, 0);
    Ok(())
}

#[test]
fn raw_literal_presence_does_not_excuse_a_hidden_encoded_copy()
-> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(31)?;
    let secret = "demo_abcd1234efgh5678";
    for carrier in [
        format!("{secret} {}", STANDARD.encode(secret)),
        format!(
            "{secret} {}",
            escaped(secret, true)?
                .iter()
                .map(|byte| char::from(*byte))
                .collect::<String>()
        ),
        format!(r#"{{"literal":"{secret}","hidden":"%64emo_abcd1234efgh5678"}}"#),
    ] {
        assert_eq!(
            scanner.scan(carrier.as_bytes(), |_| Ok(())),
            Err(ScanError::UnsupportedEncoding)
        );
    }
    Ok(())
}

#[test]
fn unchanged_literal_matches_are_delivered_for_normal_redaction()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = "demo_abcd1234efgh5678";
    for chunk in [1, 7, 31, 64 * 1024] {
        let scanner = scanner(chunk)?;
        for carrier in [
            format!(r#"{{"text":"line\n{secret}\nend"}}"#),
            format!(r#"{{"text":"line\\n{secret}\\nend"}}"#),
            format!(r#"{{"text":"line%20{secret}%20end"}}"#),
            format!(r#"{{"text":"λ\n{secret}%20end"}}"#),
        ] {
            let mut findings = 0;
            let summary = scanner.scan(carrier.as_bytes(), |finding| {
                assert!(finding.raw().eq(secret));
                let range = finding.byte_range();
                assert!(
                    carrier
                        .as_bytes()
                        .get(
                            usize::try_from(range.start).map_err(|_| ScanError::Budget)?
                                ..usize::try_from(range.end).map_err(|_| ScanError::Budget)?,
                        )
                        .is_some_and(|bytes| bytes.eq(secret.as_bytes()))
                );
                findings += 1;
                Ok(())
            })?;
            assert_eq!(summary.findings, 1);
            assert_eq!(findings, 1);
        }
    }
    Ok(())
}

#[test]
fn source_presence_does_not_excuse_changed_context_or_opaque_carriers()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = "demo_abcd1234efgh5678";
    let db = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "fixture.context",
        "Synthetic context only",
        r"key=(demo_[a-z0-9]{16})",
    ))])?;
    let scanner = Scanner::new(db, Limits::default())?;
    for carrier in [
        format!(r#"{{"text":"key\u003d{secret}"}}"#),
        format!(r#"{{"text":"key%3d{secret}"}}"#),
        STANDARD.encode(format!(r#"{{"text":"key={secret}\n"}}"#)),
    ] {
        assert_eq!(
            scanner.scan(carrier.as_bytes(), |_| Ok(())),
            Err(ScanError::UnsupportedEncoding)
        );
    }
    // Even a direct match at an artificial carrier edge is not proof of raw
    // streaming behavior. Keep that ambiguous case blocked.
    assert_eq!(
        scanner.scan(format!(r"key={secret}\n").as_bytes(), |_| Ok(())),
        Err(ScanError::UnsupportedEncoding)
    );
    Ok(())
}

#[test]
fn five_real_decode_stages_accept_benign_utf16_but_block_encoded_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    for chunk in [1, 7, 64 * 1024] {
        let scanner = scanner(chunk)?;
        for (text, secret) in [("hi there.", false), ("demo_abcd1234efgh5678", true)] {
            let base64 = STANDARD.encode(utf16(text, true));
            let percent = escaped(&base64, false)?;
            let carrier = nested_escapes(std::str::from_utf8(&percent)?, true, 2)?;
            let result = scanner.scan(carrier.as_slice(), |_| Ok(()));
            if secret {
                assert_eq!(result, Err(ScanError::UnsupportedEncoding));
            } else {
                assert_eq!(result?.findings, 0);
            }
        }
    }
    Ok(())
}

#[test]
fn provenance_does_not_invent_boundaries_or_exempt_multiline_rules()
-> Result<(), Box<dyn std::error::Error>> {
    for (pattern, input) in [
        (
            r"\Aprefix (demo_[a-z0-9]{16})",
            r"prefix demo_abcd1234efgh5678\n!",
        ),
        (
            r"(?s)(demo_[a-z0-9]{16}).*\z",
            r"! demo_abcd1234efgh5678\n!",
        ),
        (
            r"(?s)BEGIN.*?(demo_[a-z0-9]{16}).*?END",
            r"! BEGIN demo_abcd1234efgh5678 END\n!",
        ),
        (r"\bdemo_[a-z0-9]{16}", r"! x\u0020demo_abcd1234efgh5678 !"),
    ] {
        let db = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
            "fixture.boundary",
            "Synthetic boundary only",
            pattern,
        ))])?;
        let scanner = Scanner::new(db, Limits::default())?;
        assert_eq!(
            scanner.scan(input.as_bytes(), |_| Ok(())),
            Err(ScanError::UnsupportedEncoding)
        );
    }
    let scanner = scanner(7)?;
    let seeded = b"heading token \t\n{\"text\":\" demo_abcd1234efgh5678 \\n\"}";
    assert_eq!(
        scanner.scan(seeded.as_slice(), |_| Ok(())),
        Err(ScanError::UnsupportedEncoding)
    );
    let excessive = "x%20".repeat(4097);
    assert_eq!(
        scanner.scan(excessive.as_bytes(), |_| Ok(())),
        Err(ScanError::Budget)
    );
    for json in [true, false] {
        let carrier = nested_escapes("! \\q%\n!", json, 8)?;
        assert_eq!(scanner.scan(carrier.as_slice(), |_| Ok(()))?.findings, 0);
    }
    Ok(())
}

#[test]
fn multiline_utf16_uses_the_same_native_multiline_expression()
-> Result<(), Box<dyn std::error::Error>> {
    let db = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "fixture.multiline",
        "Synthetic multiline encoding",
        "BEGIN[a-z\\n]+END",
    ))])?;
    let scanner = Scanner::new(db, Limits::default())?;
    for little in [true, false] {
        let raw = utf16("BEGINabcd\nefghEND\n", little);
        for carrier in [raw.clone(), STANDARD.encode(&raw).into_bytes()] {
            assert_eq!(
                scanner.scan(carrier.as_slice(), |_| Ok(())),
                Err(ScanError::UnsupportedEncoding)
            );
        }
    }
    Ok(())
}
