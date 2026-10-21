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
    for _ in 0..6 {
        carrier = STANDARD.encode(&carrier).into_bytes();
    }
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

#[test]
fn ordinary_records_do_not_exhaust_a_lifetime_decode_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let scanner = scanner(64 * 1024)?;
    let input = b"ordinary\n".repeat(262_145);
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
        // The minimum-safe preflight can conservatively retain even this case.
        // Literal equality alone cannot prove whether a transformed copy is safe.
        format!("{secret} unrelated%20escape"),
    ] {
        assert_eq!(
            scanner.scan(carrier.as_bytes(), |_| Ok(())),
            Err(ScanError::UnsupportedEncoding)
        );
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
