//! Archive-path regressions using the full built-in catalog and localhost SDK transport.

use super::*;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use disk_archive_scanner::{ScanError, Scanner};
use disk_archive_storage::{SdkStore, test_support::MockS3};

fn carriers() -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    use std::fmt::Write as _;
    let mixed = "aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cF0iL";
    let secret = format!(
        "ghp_{}",
        mixed.repeat(2).chars().take(36).collect::<String>()
    );
    let mut json = String::new();
    let mut percent = String::new();
    for byte in secret.bytes() {
        write!(&mut json, "\\u{byte:04x}")?;
        write!(&mut percent, "%{byte:02x}")?;
    }
    let encoded = STANDARD.encode(&secret);
    let mut padded = vec![b'x'; 48];
    padded.push(b' ');
    padded.extend_from_slice(secret.as_bytes());
    padded.extend_from_slice(b" public");
    let mut binary = vec![0xfb, 0xff, 0xff, b' '];
    binary.extend_from_slice(secret.as_bytes());
    binary.push(b' ');
    assert!(std::str::from_utf8(&binary).is_err());
    let mut carriers = vec![
        format!("{{\"value\":\"{json}\"}}\n").into_bytes(),
        percent.into_bytes(),
        encoded.as_bytes().to_vec(),
        format!("PAYLOAD={encoded}\n").into_bytes(),
        format!("secret_{encoded}").into_bytes(),
        wrapped(STANDARD.encode(&padded).as_bytes(), 76),
        wrapped(encoded.as_bytes(), 4),
    ];
    for encoding in [URL_SAFE, URL_SAFE_NO_PAD] {
        let url_safe = encoding.encode(&binary);
        // ASCII tokens alone do not exercise the alternate alphabet or invalid UTF-8 path.
        assert!(url_safe.contains('-') && url_safe.contains('_'));
        carriers.push(url_safe.as_bytes().to_vec());
        carriers.push(format!("secret_{url_safe}").into_bytes());
        carriers.push(wrapped(url_safe.as_bytes(), 4));
    }
    for little in [true, false] {
        let raw: Vec<u8> = secret
            .encode_utf16()
            .flat_map(|unit| {
                if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                }
            })
            .collect();
        let encoded = STANDARD.encode(&raw);
        carriers.push(encoded.as_bytes().to_vec());
        carriers.push(wrapped(encoded.as_bytes(), 76));
        let mut bom = if little {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        bom.extend_from_slice(&raw);
        carriers.push(bom);
        carriers.push(raw);
    }
    // A visible literal must not excuse an encoded copy that survives literal redaction.
    let mixed_carriers: Vec<Vec<u8>> = carriers
        .iter()
        .map(|carrier| {
            let mut mixed = format!("{secret}\n").into_bytes();
            mixed.extend_from_slice(carrier);
            mixed
        })
        .collect();
    carriers.extend(mixed_carriers);
    // R2-F1: the secret begins at byte 49, crossing the 57-byte decoded wrap boundary.
    // These layouts must join across whitespace/prefixes, including after JSON unescaping.
    carriers.extend(gap_carriers(&padded)?);
    Ok(carriers)
}

fn gap_carriers(payload: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let encoded = STANDARD.encode(payload);
    let mut indented = Vec::new();
    let mut trailing = Vec::new();
    for line in encoded.as_bytes().chunks(76) {
        indented.extend_from_slice(b"  ");
        indented.extend_from_slice(line);
        indented.extend_from_slice(b"\r\n");
        trailing.extend_from_slice(line);
        trailing.extend_from_slice(b" \t\r\n");
    }
    let mut yaml = b"data: |\n".to_vec();
    yaml.extend_from_slice(&indented);
    let mut prefixed = b"secret: ".to_vec();
    prefixed.extend_from_slice(&wrapped(encoded.as_bytes(), 76));
    let json = serde_json::to_vec(&serde_json::json!({
        "value": String::from_utf8(indented.clone())?,
    }))?;
    Ok(vec![indented, yaml, prefixed, trailing, json])
}

pub(super) async fn blocked_carriers(
    scanner: Arc<Scanner>,
    store: Arc<SdkStore>,
    mock: &MockS3,
) -> Result<(), Box<dyn std::error::Error>> {
    let carriers = carriers()?;
    assert_eq!(carriers.len(), 47);
    let fixture = Fixture::new(0)?;
    for (index, carrier) in carriers.iter().enumerate() {
        // Check the exact native error first; the shell deliberately exposes only static Blocked.
        assert!(
            matches!(
                scanner.scan(carrier.as_slice(), |_| Ok(())),
                Err(ScanError::UnsupportedEncoding)
            ),
            "encoded carrier ordinal {index}"
        );
        tokio::fs::write(fixture.root.join(format!("{index}.jsonl")), carrier).await?;
    }
    let services = fixture.services(store, scanner)?;
    let counters = services.counters.clone();
    let before = mock.source_put_attempts();
    let report = pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(report.deleted, 0);
    assert_eq!(report.retained, carriers.len());
    assert_eq!(mock.source_put_attempts(), before);
    assert_eq!(before, 0);
    assert_eq!(fixture.remaining()?, carriers.len());
    for (index, carrier) in carriers.iter().enumerate() {
        // Boolean assertion deliberately avoids formatting sensitive fixture bytes on failure.
        assert!(
            tokio::fs::read(fixture.root.join(format!("{index}.jsonl")))
                .await?
                .as_slice()
                .eq(carrier.as_slice())
        );
    }
    let pool = BlockingPool::new(1)?;
    let database = fixture.work.join("state.sqlite");
    let rows = pool
        .run(&CancellationToken::new(), move || read_rows(database))
        .await?;
    assert_eq!(rows.len(), carriers.len());
    assert!(rows.iter().all(|row| row.status == disk_archive::state::Status::Blocked && row.expected.is_none()));
    let measured = counters.snapshot().map_err(|_| Error::Worker)?;
    assert!(measured.peak_temp_bytes > 0);
    Ok(())
}

fn wrapped(encoded: &[u8], width: usize) -> Vec<u8> {
    let mut output = Vec::new();
    for line in encoded.chunks(width) {
        output.extend_from_slice(line);
        output.extend_from_slice(b"\r\n");
    }
    output
}
