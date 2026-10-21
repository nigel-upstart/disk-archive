//! Deterministic synthetic corpus and independently planted location manifest.
use std::fmt::Write;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

/// The planting manifest is produced by the fixture builder, never by detection.
pub(crate) struct Plant {
    pub(crate) family: &'static str,
    pub(crate) rule: &'static str,
    pub(crate) range: std::ops::Range<u64>,
}

pub(crate) const BENIGN: &[&str] = &[
    "Ordinary prose about clouds, source control and database migrations.\n",
    "fn retries(timeout: u64) -> u64 { timeout + 1 }\n",
    "https://docs.example.invalid/tutorial?q=configuration\n",
    "timeout=30\nretries=3\nlog_level=info\nregion=local\n",
    "curl https://example.invalid/public\nAuthorization header documentation only\n",
    "Public configuration: database=app; host=db.invalid; user=guest\n",
    "Unicode prose: 秘密 means secret; λ is a Greek letter.\n",
];

pub(crate) type EncodedFixtures = Vec<(&'static str, Zeroizing<String>)>;

pub(crate) fn encoding_variants() -> Result<EncodedFixtures, Box<dyn std::error::Error>> {
    let (input, manifest) = corpus();
    let plant = manifest
        .iter()
        .find(|plant| plant.family == "github")
        .ok_or("missing synthetic family")?;
    let value = input
        .get(usize::try_from(plant.range.start)?..usize::try_from(plant.range.end)?)
        .ok_or("invalid synthetic manifest")?;
    let mut json_unicode = String::new();
    let mut url_percent = String::new();
    for byte in value {
        write!(&mut json_unicode, "\\u{byte:04x}")?;
        write!(&mut url_percent, "%{byte:02X}")?;
    }
    Ok(vec![
        (
            "json-unicode",
            Zeroizing::new(format!("{{\"message\":\"{json_unicode}\"}}\n")),
        ),
        (
            "url-percent",
            Zeroizing::new(format!("https://example.invalid/?value={url_percent}\n")),
        ),
        (
            "base64",
            Zeroizing::new(format!("{{\"message\":\"{}\"}}\n", STANDARD.encode(value))),
        ),
    ])
}

pub(crate) fn corpus() -> (Zeroizing<Vec<u8>>, Vec<Plant>) {
    let mut input = Zeroizing::new(Vec::new());
    let mut manifest = Vec::new();
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let token: String = alphabet.chars().cycle().take(16).collect();
    let mixed = "aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cF0iL";
    let values = [
        (
            "cloud",
            "betterleaks.aws-access-token",
            format!("AKIA{token}"),
        ),
        (
            "github",
            "betterleaks.github-pat",
            format!(
                "ghp_{}",
                mixed.repeat(2).chars().take(36).collect::<String>()
            ),
        ),
        (
            "gitlab",
            "betterleaks.gitlab-pat",
            format!("glpat-{}", mixed.chars().take(20).collect::<String>()),
        ),
        (
            "slack",
            "betterleaks.slack-bot-token",
            format!(
                "xoxb-{}-{}-{}",
                1_234_567_890_u64,
                9_876_543_210_u64,
                mixed.chars().take(24).collect::<String>()
            ),
        ),
        (
            "jwt",
            "betterleaks.jwt",
            [
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "eyJzdWIiOiJzeW50aGV0aWMiLCJleHAiOjB9",
                "YUJjREVGR2hpSktMbW5PcFFyc1R1VndYeXphQkNERUY",
            ]
            .join("."),
        ),
        (
            "private-key",
            "betterleaks.private-key",
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                mixed.repeat(3)
            ),
        ),
        (
            "database",
            "betterleaks.mongodb-connection-string",
            format!("mongodb://fixture_user:{mixed}@db.invalid/example"),
        ),
    ];
    for (family, rule, value) in values {
        let value = Zeroizing::new(value);
        input.extend_from_slice(b"synthetic fixture\n");
        let start = input.len() as u64;
        input.extend_from_slice(value.as_bytes());
        let end = input.len() as u64;
        input.push(b'\n');
        manifest.push(Plant {
            family,
            rule,
            range: start..end,
        });
    }
    // This independent plant belongs to the core's legacy env-assignment layer,
    // not to an invented native catalog rule.
    input.extend_from_slice(b"SYNTHETIC_PASSWORD=");
    let start = input.len() as u64;
    let env_value = Zeroizing::new(mixed.chars().rev().collect::<String>());
    input.extend_from_slice(env_value.as_bytes());
    let end = input.len() as u64;
    input.push(b'\n');
    manifest.push(Plant {
        family: "env",
        rule: "core.env",
        range: start..end,
    });
    (input, manifest)
}
