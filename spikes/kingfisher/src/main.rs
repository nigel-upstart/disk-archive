//! Standalone native/API feasibility check; no production inputs or validators.
use std::sync::Arc;

use kingfisher_scanner::{
    Rule, RuleSyntax, RulesDatabase, Scanner, ScannerConfig, get_builtin_rules,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert!(kingfisher_vectorscan::version().starts_with("5.4.13"));
    let custom = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "disk-archive.synthetic",
        "Synthetic fixture",
        r"(?P<token>demo_[a-z0-9]{16})",
    ))])?;
    let scanner = Scanner::with_config(
        Arc::new(custom),
        ScannerConfig {
            redact_secrets: true,
            enable_base64_decoding: false,
            ..Default::default()
        },
    );
    let findings = scanner.scan_bytes(b"token=demo_abcd1234efgh5678")?;
    assert_eq!(findings.len(), 1);
    assert!(
        scanner
            .scan_bytes(b"ordinary benign configuration")?
            .is_empty()
    );
    // Repeated scans must not hide a secret during the verification pass.
    assert_eq!(scanner.scan_bytes(b"token=demo_abcd1234efgh5678")?.len(), 1);
    // Also compile the actual embedded catalog, not only a hand-written expression.
    let catalog = RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?;
    let count = catalog.rules().len();
    assert!(count > 100);
    let builtins = Scanner::with_config(
        Arc::new(catalog),
        ScannerConfig {
            redact_secrets: true,
            ..Default::default()
        },
    );
    assert!(
        builtins
            .scan_bytes(b"ordinary benign configuration")?
            .is_empty()
    );
    println!("native/API spike passed; compiled {count} catalog rules; no finding values printed");
    Ok(())
}
