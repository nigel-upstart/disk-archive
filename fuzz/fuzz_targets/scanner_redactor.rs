//! Arbitrary-byte full-catalog scanner -> actual core redactor -> full rescan.
//! Static errors only: never log, format or serialize fuzz input/findings.
#![no_main]

use disk_archive_core::redaction::{FindingRaw, Limits as RedactionLimits, PlanBuilder};
use disk_archive_scanner::{Limits, ScanError, Scanner};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zeroize::Zeroizing;

static SCANNER: OnceLock<Result<Scanner, ScanError>> = OnceLock::new();

fuzz_target!(init: {
    assert!(SCANNER.get_or_init(|| Scanner::builtin(Limits::default())).is_ok(), "full catalog failed initialization");
}, |input: &[u8]| {
    let scanner = match SCANNER.get_or_init(|| Scanner::builtin(Limits::default())) {
        Ok(scanner) => scanner,
        Err(_) => panic!("full catalog failed initialization"),
    };
    let mut builder = match PlanBuilder::new(RedactionLimits {
        max_line_bytes: 32769,
        max_output_line_bytes: 65536,
        ..RedactionLimits::default()
    }) {
        Ok(builder) => builder,
        Err(_) => panic!("fixed redaction limits invalid"),
    };
    if scanner
        .scan(input, |finding| {
            builder
                .push(&FindingRaw {
                    label: finding.redaction_label(),
                    raw: finding.raw(),
                })
                .map_err(|_| ScanError::Consumer)
        })
        .is_err()
    {
        return; // Any error blocks; partial callback output is not usable.
    }
    let Ok(plan) = builder.finish([]) else { return };
    let mut output = Zeroizing::new(Vec::new());
    if plan.redact(input, &mut *output).is_err() {
        return;
    }
    // Findings/errors here mean blocked verification, not a panic or clean result.
    let _verification = scanner.scan(output.as_slice(), |_| Ok(()));
});
