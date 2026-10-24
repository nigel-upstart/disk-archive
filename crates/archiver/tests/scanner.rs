//! Scanner injection must never accept partial reads or swallowed consumer failures.

use std::io::Read;

use disk_archive::{
    Error,
    scanner::{self, Finding, ScanEngine, ScanReport},
};

struct Partial;
impl ScanEngine for Partial {
    fn scan(
        &self,
        _input: &mut dyn Read,
        _consume: &mut dyn FnMut(Finding<'_>) -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        Ok(ScanReport {
            bytes: 0,
            findings: 0,
        })
    }
}

struct Swallow;
impl ScanEngine for Swallow {
    fn scan(
        &self,
        input: &mut dyn Read,
        consume: &mut dyn FnMut(Finding<'_>) -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).map_err(|_| Error::Io)?;
        let _ = consume(Finding {
            rule_id: "synthetic.rule",
            label: "synthetic",
            line: 1,
            raw: "synthetic-value",
        });
        Ok(ScanReport {
            bytes: u64::try_from(bytes.len()).map_err(|_| Error::Budget)?,
            findings: 1,
        })
    }
}

#[test]
fn a_zero_byte_partial_scan_is_not_a_clean_file() {
    assert_eq!(
        scanner::scan(&Partial, b"not read".as_slice(), |_| Ok(())),
        Err(Error::Blocked)
    );
}

#[test]
fn a_swallowed_callback_error_poisons_complete_scan() {
    assert_eq!(
        scanner::scan(&Swallow, b"synthetic-value".as_slice(), |_| Err(
            Error::Budget
        )),
        Err(Error::Blocked)
    );
}

struct WrongCounts;
impl ScanEngine for WrongCounts {
    fn scan(
        &self,
        input: &mut dyn Read,
        _consume: &mut dyn FnMut(Finding<'_>) -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).map_err(|_| Error::Io)?;
        Ok(ScanReport {
            bytes: 0,
            findings: 1,
        })
    }
}

#[test]
fn successful_eof_with_false_byte_or_finding_counts_is_rejected() {
    assert_eq!(
        scanner::scan(&WrongCounts, b"synthetic".as_slice(), |_| Ok(())),
        Err(Error::Blocked)
    );
}
