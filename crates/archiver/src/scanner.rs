//! Narrow in-process scanner seam for identical-pipeline benchmark comparisons.
//!
//! The production CLI always constructs the native scanner. Benchmark adapters can implement
//! this trait without adding a production subprocess backend. Adapter completeness, budgets,
//! cancellation and whole-output semantics remain obligations of each implementation.

use std::io::Read;

use crate::Error;

/// Borrowed finding; never Debug, Clone or serializable. Consumers must not log raw values.
pub struct Finding<'a> {
    /// Original stable detector identifier for value-free counts.
    pub rule_id: &'a str,
    /// Core-compatible replacement label, safe ASCII and bounded by the core plan builder.
    pub label: &'a str,
    /// One-based physical line on which the finding begins.
    pub line: u64,
    /// Matched UTF8 value; valid only during the callback.
    pub raw: &'a str,
}

/// Complete successful scan counts, never an authorization token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanReport {
    /// Exact input bytes consumed.
    pub bytes: u64,
    /// Complete finding count; truncated/error scans must return an error instead.
    pub findings: u64,
}

/// Object-safe scanner interface shared by the pipeline and benchmark-only adapters.
pub trait ScanEngine: Send + Sync {
    /// Scan all bytes, forwarding ephemeral findings without unbounded accumulation.
    /// A callback error must poison the entire scan; partial results cannot certify clean input.
    ///
    /// # Errors
    /// Any I/O, budget, cancellation, callback or incomplete-scan failure blocks the file.
    fn scan(
        &self,
        input: &mut dyn Read,
        consume: &mut dyn FnMut(Finding<'_>) -> Result<(), Error>,
    ) -> Result<ScanReport, Error>;
}

impl ScanEngine for disk_archive_scanner::Scanner {
    fn scan(
        &self,
        input: &mut dyn Read,
        consume: &mut dyn FnMut(Finding<'_>) -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        let report = Self::scan(self, input, |finding| {
            consume(Finding {
                rule_id: finding.rule_id(),
                label: finding.redaction_label(),
                line: finding.line(),
                raw: finding.raw(),
            })
            .map_err(|_| disk_archive_scanner::ScanError::Budget)
        })
        .map_err(|_| Error::Blocked)?;
        Ok(ScanReport {
            bytes: report.bytes,
            findings: report.findings,
        })
    }
}

/// Sized convenience gateway to the object-safe interface.
///
/// # Errors
/// Propagates complete-scan or callback failure without accepting partial output.
pub fn scan(
    engine: &dyn ScanEngine,
    mut input: impl Read,
    mut consume: impl FnMut(Finding<'_>) -> Result<(), Error>,
) -> Result<ScanReport, Error> {
    let mut reader = Counted {
        input: &mut input,
        bytes: 0,
        eof: false,
    };
    let mut findings = 0_u64;
    let mut poisoned = false;
    let report = engine.scan(&mut reader, &mut |finding| {
        findings = findings.checked_add(1).ok_or(Error::Budget)?;
        let result = consume(finding);
        poisoned |= result.is_err();
        result
    })?;
    if poisoned || !reader.eof || report.bytes != reader.bytes || report.findings != findings {
        return Err(Error::Blocked);
    }
    Ok(report)
}

struct Counted<'a, R> {
    input: &'a mut R,
    bytes: u64,
    eof: bool,
}
impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let n = self.input.read(bytes)?;
        if n == 0 && !bytes.is_empty() {
            self.eof = true;
        }
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(n).map_err(|_| std::io::ErrorKind::InvalidData)?)
            .ok_or(std::io::ErrorKind::InvalidData)?;
        Ok(n)
    }
}
