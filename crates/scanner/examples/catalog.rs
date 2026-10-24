//! Compile and exercise the full embedded catalog on synthetic input only.
use disk_archive_scanner::{Limits, ScanError, Scanner};

fn main() -> Result<(), ScanError> {
    let scanner = Scanner::builtin(Limits::default())?;
    let summary = scanner.scan(&b"ordinary benign configuration\n"[..], |_| Ok(()))?;
    if summary.findings != 0 {
        return Err(ScanError::Engine);
    }
    Ok(())
}
