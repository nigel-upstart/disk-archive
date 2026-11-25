//! Fixed-buffer microbenchmarks, separate from the actual pipeline collector.
//!
//! Scanner setup compiles the entire production catalog outside the measured region.
//! The gzip/SHA256 composition uses the same library/settings as storage preparation,
//! but intentionally excludes its disk admission, file I/O, CRC64 and SDK work.
use std::io::Write as _;

use disk_archive_scanner::{Limits, ScanError, ScanSummary, Scanner};
use flate2::{Compression, GzBuilder};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// Fixed input geometry shared by Criterion and Callgrind.
pub const BUFFER_BYTES: usize = 100 * 1024;
const TOKEN: &[u8] = b"ghp_abcdefghijklmnopqrstuvwxyz0123456789";

/// Deterministic buffer with independent token placement and word boundaries.
#[must_use]
pub fn buffer() -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(b"{\"content\":\" ".to_vec());
    bytes.extend_from_slice(TOKEN);
    bytes.push(b' ');
    while bytes.len() < BUFFER_BYTES - 3 {
        bytes.extend_from_slice(b"public observed result 488 ");
    }
    bytes.truncate(BUFFER_BYTES - 3);
    bytes.extend_from_slice(b"\"}\n");
    bytes
}

/// Compile all 502 rules in the pinned production catalog.
///
/// # Errors
/// Propagates scanner initialization failures and rejects a mismatched catalog.
pub fn full_catalog() -> Result<Scanner, ScanError> {
    let scanner = Scanner::builtin(Limits::default())?;
    if scanner.rule_count() != 502 {
        return Err(ScanError::UnsupportedRules);
    }
    Ok(scanner)
}

/// Reusable full-catalog fixture. Creation is not scanner throughput.
pub struct ScannerFixture {
    scanner: Scanner,
    input: Zeroizing<Vec<u8>>,
}

impl ScannerFixture {
    /// Compile and check the full native catalog.
    ///
    /// # Errors
    /// Propagates catalog/resource failures without a faster partial result.
    pub fn new() -> Result<Self, ScanError> {
        Ok(Self {
            scanner: full_catalog()?,
            input: buffer(),
        })
    }

    /// Scan the fixed buffer and count without retaining/logging findings.
    ///
    /// # Errors
    /// Any scan failure or missing independently planted secret fails the sample.
    pub fn scan(&self) -> Result<ScanSummary, ScanError> {
        let mut planted = 0_u64;
        let summary = self.scanner.scan(self.input.as_slice(), |finding| {
            if finding.raw().as_bytes() == TOKEN {
                planted += 1;
            }
            Ok(())
        })?;
        if summary.bytes != BUFFER_BYTES as u64 || summary.findings == 0 || planted == 0 {
            return Err(ScanError::Consumer);
        }
        Ok(summary)
    }
}

/// Observed primitive outputs. This is not an upload or an end-to-end receipt.
pub struct GzipStats {
    /// Actual compressed buffer, owned/wiped by the microbenchmark.
    pub gzip: Zeroizing<Vec<u8>>,
    /// SHA256 of the fixed uncompressed input.
    pub source_sha256: [u8; 32],
    /// SHA256 of the actual compressed output.
    pub gzip_sha256: [u8; 32],
}

/// Exercise production's pinned gzip and SHA256 libraries/settings over a buffer.
///
/// # Errors
/// Compression failures invalidate a sample, never become a zero count.
pub fn gzip_sha256(input: &[u8]) -> std::io::Result<GzipStats> {
    let mut gzip = Zeroizing::new(Vec::new());
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(&mut *gzip, Compression::fast());
    encoder.write_all(input)?;
    encoder.finish()?;
    Ok(GzipStats {
        source_sha256: Sha256::digest(input).into(),
        gzip_sha256: Sha256::digest(gzip.as_slice()).into(),
        gzip,
    })
}

#[cfg(test)]
mod tests {
    use super::{BUFFER_BYTES, ScannerFixture, buffer, gzip_sha256};
    use std::io::Read as _;

    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    #[test]
    fn native_fixed_buffer_checks_independent_plant() -> Result<(), Box<dyn std::error::Error>> {
        let scanner = ScannerFixture::new()?;
        let summary = scanner.scan()?;
        assert_eq!(summary.bytes, BUFFER_BYTES as u64);
        assert!(summary.findings > 0);
        Ok(())
    }

    #[test]
    fn primitive_outputs_round_trip_and_hash() -> Result<(), Box<dyn std::error::Error>> {
        let input = buffer();
        assert_eq!(input.len(), BUFFER_BYTES);
        let stats = gzip_sha256(&input)?;
        let again = gzip_sha256(&input)?;
        if stats.gzip.as_slice() != again.gzip.as_slice() {
            return Err(std::io::Error::other("non-deterministic primitive output").into());
        }
        let mut plain = Zeroizing::new(Vec::new());
        flate2::read::GzDecoder::new(stats.gzip.as_slice()).read_to_end(&mut plain)?;
        if plain.as_slice() != input.as_slice() {
            return Err(std::io::Error::other("primitive round-trip mismatch").into());
        }
        let plain_hash: [u8; 32] = Sha256::digest(plain.as_slice()).into();
        let gzip_hash: [u8; 32] = Sha256::digest(stats.gzip.as_slice()).into();
        assert_eq!(stats.source_sha256, plain_hash);
        assert_eq!(stats.gzip_sha256, gzip_hash);
        Ok(())
    }
}
