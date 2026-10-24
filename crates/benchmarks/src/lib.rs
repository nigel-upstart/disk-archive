//! Actual production-kernel benchmark entrypoints. No surrogate end-to-end claim.
use disk_archive_core::redaction::{FindingRaw, Limits, PlanBuilder, RedactError};
use zeroize::Zeroizing;

#[cfg(feature = "transport")]
mod wire;

/// Loopback-only HTTP observations; not a replacement S3 implementation.
#[cfg(feature = "transport")]
pub mod transport;

/// Native scanner and pinned gzip/hash primitive microbenchmarks (not pipeline I/O).
#[cfg(feature = "components")]
pub mod components;

/// Stable synthetic needle, never a real credential.
pub const NEEDLE: &str = "synthetic-benchmark-value-488";

/// Metadata-only counters returned by one actual production redaction operation.
pub struct RedactionStats {
    /// Bytes supplied to the production core.
    pub input_bytes: usize,
    /// Bytes emitted by the production core.
    pub output_bytes: usize,
    /// Actual replacement count.
    pub replacements: u64,
}

/// Make a bounded tool-result physical record with a deterministic synthetic plant.
///
/// # Errors
/// The requested size cannot contain the fixed JSON framing and plant.
pub fn record(size: usize) -> Result<Zeroizing<Vec<u8>>, RedactError> {
    let prefix = b"{\"tool_result\":\"";
    let suffix = b"\"}\n";
    let minimum = prefix.len() + suffix.len() + NEEDLE.len();
    if size < minimum || size > 1024 * 1024 {
        return Err(RedactError::Budget);
    }
    let mut input = Zeroizing::new(prefix.to_vec());
    input.resize(size - suffix.len() - NEEDLE.len(), b'x');
    input.extend_from_slice(NEEDLE.as_bytes());
    input.extend_from_slice(suffix);
    Ok(input)
}

/// Measure needle construction AND line rewrite through actual merged core code.
///
/// # Errors
/// Production resource/validation errors invalidate the benchmark, not a fast sample.
pub fn redact(input: &[u8]) -> Result<RedactionStats, RedactError> {
    let mut builder = PlanBuilder::new(Limits::default())?;
    builder.push(&FindingRaw {
        label: "fixture",
        raw: NEEDLE,
    })?;
    let plan = builder.finish([])?;
    let mut output = Zeroizing::new(Vec::new());
    let report = plan.redact(input, &mut *output)?;
    Ok(RedactionStats {
        input_bytes: input.len(),
        output_bytes: output.len(),
        replacements: report.replacements,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn actual_core_rewrites_practical_record() {
        for size in [1024, 100 * 1024, 1024 * 1024] {
            let input = super::record(size);
            assert!(input.is_ok());
            if let Ok(input) = input {
                let stats = super::redact(&input);
                assert!(
                    matches!(stats, Ok(sample) if sample.input_bytes == size && sample.output_bytes < size && sample.replacements == 1)
                );
            }
        }
    }
}
