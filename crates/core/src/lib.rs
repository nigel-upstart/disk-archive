//! I/O-independent building blocks for the archiver.
//!
//! This skeleton intentionally does not scan, upload, or delete files.

/// Identifies the on-disk archive format independently of the package version.
#[must_use]
pub const fn format_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn format_version_is_stable() {
        assert_eq!(super::format_version(), 1);
    }
}
