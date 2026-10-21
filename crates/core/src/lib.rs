//! Synchronous, bounded archiver configuration and redaction.
//!
//! This crate never opens output paths, mutates input files, or grants upload/delete authority.
//! Successful redaction is NOT verification: the caller must rescan the complete output.

pub mod config;
pub mod redaction;

/// Production key and age kernels; no duplicate implementation in core.
pub use disk_archive_verified::{age, key};

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
