//! State bookkeeping and source-bound deletion capabilities.
//! Evidence is supplied by the shell; this module performs no HEAD, hash, or stat.

use crate::age::Timestamp;

/// Durable file-processing status; never itself authority to unlink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    /// Discovered candidate.
    Discovered,
    /// Initial scan complete.
    Scanned,
    /// Redaction complete.
    Redacted,
    /// Post-redaction scan accepted.
    Verified,
    /// Remote verification complete.
    Uploaded,
    /// Local unlink succeeded.
    Deleted,
    /// Remaining findings prevent archival.
    Blocked,
    /// Retriable processing failure.
    Error,
    /// Candidate excluded by policy.
    Skipped,
}

/// Reject a non-monotonic or nonsensical bookkeeping transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionError;

/// Check a durable status update. Restarting Error requires fresh discovery checks.
/// Deleted is terminal; persisted Uploaded is NOT a replacement for fresh evidence.
///
/// # Errors
/// Rejects transitions outside the documented processing graph.
pub const fn transition(from: FileState, to: FileState) -> Result<FileState, TransitionError> {
    use FileState::{
        Blocked, Deleted, Discovered, Error, Redacted, Scanned, Skipped, Uploaded, Verified,
    };
    match (from, to) {
        (Discovered, Scanned | Skipped | Error)
        | (Scanned, Redacted | Blocked | Error)
        | (Redacted, Verified | Blocked | Error)
        | (Verified, Uploaded | Error)
        | (Uploaded, Deleted | Error)
        | (Error, Discovered) => Ok(to),
        _ => Err(TransitionError),
    }
}

/// Identity of an opened regular, non-symlink source snapshot.
/// The shell supplies a cryptographic hash, never a path-only identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIdentity {
    /// Filesystem device.
    pub dev: u64,
    /// Filesystem inode.
    pub ino: u64,
    /// Exact original content size.
    pub size: u64,
    /// Modification timestamp.
    pub mtime: Timestamp,
    /// Change timestamp; catches changes hidden by restored mtime.
    pub ctime: Timestamp,
    /// SHA-256 of original bytes after final redaction/scan.
    pub sha256: [u8; 32],
}

/// Trusted upload-side expectations computed from the exact staged snapshot.
pub struct UploadExpectation {
    /// Identity of original, post-redaction bytes.
    pub source: SourceIdentity,
    /// Canonical key returned by the key kernel.
    pub key: Vec<u8>,
    /// Gzip object length, not original length.
    pub compressed_size: u64,
    /// SHA-256 of uploaded gzip bytes.
    pub compressed_sha256: [u8; 32],
}

/// Evidence parsed from the selected bucket/key's HEAD and checksum response.
/// `ETag` is deliberately absent: it is not a content hash for multipart uploads.
pub struct RemoteEvidence {
    /// Exact returned/request-bound object key.
    pub key: Vec<u8>,
    /// Remote Content-Length.
    pub content_length: u64,
    /// Remote SHA-256 of compressed bytes, never a multipart composite checksum.
    pub gz_sha256: [u8; 32],
    /// Original size metadata parsed strictly as an integer.
    pub orig_size: u64,
    /// Original SHA-256 metadata decoded strictly to 32 bytes.
    pub orig_sha256: [u8; 32],
    /// HEAD confirms SSE AES256.
    pub sse_aes256: bool,
}

/// An evidence mismatch always denies deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadError {
    /// Metadata, key, length, checksum or encryption mismatch.
    RemoteMismatch,
    /// Source identity changed, or has malformed timestamps.
    SourceMismatch,
}

/// Non-cloneable source-bound capability; only `verify_upload` constructs it.
/// Not serializable: database rows cannot mint authority after a restart.
pub struct VerifiedUpload {
    source: SourceIdentity,
}

/// Compare all expected evidence before granting upload authority.
/// The shell binds both structures to one configured bucket and staged snapshot.
///
/// # Errors
/// Rejects malformed timestamps or any missing/mismatching remote evidence.
pub fn verify_upload(
    expected: &UploadExpectation,
    remote: &RemoteEvidence,
) -> Result<VerifiedUpload, UploadError> {
    if !expected.source.mtime.is_valid() || !expected.source.ctime.is_valid() {
        return Err(UploadError::SourceMismatch);
    }
    if expected.key.is_empty()
        || expected.key != remote.key
        || expected.compressed_size != remote.content_length
        || expected.compressed_sha256 != remote.gz_sha256
        || expected.source.size != remote.orig_size
        || expected.source.sha256 != remote.orig_sha256
        || !remote.sse_aes256
    {
        return Err(UploadError::RemoteMismatch);
    }
    Ok(VerifiedUpload {
        source: expected.source,
    })
}

/// Single-use unlink-stage input, not a filesystem operation.
/// The shell must consume it without releasing the exclusive source/path guard.
pub struct DeletePermit {
    source: SourceIdentity,
}

impl DeletePermit {
    /// Bound source identity for the final platform-specific unlink adapter.
    #[must_use]
    pub const fn source(&self) -> &SourceIdentity {
        &self.source
    }
}

/// Consume verified authority after a fresh no-follow stat + content hash.
///
/// # Errors
/// A replacement inode, content mutation, changed time or size denies deletion.
// LINT-JUSTIFICATION: Consuming the non-cloneable upload token prevents reuse of this authority.
#[allow(clippy::needless_pass_by_value)]
pub fn authorize_delete(
    upload: VerifiedUpload,
    current: &SourceIdentity,
) -> Result<DeletePermit, UploadError> {
    if upload.source != *current {
        return Err(UploadError::SourceMismatch);
    }
    Ok(DeletePermit {
        source: upload.source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> SourceIdentity {
        SourceIdentity {
            dev: 1,
            ino: 2,
            size: 3,
            mtime: Timestamp { secs: 4, nanos: 0 },
            ctime: Timestamp { secs: 5, nanos: 0 },
            sha256: [6; 32],
        }
    }

    #[test]
    fn matching_evidence_and_mutation() -> Result<(), UploadError> {
        let source = identity();
        let expected = UploadExpectation {
            source,
            key: b"prefix/v1/f.gz".to_vec(),
            compressed_size: 23,
            compressed_sha256: [7; 32],
        };
        let mut remote = RemoteEvidence {
            key: expected.key.clone(),
            content_length: 23,
            gz_sha256: [7; 32],
            orig_size: 3,
            orig_sha256: [6; 32],
            sse_aes256: true,
        };
        let permit = authorize_delete(verify_upload(&expected, &remote)?, &source)?;
        assert_eq!(permit.source(), &source);
        let mut changed = source;
        changed.ino += 1;
        assert!(authorize_delete(verify_upload(&expected, &remote)?, &changed).is_err());
        changed = source;
        changed.sha256 = [8; 32];
        assert!(authorize_delete(verify_upload(&expected, &remote)?, &changed).is_err());
        remote.sse_aes256 = false;
        assert!(verify_upload(&expected, &remote).is_err());
        remote.sse_aes256 = true;
        remote.content_length += 1;
        assert!(verify_upload(&expected, &remote).is_err());
        Ok(())
    }

    #[test]
    fn state_is_not_authority() {
        assert_eq!(
            transition(FileState::Verified, FileState::Deleted),
            Err(TransitionError)
        );
        assert_eq!(
            transition(FileState::Deleted, FileState::Discovered),
            Err(TransitionError)
        );
        assert_eq!(
            transition(FileState::Error, FileState::Discovered),
            Ok(FileState::Discovered)
        );
    }
}
