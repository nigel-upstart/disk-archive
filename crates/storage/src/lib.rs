//! Source-bound archive preparation, S3 transport and independently checked upload evidence.
//!
//! Persist [`ExpectedUpload`] before starting a network upload. Persisted state alone never
//! grants deletion authority: restart requires fresh remote verification, and the shell must
//! still revalidate source identity under exclusive namespace ownership before unlinking.

pub mod blocking;
pub mod evidence;
pub mod prepare;
pub mod sdk;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use sdk::{ClientOptions, SdkStore, StoreOptions};

use std::future::Future;
use std::pin::Pin;

pub use blocking::BlockingPool;
pub use disk_archive_verified::lifecycle::{SourceIdentity, VerifiedUpload};
pub use evidence::{ExpectedUpload, HeadEvidence, Integrity, PartDigest};
pub use prepare::{ChecksumPolicy, PrepareOptions, PreparedUpload, UploadPreparer};
pub use tokio_util::sync::CancellationToken;

/// Object-safe asynchronous result, without a dependency on an async-trait macro.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// Value-free failures; never retain SDK errors, paths, credentials or input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Invalid settings, persisted schema or checksum geometry.
    Configuration,
    /// Opened source metadata, size or content hash changed.
    SourceChanged,
    /// Global payload, CPU or spool budget cannot satisfy the request.
    Budget,
    /// Source/spool I/O failed.
    Io,
    /// Cancellation requested; no upload/delete capability is returned.
    Cancelled,
    /// SDK transport/service failure after configured retries.
    Transport,
    /// Checksum-enabled HEAD returned a genuine service `NotFound`, not a transport failure.
    NotFound,
    /// Required remote checksum/metadata/encryption/version evidence mismatched.
    Integrity,
    /// Multipart abort failed; caller must retain local source and reconcile.
    Abort,
    /// A background preparation/upload task failed; partial results are invalid.
    Worker,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StoreError {}

/// Storage seam for the pipeline, SDK adapter and local HTTP integration tests.
/// Implementations bind all operations to one configured bucket. No method deletes a source.
pub trait ObjectStore: Send + Sync {
    /// Upload prepared immutable bytes and verify checksum-enabled HEAD before minting a token.
    /// Caller MUST durably persist `upload.expected()` before invoking this method.
    fn put_object_verified<'a>(
        &'a self,
        upload: &'a PreparedUpload,
        cancel: CancellationToken,
    ) -> StoreFuture<'a, VerifiedUpload>;

    /// Restart/commit-unknown reconciliation: fresh remote evidence, never a persisted token.
    fn verify_existing<'a>(
        &'a self,
        expected: &'a ExpectedUpload,
        cancel: CancellationToken,
    ) -> StoreFuture<'a, VerifiedUpload>;

    /// Inspect one exact key/version with checksum mode enabled.
    fn head<'a>(
        &'a self,
        key: &'a str,
        version_id: Option<&'a str>,
        cancel: CancellationToken,
    ) -> StoreFuture<'a, HeadEvidence>;

    /// Upload a bounded, non-secret state manifest with AES256 and integrity checks.
    fn put_manifest<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
        cancel: CancellationToken,
    ) -> StoreFuture<'a, ()>;

    /// Wait for shielded upload/cancellation/abort cleanup before releasing run ownership.
    fn drain(&self) -> StoreFuture<'_, ()>;
}
