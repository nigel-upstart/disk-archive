//! The sole source unlink adapter. Requires genuine non-serializable upload authority.
//!
//! The root directory lock remains held through fresh source hashing, capability consumption,
//! descriptor-relative unlink and parent fsync. This is safe only under the documented
//! cooperative/quiescent ownership protocol, NOT an atomic compare-and-unlink primitive.

use disk_archive_verified::lifecycle::{VerifiedUpload, authorize_delete};
use tokio_util::sync::CancellationToken;

use crate::{
    Error,
    filesystem::{self, Candidate},
};

/// Consume real kernel authority after revalidating the exact current source.
///
/// # Errors
/// Any source mutation, symlink, cancellation or unlink/fsync failure denies success.
pub fn delete(
    candidate: &Candidate,
    upload: VerifiedUpload,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    let mut source = candidate.root.source(&candidate.relative)?;
    let current = filesystem::identity(&mut source, max_bytes)?;
    let permit = authorize_delete(upload, &current).map_err(|_| Error::SourceChanged)?;
    let (parent, name) = candidate.root.parent(&candidate.relative)?;
    let path_source = candidate.root.source(&candidate.relative)?;
    if !filesystem::same_stat(
        &source.metadata().map_err(|_| Error::Io)?,
        &path_source.metadata().map_err(|_| Error::Io)?,
    ) || permit.source() != &current
    {
        return Err(Error::SourceChanged);
    }
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    rustix::fs::unlinkat(&parent, name, rustix::fs::AtFlags::empty()).map_err(|_| Error::Io)?;
    parent.sync_all().map_err(|_| Error::Io)
}
