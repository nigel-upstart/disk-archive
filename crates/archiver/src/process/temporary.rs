//! Anonymous temporary descriptors: file closes before its exact-byte lifetime lease.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use disk_archive_metrics::{AppendLease, Counters};

use crate::Error;

pub(super) struct TemporaryFile {
    pub(super) file: File,
    lease: AppendLease,
}

impl TemporaryFile {
    pub(super) fn new(work_dir: &Path, counters: &Arc<Counters>) -> Result<Self, Error> {
        let lease = counters.append_temporary().map_err(|_| Error::Worker)?;
        let file = tempfile::tempfile_in(work_dir).map_err(|_| Error::Io)?;
        Ok(Self { file, lease })
    }
}
/// Named staging file: error cleanup is checked before releasing the lease.
pub(super) struct Replacement {
    file: Option<tempfile::NamedTempFile>,
    pub(super) lease: AppendLease,
}

impl Replacement {
    pub(super) fn new(parent: &Path, counters: &Arc<Counters>) -> Result<Self, Error> {
        let lease = counters.append_temporary().map_err(|_| Error::Worker)?;
        let file = tempfile::Builder::new()
            .prefix(".disk-archive-")
            .tempfile_in(parent)
            .map_err(|_| Error::Io)?;
        Ok(Self {
            file: Some(file),
            lease,
        })
    }

    pub(super) fn get(&self) -> Result<&tempfile::NamedTempFile, Error> {
        self.file.as_ref().ok_or(Error::Worker)
    }

    pub(super) fn write_copy(
        &mut self,
        source: &mut TemporaryFile,
        max: u64,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<(), Error> {
        let file = self.file.as_mut().ok_or(Error::Worker)?;
        super::copy(
            source,
            &mut self.lease.writer(file.as_file_mut()),
            max,
            cancel,
        )
    }

    // Only after a successful rename: the inode is now a source, not temporary storage.
    pub(super) fn promoted(mut self) -> Result<File, Error> {
        let file = self.file.take().ok_or(Error::Worker)?;
        let (file, path) = file.into_parts();
        let _ = path.keep().map_err(|_| Error::Io)?;
        Ok(file)
    }
}

impl Drop for Replacement {
    fn drop(&mut self) {
        if let Some(file) = self.file.take()
            && file.close().is_err()
        {
            self.lease.cleanup_failed();
        }
    }
}

impl Read for TemporaryFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}
impl Seek for TemporaryFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}
impl Write for TemporaryFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.lease.writer(&mut self.file).write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
