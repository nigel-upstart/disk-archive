//! Private work namespace and process lock. Never constructed in a dry run.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, mkdirat, openat};

use crate::{Error, filesystem::open_absolute_directory};

/// Exclusive work-directory ownership retained through state/store drain.
pub struct Work {
    /// Validated private work directory.
    pub path: PathBuf,
    _lock: File,
    _directory: File,
}

impl Work {
    /// Create only the final private directory, then acquire an exclusive persistent lock.
    /// Existing directories must be private, owned by this user, and empty or marked as
    /// Rust-owned. Unknown/legacy state directories are rejected before opening their database.
    ///
    /// # Errors
    /// Invalid paths, insecure permissions, symlinks or contention fail closed.
    pub fn acquire(path: &Path) -> Result<Self, Error> {
        let normalized = crate::filesystem::normalize_absolute(path)?;
        let path = normalized.as_path();
        let parent = path.parent().ok_or(Error::Configuration)?;
        let name = path.file_name().ok_or(Error::Configuration)?;
        let parent = open_absolute_directory(parent)?;
        match mkdirat(&parent, name, Mode::from_raw_mode(0o700)) {
            Ok(()) => parent.sync_all().map_err(|_| Error::Io)?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(Error::Io),
        }
        let directory = open_absolute_directory(path)?;
        let metadata = directory.metadata().map_err(|_| Error::Io)?;
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(Error::Configuration);
        }
        ensure_format(path, &directory)?;
        let lock = File::from(
            openat(
                &directory,
                "run.lock",
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| Error::Io)?,
        );
        let meta = lock.metadata().map_err(|_| Error::Io)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != metadata.uid()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(Error::Configuration);
        }
        lock.try_lock().map_err(|_| Error::Locked)?;
        directory.sync_all().map_err(|_| Error::Io)?;
        // SQLite opens auxiliary names itself: all are confined by private cooperative ownership.
        for name in ["state.sqlite", "state.sqlite-wal", "state.sqlite-shm"] {
            match std::fs::symlink_metadata(path.join(name)) {
                Ok(meta)
                    if !meta.is_file() || meta.nlink() != 1 || meta.uid() != metadata.uid() =>
                {
                    return Err(Error::SourceChanged);
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Io),
            }
        }
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
            _directory: directory,
        })
    }
}

fn ensure_format(path: &Path, directory: &File) -> Result<(), Error> {
    const HEADER: &[u8] = b"disk-archive-rust-state-v1\n";
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    match openat(directory, "format", flags, Mode::empty()) {
        Ok(fd) => {
            let file = File::from(fd);
            let metadata = file.metadata().map_err(|_| Error::Io)?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.len()
                    != u64::try_from(HEADER.len()).map_err(|_| Error::Configuration)?
            {
                return Err(Error::Configuration);
            }
            let mut bytes = Vec::new();
            file.take(64)
                .read_to_end(&mut bytes)
                .map_err(|_| Error::Io)?;
            if bytes != HEADER {
                return Err(Error::Configuration);
            }
        }
        Err(rustix::io::Errno::NOENT) => {
            if std::fs::read_dir(path)
                .map_err(|_| Error::Io)?
                .next()
                .is_some()
            {
                return Err(Error::Configuration);
            }
            let mut file = File::from(
                openat(
                    directory,
                    "format",
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(|_| Error::Configuration)?,
            );
            file.write_all(HEADER).map_err(|_| Error::Io)?;
            file.sync_all().map_err(|_| Error::Io)?;
            directory.sync_all().map_err(|_| Error::Io)?;
        }
        Err(_) => return Err(Error::Configuration),
    }
    Ok(())
}
