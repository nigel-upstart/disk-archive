//! Descriptor-relative no-follow opens and cooperative namespace ownership.
//!
//! Directory advisory locks only exclude cooperating writers. `--quiescent` is an explicit
//! operator attestation that all writers obey these locks and descendants are quiescent.
//! No stat/unlink sequence is advertised as atomic against arbitrary hostile writers.

use std::fs::{File, Metadata};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use disk_archive_verified::{age::Timestamp, lifecycle::SourceIdentity};
use rustix::fs::{Mode, OFlags, open, openat};
use sha2::{Digest as _, Sha256};

use crate::Error;

/// Locked source root, held through pipeline drain and the final unlink.
pub struct Root {
    /// Normalized absolute source path, never logged.
    pub path: PathBuf,
    /// Whether discovery traverses descendants and selects only jsonl files.
    pub recursive_jsonl: bool,
    directory: File,
}

impl Root {
    /// Validate an absolute non-symlink root and optionally take its cooperative lock.
    ///
    /// # Errors
    /// Symlink components, missing directories or lock contention fail closed.
    pub fn open(path: &Path, recursive_jsonl: bool, lock: bool) -> Result<Self, Error> {
        let path = normalize_absolute(path)?;
        let directory = open_absolute_directory(&path)?;
        owned_directory(&directory)?;
        if lock {
            directory.try_lock().map_err(|_| Error::Locked)?;
        }
        Ok(Self {
            path,
            recursive_jsonl,
            directory,
        })
    }

    /// Open a regular single-link source through no-follow parent descriptors.
    ///
    /// # Errors
    /// Dot/absolute paths, symlinks, special files and hardlinks are rejected.
    pub fn source(&self, relative: &Path) -> Result<File, Error> {
        let (parent, name) = self.parent(relative)?;
        let fd = openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| Error::SourceChanged)?;
        let file = File::from(fd);
        regular(&file.metadata().map_err(|_| Error::Io)?)?;
        Ok(file)
    }

    /// Open the parent and return the final basename without following symlinks.
    ///
    /// # Errors
    /// Rejects non-normal path components and symlink directories.
    pub fn parent(&self, relative: &Path) -> Result<(File, std::ffi::OsString), Error> {
        let mut components = relative.components().peekable();
        let mut directory = self.directory.try_clone().map_err(|_| Error::Io)?;
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(Error::SourceChanged);
            };
            if components.peek().is_none() {
                return Ok((directory, name.to_owned()));
            }
            directory = File::from(
                openat(&directory, name, directory_flags(), Mode::empty())
                    .map_err(|_| Error::SourceChanged)?,
            );
            owned_directory(&directory)?;
        }
        Err(Error::SourceChanged)
    }

    /// Distinguish an actually absent basename from permissions, symlinks or missing parents.
    /// Used only to reconcile the already-unlinked/local-state commit gap, never to unlink.
    ///
    /// # Errors
    /// Unknown/changed parent namespaces and non-ENOENT failures are not evidence of absence.
    pub fn absent(&self, relative: &Path) -> Result<bool, Error> {
        let (parent, name) = self.parent(relative)?;
        match rustix::fs::statat(&parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(false),
            Err(rustix::io::Errno::NOENT) => Ok(true),
            Err(_) => Err(Error::SourceChanged),
        }
    }

    /// Flush directory entries after atomic rewrite/unlink.
    ///
    /// # Errors
    /// Fsync failure makes the operation's durability unknown.
    pub fn sync(&self) -> Result<(), Error> {
        self.directory.sync_all().map_err(|_| Error::Io)
    }
}

/// Validated source candidate with discovery metadata, not deletion authority.
pub struct Candidate {
    pub(crate) profile_id: u64,
    pub(crate) occupancy: Option<crate::pipeline::Occupancy>,
    /// Root lock/descriptor lifetime extends to final unlink.
    pub root: Arc<Root>,
    /// Validated relative path; may contain non-UTF8 Unix bytes.
    pub relative: PathBuf,
    /// No-follow discovery metadata used again before reading any contents.
    pub metadata: Metadata,
    /// Injective root-qualified canonical object key.
    pub key: String,
}

/// Compare stat identity including change time, never just restored modification time.
#[must_use]
pub fn same_stat(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && a.nlink() == b.nlink()
        && a.is_file()
        && b.is_file()
}

/// Hash an already-open bounded source, checking stat before/after and rewinding it.
///
/// # Errors
/// Oversize, changed metadata, invalid timestamps or read errors fail closed.
pub fn identity(file: &mut File, max_bytes: u64) -> Result<SourceIdentity, Error> {
    regular(&file.metadata().map_err(|_| Error::Io)?)?;
    measure(file, max_bytes)
}

/// Hash a private temporary regular file, including unlinked anonymous snapshots.
///
/// # Errors
/// Changes, size budgets or I/O failures fail closed.
pub fn content_hash(file: &mut File, max_bytes: u64) -> Result<[u8; 32], Error> {
    Ok(measure(file, max_bytes)?.sha256)
}

fn measure(file: &mut File, max_bytes: u64) -> Result<SourceIdentity, Error> {
    let before = file.metadata().map_err(|_| Error::Io)?;
    if !before.is_file() {
        return Err(Error::SourceChanged);
    }
    if before.len() > max_bytes {
        return Err(Error::Budget);
    }
    file.rewind().map_err(|_| Error::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = zeroize::Zeroizing::new(vec![0_u8; 65_536]);
    let mut size = 0_u64;
    loop {
        let n = file.read(buffer.as_mut_slice()).map_err(|_| Error::Io)?;
        if n == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(n).map_err(|_| Error::Budget)?)
            .ok_or(Error::Budget)?;
        if size > max_bytes {
            return Err(Error::Budget);
        }
        digest.update(buffer.get(..n).ok_or(Error::Budget)?);
    }
    let after = file.metadata().map_err(|_| Error::Io)?;
    if !same_stat(&before, &after) || size != before.len() {
        return Err(Error::SourceChanged);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| Error::Io)?;
    Ok(SourceIdentity {
        dev: before.dev(),
        ino: before.ino(),
        size,
        mtime: timestamp(before.mtime(), before.mtime_nsec())?,
        ctime: timestamp(before.ctime(), before.ctime_nsec())?,
        sha256: digest.finalize().into(),
    })
}

/// Parse Unix stat nanoseconds without lossy integer casts.
///
/// # Errors
/// Invalid negative/out-of-range nanoseconds fail closed.
pub fn timestamp(secs: i64, nanos: i64) -> Result<Timestamp, Error> {
    let nanos = u32::try_from(nanos).map_err(|_| Error::SourceChanged)?;
    let timestamp = Timestamp { secs, nanos };
    if !timestamp.is_valid() {
        return Err(Error::SourceChanged);
    }
    Ok(timestamp)
}

fn regular(metadata: &Metadata) -> Result<(), Error> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(Error::SourceChanged);
    }
    Ok(())
}

fn owned_directory(directory: &File) -> Result<(), Error> {
    let metadata = directory.metadata().map_err(|_| Error::Io)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(Error::Configuration);
    }
    Ok(())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY
}

/// Normalize redundant separators and literal current-directory components, never dot-names.
/// No filesystem canonicalization or symlink following occurs; parent traversal is rejected.
///
/// # Errors
/// Paths over 4096 bytes, relative paths and parent/prefix components fail closed.
pub fn normalize_absolute(path: &Path) -> Result<PathBuf, Error> {
    if path.as_os_str().len() > 4096 {
        return Err(Error::Budget);
    }
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::Configuration);
    }
    Ok(path.components().collect())
}

/// Open each absolute component independently; no symlink anywhere in the ancestry.
///
/// # Errors
/// Relative/dot/symlink paths and missing components are rejected.
pub fn open_absolute_directory(path: &Path) -> Result<File, Error> {
    if !path.is_absolute() {
        return Err(Error::Configuration);
    }
    let mut directory =
        File::from(open("/", directory_flags(), Mode::empty()).map_err(|_| Error::Io)?);
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(
                    openat(&directory, name, directory_flags(), Mode::empty())
                        .map_err(|_| Error::SourceChanged)?,
                );
            }
            _ => return Err(Error::Configuration),
        }
    }
    Ok(directory)
}
