//! Deterministic gzip/hash preparation from an already opened, identity-bound source.

use std::fs::{File, Metadata};
use std::io::{Read as _, Seek as _, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use disk_archive_verified::age::Timestamp;
use flate2::{Compression, GzBuilder};
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::blocking::BlockingPool;
use crate::{CancellationToken, ExpectedUpload, Integrity, PartDigest, SourceIdentity, StoreError};

const DISK_UNIT: u64 = 65_536;
static CRC64: crc::Crc<u64> = crc::Crc::<u64>::new(&crc::CRC_64_NVME);

/// Upload integrity policy selected before preparation; no automatic downgrade on checksum errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumPolicy {
    /// Full-object CRC64NVME, supported for single PUT and multipart.
    Crc64Nvme,
    /// Full SHA256 for single PUT; ordered SHA256 COMPOSITE for multipart.
    Sha256,
}

/// Explicit preparation limits. Work directory must already exist and be privately owned.
#[derive(Clone)]
pub struct PrepareOptions {
    /// Configured destination, never defaulted.
    pub bucket: String,
    /// G-owned exclusive work directory; no `create_dir` here.
    pub work_dir: PathBuf,
    /// Global maximum reserved spool bytes, shared by clones of the preparer.
    pub disk_budget: u64,
    /// Maximum gzip spool bytes for one file.
    pub max_spool_bytes: u64,
    /// Conservative single-PUT threshold, strictly below 5,000,000,000 bytes.
    pub multipart_threshold: u64,
    /// Target part geometry, minimum 5 MiB. Object limit prevents the 10000-part adjustment.
    pub part_size: u64,
    /// Independent actual checksum policy.
    pub checksum: ChecksumPolicy,
}

impl PrepareOptions {
    /// Validate sizes without constructing credentials, directories or temporary files.
    ///
    /// # Errors
    /// Invalid/unsafe settings are rejected.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.bucket.is_empty()
            || self.bucket.len() > 63
            || self.bucket.chars().any(char::is_control)
            || !self.work_dir.is_absolute()
            || self.disk_budget < DISK_UNIT
            || self.disk_budget / DISK_UNIT > u64::from(u32::MAX)
            || self.max_spool_bytes == 0
            || self.max_spool_bytes > self.disk_budget
            || !(5_242_880..=5_368_709_120).contains(&self.part_size)
            || !(5_242_880..5_000_000_000).contains(&self.multipart_threshold)
            || self.max_spool_bytes
                > self
                    .part_size
                    .checked_mul(10_000)
                    .ok_or(StoreError::Configuration)?
        {
            return Err(StoreError::Configuration);
        }
        Ok(())
    }
}

/// Global bounded preparation resources; clone this instance instead of recreating per file.
#[derive(Clone)]
pub struct UploadPreparer {
    options: PrepareOptions,
    disk: Arc<Semaphore>,
    cpu: BlockingPool,
}

impl UploadPreparer {
    /// Create shared admission gates without any filesystem writes or credential initialization.
    ///
    /// # Errors
    /// Invalid limits fail closed.
    pub fn new(options: PrepareOptions, cpu: BlockingPool) -> Result<Self, StoreError> {
        options.validate()?;
        let permits = usize::try_from(options.disk_budget / DISK_UNIT)
            .map_err(|_| StoreError::Configuration)?;
        Ok(Self {
            options,
            disk: Arc::new(Semaphore::new(permits)),
            cpu,
        })
    }

    /// Prepare the exact already-open regular source. G must exclude writers and provide identity
    /// after successful redaction/rescan. This method seeks the consumed descriptor to byte zero.
    /// Caller persists `PreparedUpload::expected()` before starting the network operation.
    ///
    /// # Errors
    /// Source changes, cancellation, quota, permission or I/O failure produces no prepared upload.
    pub async fn prepare(
        &self,
        source: File,
        identity: SourceIdentity,
        key: String,
        cancel: CancellationToken,
    ) -> Result<PreparedUpload, StoreError> {
        if !crate::evidence::valid_key(&key) {
            return Err(StoreError::Configuration);
        }
        // A conservative reservation estimate is only admission policy: the writer still
        // enforces it before every write, so compression exceeding it fails, never overspools.
        let cap = identity
            .size
            .checked_add(identity.size / 16)
            .and_then(|n| n.checked_add(1024))
            .ok_or(StoreError::Budget)?
            .min(self.options.max_spool_bytes);
        let units = cap.div_ceil(DISK_UNIT);
        if units > self.options.disk_budget / DISK_UNIT {
            return Err(StoreError::Budget);
        }
        let permit = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(StoreError::Cancelled),
            permit = self.disk.clone().acquire_many_owned(u32::try_from(units).map_err(|_| StoreError::Budget)?) => permit.map_err(|_| StoreError::Budget)?,
        };
        let options = self.options.clone();
        self.cpu
            .run(cancel, move |child| {
                prepare_blocking(source, identity, key, &options, cap, permit, &child)
            })
            .await
    }

    /// Current reserved spool quota (rounded up), not allocated RAM or filesystem free space.
    #[must_use]
    pub fn reserved_disk_bytes(&self) -> u64 {
        self.options.disk_budget / DISK_UNIT * DISK_UNIT
            - u64::try_from(self.disk.available_permits()).unwrap_or(0) * DISK_UNIT
    }
}

/// Immutable-by-contract prepared snapshot; owns private spool and disk reservation until cleanup.
/// No Debug/serialization of the path or file contents. The serializable expectation is separate.
pub struct PreparedUpload {
    pub(crate) multipart_threshold: u64,
    pub(crate) part_size: u64,
    pub(crate) spool: Arc<Spool>,
    expected: ExpectedUpload,
}

pub(crate) struct Spool {
    file: NamedTempFile,
    _disk: OwnedSemaphorePermit,
}

impl PreparedUpload {
    /// Durable expected evidence to persist before any network call.
    #[must_use]
    pub const fn expected(&self) -> &ExpectedUpload {
        &self.expected
    }

    pub(crate) fn path(&self) -> &Path {
        self.spool.file.path()
    }
}

fn prepare_blocking(
    mut source: File,
    identity: SourceIdentity,
    key: String,
    options: &PrepareOptions,
    cap: u64,
    permit: OwnedSemaphorePermit,
    cancel: &CancellationToken,
) -> Result<PreparedUpload, StoreError> {
    let before = source.metadata().map_err(|_| StoreError::Io)?;
    if !before.is_file() || metadata_identity(&before, identity.sha256)? != identity {
        return Err(StoreError::SourceChanged);
    }
    let directory = std::fs::symlink_metadata(&options.work_dir).map_err(|_| StoreError::Io)?;
    if !directory.is_dir() || directory.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::Configuration);
    }
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| StoreError::Io)?;
    let spool = tempfile::Builder::new()
        .prefix("archive-")
        .suffix(".gz")
        .tempfile_in(&options.work_dir)
        .map_err(|_| StoreError::Io)?;
    let mut writer = HashWriter::new(
        spool.as_file().try_clone().map_err(|_| StoreError::Io)?,
        cap,
        options.part_size,
    )?;
    let encoded = encode(&mut source, &mut writer, identity.size, cancel);
    if writer.over_budget {
        return Err(StoreError::Budget);
    }
    let digest = encoded?;
    if digest != identity.sha256
        || metadata_identity(&source.metadata().map_err(|_| StoreError::Io)?, digest)? != identity
    {
        return Err(StoreError::SourceChanged);
    }
    writer.file.sync_all().map_err(|_| StoreError::Io)?;
    let gzip_size = writer.total;
    let gzip_sha256: [u8; 32] = writer.sha.finalize().into();
    if writer.part_bytes != 0 {
        writer.parts.push(PartDigest {
            size: writer.part_bytes,
            sha256: writer.part_sha.finalize().into(),
        });
    }
    let integrity = match options.checksum {
        ChecksumPolicy::Crc64Nvme => Integrity::Crc64Nvme {
            value: writer.crc.finalize().to_be_bytes(),
        },
        ChecksumPolicy::Sha256 if gzip_size < options.multipart_threshold => {
            Integrity::Sha256 { value: gzip_sha256 }
        }
        ChecksumPolicy::Sha256 => Integrity::Sha256Composite {
            part_size: options.part_size,
            parts: writer.parts,
        },
    };
    if cancel.is_cancelled() {
        return Err(StoreError::Cancelled);
    }
    let expected = ExpectedUpload {
        schema_version: 1,
        bucket: options.bucket.clone(),
        key,
        source: identity,
        gzip_size,
        gzip_sha256,
        integrity,
        version_id: None,
        etag: None,
    };
    expected.validate()?;
    Ok(PreparedUpload {
        multipart_threshold: options.multipart_threshold,
        part_size: options.part_size,
        spool: Arc::new(Spool {
            file: spool,
            _disk: permit,
        }),
        expected,
    })
}

fn encode(
    source: &mut File,
    writer: &mut HashWriter,
    size: u64,
    cancel: &CancellationToken,
) -> Result<[u8; 32], StoreError> {
    let mut input = Zeroizing::new(vec![0; 65_536]);
    let mut original = Sha256::new();
    let mut total = 0_u64;
    let mut encoder = GzBuilder::new().mtime(0).write(writer, Compression::fast());
    loop {
        if cancel.is_cancelled() {
            return Err(StoreError::Cancelled);
        }
        let n = source.read(&mut input).map_err(|_| StoreError::Io)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(n).map_err(|_| StoreError::Budget)?)
            .ok_or(StoreError::Budget)?;
        if total > size {
            return Err(StoreError::SourceChanged);
        }
        let chunk = input.get(..n).ok_or(StoreError::Io)?;
        original.update(chunk);
        encoder.write_all(chunk).map_err(|_| StoreError::Io)?;
    }
    if total != size {
        return Err(StoreError::SourceChanged);
    }
    encoder.finish().map_err(|_| StoreError::Io)?;
    Ok(original.finalize().into())
}

/// Stat-to-kernel identity conversion for an already-open descriptor and independently computed hash.
/// Does not read or reopen any path; G must supply the actual post-scan digest.
///
/// # Errors
/// Non-regular files and malformed timestamps fail closed.
pub fn metadata_identity(
    metadata: &Metadata,
    sha256: [u8; 32],
) -> Result<SourceIdentity, StoreError> {
    if !metadata.is_file() {
        return Err(StoreError::SourceChanged);
    }
    Ok(SourceIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.len(),
        mtime: Timestamp {
            secs: metadata.mtime(),
            nanos: u32::try_from(metadata.mtime_nsec()).map_err(|_| StoreError::SourceChanged)?,
        },
        ctime: Timestamp {
            secs: metadata.ctime(),
            nanos: u32::try_from(metadata.ctime_nsec()).map_err(|_| StoreError::SourceChanged)?,
        },
        sha256,
    })
}

struct HashWriter {
    file: File,
    cap: u64,
    total: u64,
    sha: Sha256,
    crc: crc::Digest<'static, u64>,
    part_size: usize,
    part_bytes: u64,
    part_sha: Sha256,
    parts: Vec<PartDigest>,
    over_budget: bool,
}

impl HashWriter {
    fn new(file: File, cap: u64, part_size: u64) -> Result<Self, StoreError> {
        Ok(Self {
            file,
            cap,
            total: 0,
            sha: Sha256::new(),
            crc: CRC64.digest(),
            part_size: usize::try_from(part_size).map_err(|_| StoreError::Configuration)?,
            part_bytes: 0,
            part_sha: Sha256::new(),
            parts: Vec::new(),
            over_budget: false,
        })
    }
}

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let size = u64::try_from(bytes.len()).map_err(std::io::Error::other)?;
        if self.total.checked_add(size).is_none_or(|n| n > self.cap) {
            self.over_budget = true;
            return Err(std::io::Error::other("spool budget"));
        }
        let n = self.file.write(bytes)?;
        let bytes = bytes
            .get(..n)
            .ok_or_else(|| std::io::Error::other("spool range"))?;
        self.sha.update(bytes);
        self.crc.update(bytes);
        self.total += u64::try_from(n).map_err(std::io::Error::other)?;
        let mut rest = bytes;
        while !rest.is_empty() {
            let available = self
                .part_size
                .checked_sub(usize::try_from(self.part_bytes).map_err(std::io::Error::other)?)
                .ok_or_else(|| std::io::Error::other("part range"))?;
            let len = available.min(rest.len());
            let chunk = rest
                .get(..len)
                .ok_or_else(|| std::io::Error::other("part range"))?;
            self.part_sha.update(chunk);
            self.part_bytes += u64::try_from(len).map_err(std::io::Error::other)?;
            rest = rest
                .get(len..)
                .ok_or_else(|| std::io::Error::other("part range"))?;
            if usize::try_from(self.part_bytes).map_err(std::io::Error::other)? == self.part_size {
                self.parts.push(PartDigest {
                    size: self.part_bytes,
                    sha256: std::mem::take(&mut self.part_sha).finalize().into(),
                });
                self.part_bytes = 0;
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
