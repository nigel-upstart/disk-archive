//! Stable snapshot -> bounded core rewrite -> whole-output native scan -> atomic replacement.

use std::collections::BTreeMap;
use std::fs::{File, FileTimes};
use std::io::{Read, Seek as _, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;

use disk_archive_metrics::Counters;

mod temporary;
use temporary::{Replacement, TemporaryFile};

use crate::scanner::{self, ScanEngine};
use disk_archive_core::{
    config::Config,
    redaction::{Limits, PlanBuilder},
};
use disk_archive_verified::{lifecycle::SourceIdentity, needles::FindingRaw};
use tokio_util::sync::CancellationToken;

use crate::{
    Error, discovery,
    filesystem::{self, Candidate},
    profile::{self, Stage},
};

/// Verified local input to compression; source descriptor and evidence bind the same inode.
pub struct Accepted {
    /// Root ownership extends through upload and unlink.
    pub candidate: Candidate,
    /// Exact post-redaction source descriptor, rewound for preparation.
    pub source: File,
    /// Fresh hash/stat binding of source after successful whole-output scanning.
    pub identity: SourceIdentity,
    /// Value-free per-rule telemetry from the initial scan.
    pub detectors: BTreeMap<String, u64>,
}

/// Execute the CPU/filesystem stage inside the bounded blocking wrapper only.
/// Intermediate files are private, bounded, and never valid on scan/write errors.
///
/// # Errors
/// Changes, budgets, cancellation and any incomplete/remaining scan fail closed.
pub fn process(
    candidate: Candidate,
    scanner: &dyn ScanEngine,
    config: &Config,
    max_bytes: u64,
    cancel: &CancellationToken,
    counters: &Arc<Counters>,
) -> Result<Accepted, Error> {
    let limits = config.redaction;
    let work_dir = config.work_dir.as_deref().ok_or(Error::Configuration)?;
    let min_age = config.min_age_secs;
    check_cancel(cancel)?;
    let mut source = candidate.root.source(&candidate.relative)?;
    let original_meta = source.metadata().map_err(|_| Error::Io)?;
    if !filesystem::same_stat(&candidate.metadata, &original_meta)
        || !discovery::eligible(&original_meta, min_age)?
    {
        return Err(Error::SourceChanged);
    }
    let original = filesystem::identity(&mut source, max_bytes)?;
    let mut snapshot = TemporaryFile::new(work_dir, counters)?;
    copy(&mut source, &mut snapshot, max_bytes, cancel)?;
    if filesystem::identity(&mut source, max_bytes)? != original {
        return Err(Error::SourceChanged);
    }
    if filesystem::content_hash(&mut snapshot.file, max_bytes)? != original.sha256 {
        return Err(Error::SourceChanged);
    }
    snapshot.rewind().map_err(|_| Error::Io)?;
    let mut builder = PlanBuilder::new(limits).map_err(|_| Error::Blocked)?;
    let mut detectors = BTreeMap::<String, u64>::new();
    profile::work(Stage::Scan, candidate.profile_id, || {
        scanner::scan(scanner, Cancellable(&mut snapshot, cancel), |finding| {
            builder
                .push(&FindingRaw {
                    label: finding.label,
                    raw: finding.raw,
                })
                .map_err(|_| Error::Budget)?;
            let count = detectors.entry(finding.rule_id.to_owned()).or_default();
            *count = count.checked_add(1).ok_or(Error::Budget)?;
            Ok(())
        })
    })
    .map_err(|_| Error::Blocked)?;
    let plan = builder.finish([]).map_err(|_| Error::Blocked)?;
    snapshot.rewind().map_err(|_| Error::Io)?;
    let mut output = TemporaryFile::new(work_dir, counters)?;
    profile::work(Stage::Redact, candidate.profile_id, || {
        plan.redact(
            Cancellable(&mut snapshot, cancel),
            BoundedOutput::new(&mut output, max_bytes),
        )
    })
    .map_err(|_| Error::Blocked)?;
    drop(plan);
    drop(snapshot);
    let mut output = profile::work(Stage::Verify, candidate.profile_id, || {
        verify_output(
            output, scanner, limits, work_dir, max_bytes, cancel, counters,
        )
    })?;
    check_cancel(cancel)?;
    // Do not change a source already represented by durable resume evidence when bytes agree.
    let final_hash = filesystem::content_hash(&mut output.file, max_bytes)?;
    let mut source = if final_hash == original.sha256 {
        source
    } else {
        replace(
            &candidate,
            &mut source,
            SourceVersion {
                identity: original,
                metadata: &original_meta,
            },
            &mut output,
            max_bytes,
            cancel,
            counters,
        )?
    };
    let identity = filesystem::identity(&mut source, max_bytes)?;
    if identity.sha256 != final_hash {
        return Err(Error::SourceChanged);
    }
    let path_source = candidate.root.source(&candidate.relative)?;
    if !filesystem::same_stat(
        &source.metadata().map_err(|_| Error::Io)?,
        &path_source.metadata().map_err(|_| Error::Io)?,
    ) {
        return Err(Error::SourceChanged);
    }
    Ok(Accepted {
        candidate,
        source,
        identity,
        detectors,
    })
}

fn verify_output(
    mut output: TemporaryFile,
    scanner: &dyn ScanEngine,
    limits: Limits,
    work_dir: &Path,
    max_bytes: u64,
    cancel: &CancellationToken,
    counters: &Arc<Counters>,
) -> Result<TemporaryFile, Error> {
    output.rewind().map_err(|_| Error::Io)?;
    let mut drops = Vec::new();
    scanner::scan(scanner, Cancellable(&mut output, cancel), |finding| {
        if drops.len() >= limits.max_drop_lines {
            return Err(Error::Budget);
        }
        drops.push(finding.line);
        Ok(())
    })?;
    if drops.is_empty() {
        return Ok(output);
    }
    output.rewind().map_err(|_| Error::Io)?;
    let mut fallback = TemporaryFile::new(work_dir, counters)?;
    let plan = PlanBuilder::new(limits)
        .map_err(|_| Error::Blocked)?
        .finish(drops)
        .map_err(|_| Error::Blocked)?;
    plan.redact(
        Cancellable(&mut output, cancel),
        BoundedOutput::new(&mut fallback, max_bytes),
    )
    .map_err(|_| Error::Blocked)?;
    fallback.rewind().map_err(|_| Error::Io)?;
    let summary = scanner::scan(scanner, Cancellable(&mut fallback, cancel), |_| Ok(()))?;
    if summary.findings != 0 {
        return Err(Error::Blocked);
    }
    Ok(fallback)
}

#[derive(Clone, Copy)]
struct SourceVersion<'a> {
    identity: SourceIdentity,
    metadata: &'a std::fs::Metadata,
}

fn replace(
    candidate: &Candidate,
    source: &mut File,
    original: SourceVersion<'_>,
    output: &mut TemporaryFile,
    max_bytes: u64,
    cancel: &CancellationToken,
    counters: &Arc<Counters>,
) -> Result<File, Error> {
    let parent_path = candidate
        .root
        .path
        .join(&candidate.relative)
        .parent()
        .ok_or(Error::SourceChanged)?
        .to_owned();
    let (parent, name) = candidate.root.parent(&candidate.relative)?;
    let mut replacement = Replacement::new(&parent_path, counters)?;
    replacement.write_copy(output, max_bytes, cancel)?;
    let meta = original.metadata;
    replacement
        .get()?
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(
            meta.permissions().mode() & 0o777,
        ))
        .map_err(|_| Error::Io)?;
    replacement
        .get()?
        .as_file()
        .set_times(
            FileTimes::new()
                .set_accessed(meta.accessed().map_err(|_| Error::Io)?)
                .set_modified(meta.modified().map_err(|_| Error::Io)?),
        )
        .map_err(|_| Error::Io)?;
    replacement
        .get()?
        .as_file()
        .sync_all()
        .map_err(|_| Error::Io)?;
    check_cancel(cancel)?;
    let mut current = candidate.root.source(&candidate.relative)?;
    if filesystem::identity(&mut current, max_bytes)? != original.identity
        || filesystem::identity(source, max_bytes)? != original.identity
    {
        return Err(Error::SourceChanged);
    }
    let temporary_name = replacement.get()?.path().file_name().ok_or(Error::Io)?;
    rustix::fs::renameat(&parent, temporary_name, &parent, &name).map_err(|_| Error::Io)?;
    // Disarm path cleanup: a recreated temp pathname must not be accidentally removed later.
    let file = replacement.promoted()?;
    parent.sync_all().map_err(|_| Error::Io)?;
    Ok(file)
}

fn copy(
    source: &mut (impl Read + std::io::Seek),
    destination: &mut impl Write,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    source.rewind().map_err(|_| Error::Io)?;
    let mut buffer = zeroize::Zeroizing::new(vec![0; 65_536]);
    let mut total = 0_u64;
    loop {
        check_cancel(cancel)?;
        let n = source.read(&mut buffer).map_err(|_| Error::Io)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(n).map_err(|_| Error::Budget)?)
            .ok_or(Error::Budget)?;
        if total > max_bytes {
            return Err(Error::Budget);
        }
        destination
            .write_all(buffer.get(..n).ok_or(Error::Budget)?)
            .map_err(|_| Error::Io)?;
    }
    Ok(())
}

struct Cancellable<'a, R>(&'a mut R, &'a CancellationToken);
impl<R: Read> Read for Cancellable<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.1.is_cancelled() {
            return Err(std::io::ErrorKind::Other.into());
        }
        self.0.read(bytes)
    }
}

struct BoundedOutput<'a, W> {
    file: &'a mut W,
    remaining: u64,
}
impl<'a, W> BoundedOutput<'a, W> {
    fn new(file: &'a mut W, remaining: u64) -> Self {
        Self { file, remaining }
    }
}
impl<W: Write> Write for BoundedOutput<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let n = u64::try_from(bytes.len()).map_err(|_| std::io::ErrorKind::InvalidData)?;
        if n > self.remaining {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        let written = self.file.write(bytes)?;
        self.remaining -= u64::try_from(written).map_err(|_| std::io::ErrorKind::InvalidData)?;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), Error> {
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    Ok(())
}
