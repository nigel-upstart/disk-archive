//! Bounded streaming discovery and the separate metadata-only dry-run path.

use std::collections::BTreeSet;
use std::os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use disk_archive_core::config::Config;
use disk_archive_verified::{age, key};
use tokio_util::sync::CancellationToken;

use crate::Error;
use crate::filesystem::{Candidate, Root, normalize_absolute, timestamp};

const MAX_IDENTITIES: usize = 100_000;
const MAX_KEY_BYTES: usize = 67_108_864;

#[cfg(test)]
mod tests;

/// Both indexes are bounded, including keys kept after candidates leave the pipeline.
struct Seen {
    keys: BTreeSet<String>,
    identities: BTreeSet<(u64, u64, i64, i64)>,
    bytes: usize,
    max_items: usize,
    max_bytes: usize,
}
impl Seen {
    fn new(max_items: usize, max_bytes: usize) -> Self {
        Self {
            keys: BTreeSet::new(),
            identities: BTreeSet::new(),
            bytes: 0,
            max_items,
            max_bytes,
        }
    }

    fn remember(&mut self, key: &str, metadata: &std::fs::Metadata) -> Result<bool, Error> {
        let identity = (
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        );
        if self.keys.contains(key) || self.identities.contains(&identity) {
            return Ok(false);
        }
        let bytes = self.bytes.checked_add(key.len()).ok_or(Error::Budget)?;
        if self.keys.len() >= self.max_items || bytes > self.max_bytes {
            return Err(Error::Budget);
        }
        self.keys.insert(key.to_owned());
        self.identities.insert(identity);
        self.bytes = bytes;
        Ok(true)
    }
}

/// Aggregate metadata-only report; neither scanner nor state/store is constructed.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct DryReport {
    /// Selected old regular files; redaction/verification outcomes remain unknown.
    pub eligible: usize,
    /// Inaccessible entries/subtrees or unencodable paths retained without source reads.
    pub retained: usize,
    /// Discovery was stopped by cancellation.
    pub cancelled: bool,
}

/// Explicitly reported per-entry failures; inaccessible subtrees are not a file census.
#[derive(Default)]
pub struct WalkReport {
    /// Entries/subtrees retained for retry or operator repair; no path values are logged.
    pub retained: usize,
}
impl WalkReport {
    fn retain(&mut self) -> Result<(), Error> {
        self.retained = self.retained.checked_add(1).ok_or(Error::Budget)?;
        Ok(())
    }
}

/// Validate disjoint roots/workdir without creating anything.
///
/// # Errors
/// Missing/symlink roots, overlapping namespaces or workdir inside a root fail closed.
pub fn roots(config: &Config, lock: bool) -> Result<Vec<Arc<Root>>, Error> {
    if config
        .roots_all_files
        .len()
        .saturating_add(config.roots_jsonl.len())
        > 256
    {
        return Err(Error::Budget);
    }
    let work = config
        .work_dir
        .as_deref()
        .map(normalize_absolute)
        .transpose()?;
    let mut roots: Vec<Arc<Root>> = Vec::new();
    for (paths, recursive) in [
        (&config.roots_all_files, false),
        (&config.roots_jsonl, true),
    ] {
        for path in paths {
            let path = normalize_absolute(path)?;
            if roots
                .iter()
                .any(|r| path.starts_with(&r.path) || r.path.starts_with(&path))
                || work
                    .as_ref()
                    .is_some_and(|w| w.starts_with(&path) || path.starts_with(w))
            {
                return Err(Error::Configuration);
            }
            roots.push(Arc::new(Root::open(&path, recursive, lock)?));
        }
    }
    if roots.is_empty() {
        return Err(Error::Configuration);
    }
    Ok(roots)
}

/// Run metadata-only planning, before initializing any mutable resource or credential chain.
///
/// # Errors
/// Invalid roots or global resource limits fail closed; per-entry errors are counted/retained.
pub fn dry_run(
    config: &Config,
    limit: Option<usize>,
    cancel: &CancellationToken,
) -> Result<DryReport, Error> {
    let roots = roots(config, false)?;
    let mut report = DryReport::default();
    let walked = walk(&roots, config, limit, cancel, |_| {
        report.eligible = report.eligible.checked_add(1).ok_or(Error::Budget)?;
        Ok(())
    })?;
    report.retained = walked.retained;
    report.cancelled = cancel.is_cancelled();
    Ok(report)
}

/// Walk with at most sixteen open directory handles and a fixed depth limit.
/// Callback backpressure stops traversal; candidates are never collected in memory.
///
/// # Errors
/// Global depth/identity/byte caps and callback failures stop discovery, never truncate.
/// Individual I/O failures and overlong keys are counted/retained while other entries continue.
pub fn walk(
    roots: &[Arc<Root>],
    config: &Config,
    limit: Option<usize>,
    cancel: &CancellationToken,
    mut send: impl FnMut(Candidate) -> Result<(), Error>,
) -> Result<WalkReport, Error> {
    let mut selected = 0_usize;
    let mut report = WalkReport::default();
    let mut seen = Seen::new(MAX_IDENTITIES, MAX_KEY_BYTES);
    for root in roots {
        let max_depth = if root.recursive_jsonl { 65 } else { 1 };
        for entry in walkdir::WalkDir::new(&root.path)
            .follow_links(false)
            .max_open(16)
            .min_depth(1)
            .max_depth(max_depth)
        {
            if cancel.is_cancelled() || limit.is_some_and(|n| selected >= n) {
                return Ok(report);
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error)
                    if error
                        .io_error()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    continue;
                }
                Err(_) => {
                    report.retain()?;
                    continue;
                }
            };
            if entry.depth() >= 65 {
                return Err(Error::Budget);
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error)
                    if error
                        .io_error()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    continue;
                }
                Err(_) => {
                    report.retain()?;
                    continue;
                }
            };
            if !metadata.is_file()
                || entry.file_name().as_bytes().starts_with(b".disk-archive-")
                || metadata.nlink() != 1
                || (root.recursive_jsonl && entry.path().extension().is_none_or(|s| s != "jsonl"))
                || !eligible(&metadata, config.min_age_secs)?
            {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(&root.path)
                .map_err(|_| Error::SourceChanged)?
                .to_owned();
            // Absolute root-qualified bytes avoid cross-root basename collisions. Keep all dots.
            let qualified = entry
                .path()
                .strip_prefix("/")
                .map_err(|_| Error::Configuration)?;
            let encoded = match key::encode_key(&config.prefix, qualified.as_os_str().as_bytes()) {
                Ok(encoded) => encoded,
                Err(key::KeyError::TooLong) => {
                    report.retain()?;
                    continue;
                }
                Err(_) => return Err(Error::Configuration),
            };
            let key = String::from_utf8(encoded).map_err(|_| Error::Configuration)?;
            if !seen.remember(&key, &metadata)? {
                continue;
            }
            send(Candidate {
                occupancy: None,
                root: root.clone(),
                relative,
                metadata,
                key,
            })?;
            selected = selected.checked_add(1).ok_or(Error::Budget)?;
        }
    }
    Ok(report)
}

/// Repeat the actual verified age comparison immediately before scanning.
///
/// # Errors
/// Clock/stat conversion failures fail closed.
pub fn eligible(metadata: &std::fs::Metadata, min_age_secs: u64) -> Result<bool, Error> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Io)?;
    let now = age::Timestamp {
        secs: i64::try_from(duration.as_secs()).map_err(|_| Error::Io)?,
        nanos: duration.subsec_nanos(),
    };
    Ok(age::is_older_than(
        now,
        timestamp(metadata.mtime(), metadata.mtime_nsec())?,
        min_age_secs,
    ))
}
