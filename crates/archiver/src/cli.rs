//! Strict argument parsing; no credential providers or mutable resources are initialized here.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::Error;

/// Shell options separate from core's read-only dotenv configuration.
#[derive(Default)]
pub struct Arguments {
    /// Metadata-only planning; selected before all mutable resources.
    pub dry_run: bool,
    /// Explicit cooperative/quiescent-root ownership acknowledgement.
    pub quiescent: bool,
    /// Maximum selected files for this invocation; zero selects none.
    pub limit: Option<usize>,
    /// Runtime and per-stage concurrency override.
    pub workers: Option<usize>,
    /// Maximum blocking-pool threads override.
    pub blocking_threads: Option<usize>,
    /// Capacity of each bounded stage/state queue.
    pub queue_capacity: Option<usize>,
    /// Selected dotenv path; missing explicit files fail without creation.
    pub env_file: Option<PathBuf>,
    /// Print usage without loading configuration.
    pub help: bool,
    /// Optional diagnostics; parsed without initialization and ignored by dry-run.
    pub profile: Option<crate::profile::Request>,
}

impl Arguments {
    /// Parse arguments after argv[0], without lossy path conversions.
    ///
    /// # Errors
    /// Unknown, duplicate, missing or malformed options fail closed.
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, Error> {
        let mut result = Self::default();
        let mut seen = std::collections::BTreeSet::new();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let name = match arg.to_str().ok_or(Error::Configuration)? {
                "-h" => "--help",
                name => name,
            };
            if !seen.insert(name.to_owned()) {
                return Err(Error::Configuration);
            }
            match name {
                "--dry-run" => result.dry_run = true,
                "--quiescent" => result.quiescent = true,
                "--help" => result.help = true,
                "--env-file" => {
                    let value = args.next().ok_or(Error::Configuration)?;
                    // Option-like filenames must be explicit paths (for example ./--dry-run).
                    if value.is_empty() || value.as_encoded_bytes().starts_with(b"-") {
                        return Err(Error::Configuration);
                    }
                    result.env_file = Some(value.into());
                }
                #[cfg(feature = "profiling")]
                "--profile-trace" => {
                    select_profile(
                        &mut result,
                        crate::profile::Request::Trace(profile_path(args.next())?),
                    )?;
                }
                #[cfg(feature = "profiling-heap")]
                "--profile-heap" => {
                    select_profile(
                        &mut result,
                        crate::profile::Request::Heap(profile_path(args.next())?),
                    )?;
                }
                #[cfg(feature = "profiling-console")]
                "--profile-console" => {
                    select_profile(&mut result, crate::profile::Request::Console)?;
                }
                "--limit" => result.limit = Some(number(args.next(), 0, usize::MAX)?),
                "--workers" => result.workers = Some(number(args.next(), 1, 256)?),
                "--blocking-threads" => {
                    result.blocking_threads = Some(number(args.next(), 2, 512)?);
                }
                "--queue-capacity" => result.queue_capacity = Some(number(args.next(), 1, 1024)?),
                _ => return Err(Error::Configuration),
            }
        }
        Ok(result)
    }
}

#[cfg(feature = "profiling")]
fn select_profile(result: &mut Arguments, request: crate::profile::Request) -> Result<(), Error> {
    if result.profile.is_some() {
        return Err(Error::Configuration);
    }
    result.profile = Some(request);
    Ok(())
}

#[cfg(feature = "profiling")]
fn profile_path(value: Option<OsString>) -> Result<PathBuf, Error> {
    let value = value.ok_or(Error::Configuration)?;
    if value.is_empty() || value.as_encoded_bytes().starts_with(b"-") {
        return Err(Error::Configuration);
    }
    Ok(value.into())
}

fn number(value: Option<OsString>, min: usize, max: usize) -> Result<usize, Error> {
    let value = value.ok_or(Error::Configuration)?;
    let value = value.to_str().ok_or(Error::Configuration)?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Configuration);
    }
    let number = value.parse().map_err(|_| Error::Configuration)?;
    if !(min..=max).contains(&number) {
        return Err(Error::Configuration);
    }
    Ok(number)
}

/// Public usage text contains no operational configuration or default destination.
pub const USAGE: &str = "disk-archive [--env-file PATH] [--dry-run] [--limit N] [--workers N]\n  [--queue-capacity N] [--blocking-threads N] [--quiescent]\n\n--dry-run inspects metadata only; redaction/verification remain unknown.\nMutation requires --quiescent: every writer must honor the source directory locks.\n";
