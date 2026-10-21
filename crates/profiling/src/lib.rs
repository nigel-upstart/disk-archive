//! Explicit opt-in profiling. The default build has no dependencies or resources.
//! Call session constructors only after the application's dry-run early return.

/// Fixed, value-free pipeline stage labels.
#[derive(Clone, Copy, Debug)]
pub enum Stage {
    /// Metadata discovery.
    Discovery,
    /// Native detection.
    Scan,
    /// Redaction and output verification.
    Redact,
    /// Gzip preparation.
    Prepare,
    /// Object transfer.
    Upload,
    /// Fresh remote evidence validation.
    Verify,
    /// Source-bound unlink.
    Delete,
    /// Durable bookkeeping.
    State,
    /// Terminal manifest publication.
    Manifest,
}

impl Stage {
    /// Static label; never a path, configuration value or input.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Scan => "scan",
            Self::Redact => "redact",
            Self::Prepare => "prepare",
            Self::Upload => "upload",
            Self::Verify => "verify",
            Self::Delete => "delete",
            Self::State => "state",
            Self::Manifest => "manifest",
        }
    }
}

/// Instrument one future with a static stage and an opaque ordinal (not a path).
/// `skip_all` prevents the future and its arguments from being formatted. The
/// generated instrumentation enters/exits on poll, never across await boundaries.
#[cfg_attr(feature = "profiling", tracing::instrument(
    name = "stage", target = "disk_archive_profiling::safe_stage", skip_all,
    fields(stage = stage.as_str(), file_id = file_id)
))]
pub async fn stage<F: std::future::Future>(stage: Stage, file_id: u64, future: F) -> F::Output {
    // Keep the no-feature implementation dependency-free without lint suppression.
    let _ = (stage, file_id);
    future.await
}

/// Instrument actual synchronous work inside an already-admitted blocking worker.
/// This does not spawn a task or hold an entered span across an await.
#[cfg_attr(feature = "profiling", tracing::instrument(
    name = "stage", target = "disk_archive_profiling::safe_stage", skip_all,
    fields(stage = stage.as_str(), file_id = file_id)
))]
pub fn work<R>(stage: Stage, file_id: u64, work: impl FnOnce() -> R) -> R {
    let _ = (stage, file_id);
    work()
}

#[cfg(feature = "profiling")]
mod trace;
#[cfg(feature = "profiling")]
pub use trace::{ProfileError, Session};

#[cfg(feature = "heap")]
mod heap;
#[cfg(feature = "heap")]
pub use heap::HeapSession;

#[cfg(feature = "console")]
mod console;
#[cfg(feature = "console")]
pub use console::console;
