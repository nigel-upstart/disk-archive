//! Explicit, feature-gated diagnostics. No environment filters or automatic initialization.

#[cfg(feature = "profiling")]
pub(crate) use disk_archive_profiling::{Stage, stage, work};

#[cfg(not(feature = "profiling"))]
mod inert {
    // Same call sites compile without even the optional helper in the dependency tree.
    #[derive(Clone, Copy)]
    pub enum Stage {
        Discovery,
        Scan,
        Redact,
        Prepare,
        Upload,
        Verify,
        Delete,
        State,
        Manifest,
    }
    pub async fn stage<F: std::future::Future>(_: Stage, _: u64, future: F) -> F::Output {
        future.await
    }
    pub fn work<R>(_: Stage, _: u64, work: impl FnOnce() -> R) -> R {
        work()
    }
}
#[cfg(not(feature = "profiling"))]
pub(crate) use inert::{Stage, stage, work};

/// Explicit capture selection. Default builds have no constructible variants.
/// Parsing this selection does not open outputs, spawn threads or create listeners.
pub enum Request {
    /// Sanitized, bounded Chrome/Perfetto trace, created without overwriting.
    #[cfg(feature = "profiling")]
    Trace(std::path::PathBuf),
    /// Sanitized DHAT allocation profile.
    #[cfg(feature = "profiling-heap")]
    Heap(std::path::PathBuf),
    /// Loopback-only Tokio telemetry; needs the explicit unstable build.
    #[cfg(feature = "profiling-console")]
    Console,
}

/// Run with optional diagnostics only on the mutable branch. A capture is owned by
/// the pipeline's shielded owner, not the caller's cancellable waiter.
///
/// # Errors
/// Pipeline errors take precedence; capture errors are returned only after drain.
pub async fn run(
    config: std::sync::Arc<disk_archive_core::config::Config>,
    options: crate::pipeline::Options,
    services: crate::pipeline::Services,
    cancel: disk_archive_storage::CancellationToken,
    request: Option<Request>,
) -> Result<crate::pipeline::Report, crate::Error> {
    #[cfg(feature = "profiling")]
    if let Some(request) = request {
        return crate::pipeline::run_profiled(config, options, services, cancel, request).await;
    }
    #[cfg(not(feature = "profiling"))]
    let _ = request;
    crate::pipeline::run(config, options, services, cancel).await
}

#[cfg(feature = "profiling")]
pub(crate) enum Capture {
    Trace(disk_archive_profiling::Session),
    #[cfg(feature = "profiling-heap")]
    Heap(disk_archive_profiling::HeapSession),
    #[cfg(feature = "profiling-console")]
    Console(disk_archive_profiling::ConsoleSession),
}

#[cfg(feature = "profiling")]
impl Capture {
    pub(crate) fn start(request: Request) -> Result<Self, disk_archive_profiling::ProfileError> {
        match request {
            Request::Trace(path) => disk_archive_profiling::Session::trace(&path).map(Self::Trace),
            #[cfg(feature = "profiling-heap")]
            Request::Heap(path) => {
                disk_archive_profiling::HeapSession::start(&path).map(Self::Heap)
            }
            #[cfg(feature = "profiling-console")]
            Request::Console => disk_archive_profiling::console().map(Self::Console),
        }
    }

    pub(crate) async fn finish(
        self,
        pool: &crate::blocking::BlockingPool,
    ) -> Result<(), crate::Error> {
        match self {
            Self::Trace(session) => {
                pool.run(&disk_archive_storage::CancellationToken::new(), move || {
                    session.finish().map_err(|_| crate::Error::Profiling)
                })
                .await
            }
            #[cfg(feature = "profiling-heap")]
            Self::Heap(session) => {
                pool.run(&disk_archive_storage::CancellationToken::new(), move || {
                    session.finish().map_err(|_| crate::Error::Profiling)
                })
                .await
            }
            #[cfg(feature = "profiling-console")]
            Self::Console(session) => session.finish().await.map_err(|_| crate::Error::Profiling),
        }
    }
}
