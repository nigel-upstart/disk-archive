//! Bounded async archive orchestration and trusted filesystem/state adapters.
//!
//! Mutation requires cooperative exclusive ownership of every configured source root.
//! Advisory directory locks do not exclude uncooperative processes; absent that protocol,
//! callers must use metadata-only [`discovery::dry_run`], never enable the mutable pipeline.

pub mod blocking;
pub mod cli;
pub mod delete;
pub mod discovery;
pub mod filesystem;
pub mod manifest;
pub mod pipeline;
pub mod process;
pub mod scanner;
pub mod state;
pub mod work;

/// Static, value-free failures. Never embed source bytes, paths or SDK diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid arguments, settings or ownership assumptions.
    Configuration,
    /// Filesystem or state I/O failed.
    Io,
    /// Another cooperative owner holds the namespace.
    Locked,
    /// Source identity changed or a symlink/special file was encountered.
    SourceChanged,
    /// A resource limit was exceeded; partial output must not be accepted.
    Budget,
    /// A worker failed; partial results are invalid.
    Worker,
    /// Cancellation was requested.
    Cancelled,
    /// Scan/redaction verification failed closed.
    Blocked,
    /// Remote verification or transport failed.
    Store,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
