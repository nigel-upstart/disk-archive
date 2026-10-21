use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tracing_subscriber::{Layer as _, layer::SubscriberExt as _};

const MAX_TRACE_BYTES: usize = 16 * 1_048_576;

/// Static errors; never carry output paths, SDK errors or configuration values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// Cannot open/write the explicitly selected output.
    Output,
    /// A subscriber/profiler is already initialized.
    AlreadyInitialized,
    /// Trace exceeded its hard in-memory bound or was malformed.
    Budget,
    /// Console requires an explicitly unstable Tokio build.
    TokioUnstableRequired,
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Output => "profiling output unavailable",
            Self::AlreadyInitialized => "profiling already initialized",
            Self::Budget => "profiling trace budget or format rejected",
            Self::TokioUnstableRequired => "console requires RUSTFLAGS=--cfg tokio_unstable",
        })
    }
}

impl std::error::Error for ProfileError {}

#[derive(Default)]
struct Buffer {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Clone, Default)]
struct BoundedWriter(Arc<Mutex<Buffer>>);

impl std::io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        // Pinned tracing-chrome 0.7.2 unwraps writer errors in its background
        // thread. Never return one here, including on poison: finish observes
        // the still-poisoned mutex and rejects the artifact with a static error.
        let Ok(mut buffer) = self.0.lock() else {
            return Ok(bytes.len());
        };
        if buffer.bytes.len().saturating_add(bytes.len()) > MAX_TRACE_BYTES {
            buffer.truncated = true;
        }
        if !buffer.truncated {
            buffer.bytes.extend_from_slice(bytes);
        }
        // Do not panic the upstream writer on budget overflow. finish fails closed.
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Flush-on-drop Chrome trace session. Use `finish` to observe output/budget errors.
/// Explicit construction installs one global subscriber; never called implicitly.
/// Raw exporter metadata stays in bounded memory, never in an artifact.
pub struct Session {
    guard: Option<tracing_chrome::FlushGuard>,
    buffer: BoundedWriter,
    output: Option<File>,
}

impl Session {
    /// Start a private, non-overwriting trace after the caller's dry-run return.
    /// Ignores `RUST_LOG` and all SDK targets. The fixed helper is the only trace target.
    ///
    /// # Errors
    /// Rejects output errors and an existing global subscriber.
    pub fn trace(path: &Path) -> Result<Self, ProfileError> {
        let output = private_output(path)?;
        let buffer = BoundedWriter::default();
        let (layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
            .writer(buffer.clone())
            .include_args(true)
            .include_locations(false)
            .build();
        let layer = layer.with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.target() == "disk_archive_profiling::safe_stage"
                && metadata.is_span()
                && metadata.name() == "stage"
        }));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|_| ProfileError::AlreadyInitialized)?;
        Ok(Self {
            guard: Some(guard),
            buffer,
            output: Some(output),
        })
    }

    /// Flush, sanitize and finish. A truncated trace is never reported as complete.
    ///
    /// # Errors
    /// Rejects trace budget/format or output failures. An error means the artifact
    /// is incomplete, even if some sanitized bytes reached the output. Call only
    /// after pipeline work and detached cleanup have drained; do not use an export
    /// error to early-return past the application's owned-work shutdown protocol.
    pub fn finish(mut self) -> Result<(), ProfileError> {
        self.finish_inner()
    }

    fn finish_inner(&mut self) -> Result<(), ProfileError> {
        let Some(mut output) = self.output.take() else {
            return Ok(());
        };
        drop(self.guard.take());
        let buffer = self.buffer.0.lock().map_err(|_| ProfileError::Budget)?;
        write_artifact(&buffer, &mut output)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // No raw errors or metadata are logged from a destructor.
        let _ = self.finish_inner();
    }
}

pub(crate) fn private_output(path: &Path) -> Result<File, ProfileError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ProfileError::Output)
}

#[cfg(test)]
mod fault_tests;
#[cfg(test)]
mod tests;

fn write_artifact(buffer: &Buffer, output: &mut impl std::io::Write) -> Result<(), ProfileError> {
    // Never parse or export a partial capture as though it were a complete trace.
    if buffer.truncated {
        return Err(ProfileError::Budget);
    }
    let mut entries: Vec<Value> =
        serde_json::from_slice(&buffer.bytes).map_err(|_| ProfileError::Budget)?;
    for entry in &mut entries {
        sanitize(entry)?;
    }
    serde_json::to_writer(&mut *output, &entries).map_err(|_| ProfileError::Output)?;
    output.flush().map_err(|_| ProfileError::Output)
}

fn sanitize(entry: &mut Value) -> Result<(), ProfileError> {
    if entry.get("ph").and_then(Value::as_str) == Some("M") {
        // tracing-chrome records OS thread names even with include_args=false.
        // They can contain application data. Replace before any bytes reach disk.
        *entry = json!({"ph":"M", "pid":1, "name":"thread_name", "tid":entry.get("tid"), "args":{"name":"worker"}});
        return Ok(());
    }
    let args = entry.get("args").ok_or(ProfileError::Budget)?;
    let stage = args
        .get("stage")
        .and_then(Value::as_str)
        .ok_or(ProfileError::Budget)?
        .trim_matches('"');
    if ![
        "discovery",
        "scan",
        "redact",
        "prepare",
        "upload",
        "verify",
        "delete",
        "state",
        "manifest",
    ]
    .contains(&stage)
    {
        return Err(ProfileError::Budget);
    }
    let file_id: u64 = args
        .get("file_id")
        .and_then(Value::as_str)
        .ok_or(ProfileError::Budget)?
        .parse()
        .map_err(|_| ProfileError::Budget)?;
    // Rebuild with an allowlist, rather than attempting to denylist sensitive fields.
    *entry = json!({"ph":entry.get("ph"), "pid":1, "tid":entry.get("tid"), "ts":entry.get("ts"), "name":stage, "cat":"disk_archive", "args":{"file_id":file_id}});
    Ok(())
}
