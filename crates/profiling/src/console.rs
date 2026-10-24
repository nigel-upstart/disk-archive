mod observation;
pub use observation::{ConsoleObservation, observe_console};

use super::ProfileError;
use tracing_subscriber::{Layer as _, layer::SubscriberExt as _};

/// Loopback-only console server. Dropping the guard aborts the server task.
pub struct ConsoleSession {
    task: Option<tokio::task::JoinHandle<Result<(), ProfileError>>>,
}

impl ConsoleSession {
    /// Stop serving and report a prior server/bind failure.
    ///
    /// # Errors
    /// Returns a static error if the server failed before shutdown.
    pub async fn finish(mut self) -> Result<(), ProfileError> {
        let task = self.task.take().ok_or(ProfileError::Output)?;
        if !task.is_finished() {
            task.abort();
        }
        match task.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(_) => Err(ProfileError::Output),
        }
    }
}

impl Drop for ConsoleSession {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// Start explicitly inside a runtime, after dry-run. Ignores all environment
/// filters and admits only Tokio runtime telemetry, never SDK/app body events.
///
/// # Errors
/// Fails clearly without `--cfg tokio_unstable`, without a runtime or when a
/// subscriber is already installed. Bind/serve errors are exposed by `finish`.
pub fn console() -> Result<ConsoleSession, ProfileError> {
    if !cfg!(tokio_unstable) {
        return Err(ProfileError::TokioUnstableRequired);
    }
    let handle = tokio::runtime::Handle::try_current().map_err(|_| ProfileError::Output)?;
    let (layer, server) = console_subscriber::ConsoleLayer::builder()
        .server_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 6669)))
        .event_buffer_capacity(4096)
        .client_buffer_capacity(256)
        .retention(std::time::Duration::from_secs(30))
        .enable_self_trace(false)
        .build();
    let layer = layer.with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
        // Exact targets audited against pinned Tokio 1.54.1. No namespace prefix
        // subscription: unrelated SDK/app targets and future targets stay excluded.
        matches!(
            metadata.target(),
            "tokio::task"
                | "tokio::task::blocking"
                | "tokio::task::waker"
                | "tokio::util::trace"
                | "tokio::sync::batch_semaphore"
                | "tokio::sync::oneshot"
                | "tokio::sync::barrier"
                | "tokio::sync::mutex"
                | "tokio::sync::rwlock"
                | "tokio::time::sleep"
                | "runtime::resource::state_update"
                | "runtime::resource::async_op::state_update"
                | "runtime::resource::poll_op"
        )
    }));
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
        .map_err(|_| ProfileError::AlreadyInitialized)?;
    Ok(ConsoleSession {
        task: Some(
            handle.spawn(async move { server.serve().await.map_err(|_| ProfileError::Output) }),
        ),
    })
}
