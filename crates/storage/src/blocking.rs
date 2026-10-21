//! Permit-owned blocking work shared with the pipeline; cancellation never releases a live worker.

use crate::{CancellationToken, StoreError};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Cloneable CPU admission gate. G can share the same semaphore with scanner/redactor work.
#[derive(Clone)]
pub struct BlockingPool {
    permits: Arc<Semaphore>,
}

impl BlockingPool {
    /// Create a bounded gate.
    ///
    /// # Errors
    /// Zero or more than 256 workers is invalid.
    pub fn new(workers: usize) -> Result<Self, StoreError> {
        if !(1..=256).contains(&workers) {
            return Err(StoreError::Configuration);
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(workers)),
        })
    }

    /// Use the pipeline's existing admission semaphore rather than adding independent CPU limits.
    #[must_use]
    pub fn from_shared(permits: Arc<Semaphore>) -> Self {
        Self { permits }
    }

    /// Current available permits, for shutdown/resource regression tests and metrics.
    #[must_use]
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }

    /// Acquire BEFORE spawning, move permit INTO closure, and signal cancellation on future drop.
    /// Jobs must check their supplied child token between bounded chunks. Blocking OS calls are
    /// not forcibly interruptible; their permit remains owned until the closure really exits.
    ///
    /// # Errors
    /// Cancellation, a closed gate, task failure or the job's static error is returned.
    pub async fn run<T, F>(&self, cancel: CancellationToken, job: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(CancellationToken) -> Result<T, StoreError> + Send + 'static,
    {
        let child = cancel.child_token();
        let _drop_cancel = child.clone().drop_guard();
        let permit = tokio::select! {
            biased;
            () = child.cancelled() => return Err(StoreError::Cancelled),
            permit = self.permits.clone().acquire_owned() => permit.map_err(|_| StoreError::Budget)?,
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if child.is_cancelled() {
                return Err(StoreError::Cancelled);
            }
            job(child)
        })
        .await
        .map_err(|_| StoreError::Worker)?
    }
}
