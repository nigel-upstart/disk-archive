//! The only blocking-pool gateway. Permits are held by closures, not their waiters.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::Error;

/// Bounded CPU/filesystem scheduling shared by all pipeline stages.
#[derive(Clone)]
pub struct BlockingPool {
    limit: usize,
    permits: Arc<Semaphore>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl BlockingPool {
    /// Construct a nonzero, bounded pool.
    ///
    /// # Errors
    /// Rejects zero or excessive concurrency.
    pub fn new(limit: usize) -> Result<Self, Error> {
        if !(1..=256).contains(&limit) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            limit,
            permits: Arc::new(Semaphore::new(limit)),
            active: Arc::default(),
            peak: Arc::default(),
        })
    }

    /// Acquire capacity BEFORE spawning. Cancellation cannot release a running closure's slot.
    ///
    /// # Errors
    /// Cancellation, worker panic, or the operation's static failure.
    pub async fn run<T, F>(&self, cancel: &CancellationToken, work: F) -> Result<T, Error>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, Error> + Send + 'static,
    {
        let permit = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Error::Cancelled),
            p = self.permits.clone().acquire_owned() => p.map_err(|_| Error::Worker)?,
        };
        let active = self.active.clone();
        let peak = self.peak.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            let _active = Active(active);
            work()
        })
        .await
        .map_err(|_| Error::Worker)?
    }

    /// Configured admission bound, used to validate the public pipeline resource contract.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Wait for all real closures, including those whose async waiter was dropped.
    /// Must be called only after all producers have stopped; ignores cancellation for cleanup.
    ///
    /// # Errors
    /// A closed semaphore or impossible limit is a worker failure, not a successful drain.
    pub async fn drain(&self) -> Result<(), Error> {
        let count = u32::try_from(self.limit).map_err(|_| Error::Worker)?;
        let _idle = self
            .permits
            .clone()
            .acquire_many_owned(count)
            .await
            .map_err(|_| Error::Worker)?;
        Ok(())
    }

    /// Share the same admission gate with storage's bounded preparation adapter.
    #[must_use]
    pub fn semaphore(&self) -> Arc<Semaphore> {
        self.permits.clone()
    }

    /// Largest observed concurrent blocking-job count, not the configured limit.
    #[must_use]
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
