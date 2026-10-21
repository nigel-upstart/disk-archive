//! Exact, explicit operation instrumentation shared by runtime adapters and benchmarks.
//! Not a syscall tracer: every adapter operation must pass through these counters.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const MAX_REQUEST_OBJECTS: usize = 100_000;

/// Static counter overflow/poison error. Never continue with a partial measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterError;

/// Object size classes are independent of machine/resource fingerprints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SizeClass {
    /// Single-request payload geometry.
    Single,
    /// Multipart payload geometry.
    Multipart,
}

/// Exact observed behavioral counters, not resource estimates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Attempts through the authorized process-spawn gateway, including failures.
    pub process_spawns: u64,
    /// Bytes actually submitted to the transport, including retry traffic.
    pub bytes_uploaded: u64,
    /// Peak simultaneously reserved/occupied temporary bytes, not a sum of file sizes.
    pub peak_temp_bytes: u64,
    /// Actual request attempts per object; key is a synthetic ordinal, never a source path.
    pub requests: BTreeMap<(SizeClass, u64), u64>,
}

/// Thread-safe shared counters. Zero is obtained from instrumentation, never a fixture constant.
/// Scalar updates are atomic; the bounded per-object request index has one short mutex.
#[derive(Default)]
pub struct Counters {
    process_spawns: AtomicU64,
    bytes_uploaded: AtomicU64,
    peak_temp_bytes: AtomicU64,
    temp_bytes: AtomicU64,
    live_leases: AtomicU64,
    poisoned: AtomicBool,
    requests: Mutex<BTreeMap<(SizeClass, u64), u64>>,
}

impl Counters {
    fn valid(&self) -> Result<(), CounterError> {
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(CounterError);
        }
        Ok(())
    }

    fn add(&self, counter: &AtomicU64, amount: u64) -> Result<u64, CounterError> {
        self.valid()?;
        if let Ok(previous) = counter.try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_add(amount)
        }) {
            Ok(previous + amount)
        } else {
            self.poisoned.store(true, Ordering::SeqCst);
            Err(CounterError)
        }
    }

    fn subtract(&self, counter: &AtomicU64, amount: u64) {
        if counter
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(amount)
            })
            .is_err()
        {
            self.poisoned.store(true, Ordering::SeqCst);
        }
    }

    /// Count an attempted hot-path process launch BEFORE performing it.
    ///
    /// # Errors
    /// Overflow or poisoned state invalidates the measurement.
    pub fn process_spawn(&self) -> Result<(), CounterError> {
        self.add(&self.process_spawns, 1).map(|_| ())
    }

    /// Count an actual S3 request attempt, including HEAD, MPU and retries.
    /// At most 100,000 distinct (size class, synthetic ordinal) pairs are admitted.
    ///
    /// # Errors
    /// Overflow, cardinality limits or poisoned state invalidate the measurement.
    pub fn request(&self, class: SizeClass, object: u64) -> Result<(), CounterError> {
        let mut requests = self.requests.lock().map_err(|_| CounterError)?;
        self.valid()?;
        let key = (class, object);
        let count = requests.get(&key).copied();
        if count.is_none() && requests.len() >= MAX_REQUEST_OBJECTS {
            self.poisoned.store(true, Ordering::SeqCst);
            return Err(CounterError);
        }
        let Some(total) = count.unwrap_or(0).checked_add(1) else {
            self.poisoned.store(true, Ordering::SeqCst);
            return Err(CounterError);
        };
        requests.insert(key, total);
        Ok(())
    }

    /// Count bytes at the actual transport boundary, not the input or gzip size estimate.
    ///
    /// # Errors
    /// Overflow or poisoned state invalidates the measurement.
    pub fn uploaded(&self, bytes: u64) -> Result<(), CounterError> {
        self.add(&self.bytes_uploaded, bytes).map(|_| ())
    }

    /// Reserve/count temporary disk before a write. Hold the lease until removal completes.
    ///
    /// # Errors
    /// Overflow or poisoned state invalidates the measurement.
    pub fn temporary(&self, bytes: u64) -> Result<TempLease<'_>, CounterError> {
        self.add(&self.live_leases, 1)?;
        let total = match self.add(&self.temp_bytes, bytes) {
            Ok(total) => total,
            Err(error) => {
                self.subtract(&self.live_leases, 1);
                return Err(error);
            }
        };
        self.peak_temp_bytes.fetch_max(total, Ordering::SeqCst);
        Ok(TempLease {
            counters: self,
            bytes,
        })
    }

    /// Capture exact observations. Call only after all worker tasks and cleanup have drained.
    /// This is not a coherent concurrent snapshot of active scalar updates.
    ///
    /// # Errors
    /// Poisoned state or live temp leases invalidate a completed-run snapshot.
    pub fn snapshot(&self) -> Result<Snapshot, CounterError> {
        let requests = self.requests.lock().map_err(|_| CounterError)?;
        self.valid()?;
        if self.live_leases.load(Ordering::SeqCst) != 0
            || self.temp_bytes.load(Ordering::SeqCst) != 0
        {
            return Err(CounterError);
        }
        Ok(Snapshot {
            process_spawns: self.process_spawns.load(Ordering::SeqCst),
            bytes_uploaded: self.bytes_uploaded.load(Ordering::SeqCst),
            peak_temp_bytes: self.peak_temp_bytes.load(Ordering::SeqCst),
            requests: requests.clone(),
        })
    }
}

/// Temporary-disk reservation. Adapters must retain it through successful cleanup.
pub struct TempLease<'a> {
    counters: &'a Counters,
    bytes: u64,
}

impl Drop for TempLease<'_> {
    fn drop(&mut self) {
        self.counters
            .subtract(&self.counters.temp_bytes, self.bytes);
        self.counters.subtract(&self.counters.live_leases, 1);
    }
}

#[cfg(test)]
mod tests;
