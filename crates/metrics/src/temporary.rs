//! Exact append-only temporary-file accounting, independent of the filesystem implementation.

use std::io::{self, Write};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use crate::{CounterError, Counters};

struct Lifetime {
    counters: Arc<Counters>,
    bytes: AtomicU64,
}

/// One logical append-only temporary file, shared by every retained descriptor/body owner.
/// Starts at zero; count successful writes, not buffer sizes or conservative admission bounds.
/// Release only after closing/unlinking the file, or promoting it to a non-temporary source.
#[derive(Clone)]
pub struct AppendLease(Arc<Lifetime>);

impl Counters {
    /// Begin an empty temporary-file lifetime without I/O.
    ///
    /// # Errors
    /// Overflow or poisoned state invalidates the measurement.
    pub fn append_temporary(self: &Arc<Self>) -> Result<AppendLease, CounterError> {
        self.add(&self.live_leases, 1)?;
        Ok(AppendLease(Arc::new(Lifetime {
            counters: self.clone(),
            bytes: AtomicU64::new(0),
        })))
    }
}

impl AppendLease {
    /// Record an actual successful append. Never use for overwrites, truncation or guessed sizes.
    ///
    /// # Errors
    /// Any overflow poisons the whole run, including when a caller ignores the error.
    pub fn written(&self, bytes: u64) -> Result<(), CounterError> {
        self.0.counters.add(&self.0.bytes, bytes)?;
        let total = self.0.counters.add(&self.0.counters.temp_bytes, bytes)?;
        self.0
            .counters
            .peak_temp_bytes
            .fetch_max(total, Ordering::SeqCst);
        Ok(())
    }

    /// Invalidate the observation when cleanup cannot establish removal/release.
    pub fn cleanup_failed(&self) {
        self.0.counters.poisoned.store(true, Ordering::SeqCst);
    }

    /// Count successful writes, including partial writes followed by an error.
    /// Caller must keep this lease alive through the file's real lifetime.
    pub fn writer<'a, W: Write>(&'a self, writer: &'a mut W) -> AppendWriter<'a, W> {
        AppendWriter {
            writer,
            lease: self,
        }
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.counters
            .subtract(&self.counters.temp_bytes, self.bytes.load(Ordering::SeqCst));
        self.counters.subtract(&self.counters.live_leases, 1);
    }
}

/// Borrowed append writer; flushes do not change logical file length.
pub struct AppendWriter<'a, W> {
    writer: &'a mut W,
    lease: &'a AppendLease,
}

impl<W: Write> Write for AppendWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.lease
            .0
            .counters
            .valid()
            .map_err(|_| io::Error::other("temporary accounting"))?;
        let n = self.writer.write(bytes)?;
        let bytes = u64::try_from(n).map_err(|_| io::Error::other("temporary accounting"))?;
        self.lease
            .written(bytes)
            .map_err(|_| io::Error::other("temporary accounting"))?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests;
