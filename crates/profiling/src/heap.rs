use std::fs::File;
use std::io::Write as _;
use std::mem::ManuallyDrop;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{ProfileError, trace::private_output};

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Heap profiler guard, constructed only after dry-run. The allocator exists in
/// heap-feature binaries, but does not collect or create resources until this guard.
pub struct HeapSession {
    profiler: Option<ManuallyDrop<dhat::Profiler>>,
    output: Option<File>,
}

impl HeapSession {
    /// Start explicitly; never overwrite a previous artifact.
    ///
    /// # Errors
    /// Rejects an active profiler or an unavailable output.
    pub fn start(path: &Path) -> Result<Self, ProfileError> {
        let output = private_output(path)?;
        if ACTIVE.swap(true, Ordering::AcqRel) {
            return Err(ProfileError::AlreadyInitialized);
        }
        Ok(Self {
            profiler: Some(ManuallyDrop::new(dhat::Profiler::builder().build())),
            output: Some(output),
        })
    }

    /// Export DHAT JSON without its raw command line ever reaching disk.
    ///
    /// # Errors
    /// Rejects malformed profiler output or file failures.
    pub fn finish(mut self) -> Result<(), ProfileError> {
        self.finish_inner()
    }

    fn finish_inner(&mut self) -> Result<(), ProfileError> {
        let Some(mut profiler) = self.profiler.take() else {
            return Ok(());
        };
        // Pinned dhat 0.3.3's public memory-export API finishes the profiler.
        // ManuallyDrop prevents a second finish in dhat::Profiler::drop; no unsafe
        // code or raw intermediate profile file is needed. Recheck on upgrades.
        let raw = profiler.drop_and_get_memory_output();
        ACTIVE.store(false, Ordering::Release);
        let mut value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| ProfileError::Budget)?;
        let object = value.as_object_mut().ok_or(ProfileError::Budget)?;
        object.insert("cmd".into(), "disk-archive synthetic profile".into());
        let mut output = self.output.take().ok_or(ProfileError::Output)?;
        serde_json::to_writer(&mut output, &value).map_err(|_| ProfileError::Output)?;
        output.flush().map_err(|_| ProfileError::Output)
    }
}

impl Drop for HeapSession {
    fn drop(&mut self) {
        let _ = self.finish_inner();
    }
}
