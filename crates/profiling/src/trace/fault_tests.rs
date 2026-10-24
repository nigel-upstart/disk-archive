use super::*;
use std::io::Write as _;

struct FailingOutput {
    bytes: Vec<u8>,
    fail_after: usize,
    fail_flush: bool,
}

impl std::io::Write for FailingOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let available = self.fail_after.saturating_sub(self.bytes.len());
        let count = available.min(bytes.len());
        if count == 0 {
            return Err(std::io::Error::other("synthetic output fault"));
        }
        self.bytes.extend(bytes.iter().take(count));
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.fail_flush {
            return Err(std::io::Error::other("synthetic flush fault"));
        }
        Ok(())
    }
}

fn complete_capture() -> Buffer {
    Buffer {
        bytes: br#"[{"ph":"B","tid":1,"ts":0,"args":{"stage":"scan","file_id":"1","extra":"discard-private-marker"}}]"#.to_vec(),
        truncated: false,
    }
}

#[test]
fn partial_capture_never_reaches_output_or_claims_valid_json() {
    for buffer in [
        Buffer {
            bytes: b"[{".to_vec(),
            truncated: false,
        },
        Buffer {
            bytes: complete_capture().bytes,
            truncated: true,
        },
    ] {
        let mut output = Vec::new();
        assert_eq!(
            write_artifact(&buffer, &mut output),
            Err(ProfileError::Budget)
        );
        assert_eq!(output, [] as [u8; 0]);
    }
}

#[test]
fn output_write_and_flush_faults_return_static_errors_without_unwinding() {
    for (fail_after, fail_flush) in [(0, false), (8, false), (usize::MAX, true)] {
        let mut output = FailingOutput {
            bytes: Vec::new(),
            fail_after,
            fail_flush,
        };
        // Returning normally with Err is part of the assertion: an I/O panic fails
        // the test, and must never unwind a caller's source/root ownership guards.
        assert_eq!(
            write_artifact(&complete_capture(), &mut output),
            Err(ProfileError::Output)
        );
        assert_eq!(
            ProfileError::Output.to_string(),
            "profiling output unavailable"
        );
        assert!(!String::from_utf8_lossy(&output.bytes).contains("discard-private-marker"));
        if fail_after == 8 {
            assert!(serde_json::from_slice::<Value>(&output.bytes).is_err());
        }
    }
}

#[test]
fn real_chrome_writer_survives_cap_and_finish_rejects_partial_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let writer = BoundedWriter::default();
    // Force a cap crossing in the actual upstream writer, not a substitute
    // exporter. No file I/O is supplied to its unwrap-based background loop.
    writer
        .0
        .lock()
        .map_err(|_| ProfileError::Budget)?
        .bytes
        .resize(MAX_TRACE_BYTES, 0);
    let (layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
        .writer(writer.clone())
        .include_args(true)
        .include_locations(false)
        .build();
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(layer));
    tracing::dispatcher::with_default(&dispatch, || crate::work(crate::Stage::Scan, 1, || ()));
    drop(guard);
    let buffer = writer.0.lock().map_err(|_| ProfileError::Budget)?;
    assert!(buffer.truncated);
    assert_eq!(buffer.bytes.len(), MAX_TRACE_BYTES);
    let mut output = Vec::new();
    assert_eq!(
        write_artifact(&buffer, &mut output),
        Err(ProfileError::Budget)
    );
    assert_eq!(output, [] as [u8; 0]);
    Ok(())
}

#[test]
fn poisoned_sink_is_acknowledged_and_finish_returns_static_error()
-> Result<(), Box<dyn std::error::Error>> {
    let writer = BoundedWriter::default();
    let poisoned = writer.clone();
    let fault = std::thread::spawn(move || {
        let Ok(_held) = poisoned.0.lock() else {
            return;
        };
        // Deliberately unwind only this synthetic fault-injection thread while
        // holding the sink mutex. No application task or guard is involved.
        std::panic::resume_unwind(Box::new(()));
    });
    assert!(fault.join().is_err());
    let (layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
        .writer(writer.clone())
        .build();
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(layer));
    tracing::dispatcher::with_default(&dispatch, || crate::work(crate::Stage::Scan, 1, || ()));
    let output = tempfile::tempfile()?;
    let observer = output.try_clone()?;
    let session = Session {
        budget: Budget::default(),
        guard: Some(guard),
        buffer: writer,
        output: Some(output),
    };
    assert_eq!(session.finish(), Err(ProfileError::Budget));
    assert_eq!(observer.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn actual_callback_cap_finishes_statically_without_exporting_partial_spans()
-> Result<(), Box<dyn std::error::Error>> {
    let writer = BoundedWriter::default();
    let budget = Budget::default();
    let (layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
        .writer(writer.clone())
        .include_args(true)
        .include_locations(false)
        .build();
    let layer = BoundedLayer {
        inner: layer,
        budget: budget.clone(),
    };
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(layer));
    tracing::dispatcher::with_default(&dispatch, || {
        for file_id in 0..=budget::MAX_CALLBACKS / 2 {
            crate::work(crate::Stage::Scan, file_id, || ());
        }
    });
    assert!(budget.exceeded());
    let output = tempfile::tempfile()?;
    let observer = output.try_clone()?;
    let session = Session {
        budget,
        guard: Some(guard),
        buffer: writer,
        output: Some(output),
    };
    assert_eq!(session.finish(), Err(ProfileError::Budget));
    assert_eq!(observer.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn bounded_writer_always_acknowledges_cap_failures() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = BoundedWriter::default();
    assert_eq!(
        writer.write(&vec![0; MAX_TRACE_BYTES + 1])?,
        MAX_TRACE_BYTES + 1
    );
    assert_eq!(writer.write(b"after cap")?, 9);
    writer.flush()?;
    Ok(())
}
