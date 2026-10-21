//! Real exporter privacy and format regression.
#![cfg(feature = "profiling")]

use std::future::Future as _;
use std::task::{Context, Poll, Waker};

use disk_archive_profiling::{Session, Stage, stage, work};

#[test]
fn trace_is_valid_and_excludes_inputs_sdk_events_and_thread_names()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("trace.json");
    let session = Session::trace(&path)?;
    let plant = "SYNTHETIC-PRIVATE-TRACE-CANARY-7281";
    let thread = std::thread::Builder::new()
        .name(plant.into())
        .spawn(move || {
            let mut context = Context::from_waker(Waker::noop());
            let mut future = Box::pin(stage(Stage::Scan, 42, async move {
                tracing::info!(target: "aws_sdk_s3", body = plant);
                tracing::info!(target: "disk_archive_profiling", message = plant);
                plant.len()
            }));
            assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(plant.len()));
            assert_eq!(work(Stage::Prepare, 43, || plant.len()), plant.len());
            let mut first = true;
            let pending = std::future::poll_fn(move |_| {
                if first {
                    first = false;
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            });
            let mut instrumented = Box::pin(stage(Stage::Upload, 44, pending));
            assert_eq!(instrumented.as_mut().poll(&mut context), Poll::Pending);
            assert_eq!(instrumented.as_mut().poll(&mut context), Poll::Ready(()));
        })?;
    assert!(thread.join().is_ok());
    session.finish()?;
    let bytes = std::fs::read(&path)?;
    let text = std::str::from_utf8(&bytes)?;
    assert!(!text.contains(plant));
    assert!(!text.contains("aws_sdk_s3"));
    let events: Vec<serde_json::Value> = serde_json::from_slice(&bytes)?;
    assert!(events.iter().any(|v| {
        v.get("name").is_some_and(|v| v == "scan")
            && v.get("args")
                .and_then(|v| v.get("file_id"))
                .is_some_and(|v| v == 42)
    }));
    let upload_phases = events
        .iter()
        .filter(|v| v.get("name").is_some_and(|v| v == "upload"))
        .count();
    assert_eq!(
        upload_phases, 6,
        "two polls and future drop must each enter/exit, not hold a span across await"
    );
    for event in &events {
        assert!(matches!(
            event.get("ph").and_then(serde_json::Value::as_str),
            Some("B" | "E" | "M")
        ));
        assert!(event.get(".file").is_none());
    }
    // Repeated initialization/output cannot overwrite a prior artifact.
    assert!(Session::trace(&path).is_err());
    Ok(())
}
