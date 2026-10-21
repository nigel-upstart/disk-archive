//! Real DHAT export and allocator opt-in regression.
#![cfg(feature = "heap")]

use disk_archive_profiling::HeapSession;

#[test]
fn heap_exports_only_sanitized_command_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("heap.json");
    let session = HeapSession::start(&path)?;
    let allocation = vec![19_u8; 8192];
    std::hint::black_box(&allocation);
    drop(allocation);
    session.finish()?;
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert!(
        value
            .get("cmd")
            .is_some_and(|v| v == "disk-archive synthetic profile")
    );
    assert!(value.get("dhatFileVersion").is_some_and(|v| v == 2));
    assert!(
        value
            .get("pps")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|v| !v.is_empty())
    );
    // A second session is legal after an explicit finish; no double-drop or stale state.
    HeapSession::start(&directory.path().join("second.json"))?.finish()?;
    Ok(())
}
