use super::*;

#[test]
fn buffer_overflow_is_latched_and_never_writes_unbounded_data()
-> Result<(), Box<dyn std::error::Error>> {
    let mut writer = BoundedWriter::default();
    writer.write_all(&vec![0; MAX_TRACE_BYTES + 1])?;
    writer.write_all(b"later")?;
    let buffer = writer.0.lock().map_err(|_| ProfileError::Budget)?;
    assert!(buffer.truncated);
    assert_eq!(buffer.bytes, [] as [u8; 0]);
    Ok(())
}

#[test]
fn sanitization_allowlists_fields_and_rejects_invalid_stage_values() -> Result<(), ProfileError> {
    let mut entry = json!({"ph":"B", "ts":1, "tid":2, "name":"stage", "args":{"stage":"\"scan\"", "file_id":"3", "extra":"discard-me"}, ".file":"discard-path"});
    sanitize(&mut entry)?;
    assert!(!entry.to_string().contains("discard"));
    assert_eq!(entry.get("name"), Some(&json!("scan")));
    for args in [
        json!({}),
        json!({"stage":"unknown", "file_id":"3"}),
        json!({"stage":"scan", "file_id":"private"}),
    ] {
        let mut invalid = json!({"ph":"B", "args":args});
        assert_eq!(sanitize(&mut invalid), Err(ProfileError::Budget));
    }
    Ok(())
}
