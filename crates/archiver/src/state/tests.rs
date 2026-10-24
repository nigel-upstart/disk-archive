//! Small-budget tests exercise the production startup and manifest paths, without huge fixtures.

use super::*;

fn database(count: usize) -> Result<(Connection, usize), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch("CREATE TABLE files (key TEXT PRIMARY KEY, record BLOB NOT NULL)")?;
    let mut total = 0;
    for index in 0..count {
        let row = Row {
            key: format!("synthetic/v1/{index}.gz"),
            path: format!("/synthetic/{index}").into_bytes(),
            status: Status::Discovered,
            detectors: BTreeMap::new(),
            expected: Some(b"{}".to_vec()),
        };
        let bytes = row.encode()?;
        total += bytes.len();
        connection.execute("INSERT INTO files VALUES (?1, ?2)", params![row.key, bytes])?;
    }
    Ok((connection, total))
}

#[test]
fn startup_cardinality_and_byte_limits_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (connection, bytes) = database(3)?;
    assert_eq!(
        read_resume(&connection, ReadBudget::new(3, bytes, 0))?.len(),
        3
    );
    assert!(matches!(
        read_resume(&connection, ReadBudget::new(2, bytes, 0)),
        Err(Error::Budget)
    ));
    assert!(matches!(
        read_resume(&connection, ReadBudget::new(3, bytes - 1, 0)),
        Err(Error::Budget)
    ));
    Ok(())
}

#[test]
fn manifest_caps_include_array_and_comma_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let (connection, bytes) = database(3)?;
    let exact = bytes + 4; // two brackets and two commas
    let output = manifest_bounded(&connection, ReadBudget::new(3, exact, 2))?;
    assert_eq!(output.len(), exact);
    let decoded: Vec<Row> = serde_json::from_slice(&output)?;
    assert_eq!(decoded.len(), 3);
    assert!(matches!(
        manifest_bounded(&connection, ReadBudget::new(3, exact - 1, 2)),
        Err(Error::Budget)
    ));
    assert!(matches!(
        manifest_bounded(&connection, ReadBudget::new(2, exact, 2)),
        Err(Error::Budget)
    ));
    let (empty, _) = database(0)?;
    assert_eq!(manifest_bounded(&empty, ReadBudget::new(0, 2, 2))?, b"[]");
    assert!(matches!(
        manifest_bounded(&empty, ReadBudget::new(0, 1, 2)),
        Err(Error::Budget)
    ));
    Ok(())
}

#[test]
fn indexed_key_mismatch_cannot_collapse_resume_rows() -> Result<(), Box<dyn std::error::Error>> {
    let (connection, _) = database(2)?;
    connection.execute(
        "UPDATE files SET record=(SELECT record FROM files WHERE key=?1) WHERE key=?2",
        params!["synthetic/v1/0.gz", "synthetic/v1/1.gz"],
    )?;
    assert!(matches!(
        read_resume(&connection, ReadBudget::new(MAX_ROWS, MAX_RESUME, 0)),
        Err(Error::Configuration)
    ));
    assert!(matches!(manifest(&connection), Err(Error::Configuration)));
    Ok(())
}

#[test]
fn oversized_record_is_rejected_before_decode() -> Result<(), Box<dyn std::error::Error>> {
    let (connection, _) = database(1)?;
    connection.execute(
        "UPDATE files SET record=zeroblob(?1)",
        [i64::try_from(MAX_RECORD * 5 + 1)?],
    )?;
    assert!(matches!(
        read_resume(&connection, ReadBudget::new(MAX_ROWS, MAX_RESUME, 0)),
        Err(Error::Budget)
    ));
    assert!(matches!(manifest(&connection), Err(Error::Budget)));
    Ok(())
}

#[test]
fn compact_codec_preserves_exact_expected_json_and_legacy_path_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let expected =
        serde_json::to_vec(&serde_json::json!({"format":"synthetic", "padding":"x".repeat(512)}))?;
    let path = vec![b'/', 255, b'a'];
    let legacy = serde_json::to_vec(&serde_json::json!({
        "key":"synthetic/v1/source.gz", "path":path, "status":"verified",
        "detectors":{}, "expected":expected,
    }))?;
    let row: Row = serde_json::from_slice(&legacy)?;
    assert_eq!(row.path, path);
    assert_eq!(row.expected.as_deref(), Some(expected.as_slice()));
    let compact = row.encode()?;
    assert!(compact.len() < legacy.len() / 2);
    let wire: serde_json::Value = serde_json::from_slice(&compact)?;
    assert!(wire.get("path").is_some_and(serde_json::Value::is_string));
    assert!(
        wire.get("expected")
            .is_some_and(serde_json::Value::is_object)
    );
    let restored: Row = serde_json::from_slice(&compact)?;
    assert_eq!(restored.path, path);
    assert_eq!(restored.expected.as_deref(), Some(expected.as_slice()));
    Ok(())
}

#[test]
fn completed_history_does_not_consume_the_pending_resume_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let (connection, _) = database(300)?;
    connection.execute(
        "UPDATE files SET record=CAST(json_set(CAST(record AS TEXT),'$.status','deleted') AS BLOB)",
        [],
    )?;
    let active = Row {
        key: "synthetic/v1/299.gz".into(),
        path: b"/synthetic/299".to_vec(),
        status: Status::Error,
        detectors: BTreeMap::new(),
        expected: Some(b"{}".to_vec()),
    };
    let bytes = active.encode()?;
    connection.execute(
        "UPDATE files SET record=?2 WHERE key=?1",
        params![active.key, bytes],
    )?;
    let resumed = read_resume(&connection, ReadBudget::new(1, bytes.len(), 0))?;
    assert_eq!(resumed.len(), 1);
    assert!(resumed.contains_key(&active.key));
    assert!(
        historical_row(&connection, "synthetic/v1/0.gz")?
            .is_some_and(|row| row.status == Status::Deleted)
    );
    assert!(
        historical_row(&connection, &active.key)?.is_some_and(|row| row.status == Status::Error)
    );
    let mut after = None;
    let mut total = 0;
    loop {
        let page = manifest_page(
            &connection,
            after.as_deref(),
            ReadBudget::new(MAX_ROWS, 4096, 2),
        )?;
        assert!(page.bytes.len() <= 4096);
        total += page.rows;
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(total, 300); // histories still appear in the complete streamed snapshot
    Ok(())
}

#[test]
fn deleted_records_cannot_be_replaced_even_if_a_caller_bypasses_the_discovery_guard()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().canonicalize()?.join("state.sqlite");
    let (connection, _) = initialize(&path)?;
    let mut row = Row {
        key: "synthetic/v1/source.gz".into(),
        path: b"/synthetic/source".to_vec(),
        status: Status::Deleted,
        detectors: BTreeMap::new(),
        expected: None,
    };
    let original = row.encode()?;
    let connection = commit(connection, vec![(row.clone(), None)])?;
    row.status = Status::Error;
    let (tx, mut rx) = oneshot::channel();
    assert!(matches!(
        commit(connection, vec![(row, Some(tx))]),
        Err(Error::Configuration)
    ));
    assert_eq!(rx.try_recv()?, Err(Error::Configuration));
    let connection = Connection::open(&path)?;
    let persisted: Vec<u8> =
        connection.query_row("SELECT record FROM files", [], |row| row.get(0))?;
    assert_eq!(persisted, original);
    Ok(())
}

#[test]
fn history_without_upload_intents_does_not_consume_startup_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let (connection, _) = database(300)?;
    connection.execute(
        "UPDATE files SET record=CAST(json_set(CAST(record AS TEXT),'$.status',CASE rowid%3 WHEN 0 THEN 'blocked' WHEN 1 THEN 'error' ELSE 'skipped' END,'$.expected',NULL) AS BLOB)",
        [],
    )?;
    // This is the production query with a lowered cap, not a 100k-row allocation.
    assert!(read_resume(&connection, ReadBudget::new(0, 0, 0))?.is_empty());
    let history: Vec<Row> = serde_json::from_slice(&manifest(&connection)?)?;
    assert_eq!(history.len(), 300);
    assert!(history.iter().all(|row| row.expected.is_none()));
    let key = "synthetic/v1/0.gz";
    let original = historical_row(&connection, key)?.ok_or("missing history")?;
    assert!(original.expected.is_none());
    assert!(historical_row(&connection, "synthetic/v1/absent.gz")?.is_none());
    // Existing no-intent records are not mislabeled Deleted or removed from the manifest.
    assert!(original.status != Status::Deleted);
    connection.execute(
        "UPDATE files SET record=CAST(json_set(CAST(record AS TEXT),'$.expected',json('{}')) AS BLOB) WHERE key=?1",
        [key],
    )?;
    assert!(matches!(
        read_resume(&connection, ReadBudget::new(0, MAX_RESUME, 0)),
        Err(Error::Budget)
    ));
    assert_eq!(
        read_resume(&connection, ReadBudget::new(1, MAX_RESUME, 0))?.len(),
        1
    );
    Ok(())
}

#[test]
fn missing_expectation_is_not_treated_as_explicit_no_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let (connection, _) = database(1)?;
    connection.execute(
        "UPDATE files SET record=CAST(json_remove(CAST(record AS TEXT),'$.expected') AS BLOB)",
        [],
    )?;
    assert!(read_resume(&connection, ReadBudget::new(MAX_ROWS, MAX_RESUME, 0)).is_err());
    Ok(())
}

#[test]
fn byte_accounting_never_wraps() {
    let mut budget = ReadBudget::new(1, usize::MAX, usize::MAX);
    assert_eq!(budget.charge(1, 0), Err(Error::Budget));
    assert_eq!(budget.charge(0, 1), Err(Error::Budget));
    assert_eq!(budget.rows, 0);
}
