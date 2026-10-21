use super::*;

fn fixture() -> (ExpectedUpload, HeadEvidence) {
    let expected = ExpectedUpload {
        schema_version: 1,
        bucket: "synthetic-bucket".into(),
        key: "prefix/v1/file.gz".into(),
        source: SourceIdentity {
            dev: 1,
            ino: 2,
            size: 3,
            mtime: Timestamp { secs: 4, nanos: 0 },
            ctime: Timestamp { secs: 5, nanos: 0 },
            sha256: [6; 32],
        },
        gzip_size: 23,
        gzip_sha256: [7; 32],
        integrity: Integrity::Crc64Nvme { value: [8; 8] },
        version_id: None,
        etag: None,
    };
    let head = HeadEvidence {
        bucket: expected.bucket.clone(),
        key: expected.key.clone(),
        content_length: Some(expected.gzip_size),
        encryption: Some("AES256".into()),
        checksum_type: Some(expected.integrity.checksum_type().into()),
        checksum_algorithm: Some(expected.integrity.algorithm().into()),
        checksum_value: Some(expected.integrity.wire_value()),
        metadata: expected.metadata(),
        version_id: None,
        etag: None,
    };
    (expected, head)
}

#[test]
fn observed_fields_reach_kernel_without_adapter_prechecks() -> Result<(), StoreError> {
    let changes: [fn(&mut HeadEvidence); 7] = [
        |h| h.key.push('x'),
        |h| h.content_length = Some(24),
        |h| {
            h.metadata.insert("sha256".into(), hex(&[9; 32]));
        },
        |h| {
            h.metadata.insert("orig-size".into(), "4".into());
        },
        |h| {
            h.metadata.insert("orig-sha256".into(), hex(&[10; 32]));
        },
        |h| h.encryption = Some("aws:kms".into()),
        |h| h.encryption = None,
    ];
    for change in changes {
        let (expected, mut head) = fixture();
        assert!(verify(&expected, &head).is_ok());
        change(&mut head);
        // Deliberately skip verify's length/metadata/SSE/key prechecks.
        let remote = project_remote(&head, &expected.integrity)?;
        assert_eq!(remote.key, head.key.as_bytes());
        assert_eq!(Some(remote.content_length), head.content_length);
        assert_eq!(
            hex(&remote.gz_sha256),
            *head.metadata.get("sha256").ok_or(StoreError::Integrity)?
        );
        assert_eq!(
            remote.orig_size.to_string(),
            *head
                .metadata
                .get("orig-size")
                .ok_or(StoreError::Integrity)?
        );
        assert_eq!(
            hex(&remote.orig_sha256),
            *head
                .metadata
                .get("orig-sha256")
                .ok_or(StoreError::Integrity)?
        );
        assert_eq!(
            remote.sse_aes256,
            head.encryption.as_deref() == Some("AES256")
        );
        assert!(matches!(
            lifecycle::verify_upload(
                &lifecycle::UploadExpectation {
                    source: expected.source,
                    key: expected.key.as_bytes().to_vec(),
                    compressed_size: expected.gzip_size,
                    compressed_sha256: expected.gzip_sha256,
                },
                &remote,
            ),
            Err(lifecycle::UploadError::RemoteMismatch)
        ));
        assert!(verify(&expected, &head).is_err());
    }
    Ok(())
}

#[test]
fn projection_rejects_missing_or_malformed_facts() {
    for size in [
        "",
        "+3",
        "-3",
        " 3",
        "3 ",
        "03",
        "3.0",
        "18446744073709551616",
        "٣",
    ] {
        let (expected, mut head) = fixture();
        head.metadata.insert("orig-size".into(), size.into());
        assert!(project_remote(&head, &expected.integrity).is_err());
    }
    for key in ["sha256", "orig-sha256"] {
        for value in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            "A".repeat(64),
            "é".repeat(32),
        ] {
            let (expected, mut head) = fixture();
            head.metadata.insert(key.into(), value);
            assert!(project_remote(&head, &expected.integrity).is_err());
        }
    }
    for key in ["sha256", "orig-sha256", "orig-size"] {
        let (expected, mut head) = fixture();
        head.metadata.remove(key);
        assert!(project_remote(&head, &expected.integrity).is_err());
    }
    let (expected, mut head) = fixture();
    head.content_length = None;
    assert!(project_remote(&head, &expected.integrity).is_err());
}

#[test]
fn independent_checksum_gate_precedes_metadata_projection() {
    let changes: [fn(&mut HeadEvidence); 6] = [
        |h| h.checksum_type = None,
        |h| h.checksum_type = Some("COMPOSITE".into()),
        |h| h.checksum_algorithm = None,
        |h| h.checksum_algorithm = Some("SHA256".into()),
        |h| h.checksum_value = None,
        |h| h.checksum_value = Some("AAAAAAAAAAA=".into()),
    ];
    for change in changes {
        let (expected, mut head) = fixture();
        change(&mut head);
        // Even perfectly echoed metadata cannot bypass actual-checksum verification.
        assert!(project_remote(&head, &expected.integrity).is_err());
        assert!(verify(&expected, &head).is_err());
    }
}

#[test]
fn strict_parsers_accept_boundaries_and_hex_bytes() -> Result<(), StoreError> {
    let (expected, mut head) = fixture();
    for size in [0, u64::MAX] {
        head.metadata.insert("orig-size".into(), size.to_string());
        head.metadata.insert("orig-sha256".into(), hex(&[0xab; 32]));
        let remote = project_remote(&head, &expected.integrity)?;
        assert_eq!(remote.orig_size, size);
        assert_eq!(remote.orig_sha256, [0xab; 32]);
    }
    Ok(())
}
