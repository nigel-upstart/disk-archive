use std::fs::Permissions;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use super::{FaultType, HeadFault, MockS3, Occurrence};
use crate::{
    BlockingPool, CancellationToken, ChecksumPolicy, ExpectedUpload, ObjectStore, PrepareOptions,
    PreparedUpload, SdkStore, StoreError, StoreOptions, UploadPreparer, prepare::metadata_identity,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn options() -> StoreOptions {
    StoreOptions {
        bucket: "synthetic-archive".into(),
        multipart_threshold: 5_242_880,
        part_size: 5_242_880,
        concurrency: 2,
        in_flight_bytes: 32 * 1_048_576,
    }
}

pub(super) fn preparer(
    work: &TempDir,
    checksum: ChecksumPolicy,
) -> Result<UploadPreparer, StoreError> {
    UploadPreparer::new(
        PrepareOptions {
            bucket: options().bucket,
            work_dir: work.path().to_owned(),
            disk_budget: 64 * 1_048_576,
            max_spool_bytes: 32 * 1_048_576,
            multipart_threshold: options().multipart_threshold,
            part_size: options().part_size,
            checksum,
        },
        BlockingPool::new(2)?,
    )
}

pub(super) fn workdir() -> Result<TempDir, std::io::Error> {
    let work = tempfile::tempdir()?;
    std::fs::set_permissions(work.path(), Permissions::from_mode(0o700))?;
    Ok(work)
}

pub(super) fn corpus(length: usize) -> Vec<u8> {
    let mut state = 17_u64;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes().first().copied().unwrap_or(0)
        })
        .collect()
}

pub(super) async fn prepare(
    work: &TempDir,
    prep: &UploadPreparer,
    bytes: &[u8],
    key: &str,
) -> Result<PreparedUpload, Box<dyn std::error::Error>> {
    let mut source = tempfile::tempfile_in(work.path())?;
    source.write_all(bytes)?;
    let identity = metadata_identity(&source.metadata()?, Sha256::digest(bytes).into())?;
    Ok(prep
        .prepare(source, identity, key.into(), CancellationToken::new())
        .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_single_multipart_resume_manifest_and_checksum_faults() -> TestResult {
    let mock = MockS3::start().await?;
    let store = SdkStore::new(mock.client(), options())?;
    let work = workdir()?;
    for checksum in [ChecksumPolicy::Crc64Nvme, ChecksumPolicy::Sha256] {
        let prep = preparer(&work, checksum)?;
        for (index, bytes) in [
            Vec::new(),
            b"synthetic small file".to_vec(),
            corpus(12 * 1_048_576),
        ]
        .into_iter()
        .enumerate()
        {
            let key = format!("archive/{checksum:?}-{index}.gz");
            let upload = prepare(&work, &prep, &bytes, &key).await?;
            let record = upload.expected().to_record()?;
            let expected = ExpectedUpload::from_record(&record)?;
            assert!(prep.reserved_disk_bytes() > 0);
            let result = store
                .put_object_verified(&upload, CancellationToken::new())
                .await;
            let raw = mock
                .client()
                .head_object()
                .bucket("synthetic-archive")
                .key(&key)
                .send()
                .await?;
            assert_eq!(
                raw.checksum_sha256().is_some(),
                matches!(checksum, ChecksumPolicy::Sha256),
                "wire sha present {checksum:?}-{index}"
            );
            assert!(result.is_ok(), "put {checksum:?}-{index}");
            let token = result?;
            let mut changed = expected.source;
            changed.sha256 = [0; 32];
            assert!(disk_archive_verified::lifecycle::authorize_delete(token, &changed).is_err());
            assert!(
                store
                    .verify_existing(&expected, CancellationToken::new())
                    .await
                    .is_ok(),
                "resume {checksum:?}-{index}"
            );
            let head = store.head(&key, None, CancellationToken::new()).await?;
            assert_eq!(
                head.checksum_type.as_deref(),
                Some(expected.integrity.checksum_type())
            );
            assert_eq!(head.checksum_value, Some(expected.integrity.wire_value()));
            for fault in [
                HeadFault::Checksum,
                HeadFault::MissingChecksum,
                HeadFault::Type,
                HeadFault::Length,
                HeadFault::Metadata,
                HeadFault::Encryption,
            ] {
                mock.set_head_fault(fault);
                assert!(matches!(
                    store
                        .verify_existing(&expected, CancellationToken::new())
                        .await,
                    Err(StoreError::Integrity)
                ));
            }
            mock.set_head_fault(HeadFault::None);
            drop(upload);
            assert_eq!(prep.reserved_disk_bytes(), 0);
        }
    }
    assert_eq!(mock.created(), 2);
    assert!(mock.parts() >= 6);
    store
        .put_manifest("manifest/state.json", b"{}", CancellationToken::new())
        .await?;
    assert!(matches!(
        store.head("absent", None, CancellationToken::new()).await,
        Err(StoreError::NotFound)
    ));
    store.drain().await?;
    mock.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retryable_5xx_and_throttling_preserve_integrity() -> TestResult {
    let mock = MockS3::start().await?;
    let store = SdkStore::new(mock.client(), options())?;
    let work = workdir()?;
    let prep = preparer(&work, ChecksumPolicy::Crc64Nvme)?;
    for status in [500, 503] {
        let key = format!("retry/{status}.gz");
        let upload = prepare(&work, &prep, b"synthetic retry", &key).await?;
        mock.server.insert_fault(
            "synthetic-archive",
            &key,
            FaultType::ServiceError { status },
            0,
            Occurrence::Once,
        );
        store
            .put_object_verified(&upload, CancellationToken::new())
            .await?;
    }
    store.drain().await?;
    mock.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_part_aborts_and_corrupt_post_put_never_grants_authority() -> TestResult {
    let mock = MockS3::start().await?;
    let store = SdkStore::new(mock.client(), options())?;
    let work = workdir()?;
    let prep = preparer(&work, ChecksumPolicy::Crc64Nvme)?;
    let upload = prepare(&work, &prep, &corpus(12 * 1_048_576), "failure.gz").await?;
    mock.server.insert_fault(
        "synthetic-archive",
        "failure.gz",
        FaultType::ServiceError { status: 403 },
        0,
        Occurrence::Always,
    );
    assert!(
        store
            .put_object_verified(&upload, CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(mock.created(), 1);
    assert_eq!(mock.aborted(), 1);
    assert!(
        !mock
            .server
            .object_exists("synthetic-archive", "failure.gz")
            .await?
    );
    let small = prepare(&work, &prep, b"synthetic", "bad-head.gz").await?;
    mock.set_head_fault(HeadFault::Checksum);
    assert!(matches!(
        store
            .put_object_verified(&small, CancellationToken::new())
            .await,
        Err(StoreError::Integrity)
    ));
    mock.set_head_fault(HeadFault::None);
    store.drain().await?;
    mock.shutdown().await?;
    Ok(())
}

async fn wait_part(mock: &MockS3) -> Result<(), tokio::time::error::Elapsed> {
    tokio::time::timeout(Duration::from_secs(8), async {
        while mock.parts() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_and_caller_drop_shield_abort_and_spool_quota() -> TestResult {
    for drop_caller in [false, true] {
        let mock = MockS3::start().await?;
        let store = SdkStore::new(mock.client(), options())?;
        let work = workdir()?;
        let prep = preparer(&work, ChecksumPolicy::Sha256)?;
        let key = "cancel/multipart.gz";
        let upload = Arc::new(prepare(&work, &prep, &corpus(12 * 1_048_576), key).await?);
        mock.server.insert_fault(
            "synthetic-archive",
            key,
            FaultType::StallRequestRead { after_bytes: 0 },
            0,
            Occurrence::Always,
        );
        let token = CancellationToken::new();
        let child = token.clone();
        let owned = upload.clone();
        let worker_store = store.clone();
        let job =
            tokio::spawn(async move { worker_store.put_object_verified(&owned, child).await });
        wait_part(&mock).await?;
        assert_eq!(mock.created(), 1);
        drop(upload);
        assert!(prep.reserved_disk_bytes() > 0);
        if drop_caller {
            job.abort();
            assert!(job.await.is_err());
        } else {
            token.cancel();
            assert!(matches!(job.await?, Err(StoreError::Cancelled)));
        }
        tokio::time::timeout(Duration::from_secs(8), store.drain()).await??;
        assert_eq!(mock.aborted(), mock.created());
        assert_eq!(prep.reserved_disk_bytes(), 0);
        assert!(!mock.server.object_exists("synthetic-archive", key).await?);
        mock.shutdown().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_identity_budget_and_drain_fail_closed() -> TestResult {
    let work = workdir()?;
    let prep = preparer(&work, ChecksumPolicy::Crc64Nvme)?;
    let mut file = tempfile::tempfile_in(work.path())?;
    file.write_all(b"synthetic original")?;
    let original = metadata_identity(
        &file.metadata()?,
        Sha256::digest(b"synthetic original").into(),
    )?;
    file.write_all(b" changed")?;
    assert!(matches!(
        prep.prepare(
            file,
            original,
            "changed.gz".into(),
            CancellationToken::new()
        )
        .await,
        Err(StoreError::SourceChanged)
    ));
    assert_eq!(prep.reserved_disk_bytes(), 0);
    let mock = MockS3::start().await?;
    let store = SdkStore::new(mock.client(), options())?;
    let upload = prepare(&work, &prep, b"small", "closed.gz").await?;
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        store.put_object_verified(&upload, cancelled).await,
        Err(StoreError::Cancelled)
    ));
    store.drain().await?;
    assert!(matches!(
        store
            .put_object_verified(&upload, CancellationToken::new())
            .await,
        Err(StoreError::Cancelled)
    ));
    assert_eq!(mock.created(), 0);
    mock.shutdown().await?;
    Ok(())
}

#[test]
fn invalid_records_and_limits_are_not_authority() {
    assert!(ExpectedUpload::from_record(b"{}").is_err());
    assert!(ExpectedUpload::from_record(&vec![0; 2_097_153]).is_err());
    for field in 0..4 {
        let mut limits = options();
        match field {
            0 => limits.bucket.clear(),
            1 => limits.multipart_threshold = 5_000_000_000,
            2 => limits.concurrency = 0,
            _ => limits.in_flight_bytes = 1,
        }
        assert_eq!(limits.validate(), Err(StoreError::Configuration));
    }
}
