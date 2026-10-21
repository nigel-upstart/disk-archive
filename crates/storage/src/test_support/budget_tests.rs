use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use super::tests::{corpus, options, prepare, preparer, workdir};
use super::{FaultType, MockS3, Occurrence};
use crate::{
    BlockingPool, CancellationToken, ChecksumPolicy, ObjectStore, SdkStore, StoreError,
    UploadPreparer,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_drop_retains_blocking_cpu_permit_until_worker_exits() -> TestResult {
    let pool = BlockingPool::new(1)?;
    let (started, ready) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let worker_pool = pool.clone();
    let task = tokio::spawn(async move {
        worker_pool
            .run(CancellationToken::new(), move |_| {
                let _ = started.send(());
                blocked.recv().map_err(|_| StoreError::Worker)
            })
            .await
    });
    ready.await?;
    assert_eq!(pool.available(), 0);
    task.abort();
    assert!(task.await.is_err());
    assert_eq!(pool.available(), 0);
    release.send(())?;
    tokio::time::timeout(Duration::from_secs(3), async {
        while pool.available() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(pool.available(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cloned_preparers_share_disk_quota_and_cancel_waiters() -> TestResult {
    let work = workdir()?;
    let mut limits = preparer_options(&work);
    limits.disk_budget = 65_536;
    limits.max_spool_bytes = 65_536;
    let prep = UploadPreparer::new(limits, BlockingPool::new(1)?)?;
    let upload = prepare(&work, &prep, b"small synthetic bytes", "first.gz").await?;
    assert_eq!(prep.reserved_disk_bytes(), 65_536);
    let clone = prep.clone();
    let mut file = tempfile::tempfile_in(work.path())?;
    std::io::Write::write_all(&mut file, b"second")?;
    let identity =
        crate::prepare::metadata_identity(&file.metadata()?, Sha256::digest(b"second").into())?;
    let cancel = CancellationToken::new();
    let child = cancel.clone();
    let task = tokio::spawn(async move {
        clone
            .prepare(file, identity, "second.gz".into(), child)
            .await
    });
    tokio::task::yield_now().await;
    cancel.cancel();
    assert!(matches!(task.await?, Err(StoreError::Cancelled)));
    assert_eq!(prep.reserved_disk_bytes(), 65_536);
    drop(upload);
    assert_eq!(prep.reserved_disk_bytes(), 0);
    let mut invalid = preparer_options(&work);
    invalid.disk_budget = 0;
    assert!(UploadPreparer::new(invalid, BlockingPool::new(1)?).is_err());
    Ok(())
}

pub(super) fn preparer_options(work: &tempfile::TempDir) -> crate::PrepareOptions {
    crate::PrepareOptions {
        bucket: options().bucket,
        work_dir: work.path().to_owned(),
        disk_budget: 64 * 1_048_576,
        max_spool_bytes: 32 * 1_048_576,
        multipart_threshold: options().multipart_threshold,
        part_size: options().part_size,
        checksum: ChecksumPolicy::Crc64Nvme,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_cloned_stores_share_one_payload_admission_domain() -> TestResult {
    let mock = MockS3::start().await?;
    let mut limits = options();
    limits.in_flight_bytes = 8 * 1_048_576;
    let store = SdkStore::new(mock.client(), limits.clone())?;
    let work = workdir()?;
    let prep = preparer(&work, ChecksumPolicy::Crc64Nvme)?;
    let upload = Arc::new(prepare(&work, &prep, &corpus(12 * 1_048_576), "budget.gz").await?);
    mock.server.insert_fault(
        "synthetic-archive",
        "budget.gz",
        FaultType::StallRequestRead { after_bytes: 0 },
        0,
        Occurrence::Always,
    );
    let cancel = CancellationToken::new();
    let mut jobs = Vec::new();
    for _ in 0..3 {
        let store = store.clone();
        let upload = upload.clone();
        let token = cancel.clone();
        jobs.push(tokio::spawn(async move {
            store.put_object_verified(&upload, token).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(8), async {
        while mock.parts() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(store.payload_bytes_reserved() > 0);
    assert!(store.payload_bytes_reserved() <= u64::try_from(limits.in_flight_bytes)?);
    cancel.cancel();
    for task in jobs {
        assert!(task.await?.is_err());
    }
    store.drain().await?;
    // Hyper may retain a cancelled request-body frame until its connection retires.
    // That storage remains CHARGED, never recycled past the global ceiling.
    assert!(store.payload_bytes_reserved() <= u64::try_from(limits.in_flight_bytes)?);
    assert_eq!(mock.created(), mock.aborted());
    mock.shutdown().await?;
    Ok(())
}
