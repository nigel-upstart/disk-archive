use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use tokio::sync::Semaphore;

use super::{
    MockS3,
    budget_tests::preparer_options,
    tests::{options, workdir},
};
use crate::{
    BlockingPool, CancellationToken, ObjectStore, SdkStore, SourceIdentity, StoreError,
    UploadPreparer, prepare::metadata_identity,
};

fn source(
    work: &TempDir,
    bytes: &[u8],
) -> Result<(File, SourceIdentity), Box<dyn std::error::Error>> {
    let mut file = tempfile::tempfile_in(work.path())?;
    file.write_all(bytes)?;
    let identity = metadata_identity(&file.metadata()?, Sha256::digest(bytes).into())?;
    Ok((file, identity))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disk_waiter_cannot_starve_final_hash_at_shared_cpu_capacity_one()
-> Result<(), Box<dyn std::error::Error>> {
    let mock = MockS3::start().await?;
    let mut store_limits = options();
    store_limits.concurrency = 1;
    store_limits.in_flight_bytes = 6 * 1_048_576;
    let store = SdkStore::new(mock.client(), store_limits)?;
    let work = workdir()?;
    let cpu = BlockingPool::from_shared(Arc::new(Semaphore::new(1)));
    let mut limits = preparer_options(&work);
    limits.disk_budget = 65_536;
    limits.max_spool_bytes = 65_536;
    let prep = UploadPreparer::new(limits, cpu.clone())?;
    let (first_source, first_identity) = source(&work, b"synthetic first file")?;
    let mut final_source = first_source.try_clone()?;
    let first = prep
        .prepare(
            first_source,
            first_identity,
            "order/first.gz".into(),
            CancellationToken::new(),
        )
        .await?;
    assert_eq!(prep.reserved_disk_bytes(), 65_536);
    assert_eq!(cpu.available(), 1);
    let (second_source, second_identity) = source(&work, b"synthetic second file")?;
    let (started, ready) = tokio::sync::oneshot::channel();
    let clone = prep.clone();
    let second_job = tokio::spawn(async move {
        let _ = started.send(());
        clone
            .prepare(
                second_source,
                second_identity,
                "order/second.gz".into(),
                CancellationToken::new(),
            )
            .await
    });
    ready.await?;
    tokio::task::yield_now().await;
    assert!(!second_job.is_finished());
    assert_eq!(
        cpu.available(),
        1,
        "disk waiter must not own the final-hash CPU permit"
    );
    let token = store
        .put_object_verified(&first, CancellationToken::new())
        .await?;
    let permit = tokio::time::timeout(
        Duration::from_secs(3),
        cpu.run(CancellationToken::new(), move |_| {
            final_source
                .seek(SeekFrom::Start(0))
                .map_err(|_| StoreError::Io)?;
            let mut bytes = Vec::new();
            final_source
                .read_to_end(&mut bytes)
                .map_err(|_| StoreError::Io)?;
            let current = metadata_identity(
                &final_source.metadata().map_err(|_| StoreError::Io)?,
                Sha256::digest(&bytes).into(),
            )?;
            disk_archive_verified::lifecycle::authorize_delete(token, &current)
                .map_err(|_| StoreError::Integrity)
        }),
    )
    .await??;
    assert_eq!(permit.source(), &first_identity);
    drop(first); // G releases prepared quota after final hash/commit/delete disposition.
    let second = tokio::time::timeout(Duration::from_secs(3), second_job).await???;
    assert_eq!(prep.reserved_disk_bytes(), 65_536);
    store
        .put_object_verified(&second, CancellationToken::new())
        .await?;
    drop(second);
    store.drain().await?;
    assert_eq!(prep.reserved_disk_bytes(), 0);
    assert_eq!(cpu.available(), 1);
    mock.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_source_fails_before_cpu_or_partial_spool()
-> Result<(), Box<dyn std::error::Error>> {
    let work = workdir()?;
    let shared = Arc::new(Semaphore::new(1));
    let hold = shared.clone().acquire_owned().await?;
    let mut limits = preparer_options(&work);
    limits.disk_budget = 65_536;
    limits.max_spool_bytes = 65_536;
    let prep = UploadPreparer::new(limits, BlockingPool::from_shared(shared))?;
    let (file, identity) = source(&work, &vec![b'x'; 65_536])?;
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        prep.prepare(
            file,
            identity,
            "oversize.gz".into(),
            CancellationToken::new(),
        ),
    )
    .await?;
    assert!(matches!(result, Err(StoreError::Budget)));
    assert_eq!(prep.reserved_disk_bytes(), 0);
    drop(hold);
    Ok(())
}
