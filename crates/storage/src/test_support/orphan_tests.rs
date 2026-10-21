use super::budget_tests::preparer_options;
use super::tests::{prepare, workdir};
use crate::{BlockingPool, CancellationToken, StoreError, UploadPreparer};

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn rejects_permanently_unsatisfiable_spool(orphan_size: u64, bytes: &[u8]) -> TestResult {
    let work = workdir()?;
    let old = work.path().join("archive-synthetic-crash.gz");
    tokio::fs::File::create(&old)
        .await?
        .set_len(orphan_size)
        .await?;
    let mut options = preparer_options(&work);
    options.disk_budget = 2 * 65_536;
    options.max_spool_bytes = 2 * 65_536;
    let cpu = BlockingPool::new(1)?;
    let prep = UploadPreparer::new(options, cpu.clone())?;
    // G explicitly accounts after acquiring its Work lock, before preparing sources.
    prep.account_existing_spools(CancellationToken::new())
        .await?;
    let permanent_bytes = orphan_size.div_ceil(65_536) * 65_536;
    assert_eq!(prep.reserved_disk_bytes(), permanent_bytes);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        prepare(&work, &prep, bytes, "cannot-fit.gz"),
    )
    .await?;
    let error = result
        .err()
        .ok_or("impossible reservation unexpectedly succeeded")?;
    assert_eq!(
        error.downcast_ref::<StoreError>(),
        Some(&StoreError::Budget)
    );
    assert_eq!(prep.reserved_disk_bytes(), permanent_bytes);
    assert_eq!(cpu.available(), 1);
    assert_eq!(tokio::fs::metadata(old).await?.len(), orphan_size);
    Ok(())
}

#[tokio::test]
async fn full_orphan_quota_rejects_preparation_instead_of_waiting_forever() -> TestResult {
    rejects_permanently_unsatisfiable_spool(2 * 65_536, b"synthetic").await
}

#[tokio::test]
async fn partial_orphan_remainder_rejects_larger_reservation_instead_of_waiting_forever()
-> TestResult {
    // Only one unit remains; this source's conservative bound requires two units.
    rejects_permanently_unsatisfiable_spool(1, &vec![b's'; 65_536]).await
}

#[tokio::test]
async fn crash_spools_are_charged_once_before_live_spools_across_clones() -> TestResult {
    let work = workdir()?;
    let old = work.path().join("archive-synthetic-crash.gz");
    tokio::fs::write(&old, b"synthetic derived gzip placeholder").await?;
    let mut options = preparer_options(&work);
    options.disk_budget = 2 * 65_536;
    options.max_spool_bytes = 65_536;
    let prep = UploadPreparer::new(options, BlockingPool::new(1)?)?;
    let upload = prepare(&work, &prep, b"synthetic", "new.gz").await?;
    assert_eq!(prep.reserved_disk_bytes(), 2 * 65_536);
    prep.clone()
        .account_existing_spools(CancellationToken::new())
        .await?;
    assert_eq!(prep.reserved_disk_bytes(), 2 * 65_536);
    drop(upload);
    assert_eq!(prep.reserved_disk_bytes(), 65_536);
    assert!(old.is_file());
    Ok(())
}

#[tokio::test]
async fn oversized_or_symlinked_crash_spools_fail_closed_without_removal() -> TestResult {
    for link in [false, true] {
        let work = workdir()?;
        let old = work.path().join("archive-synthetic-crash.gz");
        if link {
            tokio::fs::symlink(work.path().join("absent"), &old).await?;
        } else {
            tokio::fs::File::create(&old).await?.set_len(65_537).await?;
        }
        let mut options = preparer_options(&work);
        options.disk_budget = 65_536;
        options.max_spool_bytes = 65_536;
        let prep = UploadPreparer::new(options, BlockingPool::new(1)?)?;
        let result = prep.account_existing_spools(CancellationToken::new()).await;
        assert_eq!(
            result,
            Err(if link {
                StoreError::Configuration
            } else {
                StoreError::Budget
            })
        );
        assert_eq!(prep.reserved_disk_bytes(), 0);
        assert!(tokio::fs::symlink_metadata(old).await.is_ok());
    }
    Ok(())
}
