use super::budget_tests::preparer_options;
use super::tests::{prepare, workdir};
use crate::{BlockingPool, CancellationToken, StoreError, UploadPreparer};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
