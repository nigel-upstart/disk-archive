//! Genuine gzip append/lifetime accounting; no compressed-size estimate is used by production.
use std::io::Write as _;
use std::sync::Arc;

use disk_archive_metrics::Counters;
use sha2::{Digest as _, Sha256};

use super::tests::{prepare, preparer, workdir};
type TestResult = Result<(), Box<dyn std::error::Error>>;
use crate::{CancellationToken, ChecksumPolicy, StoreError, prepare::metadata_identity};

#[tokio::test]
async fn successful_spool_is_counted_until_its_last_retained_owner() -> TestResult {
    let work = workdir()?;
    let counters = Arc::new(Counters::default());
    let prep = preparer(&work, ChecksumPolicy::Crc64Nvme)?.with_counters(counters.clone());
    let upload = prepare(&work, &prep, b"synthetic temporary lifetime", "metrics.gz").await?;
    let size = upload.expected().gzip_size;
    assert_eq!(std::fs::metadata(upload.path()?)?.len(), size);
    let retained = upload.spool.clone();
    let path = upload.path()?.to_owned();
    drop(upload);
    assert!(counters.snapshot().is_err());
    assert!(path.is_file());
    drop(retained);
    assert!(!path.exists());
    assert_eq!(
        counters.snapshot().map_err(|_| "snapshot")?.peak_temp_bytes,
        size
    );
    Ok(())
}

#[tokio::test]
async fn changed_source_after_actual_writes_cleans_up_exact_resources() -> TestResult {
    let work = workdir()?;
    let counters = Arc::new(Counters::default());
    let prep = preparer(&work, ChecksumPolicy::Crc64Nvme)?.with_counters(counters.clone());
    let mut source = tempfile::tempfile_in(work.path())?;
    source.write_all(b"synthetic wrong hash")?;
    let identity = metadata_identity(&source.metadata()?, Sha256::digest(b"different").into())?;
    let result = prep
        .prepare(
            source,
            identity,
            "changed.gz".into(),
            CancellationToken::new(),
        )
        .await;
    assert!(matches!(result, Err(StoreError::SourceChanged)));
    assert!(counters.snapshot().map_err(|_| "snapshot")?.peak_temp_bytes > 0);
    assert_eq!(std::fs::read_dir(work.path())?.count(), 0);
    assert_eq!(prep.reserved_disk_bytes(), 0);
    Ok(())
}

#[tokio::test]
async fn cancelled_preparation_and_failed_cleanup_cannot_report_fake_zero() -> TestResult {
    let work = workdir()?;
    let counters = Arc::new(Counters::default());
    let prep = preparer(&work, ChecksumPolicy::Crc64Nvme)?.with_counters(counters.clone());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut source = tempfile::tempfile_in(work.path())?;
    source.write_all(b"synthetic cancel")?;
    let identity = metadata_identity(
        &source.metadata()?,
        Sha256::digest(b"synthetic cancel").into(),
    )?;
    assert!(matches!(
        prep.prepare(source, identity, "cancel.gz".into(), cancel)
            .await,
        Err(StoreError::Cancelled)
    ));
    assert_eq!(
        counters.snapshot().map_err(|_| "snapshot")?.peak_temp_bytes,
        0
    );
    let upload = prepare(&work, &prep, b"synthetic cleanup failure", "cleanup.gz").await?;
    let path = upload.path()?.to_owned();
    tokio::fs::rename(&path, work.path().join("synthetic-retained-spool")).await?;
    tokio::fs::create_dir(&path).await?; // synthetic unremovable-as-file replacement
    drop(upload);
    assert!(counters.snapshot().is_err());
    tokio::fs::remove_dir(path).await?;
    Ok(())
}
