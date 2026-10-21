use std::fs::Permissions;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;

use super::budget_tests::preparer_options;
use super::tests::{corpus, preparer, workdir};
use crate::{
    BlockingPool, CancellationToken, ChecksumPolicy, StoreError, UploadPreparer,
    prepare::metadata_identity,
};
use sha2::{Digest as _, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparer_denies_wrong_content_hash_quota_and_unsafe_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let work = workdir()?;
    let prep = preparer(&work, ChecksumPolicy::Crc64Nvme)?;
    let mut file = tempfile::tempfile_in(work.path())?;
    file.write_all(b"synthetic")?;
    let identity = metadata_identity(&file.metadata()?, [0; 32])?;
    assert!(matches!(
        prep.prepare(file, identity, "hash.gz".into(), CancellationToken::new())
            .await,
        Err(StoreError::SourceChanged)
    ));
    assert_eq!(prep.reserved_disk_bytes(), 0);

    let mut limits = preparer_options(&work);
    limits.disk_budget = 65_536;
    limits.max_spool_bytes = 65_536;
    let prep = UploadPreparer::new(limits, BlockingPool::new(1)?)?;
    let bytes = corpus(1_048_576);
    let mut file = tempfile::tempfile_in(work.path())?;
    file.write_all(&bytes)?;
    let identity = metadata_identity(&file.metadata()?, Sha256::digest(&bytes).into())?;
    assert!(matches!(
        prep.prepare(file, identity, "quota.gz".into(), CancellationToken::new())
            .await,
        Err(StoreError::Budget)
    ));
    assert_eq!(prep.reserved_disk_bytes(), 0);

    let mut file = tempfile::tempfile_in(work.path())?;
    file.write_all(b"synthetic")?;
    let identity = metadata_identity(&file.metadata()?, Sha256::digest(b"synthetic").into())?;
    tokio::fs::set_permissions(work.path(), Permissions::from_mode(0o755)).await?;
    assert!(matches!(
        prep.prepare(
            file,
            identity,
            "unsafe-directory.gz".into(),
            CancellationToken::new()
        )
        .await,
        Err(StoreError::Configuration)
    ));
    assert_eq!(prep.reserved_disk_bytes(), 0);
    Ok(())
}
