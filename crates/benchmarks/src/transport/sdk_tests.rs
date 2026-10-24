//! Actual SDK/local-HTTP transport controls; these do NOT benchmark the G/F pipeline.
use std::{
    fs::Permissions,
    io::{Read as _, Write as _},
    os::unix::fs::PermissionsExt as _,
    sync::Arc,
};

use disk_archive_storage::{
    BlockingPool, CancellationToken, ChecksumPolicy, ObjectStore, PrepareOptions, PreparedUpload,
    SdkStore, StoreOptions, UploadPreparer,
    prepare::metadata_identity,
    test_support::{FaultType, MockS3, Occurrence},
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{Bindings, MeasuringProxy, SizeClass};

async fn prepare(
    work: &tempfile::TempDir,
    preparer: &UploadPreparer,
    input: &[u8],
    key: &str,
) -> Result<PreparedUpload, Box<dyn std::error::Error>> {
    let mut file = tempfile::tempfile_in(work.path())?;
    file.write_all(input)?;
    let identity = metadata_identity(&file.metadata()?, Sha256::digest(input).into())?;
    Ok(preparer
        .prepare(file, identity, key.into(), CancellationToken::new())
        .await?)
}

fn incompressible(size: usize) -> Zeroizing<Vec<u8>> {
    let mut state = 488_u64;
    Zeroizing::new(
        (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes().first().copied().unwrap_or(0)
            })
            .collect(),
    )
}

fn assert_drained(
    proxy: &MeasuringProxy,
    bindings: &Bindings,
) -> Result<(), super::ObservationError> {
    let observed = proxy
        .observation
        .0
        .lock()
        .map_err(|_| super::ObservationError)?;
    assert!(
        !observed.poisoned,
        "complete SDK traffic must not poison observation"
    );
    assert_eq!(observed.active, 0, "SDK store drained active requests");
    assert_eq!(observed.bodies, 0, "SDK store drained request bodies");
    assert!(
        observed
            .routes
            .keys()
            .all(|path| bindings.routes.contains_key(path)),
        "independent bindings cover every SDK route"
    );
    Ok(())
}

// Independent unmeasured download checks actual stored gzip and original bytes.
async fn verify_download(
    mock: &MockS3,
    upload: &PreparedUpload,
    input: &[u8],
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = mock
        .client()
        .get_object()
        .bucket("synthetic-archive")
        .key(key)
        .send()
        .await?;
    let gzip = response.body.collect().await?.into_bytes();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&gzip)),
        upload.expected().gzip_sha256
    );
    let mut decoded = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(gzip.as_ref())
        .take(u64::try_from(input.len())? + 1)
        .read_to_end(&mut decoded)?;
    // Keep even synthetic payload bytes out of panic diagnostics.
    if decoded.as_slice() != input {
        return Err(super::ObservationError.into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vetted_sdk_single_retry_multipart_manifest_have_observed_http_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let mock = MockS3::start().await?;
    let proxy = MeasuringProxy::around_mock(&mock).await?;
    let options = StoreOptions {
        bucket: "synthetic-archive".into(),
        multipart_threshold: 5_242_880,
        part_size: 5_242_880,
        concurrency: 2,
        in_flight_bytes: 32 * 1_048_576,
    };
    let store = SdkStore::new(proxy.client(&mock), options.clone())?;
    let work = tempfile::tempdir()?;
    tokio::fs::set_permissions(work.path(), Permissions::from_mode(0o700)).await?;
    let counters = Arc::new(disk_archive_metrics::Counters::default());
    let preparer = UploadPreparer::new(
        PrepareOptions {
            bucket: options.bucket,
            work_dir: work.path().into(),
            disk_budget: 32 * 1_048_576,
            max_spool_bytes: 16 * 1_048_576,
            multipart_threshold: options.multipart_threshold,
            part_size: options.part_size,
            checksum: ChecksumPolicy::Crc64Nvme,
        },
        BlockingPool::new(2)?,
    )?
    .with_counters(counters.clone());
    let small = b"public synthetic SDK body\n";
    let large = incompressible(6 * 1_048_576);
    let mut expected_bytes = 0_u64;
    let mut largest_gzip = 0_u64;
    let mut bindings = Bindings::default();
    for (slot, key, input, class, copies) in [
        (7, "archive/small.gz", &small[..], SizeClass::Single, 1_u64),
        (9, "archive/retry.gz", &small[..], SizeClass::Single, 2),
        (2, "archive/large.gz", &large[..], SizeClass::Multipart, 1),
    ] {
        let upload = prepare(&work, &preparer, input, key).await?;
        if class == SizeClass::Multipart {
            assert!(upload.expected().gzip_size >= options.multipart_threshold);
        }
        expected_bytes += upload.expected().gzip_size * copies;
        largest_gzip = largest_gzip.max(upload.expected().gzip_size);
        if copies == 2 {
            mock.server.insert_fault(
                "synthetic-archive",
                key,
                FaultType::ServiceError { status: 503 },
                0,
                Occurrence::Once,
            );
        }
        store
            .put_object_verified(&upload, CancellationToken::new())
            .await?;
        verify_download(&mock, &upload, input, key).await?;
        bindings.archive(&format!("/synthetic-archive/{key}"), slot, class)?;
    }
    let manifest = b"{\"format\":\"synthetic-control\"}";
    store
        .put_manifest("manifest/root.json", manifest, CancellationToken::new())
        .await?;
    bindings.manifest("/synthetic-archive/manifest/root.json", 0)?;
    store.drain().await?;
    drop(store);
    assert_eq!(preparer.reserved_disk_bytes(), 0);
    let resources = counters.snapshot().map_err(|_| super::ObservationError)?;
    assert!(resources.peak_temp_bytes >= largest_gzip);
    assert!(resources.peak_temp_bytes > options.multipart_threshold);
    assert_drained(&proxy, &bindings)?;
    let stats = proxy.finish(&bindings).await?;
    assert_eq!(stats.requests.get("single/archive-000007"), Some(&2));
    assert_eq!(stats.requests.get("single/archive-000009"), Some(&3));
    assert_eq!(stats.requests.get("multipart/archive-000002"), Some(&5));
    assert_eq!(stats.requests.get("single/manifest-000000"), Some(&2));
    assert_eq!(stats.bytes_uploaded, expected_bytes);
    assert_eq!(stats.manifest_bytes, u64::try_from(manifest.len())?);
    assert!(stats.control_bytes > 0);
    assert!(
        stats.wire_body_bytes >= stats.bytes_uploaded + stats.manifest_bytes + stats.control_bytes
    );
    mock.shutdown().await?;
    Ok(())
}
