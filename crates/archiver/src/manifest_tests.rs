//! Real SDK/HTTP regression, larger than both 400 historical rows and one manifest payload.

use std::{collections::BTreeMap, time::Duration};

use disk_archive_storage::{SdkStore, StoreOptions, test_support::MockS3};

use super::*;
use crate::state::{Row, Status};

async fn get(mock: &MockS3, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = mock
        .client()
        .get_object()
        .bucket("synthetic-archive")
        .key(key)
        .send()
        .await?
        .body
        .collect()
        .await?
        .into_bytes();
    assert!(bytes.len() <= MAX_MANIFEST_PAGE);
    Ok(bytes.to_vec())
}

#[test]
fn all_history_streams_through_real_store_without_a_lifetime_payload_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let database = temp.path().canonicalize()?.join("state.sqlite");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mock = MockS3::start().await?;
        let store = SdkStore::new(
            mock.client(),
            StoreOptions {
                bucket: "synthetic-archive".into(),
                multipart_threshold: 8 * 1_048_576,
                part_size: 8 * 1_048_576,
                concurrency: 2,
                in_flight_bytes: 32 * 1_048_576,
            },
        )?;
        let (writer, _, task) = Writer::start(database, 1, 32, Duration::from_millis(10)).await?;
        for ordinal in 0..600 {
            writer
                .update(Row {
                    key: format!("synthetic/v1/item-{ordinal:04}.gz"),
                    path: format!("/synthetic/item-{ordinal:04}").into_bytes(),
                    status: Status::Error, // plausible failed scan/preparation, not fake delete authority
                    detectors: (0..32)
                        .map(|n| (format!("synthetic.detector-{n:02}-{}", "x".repeat(65)), 1))
                        .collect::<BTreeMap<_, _>>(),
                    expected: None,
                })
                .await?;
        }
        let pool = BlockingPool::new(1)?;
        let root_key = "synthetic/manifests/history-regression.json";
        // A one-entry index forces the same streaming code to emit several bounded index pages
        // without allocating a 512 MiB test corpus. Production uses 512 entries per index.
        publish_with_index_limit(
            &writer,
            &store,
            &pool,
            root_key,
            CancellationToken::new(),
            1,
        )
        .await?;
        store.drain().await?;
        let body = get(&mock, root_key).await?;
        assert!(body.len() <= MAX_MANIFEST_PAGE);
        let root: Root = serde_json::from_slice(&body)?;
        assert_eq!(root.format, "disk-archive-manifest-v2");
        assert_eq!(root.rows, 600);
        assert!(root.data_parts >= 2);
        assert!(root.index_pages >= 2);
        let mut chain = Sha256::new();
        let mut observed = std::collections::BTreeSet::new();
        let mut observed_parts = 0;
        for ordinal in 0..root.index_pages {
            let key = format!("{root_key}.parts/index-{ordinal:020}.json");
            let bytes = get(&mock, &key).await?;
            assert!(bytes.len() <= MAX_MANIFEST_PAGE);
            chain.update(u64::try_from(bytes.len())?.to_be_bytes());
            chain.update(&bytes);
            let index: Index = serde_json::from_slice(&bytes)?;
            assert_eq!(index.parts.len(), 1);
            for part in index.parts {
                let key = format!("{root_key}.parts/{}", part.name);
                let bytes = get(&mock, &key).await?;
                assert!(bytes.len() <= MAX_MANIFEST_PAGE);
                let digest: [u8; 32] = Sha256::digest(&bytes).into();
                assert_eq!(digest, part.sha256);
                let rows: Vec<Row> = serde_json::from_slice(&bytes)?;
                assert_eq!(u64::try_from(rows.len())?, part.rows);
                for row in rows {
                    assert!(observed.insert(row.key));
                }
                observed_parts += 1;
            }
        }
        assert_eq!(observed.len(), 600);
        assert_eq!(observed_parts, root.data_parts);
        let digest: [u8; 32] = chain.finalize().into();
        assert_eq!(digest, root.index_chain_sha256);
        writer.finish().await?;
        task.await??;
        drop(store);
        mock.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn reserved_names_fit_before_work_begins() {
    assert!(validate_key(&"x".repeat(986)).is_ok());
    assert_eq!(validate_key(&"x".repeat(987)), Err(Error::Configuration));
}
