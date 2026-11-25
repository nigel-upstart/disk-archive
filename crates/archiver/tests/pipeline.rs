//! Synthetic `ObjectStore` control-flow tests plus a separately named real-HTTP/native test.
//! `UnitStore` tests do not claim transport coverage. The CLI always uses the native scanner.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, FileTimes};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, UNIX_EPOCH};

use disk_archive::{
    Error,
    blocking::BlockingPool,
    pipeline::{self, Options, Services},
    scanner::{Finding, ScanEngine, ScanReport},
    state::Row,
};
use disk_archive_core::config::{Config, Environment};
use disk_archive_metrics::Counters;
use disk_archive_storage::{
    CancellationToken, ExpectedUpload, HeadEvidence, ObjectStore, PreparedUpload, StoreError,
    StoreFuture, UploadPreparer, VerifiedUpload, evidence,
    prepare::{ChecksumPolicy, PrepareOptions},
};

#[path = "support/encoding.rs"]
mod native_encoding;

struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    work: PathBuf,
}
impl Fixture {
    fn new(count: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let base = temp.path().canonicalize()?;
        let root = base.join("root");
        std::fs::create_dir(&root)?;
        for n in 0..count {
            let path = root.join(format!("{n}.jsonl"));
            std::fs::write(&path, b"safe prefix synthetic-secret-value suffix\n")?;
            File::open(path)?.set_times(
                FileTimes::new()
                    .set_accessed(UNIX_EPOCH + Duration::from_secs(1))
                    .set_modified(UNIX_EPOCH + Duration::from_secs(2)),
            )?;
        }
        let work = base.join("work");
        Ok(Self {
            _temp: temp,
            base,
            root,
            work,
        })
    }
    fn config(&self) -> Result<Config, Error> {
        let env = Environment::from_pairs(
            [
                ("DISK_ARCHIVE_BUCKET", "synthetic-archive".to_owned()),
                ("DISK_ARCHIVE_PREFIX", "synthetic".to_owned()),
                (
                    "DISK_ARCHIVE_ROOTS_ALL_FILES",
                    self.root.to_string_lossy().into_owned(),
                ),
                (
                    "DISK_ARCHIVE_WORK_DIR",
                    self.work.to_string_lossy().into_owned(),
                ),
                ("DISK_ARCHIVE_MIN_AGE_DAYS", "0".to_owned()),
            ]
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        );
        Config::load(None, &self.base, &env).map_err(|_| Error::Configuration)
    }
    fn store(&self) -> UnitStore {
        UnitStore {
            objects: Mutex::default(),
            puts: AtomicUsize::new(0),
            started: AtomicUsize::new(0),
            drains: AtomicUsize::new(0),
            verify_fault: Mutex::new(None),
            manifests: AtomicUsize::new(0),
            heads: AtomicUsize::new(0),
            fault: AtomicUsize::new(usize::MAX),
            database: self.work.join("state.sqlite"),
            delay: Duration::ZERO,
            verify_delay: Duration::ZERO,
            mutation: None,
        }
    }
    fn services(
        &self,
        store: Arc<dyn ObjectStore>,
        scanner: Arc<dyn ScanEngine>,
    ) -> Result<Services, Error> {
        let pool = BlockingPool::new(1)?;
        let preparer = UploadPreparer::new(
            PrepareOptions {
                bucket: "synthetic-archive".into(),
                work_dir: self.work.clone(),
                disk_budget: 16 * 1_048_576,
                max_spool_bytes: 1_048_576,
                multipart_threshold: 8 * 1_048_576,
                part_size: 8 * 1_048_576,
                checksum: ChecksumPolicy::Crc64Nvme,
            },
            disk_archive_storage::blocking::BlockingPool::from_shared(pool.semaphore()),
        )
        .map_err(|_| Error::Store)?;
        Ok(Services {
            pool,
            scanner,
            store,
            preparer,
            counters: Arc::new(Counters::default()),
        })
    }
    fn remaining(&self) -> Result<usize, std::io::Error> {
        Ok(std::fs::read_dir(&self.root)?.count())
    }
}

fn options() -> Options {
    Options {
        workers: 1,
        queue_capacity: 1,
        cpu_jobs: 1,
        max_file_bytes: 65_536,
        limit: None,
        quiescent: true,
    }
}

struct SyntheticScanner;
impl ScanEngine for SyntheticScanner {
    fn scan(
        &self,
        input: &mut dyn Read,
        consume: &mut dyn FnMut(Finding<'_>) -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        let mut bytes = Vec::new();
        input
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Blocked)?;
        if bytes.len() > 65_536 {
            return Err(Error::Budget);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::Blocked)?;
        let mut findings = 0;
        for (index, line) in text.lines().enumerate() {
            if line.contains("synthetic-secret-value") {
                consume(Finding {
                    rule_id: "synthetic.rule",
                    label: "synthetic-rule",
                    line: u64::try_from(index + 1).map_err(|_| Error::Budget)?,
                    raw: "synthetic-secret-value",
                })?;
                findings += 1;
            }
        }
        Ok(ScanReport {
            bytes: u64::try_from(bytes.len()).map_err(|_| Error::Budget)?,
            findings,
        })
    }
}

struct FallbackScanner {
    calls: AtomicUsize,
    remain_after_fallback: bool,
}
impl ScanEngine for FallbackScanner {
    fn scan(
        &self,
        input: &mut dyn Read,
        consume: &mut dyn FnMut(Finding<'_>) -> Result<(), Error>,
    ) -> Result<ScanReport, Error> {
        let mut bytes = Vec::new();
        input
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Blocked)?;
        if bytes.len() > 65_536 {
            return Err(Error::Budget);
        }
        let stage = self.calls.fetch_add(1, Ordering::SeqCst);
        let finding = stage <= 1 || self.remain_after_fallback;
        if finding {
            consume(Finding {
                rule_id: "synthetic.rule",
                label: "synthetic-rule",
                line: 1,
                raw: if stage == 0 {
                    "synthetic-secret-value"
                } else {
                    "[REDACTED-synthetic-rule]"
                },
            })?;
        }
        Ok(ScanReport {
            bytes: u64::try_from(bytes.len()).map_err(|_| Error::Budget)?,
            findings: u64::from(finding),
        })
    }
}

struct UnitStore {
    objects: Mutex<BTreeMap<String, ExpectedUpload>>,
    puts: AtomicUsize,
    started: AtomicUsize,
    drains: AtomicUsize,
    verify_fault: Mutex<Option<StoreError>>,
    manifests: AtomicUsize,
    heads: AtomicUsize,
    // 0: cancel before put; 1: cancel after remote commit; 2: return verified token but cancel;
    // 3: corrupt actual HEAD checksum; MAX: normal. This is not an HTTP transport mock.
    fault: AtomicUsize,
    database: PathBuf,
    delay: Duration,
    verify_delay: Duration,
    mutation: Option<PathBuf>,
}

impl ObjectStore for UnitStore {
    fn put_object_verified<'a>(
        &'a self,
        upload: &'a PreparedUpload,
        cancel: CancellationToken,
    ) -> StoreFuture<'a, VerifiedUpload> {
        Box::pin(async move {
            self.started.fetch_add(1, Ordering::SeqCst);
            if cancel.is_cancelled() {
                return Err(StoreError::Cancelled);
            }
            let path = self.database.clone();
            let expected = upload.expected().clone();
            let intent = expected.to_record()?;
            let key = expected.key.clone();
            // Independently inspect committed WAL state BEFORE the modeled remote side effect.
            BlockingPool::new(1)
                .map_err(|_| StoreError::Worker)?
                .run(&CancellationToken::new(), move || {
                    let db = rusqlite::Connection::open_with_flags(
                        path,
                        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                    )
                    .map_err(|_| Error::Io)?;
                    let bytes: Vec<u8> = db
                        .query_row("SELECT record FROM files WHERE key=?1", [key], |r| r.get(0))
                        .map_err(|_| Error::Io)?;
                    let row: Row = serde_json::from_slice(&bytes).map_err(|_| Error::Io)?;
                    if row.expected != Some(intent) {
                        return Err(Error::Store);
                    }
                    Ok(())
                })
                .await
                .map_err(|_| StoreError::Integrity)?;
            let fault = self.fault.swap(usize::MAX, Ordering::SeqCst);
            if fault == 0 {
                cancel.cancel();
                return Err(StoreError::Cancelled);
            }
            tokio::time::sleep(self.delay).await;
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.objects
                .lock()
                .map_err(|_| StoreError::Worker)?
                .insert(expected.key.clone(), expected.clone());
            if let Some(path) = &self.mutation {
                let path = path.clone();
                BlockingPool::new(1)
                    .map_err(|_| StoreError::Worker)?
                    .run(&CancellationToken::new(), move || mutate(path))
                    .await
                    .map_err(|_| StoreError::Worker)?;
            }
            if fault == 1 {
                cancel.cancel();
                return Err(StoreError::Cancelled);
            }
            let mut head = matching_head(&expected);
            if fault == 3 {
                head.checksum_value = Some("incorrect".into());
            }
            let token = evidence::verify(&expected, &head)?;
            if fault == 2 {
                cancel.cancel();
            }
            Ok(token)
        })
    }
    fn verify_existing<'a>(
        &'a self,
        expected: &'a ExpectedUpload,
        cancel: CancellationToken,
    ) -> StoreFuture<'a, VerifiedUpload> {
        let injected = self
            .verify_fault
            .lock()
            .ok()
            .and_then(|mut fault| fault.take());
        let result = if let Some(error) = injected {
            Err(error)
        } else if cancel.is_cancelled() {
            Err(StoreError::Cancelled)
        } else {
            self.heads.fetch_add(1, Ordering::SeqCst);
            self.objects
                .lock()
                .map_err(|_| StoreError::Worker)
                .and_then(|objects| {
                    let observed = objects.get(&expected.key).ok_or(StoreError::NotFound)?;
                    evidence::verify(expected, &matching_head(observed))
                })
        };
        let delay = self.verify_delay;
        Box::pin(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            result
        })
    }
    fn head<'a>(
        &'a self,
        key: &'a str,
        _version: Option<&'a str>,
        _cancel: CancellationToken,
    ) -> StoreFuture<'a, HeadEvidence> {
        let result = self
            .objects
            .lock()
            .map_err(|_| StoreError::Worker)
            .and_then(|objects| {
                objects
                    .get(key)
                    .map(matching_head)
                    .ok_or(StoreError::Integrity)
            });
        Box::pin(std::future::ready(result))
    }
    fn put_manifest<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
        cancel: CancellationToken,
    ) -> StoreFuture<'a, ()> {
        if cancel.is_cancelled() {
            return Box::pin(std::future::ready(Err(StoreError::Cancelled)));
        }
        if bytes.len() > disk_archive::state::MAX_MANIFEST_PAGE {
            return Box::pin(std::future::ready(Err(StoreError::Budget)));
        }
        // Count completed root manifests, not their data/index objects. The real SDK test
        // separately validates every uploaded page against the actual transport payload cap.
        if !key.contains(".json.parts/") {
            self.manifests.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(std::future::ready(Ok(())))
    }
    fn drain(&self) -> StoreFuture<'_, ()> {
        self.drains.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(Ok(())))
    }
}

fn matching_head(expected: &ExpectedUpload) -> HeadEvidence {
    HeadEvidence {
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
    }
}
fn mutate(path: PathBuf) -> Result<(), Error> {
    std::fs::write(path, b"synthetic concurrent change").map_err(|_| Error::Io)
}

#[test]
fn minimum_capacity_pipeline_has_backpressure_without_writer_deadlock()
-> Result<(), Box<dyn std::error::Error>> {
    // More than four inputs forces discovery to block on queue=1 while CPU producers run.
    let fixture = Fixture::new(24)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(3)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut slow = fixture.store();
        slow.delay = Duration::from_millis(5);
        let store = Arc::new(slow);
        let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
        let observed = services.counters.clone();
        let report = tokio::time::timeout(
            Duration::from_secs(30),
            pipeline::run(
                Arc::new(fixture.config()?),
                options(),
                services,
                CancellationToken::new(),
            ),
        )
        .await??;
        assert_eq!(report.deleted, 24);
        assert_eq!(report.retained, 0);
        assert!(report.peak_active_stages <= options().workers * 4);
        assert!(report.peak_live_items <= 4 * (options().workers + options().queue_capacity) + 1);
        assert!(report.peak_live_items < 24);
        assert_eq!(
            report.process_spawns,
            observed
                .snapshot()
                .map_err(|_| Error::Worker)?
                .process_spawns
        );
        assert_eq!(report.process_spawns, 0);
        assert_eq!(store.puts.load(Ordering::SeqCst), 24);
        assert_eq!(store.manifests.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.remaining()?, 0);
        Ok(())
    })
}

#[test]
fn minimum_capacity_cancellation_drains_backpressured_queues_and_writer()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(24)?;
    let mut delayed = fixture.store();
    delayed.delay = Duration::from_millis(200);
    let store = Arc::new(delayed);
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let config = Arc::new(fixture.config()?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(3)
        .enable_all()
        .build()?;
    let report = runtime.block_on(async {
        let cancel = CancellationToken::new();
        let run_cancel = cancel.clone();
        let worker = tokio::spawn(pipeline::run(config, options(), services, run_cancel));
        tokio::time::timeout(Duration::from_secs(5), async {
            while store.started.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.cancel();
        Ok::<_, Box<dyn std::error::Error>>(
            tokio::time::timeout(Duration::from_secs(5), worker).await???,
        )
    })?;
    assert!(report.cancelled);
    assert_eq!(report.deleted, 0);
    assert!(report.peak_live_items <= 9);
    assert_eq!(fixture.remaining()?, 24);
    assert_eq!(store.manifests.load(Ordering::SeqCst), 0);
    assert_eq!(store.drains.load(Ordering::SeqCst), 1);
    let _ownership_after_flush = disk_archive::work::Work::acquire(&fixture.work)?;
    Ok(())
}

#[test]
fn reappearing_generation_preserves_deleted_tombstone_and_signals_namespace_conflict()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let store = Arc::new(fixture.store());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(3)
        .enable_all()
        .build()?;
    let first = runtime.block_on(pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        fixture.services(store.clone(), Arc::new(SyntheticScanner))?,
        CancellationToken::new(),
    ))?;
    assert_eq!(first.deleted, 1);
    let before = serde_json::to_vec(&read_rows(fixture.work.join("state.sqlite"))?)?;
    let path = fixture.root.join("0.jsonl");
    std::fs::write(&path, b"new synthetic generation, retain unchanged\n")?;
    File::open(&path)?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2)))?;
    let second = runtime.block_on(pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        fixture.services(store.clone(), Arc::new(SyntheticScanner))?,
        CancellationToken::new(),
    ))?;
    assert_eq!(second.deleted, 0);
    assert_eq!(second.retained, 1);
    assert_eq!(second.namespace_conflicts, 1);
    assert_eq!(store.puts.load(Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read(&path)?,
        b"new synthetic generation, retain unchanged\n"
    );
    assert_eq!(
        serde_json::to_vec(&read_rows(fixture.work.join("state.sqlite"))?)?,
        before
    );
    Ok(())
}

#[test]
fn resume_reprepare_cannot_wait_on_spools_queued_behind_its_upload_worker()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let path = fixture.root.join("0.jsonl");
    std::fs::write(&path, vec![b'x'; 32_000])?;
    File::open(path)?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2)))?;
    let mut configured = fixture.store();
    configured.verify_delay = Duration::from_millis(200);
    let store = Arc::new(configured);
    store.fault.store(0, Ordering::SeqCst); // intent durable, remote object genuinely absent
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(3)
        .enable_all()
        .build()?;
    let interrupted = runtime.block_on(pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        fixture.services(store.clone(), Arc::new(SyntheticScanner))?,
        CancellationToken::new(),
    ))?;
    assert!(interrupted.cancelled);
    assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    let fresh = fixture.base.join("fresh");
    std::fs::create_dir(&fresh)?;
    for n in 0..2 {
        let path = fresh.join(format!("{n}.jsonl"));
        std::fs::write(&path, vec![b'x'; 32_000])?;
        File::open(path)?
            .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2)))?;
    }
    // Root order guarantees the resumed intent enters first. While its old upload-stage HEAD
    // waits, two fresh spools can occupy BOTH 64KiB slots: one queued and one blocked sender.
    let mut config = fixture.config()?;
    config.roots_all_files.push(fresh.clone());
    let mut services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    services.preparer = UploadPreparer::new(
        PrepareOptions {
            bucket: "synthetic-archive".into(),
            work_dir: fixture.work.clone(),
            disk_budget: 2 * 65_536,
            max_spool_bytes: 65_536,
            multipart_threshold: 8 * 1_048_576,
            part_size: 8 * 1_048_576,
            checksum: ChecksumPolicy::Crc64Nvme,
        },
        disk_archive_storage::BlockingPool::from_shared(services.pool.semaphore()),
    )?;
    let cancel = CancellationToken::new();
    let config = Arc::new(config);
    let result = runtime.block_on(async {
        let run = pipeline::run(config, options(), services, cancel.clone());
        tokio::pin!(run);
        if let Ok(result) = tokio::time::timeout(Duration::from_secs(2), &mut run).await {
            result
        } else {
            // Also drain the red-test run; never abandon a real CPU job or held root lock.
            cancel.cancel();
            let _ = run.await;
            Err(Error::Worker)
        }
    })?;
    assert_eq!(result.deleted, 3);
    assert_eq!(result.retained, 0);
    assert_eq!(store.puts.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.remaining()?, 0);
    assert_eq!(std::fs::read_dir(fresh)?.count(), 0);
    Ok(())
}

#[test]
fn oversized_source_fails_closed_without_upload_or_unlink() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new(1)?;
    let path = fixture.root.join("0.jsonl");
    std::fs::write(&path, vec![b'x'; 65_537])?;
    File::open(&path)?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2)))?;
    let store = Arc::new(fixture.store());
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let config = Arc::new(fixture.config()?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(3)
        .enable_all()
        .build()?;
    let report = runtime.block_on(pipeline::run(
        config,
        options(),
        services,
        CancellationToken::new(),
    ))?;
    assert_eq!(report.deleted, 0);
    assert_eq!(report.retained, 1);
    assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::metadata(path)?.len(), 65_537);
    let rows = read_rows(fixture.work.join("state.sqlite"))?;
    assert!(
        rows.iter()
            .all(|row| row.status == disk_archive::state::Status::Error && row.expected.is_none())
    );
    Ok(())
}

#[test]
fn startup_orphan_overbudget_stops_before_state_scan_or_remote_work()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let original = std::fs::read(fixture.root.join("0.jsonl"))?;
    let ownership = disk_archive::work::Work::acquire(&fixture.work)?;
    let orphan = fixture.work.join("archive-synthetic-orphan.gz");
    File::create(&orphan)?.set_len(17 * 1_048_576)?;
    drop(ownership);
    let store = Arc::new(fixture.store());
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(3)
        .enable_all()
        .build()?;
    let config = Arc::new(fixture.config()?);
    let result = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(2),
            pipeline::run(config, options(), services, CancellationToken::new()),
        )
        .await
    })?;
    assert!(matches!(result, Err(Error::Budget)));
    assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    assert_eq!(store.manifests.load(Ordering::SeqCst), 0);
    assert!(!fixture.work.join("state.sqlite").exists());
    assert!(orphan.exists());
    assert_eq!(std::fs::read(fixture.root.join("0.jsonl"))?, original);
    let _work_released = disk_archive::work::Work::acquire(&fixture.work)?;
    let _root_released = disk_archive::filesystem::Root::open(&fixture.root, false, true)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_commit_gap_resumes_without_double_upload_or_data_loss()
-> Result<(), Box<dyn std::error::Error>> {
    // Exhaustively cover remote cancellation boundaries, repeated with a deterministic seed.
    let mut seed = 17_u64;
    for _ in 0..16 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let point = usize::try_from((seed >> 32) % 3)?;
        let fixture = Fixture::new(1)?;
        let store = Arc::new(fixture.store());
        store.fault.store(point, Ordering::SeqCst);
        let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
        let interrupted = pipeline::run(
            Arc::new(fixture.config()?),
            options(),
            services,
            CancellationToken::new(),
        )
        .await?;
        assert!(interrupted.cancelled);
        assert_eq!(interrupted.deleted, 0);
        assert_eq!(fixture.remaining()?, 1);
        assert_eq!(store.manifests.load(Ordering::SeqCst), 0);
        let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
        let resumed = pipeline::run(
            Arc::new(fixture.config()?),
            options(),
            services,
            CancellationToken::new(),
        )
        .await?;
        assert_eq!(resumed.deleted, 1);
        assert_eq!(fixture.remaining()?, 0);
        assert_eq!(store.puts.load(Ordering::SeqCst), 1);
        assert_eq!(store.manifests.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn checksum_mismatch_and_source_change_never_unlink() -> Result<(), Box<dyn std::error::Error>>
{
    for checksum in [true, false] {
        let fixture = Fixture::new(1)?;
        let mut configured = fixture.store();
        if checksum {
            configured.fault.store(3, Ordering::SeqCst);
        } else {
            configured.mutation = Some(fixture.root.join("0.jsonl"));
        }
        let store = Arc::new(configured);
        let services = fixture.services(store, Arc::new(SyntheticScanner))?;
        let report = pipeline::run(
            Arc::new(fixture.config()?),
            options(),
            services,
            CancellationToken::new(),
        )
        .await?;
        assert_eq!(report.deleted, 0);
        assert_eq!(report.retained, 1);
        assert_eq!(fixture.remaining()?, 1);
    }
    Ok(())
}

#[tokio::test]
async fn positive_process_counter_canary_is_not_a_constant()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(0)?;
    let services = fixture.services(Arc::new(fixture.store()), Arc::new(SyntheticScanner))?;
    assert!(services.deny_process_spawn().is_err());
    assert_eq!(
        services
            .counters
            .snapshot()
            .map_err(|_| Error::Worker)?
            .process_spawns,
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn whole_output_gets_one_line_drop_fallback_then_blocks()
-> Result<(), Box<dyn std::error::Error>> {
    for remain_after_fallback in [false, true] {
        let fixture = Fixture::new(1)?;
        let store = Arc::new(fixture.store());
        let scanner = Arc::new(FallbackScanner {
            calls: AtomicUsize::new(0),
            remain_after_fallback,
        });
        let services = fixture.services(store.clone(), scanner.clone())?;
        let report = pipeline::run(
            Arc::new(fixture.config()?),
            options(),
            services,
            CancellationToken::new(),
        )
        .await?;
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 3);
        assert_eq!(report.deleted, usize::from(!remain_after_fallback));
        assert_eq!(report.retained, usize::from(remain_after_fallback));
        assert_eq!(
            store.puts.load(Ordering::SeqCst),
            usize::from(!remain_after_fallback)
        );
        if remain_after_fallback {
            let path = fixture.root.join("0.jsonl");
            let original = BlockingPool::new(1)?
                .run(&CancellationToken::new(), move || read_file(path))
                .await?;
            assert_eq!(original, b"safe prefix synthetic-secret-value suffix\n");
        }
    }
    Ok(())
}

fn read_file(path: PathBuf) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|_| Error::Io)
}

#[tokio::test]
async fn removed_root_retains_its_intent_without_blocking_other_roots()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let store = Arc::new(fixture.store());
    store.fault.store(1, Ordering::SeqCst);
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    assert!(
        pipeline::run(
            Arc::new(fixture.config()?),
            options(),
            services,
            CancellationToken::new()
        )
        .await?
        .cancelled
    );
    let old_path = fixture.root.join("0.jsonl");
    let old_source = tokio::fs::read(&old_path).await?;
    let pool = BlockingPool::new(1)?;
    let database = fixture.work.join("state.sqlite");
    let previous = pool
        .run(&CancellationToken::new(), move || read_rows(database))
        .await?;
    let old = previous.first().ok_or(Error::Worker)?;
    assert!(old.expected.is_some());
    let record = serde_json::to_vec(old)?;
    let key = old.key.clone();
    let new_root = fixture.base.join("new-root");
    tokio::fs::create_dir(&new_root).await?;
    tokio::fs::write(new_root.join("fresh.jsonl"), b"public source\n").await?;
    let mut configured = fixture.config()?;
    configured.roots_all_files = vec![new_root.clone()];
    store.fault.store(usize::MAX, Ordering::SeqCst);
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let report = pipeline::run(
        Arc::new(configured),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(report.deleted, 1);
    assert_eq!(report.retained, 1);
    assert_eq!(report.reconciled_absent, 0);
    assert_eq!(store.puts.load(Ordering::SeqCst), 2);
    assert!(!tokio::fs::try_exists(new_root.join("fresh.jsonl")).await?);
    assert!(tokio::fs::read(old_path).await?.eq(&old_source));
    let database = fixture.work.join("state.sqlite");
    let current = pool
        .run(&CancellationToken::new(), move || read_rows(database))
        .await?;
    let retained = current
        .iter()
        .find(|row| row.key == key)
        .ok_or(Error::Worker)?;
    assert!(serde_json::to_vec(retained)?.eq(&record));
    Ok(())
}

#[tokio::test]
async fn no_intent_history_survives_absence_without_false_deletion_and_retries_on_demand()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let store = Arc::new(fixture.store());
    let scanner = Arc::new(FallbackScanner {
        calls: AtomicUsize::new(0),
        remain_after_fallback: true,
    });
    let config = Arc::new(fixture.config()?);
    let services = fixture.services(store.clone(), scanner)?;
    let blocked = pipeline::run(
        config.clone(),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(blocked.retained, 1);
    assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    let path = fixture.root.join("0.jsonl");
    // Simulate external pruning by moving the synthetic file outside the selected namespace.
    tokio::fs::rename(&path, fixture.base.join("synthetic-pruned.jsonl")).await?;
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let absent = pipeline::run(
        config.clone(),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(absent.deleted, 0);
    assert_eq!(absent.reconciled_absent, 0);
    assert_eq!(store.heads.load(Ordering::SeqCst), 0);
    let database = fixture.work.join("state.sqlite");
    let history = BlockingPool::new(1)?
        .run(&CancellationToken::new(), move || read_rows(database))
        .await?;
    assert_eq!(history.len(), 1);
    assert!(history.iter().all(|row| row.status == disk_archive::state::Status::Blocked && row.expected.is_none()));
    tokio::fs::write(path, b"safe prefix synthetic-secret-value suffix\n").await?;
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let retry = pipeline::run(config, options(), services, CancellationToken::new()).await?;
    assert_eq!(retry.deleted, 1);
    assert_eq!(store.puts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.remaining()?, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_resume_head_is_not_absence_and_changed_source_keeps_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let store = Arc::new(fixture.store());
    store.fault.store(1, Ordering::SeqCst);
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    assert!(
        pipeline::run(
            Arc::new(fixture.config()?),
            options(),
            services,
            CancellationToken::new()
        )
        .await?
        .cancelled
    );
    *store.verify_fault.lock().map_err(|_| Error::Worker)? = Some(StoreError::Transport);
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let retry = pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(retry.deleted, 0);
    assert_eq!(store.puts.load(Ordering::SeqCst), 1);
    let pool = BlockingPool::new(1)?;
    let database = fixture.work.join("state.sqlite");
    let previous = pool
        .run(&CancellationToken::new(), move || read_rows(database))
        .await?;
    let path = fixture.root.join("0.jsonl");
    pool.run(&CancellationToken::new(), move || mutate(path))
        .await?;
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let changed = pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(changed.deleted, 0);
    assert_eq!(store.puts.load(Ordering::SeqCst), 1);
    let database = fixture.work.join("state.sqlite");
    let current = pool
        .run(&CancellationToken::new(), move || read_rows(database))
        .await?;
    assert_eq!(
        previous.first().and_then(|r| r.expected.as_ref()),
        current.first().and_then(|r| r.expected.as_ref())
    );
    assert_eq!(fixture.remaining()?, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_waiter_keeps_ownership_until_shielded_flush_and_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let mut delayed = fixture.store();
    delayed.delay = Duration::from_millis(200);
    let store = Arc::new(delayed);
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let config = Arc::new(fixture.config()?);
    let counters = services.counters.clone();
    let waiter = tokio::spawn(pipeline::run(
        config,
        options(),
        services,
        CancellationToken::new(),
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        while store.started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(counters.snapshot().is_err()); // actual gzip spool held across detached work
    waiter.abort();
    let _ = waiter.await;
    let pool = BlockingPool::new(1)?;
    let work = fixture.work.clone();
    assert!(matches!(
        pool.run(&CancellationToken::new(), move || {
            disk_archive::work::Work::acquire(&work)
        })
        .await,
        Err(Error::Locked)
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let work = fixture.work.clone();
            match pool
                .run(&CancellationToken::new(), move || {
                    disk_archive::work::Work::acquire(&work)
                })
                .await
            {
                Ok(guard) => {
                    drop(guard);
                    break Ok::<_, Error>(());
                }
                Err(Error::Locked) => tokio::time::sleep(Duration::from_millis(5)).await,
                Err(error) => break Err(error),
            }
        }
    })
    .await??;
    assert_eq!(store.drains.load(Ordering::SeqCst), 1);
    assert!(
        counters
            .snapshot()
            .map_err(|_| Error::Worker)?
            .peak_temp_bytes
            > 0
    );
    assert_eq!(fixture.remaining()?, 1);
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let resumed = pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(resumed.deleted, 1);
    assert_eq!(store.puts.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn already_unlinked_state_commit_gap_is_reconciled_without_unlink()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let store = Arc::new(fixture.store());
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    assert_eq!(
        pipeline::run(
            Arc::new(fixture.config()?),
            options(),
            services,
            CancellationToken::new()
        )
        .await?
        .deleted,
        1
    );
    let pool = BlockingPool::new(1)?;
    let database = fixture.work.join("state.sqlite");
    let rows = pool
        .run(&CancellationToken::new(), move || read_rows(database))
        .await?;
    let mut row = rows.into_iter().next().ok_or(Error::Worker)?;
    row.status = disk_archive::state::Status::Uploaded;
    // Rewind ONLY the synthetic SQL fixture to emulate the last durable pre-unlink commit.
    // The public writer now deliberately rejects Deleted -> Uploaded rollback.
    let database = fixture.work.join("state.sqlite");
    pool.run(&CancellationToken::new(), move || {
        let db = rusqlite::Connection::open(database).map_err(|_| Error::Io)?;
        let bytes = serde_json::to_vec(&row).map_err(|_| Error::Io)?;
        db.execute(
            "UPDATE files SET record=?2 WHERE key=?1",
            rusqlite::params![row.key, bytes],
        )
        .map_err(|_| Error::Io)?;
        Ok(())
    })
    .await?;
    let services = fixture.services(store.clone(), Arc::new(SyntheticScanner))?;
    let resumed = pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(resumed.deleted, 0);
    assert_eq!(resumed.reconciled_absent, 1);
    assert_eq!(store.puts.load(Ordering::SeqCst), 1);
    Ok(())
}

/// Actual native catalog, gzip precomputation, SDK SigV4/PUT/HEAD and SQLite/delete adapters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_catalog_real_http_s3_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    use disk_archive_storage::{SdkStore, StoreOptions, test_support::MockS3};
    use sha2::{Digest as _, Sha256};
    let fixture = Fixture::new(3)?;
    plant_native(&fixture)?;
    let mock = MockS3::start().await?;
    assert!(mock.endpoint().starts_with("http://127.0.0.1:"));
    let store_options = StoreOptions {
        bucket: "synthetic-archive".into(),
        multipart_threshold: 8 * 1_048_576,
        part_size: 8 * 1_048_576,
        concurrency: 2,
        in_flight_bytes: 32 * 1_048_576,
    };
    let store = Arc::new(SdkStore::new(mock.client(), store_options.clone())?);
    let pool = BlockingPool::new(1)?;
    let scanner = pool
        .run(&CancellationToken::new(), || {
            disk_archive_scanner::Scanner::builtin(disk_archive_scanner::Limits::default())
                .map_err(|_| Error::Blocked)
        })
        .await?;
    assert_eq!(scanner.rule_count(), 488);
    let scanner = Arc::new(scanner);
    Box::pin(native_encoding::blocked_carriers(
        scanner.clone(),
        Arc::new(SdkStore::new(mock.client(), store_options)?),
        &mock,
    ))
    .await?;
    let services = fixture.services(store.clone(), scanner)?;
    let counters = services.counters.clone();
    let report = pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(report.deleted, 3);
    assert_eq!(report.retained, 0);
    assert_eq!(mock.source_put_attempts(), 3);
    assert!(
        counters
            .snapshot()
            .map_err(|_| Error::Worker)?
            .peak_temp_bytes
            > 0
    );
    assert_eq!(report.process_spawns, 0);
    assert_eq!(fixture.remaining()?, 0);
    let database = fixture.work.join("state.sqlite");
    let rows = pool
        .run(&CancellationToken::new(), move || read_rows(database))
        .await?;
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|row| row.status == disk_archive::state::Status::Deleted)
    );
    assert!(rows.iter().any(|row| !row.detectors.is_empty()));
    assert!(!String::from_utf8_lossy(&serde_json::to_vec(&rows)?).contains("ghp_"));
    for row in &rows {
        // Independently download actual mock objects, not just echoed HEAD metadata.
        let expected = ExpectedUpload::from_record(row.expected.as_deref().ok_or(Error::Worker)?)?;
        let response = mock
            .client()
            .get_object()
            .bucket("synthetic-archive")
            .key(&row.key)
            .send()
            .await?;
        let gzip = response.body.collect().await?.into_bytes();
        let compressed_hash: [u8; 32] = Sha256::digest(&gzip).into();
        assert_eq!(compressed_hash, expected.gzip_sha256);
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(gzip.as_ref())
            .take(65_537)
            .read_to_end(&mut decoded)?;
        assert!(decoded.len() <= 65_536);
        assert_eq!(u64::try_from(decoded.len())?, expected.source.size);
        let source_hash: [u8; 32] = Sha256::digest(&decoded).into();
        assert_eq!(source_hash, expected.source.sha256);
        assert!(!std::str::from_utf8(&decoded)?.contains("ghp_"));
        assert!(!std::str::from_utf8(&decoded)?.contains("fixture_password"));
    }
    drop(store);
    mock.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_snapshot_rewrite_and_rename_lifetimes_have_exact_peak()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(1)?;
    let store = Arc::new(fixture.store());
    let services = fixture.services(store, Arc::new(SyntheticScanner))?;
    let counters = services.counters.clone();
    let report = pipeline::run(
        Arc::new(fixture.config()?),
        options(),
        services,
        CancellationToken::new(),
    )
    .await?;
    assert_eq!(report.deleted, 1);
    // The larger redacted output and same-sized rename staging overlap. Snapshot
    // was closed first; source and SQLite are not temporary files. Gzip is smaller.
    let rewritten = b"safe prefix [REDACTED-synthetic-rule] suffix\n";
    assert_eq!(
        counters
            .snapshot()
            .map_err(|_| Error::Worker)?
            .peak_temp_bytes,
        2 * u64::try_from(rewritten.len())?
    );
    assert_eq!(std::fs::read_dir(fixture.root)?.count(), 0);
    assert!(!std::fs::read_dir(fixture.work)?.any(|entry| {
        entry.is_ok_and(|e| e.file_name().as_encoded_bytes().starts_with(b"archive-"))
    }));
    Ok(())
}

fn plant_native(fixture: &Fixture) -> Result<(), std::io::Error> {
    let mixed = "aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cF0iL";
    let synthetic = format!(
        "ghp_{}",
        mixed.repeat(2).chars().take(36).collect::<String>()
    );
    for (ordinal, input) in [
        (
            0,
            format!(r#"{{"text":"before\n {synthetic} after\\nend"}}"#),
        ),
        (
            1,
            String::from(
                r#"{"text":"before\n https://fixture_user:fixture_password@example.invalid/path\nend"}"#,
            ),
        ),
    ] {
        let path = fixture.root.join(format!("{ordinal}.jsonl"));
        std::fs::write(&path, format!("synthetic fixture.\n{input}\n"))?;
        File::open(path)?.set_times(
            FileTimes::new()
                .set_accessed(UNIX_EPOCH + Duration::from_secs(1))
                .set_modified(UNIX_EPOCH + Duration::from_secs(2)),
        )?;
    }
    Ok(())
}

fn read_rows(path: PathBuf) -> Result<Vec<Row>, Error> {
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| Error::Io)?;
    let mut statement = db
        .prepare("SELECT record FROM files ORDER BY key")
        .map_err(|_| Error::Io)?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| Error::Io)?;
    rows.map(|row| serde_json::from_slice(&row.map_err(|_| Error::Io)?).map_err(|_| Error::Io))
        .collect()
}
