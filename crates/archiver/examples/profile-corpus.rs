//! Bounded synthetic diagnostics using the real native catalog, G pipeline and SDK/localhost S3.
//! Never loads dotenv, ambient roots, credentials, SDK profiles or providers.

use std::fs::{File, FileTimes, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use disk_archive::{
    Error,
    blocking::BlockingPool,
    pipeline::{Options, Services},
    profile::{self, Request},
    state::{Row, Status},
};
use disk_archive_core::{config::Config, key::KeyPrefix, redaction::Limits};
use disk_archive_metrics::Counters;
use disk_archive_storage::{
    CancellationToken, ChecksumPolicy, ExpectedUpload, PrepareOptions, SdkStore, StoreOptions,
    UploadPreparer, test_support::MockS3,
};
use sha2::{Digest as _, Sha256};

const FILES: usize = 32;
const PRIVATE: &str = "SYNTHETIC-PRIVATE-TRACE-CANARY-7281";

fn main() -> Result<(), Error> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or(Error::Configuration)?;
    let mode = mode.to_str().ok_or(Error::Configuration)?;
    let output = PathBuf::from(args.next().ok_or(Error::Configuration)?);
    if args.next().is_some() || !matches!(mode, "trace" | "heap" | "console" | "cpu") {
        return Err(Error::Configuration);
    }
    let request = match mode {
        "trace" => Some(Request::Trace(output.join("trace.json"))),
        #[cfg(feature = "profiling-heap")]
        "heap" => Some(Request::Heap(output.join("heap.json"))),
        "cpu" | "console" => None,
        _ => return Err(Error::Configuration),
    };
    #[cfg(not(feature = "profiling-console"))]
    if mode == "console" {
        return Err(Error::Configuration);
    }
    if !output.is_dir()
        || output
            .symlink_metadata()
            .map_err(|_| Error::Io)?
            .is_symlink()
    {
        return Err(Error::Configuration);
    }
    let corpus = corpus()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_name(if mode == "trace" {
            PRIVATE
        } else {
            "profile-worker"
        })
        .enable_all()
        .build()
        .map_err(|_| Error::Worker)?;
    runtime.block_on(run(mode, &output, request, corpus))
}

struct Corpus {
    _temporary: tempfile::TempDir,
    config: Arc<Config>,
    root: PathBuf,
    work: PathBuf,
}

fn corpus() -> Result<Corpus, Error> {
    let temporary = tempfile::Builder::new()
        .prefix("synthetic-profile-private-value-")
        .tempdir()
        .map_err(|_| Error::Io)?;
    let base = temporary.path().canonicalize().map_err(|_| Error::Io)?;
    let root = base.join(PRIVATE);
    let work = base.join("work");
    std::fs::create_dir(&root).map_err(|_| Error::Io)?;
    let plant = format!(
        "ghp_{}",
        "aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cF0iL"
            .repeat(2)
            .chars()
            .take(36)
            .collect::<String>()
    );
    for n in 0..FILES {
        let path = root.join(format!("synthetic-{n}.jsonl"));
        let mut file = File::create(path).map_err(|_| Error::Io)?;
        for line in 0..1024 {
            writeln!(
                file,
                "{{\"event\":\"synthetic {n} {line} alpha beta gamma delta epsilon zeta\"}}"
            )
            .map_err(|_| Error::Io)?;
        }
        writeln!(file, "{PRIVATE}\n{plant}\n").map_err(|_| Error::Io)?;
        file.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2)))
            .map_err(|_| Error::Io)?;
    }
    // Config is constructed directly: not even synthetic cwd/XDG dotenv discovery is needed.
    let config = Arc::new(Config {
        bucket: "synthetic-archive".into(),
        prefix: KeyPrefix::new(b"synthetic").map_err(|_| Error::Configuration)?,
        aws_profile: None,
        region: None,
        ca_bundle: None,
        roots_all_files: vec![root.clone()],
        roots_jsonl: vec![],
        work_dir: Some(work.clone()),
        min_age_secs: 0,
        workers: 2,
        redaction: Limits::default(),
    });
    Ok(Corpus {
        _temporary: temporary,
        config,
        root,
        work,
    })
}

async fn services(work: PathBuf) -> Result<(MockS3, Services), Error> {
    let cancel = CancellationToken::new();
    let pool = BlockingPool::new(2)?;
    let scanner = pool
        .run(&cancel, || {
            disk_archive_scanner::Scanner::builtin(disk_archive_scanner::Limits::default())
                .map_err(|_| Error::Blocked)
        })
        .await?;
    if scanner.rule_count() != 488 {
        return Err(Error::Blocked);
    }
    let mock = MockS3::start().await.map_err(|_| Error::Store)?;
    let part_size = 8 * 1_048_576;
    let store = Arc::new(
        SdkStore::new(
            mock.client(),
            StoreOptions {
                bucket: "synthetic-archive".into(),
                multipart_threshold: part_size,
                part_size,
                concurrency: 2,
                in_flight_bytes: 32 * 1_048_576,
            },
        )
        .map_err(|_| Error::Store)?,
    );
    let preparer = UploadPreparer::new(
        PrepareOptions {
            bucket: "synthetic-archive".into(),
            work_dir: work,
            disk_budget: 32 * 1_048_576,
            max_spool_bytes: 2 * 1_048_576,
            multipart_threshold: part_size,
            part_size,
            checksum: ChecksumPolicy::Crc64Nvme,
        },
        disk_archive_storage::BlockingPool::from_shared(pool.semaphore()),
    )
    .map_err(|_| Error::Store)?;
    Ok((
        mock,
        Services {
            pool,
            scanner: Arc::new(scanner),
            store,
            preparer,
            counters: Arc::new(Counters::default()),
        },
    ))
}

async fn run(
    mode: &str,
    output: &Path,
    request: Option<Request>,
    corpus: Corpus,
) -> Result<(), Error> {
    let Corpus {
        _temporary,
        config,
        root,
        work,
    } = corpus;
    let (mock, services) = services(work.clone()).await?;
    let pool = services.pool.clone();
    let counters = services.counters.clone();
    #[cfg(feature = "profiling-console")]
    let console = if mode == "console" {
        Some(disk_archive_profiling::console().map_err(|_| Error::Profiling)?)
    } else {
        None
    };
    #[cfg(feature = "profiling-console")]
    let observation = if console.is_some() {
        Some(tokio::spawn(disk_archive_profiling::observe_console()))
    } else {
        None
    };
    #[cfg(not(feature = "profiling-console"))]
    let _ = mode;
    let result = Box::pin(profile::run(
        config,
        Options {
            workers: 2,
            queue_capacity: 2,
            cpu_jobs: 2,
            max_file_bytes: 1_048_576,
            limit: None,
            quiescent: true,
        },
        services,
        CancellationToken::new(),
        request,
    ))
    .await;
    // Never return a profiling or verification error before all mock-owned bodies/tasks drain.
    let verified = match &result {
        Ok(report) if report.deleted == FILES && report.retained == 0 && !report.cancelled => {
            verify(&mock, &pool, work, root).await
        }
        _ => Err(Error::Worker),
    };
    #[cfg(feature = "profiling-console")]
    let console_result = if let (Some(console), Some(observation)) = (console, observation) {
        let observed = observation
            .await
            .map_err(|_| Error::Profiling)
            .and_then(|r| r.map_err(|_| Error::Profiling));
        // Bounded attach period, synthetic resources only. Even observation failure drains first.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let finished = console.finish().await.map_err(|_| Error::Profiling);
        match (observed, finished) {
            (Ok(stats), Ok(())) => {
                let path = output.join("console.json");
                pool.run(&CancellationToken::new(), move || {
                    write_json(
                        &path,
                        &serde_json::json!({"schema":1,"tasks":stats.tasks,"polls":stats.polls,"dropped_events":stats.dropped_events}),
                    )
                }).await
            }
            _ => Err(Error::Profiling),
        }
    } else {
        Ok(())
    };
    let shutdown = mock.shutdown().await.map_err(|_| Error::Store);
    let report = result?;
    verified?;
    shutdown?;
    #[cfg(feature = "profiling-console")]
    console_result?;
    let snapshot = counters.snapshot().map_err(|_| Error::Worker)?;
    if snapshot.peak_temp_bytes == 0 || report.process_spawns != 0 {
        return Err(Error::Worker);
    }
    let path = output.join("run.json");
    pool.run(&CancellationToken::new(), move || {
        write_json(
            &path,
            &serde_json::json!({
                "schema":1,"files":FILES,"deleted":report.deleted,"retained":report.retained,
                "rules":488,"verified_downloads":FILES,"process_spawns":report.process_spawns,
                "peak_temp_bytes":snapshot.peak_temp_bytes,
            }),
        )
    })
    .await
}

fn rows(work: &Path, root: &Path) -> Result<Vec<Row>, Error> {
    if std::fs::read_dir(root)
        .map_err(|_| Error::Io)?
        .next()
        .is_some()
    {
        return Err(Error::Worker);
    }
    let rows = {
        let db = rusqlite::Connection::open_with_flags(
            work.join("state.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|_| Error::Io)?;
        let mut query = db
            .prepare("SELECT record FROM files")
            .map_err(|_| Error::Io)?;
        query
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| Error::Io)?
            .map(|row| {
                serde_json::from_slice::<Row>(&row.map_err(|_| Error::Io)?).map_err(|_| Error::Io)
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() != FILES
        || rows
            .iter()
            .any(|r| r.status != Status::Deleted || r.detectors.is_empty())
    {
        return Err(Error::Blocked);
    }
    Ok(rows)
}

async fn verify(
    mock: &MockS3,
    pool: &BlockingPool,
    work: PathBuf,
    root: PathBuf,
) -> Result<(), Error> {
    let rows = pool
        .run(&CancellationToken::new(), move || rows(&work, &root))
        .await?;
    for row in rows {
        let expected = ExpectedUpload::from_record(row.expected.as_deref().ok_or(Error::Store)?)
            .map_err(|_| Error::Store)?;
        let response = mock
            .client()
            .get_object()
            .bucket("synthetic-archive")
            .key(&row.key)
            .send()
            .await
            .map_err(|_| Error::Store)?;
        let gzip = response
            .body
            .collect()
            .await
            .map_err(|_| Error::Store)?
            .into_bytes();
        pool.run(&CancellationToken::new(), move || {
            let hash: [u8; 32] = Sha256::digest(&gzip).into();
            if hash != expected.gzip_sha256 {
                return Err(Error::Store);
            }
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(gzip.as_ref())
                .take(1_048_577)
                .read_to_end(&mut decoded)
                .map_err(|_| Error::Io)?;
            let hash: [u8; 32] = Sha256::digest(&decoded).into();
            if decoded.len() > 1_048_576
                || hash != expected.source.sha256
                || u64::try_from(decoded.len()).map_err(|_| Error::Budget)? != expected.source.size
                || decoded.windows(4).any(|w| w == b"ghp_")
            {
                return Err(Error::Store);
            }
            Ok(())
        })
        .await?;
    }
    Ok(())
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), Error> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Error::Profiling)?;
    serde_json::to_writer(&mut output, value).map_err(|_| Error::Profiling)?;
    output.flush().map_err(|_| Error::Profiling)
}
