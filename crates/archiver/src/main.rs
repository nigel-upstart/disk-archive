//! Native asynchronous CLI. The dry-run branch precedes all mutable/store/scanner setup.

use std::io::{Write as _, stdout};
use std::sync::Arc;
use std::time::Duration;

use disk_archive::{
    Error,
    blocking::BlockingPool,
    cli::{Arguments, USAGE},
    discovery,
    pipeline::{self, Options, Report, Services},
};
use disk_archive_core::config::{Config, Environment};
use disk_archive_metrics::Counters;
use disk_archive_storage::{
    CancellationToken, ChecksumPolicy, ClientOptions, PrepareOptions, SdkStore, StoreOptions,
    UploadPreparer,
};

fn main() -> Result<(), Error> {
    // Rust's Result termination prints only our static error class, never operational values.
    entry()
}

fn entry() -> Result<(), Error> {
    let arguments = Arguments::parse(std::env::args_os().skip(1))?;
    if arguments.help {
        return stdout()
            .lock()
            .write_all(USAGE.as_bytes())
            .map_err(|_| Error::Io);
    }
    let cwd = std::env::current_dir().map_err(|_| Error::Io)?;
    let config = Arc::new(
        Config::load(arguments.env_file.as_deref(), &cwd, &Environment::capture())
            .map_err(|_| Error::Configuration)?,
    );
    if arguments.dry_run {
        let report = discovery::dry_run(&config, arguments.limit, &CancellationToken::new())?;
        return writeln!(
            stdout().lock(),
            "eligible={} retained={} redaction=unknown verification=unknown",
            report.eligible,
            report.retained
        )
        .map_err(|_| Error::Io);
    }
    let workers = arguments.workers.unwrap_or(config.workers);
    let options = Options {
        workers,
        queue_capacity: arguments.queue_capacity.unwrap_or(workers),
        cpu_jobs: workers,
        max_file_bytes: 67_108_864,
        limit: arguments.limit,
        quiescent: arguments.quiescent,
    };
    options.validate()?;
    if config.work_dir.is_none() {
        return Err(Error::Configuration);
    }
    // Fail invalid namespaces before costly catalog/credential initialization. Mutable runs
    // repeat this check under their real retained ownership locks in pipeline::run.
    drop(discovery::roots(&config, false)?);
    let blocking_threads = arguments.blocking_threads.unwrap_or(workers + 2);
    if blocking_threads < workers + 2 {
        return Err(Error::Configuration);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(blocking_threads)
        .enable_all()
        .build()
        .map_err(|_| Error::Worker)?;
    let report = runtime.block_on(execute(config, options))?;
    if report.cancelled {
        return Err(Error::Cancelled);
    }
    writeln!(
        stdout().lock(),
        "deleted={} retained={} namespace_conflicts={}",
        report.deleted,
        report.retained,
        report.namespace_conflicts
    )
    .map_err(|_| Error::Io)
}

async fn execute(config: Arc<Config>, options: Options) -> Result<Report, Error> {
    let cancel = CancellationToken::new();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| Error::Worker)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| Error::Worker)?;
    let signal_cancel = cancel.clone();
    let signals = tokio::spawn(async move {
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        signal_cancel.cancel();
    });
    let result = Box::pin(execute_with_cancel(config, options, cancel)).await;
    signals.abort();
    let _ = signals.await;
    result
}

async fn execute_with_cancel(
    config: Arc<Config>,
    options: Options,
    cancel: CancellationToken,
) -> Result<Report, Error> {
    let pool = BlockingPool::new(options.cpu_jobs)?;
    let scanner = pool
        .run(&cancel, || {
            disk_archive_scanner::Scanner::builtin(disk_archive_scanner::Limits::default())
                .map_err(|_| Error::Blocked)
        })
        .await?;
    let storage_pool = disk_archive_storage::BlockingPool::from_shared(pool.semaphore());
    let part_size = 8 * 1_048_576;
    let store = SdkStore::load(
        StoreOptions {
            bucket: config.bucket.clone(),
            multipart_threshold: part_size,
            part_size,
            concurrency: options.workers,
            in_flight_bytes: options
                .workers
                .checked_mul(8 * 1_048_576)
                .and_then(|n| n.checked_add(1_048_576))
                .ok_or(Error::Budget)?,
        },
        ClientOptions {
            profile: config.aws_profile.clone(),
            region: config.region.clone(),
            ca_bundle: config.ca_bundle.clone(),
            connect_timeout: Duration::from_secs(10),
            attempt_timeout: Duration::from_secs(60),
        },
        storage_pool.clone(),
    )
    .await
    .map_err(|_| Error::Store)?;
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    let max_spool_bytes = options
        .max_file_bytes
        .checked_add(options.max_file_bytes / 16)
        .and_then(|n| n.checked_add(1024))
        .ok_or(Error::Budget)?;
    let disk_budget = max_spool_bytes
        .checked_mul(
            u64::try_from(options.workers + options.queue_capacity).map_err(|_| Error::Budget)?,
        )
        .ok_or(Error::Budget)?;
    let preparer = UploadPreparer::new(
        PrepareOptions {
            bucket: config.bucket.clone(),
            work_dir: config.work_dir.clone().ok_or(Error::Configuration)?,
            disk_budget,
            max_spool_bytes,
            multipart_threshold: part_size,
            part_size,
            checksum: ChecksumPolicy::Crc64Nvme,
        },
        storage_pool,
    )
    .map_err(|_| Error::Configuration)?;
    pipeline::run(
        config,
        options,
        Services {
            pool,
            scanner: Arc::new(scanner),
            store: Arc::new(store),
            preparer,
            counters: Arc::new(Counters::default()),
        },
        cancel,
    )
    .await
}
