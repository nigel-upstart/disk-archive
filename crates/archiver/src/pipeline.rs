//! Fixed-worker staged pipeline. No per-input task spawning or unbounded task/result collection.

use std::collections::BTreeMap;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use crate::scanner::ScanEngine;
use disk_archive_core::config::Config;
use disk_archive_metrics::Counters;
use disk_archive_storage::{
    CancellationToken, ExpectedUpload, ObjectStore, PreparedUpload, StoreError, UploadPreparer,
    VerifiedUpload,
};
use tokio::sync::{Mutex, mpsc};

use crate::{
    Error,
    blocking::BlockingPool,
    discovery,
    filesystem::{self, Candidate, Root},
    process::{self, Accepted},
    profile::{self, Stage},
    state::{Row, Status, Writer},
    work::Work,
};

/// Per-run explicit resource limits. Queue capacity and fixed workers bound every stage.
#[derive(Clone, Copy)]
pub struct Options {
    /// Fixed workers per stage; no task is spawned for an individual file.
    pub workers: usize,
    /// Bounded message count per stage and state channel.
    pub queue_capacity: usize,
    /// Global CPU/filesystem job concurrency, shared with compression.
    pub cpu_jobs: usize,
    /// Maximum source, snapshot or rewritten bytes per file.
    pub max_file_bytes: u64,
    /// Selected-file limit; zero permits a normal empty manifest run.
    pub limit: Option<usize>,
    /// Explicit attestation that every source writer obeys directory locks.
    pub quiescent: bool,
}

impl Options {
    /// Validate finite bounds before constructing any mutable resource.
    ///
    /// # Errors
    /// Missing ownership attestation or invalid bounds fail closed.
    pub fn validate(self) -> Result<(), Error> {
        if !self.quiescent
            || !(1..=256).contains(&self.workers)
            || !(1..=1024).contains(&self.queue_capacity)
            || !(1..=256).contains(&self.cpu_jobs)
            || self.max_file_bytes == 0
            || self.max_file_bytes > 1_073_741_824
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Observed completed-run summary. Per-file failures do not stop unrelated inputs.
#[derive(Default, Debug)]
pub struct Report {
    /// Actual capability-gated unlinks performed in this invocation.
    pub deleted: usize,
    /// Retained rows or inaccessible entries/subtrees requiring retry/operator repair; not a file census.
    pub retained: usize,
    /// Selected paths refused because their write-once key already has terminal Deleted history.
    pub namespace_conflicts: usize,
    /// Already-absent sources reconciled after fresh remote verification; no unlink was issued.
    pub reconciled_absent: usize,
    /// Peak concurrently executing file stages (includes bounded queue-admission waits).
    pub peak_active_stages: usize,
    /// Observed candidate ownership across every queue, worker and the blocked discovery sender.
    pub peak_live_items: usize,
    /// Cancellation suppresses the terminal manifest.
    pub cancelled: bool,
    /// Observed authorized process-gateway attempts; not an OS syscall-tracing claim.
    pub process_spawns: u64,
}

struct Counts {
    active: AtomicUsize,
    peak: AtomicUsize,
    deleted: AtomicUsize,
    retained: AtomicUsize,
    conflicts: AtomicUsize,
    reconciled: AtomicUsize,
    live: AtomicUsize,
    peak_live: AtomicUsize,
}
impl Counts {
    fn enter(self: &Arc<Self>) -> Active {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        Active(self.clone())
    }

    fn retain(&self, count: usize) -> Result<(), Error> {
        self.retained
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(count))
            .map(|_| ())
            .map_err(|_| Error::Budget)
    }

    fn report(&self, cancelled: bool, process_spawns: u64) -> Report {
        Report {
            deleted: self.deleted.load(Ordering::SeqCst),
            retained: self.retained.load(Ordering::SeqCst),
            namespace_conflicts: self.conflicts.load(Ordering::SeqCst),
            reconciled_absent: self.reconciled.load(Ordering::SeqCst),
            peak_active_stages: self.peak.load(Ordering::SeqCst),
            peak_live_items: self.peak_live.load(Ordering::SeqCst),
            cancelled,
            process_spawns,
        }
    }
}
/// A candidate lease survives queue transfers, waiter drops and real blocking jobs.
pub(crate) struct Occupancy(Arc<Counts>);
impl Occupancy {
    fn new(counts: Arc<Counts>) -> Self {
        let live = counts.live.fetch_add(1, Ordering::SeqCst) + 1;
        counts.peak_live.fetch_max(live, Ordering::SeqCst);
        Self(counts)
    }
}
impl Drop for Occupancy {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Active(Arc<Counts>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

type Receiver<T> = Arc<Mutex<mpsc::Receiver<T>>>;
struct Context {
    config: Arc<Config>,
    options: Options,
    pool: BlockingPool,
    scanner: Arc<dyn ScanEngine>,
    store: Arc<dyn ObjectStore>,
    preparer: UploadPreparer,
    writer: Writer,
    resume: BTreeMap<String, Row>,
    counts: Arc<Counts>,
    cancel: CancellationToken,
    counters: Arc<Counters>,
}

struct Local {
    accepted: Accepted,
    row: Row,
}
enum Ready {
    Fresh(Candidate, Row, Box<PreparedUpload>),
    Verified(Candidate, Row, VerifiedUpload),
}
struct Uploaded {
    candidate: Candidate,
    row: Row,
    token: VerifiedUpload,
}
enum Scanned {
    Fresh(Local),
    Resume(Candidate, Row, ExpectedUpload),
}

/// Shared adapters, constructed once after selecting the non-dry branch.
pub struct Services {
    /// Bounded shell CPU/filesystem gateway.
    pub pool: BlockingPool,
    /// Immutable in-process detector; no subprocess or provider validation.
    pub scanner: Arc<dyn ScanEngine>,
    /// One shared object store and its background cleanup ownership.
    pub store: Arc<dyn ObjectStore>,
    /// Preparer constructed with the same shell CPU semaphore.
    pub preparer: UploadPreparer,
    /// Exact operation instrumentation, shared with the benchmark adapters.
    pub counters: Arc<Counters>,
}

impl Services {
    /// Record an attempted process gateway entry BEFORE denying it. The production pipeline
    /// has no process implementation; static policy also forbids bypassing this gateway.
    ///
    /// # Errors
    /// Always denies subprocess execution; a counter failure invalidates measurement.
    pub fn deny_process_spawn(&self) -> Result<(), Error> {
        self.counters.process_spawn().map_err(|_| Error::Worker)?;
        Err(Error::Configuration)
    }
}

/// Run only after selecting the non-dry branch. Holds ownership through all worker/store/state drain.
/// `preparer` MUST share `pool.semaphore()` with the shell; callers construct both once.
/// The caller's runtime must reserve at least `cpu_jobs + 2` blocking threads for the shared
/// CPU lane and the separate bounded discovery/writer lanes; the CLI enforces this minimum.
/// Signal `cancel` and await for graceful shutdown. Dropping the waiter cancels a shielded
/// owner task, which retains locks through cleanup while the runtime remains alive. Destroying
/// the runtime/process is a crash, handled by durable upload-intent reconciliation.
///
/// # Errors
/// Infrastructure failures are reported after cleanup; per-file failures are persisted and retained.
pub async fn run(
    config: Arc<Config>,
    options: Options,
    services: Services,
    cancel: CancellationToken,
) -> Result<Report, Error> {
    options.validate()?;
    if services.pool.limit() != options.cpu_jobs {
        return Err(Error::Configuration);
    }
    let child = cancel.child_token();
    let _cancel_on_drop = child.clone().drop_guard();
    tokio::spawn(Box::pin(run_owned(config, options, services, child)))
        .await
        .map_err(|_| Error::Worker)?
}

/// Run an explicitly selected profiler inside the shielded pipeline owner.
/// Initialization/export errors never skip any pipeline shutdown barrier.
///
/// # Errors
/// Returns pipeline failures first, or a static profiling error after all work drains.
#[cfg(feature = "profiling")]
pub async fn run_profiled(
    config: Arc<Config>,
    options: Options,
    services: Services,
    cancel: CancellationToken,
    request: crate::profile::Request,
) -> Result<Report, Error> {
    options.validate()?;
    if services.pool.limit() != options.cpu_jobs {
        return Err(Error::Configuration);
    }
    let child = cancel.child_token();
    let _cancel_on_drop = child.clone().drop_guard();
    tokio::spawn(async move {
        // Keep even an initialization failure until AFTER owned cleanup completes.
        let profile_pool = services.pool.clone();
        let capture = profile_pool
            .run(&CancellationToken::new(), move || {
                crate::profile::Capture::start(request).map_err(|_| Error::Profiling)
            })
            .await;
        let result = Box::pin(run_owned(config, options, services, child)).await;
        let finished = match capture {
            Ok(capture) => capture.finish(&profile_pool).await,
            Err(error) => Err(error),
        };
        let report = result?;
        finished.map_err(|_| Error::Profiling)?;
        Ok(report)
    })
    .await
    .map_err(|_| Error::Worker)?
}

async fn run_owned(
    config: Arc<Config>,
    options: Options,
    services: Services,
    cancel: CancellationToken,
) -> Result<Report, Error> {
    let Services {
        pool,
        scanner,
        store,
        preparer,
        counters,
    } = services;
    let preparer = preparer.with_counters(counters.clone());
    let terminal_manifest_key = manifest_key(&config)?;
    let work_path = config.work_dir.clone().ok_or(Error::Configuration)?;
    let root_config = config.clone();
    let ownership = pool
        .run(&cancel, move || {
            let roots = discovery::roots(&root_config, true)?;
            let work = Work::acquire(&work_path)?;
            Ok((roots, work))
        })
        .await?;
    let (roots, work) = ownership;
    // Crash-leftover derived spools consume the same quota as new preparations. This is
    // read-only and must happen after exclusive Rust work ownership, before any scan/rewrite.
    preparer
        .account_existing_spools(cancel.clone())
        .await
        .map_err(storage_error)?;
    let (writer, resume, writer_task) = Writer::start(
        work.path.join("state.sqlite"),
        options.queue_capacity,
        32,
        Duration::from_millis(50),
    )
    .await?;
    let counts = Arc::new(Counts {
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        deleted: AtomicUsize::new(0),
        retained: AtomicUsize::new(0),
        conflicts: AtomicUsize::new(0),
        reconciled: AtomicUsize::new(0),
        live: AtomicUsize::new(0),
        peak_live: AtomicUsize::new(0),
    });
    let context = Arc::new(Context {
        config,
        options,
        pool,
        scanner,
        store,
        preparer,
        writer: writer.clone(),
        resume,
        counts: counts.clone(),
        cancel: cancel.clone(),
        counters: counters.clone(),
    });
    let _root_ownership = roots.clone();
    let result = match stages(context.clone(), roots).await {
        Err(Error::Cancelled) if cancel.is_cancelled() => Ok(()),
        result => result,
    };
    // No early-return can strand an uploader or skip the durable shutdown barrier.
    let store_drained = context.store.drain().await.map_err(|_| Error::Store);
    let cpu_drained = context.pool.drain().await;
    let drained = store_drained.and(cpu_drained);
    let manifest = if result.is_ok() && drained.is_ok() && !cancel.is_cancelled() {
        let published = profile::stage(
            Stage::Manifest,
            0,
            crate::manifest::publish(
                &writer,
                context.store.as_ref(),
                &context.pool,
                &terminal_manifest_key,
                cancel.clone(),
            ),
        )
        .await;
        // Manifest uploads happen after the data-plane drain. Drain those requests too, even
        // when a chunk or root fails; source/work ownership lasts through the final barrier.
        let manifest_drained = context.store.drain().await.map_err(|_| Error::Store);
        published.and(manifest_drained)
    } else {
        Ok(())
    };
    drop(context);
    let flushed = writer.finish().await;
    let joined = writer_task
        .await
        .map_err(|_| Error::Worker)
        .and_then(std::convert::identity);
    result?;
    drained?;
    manifest?;
    flushed?;
    joined?;
    if counts.live.load(Ordering::SeqCst) != 0 {
        return Err(Error::Worker);
    }
    let process_spawns = counters
        .snapshot()
        .map_err(|_| Error::Worker)?
        .process_spawns;
    Ok(counts.report(cancel.is_cancelled(), process_spawns))
}

fn channel<T>(capacity: usize) -> (mpsc::Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc::channel(capacity);
    (tx, Arc::new(Mutex::new(rx)))
}

async fn receive<T>(rx: &Receiver<T>) -> Option<T> {
    rx.lock().await.recv().await
}

async fn stages(context: Arc<Context>, roots: Vec<Arc<Root>>) -> Result<(), Error> {
    reconcile_absent(&context, &roots).await?;
    let capacity = context.options.queue_capacity;
    let (discovered_tx, discovered_rx) = channel(capacity);
    let (scanned_tx, scanned_rx) = channel(capacity);
    let (prepared_tx, prepared_rx) = channel(capacity);
    let (uploaded_tx, uploaded_rx) = channel(capacity);
    let mut tasks = Vec::with_capacity(context.options.workers * 4);
    for _ in 0..context.options.workers {
        tasks.push(tokio::spawn(scan_worker(
            context.clone(),
            discovered_rx.clone(),
            scanned_tx.clone(),
        )));
        tasks.push(tokio::spawn(prepare_worker(
            context.clone(),
            scanned_rx.clone(),
            prepared_tx.clone(),
        )));
        tasks.push(tokio::spawn(upload_worker(
            context.clone(),
            prepared_rx.clone(),
            uploaded_tx.clone(),
        )));
        tasks.push(tokio::spawn(delete_worker(
            context.clone(),
            uploaded_rx.clone(),
        )));
    }
    drop((scanned_tx, prepared_tx, uploaded_tx));
    // Drop coordinator receiver clones: failure of all consumers must close the send side.
    drop((discovered_rx, scanned_rx, prepared_rx, uploaded_rx));
    let discovery_context = context.clone();
    let discovery_cancel = context.cancel.clone();
    // The long-lived blocking sender has a separate slot: otherwise cpu_jobs=1 deadlocks
    // while discovery holds the only CPU permit and waits for a full first-stage channel.
    let discovery_pool = BlockingPool::new(1)?;
    let discovery = discovery_pool
        .run(&discovery_cancel, move || {
            let walked = profile::work(Stage::Discovery, 0, || {
                discovery::walk(
                    &roots,
                    &discovery_context.config,
                    discovery_context.options.limit,
                    &discovery_context.cancel,
                    |mut candidate| {
                        candidate.occupancy =
                            Some(Occupancy::new(discovery_context.counts.clone()));
                        discovered_tx
                            .blocking_send(candidate)
                            .map_err(|_| Error::Worker)
                    },
                )
            })?;
            discovery_context.counts.retain(walked.retained)?;
            Ok(())
        })
        .await;
    let mut result = discovery;
    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                result = Err(error);
                context.cancel.cancel();
            }
            Err(_) => {
                result = Err(Error::Worker);
                context.cancel.cancel();
            }
        }
    }
    result
}

async fn reconcile_absent(context: &Context, roots: &[Arc<Root>]) -> Result<(), Error> {
    for row in context.resume.values() {
        if context.cancel.is_cancelled() {
            break;
        }
        if row.status == Status::Deleted {
            continue;
        }
        let Some(record) = &row.expected else {
            continue;
        };
        let expected = context.decode_expected(record).await?;
        if expected.bucket != context.config.bucket || expected.key != row.key {
            return Err(Error::Configuration);
        }
        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(row.path.clone()));
        let Some(root) = roots.iter().find(|root| path.starts_with(&root.path)) else {
            // An unselected namespace never authorizes work on this durable intent.
            // Retain its exact history without blocking unrelated configured roots.
            context.counts.retain(1)?;
            continue;
        };
        let relative = path
            .strip_prefix(&root.path)
            .map_err(|_| Error::Configuration)?
            .to_owned();
        let root = root.clone();
        let checked_root = root.clone();
        let checked_relative = relative.clone();
        let absent = context
            .pool
            .run(&context.cancel, move || {
                checked_root.absent(&checked_relative)
            })
            .await;
        match absent {
            Ok(false) => continue,
            Err(error) => {
                context.fail(row.clone(), error).await?;
                continue;
            }
            Ok(true) => {}
        }
        match context
            .store
            .verify_existing(&expected, context.cancel.clone())
            .await
        {
            Ok(_token) => {
                // A fresh token proves remote evidence, but no absent pathname is ever unlinked.
                // Recheck absence under the retained namespace lock before classifying the row.
                let still_absent = context
                    .pool
                    .run(&context.cancel, move || root.absent(&relative))
                    .await;
                if still_absent == Ok(true) && !context.cancel.is_cancelled() {
                    let mut completed = row.clone();
                    completed.status = Status::Deleted;
                    context.writer.durable(completed).await?;
                    context.counts.reconciled.fetch_add(1, Ordering::SeqCst);
                } else {
                    context.fail(row.clone(), Error::SourceChanged).await?;
                }
            }
            Err(error) => context.fail(row.clone(), storage_error(error)).await?,
        }
    }
    Ok(())
}

async fn scan_worker(
    context: Arc<Context>,
    rx: Receiver<Candidate>,
    tx: mpsc::Sender<Scanned>,
) -> Result<(), Error> {
    while let Some(candidate) = receive(&rx).await {
        let _active = context.counts.enter();
        let file_id = candidate.profile_id;
        let mut row = Row {
            key: candidate.key.clone(),
            path: candidate
                .root
                .path
                .join(&candidate.relative)
                .as_os_str()
                .as_bytes()
                .to_vec(),
            status: Status::Discovered,
            detectors: BTreeMap::new(),
            expected: None,
        };
        let previous = context.previous(&row.key).await?;
        let previous = previous.as_ref();
        if previous.is_some_and(|old| old.status == Status::Deleted) {
            // Deleted is immutable historical bookkeeping, not a retry state. A newly appearing
            // generation needs an operator-selected disjoint namespace; never erase the tombstone.
            context.counts.retain(1)?;
            context.counts.conflicts.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        if previous.is_some_and(|old| old.path != row.path) {
            return Err(Error::Configuration);
        }
        if context.cancel.is_cancelled() {
            context
                .fail(previous.cloned().unwrap_or(row), Error::Cancelled)
                .await?;
            continue;
        }
        if let Some(previous) = previous
            && let Some(record) = &previous.expected
        {
            let expected = context.decode_expected(record).await?;
            if expected.key != row.key || expected.bucket != context.config.bucket {
                return Err(Error::Configuration);
            }
            let root = candidate.root.clone();
            let relative = candidate.relative.clone();
            let max = context.options.max_file_bytes;
            let current = context
                .pool
                .run(&context.cancel, move || {
                    filesystem::identity(&mut root.source(&relative)?, max)
                })
                .await;
            if current == Ok(expected.source) {
                // Restore already-completed local verification only after exact source identity
                // equality. This is bookkeeping, never restored remote/delete authority.
                let mut restored = previous.clone();
                restored.status = Status::Verified;
                tx.send(Scanned::Resume(candidate, restored, expected))
                    .await
                    .map_err(|_| Error::Worker)?;
                continue;
            }
            // Never erase a durable intent because cancellation, hashing or identity validation
            // failed. A changed generation at a write-once key is retained for operator action.
            context
                .fail(
                    previous.clone(),
                    current.err().unwrap_or(Error::SourceChanged),
                )
                .await?;
            continue;
        }
        profile::stage(Stage::State, file_id, context.writer.update(row.clone())).await?;
        let (scanner, config) = (context.scanner.clone(), context.config.clone());
        let max = context.options.max_file_bytes;
        let cancel = context.cancel.clone();
        let counters = context.counters.clone();
        let result = context
            .pool
            .run(&context.cancel, move || {
                process::process(
                    candidate,
                    scanner.as_ref(),
                    &config,
                    max,
                    &cancel,
                    &counters,
                )
            })
            .await;
        match result {
            Ok(accepted) => {
                row.detectors.clone_from(&accepted.detectors);
                row.advance(Status::Scanned)?;
                profile::stage(Stage::State, file_id, context.writer.update(row.clone())).await?;
                row.advance(Status::Redacted)?;
                profile::stage(Stage::State, file_id, context.writer.update(row.clone())).await?;
                row.advance(Status::Verified)?;
                tx.send(Scanned::Fresh(Local { accepted, row }))
                    .await
                    .map_err(|_| Error::Worker)?;
            }
            Err(error) => context.fail(row, error).await?,
        }
    }
    Ok(())
}

async fn prepare_worker(
    context: Arc<Context>,
    rx: Receiver<Scanned>,
    tx: mpsc::Sender<Ready>,
) -> Result<(), Error> {
    while let Some(scanned) = receive(&rx).await {
        let _active = context.counts.enter();
        match scanned {
            Scanned::Resume(candidate, row, expected) => {
                if let Some(ready) = prepare_resume(&context, candidate, row, expected).await? {
                    tx.send(ready).await.map_err(|_| Error::Worker)?;
                }
            }
            Scanned::Fresh(local) => {
                let Accepted {
                    candidate,
                    source,
                    identity,
                    detectors: _,
                } = local.accepted;
                let row = local.row;
                let result = profile::stage(
                    Stage::Prepare,
                    candidate.profile_id,
                    context.preparer.prepare(
                        source,
                        identity,
                        row.key.clone(),
                        context.cancel.clone(),
                    ),
                )
                .await;
                match result {
                    Ok(prepared) => {
                        let (row, prepared) = context.durable_prepared(row, prepared).await?;
                        tx.send(Ready::Fresh(candidate, row, Box::new(prepared)))
                            .await
                            .map_err(|_| Error::Worker)?;
                    }
                    Err(error) => context.fail(row, storage_error(error)).await?,
                }
            }
        }
    }
    Ok(())
}

// Resume HEAD/readmission belongs on the PRODUCER side of the prepared queue. An upload
// worker must never wait for disk held by prepared items that only upload workers can consume.
async fn prepare_resume(
    context: &Context,
    candidate: Candidate,
    row: Row,
    expected: ExpectedUpload,
) -> Result<Option<Ready>, Error> {
    match profile::stage(
        Stage::Verify,
        candidate.profile_id,
        context
            .store
            .verify_existing(&expected, context.cancel.clone()),
    )
    .await
    {
        Ok(token) => return Ok(Some(Ready::Verified(candidate, row, token))),
        Err(StoreError::NotFound | StoreError::Integrity) => {}
        Err(error) => {
            context.fail(row, storage_error(error)).await?;
            return Ok(None);
        }
    }
    let root = candidate.root.clone();
    let relative = candidate.relative.clone();
    let source = match context
        .pool
        .run(&context.cancel, move || root.source(&relative))
        .await
    {
        Ok(source) => source,
        Err(error) => {
            context.fail(row, error).await?;
            return Ok(None);
        }
    };
    match profile::stage(
        Stage::Prepare,
        candidate.profile_id,
        context.preparer.prepare(
            source,
            expected.source,
            row.key.clone(),
            context.cancel.clone(),
        ),
    )
    .await
    {
        Ok(prepared) => {
            let (row, prepared) = context.durable_prepared(row, prepared).await?;
            Ok(Some(Ready::Fresh(candidate, row, Box::new(prepared))))
        }
        Err(error) => {
            context.fail(row, storage_error(error)).await?;
            Ok(None)
        }
    }
}

async fn upload_worker(
    context: Arc<Context>,
    rx: Receiver<Ready>,
    tx: mpsc::Sender<Uploaded>,
) -> Result<(), Error> {
    while let Some(ready) = receive(&rx).await {
        let _active = context.counts.enter();
        let (candidate, mut row, result) = match ready {
            Ready::Fresh(candidate, row, prepared) => {
                let token = profile::stage(
                    Stage::Upload,
                    candidate.profile_id,
                    context
                        .store
                        .put_object_verified(&prepared, context.cancel.clone()),
                )
                .await;
                (candidate, row, token)
            }
            Ready::Verified(candidate, row, token) => (candidate, row, Ok(token)),
        };
        match result {
            Ok(token) => {
                row.advance(Status::Uploaded)?;
                profile::stage(
                    Stage::State,
                    candidate.profile_id,
                    context.writer.durable(row.clone()),
                )
                .await?;
                tx.send(Uploaded {
                    candidate,
                    row,
                    token,
                })
                .await
                .map_err(|_| Error::Worker)?;
            }
            Err(error) => context.fail(row, storage_error(error)).await?,
        }
    }
    Ok(())
}

async fn delete_worker(context: Arc<Context>, rx: Receiver<Uploaded>) -> Result<(), Error> {
    while let Some(Uploaded {
        candidate,
        mut row,
        token,
    }) = receive(&rx).await
    {
        let _active = context.counts.enter();
        let cancel = context.cancel.clone();
        let max = context.options.max_file_bytes;
        let file_id = candidate.profile_id;
        let result = context
            .pool
            .run(&context.cancel, move || {
                profile::work(Stage::Delete, candidate.profile_id, || {
                    crate::delete::delete(&candidate, token, max, &cancel)
                })
            })
            .await;
        match result {
            Ok(()) => {
                row.advance(Status::Deleted)?;
                profile::stage(Stage::State, file_id, context.writer.durable(row)).await?;
                context.counts.deleted.fetch_add(1, Ordering::SeqCst);
            }
            Err(error) => context.fail(row, error).await?,
        }
    }
    Ok(())
}

impl Context {
    async fn previous(&self, key: &str) -> Result<Option<Row>, Error> {
        match self.resume.get(key) {
            Some(row) => Ok(Some(row.clone())),
            None => self.writer.historical_row(key.to_owned()).await,
        }
    }

    async fn decode_expected(&self, record: &[u8]) -> Result<ExpectedUpload, Error> {
        let record = record.to_vec();
        self.pool
            .run(&CancellationToken::new(), move || {
                ExpectedUpload::from_record(&record).map_err(|_| Error::Store)
            })
            .await
    }

    async fn durable_prepared(
        &self,
        mut row: Row,
        prepared: PreparedUpload,
    ) -> Result<(Row, PreparedUpload), Error> {
        let (prepared, record) = self
            .pool
            .run(&CancellationToken::new(), move || {
                let record = prepared.expected().to_record().map_err(|_| Error::Store)?;
                Ok((prepared, record))
            })
            .await?;
        row.expected = Some(record);
        row.status = Status::Verified;
        // Remote work cannot race ahead of this FULL-synchronous WAL commit.
        self.writer.durable(row.clone()).await?;
        Ok((row, prepared))
    }

    async fn fail(&self, mut row: Row, error: Error) -> Result<(), Error> {
        row.status = if error == Error::Blocked {
            Status::Blocked
        } else {
            Status::Error
        };
        self.writer.update(row).await?;
        self.counts.retain(1)
    }
}

fn storage_error(error: StoreError) -> Error {
    match error {
        StoreError::Cancelled => Error::Cancelled,
        StoreError::SourceChanged => Error::SourceChanged,
        StoreError::Budget => Error::Budget,
        _ => Error::Store,
    }
}

fn manifest_key(config: &Config) -> Result<String, Error> {
    // Outside v1 source keys: no source file can collide with the manifest namespace.
    let key = disk_archive_verified::key::encode_key(&config.prefix, b"manifest")
        .map_err(|_| Error::Configuration)?;
    let key = String::from_utf8(key).map_err(|_| Error::Configuration)?;
    let prefix = key
        .strip_suffix("/v1/manifest.gz")
        .ok_or(Error::Configuration)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Io)?;
    let key = format!(
        "{prefix}/manifests/{}-{}.json",
        now.as_secs(),
        now.subsec_nanos()
    );
    crate::manifest::validate_key(&key)?;
    Ok(key)
}
