//! Synthetic filesystem/state/backpressure regressions; never inspect user configuration.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, FileTimes};
use std::os::unix::{
    ffi::{OsStrExt as _, OsStringExt as _},
    fs::PermissionsExt as _,
};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use disk_archive::{
    Error,
    blocking::BlockingPool,
    cli::Arguments,
    discovery,
    filesystem::{self, Root},
    state::{Row, Status, Writer},
    work::Work,
};
use disk_archive_core::config::{Config, Environment};
use tokio_util::sync::CancellationToken;

struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    work: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let base = temp.path().canonicalize()?;
        let root = base.join("root");
        std::fs::create_dir(&root)?;
        let work = base.join("work");
        Ok(Self {
            _temp: temp,
            base,
            root,
            work,
        })
    }
    fn file(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let path = self.root.join(name);
        std::fs::write(&path, bytes)?;
        settle_creation();
        File::open(&path)?.set_times(
            FileTimes::new()
                .set_accessed(UNIX_EPOCH + Duration::from_secs(1))
                .set_modified(UNIX_EPOCH + Duration::from_secs(2)),
        )?;
        Ok(path)
    }
    fn config(&self) -> Result<Config, Error> {
        let env = Environment::from_pairs(
            [
                ("DISK_ARCHIVE_BUCKET", "synthetic-bucket".to_owned()),
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
}

#[test]
fn dry_run_is_metadata_only_and_leaves_no_work_namespace() -> Result<(), Box<dyn std::error::Error>>
{
    let f = Fixture::new()?;
    let path = f.file(".hidden.jsonl", b"synthetic untouched bytes")?;
    let before = std::fs::metadata(&path)?;
    let root_before = std::fs::metadata(&f.root)?.modified()?;
    std::os::unix::fs::symlink(&path, f.root.join("link.jsonl"))?;
    let root_before = std::fs::metadata(&f.root)?.modified()?.max(root_before);
    let config = f.config().map_err(debug)?;
    let report = discovery::dry_run(&config, None, &CancellationToken::new()).map_err(debug)?;
    assert_eq!(report.eligible, 1);
    let after = std::fs::metadata(&path)?;
    assert_eq!(before.modified()?, after.modified()?);
    assert_eq!(before.accessed()?, after.accessed()?);
    assert_eq!(root_before, std::fs::metadata(&f.root)?.modified()?);
    assert!(!f.work.exists());
    assert_eq!(std::fs::read(path)?, b"synthetic untouched bytes");
    assert_eq!(
        discovery::dry_run(&config, Some(0), &CancellationToken::new())
            .map_err(debug)?
            .eligible,
        0
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(
        discovery::dry_run(&config, None, &cancelled)
            .map_err(debug)?
            .cancelled
    );
    Ok(())
}

#[test]
fn dry_run_does_not_open_existing_state_and_unknown_workdirs_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    f.file("source", b"synthetic input")?;
    std::fs::create_dir(&f.work)?;
    std::fs::set_permissions(&f.work, std::fs::Permissions::from_mode(0o700))?;
    let state = f.work.join("state.sqlite");
    std::fs::write(&state, b"synthetic sentinel, deliberately not SQLite")?;
    settle_creation();
    File::open(&state)?.set_times(
        FileTimes::new()
            .set_accessed(UNIX_EPOCH + Duration::from_secs(1))
            .set_modified(UNIX_EPOCH + Duration::from_secs(2)),
    )?;
    let before = std::fs::metadata(&state)?;
    let config = f.config().map_err(debug)?;
    assert_eq!(
        discovery::dry_run(&config, None, &CancellationToken::new())
            .map_err(debug)?
            .eligible,
        1
    );
    let after = std::fs::metadata(&state)?;
    assert_eq!(before.modified()?, after.modified()?);
    assert_eq!(before.accessed()?, after.accessed()?);
    assert!(!f.work.join("run.lock").exists());
    assert!(!f.work.join("format").exists());
    assert!(matches!(Work::acquire(&f.work), Err(Error::Configuration)));
    assert!(!f.work.join("run.lock").exists());
    assert_eq!(
        std::fs::read(state)?,
        b"synthetic sentinel, deliberately not SQLite"
    );
    Ok(())
}

#[test]
fn per_entry_key_and_directory_failures_are_counted_without_blocking_neighbours()
-> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    f.file("safe.jsonl", b"synthetic safe bytes")?;
    f.file(&" ".repeat(255), b"synthetic retained overlong key")?;
    let mut config = f.config()?;
    config.prefix = disk_archive_verified::key::KeyPrefix::new(&[b'p'; 400])
        .map_err(|_| Error::Configuration)?;
    let planned = discovery::dry_run(&config, None, &CancellationToken::new())?;
    assert_eq!(planned.eligible, 1);
    assert_eq!(planned.retained, 1);
    let blocked = f.root.join("blocked");
    std::fs::create_dir(&blocked)?;
    std::fs::write(
        blocked.join("unreadable.jsonl"),
        b"synthetic retained subtree",
    )?;
    config.roots_all_files.clear();
    config.roots_jsonl.push(f.root.clone());
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o0))?;
    let denied = std::fs::read_dir(&blocked).is_err();
    let planned = discovery::dry_run(&config, None, &CancellationToken::new());
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700))?;
    assert!(
        denied,
        "the permission-error control requires an unprivileged test user"
    );
    let planned = planned?;
    assert_eq!(planned.eligible, 1);
    assert_eq!(planned.retained, 1); // one unknown subtree, not a fabricated file count
    assert!(!f.work.exists());
    Ok(())
}

#[test]
fn keys_preserve_dots_and_include_distinct_roots() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    f.file(".same", b"a")?;
    f.file("same", b"b")?;
    let other = f.base.join("other");
    std::fs::create_dir(&other)?;
    let other_source = other.join("same");
    std::fs::write(&other_source, b"c")?;
    File::open(other_source)?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2)))?;
    let mut config = f.config().map_err(debug)?;
    config.roots_all_files.push(other);
    let roots = discovery::roots(&config, false).map_err(debug)?;
    let mut keys = Vec::new();
    discovery::walk(&roots, &config, None, &CancellationToken::new(), |c| {
        keys.push(c.key);
        Ok(())
    })
    .map_err(debug)?;
    assert_eq!(keys.len(), 3);
    assert_eq!(
        keys.iter().collect::<std::collections::BTreeSet<_>>().len(),
        3
    );
    assert!(keys.iter().any(|k| k.ends_with("/.same.gz")));
    Ok(())
}

// APFS rejects non-UTF8 file creation. Linux CI exercises real byte-preserving discovery.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_filename_bytes_survive_discovery_keys_and_state()
-> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let name = OsString::from_vec(b"synthetic-\xff.jsonl".to_vec());
    let path = f.root.join(&name);
    std::fs::write(&path, b"synthetic safe file")?;
    File::open(&path)?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(2)))?;
    let config = f.config()?;
    let roots = discovery::roots(&config, false)?;
    let mut selected = None;
    discovery::walk(
        &roots,
        &config,
        None,
        &CancellationToken::new(),
        |candidate| {
            selected = Some(candidate);
            Ok(())
        },
    )?;
    let candidate = selected.ok_or(Error::Worker)?;
    assert_eq!(candidate.relative.as_os_str(), name.as_os_str());
    let decoded = disk_archive_verified::key::decode_rel(&config.prefix, candidate.key.as_bytes())
        .map_err(|_| Error::Configuration)?;
    assert_eq!(decoded, path.strip_prefix("/")?.as_os_str().as_bytes());
    let row = Row {
        key: candidate.key,
        path: path.as_os_str().as_bytes().to_vec(),
        status: Status::Discovered,
        detectors: BTreeMap::new(),
        expected: None,
    };
    let decoded: Row = serde_json::from_slice(&serde_json::to_vec(&row)?)?;
    assert_eq!(PathBuf::from(OsString::from_vec(decoded.path)), path);
    Ok(())
}

#[test]
fn non_utf8_path_codec_is_lossless_without_filesystem_support()
-> Result<(), Box<dyn std::error::Error>> {
    let path = b"synthetic/file-\xff.jsonl";
    let prefix = disk_archive_verified::key::KeyPrefix::new(b"synthetic")
        .map_err(|_| Error::Configuration)?;
    let key =
        disk_archive_verified::key::encode_key(&prefix, path).map_err(|_| Error::Configuration)?;
    assert_eq!(
        disk_archive_verified::key::decode_rel(&prefix, &key).map_err(|_| Error::Configuration)?,
        path
    );
    let row = Row {
        key: String::from_utf8(key)?,
        path: path.to_vec(),
        status: Status::Discovered,
        detectors: BTreeMap::new(),
        expected: None,
    };
    let restored: Row = serde_json::from_slice(&serde_json::to_vec(&row)?)?;
    assert_eq!(
        PathBuf::from(OsString::from_vec(restored.path))
            .as_os_str()
            .as_bytes(),
        path
    );
    Ok(())
}

#[test]
fn no_follow_applies_to_roots_parent_components_and_special_files()
-> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    f.file("source", b"safe")?;
    let alias = f.base.join("alias");
    std::os::unix::fs::symlink(&f.root, &alias)?;
    assert!(Root::open(&alias, false, false).is_err());
    std::os::unix::fs::symlink(&f.root, f.root.join("linked-parent"))?;
    let root = Root::open(&f.root, false, true)?;
    assert!(
        root.source(std::path::Path::new("linked-parent/source"))
            .is_err()
    );
    let _socket = std::os::unix::net::UnixListener::bind(f.root.join("socket"))?;
    assert!(root.source(std::path::Path::new("socket")).is_err());
    std::fs::set_permissions(
        f.root.join("source"),
        std::fs::Permissions::from_mode(0o666),
    )?;
    assert!(root.source(std::path::Path::new("source")).is_err());
    Ok(())
}

// rustix exposes safe mkfifoat on Linux, not macOS; the Linux CI test is mandatory there.
#[cfg(target_os = "linux")]
#[test]
fn fifo_open_is_nonblocking_and_rejected_as_nonregular() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        f.root.join("fifo"),
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    let root = Root::open(&f.root, false, true)?;
    assert!(root.source(std::path::Path::new("fifo")).is_err());
    Ok(())
}

#[test]
fn namespace_comparisons_use_normalized_paths() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let mut config = f.config()?;
    let root = config.roots_all_files.first_mut().ok_or(Error::Worker)?;
    *root = root.join(".");
    let roots = discovery::roots(&config, false)?;
    assert_eq!(roots.first().ok_or(Error::Worker)?.path, f.root);
    config.work_dir = Some(f.root.join("./future-work"));
    assert!(matches!(
        discovery::roots(&config, false),
        Err(Error::Configuration)
    ));
    config.work_dir = Some(f.work.clone());
    config.roots_jsonl.push(f.root.join("./descendant"));
    assert!(matches!(
        discovery::roots(&config, false),
        Err(Error::Configuration)
    ));
    config.roots_jsonl.clear();
    config.roots_all_files.push(f.root.clone());
    assert!(matches!(
        discovery::roots(&config, false),
        Err(Error::Configuration)
    ));
    assert!(filesystem::normalize_absolute(&f.root.join("../root")).is_err());
    assert!(filesystem::normalize_absolute(std::path::Path::new("relative")).is_err());
    assert_eq!(
        filesystem::normalize_absolute(&PathBuf::from(format!("/{}", "a".repeat(4096)))),
        Err(Error::Budget)
    );
    config.roots_all_files = vec![f.root.clone(); 257];
    assert!(matches!(
        discovery::roots(&config, false),
        Err(Error::Budget)
    ));
    Ok(())
}

#[test]
fn namespace_locks_and_no_follow_are_real() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    f.file("source", b"original")?;
    let first = Work::acquire(&f.work).map_err(debug)?;
    assert!(matches!(Work::acquire(&f.work), Err(Error::Locked)));
    drop(first);
    let _second = Work::acquire(&f.work).map_err(debug)?;
    let root = Root::open(&f.root, false, true).map_err(debug)?;
    assert!(matches!(
        Root::open(&f.root, false, true),
        Err(Error::Locked)
    ));
    std::os::unix::fs::symlink("source", f.root.join("link"))?;
    assert!(root.source(std::path::Path::new("link")).is_err());
    assert!(root.source(std::path::Path::new("../root/source")).is_err());
    std::fs::hard_link(f.root.join("source"), f.root.join("hard"))?;
    assert!(root.source(std::path::Path::new("source")).is_err());
    Ok(())
}

#[test]
fn content_identity_detects_mutation_even_with_restored_mtime()
-> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let path = f.file("source", b"original")?;
    let root = Root::open(&f.root, false, true).map_err(debug)?;
    let mut source = root.source(std::path::Path::new("source")).map_err(debug)?;
    let before = filesystem::identity(&mut source, 1024).map_err(debug)?;
    let modified = source.metadata()?.modified()?;
    std::fs::write(path, b"mutated!")?;
    source.set_times(FileTimes::new().set_modified(modified))?;
    let after = filesystem::identity(&mut source, 1024).map_err(debug)?;
    assert_ne!(before.sha256, after.sha256);
    assert_eq!(before.mtime, after.mtime);
    Ok(())
}

#[test]
fn cli_is_strict_and_zero_limit_is_inert() -> Result<(), Error> {
    let args =
        Arguments::parse(["--dry-run", "--limit", "0", "--workers", "2"].map(OsString::from))?;
    assert!(args.dry_run);
    assert_eq!(args.limit, Some(0));
    assert_eq!(args.workers, Some(2));
    let literal = Arguments::parse(
        ["--env-file", "./--dry-run", "--dry-run", "--quiescent"].map(OsString::from),
    )?;
    assert_eq!(literal.env_file, Some("./--dry-run".into()));
    assert!(literal.dry_run);
    assert!(literal.quiescent);
    for args in [
        vec!["--workers", "0"],
        vec!["--limit", "-1"],
        vec!["--limit"],
        vec!["--unknown"],
        vec!["--dry-run", "--dry-run"],
        vec!["--help", "-h"],
        vec!["--env-file"],
        vec!["--env-file", ""],
        vec!["--env-file", "--dry-run"],
        vec!["--env-file", "--quiescent"],
        vec!["--env-file", "--help"],
        vec!["--env-file", "-h"],
        vec!["--env-file", "--env-file"],
        vec!["--env-file", "--limit"],
        vec!["--env-file", "--workers"],
        vec!["--env-file", "--queue-capacity"],
        vec!["--env-file", "--blocking-threads"],
        vec!["--env-file", "--unknown"],
    ] {
        assert!(Arguments::parse(args.into_iter().map(OsString::from)).is_err());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_permit_survives_waiter_cancellation() -> Result<(), Error> {
    let pool = BlockingPool::new(1)?;
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let first_pool = pool.clone();
    let first = tokio::spawn(async move {
        first_pool
            .run(&CancellationToken::new(), move || {
                let _ = started_tx.send(());
                release_rx.recv().map_err(|_| Error::Worker)?;
                Ok(())
            })
            .await
    });
    started_rx.await.map_err(|_| Error::Worker)?;
    first.abort();
    let second_pool = pool.clone();
    let (second_tx, mut second_rx) = tokio::sync::oneshot::channel();
    let second = tokio::spawn(async move {
        second_pool
            .run(&CancellationToken::new(), move || {
                let _ = second_tx.send(());
                Ok(())
            })
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut second_rx)
            .await
            .is_err()
    );
    release_tx.send(()).map_err(|_| Error::Worker)?;
    second_rx.await.map_err(|_| Error::Worker)?;
    second.await.map_err(|_| Error::Worker)??;
    assert_eq!(pool.peak(), 1);
    Ok(())
}

#[tokio::test]
async fn durable_writer_barrier_flushes_before_ack_and_survives_restart() -> Result<(), Error> {
    let temp = tempfile::tempdir().map_err(|_| Error::Io)?;
    let path = canonical_db_path(&temp)?;
    let (writer, resumed, task) =
        Writer::start(path.clone(), 1, 8, Duration::from_millis(10)).await?;
    assert!(resumed.is_empty());
    let row = Row {
        key: "synthetic/v1/source.gz".into(),
        path: b"synthetic/source".to_vec(),
        status: Status::Verified,
        detectors: BTreeMap::from([("synthetic-rule".into(), 3)]),
        expected: Some(br#"{"synthetic":"evidence"}"#.to_vec()),
    };
    writer.update(row.clone()).await?;
    writer.durable(row).await?;
    let manifest = writer.manifest().await?;
    assert!(String::from_utf8_lossy(&manifest).contains("synthetic-rule"));
    writer.finish().await?;
    task.await.map_err(|_| Error::Worker)??;
    let (writer, resumed, task) = Writer::start(path, 1, 8, Duration::from_millis(10)).await?;
    assert_eq!(resumed.len(), 1);
    assert_eq!(
        resumed
            .first_key_value()
            .and_then(|(_, r)| r.expected.as_deref()),
        Some(br#"{"synthetic":"evidence"}"#.as_slice())
    );
    writer.finish().await?;
    task.await.map_err(|_| Error::Worker)??;
    Ok(())
}

#[test]
fn detached_delete_job_retains_root_guard_until_real_unlink_and_drain()
-> Result<(), Box<dyn std::error::Error>> {
    use disk_archive_verified::lifecycle::{RemoteEvidence, UploadExpectation, verify_upload};
    let fixture = Fixture::new()?;
    let path = fixture.file("source", b"original")?;
    let config = fixture.config()?;
    let roots = discovery::roots(&config, true)?;
    let mut selected = None;
    discovery::walk(
        &roots,
        &config,
        Some(1),
        &CancellationToken::new(),
        |candidate| {
            selected = Some(candidate);
            Ok(())
        },
    )?;
    let candidate = selected.ok_or(Error::Worker)?;
    drop(roots);
    let mut file = candidate.root.source(&candidate.relative)?;
    let source = filesystem::identity(&mut file, 1024)?;
    // Synthetic kernel evidence isolates guard lifetime; the real HTTP suite tests authenticity.
    let expected = UploadExpectation {
        source,
        key: candidate.key.as_bytes().to_vec(),
        compressed_size: 23,
        compressed_sha256: [7; 32],
    };
    let token = verify_upload(
        &expected,
        &RemoteEvidence {
            key: expected.key.clone(),
            content_length: 23,
            gz_sha256: [7; 32],
            orig_size: source.size,
            orig_sha256: source.sha256,
            sse_aes256: true,
        },
    )
    .map_err(|_| Error::Store)?;
    let root_path = fixture.root.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(3)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let pool = BlockingPool::new(1)?;
        let first_pool = pool.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let waiter = tokio::spawn(async move {
            first_pool
                .run(&CancellationToken::new(), move || {
                    let _ = started_tx.send(());
                    release_rx.recv().map_err(|_| Error::Worker)?;
                    disk_archive::delete::delete(&candidate, token, 1024, &CancellationToken::new())
                })
                .await
        });
        started_rx.await.map_err(|_| Error::Worker)?;
        waiter.abort();
        let _ = waiter.await;
        let probe = BlockingPool::new(1)?;
        let attempt = root_path.clone();
        assert!(matches!(
            probe
                .run(&CancellationToken::new(), move || Root::open(
                    &attempt, false, true
                ))
                .await,
            Err(Error::Locked)
        ));
        release_tx.send(()).map_err(|_| Error::Worker)?;
        pool.drain().await?;
        let _released = probe
            .run(&CancellationToken::new(), move || {
                Root::open(&root_path, false, true)
            })
            .await?;
        Ok::<_, Error>(())
    })?;
    assert!(!path.exists());
    Ok(())
}

// A no-archiver control on this macOS host reproduced asynchronous new-file inspection.
// Set atime sentinels only after creation settles; the real read-detection assertions remain.
fn settle_creation() {
    #[cfg(target_os = "macos")]
    std::thread::sleep(Duration::from_millis(250));
}

fn canonical_db_path(temp: &tempfile::TempDir) -> Result<PathBuf, Error> {
    Ok(temp
        .path()
        .canonicalize()
        .map_err(|_| Error::Io)?
        .join("synthetic.sqlite"))
}

fn debug(error: Error) -> std::io::Error {
    std::io::Error::other(format!("{error:?}"))
}
