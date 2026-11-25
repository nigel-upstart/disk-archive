//! Synthetic collector using actual merged native/G/SQLite/SDK/HTTP workspace code.
//! Never accepts production configuration: copies only a bounded generated corpus into a
//! new owned `TempDir`, injects fixed mock credentials and writes metadata to a new file.
#![forbid(unsafe_code)]

use disk_archive::{
    blocking::BlockingPool,
    pipeline::{self, Options, Services},
    state::{Row, Status},
};
use disk_archive_benchmarks::{
    components::full_catalog,
    transport::{Bindings, MeasuringProxy, SizeClass, TransportStats},
};
use disk_archive_core::config::{Config, Environment};
use disk_archive_metrics::Counters;
use disk_archive_scanner::Scanner;
use disk_archive_storage::{
    CancellationToken, ChecksumPolicy, ExpectedUpload, PrepareOptions, SdkStore, StoreOptions,
    UploadPreparer, test_support::MockS3,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt::Write as _,
    fs::{File, FileTimes, OpenOptions, Permissions},
    io::{Read as _, Write as _},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_BYTES: u64 = 8 * 1_048_576;
const BLOCKED: &str = "encoded-blocked.jsonl";
const BUCKET: &str = "synthetic-archive";

type Result<T> = std::result::Result<T, ()>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    revision: String,
    seed: u64,
    files: usize,
    bytes: u64,
    sha256: String,
    plants: Vec<Plant>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plant {
    file: String,
    family: String,
    offset: usize,
    length: usize,
    scope: String,
}
struct Input {
    name: String,
    original: Zeroizing<Vec<u8>>,
    offset: usize,
    length: usize,
}
struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    work: PathBuf,
    inputs: Vec<Input>,
}

fn check(condition: bool) -> Result<()> {
    if condition { Ok(()) } else { Err(()) }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    fn digit(nibble: u8) -> char {
        char::from(if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        })
    }
    bytes
        .iter()
        .flat_map(|b| [digit(b >> 4), digit(b & 15)])
        .collect()
}
fn read_bounded(path: &Path, cap: u64) -> Result<Zeroizing<Vec<u8>>> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| ())?;
    check(meta.is_file() && meta.len() <= cap)?;
    let mut out = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(|_| ())?
        .take(cap + 1)
        .read_to_end(&mut out)
        .map_err(|_| ())?;
    check(u64::try_from(out.len()).map_err(|_| ())? <= cap)?;
    Ok(out)
}

fn fixture(corpus: &Path) -> Result<Fixture> {
    let spec: Corpus =
        serde_json::from_slice(&read_bounded(&corpus.join("manifest.json"), 65_536)?)
            .map_err(|_| ())?;
    check(
        spec.revision == "agent-jsonl-v2"
            && spec.seed == 488
            && spec.files == 89
            && spec.bytes == 7_029_003
            && spec.plants.len() == 89,
    )?;
    let mut names: BTreeSet<String> = (0..87).map(|n| format!("agent-{n:03}.jsonl")).collect();
    names.extend(["terminal-env.log".into(), "terminal-pem.log".into()]);
    let temp = tempfile::tempdir().map_err(|_| ())?;
    let base = temp.path().canonicalize().map_err(|_| ())?;
    let root = base.join("inputs");
    std::fs::create_dir(&root).map_err(|_| ())?;
    std::fs::set_permissions(&root, Permissions::from_mode(0o700)).map_err(|_| ())?;
    let mut inputs = Vec::new();
    let mut total = 0_u64;
    for plant in spec.plants {
        check(names.remove(&plant.file))?;
        check(matches!(
            (plant.family.as_str(), plant.scope.as_str()),
            ("github" | "private-key", "direct") | ("env", "core-extra")
        ))?;
        let original = read_bounded(&corpus.join("inputs").join(&plant.file), MAX_BYTES)?;
        check(
            plant.length > 0
                && plant
                    .offset
                    .checked_add(plant.length)
                    .is_some_and(|end| end <= original.len()),
        )?;
        total = total
            .checked_add(u64::try_from(original.len()).map_err(|_| ())?)
            .ok_or(())?;
        check(total <= MAX_BYTES)?;
        inputs.push(Input {
            name: plant.file,
            original,
            offset: plant.offset,
            length: plant.length,
        });
    }
    check(names.is_empty() && total == spec.bytes)?;
    inputs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut digest = Sha256::new();
    for input in &inputs {
        digest.update(input.name.as_bytes());
        digest.update(hash(&input.original));
    }
    check(hex(&digest.finalize()) == spec.sha256)?;
    // Deliberately encoded secret: native preflight must block/retain, never upload it.
    let token = inputs
        .first()
        .and_then(|i| i.original.get(i.offset..i.offset + i.length))
        .ok_or(())?;
    let mut encoded = Zeroizing::new(String::new());
    for byte in token {
        write!(&mut *encoded, "\\u{byte:04x}").map_err(|_| ())?;
    }
    inputs.push(Input {
        name: BLOCKED.into(),
        original: Zeroizing::new(format!("{{\"token\":\"{}\"}}\n", encoded.as_str()).into_bytes()),
        offset: 0,
        length: 0,
    });
    for input in &inputs {
        let path = root.join(&input.name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| ())?;
        file.write_all(&input.original).map_err(|_| ())?;
        file.set_times(
            FileTimes::new()
                .set_accessed(UNIX_EPOCH + Duration::from_secs(1))
                .set_modified(UNIX_EPOCH + Duration::from_secs(2)),
        )
        .map_err(|_| ())?;
    }
    let work = base.join("work");
    Ok(Fixture {
        temp,
        root,
        work,
        inputs,
    })
}

fn configuration(fixture: &Fixture) -> Result<Config> {
    let env = Environment::from_pairs(
        [
            ("DISK_ARCHIVE_BUCKET", BUCKET.to_owned()),
            ("DISK_ARCHIVE_PREFIX", "synthetic".to_owned()),
            (
                "DISK_ARCHIVE_ROOTS_ALL_FILES",
                fixture.root.to_str().ok_or(())?.to_owned(),
            ),
            (
                "DISK_ARCHIVE_WORK_DIR",
                fixture.work.to_str().ok_or(())?.to_owned(),
            ),
            ("DISK_ARCHIVE_MIN_AGE_DAYS", "0".to_owned()),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    );
    Config::load(None, fixture.temp.path(), &env).map_err(|_| ())
}

fn rows(path: &Path) -> Result<Vec<Row>> {
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| ())?;
    let mut query = db
        .prepare("SELECT record FROM files ORDER BY key")
        .map_err(|_| ())?;
    let records = query
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| ())?;
    records
        .map(|record| serde_json::from_slice(&record.map_err(|_| ())?).map_err(|_| ()))
        .collect()
}

fn correct_transform(input: &Input, output: &[u8]) -> Result<()> {
    let prefix = input.original.get(..input.offset).ok_or(())?;
    let end = input.offset.checked_add(input.length).ok_or(())?;
    let suffix = input.original.get(end..).ok_or(())?;
    check(output.starts_with(prefix) && output.ends_with(suffix))?;
    let end = output.len().checked_sub(suffix.len()).ok_or(())?;
    let middle = output.get(prefix.len()..end).ok_or(())?;
    // Independent offset oracle: outside the planted span every byte is preserved.
    // Inside it accept only the documented redaction marker grammar, not arbitrary loss.
    for marker in middle.split(|b| *b == b'\n') {
        let inner = marker
            .strip_prefix(b"[REDACTED")
            .and_then(|b| b.strip_suffix(b"]"))
            .ok_or(())?;
        check(
            inner.is_empty()
                || (inner.starts_with(b"-")
                    && inner.len() <= 65
                    && inner
                        .iter()
                        .skip(1)
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))),
        )?;
    }
    check(!middle.is_empty())?;
    let plant = input
        .original
        .get(input.offset..input.offset + input.length)
        .ok_or(())?;
    check(!output.windows(plant.len()).any(|w| w == plant))
}

async fn download(mock: &MockS3, key: &str, cap: u64) -> Result<Zeroizing<Vec<u8>>> {
    let response = mock
        .client()
        .get_object()
        .bucket(BUCKET)
        .key(key)
        .send()
        .await
        .map_err(|_| ())?;
    let length = response
        .content_length()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(())?;
    check(length <= cap)?;
    let bytes = response.body.collect().await.map_err(|_| ())?.into_bytes();
    check(u64::try_from(bytes.len()).map_err(|_| ())? == length)?;
    Ok(Zeroizing::new(bytes.to_vec()))
}

async fn verify_sources(
    fixture: &Fixture,
    config: &Config,
    mock: &MockS3,
    scanner: &Scanner,
    rows: &[Row],
    bindings: &mut Bindings,
) -> Result<BTreeSet<String>> {
    check(rows.len() == fixture.inputs.len())?;
    let by_key: BTreeMap<_, _> = rows.iter().map(|row| (row.key.as_str(), row)).collect();
    check(by_key.len() == rows.len())?;
    let mut keys = BTreeSet::new();
    for (slot, input) in fixture.inputs.iter().enumerate() {
        let path = fixture.root.join(&input.name);
        let key = String::from_utf8(
            disk_archive_verified::key::encode_key(
                &config.prefix,
                path.strip_prefix("/")
                    .map_err(|_| ())?
                    .as_os_str()
                    .as_bytes(),
            )
            .map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let row = by_key.get(key.as_str()).ok_or(())?;
        if input.name == BLOCKED {
            check(row.status == Status::Blocked && row.expected.is_none())?;
            check(read_bounded(&path, MAX_BYTES)?.as_slice() == input.original.as_slice())?;
            continue;
        }
        check(row.status == Status::Deleted && !path.try_exists().map_err(|_| ())?)?;
        let expected =
            ExpectedUpload::from_record(row.expected.as_deref().ok_or(())?).map_err(|_| ())?;
        let gzip = download(mock, &key, MAX_BYTES * 2).await?;
        check(
            hash(&gzip) == expected.gzip_sha256
                && u64::try_from(gzip.len()).map_err(|_| ())? == expected.gzip_size,
        )?;
        let mut output = Zeroizing::new(Vec::new());
        flate2::read::GzDecoder::new(gzip.as_slice())
            .take(MAX_BYTES + 1)
            .read_to_end(&mut output)
            .map_err(|_| ())?;
        check(
            u64::try_from(output.len()).map_err(|_| ())? == expected.source.size
                && hash(&output) == expected.source.sha256,
        )?;
        correct_transform(input, &output)?;
        check(
            scanner
                .scan(output.as_slice(), |_| Ok(()))
                .map_err(|_| ())?
                .findings
                == 0,
        )?;
        bindings
            .archive(
                &format!("/{BUCKET}/{key}"),
                u64::try_from(slot).map_err(|_| ())?,
                SizeClass::Single,
            )
            .map_err(|_| ())?;
        keys.insert(key);
    }
    Ok(keys)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    format: String,
    rows: u64,
    data_parts: u64,
    index_pages: u64,
    index_chain_sha256: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    format: String,
    parts: Vec<Part>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Part {
    name: String,
    rows: u64,
    sha256: [u8; 32],
}

async fn verify_manifests(
    mock: &MockS3,
    rows: &[Row],
    keys: &mut BTreeSet<String>,
    bindings: &mut Bindings,
) -> Result<()> {
    let listed = mock
        .client()
        .list_objects_v2()
        .bucket(BUCKET)
        .max_keys(1000)
        .send()
        .await
        .map_err(|_| ())?;
    check(listed.is_truncated() != Some(true))?;
    let all: BTreeSet<String> = listed
        .contents()
        .iter()
        .map(|o| o.key().map(ToOwned::to_owned).ok_or(()))
        .collect::<Result<_>>()?;
    let roots: Vec<_> = all
        .iter()
        .filter(|key| key.starts_with("synthetic/manifests/") && !key.contains(".parts/"))
        .collect();
    check(roots.len() == 1)?;
    let key = roots.first().ok_or(())?;
    let root: Root =
        serde_json::from_slice(&download(mock, key, 1_048_576).await?).map_err(|_| ())?;
    check(
        root.format == "disk-archive-manifest-v2"
            && root.rows == u64::try_from(rows.len()).map_err(|_| ())?
            && root.data_parts <= root.rows
            && root.index_pages <= root.data_parts,
    )?;
    bindings
        .manifest(&format!("/{BUCKET}/{key}"), 0)
        .map_err(|_| ())?;
    keys.insert((*key).clone());
    let mut chain = Sha256::new();
    let mut data_parts = 0_u64;
    let mut manifest_rows = Vec::new();
    for ordinal in 0..root.index_pages {
        let index_key = format!("{key}.parts/index-{ordinal:020}.json");
        let bytes = download(mock, &index_key, 1_048_576).await?;
        chain.update(u64::try_from(bytes.len()).map_err(|_| ())?.to_be_bytes());
        chain.update(bytes.as_slice());
        let index: Index = serde_json::from_slice(&bytes).map_err(|_| ())?;
        check(
            index.format == "disk-archive-index-v1"
                && !index.parts.is_empty()
                && index.parts.len() <= 512,
        )?;
        bindings
            .manifest(&format!("/{BUCKET}/{index_key}"), 1 + 2 * ordinal)
            .map_err(|_| ())?;
        keys.insert(index_key);
        for part in index.parts {
            check(
                part.name == format!("part-{data_parts:020}.json") && data_parts < root.data_parts,
            )?;
            let part_key = format!("{key}.parts/{}", part.name);
            let bytes = download(mock, &part_key, 1_048_576).await?;
            check(hash(&bytes) == part.sha256)?;
            let page: Vec<serde_json::Value> = serde_json::from_slice(&bytes).map_err(|_| ())?;
            check(
                u64::try_from(page.len()).map_err(|_| ())? == part.rows
                    && manifest_rows.len() + page.len() <= rows.len(),
            )?;
            manifest_rows.extend(page);
            bindings
                .manifest(&format!("/{BUCKET}/{part_key}"), 2 + 2 * data_parts)
                .map_err(|_| ())?;
            keys.insert(part_key);
            data_parts += 1;
        }
    }
    check(
        data_parts == root.data_parts
            && <[u8; 32]>::from(chain.finalize()) == root.index_chain_sha256
            && &all == keys,
    )?;
    let expected: Vec<_> = rows
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| ())?;
    check(manifest_rows == expected)
}

#[derive(Serialize)]
struct Exact {
    process_spawns: u64,
    bytes_uploaded: u64,
    peak_temp_bytes: u64,
    requests: BTreeMap<String, u64>,
}
#[derive(Serialize)]
struct Advisory {
    manifest_bytes: u64,
    control_bytes: u64,
    wire_body_bytes: u64,
    history_rows: usize,
    verified_archives: usize,
    verified_retained: usize,
    catalog_init_seconds: f64,
}
#[derive(Serialize)]
struct Receipt {
    schema: u8,
    complete: bool,
    binary_sha256: String,
    exact: Exact,
    advisory: Advisory,
}

fn receipt(
    binary_sha256: String,
    stats: TransportStats,
    resources: &disk_archive_metrics::Snapshot,
    rows: usize,
    catalog_init_seconds: f64,
) -> Result<Receipt> {
    check(
        resources.process_spawns == 0
            && resources.peak_temp_bytes > 0
            && stats.bytes_uploaded > 0
            && !stats.requests.is_empty(),
    )?;
    Ok(Receipt {
        schema: 1,
        complete: true,
        binary_sha256,
        exact: Exact {
            process_spawns: resources.process_spawns,
            bytes_uploaded: stats.bytes_uploaded,
            peak_temp_bytes: resources.peak_temp_bytes,
            requests: stats.requests,
        },
        advisory: Advisory {
            manifest_bytes: stats.manifest_bytes,
            control_bytes: stats.control_bytes,
            wire_body_bytes: stats.wire_body_bytes,
            history_rows: rows,
            verified_archives: rows - 1,
            verified_retained: 1,
            catalog_init_seconds,
        },
    })
}

async fn collect(corpus: &Path, binary_sha256: String) -> Result<Receipt> {
    let fixture = fixture(corpus)?;
    let config = Arc::new(configuration(&fixture)?);
    let pool = BlockingPool::new(2).map_err(|_| ())?;
    let start = Instant::now();
    let scanner = Arc::new(
        pool.run(&CancellationToken::new(), || {
            full_catalog().map_err(|_| disk_archive::Error::Blocked)
        })
        .await
        .map_err(|_| ())?,
    );
    let catalog_init_seconds = start.elapsed().as_secs_f64();
    let mock = MockS3::start().await.map_err(|_| ())?;
    let proxy = MeasuringProxy::around_mock(&mock).await.map_err(|_| ())?;
    let store_options = StoreOptions {
        bucket: BUCKET.into(),
        multipart_threshold: 5_242_880,
        part_size: 5_242_880,
        concurrency: 2,
        in_flight_bytes: 32 * 1_048_576,
    };
    let store = Arc::new(SdkStore::new(proxy.client(&mock), store_options).map_err(|_| ())?);
    let counters = Arc::new(Counters::default());
    let services = Services {
        pool: pool.clone(),
        scanner: scanner.clone(),
        store: store.clone(),
        preparer: UploadPreparer::new(
            PrepareOptions {
                bucket: BUCKET.into(),
                work_dir: fixture.work.clone(),
                disk_budget: 64 * 1_048_576,
                max_spool_bytes: 16 * 1_048_576,
                multipart_threshold: 5_242_880,
                part_size: 5_242_880,
                checksum: ChecksumPolicy::Crc64Nvme,
            },
            disk_archive_storage::BlockingPool::from_shared(pool.semaphore()),
        )
        .map_err(|_| ())?,
        counters: counters.clone(),
    };
    let report = pipeline::run(
        config.clone(),
        Options {
            workers: 2,
            queue_capacity: 2,
            cpu_jobs: 2,
            max_file_bytes: MAX_BYTES,
            limit: None,
            quiescent: true,
        },
        services,
        CancellationToken::new(),
    )
    .await
    .map_err(|_| ())?;
    check(
        !report.cancelled
            && report.deleted == 89
            && report.retained == 1
            && report.process_spawns == 0,
    )?;
    drop(store);
    let rows = rows(&fixture.work.join("state.sqlite"))?;
    let mut bindings = Bindings::default();
    let mut keys = verify_sources(&fixture, &config, &mock, &scanner, &rows, &mut bindings).await?;
    verify_manifests(&mock, &rows, &mut keys, &mut bindings).await?;
    check(mock.source_put_attempts() == 89)?;
    let stats = proxy.finish(&bindings).await.map_err(|_| ())?;
    mock.shutdown().await.map_err(|_| ())?;
    receipt(
        binary_sha256,
        stats,
        &counters.snapshot().map_err(|_| ())?,
        rows.len(),
        catalog_init_seconds,
    )
}

fn binary_digest() -> Result<String> {
    let mut file = File::open(std::env::current_exe().map_err(|_| ())?).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    let expected_bytes = metadata.len();
    check(metadata.is_file() && expected_bytes > 0)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 65_536];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| ())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| ())?)
            .ok_or(())?;
        // Hash the complete trusted Cargo executable, including platform-specific
        // debug information. Bound progress by its observed file size, not an
        // arbitrary limit that can reject a valid Linux debug executable.
        check(total <= expected_bytes)?;
        digest.update(buffer.get(..count).ok_or(())?);
    }
    check(total == expected_bytes && file.metadata().map_err(|_| ())?.len() == expected_bytes)?;
    Ok(hex(&digest.finalize()))
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    check(
        matches!(args.len(), 4 | 6)
            && args.first().is_some_and(|a| a == "--corpus")
            && args.get(2).is_some_and(|a| a == "--output")
            && (args.len() == 4 || args.get(4).is_some_and(|a| a == "--binary-sha256")),
    )?;
    let corpus = PathBuf::from(args.get(1).ok_or(())?);
    let output = PathBuf::from(args.get(3).ok_or(())?);
    check(!output.try_exists().map_err(|_| ())?)?;
    let digest = binary_digest()?;
    if args.len() == 6 {
        check(args.get(5).and_then(|a| a.to_str()) == Some(digest.as_str()))?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()
        .map_err(|_| ())?;
    let receipt = runtime.block_on(collect(&corpus, digest))?;
    let data = serde_json::to_vec(&receipt).map_err(|_| ())?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(output)
        .map_err(|_| ())?;
    file.write_all(&data).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())
}

fn main() -> std::result::Result<(), disk_archive_benchmarks::transport::ObservationError> {
    // Result termination prints only the static observation error, never input/config values.
    run().map_err(|()| disk_archive_benchmarks::transport::ObservationError)
}
