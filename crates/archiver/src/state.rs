//! Single batched WAL writer with explicit durability barriers before remote side effects.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{Error, blocking::BlockingPool};

const MAX_RECORD: usize = 2_097_152;
const MAX_RESUME: usize = 67_108_864;
/// Actual store payload ceiling, including JSON brackets and separators.
pub const MAX_MANIFEST_PAGE: usize = 1_048_576;

mod codec;
const MAX_ROWS: usize = 100_000;

#[cfg(test)]
mod tests;

/// Check cardinality and serialized bytes BEFORE copying/decoding a database record.
struct ReadBudget {
    rows: usize,
    bytes: usize,
    max_rows: usize,
    max_bytes: usize,
}
impl ReadBudget {
    const fn new(max_rows: usize, max_bytes: usize, bytes: usize) -> Self {
        Self {
            rows: 0,
            bytes,
            max_rows,
            max_bytes,
        }
    }

    fn charge(&mut self, length: usize, overhead: usize) -> Result<(), Error> {
        let bytes = self
            .bytes
            .checked_add(length)
            .and_then(|n| n.checked_add(overhead))
            .ok_or(Error::Budget)?;
        if length > MAX_RECORD * 5 || self.rows >= self.max_rows || bytes > self.max_bytes {
            return Err(Error::Budget);
        }
        self.rows += 1;
        self.bytes = bytes;
        Ok(())
    }
}

/// State rows contain only bounded operational provenance and detector counts, never values.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    /// Canonical root-qualified key.
    pub key: String,
    /// Exact Unix pathname bytes, hex on disk; legacy number arrays remain readable.
    #[serde(with = "codec::path")]
    pub path: Vec<u8>,
    /// Durable bookkeeping status, never deletion authority.
    pub status: Status,
    /// Original rule identifiers and counts only.
    pub detectors: BTreeMap<String, u64>,
    /// Opaque validated expectation JSON, embedded without byte-array inflation; never a token.
    #[serde(with = "codec::expected")]
    pub expected: Option<Vec<u8>>,
}

/// Persisted lifecycle markers. Authority is always obtained independently from the kernel.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Selected by metadata discovery.
    Discovered,
    /// Initial scan complete.
    Scanned,
    /// Redaction output complete.
    Redacted,
    /// Whole-output verification complete and upload intent durable.
    Verified,
    /// Fresh remote evidence accepted.
    Uploaded,
    /// Capability-gated unlink completed.
    Deleted,
    /// Full scan/redaction could not certify output.
    Blocked,
    /// Retriable static failure; previous expectation is retained.
    Error,
    /// Excluded by current policy.
    Skipped,
}

impl Status {
    const fn kernel(self) -> disk_archive_verified::lifecycle::FileState {
        use disk_archive_verified::lifecycle::FileState as F;
        match self {
            Self::Discovered => F::Discovered,
            Self::Scanned => F::Scanned,
            Self::Redacted => F::Redacted,
            Self::Verified => F::Verified,
            Self::Uploaded => F::Uploaded,
            Self::Deleted => F::Deleted,
            Self::Blocked => F::Blocked,
            Self::Error => F::Error,
            Self::Skipped => F::Skipped,
        }
    }
}

impl Row {
    /// Apply the actual verified lifecycle kernel to a live processing transition.
    /// Persisted rows still cannot mint any upload or deletion authority.
    ///
    /// # Errors
    /// Rejects illegal live transitions; idempotent durable updates are allowed.
    pub fn advance(&mut self, next: Status) -> Result<(), Error> {
        if self.status != next {
            disk_archive_verified::lifecycle::transition(self.status.kernel(), next.kernel())
                .map_err(|_| Error::Configuration)?;
            self.status = next;
        }
        Ok(())
    }

    fn budget(&self) -> Result<(), Error> {
        if self.key.is_empty()
            || self.key.len() > 1024
            || self.path.len() > 4096
            || self.detectors.len() > 1024
            || self.detectors.keys().any(|k| k.is_empty() || k.len() > 256)
            || self.expected.as_ref().is_some_and(|e| e.len() > MAX_RECORD)
        {
            return Err(Error::Budget);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.budget()?;
        if self
            .detectors
            .keys()
            .any(|key| key.chars().any(char::is_control))
        {
            return Err(Error::Configuration);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Io)?;
        // Refuse an unpageable row BEFORE its durable upload intent can be acknowledged.
        if bytes.len() > MAX_MANIFEST_PAGE - 2 {
            return Err(Error::Budget);
        }
        Ok(bytes)
    }
}

/// One independently valid JSON page of the complete history, never an authorization token.
pub struct ManifestPage {
    /// At most the actual store's 1MiB payload ceiling, including delimiters.
    pub bytes: Vec<u8>,
    /// Exclusive continuation key; None means the entire snapshot has been emitted.
    pub next: Option<String>,
    /// Exact rows in this page.
    pub rows: usize,
}

enum Message {
    Update(Row, Option<oneshot::Sender<Result<(), Error>>>),
    Manifest(Option<String>, oneshot::Sender<Result<ManifestPage, Error>>),
    Historical(String, oneshot::Sender<Result<Option<Row>, Error>>),
    Finish(oneshot::Sender<Result<(), Error>>),
}

/// Cloneable bounded state sender. Durable calls return only after a FULL-synchronous commit.
#[derive(Clone)]
pub struct Writer(mpsc::Sender<Message>);

impl Writer {
    /// Start one writer, loading resumable rows exactly once with a total byte budget.
    ///
    /// # Errors
    /// Invalid limits, malformed state or SQLite failures fail closed.
    pub async fn start(
        path: PathBuf,
        capacity: usize,
        batch: usize,
        flush: Duration,
    ) -> Result<(Self, BTreeMap<String, Row>, JoinHandle<Result<(), Error>>), Error> {
        if capacity == 0 || capacity > 1024 || batch == 0 || batch > 1024 || flush.is_zero() {
            return Err(Error::Configuration);
        }
        let pool = BlockingPool::new(1)?;
        let cancel = CancellationToken::new();
        let (connection, rows) = pool.run(&cancel, move || initialize(&path)).await?;
        let (tx, rx) = mpsc::channel(capacity);
        let task = tokio::spawn(writer_loop(connection, rx, pool, batch, flush));
        Ok((Self(tx), rows, task))
    }

    /// Enqueue an update; bounded send applies backpressure.
    ///
    /// # Errors
    /// Writer failure closes the channel.
    pub async fn update(&self, row: Row) -> Result<(), Error> {
        row.budget()?;
        self.0
            .send(Message::Update(row, None))
            .await
            .map_err(|_| Error::Io)
    }

    /// Commit an upload intent or terminal state before allowing the caller to proceed.
    /// Not cancelled by the pipeline token: shutdown must drain durable barriers.
    ///
    /// # Errors
    /// Does not acknowledge a failed transaction or a failed writer.
    pub async fn durable(&self, row: Row) -> Result<(), Error> {
        row.budget()?;
        let (tx, rx) = oneshot::channel();
        self.0
            .send(Message::Update(row, Some(tx)))
            .await
            .map_err(|_| Error::Io)?;
        rx.await.map_err(|_| Error::Io)?
    }

    /// Read a single-page snapshot; use `manifest_page` for arbitrarily large history.
    ///
    /// # Errors
    /// Multiple pages return Budget, never a silently truncated array.
    pub async fn manifest(&self) -> Result<Vec<u8>, Error> {
        let page = self.manifest_page(None).await?;
        if page.next.is_some() {
            return Err(Error::Budget);
        }
        Ok(page.bytes)
    }

    /// Flush preceding updates and stream one bounded page, ordered by immutable key.
    /// Producers must have drained before paging so every page belongs to one snapshot.
    ///
    /// # Errors
    /// Invalid cursors, oversized records or database errors fail closed.
    pub async fn manifest_page(&self, after: Option<String>) -> Result<ManifestPage, Error> {
        if after
            .as_ref()
            .is_some_and(|key| key.is_empty() || key.len() > 1024)
        {
            return Err(Error::Configuration);
        }
        let (tx, rx) = oneshot::channel();
        self.0
            .send(Message::Manifest(after, tx))
            .await
            .map_err(|_| Error::Io)?;
        rx.await.map_err(|_| Error::Io)?
    }

    /// Look up historical terminal bookkeeping without loading lifetime history.
    ///
    /// # Errors
    /// Invalid keys, malformed rows or writer failure deny processing.
    pub async fn is_deleted(&self, key: String) -> Result<bool, Error> {
        Ok(self
            .historical_row(key)
            .await?
            .is_some_and(|row| row.status == Status::Deleted))
    }

    /// Fetch one selected key's history after flushing preceding updates. Rows without an
    /// upload intent are fetched here, not kept in the bounded startup resume map.
    /// Absence of an intent never becomes a claim of successful upload or deletion.
    ///
    /// # Errors
    /// Invalid keys, malformed/oversized rows or writer failure deny processing.
    pub async fn historical_row(&self, key: String) -> Result<Option<Row>, Error> {
        if key.is_empty() || key.len() > 1024 {
            return Err(Error::Configuration);
        }
        let (tx, rx) = oneshot::channel();
        self.0
            .send(Message::Historical(key, tx))
            .await
            .map_err(|_| Error::Io)?;
        rx.await.map_err(|_| Error::Io)?
    }

    /// Flush and close the writer after every worker has drained.
    ///
    /// # Errors
    /// Any commit/checkpoint failure is reported; never claim a successful flush otherwise.
    pub async fn finish(self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(Message::Finish(tx))
            .await
            .map_err(|_| Error::Io)?;
        rx.await.map_err(|_| Error::Io)?
    }
}

fn initialize(path: &Path) -> Result<(Connection, BTreeMap<String, Row>), Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
            return Err(Error::SourceChanged);
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Io),
    }
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags).map_err(|_| Error::Io)?;
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS files (key TEXT PRIMARY KEY, record BLOB NOT NULL);").map_err(|_| Error::Io)?;
    let rows = read_resume(&connection, ReadBudget::new(MAX_ROWS, MAX_RESUME, 0))?;
    Ok((connection, rows))
}

fn read_resume(
    connection: &Connection,
    mut budget: ReadBudget,
) -> Result<BTreeMap<String, Row>, Error> {
    let mut rows = BTreeMap::new();
    // Only outstanding upload intents need absent-source reconciliation at startup. All
    // no-intent history (including orphaned Blocked/Error/Skipped rows) is read by selected key.
    // Explicit JSON null alone is excluded; missing/malformed expectation fields still fail closed.
    let mut statement = connection.prepare("SELECT key, record, length(record) FROM files WHERE CASE WHEN length(record)>?1 THEN 1 ELSE json_extract(CAST(record AS TEXT), '$.status') IS NOT 'deleted' AND json_type(CAST(record AS TEXT), '$.expected') IS NOT 'null' END ORDER BY key").map_err(|_| Error::Io)?;
    let mut cursor = statement
        .query([i64::try_from(MAX_RECORD * 5).map_err(|_| Error::Budget)?])
        .map_err(|_| Error::Io)?;
    while let Some(row) = cursor.next().map_err(|_| Error::Io)? {
        budget.charge(record_length(row)?, 0)?;
        let record = decode_record(row)?;
        let key = record.key.clone();
        if rows.insert(key, record).is_some() {
            return Err(Error::Configuration);
        }
    }
    Ok(rows)
}

fn record_length(row: &rusqlite::Row<'_>) -> Result<usize, Error> {
    usize::try_from(row.get::<_, i64>(2).map_err(|_| Error::Io)?).map_err(|_| Error::Budget)
}

fn record_bytes<'a>(row: &'a rusqlite::Row<'_>) -> Result<&'a [u8], Error> {
    row.get_ref(1)
        .map_err(|_| Error::Io)?
        .as_blob()
        .map_err(|_| Error::Io)
}

fn decode_record(row: &rusqlite::Row<'_>) -> Result<Row, Error> {
    let key = row.get_ref(0).map_err(|_| Error::Io)?;
    let key = key.as_str().map_err(|_| Error::Io)?;
    if key.len() > 1024 {
        return Err(Error::Budget);
    }
    let record: Row = serde_json::from_slice(record_bytes(row)?).map_err(|_| Error::Io)?;
    // An indexed key mismatch could otherwise collapse distinct SQL rows in the resume map.
    if record.key != key {
        return Err(Error::Configuration);
    }
    record.encode()?;
    Ok(record)
}

async fn writer_loop(
    mut connection: Connection,
    mut rx: mpsc::Receiver<Message>,
    pool: BlockingPool,
    batch: usize,
    flush: Duration,
) -> Result<(), Error> {
    let cancel = CancellationToken::new();
    let mut interval = tokio::time::interval(flush);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pending = Vec::with_capacity(batch);
    loop {
        let message = tokio::select! {
            message = rx.recv() => message,
            _ = interval.tick(), if !pending.is_empty() => {
                let updates = std::mem::replace(&mut pending, Vec::with_capacity(batch));
                connection = pool.run(&cancel, move || commit(connection, updates)).await?;
                continue;
            }
        };
        match message {
            Some(Message::Update(row, ack)) => {
                let durable = ack.is_some();
                pending.push((row, ack));
                if durable || pending.len() >= batch {
                    let updates = std::mem::replace(&mut pending, Vec::with_capacity(batch));
                    connection = pool
                        .run(&cancel, move || commit(connection, updates))
                        .await?;
                }
            }
            Some(Message::Manifest(after, reply)) => {
                let updates = std::mem::replace(&mut pending, Vec::with_capacity(batch));
                connection = pool
                    .run(&cancel, move || {
                        let connection = commit(connection, updates)?;
                        let _ = reply.send(manifest_page(
                            &connection,
                            after.as_deref(),
                            ReadBudget::new(MAX_ROWS, MAX_MANIFEST_PAGE, 2),
                        ));
                        Ok(connection)
                    })
                    .await?;
            }
            Some(Message::Historical(key, reply)) => {
                let updates = std::mem::replace(&mut pending, Vec::with_capacity(batch));
                connection = pool
                    .run(&cancel, move || {
                        let connection = commit(connection, updates)?;
                        let _ = reply.send(historical_row(&connection, &key));
                        Ok(connection)
                    })
                    .await?;
            }
            finish => {
                pool.run(&cancel, move || {
                    let connection = commit(connection, pending)?;
                    let result = connection
                        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                        .map_err(|_| Error::Io);
                    if let Some(Message::Finish(reply)) = finish {
                        let _ = reply.send(result);
                    }
                    result
                })
                .await?;
                return Ok(());
            }
        }
    }
}

type Update = (Row, Option<oneshot::Sender<Result<(), Error>>>);
fn commit(mut connection: Connection, updates: Vec<Update>) -> Result<Connection, Error> {
    let result = (|| {
        let transaction = connection.transaction().map_err(|_| Error::Io)?;
        for (row, _) in &updates {
            let changed = transaction.execute("INSERT INTO files(key,record) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET record=excluded.record WHERE json_extract(CAST(files.record AS TEXT), '$.status') IS NOT 'deleted' OR files.record=excluded.record", params![row.key, row.encode()?]).map_err(|_| Error::Io)?;
            if changed != 1 {
                return Err(Error::Configuration);
            }
        }
        transaction.commit().map_err(|_| Error::Io)
    })();
    for (_, ack) in updates {
        if let Some(ack) = ack {
            let _ = ack.send(result);
        }
    }
    result?;
    Ok(connection)
}

fn historical_row(connection: &Connection, key: &str) -> Result<Option<Row>, Error> {
    let mut statement = connection
        .prepare("SELECT key, record, length(record) FROM files WHERE key=?1")
        .map_err(|_| Error::Io)?;
    let mut cursor = statement.query([key]).map_err(|_| Error::Io)?;
    let Some(row) = cursor.next().map_err(|_| Error::Io)? else {
        return Ok(None);
    };
    if record_length(row)? > MAX_RECORD * 5 {
        return Err(Error::Budget);
    }
    Ok(Some(decode_record(row)?))
}

fn manifest_page(
    connection: &Connection,
    after: Option<&str>,
    mut budget: ReadBudget,
) -> Result<ManifestPage, Error> {
    if budget.bytes > budget.max_bytes {
        return Err(Error::Budget);
    }
    let query = if after.is_some() {
        "SELECT key, record, length(record) FROM files WHERE key>?1 ORDER BY key"
    } else {
        "SELECT key, record, length(record) FROM files WHERE key>=?1 ORDER BY key"
    };
    let mut statement = connection.prepare(query).map_err(|_| Error::Io)?;
    let mut cursor = statement
        .query([after.unwrap_or("")])
        .map_err(|_| Error::Io)?;
    let mut output = vec![b'['];
    let mut last = None;
    let mut more = false;
    while let Some(row) = cursor.next().map_err(|_| Error::Io)? {
        if record_length(row)? > MAX_RECORD * 5 {
            return Err(Error::Budget);
        }
        let record = decode_record(row)?;
        let bytes = record.encode()?; // compact legacy arrays without rewriting tombstones
        let comma = usize::from(budget.rows != 0);
        if budget
            .bytes
            .checked_add(bytes.len())
            .and_then(|n| n.checked_add(comma))
            .is_none_or(|n| n > budget.max_bytes)
        {
            if budget.rows == 0 {
                return Err(Error::Budget);
            }
            more = true;
            break;
        }
        budget.charge(bytes.len(), comma)?;
        if comma != 0 {
            output.push(b',');
        }
        output.extend_from_slice(&bytes);
        last = Some(record.key);
    }
    output.push(b']');
    Ok(ManifestPage {
        bytes: output,
        next: if more { last } else { None },
        rows: budget.rows,
    })
}

#[cfg(test)]
fn manifest(connection: &Connection) -> Result<Vec<u8>, Error> {
    manifest_bounded(connection, ReadBudget::new(MAX_ROWS, MAX_MANIFEST_PAGE, 2))
}

#[cfg(test)]
fn manifest_bounded(connection: &Connection, budget: ReadBudget) -> Result<Vec<u8>, Error> {
    let page = manifest_page(connection, None, budget)?;
    if page.next.is_some() {
        return Err(Error::Budget);
    }
    Ok(page.bytes)
}
