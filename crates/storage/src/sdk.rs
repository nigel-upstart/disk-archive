//! Shared in-process SDK/transfer-manager adapter. No subprocess or source deletion.

use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Region, retry::RetryConfig, timeout::TimeoutConfig},
    types::{ChecksumMode, ServerSideEncryption},
};
use aws_sdk_s3_transfer_manager::{
    Client as TransferManager, Config as TransferConfig,
    io::InputStream,
    memory::{BufferPool, MemoryBudgetConfig, MemoryConfig, Reservation},
    operation::upload::ChecksumStrategy,
    types::{ConcurrencyMode, FailedMultipartUploadPolicy, PartSize, TransferStatus},
};
use aws_smithy_http_client::{
    Builder as HttpBuilder,
    tls::{Provider, TlsContext, TrustStore, rustls_provider::CryptoMode},
};
use base64::Engine as _;
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use sha2::{Digest as _, Sha256};
use tokio_util::task::TaskTracker;

use crate::{
    BlockingPool, CancellationToken, ExpectedUpload, HeadEvidence, Integrity, ObjectStore,
    PreparedUpload, StoreError, StoreFuture, VerifiedUpload, evidence,
};

/// Explicit SDK settings; the shell resolves flag/dotenv/environment precedence first.
/// Construct/load only after dry-run has exited. Standard providers remain in-process;
/// the resolved feature gate forbids `credential_process` execution.
#[derive(Clone)]
pub struct ClientOptions {
    /// Optional explicit shared profile; otherwise use the SDK's standard provider chain.
    pub profile: Option<String>,
    /// Optional region override; otherwise use the SDK's standard provider chain.
    pub region: Option<String>,
    /// Additional PEM trust roots (OS roots remain enabled).
    pub ca_bundle: Option<PathBuf>,
    /// Connection establishment timeout.
    pub connect_timeout: Duration,
    /// Bound on each SDK request attempt, including stalled response streams.
    pub attempt_timeout: Duration,
}

/// Limits shared by every clone of one store. Match the preparer's geometry exactly.
#[derive(Clone)]
pub struct StoreOptions {
    /// Required bucket, never defaulted.
    pub bucket: String,
    /// Single PUT cutoff, strictly below S3's decimal 5GB limit.
    pub multipart_threshold: u64,
    /// Fixed target part size; objects larger than 10000 such parts are rejected.
    pub part_size: u64,
    /// Global SDK/TM request concurrency (also bounds each object's part concurrency).
    pub concurrency: usize,
    /// Global payload pool ceiling, not total process RSS or TLS overhead.
    pub in_flight_bytes: usize,
}

impl StoreOptions {
    /// Check settings without creating credentials, files, threads or network requests.
    ///
    /// # Errors
    /// Invalid limits fail closed, including budgets too small for one part.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.bucket.is_empty()
            || self.bucket.len() > 63
            || self.bucket.chars().any(char::is_control)
            || !(5_242_880..5_000_000_000).contains(&self.multipart_threshold)
            || !(5_242_880..=5_368_709_120).contains(&self.part_size)
            || !(1..=256).contains(&self.concurrency)
            || u64::try_from(self.in_flight_bytes).map_err(|_| StoreError::Configuration)?
                < self.part_size.saturating_add(1_048_576)
        {
            return Err(StoreError::Configuration);
        }
        Ok(())
    }
}

struct Payload {
    bytes: Vec<u8>,
    _reservation: Reservation,
    _spool: Option<Arc<crate::prepare::Spool>>,
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

struct Inner {
    client: Client,
    transfers: TransferManager,
    pool: BufferPool,
    options: StoreOptions,
    tasks: TaskTracker,
    admission: Mutex<()>,
    cleanup_failed: AtomicBool,
    manifest: tokio::sync::Semaphore,
}

/// One shared SDK client, TM scheduler and global payload pool; cheap clones share all limits.
#[derive(Clone)]
pub struct SdkStore {
    inner: Arc<Inner>,
}

impl SdkStore {
    /// Load production providers and OS/native trust roots plus an optional explicit CA bundle.
    /// No endpoint or TLS-validation overrides are accepted here.
    ///
    /// # Errors
    /// Invalid settings, malformed/unreadable CA certificates or resource limits are rejected.
    pub async fn load(
        options: StoreOptions,
        client: ClientOptions,
        blocking: BlockingPool,
    ) -> Result<Self, StoreError> {
        options.validate()?;
        if client.connect_timeout.is_zero() || client.attempt_timeout < client.connect_timeout {
            return Err(StoreError::Configuration);
        }
        let ca = if let Some(path) = client.ca_bundle {
            Some(
                blocking
                    .run(CancellationToken::new(), move |_| read_ca(path))
                    .await?,
            )
        } else {
            None
        };
        let http = tls_http(ca)?;
        let timeout = TimeoutConfig::builder()
            .connect_timeout(client.connect_timeout)
            .operation_attempt_timeout(client.attempt_timeout)
            .operation_timeout(client.attempt_timeout.saturating_mul(8))
            .build();
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .http_client(http)
            .retry_config(RetryConfig::adaptive().with_max_attempts(8))
            .timeout_config(timeout);
        if let Some(profile) = client.profile {
            loader = loader.profile_name(profile);
        }
        if let Some(region) = client.region {
            loader = loader.region(Region::new(region));
        }
        let config = loader.load().await;
        if config.endpoint_url().is_some() {
            return Err(StoreError::Configuration);
        }
        // Latest behavior enables stalled-stream protection. Set explicitly so an SDK
        // default change cannot silently remove it.
        let mut builder = aws_sdk_s3::config::Builder::from(&config);
        // Clear service-specific endpoint values loaded from shared profiles as well.
        // Synthetic endpoints are available only through the explicit new(client) seam.
        builder.set_endpoint_url(None);
        let config = builder
            .stalled_stream_protection(
                aws_sdk_s3::config::StalledStreamProtectionConfig::enabled().build(),
            )
            .build();
        Self::new(Client::from_conf(config), options)
    }

    /// Wrap an explicitly configured shared client (also the localhost synthetic-test seam).
    /// Production callers use `load`, retaining the shell's endpoint/credential override guards.
    ///
    /// # Errors
    /// Invalid limits or an unfulfillable pool budget are rejected before initiating uploads.
    pub fn new(client: Client, options: StoreOptions) -> Result<Self, StoreError> {
        options.validate()?;
        let pool = BufferPool::builder()
            .memory_budget(MemoryBudgetConfig::Limit(options.in_flight_bytes))
            .build()
            .map_err(|_| StoreError::Budget)?;
        let config = TransferConfig::builder()
            .client(client.clone())
            .multipart_threshold(PartSize::Target(options.multipart_threshold))
            .part_size(PartSize::Target(options.part_size))
            .concurrency(ConcurrencyMode::Explicit(options.concurrency))
            .memory(MemoryConfig::Explicit(pool.clone()))
            .build();
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                transfers: TransferManager::new(config),
                pool,
                options,
                tasks: TaskTracker::new(),
                admission: Mutex::new(()),
                cleanup_failed: AtomicBool::new(false),
                manifest: tokio::sync::Semaphore::new(1),
            }),
        })
    }

    /// Currently admitted payload bytes across all store clones; excludes process/TLS overhead.
    #[must_use]
    pub fn payload_bytes_reserved(&self) -> u64 {
        self.inner.pool.metrics().admission_used_bytes()
    }

    async fn upload(
        &self,
        upload: &PreparedUpload,
        cancel: CancellationToken,
    ) -> Result<VerifiedUpload, StoreError> {
        let expected = upload.expected();
        self.check_expected(expected)?;
        if upload.multipart_threshold != self.inner.options.multipart_threshold
            || upload.part_size != self.inner.options.part_size
        {
            return Err(StoreError::Configuration);
        }
        let store = self.clone();
        let expected = expected.clone();
        let path = upload.path()?.to_owned();
        let spool = upload.spool.clone();
        let child = cancel.child_token();
        // Dropping the caller future signals, but never drops the only abort handle.
        let _drop_cancel = child.clone().drop_guard();
        let task = {
            let _admission = self
                .inner
                .admission
                .lock()
                .map_err(|_| StoreError::Worker)?;
            if self.inner.tasks.is_closed() {
                return Err(StoreError::Cancelled);
            }
            self.inner.tasks.spawn(async move {
                let _spool = spool.clone(); // retain quota and private spool through abort/HEAD
                store.transfer(expected, path, spool, child).await
            })
        };
        task.await.map_err(|_| StoreError::Worker)?
    }

    fn check_expected(&self, expected: &ExpectedUpload) -> Result<(), StoreError> {
        expected.validate()?;
        if expected.bucket != self.inner.options.bucket
            || expected.gzip_size > self.inner.options.part_size.saturating_mul(10_000)
        {
            return Err(StoreError::Configuration);
        }
        Ok(())
    }

    async fn transfer(
        &self,
        mut expected: ExpectedUpload,
        path: PathBuf,
        spool: Arc<crate::prepare::Spool>,
        cancel: CancellationToken,
    ) -> Result<VerifiedUpload, StoreError> {
        if cancel.is_cancelled() {
            return Err(StoreError::Cancelled);
        }
        if expected.gzip_size < self.inner.options.multipart_threshold {
            return self.single(expected, path, spool, cancel).await;
        }
        let strategy = match &expected.integrity {
            Integrity::Crc64Nvme { .. } => {
                ChecksumStrategy::with_crc64_nvme(expected.integrity.wire_value())
            }
            _ => ChecksumStrategy::with_calculated_sha256_composite_if_multipart(),
        };
        let body = InputStream::read_from()
            .path(path)
            .length(expected.gzip_size)
            .build()
            .map_err(|_| StoreError::Io)?;
        let handle = self
            .inner
            .transfers
            .upload()
            .bucket(&expected.bucket)
            .key(&expected.key)
            .body(body)
            .content_length(
                i64::try_from(expected.gzip_size).map_err(|_| StoreError::Configuration)?,
            )
            .checksum_strategy(strategy)
            .if_none_match("*")
            .set_metadata(Some(expected.metadata().into_iter().collect()))
            .server_side_encryption(ServerSideEncryption::Aes256)
            .failed_multipart_upload_policy(FailedMultipartUploadPolicy::AbortUpload)
            .initiate()
            .map_err(|_| StoreError::Transport)?;
        loop {
            if cancel.is_cancelled()
                || matches!(
                    handle.status(),
                    TransferStatus::Failed | TransferStatus::Cancelled
                )
            {
                if handle.abort().await.is_err() {
                    self.inner.cleanup_failed.store(true, Ordering::Release);
                    return Err(StoreError::Abort);
                }
                return Err(if cancel.is_cancelled() {
                    StoreError::Cancelled
                } else {
                    StoreError::Transport
                });
            }
            if handle.status() == TransferStatus::Completed {
                break;
            }
            tokio::select! {
                () = cancel.cancelled() => {},
                () = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
        let receipt = handle.join().await.map_err(|_| StoreError::Transport)?;
        expected.version_id = receipt.version_id().map(str::to_owned);
        expected.etag = receipt.e_tag().map(str::to_owned);
        // At least one server selector is mandatory for a request-bound post-PUT HEAD.
        if expected.version_id.is_none() && expected.etag.is_none() {
            return Err(StoreError::Integrity);
        }
        self.verify_existing(&expected, cancel).await
    }

    async fn single(
        &self,
        mut expected: ExpectedUpload,
        path: PathBuf,
        spool: Arc<crate::prepare::Spool>,
        cancel: CancellationToken,
    ) -> Result<VerifiedUpload, StoreError> {
        // Reserve the entire logical body in the shared payload domain. The actual body
        // streams bounded chunks, but whole-body admission also covers HTTP/retry retention.
        let size = usize::try_from(expected.gzip_size).map_err(|_| StoreError::Budget)?;
        let reservation = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(StoreError::Cancelled),
            result = self.inner.pool.reserve(size) => result.map_err(|_| StoreError::Budget)?,
        };
        let bytes = tokio::fs::read(path).await.map_err(|_| StoreError::Io)?;
        if bytes.len() != size {
            return Err(StoreError::Integrity);
        }
        // Bytes clones keep both admission and spool quota alive even when Hyper
        // retains a frame after the SDK caller has cancelled its request future.
        let body = aws_sdk_s3::primitives::ByteStream::from(bytes::Bytes::from_owner(Payload {
            bytes,
            _reservation: reservation,
            _spool: Some(spool),
        }));
        let request = self
            .inner
            .client
            .put_object()
            .bucket(&expected.bucket)
            .key(&expected.key)
            .body(body)
            .if_none_match("*")
            .server_side_encryption(ServerSideEncryption::Aes256)
            .set_metadata(Some(expected.metadata().into_iter().collect()));
        let request = match expected.integrity {
            Integrity::Crc64Nvme { .. } => {
                request.checksum_crc64_nvme(expected.integrity.wire_value())
            }
            Integrity::Sha256 { .. } => request.checksum_sha256(expected.integrity.wire_value()),
            Integrity::Sha256Composite { .. } => return Err(StoreError::Configuration),
        };
        let receipt = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(StoreError::Cancelled),
            result = request.send() => result.map_err(|_| StoreError::Transport)?,
        };
        expected.version_id = receipt.version_id;
        expected.etag = receipt.e_tag;
        if expected.version_id.is_none() && expected.etag.is_none() {
            return Err(StoreError::Integrity);
        }
        self.verify_existing(&expected, cancel).await
    }

    async fn read_head(
        &self,
        key: &str,
        version: Option<&str>,
        etag: Option<&str>,
        cancel: CancellationToken,
    ) -> Result<HeadEvidence, StoreError> {
        if !evidence::valid_key(key) {
            return Err(StoreError::Configuration);
        }
        let request = self
            .inner
            .client
            .head_object()
            .bucket(&self.inner.options.bucket)
            .key(key)
            .set_version_id(version.map(str::to_owned))
            .set_if_match(etag.map(str::to_owned))
            .checksum_mode(ChecksumMode::Enabled);
        let output = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(StoreError::Cancelled),
            response = request.send() => response.map_err(|error| {
                if error.as_service_error().is_some_and(aws_sdk_s3::operation::head_object::HeadObjectError::is_not_found) { StoreError::NotFound } else { StoreError::Transport }
            })?,
        };
        // Reject ambiguous algorithms rather than guessing which header is authoritative.
        let checksums = [
            ("CRC64NVME", output.checksum_crc64_nvme()),
            ("SHA256", output.checksum_sha256()),
            ("CRC32", output.checksum_crc32()),
            ("CRC32C", output.checksum_crc32_c()),
            ("SHA1", output.checksum_sha1()),
        ];
        let mut actual = checksums.into_iter().filter_map(|(algorithm, value)| {
            value.map(|value| (algorithm.to_owned(), value.to_owned()))
        });
        let checksum = actual.next();
        if actual.next().is_some() {
            return Err(StoreError::Integrity);
        }
        drop(actual);
        let (algorithm, value) = checksum.map_or((None, None), |(a, v)| (Some(a), Some(v)));
        Ok(HeadEvidence {
            bucket: self.inner.options.bucket.clone(),
            key: key.to_owned(),
            content_length: output
                .content_length()
                .and_then(|size| u64::try_from(size).ok()),
            encryption: output
                .server_side_encryption()
                .map(|s| s.as_str().to_owned()),
            checksum_type: output.checksum_type().map(|s| s.as_str().to_owned()),
            checksum_algorithm: algorithm,
            checksum_value: value,
            metadata: output.metadata.unwrap_or_default().into_iter().collect(),
            version_id: output.version_id,
            etag: output.e_tag,
        })
    }
}

impl ObjectStore for SdkStore {
    fn put_object_verified<'a>(
        &'a self,
        upload: &'a PreparedUpload,
        cancel: CancellationToken,
    ) -> StoreFuture<'a, VerifiedUpload> {
        Box::pin(self.upload(upload, cancel))
    }

    fn verify_existing<'a>(
        &'a self,
        expected: &'a ExpectedUpload,
        cancel: CancellationToken,
    ) -> StoreFuture<'a, VerifiedUpload> {
        Box::pin(async move {
            self.check_expected(expected)?;
            let head = self
                .read_head(
                    &expected.key,
                    expected.version_id.as_deref(),
                    expected.etag.as_deref(),
                    cancel,
                )
                .await?;
            evidence::verify(expected, &head)
        })
    }

    fn head<'a>(
        &'a self,
        key: &'a str,
        version_id: Option<&'a str>,
        cancel: CancellationToken,
    ) -> StoreFuture<'a, HeadEvidence> {
        Box::pin(self.read_head(key, version_id, None, cancel))
    }

    fn put_manifest<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
        cancel: CancellationToken,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            if !evidence::valid_key(key) || bytes.len() > 1_048_576 {
                return Err(StoreError::Budget);
            }
            let _permit = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(StoreError::Cancelled),
                permit = self.inner.manifest.acquire() => permit.map_err(|_| StoreError::Budget)?,
            };
            let reservation = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(StoreError::Cancelled),
                result = self.inner.pool.reserve(bytes.len().max(1)) => result.map_err(|_| StoreError::Budget)?,
            };
            let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes));
            let body = bytes::Bytes::from_owner(Payload {
                bytes: bytes.to_vec(),
                _reservation: reservation,
                _spool: None,
            });
            let request = self
                .inner
                .client
                .put_object()
                .bucket(&self.inner.options.bucket)
                .key(key)
                .body(body.into())
                .checksum_sha256(&digest)
                .server_side_encryption(ServerSideEncryption::Aes256);
            let receipt = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(StoreError::Cancelled),
                result = request.send() => result.map_err(|_| StoreError::Transport)?,
            };
            if receipt.version_id().is_none() && receipt.e_tag().is_none() {
                return Err(StoreError::Integrity);
            }
            let head = self
                .read_head(key, receipt.version_id(), receipt.e_tag(), cancel)
                .await?;
            if head.content_length != u64::try_from(bytes.len()).ok()
                || head.checksum_algorithm.as_deref() != Some("SHA256")
                || head.checksum_type.as_deref() != Some("FULL_OBJECT")
                || head.checksum_value.as_deref() != Some(&digest)
                || head.encryption.as_deref() != Some("AES256")
            {
                return Err(StoreError::Integrity);
            }
            Ok(())
        })
    }

    fn drain(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            {
                let _admission = self
                    .inner
                    .admission
                    .lock()
                    .map_err(|_| StoreError::Worker)?;
                self.inner.tasks.close();
            }
            self.inner.tasks.wait().await;
            if self.inner.cleanup_failed.load(Ordering::Acquire) {
                return Err(StoreError::Abort);
            }
            Ok(())
        })
    }
}

fn read_ca(path: PathBuf) -> Result<Vec<u8>, StoreError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|_| StoreError::Configuration)?;
    if !file
        .metadata()
        .map_err(|_| StoreError::Configuration)?
        .is_file()
    {
        return Err(StoreError::Configuration);
    }
    let mut bytes = Vec::new();
    file.take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::Configuration)?;
    validate_ca(&bytes)?;
    Ok(bytes)
}

pub(crate) fn tls_http(
    ca: Option<Vec<u8>>,
) -> Result<aws_sdk_s3::config::SharedHttpClient, StoreError> {
    let mut trust = TrustStore::default();
    if let Some(pem) = ca {
        validate_ca(&pem)?;
        trust = trust.with_pem_certificate(pem);
    }
    let tls = TlsContext::builder()
        .with_trust_store(trust)
        .build()
        .map_err(|_| StoreError::Configuration)?;
    Ok(HttpBuilder::new()
        .tls_provider(Provider::Rustls(CryptoMode::AwsLc))
        .tls_context(tls)
        .build_https())
}

fn validate_ca(bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err(StoreError::Configuration);
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(bytes) {
        roots
            .add(certificate.map_err(|_| StoreError::Configuration)?)
            .map_err(|_| StoreError::Configuration)?;
    }
    if roots.is_empty() {
        return Err(StoreError::Configuration);
    }
    Ok(())
}
