//! Synthetic localhost HTTP/SigV4 fixture, never ambient credentials or live AWS.
//!
//! The unmodified upstream server incorrectly labels composite HEAD checksums `FULL_OBJECT`.
//! The proxy corrects only that label from the actual stored composite suffix. It can then
//! inject independent HEAD faults. It never supplies a missing checksum or metadata value.
//! Upstream does not implement version/If-Match enforcement or `ListMultipartUploads`; recorded
//! successful abort HTTP responses test cleanup, not real-S3 crash/lifecycle guarantees.

use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region, retry::RetryConfig, timeout::TimeoutConfig},
};
use hyper::{Request, body::Incoming, service::service_fn};
use hyper_util::{
    client::legacy::{Client as HttpClient, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::net::TcpListener;
use tokio_util::task::TaskTracker;

use crate::{CancellationToken, StoreError};
pub use s3_mock_server::{FaultType, Occurrence, S3MockServer};

/// One deliberately malformed HEAD fact. Zero is a faithful response.
#[derive(Clone, Copy)]
pub enum HeadFault {
    /// No fault.
    None = 0,
    /// Wrong checksum value.
    Checksum = 1,
    /// Required checksum header absent.
    MissingChecksum = 2,
    /// Incompatible checksum type.
    Type = 3,
    /// Wrong content length.
    Length = 4,
    /// Wrong source-size user metadata.
    Metadata = 5,
    /// Wrong SSE algorithm.
    Encryption = 6,
}

#[derive(Default)]
struct Controls {
    head_fault: AtomicU8,
    created: AtomicUsize,
    aborted: AtomicUsize,
    parts: AtomicUsize,
}

/// Local upstream server plus a fault/observation proxy. All fixtures are synthetic.
/// Call shutdown after store.drain; connection tasks are cancelled and joined.
pub struct MockS3 {
    /// Public upstream controls for deterministic request-body stalls and 5xx retries.
    pub server: S3MockServer,
    upstream: s3_mock_server::ServerHandle,
    endpoint: String,
    controls: Arc<Controls>,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

impl MockS3 {
    /// Start two loopback-only, ephemeral-port listeners with synthetic `SigV4` credentials.
    ///
    /// # Errors
    /// Listener or server initialization failure is returned without raw diagnostics.
    pub async fn start() -> Result<Self, StoreError> {
        let server = S3MockServer::builder()
            .with_in_memory_store()
            .build()
            .map_err(|_| StoreError::Worker)?;
        server
            .create_bucket("synthetic-archive")
            .await
            .map_err(|_| StoreError::Worker)?;
        let upstream = server.start().await.map_err(|_| StoreError::Worker)?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| StoreError::Io)?;
        let endpoint = format!(
            "http://{}",
            listener.local_addr().map_err(|_| StoreError::Io)?
        );
        let target = upstream.socket_addr();
        let controls = Arc::new(Controls::default());
        let cancel = CancellationToken::new();
        let tasks = TaskTracker::new();
        let tracker = tasks.clone();
        let control = controls.clone();
        let stop = cancel.clone();
        tasks.spawn(async move {
            let http: HttpClient<HttpConnector, Incoming> =
                HttpClient::builder(TokioExecutor::new()).build_http();
            loop {
                let accepted = tokio::select! {
                    biased;
                    () = stop.cancelled() => break,
                    result = listener.accept() => result,
                };
                let Ok((socket, _)) = accepted else { break };
                let http = http.clone();
                let control = control.clone();
                let stop = stop.clone();
                tracker.spawn(async move {
                    let service = service_fn(move |mut request: Request<Incoming>| {
                        let http = http.clone();
                        let control = control.clone();
                        async move {
                            let (head, create, abort, part) = classify(&request);
                            // Preserve the signed Host header; only routing changes.
                            let uri = format!(
                                "http://{target}{}",
                                request
                                    .uri()
                                    .path_and_query()
                                    .map_or("/", hyper::http::uri::PathAndQuery::as_str)
                            );
                            if let Ok(uri) = uri.parse() {
                                *request.uri_mut() = uri;
                            }
                            if part {
                                control.parts.fetch_add(1, Ordering::AcqRel);
                            }
                            let mut response = http.request(request).await?;
                            if response.status().is_success() {
                                if create {
                                    control.created.fetch_add(1, Ordering::AcqRel);
                                }
                                if abort {
                                    control.aborted.fetch_add(1, Ordering::AcqRel);
                                }
                            }
                            if head && response.status().is_success() {
                                mutate_head(
                                    response.headers_mut(),
                                    control.head_fault.load(Ordering::Acquire),
                                );
                            }

                            Ok::<_, hyper_util::client::legacy::Error>(response)
                        }
                    });
                    let builder = Builder::new(TokioExecutor::new());
                    tokio::select! {
                        () = stop.cancelled() => {},
                        _ = builder.serve_connection(TokioIo::new(socket), service) => {},
                    }
                });
            }
        });
        Ok(Self {
            server,
            upstream,
            endpoint,
            controls,
            cancel,
            tasks,
        })
    }

    /// Client with fixed synthetic credentials, region, endpoint and bounded retries/timeouts.
    /// This does not load shared files, profiles, IMDS, dotenv or environment credentials.
    #[must_use]
    pub fn client(&self) -> Client {
        Client::from_conf(
            aws_sdk_s3::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(Credentials::new(
                    "mock-akid",
                    "mock-secret",
                    None,
                    None,
                    "synthetic",
                ))
                .region(Region::new("us-east-1"))
                .endpoint_url(&self.endpoint)
                .force_path_style(true)
                .retry_config(RetryConfig::standard().with_max_attempts(3))
                .timeout_config(
                    TimeoutConfig::builder()
                        .connect_timeout(std::time::Duration::from_secs(2))
                        .operation_attempt_timeout(std::time::Duration::from_secs(4))
                        .operation_timeout(std::time::Duration::from_secs(15))
                        .build(),
                )
                .build(),
        )
    }

    /// Set independent HEAD corruption for subsequent requests.
    pub fn set_head_fault(&self, fault: HeadFault) {
        self.controls
            .head_fault
            .store(fault as u8, Ordering::Release);
    }

    /// Successful create-MPU responses observed, excluding response-loss/crash windows.
    #[must_use]
    pub fn created(&self) -> usize {
        self.controls.created.load(Ordering::Acquire)
    }

    /// Successful abort-MPU responses observed from the actual upstream server.
    #[must_use]
    pub fn aborted(&self) -> usize {
        self.controls.aborted.load(Ordering::Acquire)
    }

    /// Part requests observed before forwarding (permits deterministic mid-upload cancellation).
    #[must_use]
    pub fn parts(&self) -> usize {
        self.controls.parts.load(Ordering::Acquire)
    }

    /// Stop listeners and join fixture tasks. Does not touch any external runtime files.
    ///
    /// # Errors
    /// Failure to shut down the upstream server is returned as a static error.
    pub async fn shutdown(self) -> Result<(), StoreError> {
        self.cancel.cancel();
        self.tasks.close();
        self.tasks.wait().await;
        self.upstream
            .shutdown()
            .await
            .map_err(|_| StoreError::Worker)
    }
}

fn classify(request: &Request<Incoming>) -> (bool, bool, bool, bool) {
    let query = request.uri().query().unwrap_or_default();
    (
        request.method() == hyper::Method::HEAD,
        request.method() == hyper::Method::POST && (query == "uploads" || query == "uploads="),
        request.method() == hyper::Method::DELETE && query.contains("uploadId="),
        request.method() == hyper::Method::PUT && query.contains("partNumber="),
    )
}

fn mutate_head(headers: &mut hyper::HeaderMap, fault: u8) {
    if headers
        .get("x-amz-checksum-sha256")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.contains('-'))
    {
        headers.insert(
            "x-amz-checksum-type",
            hyper::http::HeaderValue::from_static("COMPOSITE"),
        );
    }
    match fault {
        1 => {
            headers.insert(
                "x-amz-checksum-crc64nvme",
                hyper::http::HeaderValue::from_static("AAAAAAAAAAA="),
            );
            headers.remove("x-amz-checksum-sha256");
        }
        2 => {
            headers.remove("x-amz-checksum-crc64nvme");
            headers.remove("x-amz-checksum-sha256");
        }
        3 => {
            headers.insert(
                "x-amz-checksum-type",
                hyper::http::HeaderValue::from_static("UNSUPPORTED"),
            );
        }
        4 => {
            headers.insert("content-length", hyper::http::HeaderValue::from_static("1"));
        }
        5 => {
            headers.insert(
                "x-amz-meta-orig-size",
                hyper::http::HeaderValue::from_static("99999999"),
            );
        }
        6 => {
            headers.insert(
                "x-amz-server-side-encryption",
                hyper::http::HeaderValue::from_static("aws:kms"),
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod budget_tests;
#[cfg(test)]
mod orphan_tests;
#[cfg(test)]
mod prepare_tests;
#[cfg(test)]
mod resource_order_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_tests;
