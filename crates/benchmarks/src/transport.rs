//! Transparent outer proxy for the vetted storage fixture. Never loads credentials.
//! Counts actual attempts and streamed request bodies, including retries. Raw routes
//! stay private until independently supplied corpus/manifest bindings certify them.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use hyper::{
    Method, Request, Response,
    body::{Body, Bytes, Frame, Incoming},
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::wire::{Payload, WireError};

const MAX_ROUTES: usize = 4096;
const MAX_CONNECTIONS: usize = 64;

/// Static observation failure; never includes paths, headers or body data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationError;

impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("incomplete transport observation")
    }
}
impl std::error::Error for ObservationError {}

/// Observed archive transport class. Classification must agree with actual operations.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SizeClass {
    /// One `PutObject`, plus any HEAD/retries.
    Single,
    /// Actual multipart lifecycle, including part/abort attempts.
    Multipart,
}

struct Binding {
    slot: String,
    class: SizeClass,
    manifest: bool,
}

/// Independent seeded source slots and semantic manifest chunk slots, not request order.
#[derive(Default)]
pub struct Bindings {
    routes: BTreeMap<String, Binding>,
    poisoned: bool,
}

impl Bindings {
    /// Bind one exact HTTP path to an independent source slot.
    ///
    /// # Errors
    /// Duplicate path/slot, invalid route or excessive layout size.
    pub fn archive(
        &mut self,
        path: &str,
        slot: u64,
        class: SizeClass,
    ) -> Result<(), ObservationError> {
        self.insert(path, format!("archive-{slot:06}"), class, false)
    }

    /// Bind a root/data/index manifest path using an independently checked semantic slot.
    /// The caller must verify the manifest's contents, not enumerate observed routes.
    ///
    /// # Errors
    /// Duplicate path/slot, invalid route or excessive layout size.
    pub fn manifest(&mut self, path: &str, slot: u64) -> Result<(), ObservationError> {
        self.insert(path, format!("manifest-{slot:06}"), SizeClass::Single, true)
    }

    fn insert(
        &mut self,
        path: &str,
        slot: String,
        class: SizeClass,
        manifest: bool,
    ) -> Result<(), ObservationError> {
        if self.poisoned
            || !valid_path(path)
            || self.routes.len() >= MAX_ROUTES
            || self.routes.contains_key(path)
            || self.routes.values().any(|b| b.slot == slot)
        {
            self.poisoned = true;
            return Err(ObservationError);
        }
        self.routes.insert(
            path.into(),
            Binding {
                slot,
                class,
                manifest,
            },
        );
        Ok(())
    }
}

/// Metadata-only complete transport result. No source paths, headers or payloads.
#[derive(Debug, Eq, PartialEq)]
pub struct TransportStats {
    /// Actual request attempts per normalized object, including HEAD and retries.
    pub requests: BTreeMap<String, u64>,
    /// Actual dechunked archive data sent (part and `PutObject` bodies, including retries).
    pub bytes_uploaded: u64,
    /// Advisory manifest `PutObject` payload bytes, not archive payload.
    pub manifest_bytes: u64,
    /// Advisory control-operation body bytes (e.g. `CompleteMultipartUpload` XML).
    pub control_bytes: u64,
    /// HTTP body bytes before AWS dechunking, not TCP/TLS/header bytes.
    pub wire_body_bytes: u64,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum Operation {
    Put,
    Head,
    Create,
    Part,
    Complete,
    Abort,
}

impl Operation {
    fn data(self) -> bool {
        matches!(self, Self::Put | Self::Part)
    }
    fn multipart(self) -> bool {
        matches!(
            self,
            Self::Create | Self::Part | Self::Complete | Self::Abort
        )
    }
}

#[derive(Default)]
struct Route {
    requests: u64,
    data: u64,
    control: u64,
    operations: BTreeSet<Operation>,
}

#[derive(Default)]
struct State {
    poisoned: bool,
    active: u64,
    bodies: u64,
    wire: u64,
    routes: BTreeMap<String, Route>,
}

#[derive(Clone, Default)]
struct Observation(Arc<Mutex<State>>);

impl Observation {
    fn change<T>(
        &self,
        f: impl FnOnce(&mut State) -> Result<T, ObservationError>,
    ) -> Result<T, ObservationError> {
        let mut state = self.0.lock().map_err(|_| ObservationError)?;
        if state.poisoned {
            return Err(ObservationError);
        }
        let result = f(&mut state);
        if result.is_err() {
            state.poisoned = true;
        }
        result
    }
    fn poison(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.poisoned = true;
        }
    }
}

/// Listener with bounded live connections. Call `finish` only after production store drain.
/// No ambient URL/credentials, DNS lookup, redirect handling or non-loopback forwarding.
pub struct MeasuringProxy {
    endpoint: String,
    observation: Observation,
    cancel: CancellationToken,
    tasks: TaskTracker,
}

impl MeasuringProxy {
    /// Wrap only the already-vetted synthetic SDK fixture, without environment lookup.
    ///
    /// # Errors
    /// Missing/non-loopback fixture endpoint or listener failure.
    #[cfg(feature = "sdk")]
    pub async fn around_mock(
        mock: &disk_archive_storage::test_support::MockS3,
    ) -> Result<Self, ObservationError> {
        Self::start(mock.endpoint()).await
    }

    /// Clone the fixture's fixed fake credentials/configuration and replace ONLY its endpoint.
    #[cfg(feature = "sdk")]
    #[must_use]
    pub fn client(&self, mock: &disk_archive_storage::test_support::MockS3) -> aws_sdk_s3::Client {
        let injected = mock.client();
        aws_sdk_s3::Client::from_conf(
            injected
                .config()
                .to_builder()
                .endpoint_url(self.endpoint())
                .build(),
        )
    }

    /// Forward only to a literal loopback HTTP socket (the existing `MockS3` endpoint).
    ///
    /// # Errors
    /// Invalid/non-loopback target, listener failure or incomplete observations.
    pub async fn start(endpoint: &str) -> Result<Self, ObservationError> {
        let target = loopback(endpoint)?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| ObservationError)?;
        let endpoint = format!(
            "http://{}",
            listener.local_addr().map_err(|_| ObservationError)?
        );
        let observation = Observation::default();
        let cancel = CancellationToken::new();
        let tasks = TaskTracker::new();
        let tracker = tasks.clone();
        let stop = cancel.clone();
        let observed = observation.clone();
        tasks.spawn(async move {
            let http: Client<HttpConnector, ObservedBody> = Client::builder(TokioExecutor::new()).build_http();
            let capacity = Arc::new(Semaphore::new(MAX_CONNECTIONS));
            loop {
                let accepted = tokio::select! {
                    biased;
                    () = stop.cancelled() => break,
                    result = listener.accept() => result,
                };
                let Ok((socket, peer)) = accepted else { observed.poison(); break; };
                let Ok(permit) = capacity.clone().try_acquire_owned() else { observed.poison(); break; };
                if !peer.ip().is_loopback() { observed.poison(); break; }
                let http = http.clone();
                let observed = observed.clone();
                let stop = stop.clone();
                tracker.spawn(async move {
                    let _permit = permit;
                    let audit = observed.clone();
                    let service = service_fn(move |request| forward(request, http.clone(), observed.clone(), target));
                    tokio::select! {
                        () = stop.cancelled() => {},
                        result = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service) => {
                            if result.is_err() { audit.poison(); }
                        },
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            observation,
            cancel,
            tasks,
        })
    }

    /// Use only as endpoint replacement on a clone of `MockS3`'s injected fake client config.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Stop listeners, join connections, then require complete one-to-one route coverage.
    /// Unknown routes, unfinished bodies and poisoned counters never emit a passing result.
    ///
    /// # Errors
    /// Any incomplete observation, ambiguous binding, operation/class contradiction or overflow.
    pub async fn finish(self, bindings: &Bindings) -> Result<TransportStats, ObservationError> {
        self.cancel.cancel();
        self.tasks.close();
        self.tasks.wait().await;
        self.observation.change(|state| {
            if bindings.poisoned
                || state.active != 0
                || state.bodies != 0
                || state.routes.is_empty()
            {
                return Err(ObservationError);
            }
            let mut result = TransportStats {
                requests: BTreeMap::new(),
                bytes_uploaded: 0,
                manifest_bytes: 0,
                control_bytes: 0,
                wire_body_bytes: state.wire,
            };
            for (path, route) in &state.routes {
                let binding = bindings.routes.get(path).ok_or(ObservationError)?;
                let multipart = route.operations.iter().any(|op| op.multipart());
                if multipart != (binding.class == SizeClass::Multipart)
                    || (multipart && route.operations.contains(&Operation::Put))
                    || (binding.manifest
                        && route
                            .operations
                            .iter()
                            .any(|op| !matches!(op, Operation::Put | Operation::Head)))
                {
                    return Err(ObservationError);
                }
                let class = if multipart { "multipart" } else { "single" };
                result
                    .requests
                    .insert(format!("{class}/{}", binding.slot), route.requests);
                let bytes = if binding.manifest {
                    &mut result.manifest_bytes
                } else {
                    &mut result.bytes_uploaded
                };
                *bytes = bytes.checked_add(route.data).ok_or(ObservationError)?;
                result.control_bytes = result
                    .control_bytes
                    .checked_add(route.control)
                    .ok_or(ObservationError)?;
            }
            Ok(result)
        })
    }
}

impl Drop for MeasuringProxy {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.close();
    }
}

fn loopback(endpoint: &str) -> Result<SocketAddr, ObservationError> {
    let address: SocketAddr = endpoint
        .strip_prefix("http://")
        .ok_or(ObservationError)?
        .parse()
        .map_err(|_| ObservationError)?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(ObservationError);
    }
    Ok(address)
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 1024
        && !path.contains(['?', '#'])
        && path.bytes().all(|b| b.is_ascii_graphic())
}

fn operation(request: &Request<Incoming>) -> Result<Operation, ObservationError> {
    let mut fields = BTreeMap::new();
    if let Some(query) = request.uri().query() {
        for field in query.split('&') {
            let (key, value) = field.split_once('=').unwrap_or((field, ""));
            if !matches!(
                key,
                "uploads" | "uploadId" | "partNumber" | "versionId" | "x-id"
            ) || fields.insert(key, value).is_some()
            {
                return Err(ObservationError);
            }
        }
    }
    let id = fields.remove("x-id");
    let op = match (request.method(), fields.len()) {
        (&Method::PUT, 0) => Operation::Put,
        (&Method::HEAD, 0) => Operation::Head,
        (&Method::HEAD, 1) if fields.get("versionId").is_some_and(|s| !s.is_empty()) => {
            Operation::Head
        }
        (&Method::POST, 1) if fields.get("uploads") == Some(&"") => Operation::Create,
        (&Method::PUT, 2)
            if fields.get("uploadId").is_some_and(|s| !s.is_empty())
                && fields
                    .get("partNumber")
                    .is_some_and(|s| s.parse::<u16>().is_ok_and(|n| (1..=10_000).contains(&n))) =>
        {
            Operation::Part
        }
        (&Method::POST, 1) if fields.get("uploadId").is_some_and(|s| !s.is_empty()) => {
            Operation::Complete
        }
        (&Method::DELETE, 1) if fields.get("uploadId").is_some_and(|s| !s.is_empty()) => {
            Operation::Abort
        }
        _ => return Err(ObservationError),
    };
    let name = match op {
        Operation::Put => "PutObject",
        Operation::Head => "HeadObject",
        Operation::Create => "CreateMultipartUpload",
        Operation::Part => "UploadPart",
        Operation::Complete => "CompleteMultipartUpload",
        Operation::Abort => "AbortMultipartUpload",
    };
    if id.is_some_and(|id| id != name) {
        return Err(ObservationError);
    }
    Ok(op)
}

struct RequestGuard(Observation);
impl Drop for RequestGuard {
    fn drop(&mut self) {
        let _ = self.0.change(|s| {
            s.active = s.active.checked_sub(1).ok_or(ObservationError)?;
            Ok(())
        });
    }
}

async fn forward(
    mut request: Request<Incoming>,
    http: Client<HttpConnector, ObservedBody>,
    observed: Observation,
    target: SocketAddr,
) -> Result<Response<Incoming>, ObservationError> {
    let result = async {
        if request.uri().scheme().is_some() || !valid_path(request.uri().path()) {
            return Err(ObservationError);
        }
        let op = operation(&request)?;
        let path = request.uri().path().to_owned();
        let encoding = request
            .headers()
            .get("content-encoding")
            .map(|h| h.to_str())
            .transpose()
            .map_err(|_| ObservationError)?;
        if encoding.is_some_and(|e| e != "aws-chunked") {
            return Err(ObservationError);
        }
        let aws = encoding == Some("aws-chunked");
        let length = request
            .headers()
            .get(if aws {
                "x-amz-decoded-content-length"
            } else {
                "content-length"
            })
            .map(|h| {
                h.to_str()
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or(ObservationError)
            })
            .transpose()?;
        if aws && length.is_none() {
            return Err(ObservationError);
        }
        observed.change(|s| {
            if s.routes.len() >= MAX_ROUTES && !s.routes.contains_key(&path) {
                return Err(ObservationError);
            }
            let route = s.routes.entry(path.clone()).or_default();
            route.requests = route.requests.checked_add(1).ok_or(ObservationError)?;
            route.operations.insert(op);
            s.active = s.active.checked_add(1).ok_or(ObservationError)?;
            Ok(())
        })?;
        let _guard = RequestGuard(observed.clone());
        let uri = format!(
            "http://{target}{}",
            request.uri().path_and_query().ok_or(ObservationError)?
        );
        *request.uri_mut() = uri.parse().map_err(|_| ObservationError)?;
        let (parts, incoming) = request.into_parts();
        let body = ObservedBody::new(incoming, observed.clone(), path, op, aws, length)?;
        // Preserve every signed header and actual body byte, changing only the destination.
        http.request(Request::from_parts(parts, body))
            .await
            .map_err(|_| ObservationError)
    }
    .await;
    if result.is_err() {
        observed.poison();
    }
    result
}

struct ObservedBody {
    inner: Incoming,
    observed: Observation,
    path: String,
    op: Operation,
    parser: Payload,
    done: bool,
}

impl ObservedBody {
    fn new(
        inner: Incoming,
        observed: Observation,
        path: String,
        op: Operation,
        aws: bool,
        length: Option<u64>,
    ) -> Result<Self, ObservationError> {
        let done = inner.is_end_stream();
        let parser = Payload::new(aws, length);
        if done {
            parser.finish().map_err(|_| ObservationError)?;
        } else {
            observed.change(|s| {
                s.bodies = s.bodies.checked_add(1).ok_or(ObservationError)?;
                Ok(())
            })?;
        }
        Ok(Self {
            inner,
            observed,
            path,
            op,
            parser,
            done,
        })
    }
    fn finish(&mut self) -> Result<(), ObservationError> {
        self.parser.finish().map_err(|_| ObservationError)?;
        self.observed.change(|s| {
            s.bodies = s.bodies.checked_sub(1).ok_or(ObservationError)?;
            Ok(())
        })?;
        self.done = true;
        Ok(())
    }
    fn data(&mut self, bytes: &[u8]) -> Result<(), ObservationError> {
        self.observed.change(|s| {
            s.wire = s
                .wire
                .checked_add(u64::try_from(bytes.len()).map_err(|_| ObservationError)?)
                .ok_or(ObservationError)?;
            Ok(())
        })?;
        self.parser
            .consume(bytes, |n| {
                self.observed
                    .change(|s| {
                        let route = s.routes.get_mut(&self.path).ok_or(ObservationError)?;
                        let value = if self.op.data() {
                            &mut route.data
                        } else {
                            &mut route.control
                        };
                        *value = value.checked_add(n).ok_or(ObservationError)?;
                        Ok(())
                    })
                    .map_err(|_| WireError)
            })
            .map_err(|_| ObservationError)
    }
}

impl Body for ObservedBody {
    type Data = Bytes;
    type Error = ObservationError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, ObservationError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && self.data(data).is_err()
                {
                    self.observed.poison();
                    return Poll::Ready(Some(Err(ObservationError)));
                }
                if self.inner.is_end_stream() && self.finish().is_err() {
                    self.observed.poison();
                    return Poll::Ready(Some(Err(ObservationError)));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(_))) => {
                self.observed.poison();
                Poll::Ready(Some(Err(ObservationError)))
            }
            Poll::Ready(None) => match self.finish() {
                Ok(()) => Poll::Ready(None),
                Err(error) => {
                    self.observed.poison();
                    Poll::Ready(Some(Err(error)))
                }
            },
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
}

impl Drop for ObservedBody {
    fn drop(&mut self) {
        if !self.done {
            self.observed.poison();
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "sdk"))]
mod sdk_tests;
