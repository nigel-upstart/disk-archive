//! Transport controls use a byte sink, NOT a surrogate S3 or end-to-end benchmark.
use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

struct Empty;
impl Body for Empty {
    type Data = Bytes;
    type Error = ObservationError;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, ObservationError>>> {
        Poll::Ready(None)
    }
    fn is_end_stream(&self) -> bool {
        true
    }
}

struct Sink {
    endpoint: String,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: CancellationToken,
    tasks: TaskTracker,
}
impl Sink {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = CancellationToken::new();
        let tasks = TaskTracker::new();
        let tracker = tasks.clone();
        let cancel = stop.clone();
        let bytes = received.clone();
        tasks.spawn(async move {
            loop {
                let socket = tokio::select! {
                    () = cancel.cancelled() => break,
                    result = listener.accept() => result,
                };
                let Ok((socket, _)) = socket else { break; };
                let bytes = bytes.clone();
                let cancel = cancel.clone();
                tracker.spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let bytes = bytes.clone();
                        async move {
                            let mut body = request.into_body();
                            let mut data = Vec::new();
                            while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                                let frame = frame.map_err(|_| ObservationError)?;
                                if let Some(frame) = frame.data_ref() { data.extend_from_slice(frame); }
                            }
                            bytes.lock().map_err(|_| ObservationError)?.push(data);
                            Ok::<_, ObservationError>(Response::new(Empty))
                        }
                    });
                    tokio::select! {
                        () = cancel.cancelled() => {},
                        _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service) => {},
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            received,
            stop,
            tasks,
        })
    }
    async fn close(self) {
        self.stop.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }
}

async fn send(
    endpoint: &str,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = loopback(endpoint)?;
    let mut socket = TcpStream::connect(target).await?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {target}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    );
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(body).await?;
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await?;
    if !response.starts_with(b"HTTP/1.1 200") {
        return Err(ObservationError.into());
    }
    Ok(())
}

#[tokio::test]
async fn actual_http_attempts_dechunking_and_advisory_totals()
-> Result<(), Box<dyn std::error::Error>> {
    let sink = Sink::start().await?;
    let proxy = MeasuringProxy::start(&sink.endpoint).await?;
    let body = b"3;chunk-signature=synthetic\r\nabc\r\n2\r\nde\r\n0\r\nx-amz-checksum-crc64nvme: synthetic\r\n\r\n";
    for _ in 0..2 {
        send(
            proxy.endpoint(),
            "PUT",
            "/bucket/source?x-id=PutObject",
            body,
            "Content-Encoding: aws-chunked\r\nx-amz-decoded-content-length: 5\r\n",
        )
        .await?;
    }
    send(
        proxy.endpoint(),
        "HEAD",
        "/bucket/source?x-id=HeadObject",
        b"",
        "",
    )
    .await?;
    send(proxy.endpoint(), "PUT", "/bucket/manifest", b"metadata", "").await?;
    let mut bindings = Bindings::default();
    bindings.archive("/bucket/source", 17, SizeClass::Single)?;
    bindings.manifest("/bucket/manifest", 0)?;
    let stats = proxy.finish(&bindings).await?;
    assert_eq!(stats.bytes_uploaded, 10);
    assert_eq!(stats.manifest_bytes, 8);
    assert_eq!(stats.control_bytes, 0);
    assert_eq!(stats.wire_body_bytes, 2 * u64::try_from(body.len())? + 8);
    assert_eq!(stats.requests.get("single/archive-000017"), Some(&3));
    assert_eq!(stats.requests.get("single/manifest-000000"), Some(&1));
    let received = sink.received.lock().map_err(|_| ObservationError)?.clone();
    assert_eq!(received.iter().filter(|b| b.as_slice() == body).count(), 2);
    sink.close().await;
    Ok(())
}

#[tokio::test]
async fn multipart_control_bytes_and_out_of_order_independent_slots()
-> Result<(), Box<dyn std::error::Error>> {
    let sink = Sink::start().await?;
    let proxy = MeasuringProxy::start(&sink.endpoint).await?;
    send(proxy.endpoint(), "POST", "/bucket/large?uploads", b"", "").await?;
    send(
        proxy.endpoint(),
        "PUT",
        "/bucket/large?partNumber=2&uploadId=random-nonce",
        b"part-two",
        "",
    )
    .await?;
    send(
        proxy.endpoint(),
        "PUT",
        "/bucket/large?uploadId=random-nonce&partNumber=1",
        b"part-one",
        "",
    )
    .await?;
    send(
        proxy.endpoint(),
        "POST",
        "/bucket/large?uploadId=random-nonce",
        b"<complete/>",
        "",
    )
    .await?;
    send(proxy.endpoint(), "HEAD", "/bucket/large", b"", "").await?;
    let mut bindings = Bindings::default();
    bindings.archive("/bucket/large", 99, SizeClass::Multipart)?;
    let stats = proxy.finish(&bindings).await?;
    assert_eq!(stats.requests.get("multipart/archive-000099"), Some(&5));
    assert_eq!(stats.bytes_uploaded, 16);
    assert_eq!(stats.control_bytes, 11);
    sink.close().await;
    Ok(())
}

#[tokio::test]
async fn unknown_routes_and_class_contradictions_never_emit_stats()
-> Result<(), Box<dyn std::error::Error>> {
    for missing in [true, false] {
        let sink = Sink::start().await?;
        let proxy = MeasuringProxy::start(&sink.endpoint).await?;
        send(proxy.endpoint(), "PUT", "/bucket/unbound", b"actual", "").await?;
        let mut bindings = Bindings::default();
        if !missing {
            bindings.archive("/bucket/unbound", 0, SizeClass::Multipart)?;
        }
        assert_eq!(proxy.finish(&bindings).await, Err(ObservationError));
        sink.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn malformed_body_query_and_incomplete_body_poison_measurements()
-> Result<(), Box<dyn std::error::Error>> {
    for (path, body, headers) in [
        ("/bucket/a?unrecognized=1", &b"data"[..], ""),
        (
            "/bucket/a?uploadId=x&partNumber=1&partNumber=2",
            &b"data"[..],
            "",
        ),
        ("/bucket/a?x-id=HeadObject", &b"data"[..], ""),
        (
            "/bucket/a",
            &b"3\r\nab"[..],
            "Content-Encoding: aws-chunked\r\nx-amz-decoded-content-length: 3\r\n",
        ),
        ("/bucket/a", &b"data"[..], "Content-Length: 99\r\n"),
    ] {
        let sink = Sink::start().await?;
        let proxy = MeasuringProxy::start(&sink.endpoint).await?;
        assert!(
            send(proxy.endpoint(), "PUT", path, body, headers)
                .await
                .is_err()
        );
        assert_eq!(
            proxy.finish(&Bindings::default()).await,
            Err(ObservationError)
        );
        sink.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn only_literal_loopback_http_targets_are_accepted() {
    for target in [
        "http://example.com:80",
        "http://127.0.0.1:0",
        "https://127.0.0.1:80",
        "http://192.0.2.1:80",
        "http://127.0.0.1:80/path",
        "http://user@127.0.0.1:80",
    ] {
        assert!(MeasuringProxy::start(target).await.is_err());
    }
}

#[test]
fn binding_aliases_and_poisoned_cleanup_are_not_zero() -> Result<(), ObservationError> {
    let mut bindings = Bindings::default();
    bindings.archive("/bucket/a", 0, SizeClass::Single)?;
    assert_eq!(
        bindings.archive("/bucket/a", 1, SizeClass::Single),
        Err(ObservationError)
    );
    assert_eq!(
        bindings.archive("/bucket/b", 0, SizeClass::Single),
        Err(ObservationError)
    );
    assert_eq!(
        bindings.archive("not-a-path", 2, SizeClass::Single),
        Err(ObservationError)
    );
    let observed = Observation::default();
    assert_eq!(
        observed.change::<()>(|_| Err(ObservationError)),
        Err(ObservationError)
    );
    assert_eq!(observed.change(|_| Ok(0)), Err(ObservationError));
    Ok(())
}
