use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region, retry::RetryConfig, timeout::TimeoutConfig},
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

use super::tests::options;
use crate::{BlockingPool, CancellationToken, ClientOptions, SdkStore, StoreError, sdk::tls_http};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_trust_plus_bundle_preserves_hostname_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let pem = cert.cert.pem().into_bytes();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let server = tokio::spawn(async move {
        loop {
            let socket = tokio::select! {
                () = stop.cancelled() => break,
                result = listener.accept() => result,
            };
            let Ok((socket, _)) = socket else { break };
            if let Ok(mut tls) = acceptor.accept(socket).await {
                let mut buffer = [0; 8192];
                let _ = tls.read(&mut buffer).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
            }
        }
    });
    for (bundle, host, succeeds) in [
        (None, "localhost", false),
        (Some(pem.clone()), "localhost", true),
        (Some(pem), "127.0.0.1", false),
    ] {
        let client = Client::from_conf(
            aws_sdk_s3::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .credentials_provider(Credentials::new(
                    "synthetic-id",
                    "synthetic-key",
                    None,
                    None,
                    "synthetic",
                ))
                .region(Region::new("us-east-1"))
                .endpoint_url(format!("https://{host}:{port}"))
                .force_path_style(true)
                .retry_config(RetryConfig::standard().with_max_attempts(1))
                .http_client(tls_http(bundle)?)
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_timeout(Duration::from_secs(3))
                        .build(),
                )
                .build(),
        );
        let result = client
            .head_object()
            .bucket("synthetic-archive")
            .key("test")
            .send()
            .await;
        assert_eq!(result.is_ok(), succeeds);
    }
    cancel.cancel();
    server.await?;
    Ok(())
}

#[tokio::test]
async fn invalid_ca_and_timeout_fail_before_provider_initialization()
-> Result<(), Box<dyn std::error::Error>> {
    let work = tempfile::tempdir()?;
    let bundle = work.path().join("synthetic-invalid.pem");
    tokio::fs::write(&bundle, b"not a certificate").await?;
    let client = ClientOptions {
        profile: Some("synthetic".into()),
        region: Some("us-east-1".into()),
        ca_bundle: Some(bundle),
        connect_timeout: Duration::from_secs(1),
        attempt_timeout: Duration::from_secs(2),
    };
    assert!(matches!(
        SdkStore::load(options(), client.clone(), BlockingPool::new(1)?).await,
        Err(StoreError::Configuration)
    ));
    let mut invalid = client;
    invalid.connect_timeout = Duration::ZERO;
    assert!(matches!(
        SdkStore::load(options(), invalid, BlockingPool::new(1)?).await,
        Err(StoreError::Configuration)
    ));
    assert!(tls_http(Some(Vec::new())).is_err());
    assert!(tls_http(Some(vec![b'x'; 1_048_577])).is_err());
    Ok(())
}
