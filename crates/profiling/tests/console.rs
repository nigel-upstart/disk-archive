//! Console opt-in build gate and loopback lifecycle smoke test.
#![cfg(feature = "console")]

#[cfg(not(tokio_unstable))]
#[test]
fn console_without_unstable_fails_before_runtime_or_listener() {
    assert!(matches!(
        disk_archive_profiling::console(),
        Err(disk_archive_profiling::ProfileError::TokioUnstableRequired)
    ));
}

#[cfg(tokio_unstable)]
#[test]
fn console_serves_only_loopback_and_stops_explicitly() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        disk_archive_profiling::console(),
        Err(disk_archive_profiling::ProfileError::Output)
    ));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let session = disk_archive_profiling::console()?;
        let connection = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Ok(connection) =
                    tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, 6669)).await
                {
                    break connection;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await?;
        drop(connection);
        let task = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        });
        let observation = disk_archive_profiling::observe_console().await;
        task.await?;
        // Always finish the real server, including when numeric observation failed.
        let finished = session.finish().await;
        let observation = observation?;
        assert!(observation.tasks > 0);
        assert!(observation.polls > 0);
        finished?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
