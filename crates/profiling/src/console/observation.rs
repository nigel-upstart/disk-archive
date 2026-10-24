use std::time::Duration;

use console_api::instrument::{InstrumentRequest, instrument_client::InstrumentClient};

use crate::ProfileError;

/// Numeric-only receipt from the actual console gRPC stream, not a substitute workload.
/// No task names, locations, fields, timestamps or raw protobuf are exported.
pub struct ConsoleObservation {
    /// Number of task-stat snapshots in one actual update.
    pub tasks: u64,
    /// Sum of actual cumulative task poll counters in that update.
    pub polls: u64,
    /// Dropped runtime events reported by that update (not silently ignored).
    pub dropped_events: u64,
}

/// Observe the fixed loopback console endpoint for at most five seconds.
/// The synthetic diagnostic driver calls this explicitly, never the production hot path.
///
/// # Errors
/// No connection, no polled tasks, oversized response or transport failure fails statically.
pub async fn observe_console() -> Result<ConsoleObservation, ProfileError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = loop {
            match InstrumentClient::connect("http://127.0.0.1:6669").await {
                Ok(client) => break client.max_decoding_message_size(4 * 1_048_576),
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        };
        let mut stream = client
            .watch_updates(InstrumentRequest {})
            .await
            .map_err(|_| ProfileError::Output)?
            .into_inner();
        while let Some(update) = stream.message().await.map_err(|_| ProfileError::Output)? {
            if let Some(tasks) = update.task_update {
                let polls = tasks.stats_update.values().try_fold(0_u64, |n, stats| {
                    n.checked_add(stats.poll_stats.map_or(0, |p| p.polls))
                        .ok_or(ProfileError::Budget)
                })?;
                if polls > 0 {
                    return Ok(ConsoleObservation {
                        tasks: u64::try_from(tasks.stats_update.len())
                            .map_err(|_| ProfileError::Budget)?,
                        polls,
                        dropped_events: tasks.dropped_events,
                    });
                }
            }
        }
        Err(ProfileError::Output)
    })
    .await
    .map_err(|_| ProfileError::Output)?
}
