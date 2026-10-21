//! The two frozen I tests are retained, with concurrency and every overflow boundary added.

use super::*;

#[test]
fn operations_are_observed_and_temp_is_concurrent_peak() -> Result<(), CounterError> {
    let counters = Counters::default();
    assert_eq!(counters.snapshot()?, Snapshot::default());
    counters.process_spawn()?;
    counters.uploaded(12)?;
    counters.uploaded(3)?;
    counters.request(SizeClass::Single, 1)?;
    counters.request(SizeClass::Single, 1)?;
    counters.request(SizeClass::Multipart, 2)?;
    let first = counters.temporary(40)?;
    let second = counters.temporary(60)?;
    assert!(counters.snapshot().is_err());
    drop(first);
    let third = counters.temporary(20)?;
    drop((second, third));
    let sample = counters.snapshot()?;
    assert_eq!(sample.process_spawns, 1);
    assert_eq!(sample.bytes_uploaded, 15);
    assert_eq!(sample.peak_temp_bytes, 100);
    assert_eq!(sample.requests.get(&(SizeClass::Single, 1)), Some(&2));
    assert_eq!(sample.requests.get(&(SizeClass::Multipart, 2)), Some(&1));
    Ok(())
}

#[test]
fn overflow_fails_without_wrapping() -> Result<(), CounterError> {
    let counters = Counters::default();
    counters.uploaded(u64::MAX)?;
    assert_eq!(counters.uploaded(1), Err(CounterError));
    assert!(counters.snapshot().is_err());
    let counters = Counters::default();
    let lease = counters.temporary(u64::MAX)?;
    assert!(counters.temporary(1).is_err());
    drop(lease);
    assert!(counters.snapshot().is_err());
    Ok(())
}

#[test]
fn process_request_and_lease_overflow_poison_every_observer() -> Result<(), CounterError> {
    let counters = Counters::default();
    counters.process_spawns.store(u64::MAX, Ordering::SeqCst);
    assert_eq!(counters.process_spawn(), Err(CounterError));
    assert_eq!(counters.process_spawns.load(Ordering::SeqCst), u64::MAX);
    assert_eq!(counters.uploaded(0), Err(CounterError));
    assert_eq!(counters.request(SizeClass::Single, 0), Err(CounterError));
    assert!(counters.temporary(0).is_err());
    let counters = Counters::default();
    counters
        .requests
        .lock()
        .map_err(|_| CounterError)?
        .insert((SizeClass::Single, 0), u64::MAX);
    assert_eq!(counters.request(SizeClass::Single, 0), Err(CounterError));
    assert!(counters.snapshot().is_err());
    let counters = Counters::default();
    counters.live_leases.store(u64::MAX, Ordering::SeqCst);
    assert!(counters.temporary(0).is_err());
    assert!(counters.snapshot().is_err());
    Ok(())
}

#[test]
fn zero_byte_lease_still_prevents_completed_snapshot() -> Result<(), CounterError> {
    let counters = Counters::default();
    let lease = counters.temporary(0)?;
    assert!(counters.snapshot().is_err());
    drop(lease);
    assert_eq!(counters.snapshot()?, Snapshot::default());
    Ok(())
}

#[test]
fn request_index_is_bounded_without_silent_truncation() -> Result<(), CounterError> {
    let counters = Counters::default();
    for ordinal in 0..u64::try_from(MAX_REQUEST_OBJECTS).map_err(|_| CounterError)? {
        counters.request(SizeClass::Single, ordinal)?;
    }
    counters.request(SizeClass::Single, 0)?;
    assert_eq!(counters.snapshot()?.requests.len(), MAX_REQUEST_OBJECTS);
    assert_eq!(counters.request(SizeClass::Multipart, 0), Err(CounterError));
    assert!(counters.snapshot().is_err());
    assert_eq!(
        counters.requests.lock().map_err(|_| CounterError)?.len(),
        MAX_REQUEST_OBJECTS
    );
    Ok(())
}

#[test]
fn concurrent_updates_do_not_lose_increments() -> Result<(), CounterError> {
    let counters = Counters::default();
    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..4 {
            let counters = &counters;
            threads.push(scope.spawn(move || {
                for _ in 0..1000 {
                    counters.process_spawn()?;
                    counters.uploaded(7)?;
                    counters.request(SizeClass::Multipart, 1)?;
                    drop(counters.temporary(10)?);
                }
                Ok::<_, CounterError>(())
            }));
        }
        for thread in threads {
            thread.join().map_err(|_| CounterError)??;
        }
        Ok::<_, CounterError>(())
    })?;
    let snapshot = counters.snapshot()?;
    assert_eq!(snapshot.process_spawns, 4000);
    assert_eq!(snapshot.bytes_uploaded, 28_000);
    assert_eq!(
        snapshot.requests.get(&(SizeClass::Multipart, 1)),
        Some(&4000)
    );
    assert!((10..=40).contains(&snapshot.peak_temp_bytes));
    Ok(())
}

#[test]
// LINT-JUSTIFICATION: This caught synthetic panic intentionally poisons the request mutex to test fail-closed snapshots.
#[allow(clippy::panic)]
fn release_underflow_and_mutex_poison_are_not_silent() {
    let counters = Counters::default();
    counters.subtract(&counters.temp_bytes, 1);
    assert!(counters.snapshot().is_err());
    let counters = Counters::default();
    let _caught = std::panic::catch_unwind(|| {
        let _guard = counters.requests.lock();
        panic!("synthetic poison control");
    });
    assert!(counters.snapshot().is_err());
    assert_eq!(counters.request(SizeClass::Single, 1), Err(CounterError));
}
