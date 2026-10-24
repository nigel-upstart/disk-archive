use std::io;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn partial_writes_errors_and_retained_owner_are_counted() -> TestResult {
    struct Partial {
        calls: usize,
    }
    impl io::Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 2 {
                return Err(io::Error::other("synthetic write failure"));
            }
            Ok(bytes.len().min(3))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let counters = Arc::new(Counters::default());
    let lease = counters.append_temporary().map_err(|_| "lease")?;
    let retained = lease.clone();
    let mut partial = Partial { calls: 0 };
    assert!(lease.writer(&mut partial).write_all(b"synthetic").is_err());
    lease.writer(&mut partial).flush()?;
    drop(lease);
    assert!(counters.snapshot().is_err());
    let other = counters.append_temporary().map_err(|_| "lease")?;
    other.writer(&mut io::sink()).write_all(b"12345")?;
    drop((retained, other));
    assert_eq!(
        counters.snapshot().map_err(|_| "snapshot")?.peak_temp_bytes,
        8
    );
    Ok(())
}

#[test]
fn parallel_append_lifetimes_and_cleanup_failure() -> TestResult {
    let counters = Arc::new(Counters::default());
    let first = counters.append_temporary().map_err(|_| "lease")?;
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..4 {
            let lease = first.clone();
            handles.push(scope.spawn(move || {
                for _ in 0..100 {
                    lease.writer(&mut io::sink()).write_all(&[0; 7])?;
                }
                Ok::<_, io::Error>(())
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| "worker")??;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop(first);
    assert_eq!(
        counters.snapshot().map_err(|_| "snapshot")?.peak_temp_bytes,
        2800
    );
    let lease = counters.append_temporary().map_err(|_| "lease")?;
    lease.cleanup_failed();
    assert!(lease.writer(&mut io::sink()).write_all(b"blocked").is_err());
    drop(lease);
    assert!(counters.snapshot().is_err());
    Ok(())
}

#[test]
fn append_overflow_and_zero_length_lifetimes_fail_closed() {
    let counters = Arc::new(Counters::default());
    let lease = counters.append_temporary();
    assert!(counters.snapshot().is_err());
    drop(lease);
    assert!(counters.snapshot().is_ok());
    let lease = counters.append_temporary();
    if let Ok(lease) = lease {
        assert!(lease.written(u64::MAX).is_ok());
        assert!(lease.written(1).is_err());
    }
    assert!(counters.snapshot().is_err());
    assert!(counters.append_temporary().is_err());
}
