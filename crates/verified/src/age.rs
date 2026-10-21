//! Fail-closed timestamp comparison without machine-integer overflow.

#[cfg(verus_only)]
use vstd::prelude::*;

/// Unix timestamp with normalized nanoseconds.
#[cfg_attr(verus_only, verifier::verify)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    /// Signed seconds since the Unix epoch.
    pub secs: i64,
    /// Subsecond nanoseconds; values >= one billion are invalid.
    pub nanos: u32,
}

impl Timestamp {
    /// Whether the subsecond part is normalized.
    #[must_use]
    #[cfg_attr(verus_only, verus_spec(r => ensures r == (self.nanos < 1_000_000_000)))]
    pub const fn is_valid(self) -> bool {
        self.nanos < 1_000_000_000
    }

    #[cfg_attr(verus_only, verus_spec(r => ensures r == self.secs as int * 1_000_000_000 + self.nanos as int))]
    const fn total_nanos(self) -> i128 {
        (self.secs as i128) * 1_000_000_000 + self.nanos as i128
    }
}

/// Strictly older than the cutoff; equality and malformed times fail closed.
/// The full i64 seconds and u64 age domains fit in i128 nanoseconds.
#[must_use]
#[cfg_attr(verus_only, verus_spec(r => ensures r == (now.nanos < 1_000_000_000 && mtime.nanos < 1_000_000_000 && mtime.secs as int * 1_000_000_000 + (mtime.nanos as int) < now.secs as int * 1_000_000_000 + now.nanos as int - min_age_secs as int * 1_000_000_000)))]
pub const fn is_older_than(now: Timestamp, mtime: Timestamp, min_age_secs: u64) -> bool {
    now.is_valid()
        && mtime.is_valid()
        && mtime.total_nanos() < now.total_nanos() - (min_age_secs as i128) * 1_000_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_cutoff_and_extremes() {
        let now = Timestamp {
            secs: 100,
            nanos: 0,
        };
        assert!(!is_older_than(now, Timestamp { secs: 90, nanos: 0 }, 10));
        assert!(is_older_than(
            now,
            Timestamp {
                secs: 89,
                nanos: 999_999_999
            },
            10
        ));
        assert!(!is_older_than(
            now,
            Timestamp {
                secs: 101,
                nanos: 0
            },
            0
        ));
        assert!(!is_older_than(
            now,
            Timestamp {
                secs: 0,
                nanos: 1_000_000_000
            },
            0
        ));
        assert!(!is_older_than(
            Timestamp {
                secs: i64::MIN,
                nanos: 0
            },
            Timestamp {
                secs: i64::MAX,
                nanos: 0
            },
            u64::MAX,
        ));
    }
}
