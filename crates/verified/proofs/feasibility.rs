//! Feasibility only: not yet connected to the production reference implementation.
use vstd::prelude::*;

verus! {
pub fn older_seconds(now: i64, mtime: i64, age: u64) -> (result: bool)
    ensures result == ((mtime as int) < (now as int) - (age as int)),
{
    (mtime as i128) < (now as i128) - (age as i128)
}

pub fn deletion_evidence_matches(expected: u64, observed: u64) -> (result: bool)
    ensures result ==> expected == observed,
{
    expected == observed
}
}
