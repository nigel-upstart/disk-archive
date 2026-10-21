//! Pure synchronous safety kernels with production-connected Verus contracts.
//! No filesystem, network, clock, hashing, database, or scanner side effects.
//! Only annotated functions are proved; see docs/design.md for exact proof boundaries.
#![forbid(unsafe_code)]
#![cfg_attr(verus_only, feature(proc_macro_hygiene))]

pub mod age;
mod bytes;
pub mod key;
#[cfg(verus_only)]
pub mod key_model;
pub mod lifecycle;
pub mod needles;
pub mod pem;
