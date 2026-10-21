//! Pure synchronous reference kernels. These implementations are NOT yet proved.
//! No filesystem, network, clock, hashing, database, or scanner side effects.
//! See docs/design.md for the adapter obligations and wave-two proof boundary.
#![forbid(unsafe_code)]

pub mod age;
pub mod key;
pub mod lifecycle;
pub mod needles;
pub mod pem;
