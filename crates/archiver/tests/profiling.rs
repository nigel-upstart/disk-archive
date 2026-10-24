//! Profiling selections are parsed without opening outputs or initializing resources.
#![cfg(feature = "profiling")]

use std::ffi::OsString;

use disk_archive::{Error, cli::Arguments, profile::Request};

fn parse(args: &[&str]) -> Result<Arguments, Error> {
    Arguments::parse(args.iter().map(OsString::from))
}

#[test]
fn explicit_diagnostics_parse_without_initialization() -> Result<(), Error> {
    assert!(parse(&["--dry-run"])?.profile.is_none());
    let args = parse(&["--dry-run", "--profile-trace", "./--trace"])?;
    assert!(args.dry_run);
    assert!(
        matches!(args.profile, Some(Request::Trace(path)) if path == std::path::Path::new("./--trace"))
    );
    #[cfg(feature = "profiling-heap")]
    assert!(matches!(
        parse(&["--profile-heap", "./--heap"])?.profile,
        Some(Request::Heap(_))
    ));
    #[cfg(feature = "profiling-console")]
    assert!(matches!(
        parse(&["--profile-console"])?.profile,
        Some(Request::Console)
    ));
    Ok(())
}

#[test]
fn diagnostic_options_are_strict_and_mutually_exclusive() {
    for args in [
        vec!["--profile-trace"],
        vec!["--profile-trace", ""],
        vec!["--profile-trace", "--dry-run"],
        vec!["--profile-trace", "one", "--profile-trace", "two"],
    ] {
        assert!(parse(&args).is_err());
    }
    #[cfg(feature = "profiling-heap")]
    assert!(parse(&["--profile-trace", "one", "--profile-heap", "two"]).is_err());
    #[cfg(feature = "profiling-console")]
    assert!(parse(&["--profile-console", "--profile-trace", "one"]).is_err());
}
