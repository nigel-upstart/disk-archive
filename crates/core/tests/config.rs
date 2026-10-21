//! Only invented settings and isolated temporary directories; no ambient .env is loaded.
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use disk_archive_core::config::{Config, ConfigError, Environment};

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temp(PathBuf);
impl Temp {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "disk-archive-core-test-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn env(pairs: &[(&str, &str)]) -> Environment {
    Environment::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    )
}
fn base(extra: &str) -> String {
    format!("DISK_ARCHIVE_BUCKET=synthetic-tests\nDISK_ARCHIVE_PREFIX=synthetic\n{extra}")
}
fn load(text: &str) -> Result<Config, ConfigError> {
    let dir = Temp::new().map_err(|_| ConfigError::EnvFile)?;
    std::fs::write(dir.0.join(".env"), text).map_err(|_| ConfigError::EnvFile)?;
    Config::load(None, &dir.0, &env(&[]))
}

#[test]
fn required_settings_and_invalid_values_fail_closed() {
    for text in [
        "",
        "DISK_ARCHIVE_BUCKET=synthetic-tests",
        "DISK_ARCHIVE_PREFIX=synthetic",
    ] {
        assert!(load(text).is_err());
    }
    for extra in [
        "DISK_ARCHIVE_BUKET=typo",
        "DISK_ARCHIVE_WORKERS=0",
        "DISK_ARCHIVE_WORKERS=257",
        "DISK_ARCHIVE_WORKERS=-1",
        "DISK_ARCHIVE_WORKERS=+1",
        "DISK_ARCHIVE_WORKERS=",
        "DISK_ARCHIVE_MIN_AGE_DAYS=18446744073709551615",
        "DISK_ARCHIVE_MIN_AGE_DAYS=18446744073709551616",
        "DISK_ARCHIVE_AWS_PROFILE=",
        "DISK_ARCHIVE_REGION=",
        "DISK_ARCHIVE_ROOTS_JSONL=one;;two",
        "DISK_ARCHIVE_MAX_LINE_BYTES=0",
        "DISK_ARCHIVE_MAX_OUTPUT_LINE_BYTES=67108865",
        "DISK_ARCHIVE_MAX_FINDINGS=0",
        "DISK_ARCHIVE_MAX_FINDING_BYTES=0",
        "DISK_ARCHIVE_MAX_DROP_LINES=0",
    ] {
        assert!(load(&base(extra)).is_err(), "{extra}");
    }
    for bucket in [
        "",
        "ab",
        "Upper",
        "a..b",
        "a.-b",
        "a-.b",
        "192.0.2.1",
        "-abc",
        "abc-",
        "bad/bucket",
    ] {
        assert!(
            load(&format!(
                "DISK_ARCHIVE_BUCKET={bucket}\nDISK_ARCHIVE_PREFIX=synthetic"
            ))
            .is_err()
        );
    }
    for prefix in ["", "/absolute", "../escape"] {
        assert!(
            load(&format!(
                "DISK_ARCHIVE_BUCKET=synthetic-tests\nDISK_ARCHIVE_PREFIX={prefix}"
            ))
            .is_err()
        );
    }
}

#[test]
fn strict_dotenv_syntax_without_interpolation_or_global_mutation() -> TestResult {
    let config = load(&base("# comment\nDISK_ARCHIVE_REGION='synthetic-region'\nDISK_ARCHIVE_WORK_DIR=\"work dir\"\nDISK_ARCHIVE_MIN_AGE_DAYS=0\n")).map_err(|_| "config")?;
    assert_eq!(config.min_age_secs, 0);
    assert_eq!(config.region.as_deref(), Some("synthetic-region"));
    assert!(config.work_dir.is_some());
    for extra in [
        "not-an-assignment",
        "OTHER=bad",
        "export DISK_ARCHIVE_WORKERS=2",
        "DISK_ARCHIVE_REGION='unclosed",
        "DISK_ARCHIVE_REGION=has space",
        "DISK_ARCHIVE_REGION=\"a\"b\"",
        "DISK_ARCHIVE_REGION=${OTHER}",
        "DISK_ARCHIVE_REGION=x\0y",
        "DISK_ARCHIVE_WORKERS=2\nDISK_ARCHIVE_WORKERS=3",
    ] {
        assert!(load(&base(extra)).is_err());
    }
    Ok(())
}

#[test]
fn precedence_and_read_only_loading() -> TestResult {
    let dir = Temp::new()?;
    let xdg = dir.0.join("xdg");
    std::fs::create_dir_all(xdg.join("disk-archive"))?;
    std::fs::write(dir.0.join(".env"), base("DISK_ARCHIVE_WORKERS=1"))?;
    std::fs::write(
        xdg.join("disk-archive/.env"),
        base("DISK_ARCHIVE_WORKERS=2"),
    )?;
    std::fs::write(dir.0.join("explicit.env"), base("DISK_ARCHIVE_WORKERS=3"))?;
    let xdg_str = xdg.to_str().ok_or("path")?;
    let e = env(&[("XDG_CONFIG_HOME", xdg_str)]);
    assert_eq!(
        Config::load(None, &dir.0, &e)
            .map_err(|_| "config")?
            .workers,
        2
    );
    assert_eq!(
        Config::load(Some(Path::new("explicit.env")), &dir.0, &e)
            .map_err(|_| "config")?
            .workers,
        3
    );
    let e = env(&[("XDG_CONFIG_HOME", xdg_str), ("DISK_ARCHIVE_WORKERS", "4")]);
    assert_eq!(
        Config::load(None, &dir.0, &e)
            .map_err(|_| "config")?
            .workers,
        4
    );
    assert_eq!(
        Config::load(None, &dir.0, &env(&[]))
            .map_err(|_| "config")?
            .workers,
        1
    );
    let missing = dir.0.join("absent/.env");
    assert!(Config::load(Some(&missing), &dir.0, &e).is_err());
    assert!(!dir.0.join("absent").exists());
    let before = std::fs::read_dir(&dir.0)?.count();
    let source = dir.0.join(".env");
    let modified = source.metadata()?.modified()?;
    let bytes = std::fs::read(&source)?;
    Config::load(None, &dir.0, &e).map_err(|_| "config")?;
    assert_eq!(std::fs::read_dir(&dir.0)?.count(), before);
    assert_eq!(std::fs::read(&source)?, bytes);
    assert_eq!(source.metadata()?.modified()?, modified);
    assert!(Config::load(None, &dir.0, &env(&[("XDG_CONFIG_HOME", "relative")])).is_err());
    Ok(())
}

#[test]
fn absent_files_defaults_and_paths() -> TestResult {
    let dir = Temp::new()?;
    let e = env(&[
        ("DISK_ARCHIVE_BUCKET", "synthetic-tests"),
        ("DISK_ARCHIVE_PREFIX", "synthetic"),
        ("DISK_ARCHIVE_ROOTS_ALL_FILES", "one;two"),
        ("DISK_ARCHIVE_ROOTS_JSONL", "/synthetic"),
        ("DISK_ARCHIVE_AWS_PROFILE", "synthetic"),
    ]);
    let cfg = Config::load(None, &dir.0, &e).map_err(|_| "config")?;
    assert_eq!(cfg.min_age_secs, 30 * 86_400);
    assert_eq!(cfg.workers, 4);
    assert_eq!(
        cfg.roots_all_files,
        vec![dir.0.join("one"), dir.0.join("two")]
    );
    assert_eq!(cfg.roots_jsonl, vec![PathBuf::from("/synthetic")]);
    assert_eq!(cfg.aws_profile.as_deref(), Some("synthetic"));
    assert!(cfg.region.is_none());
    assert!(cfg.work_dir.is_none());
    assert_eq!(std::fs::read_dir(&dir.0)?.count(), 0);
    // An absent XDG file falls back; malformed/present files do not.
    let absent = dir.0.join("missing");
    let e = env(&[
        ("XDG_CONFIG_HOME", absent.to_str().ok_or("path")?),
        ("DISK_ARCHIVE_BUCKET", "synthetic-tests"),
        ("DISK_ARCHIVE_PREFIX", "synthetic"),
    ]);
    assert!(Config::load(None, &dir.0, &e).is_ok());
    Ok(())
}

#[test]
fn unreadable_malformed_or_oversized_selected_file_never_falls_back() -> TestResult {
    let dir = Temp::new()?;
    std::fs::write(dir.0.join(".env"), base(""))?;
    let selected = dir.0.join("selected");
    std::fs::create_dir(&selected)?;
    assert!(Config::load(Some(&selected), &dir.0, &env(&[])).is_err());
    let oversized = dir.0.join("oversized");
    std::fs::write(&oversized, vec![b'x'; 65_537])?;
    assert!(Config::load(Some(&oversized), &dir.0, &env(&[])).is_err());
    let invalid = dir.0.join("invalid");
    std::fs::write(&invalid, [0xff])?;
    assert!(Config::load(Some(&invalid), &dir.0, &env(&[])).is_err());
    Ok(())
}
