//! Read-only, fail-closed configuration. No global environment mutation or interpolation.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::key::KeyPrefix;
use crate::redaction::Limits;

const MAX_ENV_BYTES: u64 = 65_536;

/// Static, value-free configuration failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Selected file could not be read, was too large, or was not a regular file.
    EnvFile,
    /// Dotenv syntax is invalid or a key is repeated.
    Syntax,
    /// A setting is unknown, non-Unicode, missing, or invalid.
    Setting,
}

/// Validated settings. Deliberately no Debug: paths and destinations are operational data.
pub struct Config {
    /// Required destination bucket, never defaulted.
    pub bucket: String,
    /// Validated injective-key namespace.
    pub prefix: KeyPrefix,
    /// Optional profile; None means standard SDK provider selection.
    pub aws_profile: Option<String>,
    /// Optional region; None means standard SDK provider selection.
    pub region: Option<String>,
    /// Optional extra TLS trust roots; app setting wins over the standard AWS fallback.
    pub ca_bundle: Option<PathBuf>,
    /// Explicit all-files source roots; no personal root defaults.
    pub roots_all_files: Vec<PathBuf>,
    /// Explicit recursive JSONL source roots.
    pub roots_jsonl: Vec<PathBuf>,
    /// Optional work directory. The mutable shell requires it for real runs.
    pub work_dir: Option<PathBuf>,
    /// Checked minimum age in seconds, passed to the age kernel.
    pub min_age_secs: u64,
    /// Bounded shell worker concurrency.
    pub workers: usize,
    /// Redaction resource budgets.
    pub redaction: Limits,
}

/// Selected environment snapshot. Only this module accesses the ambient environment.
pub struct Environment(BTreeMap<OsString, OsString>);

impl Environment {
    /// Snapshot app settings, XDG path and AWS CA bundle only, never AWS credentials.
    #[must_use]
    pub fn capture() -> Self {
        Self::from_pairs(std::env::vars_os())
    }

    /// Inject selected environment values for deterministic callers/tests.
    #[must_use]
    pub fn from_pairs(pairs: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        Self(
            pairs
                .into_iter()
                .filter(|(k, _)| {
                    k == "XDG_CONFIG_HOME"
                        || k == "AWS_CA_BUNDLE"
                        || k.to_string_lossy().starts_with("AWS_ENDPOINT_URL")
                        || k.to_string_lossy().starts_with("DISK_ARCHIVE_")
                })
                .collect(),
        )
    }
}

impl Config {
    /// Select explicit file, existing XDG file, or existing cwd `.env`, then apply environment.
    /// Reads only: even a missing explicit path never creates any directories or files.
    /// Relative setting paths resolve against the supplied absolute `cwd`.
    ///
    /// # Errors
    /// Invalid/unreadable files and unknown/missing/invalid settings fail closed.
    pub fn load(
        explicit: Option<&Path>,
        cwd: &Path,
        environment: &Environment,
    ) -> Result<Self, ConfigError> {
        if !cwd.is_absolute() {
            return Err(ConfigError::Setting);
        }
        if environment
            .0
            .keys()
            .any(|key| key.to_string_lossy().starts_with("AWS_ENDPOINT_URL"))
        {
            return Err(ConfigError::Setting);
        }
        let selected = select_file(explicit, cwd, environment)?;
        let mut values = selected.map_or_else(|| Ok(BTreeMap::new()), |p| read_env(&p))?;
        for (key, value) in &environment.0 {
            if key.to_string_lossy().starts_with("DISK_ARCHIVE_") {
                let key = key.to_str().ok_or(ConfigError::Setting)?;
                let value = value.to_str().ok_or(ConfigError::Setting)?;
                values.insert(key.to_owned(), value.to_owned());
            }
        }
        if !values.contains_key("DISK_ARCHIVE_CA_BUNDLE")
            && let Some(bundle) = environment.0.get(&OsString::from("AWS_CA_BUNDLE"))
        {
            let bundle = bundle.to_str().ok_or(ConfigError::Setting)?;
            values.insert("DISK_ARCHIVE_CA_BUNDLE".into(), bundle.into());
        }
        Self::from_values(&values, cwd)
    }

    fn from_values(values: &BTreeMap<String, String>, cwd: &Path) -> Result<Self, ConfigError> {
        const KNOWN: &[&str] = &[
            "BUCKET",
            "PREFIX",
            "AWS_PROFILE",
            "REGION",
            "CA_BUNDLE",
            "ROOTS_ALL_FILES",
            "ROOTS_JSONL",
            "WORK_DIR",
            "MIN_AGE_DAYS",
            "WORKERS",
            "MAX_LINE_BYTES",
            "MAX_OUTPUT_LINE_BYTES",
            "MAX_FINDINGS",
            "MAX_FINDING_BYTES",
            "MAX_DERIVED_NEEDLES",
            "MAX_LITERAL_COPY_BYTES",
            "MAX_DROP_LINES",
        ];
        if values.keys().any(|k| {
            !k.strip_prefix("DISK_ARCHIVE_")
                .is_some_and(|s| KNOWN.contains(&s))
        }) {
            return Err(ConfigError::Setting);
        }
        let settings = Settings(values);
        let bucket = settings
            .get("BUCKET")
            .filter(|v| valid_bucket(v))
            .ok_or(ConfigError::Setting)?
            .to_owned();
        let prefix = KeyPrefix::new(
            settings
                .get("PREFIX")
                .ok_or(ConfigError::Setting)?
                .as_bytes(),
        )
        .map_err(|_| ConfigError::Setting)?;
        // Even the shortest relative path must fit the S3 key limit.
        crate::key::encode_key(&prefix, b"x").map_err(|_| ConfigError::Setting)?;
        Ok(Self {
            bucket,
            prefix,
            aws_profile: settings.optional("AWS_PROFILE")?,
            region: settings.optional("REGION")?,
            ca_bundle: settings
                .optional("CA_BUNDLE")?
                .map(|v| resolve(cwd, Path::new(&v))),
            roots_all_files: settings.roots("ROOTS_ALL_FILES", cwd)?,
            roots_jsonl: settings.roots("ROOTS_JSONL", cwd)?,
            work_dir: settings
                .optional("WORK_DIR")?
                .map(|v| resolve(cwd, Path::new(&v))),
            min_age_secs: settings
                .number("MIN_AGE_DAYS", 30, u64::MAX)?
                .checked_mul(86_400)
                .ok_or(ConfigError::Setting)?,
            workers: settings.size("WORKERS", 4, 256)?,
            redaction: Limits {
                max_line_bytes: settings.size("MAX_LINE_BYTES", 1_048_576, 16_777_216)?,
                max_output_line_bytes: settings.size(
                    "MAX_OUTPUT_LINE_BYTES",
                    4_194_304,
                    67_108_864,
                )?,
                max_findings: settings.size("MAX_FINDINGS", 256, 4096)?,
                max_finding_bytes: settings.size("MAX_FINDING_BYTES", 262_144, 1_048_576)?,
                max_derived_needles: settings.size("MAX_DERIVED_NEEDLES", 256, 1024)?,
                max_literal_copy_bytes: settings.size(
                    "MAX_LITERAL_COPY_BYTES",
                    67_108_864,
                    1_073_741_824,
                )?,
                max_drop_lines: settings.size("MAX_DROP_LINES", 4096, 65_536)?,
            },
        })
    }
}

struct Settings<'a>(&'a BTreeMap<String, String>);
impl Settings<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(&format!("DISK_ARCHIVE_{key}"))
            .map(String::as_str)
    }

    fn number(&self, key: &str, default: u64, max: u64) -> Result<u64, ConfigError> {
        let n = match self.get(key) {
            None => default,
            Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
                v.parse().map_err(|_| ConfigError::Setting)?
            }
            Some(_) => return Err(ConfigError::Setting),
        };
        if n > max {
            return Err(ConfigError::Setting);
        }
        Ok(n)
    }

    fn size(&self, key: &str, default: u64, max: u64) -> Result<usize, ConfigError> {
        let value = self.number(key, default, max)?;
        if value == 0 {
            return Err(ConfigError::Setting);
        }
        usize::try_from(value).map_err(|_| ConfigError::Setting)
    }

    fn optional(&self, key: &str) -> Result<Option<String>, ConfigError> {
        self.get(key)
            .map(|v| {
                if v.is_empty() || v.chars().any(char::is_control) {
                    return Err(ConfigError::Setting);
                }
                Ok(v.to_owned())
            })
            .transpose()
    }

    fn roots(&self, key: &str, cwd: &Path) -> Result<Vec<PathBuf>, ConfigError> {
        self.get(key).map_or_else(
            || Ok(Vec::new()),
            |value| {
                value
                    .split(';')
                    .map(|v| {
                        if v.is_empty() || v.chars().any(char::is_control) {
                            return Err(ConfigError::Setting);
                        }
                        Ok(resolve(cwd, Path::new(v)))
                    })
                    .collect()
            },
        )
    }
}

fn resolve(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    }
}

fn select_file(
    explicit: Option<&Path>,
    cwd: &Path,
    environment: &Environment,
) -> Result<Option<PathBuf>, ConfigError> {
    if let Some(path) = explicit {
        return Ok(Some(resolve(cwd, path)));
    }
    let xdg = environment.0.get(&OsString::from("XDG_CONFIG_HOME"));
    let xdg_path = xdg
        .filter(|v| !v.is_empty())
        .map(|v| PathBuf::from(v).join("disk-archive/.env"));
    match xdg_path {
        Some(path) if !path.is_absolute() => Err(ConfigError::Setting),
        Some(path) if present(&path)? => Ok(Some(path)),
        _ => {
            let path = cwd.join(".env");
            Ok(present(&path)?.then_some(path))
        }
    }
}

fn read_env(path: &Path) -> Result<BTreeMap<String, String>, ConfigError> {
    // Reject obvious special files before open (e.g. a FIFO that would block).
    let meta = std::fs::metadata(path).map_err(|_| ConfigError::EnvFile)?;
    if !meta.is_file() || meta.len() > MAX_ENV_BYTES {
        return Err(ConfigError::EnvFile);
    }
    let file = std::fs::File::open(path).map_err(|_| ConfigError::EnvFile)?;
    let meta = file.metadata().map_err(|_| ConfigError::EnvFile)?;
    if !meta.is_file() || meta.len() > MAX_ENV_BYTES {
        return Err(ConfigError::EnvFile);
    }
    let mut text = zeroize::Zeroizing::new(String::new());
    file.take(MAX_ENV_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| ConfigError::EnvFile)?;
    if text.len() > usize::try_from(MAX_ENV_BYTES).map_err(|_| ConfigError::EnvFile)? {
        return Err(ConfigError::EnvFile);
    }
    parse_env(&text)
}

fn present(path: &Path) -> Result<bool, ConfigError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ConfigError::EnvFile),
    }
}

fn valid_bucket(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !["..", ".-", "-."].iter().any(|v| value.contains(v))
        && value.parse::<std::net::Ipv4Addr>().is_err()
}

fn parse_env(text: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let mut values = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (key, value) = line.split_once('=').ok_or(ConfigError::Syntax)?;
        let key = key.trim();
        if !key.starts_with("DISK_ARCHIVE_")
            || !key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(ConfigError::Syntax);
        }
        let value = value.trim();
        let value = if value.starts_with(['\'', '"']) {
            let quote = value.chars().next().ok_or(ConfigError::Syntax)?;
            let inner = value
                .strip_prefix(quote)
                .and_then(|s| s.strip_suffix(quote))
                .ok_or(ConfigError::Syntax)?;
            if inner.contains(quote) {
                return Err(ConfigError::Syntax);
            }
            inner
        } else {
            if value.chars().any(char::is_whitespace) || value.contains(['\'', '"']) {
                return Err(ConfigError::Syntax);
            }
            value
        };
        if value.contains(['$', '\0']) || values.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(ConfigError::Syntax);
        }
    }
    Ok(values)
}
