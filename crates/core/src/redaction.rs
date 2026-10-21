//! Line-streamed legacy redaction, bounded independently of input file size.
//!
//! Errors invalidate ALL partial output. Callers must discard their output sink on error,
//! and must rescan successful whole output before treating it as verified. This module
//! does not open files; atomic replacement and timestamp restoration belong to the shell.

use std::collections::BTreeSet;
use std::io::{BufReader, Read, Write};
use std::sync::LazyLock;

use disk_archive_verified::{needles, pem};
use regex::bytes::Regex;
use zeroize::Zeroizing;

static INLINE: LazyLock<Result<Regex, RedactError>> = LazyLock::new(|| {
    Regex::new(
        r"(?-u)-----BEGIN [A-Z ]*PRIVATE KEY-----.{0,20000}?-----END [A-Z ]*PRIVATE KEY-----",
    )
    .map_err(|_| RedactError::Invalid)
});
static ENV: LazyLock<Result<Regex, RedactError>> = LazyLock::new(|| {
    Regex::new(r#"(?-u)((?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS|AUTH)[A-Z0-9_]*)=)("[^"\n]{0,4096}"|'[^'\n]{0,4096}'|[^\s"']+)"#).map_err(|_| RedactError::Invalid)
});

/// Borrowed scanner finding. No Debug, Clone or serialization of raw values.
pub use disk_archive_verified::needles::FindingRaw;

/// Hard ceilings checked before buffering or replacement allocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Input physical line bytes, including newline.
    pub max_line_bytes: usize,
    /// Intermediate and final output bytes per physical input line.
    pub max_output_line_bytes: usize,
    /// Count of raw variants supplied by scanner callbacks.
    pub max_findings: usize,
    /// Total UTF-8 raw-value bytes across all callbacks.
    pub max_finding_bytes: usize,
    /// Conservative derived-needle candidates, including duplicates and line pieces.
    pub max_derived_needles: usize,
    /// Logical bytes copied by the literal kernel per input line (not CPU instructions).
    pub max_literal_copy_bytes: usize,
    /// Number of line numbers in the fallback pass.
    pub max_drop_lines: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line_bytes: 1_048_576,
            max_output_line_bytes: 4_194_304,
            max_findings: 256,
            max_finding_bytes: 262_144,
            max_derived_needles: 256,
            max_literal_copy_bytes: 67_108_864,
            max_drop_lines: 4096,
        }
    }
}

/// Errors carry no source bytes, paths, finding values or underlying I/O error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedactError {
    /// A resource budget was exceeded. Never accept incomplete results.
    Budget,
    /// Invalid label, line number, limits, or internal fixed pattern.
    Invalid,
    /// Read failed; partial output must be discarded.
    Read,
    /// Write failed; partial output must be discarded.
    Write,
}

struct OwnedFinding {
    label: String,
    raw: Zeroizing<String>,
}

/// Bounded callback accumulator. An error poisons it, so ignored callback errors fail closed.
pub struct PlanBuilder {
    limits: Limits,
    findings: Vec<OwnedFinding>,
    raw_bytes: usize,
    derived_needles: usize,
    poisoned: bool,
}

impl PlanBuilder {
    /// Create a bounded accumulator. Labels are additionally capped at 64 ASCII bytes.
    ///
    /// # Errors
    /// Zero limits are invalid.
    pub fn new(limits: Limits) -> Result<Self, RedactError> {
        if [
            limits.max_line_bytes,
            limits.max_output_line_bytes,
            limits.max_findings,
            limits.max_finding_bytes,
            limits.max_derived_needles,
            limits.max_literal_copy_bytes,
            limits.max_drop_lines,
        ]
        .contains(&0)
        {
            return Err(RedactError::Invalid);
        }
        Ok(Self {
            limits,
            findings: Vec::new(),
            raw_bytes: 0,
            derived_needles: 0,
            poisoned: false,
        })
    }

    /// Copy a borrowed callback value into bounded, zeroizing storage.
    /// Feed raw and raw-v2 separately, in scanner order. Budget counts include duplicates.
    ///
    /// # Errors
    /// Invalid labels or exhausted budgets poison the builder; stop scanning this file.
    pub fn push(&mut self, finding: &FindingRaw<'_>) -> Result<(), RedactError> {
        let total = self.raw_bytes.checked_add(finding.raw.len());
        if self.poisoned
            || self.findings.len() >= self.limits.max_findings
            || total.is_none_or(|n| n > self.limits.max_finding_bytes)
        {
            self.poisoned = true;
            return Err(RedactError::Budget);
        }
        if finding.label.is_empty()
            || finding.label.len() > 64
            || !finding
                .label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            self.poisoned = true;
            return Err(RedactError::Invalid);
        }
        // Bound BEFORE copying or invoking the kernel's quadratic deduplication.
        // >=6 scalars: two full forms plus at most 1 + raw line delimiters pieces.
        // Python ensure_ascii JSON has no physical line delimiters; its one piece
        // duplicates its full form. Count all controls (even non-delimiters) to
        // overestimate safely, and count duplicates/short pieces conservatively.
        let candidates = if finding.raw.chars().take(6).count() < 6 {
            Some(0)
        } else {
            finding
                .raw
                .chars()
                .filter(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
                .count()
                .checked_add(3)
        };
        let derived = candidates.and_then(|n| self.derived_needles.checked_add(n));
        if derived.is_none_or(|n| n > self.limits.max_derived_needles) {
            self.poisoned = true;
            return Err(RedactError::Budget);
        }
        self.derived_needles = derived.ok_or(RedactError::Budget)?;
        self.raw_bytes = total.ok_or(RedactError::Budget)?;
        self.findings.push(OwnedFinding {
            label: finding.label.to_owned(),
            raw: Zeroizing::new(finding.raw.to_owned()),
        });
        Ok(())
    }

    /// Compile the kernel needle set and bounded drop-line list. Raw accumulator is erased.
    /// Kernel needle buffers currently do not promise allocator-level erasure.
    ///
    /// # Errors
    /// Poisoned builder, invalid/too many line numbers, or invalid labels/patterns.
    pub fn finish(
        self,
        drop_lines: impl IntoIterator<Item = u64>,
    ) -> Result<RedactionPlan, RedactError> {
        if self.poisoned {
            return Err(RedactError::Budget);
        }
        let mut drops = BTreeSet::new();
        for (index, line) in drop_lines.into_iter().enumerate() {
            // Bound callback work too: duplicated input cannot evade the budget.
            if line == 0 {
                return Err(RedactError::Invalid);
            }
            if index >= self.limits.max_drop_lines {
                return Err(RedactError::Budget);
            }
            drops.insert(line);
        }
        let borrowed: Vec<_> = self
            .findings
            .iter()
            .map(|f| FindingRaw {
                label: &f.label,
                raw: &f.raw,
            })
            .collect();
        let needles =
            needles::NeedleSet::from_findings(&borrowed).map_err(|_| RedactError::Invalid)?;
        Ok(RedactionPlan {
            limits: self.limits,
            // Initial copy + one output rebuild per actual needle. Using the
            // conservative candidate count and a reduced intermediate-buffer cap
            // bounds literal copy traffic BEFORE allocation, including expansion.
            literal_output_limit: self.limits.max_output_line_bytes.min(
                self.limits.max_literal_copy_bytes
                    / self
                        .derived_needles
                        .checked_add(1)
                        .ok_or(RedactError::Budget)?,
            ),
            needles,
            drops,
            inline: INLINE.as_ref().map_err(|e| *e)?,
            env: ENV.as_ref().map_err(|e| *e)?,
        })
    }
}

/// Reusable compiled plan; no Debug or serialization. Scanning remains a separate stage.
pub struct RedactionPlan {
    limits: Limits,
    literal_output_limit: usize,
    needles: needles::NeedleSet,
    drops: BTreeSet<u64>,
    inline: &'static Regex,
    env: &'static Regex,
}

/// Non-sensitive redaction telemetry, not verification or upload authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Physical input lines (including lines discarded inside PEM blocks).
    pub lines: u64,
    /// Literal, PEM, env and explicitly dropped-line replacement count.
    pub replacements: u64,
    /// Lines dropped by the final literal guard (additional to legacy behavior).
    pub guarded_lines: u64,
}

impl RedactionPlan {
    /// Redact a stream with bounded input/output line buffers. No flush of the caller's sink.
    /// All stages, including explicit drops, pass through the kernel's final literal guard.
    ///
    /// # Errors
    /// Any budget or I/O failure invalidates all partial output. Never upload it.
    pub fn redact(&self, input: impl Read, mut output: impl Write) -> Result<Report, RedactError> {
        let mut reader = BufReader::with_capacity(8192.min(self.limits.max_line_bytes), input);
        let mut line = Zeroizing::new(Vec::new());
        let mut state = pem::PemState::default();
        let mut report = Report::default();
        while read_line(&mut reader, &mut line, self.limits.max_line_bytes)? {
            report.lines = report.lines.checked_add(1).ok_or(RedactError::Budget)?;
            let (transformed, count) = if self.drops.contains(&report.lines) {
                (b"[REDACTED-LINE]\n".to_vec(), 1)
            } else {
                self.transform(state.resume(&line), &mut state)?
            };
            let transformed = Zeroizing::new(transformed);
            if transformed.len() > self.limits.max_output_line_bytes {
                return Err(RedactError::Budget);
            }
            let guarded = needles::guard_line(&transformed, &self.needles);
            let guarded_bytes = Zeroizing::new(guarded.bytes);
            if guarded_bytes.len() > self.limits.max_output_line_bytes {
                return Err(RedactError::Budget);
            }
            report.replacements = report
                .replacements
                .checked_add(count)
                .ok_or(RedactError::Budget)?;
            report.guarded_lines = report
                .guarded_lines
                .checked_add(u64::from(guarded.dropped))
                .ok_or(RedactError::Budget)?;
            output
                .write_all(&guarded_bytes)
                .map_err(|_| RedactError::Write)?;
        }
        Ok(report)
    }

    fn transform(
        &self,
        line: &[u8],
        state: &mut pem::PemState,
    ) -> Result<(Vec<u8>, u64), RedactError> {
        let (line, count) =
            needles::replace_all_bounded(line, &self.needles, self.literal_output_limit)
                .map_err(|_| RedactError::Budget)?;
        let line = Zeroizing::new(line);
        let mut count = u64::try_from(count).map_err(|_| RedactError::Budget)?;
        let (line, n) = self.substitute(self.inline, &line, b"[REDACTED-PRIVATE-KEY]", false)?;
        count = count.checked_add(n).ok_or(RedactError::Budget)?;
        let mut line = Zeroizing::new(line);
        if let Some(begin) = pem::begin(&line) {
            let mut next = Zeroizing::new(Vec::new());
            append(
                &mut next,
                line.get(..begin.start).ok_or(RedactError::Invalid)?,
                self.limits.max_output_line_bytes,
            )?;
            append(
                &mut next,
                b"[REDACTED-PRIVATE-KEY]\n",
                self.limits.max_output_line_bytes,
            )?;
            line = next;
            state.enter();
            count = count.checked_add(1).ok_or(RedactError::Budget)?;
        }
        let (line, n) = self.substitute(self.env, &line, b"[REDACTED]", true)?;
        Ok((line, count.checked_add(n).ok_or(RedactError::Budget)?))
    }

    fn substitute(
        &self,
        regex: &Regex,
        line: &[u8],
        marker: &[u8],
        keep_name: bool,
    ) -> Result<(Vec<u8>, u64), RedactError> {
        let mut output = Zeroizing::new(Vec::new());
        let mut pos = 0;
        let mut count = 0_u64;
        for captures in regex.captures_iter(line) {
            let matched = captures.get(0).ok_or(RedactError::Invalid)?;
            append(
                &mut output,
                line.get(pos..matched.start()).ok_or(RedactError::Invalid)?,
                self.limits.max_output_line_bytes,
            )?;
            if keep_name {
                append(
                    &mut output,
                    captures.get(1).ok_or(RedactError::Invalid)?.as_bytes(),
                    self.limits.max_output_line_bytes,
                )?;
            }
            append(&mut output, marker, self.limits.max_output_line_bytes)?;
            pos = matched.end();
            count = count.checked_add(1).ok_or(RedactError::Budget)?;
        }
        append(
            &mut output,
            line.get(pos..).ok_or(RedactError::Invalid)?,
            self.limits.max_output_line_bytes,
        )?;
        Ok((std::mem::take(&mut *output), count))
    }
}

fn append(output: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), RedactError> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|n| n > max)
    {
        return Err(RedactError::Budget);
    }
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| RedactError::Budget)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_line(
    reader: &mut impl std::io::BufRead,
    line: &mut Zeroizing<Vec<u8>>,
    max: usize,
) -> Result<bool, RedactError> {
    use zeroize::Zeroize as _;
    line.zeroize();
    loop {
        let available = reader.fill_buf().map_err(|_| RedactError::Read)?;
        if available.is_empty() {
            return Ok(!line.is_empty());
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let len = newline.map_or(available.len(), |n| n + 1);
        append(line, available.get(..len).ok_or(RedactError::Invalid)?, max)?;
        reader.consume(len);
        if newline.is_some() {
            return Ok(true);
        }
    }
}
