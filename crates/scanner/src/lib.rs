//! In-process, bounded byte scanning with a pinned Kingfisher rule database.
//!
//! No high-level `Vec<Finding>` API, credential validators, archives, filesystem
//! access, logging, or subprocesses are used. Bounded encoded-carrier preflight
//! blocks confirmed decoded secrets; it never emits unsafe raw-offset findings. Findings borrow a fixed
//! zeroizing window and cannot outlive their callback. Only a successful return
//! certifies the entire reader was scanned; any error invalidates partial output.
//! Run this synchronous CPU-bound interface on the application's bounded pool.
mod encoding;
mod guard;

use std::{io::Read, ops::Range};

use guard::SpanGuard;
use kingfisher_rules::{RulesDatabase, get_builtin_rules};
use kingfisher_vectorscan::{BlockScanner, Scan};
use zeroize::{Zeroize, Zeroizing};

/// Static, value-free failures. Never attach underlying input or I/O error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanError {
    /// Invalid or excessive resource limits.
    Budget,
    /// A rule lacks a supported bounded execution strategy.
    UnsupportedRules,
    /// A finite expression's declared maximum exceeds the match budget.
    RuleTooLarge,
    /// Unbounded-expression guard cannot compile within its fixed limits.
    GuardCompile,
    /// Input cannot be safely represented by this scanner/redactor contract.
    UnsupportedInput,
    /// A decoded secret or malformed Unicode carrier cannot be safely redacted.
    UnsupportedEncoding,
    /// An input record exceeds the configured bound.
    LineTooLarge,
    /// A match or still-live match prefix exceeds the configured bound.
    MatchTooLarge,
    /// Input read failed; no clean result may be inferred.
    Read,
    /// Native candidate search failed.
    Engine,
    /// Consumer rejected the finding, including cancellation or its own budget.
    Consumer,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret scan failed: {self:?}")
    }
}

impl std::error::Error for ScanError {}

/// Resource limits, all independent of file size.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bytes read at a time, at most 1 MiB.
    pub chunk_bytes: usize,
    /// Maximum full expression span, including any non-secret context.
    pub match_bytes: usize,
    /// Maximum physical line (excluding LF), also bounds line-local rules.
    pub line_bytes: usize,
    /// Maximum findings over the entire input; exceeding it blocks the file.
    pub findings: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            chunk_bytes: 64 * 1024,
            match_bytes: 1024 * 1024,
            // Core caps physical records INCLUDING LF at 1 MiB.
            line_bytes: 1024 * 1024 - 1,
            findings: 65_536,
        }
    }
}

impl Limits {
    fn validate(self) -> Result<Self, ScanError> {
        if self.chunk_bytes == 0
            || self.chunk_bytes > 1024 * 1024
            || self.match_bytes < 2
            || self.match_bytes > 1024 * 1024
            || self.line_bytes == 0
            || self.line_bytes >= self.match_bytes
            || self.findings == 0
        {
            return Err(ScanError::Budget);
        }
        Ok(self)
    }
}

/// A temporary borrowed secret. Intentionally neither Debug, Clone nor Serialize.
///
/// The callback may use `raw()` only in its bounded redaction scope; never log or
/// persist it. Returning an error aborts immediately. Invalid UTF-8 secret values
/// block rather than being lossily converted (the redactor uses UTF-8 needles).
///
/// ```compile_fail
/// # fn expose(f: disk_archive_scanner::Finding<'_>) {
/// let _ = format!("{f:?}");
/// # }
/// ```
pub struct Finding<'a> {
    rule_id: &'a str,
    redaction_label: &'a str,
    line: u64,
    byte_range: Range<u64>,
    raw: &'a str,
}

impl Finding<'_> {
    /// Stable, non-sensitive detector identifier; safe to count/persist.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        self.rule_id
    }

    /// Kernel-safe detector label (ASCII alphanumeric, dot, underscore, hyphen).
    /// Slash-bearing catalog IDs use hyphens; collisions fail configuration.
    #[must_use]
    pub fn redaction_label(&self) -> &str {
        self.redaction_label
    }

    /// One-based physical line containing the first secret byte.
    #[must_use]
    pub fn line(&self) -> u64 {
        self.line
    }

    /// Absolute byte range of the secret, with exclusive end.
    #[must_use]
    pub fn byte_range(&self) -> Range<u64> {
        self.byte_range.clone()
    }

    /// Borrowed sensitive value, wiped with its owning window after use.
    #[must_use]
    pub fn raw(&self) -> &str {
        self.raw
    }
}

/// Successful whole-input counters only. Not an upload or deletion capability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanSummary {
    /// Number of input bytes read.
    pub bytes: u64,
    /// Number of findings delivered (not credential validations).
    pub findings: u64,
}

/// Reusable immutable, Send + Sync rules. Share one catalog across bounded workers.
/// Per-call native scratch/guard cache is private; no inputs/findings are stored here.
pub struct Scanner {
    database: RulesDatabase,
    limits: Limits,
    guard: Option<SpanGuard>,
    labels: Vec<String>,
    carrier_boundary_invariant: Vec<bool>,
}

impl Scanner {
    /// Compile every embedded Kingfisher rule without provider validation.
    ///
    /// # Errors
    /// Fails closed if any rule cannot execute under the selected budgets.
    pub fn builtin(limits: Limits) -> Result<Self, ScanError> {
        let rules = get_builtin_rules(None).map_err(|_| ScanError::UnsupportedRules)?;
        let database =
            RulesDatabase::from_rule_collection(rules).map_err(|_| ScanError::UnsupportedRules)?;
        Self::new(database, limits)
    }

    /// Wrap a compiled database. No rule is silently omitted.
    ///
    /// Finite rules must fit the match window. Unbounded line-local rules are
    /// bounded by the physical-line budget; all others use a bounded exact
    /// library-backed prefix guard. It retains offsets and automaton states,
    /// never raw match values. Native Kingfisher still detects all findings.
    ///
    /// # Errors
    /// Rejects empty-match rules, oversized finite rules, invalid budgets and
    /// expressions that exceed the bounded guard compiler's resource limits.
    pub fn new(database: RulesDatabase, limits: Limits) -> Result<Self, ScanError> {
        let limits = limits.validate()?;
        if database.rules().is_empty() || database.rules().len() > 1024 {
            return Err(ScanError::UnsupportedRules);
        }
        let mut labels = Vec::new();
        for rule in database.rules() {
            if rule.id().is_empty()
                || rule.id().len() > 128
                || !rule
                    .id()
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
            {
                return Err(ScanError::UnsupportedRules);
            }
            let normalized = rule.id().replace('/', "-");
            let label = if normalized.len() <= 64 {
                normalized
            } else {
                format!("kf.{}", rule.finding_sha1_fingerprint())
            };
            if labels.contains(&label) {
                return Err(ScanError::UnsupportedRules);
            }
            labels.push(label);
        }
        let mut unbounded = Vec::new();
        let mut carrier_boundary_invariant = Vec::with_capacity(database.num_rules());
        for (index, regex) in database.anchored_regexes().iter().enumerate() {
            let hir = regex_syntax::ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(regex.as_str())
                .map_err(|_| ScanError::UnsupportedRules)?;
            if hir.properties().minimum_len().is_none_or(|size| size == 0) {
                return Err(ScanError::UnsupportedRules);
            }
            let line_restart_safe = database.confirmation_line_restart_safe(index);
            carrier_boundary_invariant
                .push(line_restart_safe && !encoding::can_assert_after_lf(&hir, false));
            if let Some(size) = database.confirmation_match_maximum_len(index) {
                if size > limits.match_bytes {
                    return Err(ScanError::RuleTooLarge);
                }
            } else if !line_restart_safe {
                unbounded.push(regex.as_str().to_owned());
            }
        }
        let guard = SpanGuard::new(&unbounded)?;
        Ok(Self {
            database,
            limits,
            guard,
            labels,
            carrier_boundary_invariant,
        })
    }

    /// Number of admitted catalog rules; no rule is silently dropped.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.database.num_rules()
    }

    /// Fixed input allocation size, independent of reader length.
    #[must_use]
    pub fn input_buffer_bytes(&self) -> usize {
        self.limits.match_bytes + self.limits.chunk_bytes + 3
    }

    /// Scan incrementally. Callbacks finish before more bytes are read.
    ///
    /// Findings are ordered by rule within each bounded window, not globally by
    /// byte offset. Repeated calls never deduplicate away verification findings.
    /// A consumer must enforce its own aggregate raw-value storage budget.
    ///
    /// # Errors
    /// Any read, matching, size, encoding or consumer error blocks the input;
    /// never interpret already-delivered partial findings as a clean scan.
    pub fn scan<R, F>(&self, mut reader: R, mut consume: F) -> Result<ScanSummary, ScanError>
    where
        R: Read,
        F: FnMut(Finding<'_>) -> Result<(), ScanError>,
    {
        let mut native =
            BlockScanner::new(self.database.vectorscan_db()).map_err(|_| ScanError::Engine)?;
        let mut guard_stream = self
            .guard
            .as_ref()
            .map(|guard| guard.stream(self.limits.match_bytes));
        let mut preflight = Some(encoding::Preflight::new(self)?);
        let mut window = Window::new(self.limits);
        let mut state = StreamState::new(self.database.num_rules());
        loop {
            let old_len = window.used;
            let target = window
                .bytes
                .get_mut(old_len..old_len + self.limits.chunk_bytes)
                .ok_or(ScanError::Budget)?;
            // Read is allowed to return short chunks. Accumulate up to the
            // configured bound so tiny readers do not rescan a 1 MiB window on
            // every byte. Callbacks still finish before reading the next chunk.
            let mut read = 0;
            let mut eof = false;
            while read < target.len() {
                let rest = target.get_mut(read..).ok_or(ScanError::Budget)?;
                match reader.read(rest) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(ScanError::Read),
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(size) if size > rest.len() => return Err(ScanError::Read),
                    Ok(size) => read += size,
                }
            }
            window.used += read;
            let new_bytes = window
                .bytes
                .get(old_len..window.used)
                .ok_or(ScanError::Budget)?;
            state.advance(new_bytes, self.limits)?;
            if let Some(check) = preflight.as_mut() {
                check.advance(new_bytes)?;
            }
            if eof && let Some(check) = preflight.take() {
                check.finish()?;
            }
            if let Some(stream) = guard_stream.as_mut() {
                stream.advance(new_bytes)?;
            }
            if eof && let Some(stream) = guard_stream.take() {
                stream.finish()?;
            }
            // Lookahead of M+2 resolves greediness and end/word assertions. Keep
            // one preceding byte when sliding, so ^/\A cannot be fabricated.
            let frontier = if eof {
                window.base + window.used as u64
            } else {
                (window.base + window.used as u64)
                    .saturating_sub(self.limits.match_bytes as u64 + 2)
            };
            if frontier > state.frontier || eof {
                self.scan_window(&window, &mut native, &mut state, frontier, &mut consume)?;
                state.frontier = frontier;
                window.slide(frontier)?;
            }
            if eof {
                return Ok(state.summary);
            }
        }
    }

    fn scan_window<F>(
        &self,
        window: &Window,
        native: &mut BlockScanner<'_>,
        state: &mut StreamState,
        frontier: u64,
        consume: &mut F,
    ) -> Result<(), ScanError>
    where
        F: FnMut(Finding<'_>) -> Result<(), ScanError>,
    {
        let bytes = window.bytes.get(..window.used).ok_or(ScanError::Budget)?;
        let selected = self.selected_rules(native, bytes)?;
        for (index, (regex, rule)) in self
            .database
            .anchored_regexes()
            .iter()
            .zip(self.database.rules())
            .enumerate()
        {
            if !selected.get(index).copied().ok_or(ScanError::Engine)? {
                continue;
            }
            let end = state.ends.get_mut(index).ok_or(ScanError::Engine)?;
            let first = (*end).max(state.frontier);
            let mut at = usize::try_from(first.saturating_sub(window.base))
                .map_err(|_| ScanError::Budget)?;
            // Full captures are nonoverlapping, so secret starts are monotone.
            // Count each window byte at most once per selected rule rather than
            // rescanning its prefix for every finding in a dense input.
            let mut line_cursor = 0;
            let mut finding_line = window.line;
            while let Some(captures) = regex.captures_at(bytes, at) {
                let full = captures.get(0).ok_or(ScanError::Engine)?;
                if full.start() as u64 + window.base >= frontier {
                    break;
                }
                if full.is_empty() || full.len() > self.limits.match_bytes {
                    return Err(ScanError::MatchTooLarge);
                }
                at = full.end();
                *end = window.base + at as u64;
                let secret = kingfisher_scanner::primitives::find_secret_capture_with_group(
                    regex,
                    &captures,
                    rule.betterleaks_secret_group(),
                );
                let raw = std::str::from_utf8(secret.as_bytes())
                    .map_err(|_| ScanError::UnsupportedInput)?;
                if raw.is_empty() {
                    return Err(ScanError::UnsupportedInput);
                }
                state.summary.findings = state
                    .summary
                    .findings
                    .checked_add(1)
                    .ok_or(ScanError::Budget)?;
                if state.summary.findings > self.limits.findings {
                    return Err(ScanError::Budget);
                }
                let preceding_lines = memchr::memchr_iter(
                    b'\n',
                    bytes
                        .get(line_cursor..secret.start())
                        .ok_or(ScanError::Engine)?,
                )
                .count() as u64;
                finding_line = finding_line
                    .checked_add(preceding_lines)
                    .ok_or(ScanError::Budget)?;
                line_cursor = secret.start();
                consume(Finding {
                    rule_id: rule.id(),
                    redaction_label: self.labels.get(index).ok_or(ScanError::Engine)?,
                    line: finding_line,
                    byte_range: (window.base + secret.start() as u64)
                        ..(window.base + secret.end() as u64),
                    raw,
                })?;
            }
        }
        Ok(())
    }

    // Whole bounded decoded candidates need no streaming offset projection.
    // The native selector and original confirmation expressions are identical
    // to direct scanning; a decoder is never itself a credential detector.
    fn confirm_decoded(
        &self,
        native: &mut BlockScanner<'_>,
        bytes: &[u8],
        provenance: Option<&encoding::Provenance<'_>>,
    ) -> Result<bool, ScanError> {
        let selected = self.selected_rules(native, bytes)?;
        for (index, regex) in self.database.anchored_regexes().iter().enumerate() {
            if !selected.get(index).copied().ok_or(ScanError::Engine)? {
                continue;
            }
            let boundary_invariant = self
                .carrier_boundary_invariant
                .get(index)
                .copied()
                .ok_or(ScanError::Engine)?;
            let provenance = provenance.filter(|_| boundary_invariant);
            let mut originals = provenance.map(|origin| regex.captures_iter(origin.source));
            for captures in regex.captures_iter(bytes) {
                let rule = self.database.rules().get(index).ok_or(ScanError::Engine)?;
                let secret = kingfisher_scanner::primitives::find_secret_capture_with_group(
                    regex,
                    &captures,
                    rule.betterleaks_secret_group(),
                );
                let Some(origin) = provenance else {
                    return Ok(true);
                };
                let Some(range) = origin.original(secret.range()) else {
                    return Ok(true);
                };
                // Use actual nonoverlapping raw matches, not captures_at: an
                // earlier raw alternative could otherwise suppress this span.
                let mut original = None;
                for captures in originals.as_mut().ok_or(ScanError::Engine)? {
                    let full = captures.get(0).ok_or(ScanError::Engine)?;
                    // Even a skipped match at a fabricated carrier boundary
                    // can suppress different later matches in the raw stream.
                    if full.start() == 0 || full.end() >= origin.source.len() {
                        return Ok(true);
                    }
                    let raw = kingfisher_scanner::primitives::find_secret_capture_with_group(
                        regex,
                        &captures,
                        rule.betterleaks_secret_group(),
                    );
                    if raw.end() >= range.end {
                        original = Some(raw.range());
                        break;
                    }
                }
                let Some(raw) = original else {
                    return Ok(true);
                };
                if raw != range {
                    return Ok(true);
                }
                // The secret itself is unchanged and independently selected
                // by an actual raw match with non-fabricated context. Context
                // delimiters may transform; the raw secret must be identical
                // at this exact source span. Normal redaction handles it.
            }
        }
        Ok(false)
    }

    fn selected_rules(
        &self,
        native: &mut BlockScanner<'_>,
        bytes: &[u8],
    ) -> Result<Vec<bool>, ScanError> {
        let mut selected = vec![false; self.database.num_rules()];
        let mut invalid_id = false;
        let mut candidate_events = 0_u32;
        native
            .scan(bytes, |id, _, _, _| {
                candidate_events += 1;
                if candidate_events > 1_048_576 {
                    return Scan::Terminate;
                }
                if let Some(flag) = selected.get_mut(id as usize) {
                    *flag = true;
                } else {
                    invalid_id = true;
                }
                Scan::Continue
            })
            .map_err(|_| ScanError::Engine)?;
        if invalid_id {
            return Err(ScanError::Engine);
        }
        if candidate_events > 1_048_576 {
            return Err(ScanError::Budget);
        }
        Ok(selected)
    }
}

struct StreamState {
    line_length: usize,
    ends: Vec<u64>,
    frontier: u64,
    summary: ScanSummary,
}

impl StreamState {
    fn new(rules: usize) -> Self {
        Self {
            line_length: 0,
            ends: vec![0; rules],
            frontier: 0,
            summary: ScanSummary::default(),
        }
    }

    fn advance(&mut self, bytes: &[u8], limits: Limits) -> Result<(), ScanError> {
        for &byte in bytes {
            self.line_length = if byte == b'\n' {
                0
            } else {
                self.line_length + 1
            };
            if self.line_length > limits.line_bytes {
                return Err(ScanError::LineTooLarge);
            }
        }
        self.summary.bytes = self
            .summary
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or(ScanError::Budget)?;
        Ok(())
    }
}

struct Window {
    bytes: Zeroizing<Vec<u8>>,
    used: usize,
    base: u64,
    line: u64,
}

impl Window {
    fn new(limits: Limits) -> Self {
        // Allocate once, at final length: no reallocation of sensitive bytes.
        Self {
            bytes: Zeroizing::new(vec![0; limits.match_bytes + limits.chunk_bytes + 3]),
            used: 0,
            base: 0,
            line: 1,
        }
    }

    fn slide(&mut self, frontier: u64) -> Result<(), ScanError> {
        let retain = frontier.saturating_sub(1).max(self.base);
        let discard = usize::try_from(retain - self.base).map_err(|_| ScanError::Budget)?;
        let discarded_lines =
            memchr::memchr_iter(b'\n', self.bytes.get(..discard).ok_or(ScanError::Budget)?).count()
                as u64;
        self.line = self
            .line
            .checked_add(discarded_lines)
            .ok_or(ScanError::Budget)?;
        self.bytes.copy_within(discard..self.used, 0);
        let kept = self.used - discard;
        self.bytes
            .get_mut(kept..self.used)
            .ok_or(ScanError::Budget)?
            .zeroize();
        self.used = kept;
        self.base = retain;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_scanner_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Scanner>();
    }

    #[test]
    fn compaction_and_explicit_wipe_clear_sensitive_window() -> Result<(), ScanError> {
        let mut window = Window::new(Limits::default());
        let fixture = b"synthetic-only\nremaining";
        window
            .bytes
            .get_mut(..fixture.len())
            .ok_or(ScanError::Budget)?
            .copy_from_slice(fixture);
        window.used = fixture.len();
        window.slide(16)?;
        assert_eq!(window.base, 15);
        assert_eq!(window.line, 2);
        assert!(
            window
                .bytes
                .get(window.used..fixture.len())
                .ok_or(ScanError::Budget)?
                .iter()
                .all(|&byte| byte == 0)
        );
        // Inspect a live allocation, never dereference freed storage. Drop uses
        // the same zeroize primitive via Zeroizing<Vec<u8>> (including capacity).
        window.bytes.as_mut_slice().zeroize();
        assert!(window.bytes.iter().all(|&byte| byte == 0));
        Ok(())
    }
}
