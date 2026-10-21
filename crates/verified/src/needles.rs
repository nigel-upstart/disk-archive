//! Literal replacement reference semantics, not proof of detector completeness.

#[cfg(verus_only)]
use vstd::prelude::*;

#[cfg(verus_only)]
verus! {
impl NeedleSet {
    pub closed spec fn supplied(self, line: Seq<u8>) -> bool {
        exists|i: int| 0 <= i < self.0@.len() && crate::bytes::contains(line, self.0@[i].0@)
    }
}
}

/// Borrowed finding text; supply both raw variants as separate entries.
/// Deliberately does not implement Debug or serialization.
pub struct FindingRaw<'a> {
    /// Safe detector identifier, not a finding value.
    pub label: &'a str,
    /// UTF-8 scanner value (legacy Python string semantics).
    pub raw: &'a str,
}

/// Invalid detector identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeedleError;

/// Owned needles and replacement bytes, never loggable through Debug.
/// The caller bounds total findings/bytes before constructing this set.
#[cfg_attr(verus_only, verifier::verify)]
pub struct NeedleSet(Vec<(Vec<u8>, Vec<u8>)>);

impl Drop for NeedleSet {
    fn drop(&mut self) {
        // Best effort only: ordinary fill can be optimized away and does not wipe spare
        // capacity, allocator copies, construction temporaries or borrowed finding text.
        for (needle, replacement) in &mut self.0 {
            needle.fill(0);
            replacement.fill(0);
        }
    }
}

/// A size/overflow/allocation failure; never includes input or finding values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactionLimit;

// Own intermediate bytes so both success and error paths attempt best-effort wiping.
struct WipeBuffer(Vec<u8>);

impl Drop for WipeBuffer {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn append_bounded(
    output: &mut Vec<u8>,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(), RedactionLimit> {
    let size = output
        .len()
        .checked_add(bytes.len())
        .ok_or(RedactionLimit)?;
    if size > max_bytes {
        return Err(RedactionLimit);
    }
    // Check before reserving or extending; no intermediate output can exceed the budget.
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| RedactionLimit)?;
    output.extend_from_slice(bytes);
    Ok(())
}

/// Production replacement API: bound the input copy AND each intermediate output.
/// Checks each extension before reserving memory, including replacement-marker amplification.
/// The budget bounds logical bytes per buffer; two buffers may coexist during a pass,
/// and allocator capacity/overhead is not a formal resident-memory bound.
///
/// # Errors
/// Exceeding `max_bytes`, arithmetic overflow or allocation failure returns a static error,
/// never partial successful output. Caller must block the file on error.
pub fn replace_all_bounded(
    line: &[u8],
    needles: &NeedleSet,
    max_bytes: usize,
) -> Result<(Vec<u8>, usize), RedactionLimit> {
    let mut output = WipeBuffer(Vec::new());
    append_bounded(&mut output.0, line, max_bytes)?;
    let mut count = 0_usize;
    for (needle, replacement) in &needles.0 {
        let mut rest = output.0.as_slice();
        let mut next = WipeBuffer(Vec::new());
        while let Some(pos) = rest
            .windows(needle.len())
            .position(|window| window == needle)
        {
            let head = rest.get(..pos).ok_or(RedactionLimit)?;
            let tail = rest.get(pos + needle.len()..).ok_or(RedactionLimit)?;
            append_bounded(&mut next.0, head, max_bytes)?;
            append_bounded(&mut next.0, replacement, max_bytes)?;
            rest = tail;
            count = count.saturating_add(1);
        }
        append_bounded(&mut next.0, rest, max_bytes)?;
        output = next;
    }
    Ok((std::mem::take(&mut output.0), count))
}

fn json_escaped(raw: &str) -> Vec<u8> {
    let mut out = String::new();
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(ch),
            _ => {
                // Python json.dumps defaults to ensure_ascii, with UTF-16 surrogate pairs.
                for word in ch.encode_utf16(&mut [0; 2]) {
                    use std::fmt::Write as _;
                    // Writing to String cannot fail; no external writer is involved.
                    let _ = write!(out, "\\u{word:04x}");
                }
            }
        }
    }
    out.into_bytes()
}

impl NeedleSet {
    /// Preserve first detector for duplicate needles, with stable longest-first order.
    /// Ignore raw values shorter than six Unicode scalar values, like the legacy code.
    /// Full values and JSON-escaped forms are included; line pieces need >=12 scalars.
    ///
    /// # Errors
    /// Detector labels must be nonempty ASCII alphanumeric, underscore, dot or hyphen.
    pub fn from_findings(findings: &[FindingRaw<'_>]) -> Result<Self, NeedleError> {
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for finding in findings {
            if finding.label.is_empty()
                || !finding
                    .label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            {
                return Err(NeedleError);
            }
            if finding.raw.chars().count() < 6 {
                continue;
            }
            let replacement = format!("[REDACTED-{}]", finding.label).into_bytes();
            let escaped = json_escaped(finding.raw);
            for form in [finding.raw.as_bytes(), escaped.as_slice()] {
                if !entries.iter().any(|(needle, _)| needle == form) {
                    entries.push((form.to_vec(), replacement.clone()));
                }
                if let Ok(text) = std::str::from_utf8(form) {
                    for piece in text.split([
                        '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}',
                        '\u{2028}', '\u{2029}',
                    ]) {
                        if piece.chars().count() >= 12
                            && !entries.iter().any(|(needle, _)| needle == piece.as_bytes())
                        {
                            entries.push((piece.as_bytes().to_vec(), replacement.clone()));
                        }
                    }
                }
            }
        }
        entries.sort_by_key(|(needle, _)| std::cmp::Reverse(needle.len()));
        Ok(Self(entries))
    }

    /// Whether any supplied literal needle remains.
    #[must_use]
    // LINT-JUSTIFICATION: Verus proves this index remains below the owned needle count.
    #[allow(clippy::indexing_slicing)]
    #[cfg_attr(verus_only, verus_spec(r => ensures r == self.supplied(bytes@)))]
    pub fn occurs_in(&self, bytes: &[u8]) -> bool {
        let mut i = 0_usize;
        #[cfg_attr(verus_only, verus_spec(
            invariant i <= self.0.len(), forall|j: int| 0 <= j < i ==> !crate::bytes::contains(bytes@, self.0@[j].0@),
            decreases self.0.len() - i,
        ))]
        while i < self.0.len() {
            if crate::bytes::contains_literal(bytes, &self.0[i].0) {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// Unbounded reference/test API; production must use `replace_all_bounded`.
/// Sequential non-overlapping byte replacement, longest needles first.
/// A later replacement can reintroduce an earlier needle: always call `guard_line` LAST.
#[must_use]
pub fn replace_all(line: &[u8], needles: &NeedleSet) -> (Vec<u8>, usize) {
    let mut output = line.to_vec();
    let mut count = 0_usize;
    for (needle, replacement) in &needles.0 {
        let mut rest = output.as_slice();
        let mut next = Vec::new();
        while let Some(pos) = rest
            .windows(needle.len())
            .position(|window| window == needle)
        {
            if let (Some(head), Some(tail)) = (rest.get(..pos), rest.get(pos + needle.len()..)) {
                next.extend_from_slice(head);
                next.extend_from_slice(replacement);
                rest = tail;
                count = count.saturating_add(1);
            }
        }
        next.extend_from_slice(rest);
        output = next;
    }
    (output, count)
}

/// Final per-line guard result; no Debug because output may contain unrelated secrets.
#[cfg_attr(verus_only, verifier::verify)]
pub struct GuardOutcome {
    /// Output containing none of the supplied literal needles.
    pub bytes: Vec<u8>,
    /// Whether the entire unsafe line was dropped.
    pub dropped: bool,
}

/// Keep a safe line; otherwise emit a safe marker, or empty bytes if marker collides.
/// Empty output is safe even for needles containing newline or marker text.
#[must_use]
#[cfg_attr(verus_only, verus_spec(r => ensures !needles.supplied(r.bytes@), r.dropped == needles.supplied(line@)))]
pub fn guard_line(line: &[u8], needles: &NeedleSet) -> GuardOutcome {
    if !needles.occurs_in(line) {
        return GuardOutcome {
            bytes: crate::bytes::copy_bytes(line),
            dropped: false,
        };
    }
    let marker = b"[REDACTED-LINE]\n";
    GuardOutcome {
        bytes: if needles.occurs_in(marker) {
            Vec::new()
        } else {
            crate::bytes::copy_bytes(marker)
        },
        dropped: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_json_and_replacement_marker_collision() -> Result<(), NeedleError> {
        let set = NeedleSet::from_findings(&[
            FindingRaw {
                label: "test",
                raw: "abcdefé😀",
            },
            FindingRaw {
                label: "test",
                raw: "REDACTED",
            },
        ])?;
        let (out, n) = replace_all(b"abcdef\\u00e9\\ud83d\\ude00", &set);
        assert_eq!(n, 2); // JSON form plus the needle reintroduced in its marker.
        assert!(!set.occurs_in(&guard_line(&out, &set).bytes));
        assert_eq!(guard_line(b"REDACTED", &set).bytes, [] as [u8; 0]);
        assert_eq!(guard_line(b"benign", &set).bytes, b"benign");
        Ok(())
    }

    #[test]
    fn bounded_intermediate_amplification() -> Result<(), NeedleError> {
        let set = NeedleSet::from_findings(&[
            FindingRaw {
                label: "abcdef",
                raw: "abcdefgh",
            },
            FindingRaw {
                label: "x",
                raw: "abcdef",
            },
        ])?;
        assert_eq!(
            replace_all_bounded(b"abcdefgh", &set, 20),
            Err(RedactionLimit)
        );
        let expected = replace_all(b"abcdefgh", &set);
        assert_eq!(
            replace_all_bounded(b"abcdefgh", &set, expected.0.len()),
            Ok(expected)
        );
        assert_eq!(
            replace_all_bounded(b"too long", &set, 1),
            Err(RedactionLimit)
        );
        assert_eq!(replace_all_bounded(b"", &set, 0), Ok((Vec::new(), 0)));
        let mut bytes = Vec::new();
        assert_eq!(append_bounded(&mut bytes, b"x", 0), Err(RedactionLimit));
        assert_eq!(bytes.capacity(), 0); // Rejected before allocation, not after extension.
        Ok(())
    }

    #[test]
    fn multiline_longest_and_first_label() -> Result<(), NeedleError> {
        let set = NeedleSet::from_findings(&[
            FindingRaw {
                label: "first",
                raw: "abcdefghijkl\nmnopqrstuvwx",
            },
            FindingRaw {
                label: "second",
                raw: "abcdefghijkl",
            },
            FindingRaw {
                label: "ignored",
                raw: "short",
            },
        ])?;
        assert_eq!(replace_all(b"abcdefghijkl", &set).0, b"[REDACTED-first]");
        assert_eq!(replace_all(b"short", &set).1, 0);
        assert!(set.occurs_in(b"mnopqrstuvwx"));
        Ok(())
    }
}
