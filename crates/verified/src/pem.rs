//! Byte-level PEM delimiter helpers and the multiline state reference.
//! Core owns streaming, inline replacement, environment assignments and output guards.

#[cfg(verus_only)]
use vstd::prelude::*;

#[cfg(verus_only)]
verus! {
broadcast use vstd::array::group_array_axioms;
pub open spec fn valid_marker(line: Seq<u8>, prefix: Seq<u8>, start: int, end: int) -> bool {
    0 <= start && start + prefix.len() <= end - 16 && end <= line.len()
        && crate::bytes::at(line, prefix, start)
        && crate::bytes::at(line, b"PRIVATE KEY-----"@, end - 16)
        && forall|j: int| start + prefix.len() <= j < end - 16 ==> ((65 <= line[j] <= 90) || line[j] == 32)
}
impl PemState {
    pub closed spec fn active(self) -> bool { self.inside }
}
}

/// Multiline private-key state, carried between complete input lines.
#[cfg_attr(verus_only, verifier::verify)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PemState {
    inside: bool,
}

/// Half-open byte span of a PEM delimiter.
#[cfg_attr(verus_only, verifier::verify)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// First delimiter byte.
    pub start: usize,
    /// First byte after the delimiter.
    pub end: usize,
}

// LINT-JUSTIFICATION: Verus proves the scan cursor is in bounds before each byte access.
#[allow(clippy::indexing_slicing)]
#[cfg_attr(verus_only, verus_spec(r => ensures match r { Some(span) => valid_marker(line@, prefix@, span.start as int, span.end as int), None => true }))]
fn marker(line: &[u8], prefix: &[u8]) -> Option<Span> {
    #[cfg(verus_only)]
    proof! { reveal_byteslit(b"PRIVATE KEY-----"); }
    let suffix: &[u8] = b"PRIVATE KEY-----";
    let mut start = 0_usize;
    #[cfg_attr(verus_only, verus_spec(invariant start <= line.len(), suffix@ == b"PRIVATE KEY-----"@, suffix.len() == 16, decreases line.len() - start))]
    while start < line.len() {
        if crate::bytes::matches_at(line, prefix, start) {
            let first = start + prefix.len();
            let mut pos = first;
            #[cfg_attr(verus_only, verus_spec(
                invariant first == start + prefix.len(), first <= pos <= line.len(),
                    crate::bytes::at(line@, prefix@, start as int), suffix@ == b"PRIVATE KEY-----"@, suffix.len() == 16,
                    forall|j: int| first <= j < pos ==> ((65 <= line@[j] <= 90) || line@[j] == 32),
                decreases line.len() - pos + 1,
            ))]
            loop {
                if crate::bytes::matches_at(line, suffix, pos) {
                    return Some(Span {
                        start,
                        end: pos + suffix.len(),
                    });
                }
                if pos == line.len()
                    || !((b'A' <= line[pos] && line[pos] <= b'Z') || line[pos] == b' ')
                {
                    break;
                }
                pos += 1;
            }
        }
        start += 1;
    }
    None
}

/// First BEGIN delimiter matching legacy `[A-Z ]*PRIVATE KEY` semantics.
#[must_use]
#[cfg_attr(verus_only, verus_spec(r => ensures match r { Some(span) => valid_marker(line@, b"-----BEGIN "@, span.start as int, span.end as int), None => true }))]
pub fn begin(line: &[u8]) -> Option<Span> {
    #[cfg(verus_only)]
    proof! { reveal_byteslit(b"-----BEGIN "); }
    marker(line, b"-----BEGIN ")
}

/// First END delimiter matching the same uppercase/space label grammar.
#[must_use]
#[cfg_attr(verus_only, verus_spec(r => ensures match r { Some(span) => valid_marker(line@, b"-----END "@, span.start as int, span.end as int), None => true }))]
pub fn end(line: &[u8]) -> Option<Span> {
    #[cfg(verus_only)]
    proof! { reveal_byteslit(b"-----END "); }
    marker(line, b"-----END ")
}

impl PemState {
    /// Whether intervening lines must be discarded.
    #[must_use]
    #[cfg_attr(verus_only, verus_spec(r => ensures r == self.active()))]
    pub const fn is_inside(self) -> bool {
        self.inside
    }

    /// Enter after core emits the prefix plus a redaction marker for an unmatched BEGIN.
    #[cfg_attr(verus_only, verus_spec(ensures final(self).active()))]
    pub const fn enter(&mut self) {
        self.inside = true;
    }

    /// Before other transformations: discard an active block through its first END.
    /// Return an empty slice for a still-open block, otherwise the retained suffix.
    /// EOF with active state discards the remaining block, never emits its contents.
    #[cfg_attr(verus_only, verus_spec(r => ensures
        !old(self).active() ==> (r@ == line@ && !final(self).active()),
        old(self).active() && final(self).active() ==> r@.len() == 0,
        old(self).active() && !final(self).active() ==> exists|start: int, end: int| valid_marker(line@, b"-----END "@, start, end) && r@ == line@.subrange(end, line@.len() as int),
    ))]
    pub fn resume<'a>(&mut self, line: &'a [u8]) -> &'a [u8] {
        if !self.inside {
            return line;
        }
        if let Some(span) = end(line) {
            self.inside = false;
            return line.get(span.end..).unwrap_or_default();
        }
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_and_delimiter_grammar() {
        assert!(begin(b"x-----BEGIN RSA PRIVATE KEY-----y").is_some());
        assert!(begin(b"-----BEGIN PRIVATE KEY-----").is_some());
        assert!(begin(b"-----BEGIN rsa PRIVATE KEY-----").is_none());
        let mut state = PemState::default();
        state.enter();
        assert_eq!(state.resume(b"key bytes\n"), []);
        assert!(state.is_inside());
        assert_eq!(state.resume(b"-----END PRIVATE KEY-----tail\n"), b"tail\n");
        assert!(!state.is_inside());
    }
}
