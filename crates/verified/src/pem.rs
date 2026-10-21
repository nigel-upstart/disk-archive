//! Byte-level PEM delimiter helpers and the multiline state reference.
//! Core owns streaming, inline replacement, environment assignments and output guards.

/// Multiline private-key state, carried between complete input lines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PemState {
    inside: bool,
}

/// Half-open byte span of a PEM delimiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// First delimiter byte.
    pub start: usize,
    /// First byte after the delimiter.
    pub end: usize,
}

fn marker(line: &[u8], prefix: &[u8]) -> Option<Span> {
    const SUFFIX: &[u8] = b"PRIVATE KEY-----";
    for (start, _) in line
        .windows(prefix.len())
        .enumerate()
        .filter(|(_, part)| *part == prefix)
    {
        let rest = line.get(start + prefix.len()..)?;
        for (offset, part) in rest.windows(SUFFIX.len()).enumerate() {
            if part == SUFFIX
                && rest
                    .get(..offset)?
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || *b == b' ')
            {
                return Some(Span {
                    start,
                    end: start + prefix.len() + offset + SUFFIX.len(),
                });
            }
            if rest
                .get(offset)
                .is_some_and(|b| !b.is_ascii_uppercase() && *b != b' ')
            {
                break;
            }
        }
    }
    None
}

/// First BEGIN delimiter matching legacy `[A-Z ]*PRIVATE KEY` semantics.
#[must_use]
pub fn begin(line: &[u8]) -> Option<Span> {
    marker(line, b"-----BEGIN ")
}

/// First END delimiter matching the same uppercase/space label grammar.
#[must_use]
pub fn end(line: &[u8]) -> Option<Span> {
    marker(line, b"-----END ")
}

impl PemState {
    /// Whether intervening lines must be discarded.
    #[must_use]
    pub const fn is_inside(self) -> bool {
        self.inside
    }

    /// Enter after core emits the prefix plus a redaction marker for an unmatched BEGIN.
    pub const fn enter(&mut self) {
        self.inside = true;
    }

    /// Before other transformations: discard an active block through its first END.
    /// Return an empty slice for a still-open block, otherwise the retained suffix.
    /// EOF with active state discards the remaining block, never emits its contents.
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
