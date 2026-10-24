//! Bounded library-backed prefix guard; it never selects or emits findings.
//!
//! Native Kingfisher remains the detector. This exact-language guard keeps only
//! automaton states/oldest offsets for unbounded multiline rules. A lazy cache
//! avoids eager determinization blowups. Any cache clearing is forbidden: state
//! IDs retained across transitions must never become stale.
use regex_automata::{
    Anchored, MatchKind, PatternID,
    hybrid::{LazyStateID, dfa},
    nfa::thompson,
    util::{start, syntax},
};
use zeroize::Zeroize;

use crate::ScanError;

pub(crate) struct SpanGuard {
    dfa: dfa::DFA,
    starts: [Vec<PatternID>; 256],
}

impl SpanGuard {
    pub(crate) fn new(patterns: &[String]) -> Result<Option<Self>, ScanError> {
        if patterns.is_empty() {
            return Ok(None);
        }
        let dfa = dfa::DFA::builder()
            .configure(
                dfa::Config::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .starts_for_each_pattern(true)
                    .cache_capacity(64 * 1024 * 1024)
                    .minimum_cache_clear_count(Some(0)),
            )
            .syntax(syntax::Config::new().unicode(false).utf8(false))
            .thompson(
                thompson::Config::new()
                    .utf8(false)
                    .nfa_size_limit(Some(16 * 1024 * 1024)),
            )
            .build_many(patterns)
            .map_err(|_| ScanError::GuardCompile)?;
        let mut starts: [Vec<PatternID>; 256] = std::array::from_fn(|_| Vec::new());
        for (index, pattern) in patterns.iter().enumerate() {
            let id = PatternID::new(index).map_err(|_| ScanError::GuardCompile)?;
            let hir = regex_syntax::ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(pattern)
                .map_err(|_| ScanError::GuardCompile)?;
            // Library-extracted first bytes are a conservative prefilter, not a
            // detector. Infinite/empty prefixes mean spawn on EVERY byte.
            let prefixes = regex_syntax::hir::literal::Extractor::new()
                .limit_literal_len(1)
                .extract(&hir);
            let mut allowed = [false; 256];
            if let Some(literals) = prefixes.literals().filter(|items| !items.is_empty()) {
                for literal in literals {
                    if let Some(&byte) = literal.as_bytes().first() {
                        *allowed
                            .get_mut(usize::from(byte))
                            .ok_or(ScanError::GuardCompile)? = true;
                    } else {
                        allowed.fill(true);
                    }
                }
            } else {
                allowed.fill(true);
            }
            for (byte, enabled) in allowed.into_iter().enumerate() {
                if enabled {
                    starts
                        .get_mut(byte)
                        .ok_or(ScanError::GuardCompile)?
                        .push(id);
                }
            }
        }
        Ok(Some(Self { dfa, starts }))
    }

    pub(crate) fn stream(&self, maximum: usize) -> GuardStream<'_> {
        GuardStream {
            guard: self,
            cache: self.dfa.create_cache(),
            active: Vec::with_capacity(5120),
            next: Vec::with_capacity(5120),
            previous: None,
            offset: 0,
            maximum: maximum as u64,
        }
    }
}

pub(crate) struct GuardStream<'a> {
    guard: &'a SpanGuard,
    cache: dfa::Cache,
    active: Vec<(LazyStateID, u64)>,
    next: Vec<(LazyStateID, u64)>,
    previous: Option<u8>,
    offset: u64,
    maximum: u64,
}

impl GuardStream<'_> {
    pub(crate) fn advance(&mut self, bytes: &[u8]) -> Result<(), ScanError> {
        for &byte in bytes {
            for &pattern in self
                .guard
                .starts
                .get(usize::from(byte))
                .ok_or(ScanError::Budget)?
            {
                let start = self
                    .guard
                    .dfa
                    .start_state(
                        &mut self.cache,
                        &start::Config::new()
                            .anchored(Anchored::Pattern(pattern))
                            .look_behind(self.previous),
                    )
                    .map_err(|_| ScanError::Budget)?;
                if self.cache.clear_count() != 0 {
                    return Err(ScanError::Budget);
                }
                if !start.is_dead() {
                    self.active.push((start, self.offset));
                }
            }
            self.next.clear();
            for (old, begin) in self.active.iter().copied() {
                let next = self
                    .guard
                    .dfa
                    .next_state(&mut self.cache, old, byte)
                    .map_err(|_| ScanError::Budget)?;
                // Check immediately, before passing ANY older ID back to the
                // library. No clear/reset can invalidate a retained state ID.
                if self.cache.clear_count() != 0 {
                    return Err(ScanError::Budget);
                }
                if next.is_quit() {
                    return Err(ScanError::UnsupportedInput);
                }
                if !next.is_dead() {
                    // Match states have a one-byte acceptance delay. M+2 input
                    // overlap covers that delay and subsequent assertions.
                    if self.offset.saturating_sub(begin) > self.maximum {
                        return Err(ScanError::MatchTooLarge);
                    }
                    self.next.push((next, begin));
                }
            }
            // Equal states have identical futures; retain the oldest start.
            self.next.sort_unstable();
            self.next.dedup_by_key(|(id, _)| *id);
            if self.next.len() > 4096 {
                return Err(ScanError::Budget);
            }
            std::mem::swap(&mut self.active, &mut self.next);
            self.previous = Some(byte);
            self.offset = self.offset.checked_add(1).ok_or(ScanError::Budget)?;
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<(), ScanError> {
        for &(state, begin) in &self.active {
            let end = self
                .guard
                .dfa
                .next_eoi_state(&mut self.cache, state)
                .map_err(|_| ScanError::Budget)?;
            if self.cache.clear_count() != 0 {
                return Err(ScanError::Budget);
            }
            if end.is_quit() {
                return Err(ScanError::UnsupportedInput);
            }
            if end.is_match() && self.offset.saturating_sub(begin) > self.maximum {
                return Err(ScanError::MatchTooLarge);
            }
        }
        Ok(())
    }
}

impl Drop for GuardStream<'_> {
    fn drop(&mut self) {
        self.previous.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_exhaustion_blocks_without_invalidating_retained_ids()
    -> Result<(), Box<dyn std::error::Error>> {
        let dfa = dfa::DFA::builder()
            .configure(
                dfa::Config::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .starts_for_each_pattern(true)
                    .cache_capacity(16 * 1024)
                    .minimum_cache_clear_count(Some(0)),
            )
            .syntax(syntax::Config::new().unicode(false).utf8(false))
            .build("[ab]*a[ab]{15}")?;
        let guard = SpanGuard {
            dfa,
            starts: std::array::from_fn(|_| vec![PatternID::ZERO]),
        };
        let mut stream = guard.stream(1024 * 1024);
        let mut seed = 42_u32;
        let input: Vec<_> = (0..16384)
            .map(|_| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                if seed & 0x8000_0000 == 0 { b'a' } else { b'b' }
            })
            .collect();
        assert_eq!(stream.advance(&input), Err(ScanError::Budget));
        assert_eq!(stream.cache.clear_count(), 0);
        Ok(())
    }
}
