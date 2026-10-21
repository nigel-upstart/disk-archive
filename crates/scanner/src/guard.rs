//! A bounded, value-free recognizer for unfinished unbounded expressions.
//!
//! Anchored DFA states are merged by state ID, retaining the oldest start. If a
//! live path gets older than the retained window we block, even if it never ends
//! in a full match. This conservative rejection prevents chunking from silently
//! losing a giant match (or changing greedy-match selection).
use regex_automata::{
    Anchored, MatchKind,
    dfa::{Automaton, StartKind, dense},
    util::{primitives::StateID, start, syntax},
};

use zeroize::Zeroize;

use crate::ScanError;

pub(crate) struct PrefixGuard {
    dfa: dense::DFA<Vec<u32>>,
}

impl PrefixGuard {
    pub(crate) fn new(patterns: &[String]) -> Result<Option<Self>, ScanError> {
        if patterns.is_empty() {
            return Ok(None);
        }
        let dfa = dense::Builder::new()
            .configure(
                dense::Config::new()
                    .start_kind(StartKind::Anchored)
                    .match_kind(MatchKind::All)
                    .dfa_size_limit(Some(64 * 1024 * 1024))
                    .determinize_size_limit(Some(128 * 1024 * 1024)),
            )
            .syntax(syntax::Config::new().unicode(false).utf8(false))
            .build_many(patterns)
            .map_err(|_| ScanError::GuardCompile)?;
        Ok(Some(Self { dfa }))
    }

    pub(crate) fn advance(
        &self,
        state: &mut GuardState,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(), ScanError> {
        for &byte in bytes {
            let start = self
                .dfa
                .start_state(
                    &start::Config::new()
                        .anchored(Anchored::Yes)
                        .look_behind(state.previous),
                )
                .map_err(|_| ScanError::UnsupportedInput)?;
            // Merging equal states is sound: all future transitions depend only
            // on the state, so retaining the oldest start is conservative.
            state.next.clear();
            for (old, begin) in state
                .active
                .iter()
                .copied()
                .chain(std::iter::once((start, state.offset)))
            {
                let next = self.dfa.next_state(old, byte);
                if self.dfa.is_quit_state(next) {
                    return Err(ScanError::UnsupportedInput);
                }
                if !self.dfa.is_dead_state(next) {
                    // DFA matches are delayed one byte for look assertions.
                    if state.offset.saturating_sub(begin) > maximum as u64 {
                        return Err(ScanError::MatchTooLarge);
                    }
                    state.next.push((next, begin));
                }
            }
            state.next.sort_unstable();
            state.next.dedup_by_key(|(id, _)| *id);
            if state.next.len() > 4096 {
                return Err(ScanError::Budget);
            }
            std::mem::swap(&mut state.active, &mut state.next);
            state.previous = Some(byte);
            state.offset = state.offset.checked_add(1).ok_or(ScanError::Budget)?;
        }
        Ok(())
    }
}

impl Drop for GuardState {
    fn drop(&mut self) {
        self.previous.zeroize();
    }
}

pub(crate) struct GuardState {
    active: Vec<(StateID, u64)>,
    next: Vec<(StateID, u64)>,
    previous: Option<u8>,
    offset: u64,
}

impl Default for GuardState {
    fn default() -> Self {
        Self {
            active: Vec::with_capacity(4097),
            next: Vec::with_capacity(4097),
            previous: None,
            offset: 0,
        }
    }
}
