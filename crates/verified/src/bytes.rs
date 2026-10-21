//! Shared literal byte comparisons used by production safety kernels.

#[cfg(verus_only)]
use vstd::prelude::*;

#[cfg(verus_only)]
verus! {
pub open spec fn at(haystack: Seq<u8>, needle: Seq<u8>, start: int) -> bool {
    0 <= start && start + needle.len() <= haystack.len()
        && forall|j: int| 0 <= j < needle.len() ==> haystack[start + j] == needle[j]
}

pub open spec fn contains(haystack: Seq<u8>, needle: Seq<u8>) -> bool {
    needle.len() > 0 && exists|start: int| at(haystack, needle, start)
}
}

/// Copy bytes without relying on an unmodelled slice-to-Vec library operation.
// LINT-JUSTIFICATION: Verus proves the index is below the source slice length on every push.
#[allow(clippy::indexing_slicing)]
#[cfg_attr(verus_only, verus_spec(r => ensures r@ == source@))]
pub fn copy_bytes(source: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut i = 0_usize;
    #[cfg_attr(verus_only, verus_spec(
        invariant i <= source.len(), output@ == source@.subrange(0, i as int),
        decreases source.len() - i,
    ))]
    while i < source.len() {
        output.push(source[i]);
        i += 1;
    }
    output
}

/// Append a bounded slice; allocation behavior remains that of the standard Vec.
// LINT-JUSTIFICATION: Verus proves the source index and resulting Vec length are in range.
#[allow(clippy::indexing_slicing)]
#[cfg_attr(verus_only, verus_spec(
    requires old(output).len() + source.len() <= usize::MAX,
    ensures final(output)@ == old(output)@ + source@,
))]
pub fn append_bytes(output: &mut Vec<u8>, source: &[u8]) {
    let mut i = 0_usize;
    #[cfg_attr(verus_only, verus_spec(
        invariant i <= source.len(), output@ == old(output)@ + source@.subrange(0, i as int),
            old(output).len() + source.len() <= usize::MAX,
        decreases source.len() - i,
    ))]
    while i < source.len() {
        output.push(source[i]);
        i += 1;
    }
}

/// Match a literal at one checked byte offset, including empty literals.
#[must_use]
// LINT-JUSTIFICATION: Verus proves both array indexes are within their slice lengths.
#[allow(clippy::indexing_slicing)]
#[cfg_attr(verus_only, verus_spec(r => ensures r == at(haystack@, needle@, start as int)))]
pub fn matches_at(haystack: &[u8], needle: &[u8], start: usize) -> bool {
    if needle.len() > haystack.len() || start > haystack.len() - needle.len() {
        return false;
    }
    let mut i = 0_usize;
    #[cfg_attr(verus_only, verus_spec(
        invariant i <= needle.len(), start + needle.len() <= haystack.len(),
            forall|j: int| 0 <= j < i ==> haystack@[start as int + j] == needle@[j],
        decreases needle.len() - i,
    ))]
    while i < needle.len() {
        if haystack[start + i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Literal occurrence; an empty literal is not a secret needle.
#[must_use]
#[cfg_attr(verus_only, verus_spec(r => ensures r == contains(haystack@, needle@)))]
pub fn contains_literal(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let mut start = 0_usize;
    #[cfg_attr(verus_only, verus_spec(
        invariant start <= haystack.len() - needle.len() + 1,
            needle.len() > 0, needle.len() <= haystack.len(),
            forall|j: int| 0 <= j < start ==> !at(haystack@, needle@, j),
        decreases haystack.len() - needle.len() + 1 - start,
    ))]
    while start <= haystack.len() - needle.len() {
        if matches_at(haystack, needle, start) {
            return true;
        }
        start += 1;
    }
    false
}
