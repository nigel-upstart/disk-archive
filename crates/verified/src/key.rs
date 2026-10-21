//! Canonical versioned, injective encoding of home-relative Unix path bytes.

#[cfg(verus_only)]
use vstd::prelude::*;

#[cfg(verus_only)]
verus! {
impl KeyPrefix {
    pub closed spec fn value(self) -> Seq<u8> { self.0@ }
}
}

/// Invalid prefix, path, encoding, or S3 key length.
#[cfg_attr(verus_only, verifier::verify)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Prefix must be nonempty printable ASCII with no empty or dot components.
    Prefix,
    /// Path must be relative, nonempty, and contain no NUL or empty/dot components.
    Path,
    /// Key exceeds S3's 1024-byte limit.
    TooLong,
    /// Key is not the canonical encoding for this prefix.
    Encoding,
}

/// Validated destination namespace; stores no bucket or credentials.
#[cfg_attr(verus_only, verifier::verify)]
#[derive(Debug, PartialEq, Eq)]
pub struct KeyPrefix(Vec<u8>);

#[cfg_attr(verus_only, verifier::verify)]
impl Clone for KeyPrefix {
    #[cfg_attr(verus_only, verus_spec(r => ensures r.value() == self.value()))]
    fn clone(&self) -> Self {
        Self(crate::bytes::copy_bytes(&self.0))
    }
}

// LINT-JUSTIFICATION: Verus proves component bounds before testing one- or two-dot names.
#[allow(clippy::indexing_slicing)]
#[cfg_attr(verus_only, verus_spec(requires start <= end <= bytes.len()))]
fn valid_component(bytes: &[u8], start: usize, end: usize) -> bool {
    let len = end - start;
    len != 0
        && !(len == 1 && bytes[start] == b'.')
        && !(len == 2 && bytes[start] == b'.' && bytes[start + 1] == b'.')
}

// LINT-JUSTIFICATION: Verus proves scan and component cursors remain within the path slice.
#[allow(clippy::indexing_slicing)]
#[cfg_attr(verus_only, verus_spec())]
fn valid_components(bytes: &[u8]) -> bool {
    let mut start = 0_usize;
    let mut i = 0_usize;
    #[cfg_attr(verus_only, verus_spec(invariant start <= i <= bytes.len(), decreases bytes.len() - i))]
    while i < bytes.len() {
        if bytes[i] == 0 {
            return false;
        }
        if bytes[i] == b'/' {
            if !valid_component(bytes, start, i) {
                return false;
            }
            start = i + 1;
        }
        i += 1;
    }
    valid_component(bytes, start, bytes.len())
}

// LINT-JUSTIFICATION: Explicit byte comparisons share the exact predicate verified by Verus.
#[allow(clippy::manual_range_contains)]
#[cfg_attr(verus_only, verus_spec(r => ensures r == crate::key_model::plain(byte)))]
fn plain_byte(byte: u8) -> bool {
    (b'0' <= byte && byte <= b'9')
        || (b'A' <= byte && byte <= b'Z')
        || (b'a' <= byte && byte <= b'z')
        || byte == b'-'
        || byte == b'_'
        || byte == b'.'
        || byte == b'/'
}

#[cfg_attr(verus_only, verus_spec(r => requires value < 16, ensures r == crate::key_model::digit(value as int)))]
fn hex_digit(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'A' + value - 10
    }
}

// LINT-JUSTIFICATION: Verus proves the source cursor and encoded-size arithmetic are bounded.
#[allow(clippy::indexing_slicing)]
#[cfg_attr(verus_only, verus_spec(r => requires source.len() <= 1024,
    ensures r@ == crate::key_model::encoded(source@), r.len() <= source.len() * 3,
))]
fn encode_path(source: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut i = 0_usize;
    #[cfg_attr(verus_only, verus_spec(
        invariant i <= source.len() <= 1024, output@ == crate::key_model::encoded(source@.subrange(0, i as int)), output.len() <= i * 3,
        decreases source.len() - i,
    ))]
    while i < source.len() {
        let byte = source[i];
        #[cfg(verus_only)]
        proof! {
            crate::key_model::encoded_push(source@.subrange(0, i as int), byte);
            assert(source@.subrange(0, i as int).push(byte) =~= source@.subrange(0, i as int + 1));
        }
        if plain_byte(byte) {
            output.push(byte);
        } else {
            output.push(b'%');
            output.push(hex_digit(byte / 16));
            output.push(hex_digit(byte % 16));
        }
        i += 1;
    }
    #[cfg(verus_only)]
    proof! { assert(source@.subrange(0, source@.len() as int) =~= source@); }
    output
}

impl KeyPrefix {
    /// Construct a prefix without leading/trailing slash; no implicit normalization.
    ///
    /// # Errors
    /// Returns `KeyError::Prefix` for invalid components or nonprintable/non-ASCII bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, KeyError> {
        if !valid_components(bytes) || !bytes.iter().all(|b| (0x21..=0x7e).contains(b)) {
            return Err(KeyError::Prefix);
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// Encode as `prefix/v1/<percent-encoded path>.gz`.
/// '/' is preserved; only ASCII alphanumerics, '-', '_' and '.' are unescaped.
/// Percent signs and non-UTF8 bytes are encoded; dotfiles are never stripped.
///
/// # Errors
/// Returns an error for invalid relative components or a key longer than 1024 bytes.
#[cfg_attr(verus_only, verus_spec(r => ensures match r {
    Ok(bytes) => bytes.len() <= 1024 && bytes@ == crate::key_model::key(prefix.value(), rel_path@),
    Err(_) => true,
}))]
pub fn encode_key(prefix: &KeyPrefix, rel_path: &[u8]) -> Result<Vec<u8>, KeyError> {
    if !valid_components(rel_path) {
        return Err(KeyError::Path);
    }
    if prefix.0.len() > 1024 || rel_path.len() > 1024 {
        return Err(KeyError::TooLong);
    }
    let body = encode_path(rel_path);
    let size = prefix.0.len() + 4 + body.len() + 3;
    if size > 1024 {
        return Err(KeyError::TooLong);
    }
    #[cfg(verus_only)]
    proof! { reveal_byteslit(b"/v1/"); reveal_byteslit(b".gz"); }
    let mut output = crate::bytes::copy_bytes(&prefix.0);
    crate::bytes::append_bytes(&mut output, b"/v1/");
    crate::bytes::append_bytes(&mut output, &body);
    crate::bytes::append_bytes(&mut output, b".gz");
    Ok(output)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Inverse restricted to canonical keys; intended for tests and the injectivity proof.
///
/// # Errors
/// Rejects wrong namespace, malformed escapes, noncanonical encoding, and invalid paths.
pub fn decode_rel(prefix: &KeyPrefix, key: &[u8]) -> Result<Vec<u8>, KeyError> {
    let mut start = prefix.0.clone();
    start.extend_from_slice(b"/v1/");
    let body = key
        .strip_prefix(start.as_slice())
        .and_then(|s| s.strip_suffix(b".gz"))
        .ok_or(KeyError::Encoding)?;
    let mut out = Vec::new();
    let mut bytes = body.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hi = bytes.next().and_then(hex).ok_or(KeyError::Encoding)?;
            let lo = bytes.next().and_then(hex).ok_or(KeyError::Encoding)?;
            out.push(hi * 16 + lo);
        } else {
            out.push(byte);
        }
    }
    if encode_key(prefix, &out)?.as_slice() != key {
        return Err(KeyError::Encoding);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_prefixes_do_not_guarantee_namespace_isolation() -> Result<(), KeyError> {
        let short = KeyPrefix::new(b"archive")?;
        let nested = KeyPrefix::new(b"archive/v1/other")?;
        assert_eq!(
            encode_key(&short, b"other/v1/file")?,
            encode_key(&nested, b"file")?
        );
        Ok(())
    }

    #[test]
    fn roundtrip_and_legacy_collision() -> Result<(), KeyError> {
        let prefix = KeyPrefix::new(b"archive")?;
        assert_ne!(encode_key(&prefix, b".x/f")?, encode_key(&prefix, b"x/f")?);
        for path in [b".x/f".as_slice(), b"a/%2F", b"a/\xff", b"a/a.gz", b"a/ "] {
            assert_eq!(decode_rel(&prefix, &encode_key(&prefix, path)?)?, path);
        }
        for path in [b"".as_slice(), b"/x", b"x//y", b"x/../y", b"x/.", b"x/"] {
            assert_eq!(encode_key(&prefix, path), Err(KeyError::Path));
        }
        for byte in 1..=255_u8 {
            if byte != b'/' && byte != b'.' {
                assert_eq!(decode_rel(&prefix, &encode_key(&prefix, &[byte])?)?, [byte]);
            }
        }
        assert!(encode_key(&prefix, &vec![b'x'; 1024]).is_err());
        assert!(decode_rel(&prefix, b"archive/v1/%61.gz").is_err());
        Ok(())
    }
}
