//! Canonical versioned, injective encoding of home-relative Unix path bytes.

/// Invalid prefix, path, encoding, or S3 key length.
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPrefix(Vec<u8>);

fn valid_components(bytes: &[u8]) -> bool {
    !bytes.contains(&0)
        && bytes
            .split(|b| *b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
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
pub fn encode_key(prefix: &KeyPrefix, rel_path: &[u8]) -> Result<Vec<u8>, KeyError> {
    const HEX: &[u8] = b"0123456789ABCDEF";
    if !valid_components(rel_path) {
        return Err(KeyError::Path);
    }
    let mut out = prefix.0.clone();
    out.extend_from_slice(b"/v1/");
    for &byte in rel_path {
        if byte.is_ascii_alphanumeric() || b"-_./".contains(&byte) {
            out.push(byte);
        } else {
            out.push(b'%');
            // get() keeps this unproved reference implementation bounds-safe.
            if let (Some(&hi), Some(&lo)) = (
                HEX.get(usize::from(byte >> 4)),
                HEX.get(usize::from(byte & 15)),
            ) {
                out.extend_from_slice(&[hi, lo]);
            }
        }
        if out.len() > 1021 {
            return Err(KeyError::TooLong);
        }
    }
    out.extend_from_slice(b".gz");
    if out.len() > 1024 {
        return Err(KeyError::TooLong);
    }
    Ok(out)
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
