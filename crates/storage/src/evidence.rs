//! Durable expectations and strict independent remote-evidence validation.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use disk_archive_verified::{age::Timestamp, lifecycle};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{SourceIdentity, StoreError, VerifiedUpload};

#[derive(Serialize, Deserialize)]
#[serde(remote = "Timestamp")]
struct TimestampRecord {
    secs: i64,
    nanos: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "SourceIdentity")]
struct SourceRecord {
    dev: u64,
    ino: u64,
    size: u64,
    #[serde(with = "TimestampRecord")]
    mtime: Timestamp,
    #[serde(with = "TimestampRecord")]
    ctime: Timestamp,
    sha256: [u8; 32],
}

/// One ordered multipart SHA256 digest and exact logical part length.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartDigest {
    /// Part bytes, not original uncompressed bytes.
    pub size: u64,
    /// SHA256 of this part's bytes.
    pub sha256: [u8; 32],
}

/// Expected S3 checksum semantics; full gzip SHA256 metadata is separate.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algorithm", rename_all = "snake_case", deny_unknown_fields)]
pub enum Integrity {
    /// Full-object CRC64/NVME for either single PUT or multipart.
    Crc64Nvme {
        /// Big-endian CRC bytes, encoded as base64 on the wire.
        value: [u8; 8],
    },
    /// Full-object SHA256 for single PUT only.
    Sha256 {
        /// Whole-object SHA256 digest.
        value: [u8; 32],
    },
    /// S3 multipart SHA256 composite, never whole-object SHA256.
    Sha256Composite {
        /// Planned fixed part size; object limits must prevent TM geometry adjustment.
        part_size: u64,
        /// Ordered exact part digests, persisted before upload for restart validation.
        parts: Vec<PartDigest>,
    },
}

impl Integrity {
    /// Canonical wire checksum including the multipart part-count suffix when applicable.
    #[must_use]
    pub fn wire_value(&self) -> String {
        match self {
            Self::Crc64Nvme { value } => STANDARD.encode(value),
            Self::Sha256 { value } => STANDARD.encode(value),
            Self::Sha256Composite { parts, .. } => {
                let mut sha = Sha256::new();
                for part in parts {
                    sha.update(part.sha256);
                }
                format!("{}-{}", STANDARD.encode(sha.finalize()), parts.len())
            }
        }
    }

    /// Exact S3 checksum type expected from HEAD.
    #[must_use]
    pub const fn checksum_type(&self) -> &'static str {
        match self {
            Self::Sha256Composite { .. } => "COMPOSITE",
            _ => "FULL_OBJECT",
        }
    }

    /// Exact S3 algorithm identifier expected from HEAD.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        match self {
            Self::Crc64Nvme { .. } => "CRC64NVME",
            _ => "SHA256",
        }
    }
}

/// Bounded, serializable expected evidence. Never a serializable deletion capability.
/// G persists this BEFORE starting any network upload and treats its provenance as trusted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedUpload {
    /// Persisted record schema; currently exactly 1.
    pub schema_version: u32,
    /// Required configured bucket, bound again by the store on restart.
    pub bucket: String,
    /// Canonical kernel-generated archive key (UTF8 ASCII percent encoding).
    pub key: String,
    /// Source snapshot after successful redaction/rescan; never path-only identity.
    #[serde(with = "SourceRecord")]
    pub source: SourceIdentity,
    /// Exact gzip object size.
    pub gzip_size: u64,
    /// SHA256 of all gzip bytes, independent of S3 composite checksums.
    pub gzip_sha256: [u8; 32],
    /// Independently computed expected S3 checksum and multipart geometry.
    pub integrity: Integrity,
    /// Optional version returned by a prior successful upload, pinned on re-verification.
    pub version_id: Option<String>,
    /// Optional `ETag` selector, not a content hash, for a prior successful receipt.
    pub etag: Option<String>,
}

impl ExpectedUpload {
    /// Validate durable schema, sizes and composite geometry before network use.
    ///
    /// # Errors
    /// Rejects malformed source timestamps, destination, sizes, geometry or selectors.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.schema_version != 1
            || self.bucket.is_empty()
            || self.bucket.len() > 63
            || self.bucket.chars().any(char::is_control)
            || !valid_key(&self.key)
            || self.gzip_size > i64::MAX.unsigned_abs()
            || !self.source.mtime.is_valid()
            || !self.source.ctime.is_valid()
            || [&self.version_id, &self.etag]
                .into_iter()
                .flatten()
                .any(|s| s.is_empty() || s.len() > 1024 || s.chars().any(char::is_control))
        {
            return Err(StoreError::Configuration);
        }
        match &self.integrity {
            Integrity::Sha256 { value } if *value != self.gzip_sha256 => {
                return Err(StoreError::Configuration);
            }
            Integrity::Sha256Composite { part_size, parts } => {
                if !(5_242_880..=5_368_709_120).contains(part_size)
                    || parts.is_empty()
                    || parts.len() > 10_000
                {
                    return Err(StoreError::Configuration);
                }
                let mut total = 0_u64;
                for (index, part) in parts.iter().enumerate() {
                    if part.size == 0
                        || part.size > *part_size
                        || (index + 1 < parts.len() && part.size != *part_size)
                    {
                        return Err(StoreError::Configuration);
                    }
                    total = total
                        .checked_add(part.size)
                        .ok_or(StoreError::Configuration)?;
                }
                if total != self.gzip_size {
                    return Err(StoreError::Configuration);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Serialize bounded durable expectations, never source contents or findings.
    ///
    /// # Errors
    /// Invalid evidence or an unexpectedly large record fails closed.
    pub fn to_record(&self) -> Result<Vec<u8>, StoreError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| StoreError::Configuration)?;
        if bytes.len() > 2_097_152 {
            return Err(StoreError::Budget);
        }
        Ok(bytes)
    }

    /// Parse only a bounded, validated record. This does NOT grant authority.
    ///
    /// # Errors
    /// Malformed, oversized, unknown-schema or invalid records are rejected.
    pub fn from_record(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > 2_097_152 {
            return Err(StoreError::Budget);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| StoreError::Configuration)?;
        value.validate()?;
        Ok(value)
    }

    /// Canonical metadata values sent before upload initiation.
    #[must_use]
    pub fn metadata(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("sha256".into(), hex(&self.gzip_sha256)),
            ("orig-size".into(), self.source.size.to_string()),
            ("orig-sha256".into(), hex(&self.source.sha256)),
        ])
    }
}

/// Parsed HEAD facts from one request-bound bucket/key/version. No Debug/raw SDK errors.
pub struct HeadEvidence {
    /// Configured bucket used for this exact request.
    pub bucket: String,
    /// Exact key used for this request (S3 HEAD does not echo it).
    pub key: String,
    /// Content-Length, absent/negative wire values rejected by adapter.
    pub content_length: Option<u64>,
    /// Response SSE algorithm, required exactly AES256.
    pub encryption: Option<String>,
    /// Response checksum type, required and not inferred.
    pub checksum_type: Option<String>,
    /// Response checksum algorithm, required and not inferred from metadata.
    pub checksum_algorithm: Option<String>,
    /// Actual additional checksum from the response, not a user metadata field.
    pub checksum_value: Option<String>,
    /// S3 user metadata; only expected non-secret archive evidence is accepted for authority.
    pub metadata: BTreeMap<String, String>,
    /// Response version identifier.
    pub version_id: Option<String>,
    /// Response `ETag` selector, never used as a content checksum.
    pub etag: Option<String>,
}

/// Validate independent checksum, exact metadata and selectors, then call the real kernel.
/// Caller binds the response to an authenticated S3 request and exclusive object namespace.
/// CRC64NVME integrity relies on the trusted S3 checksum/TLS adapter, not collision resistance.
///
/// # Errors
/// Any missing/mismatching checksum type/value, metadata, length, encryption or selector denies authority.
pub fn verify(
    expected: &ExpectedUpload,
    head: &HeadEvidence,
) -> Result<VerifiedUpload, StoreError> {
    expected.validate()?;
    if expected.bucket != head.bucket
        || expected.key != head.key
        || head.content_length != Some(expected.gzip_size)
        || head.encryption.as_deref() != Some("AES256")
        || expected
            .metadata()
            .iter()
            .any(|(k, v)| head.metadata.get(k) != Some(v))
        || expected
            .version_id
            .as_ref()
            .is_some_and(|v| head.version_id.as_ref() != Some(v))
        || expected
            .etag
            .as_ref()
            .is_some_and(|v| head.etag.as_ref() != Some(v))
    {
        return Err(StoreError::Integrity);
    }
    let remote = project_remote(head, &expected.integrity)?;
    lifecycle::verify_upload(
        &lifecycle::UploadExpectation {
            source: expected.source,
            key: expected.key.as_bytes().to_vec(),
            compressed_size: expected.gzip_size,
            compressed_sha256: expected.gzip_sha256,
        },
        &remote,
    )
    .map_err(|_| StoreError::Integrity)
}

// This projection deliberately has no upload expectation to copy remote fields from.
// The checksum gate is independent of user metadata. Binding that metadata to the
// same object's bytes still trusts the S3/TLS adapter and exclusive namespace;
// neither CRC nor multipart composite SHA proves a whole-object SHA256 digest.
fn project_remote(
    head: &HeadEvidence,
    integrity: &Integrity,
) -> Result<lifecycle::RemoteEvidence, StoreError> {
    if head.checksum_type.as_deref() != Some(integrity.checksum_type())
        || head.checksum_algorithm.as_deref() != Some(integrity.algorithm())
        || head.checksum_value.as_deref() != Some(integrity.wire_value().as_str())
    {
        return Err(StoreError::Integrity);
    }
    let size = head
        .metadata
        .get("orig-size")
        .ok_or(StoreError::Integrity)?;
    // Canonical unsigned decimal only: no whitespace, sign or leading zeroes.
    if size.is_empty()
        || !size.bytes().all(|b| b.is_ascii_digit())
        || (size.len() > 1 && size.starts_with('0'))
    {
        return Err(StoreError::Integrity);
    }
    Ok(lifecycle::RemoteEvidence {
        key: head.key.as_bytes().to_vec(),
        content_length: head.content_length.ok_or(StoreError::Integrity)?,
        gz_sha256: metadata_sha(head, "sha256")?,
        orig_size: size.parse().map_err(|_| StoreError::Integrity)?,
        orig_sha256: metadata_sha(head, "orig-sha256")?,
        sse_aes256: head.encryption.as_deref() == Some("AES256"),
    })
}

fn metadata_sha(head: &HeadEvidence, key: &str) -> Result<[u8; 32], StoreError> {
    let value = head.metadata.get(key).ok_or(StoreError::Integrity)?;
    let mut decoded = [0_u8; 32];
    if value.len() != 64 {
        return Err(StoreError::Integrity);
    }
    for (out, pair) in decoded.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let mut byte = 0_u8;
        for digit in pair {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                _ => return Err(StoreError::Integrity),
            };
            byte = (byte << 4) | nibble;
        }
        *out = byte;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests;

pub(crate) fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 1024 && !key.chars().any(char::is_control)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
                HEX.get(usize::from(b & 15)).copied().unwrap_or(b'0'),
            ]
        })
        .map(char::from)
        .collect()
}
