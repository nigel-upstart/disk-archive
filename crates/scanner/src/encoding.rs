//! Conservative, bounded preflight, not decoded-offset redaction. Only the same
//! native catalog can confirm a decoded secret. No decoded value leaves this module.
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use kingfisher_vectorscan::BlockScanner;
use zeroize::{Zeroize, Zeroizing};

use crate::{ScanError, Scanner};

const CARRIER_BYTES: usize = 1024 * 1024;
const DECODE_BYTES: usize = 64 * 1024 * 1024;
const CANDIDATES: usize = 1_048_576;
const DEPTH: usize = 4;

pub(crate) struct Preflight<'a> {
    scanner: &'a Scanner,
    native: BlockScanner<'a>,
    record: Zeroizing<Vec<u8>>,
    used: usize,
    line_start: usize,
    utf16_carrier: bool,
    budget: Budget,
}

impl<'a> Preflight<'a> {
    pub(crate) fn new(scanner: &'a Scanner) -> Result<Self, ScanError> {
        Ok(Self {
            scanner,
            native: BlockScanner::new(scanner.database.vectorscan_db())
                .map_err(|_| ScanError::Engine)?,
            record: Zeroizing::new(vec![0; CARRIER_BYTES]),
            used: 0,
            line_start: 0,
            utf16_carrier: false,
            budget: Budget::default(),
        })
    }

    pub(crate) fn advance(&mut self, bytes: &[u8]) -> Result<(), ScanError> {
        for &byte in bytes {
            // Physical LF is not a decoded record boundary in UTF16LE/BE. Keep
            // the bounded NUL-bearing carrier together, including multiple lines.
            // An excessive carrier blocks; it is never truncated and certified.
            self.utf16_carrier |= byte == 0;
            *self.record.get_mut(self.used).ok_or(ScanError::Budget)? = byte;
            self.used += 1;
            if byte == b'\n' && !self.utf16_carrier {
                let line = self
                    .record
                    .get(self.line_start..self.used)
                    .ok_or(ScanError::Budget)?;
                let base64_line = line.iter().any(|byte| is_base64(*byte))
                    && line
                        .iter()
                        .all(|byte| is_base64(*byte) || b"=\r\n".contains(byte));
                if base64_line {
                    // Check each physical line AND the bounded joined run.
                    // Independent unpadded carriers must not shift one another;
                    // tiny wraps must not split a recoverable secret away.
                    inspect(self.scanner, &mut self.native, line, 0, &mut self.budget)?;
                    let padded_end =
                        line.iter().rev().find(|byte| !b"\r\n".contains(byte)) == Some(&b'=');
                    self.line_start = self.used;
                    if padded_end {
                        self.inspect_record()?;
                    }
                } else {
                    self.inspect_record()?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<(), ScanError> {
        self.inspect_record()
    }

    fn inspect_record(&mut self) -> Result<(), ScanError> {
        // Line and joined-run checks share one budget for this bounded carrier,
        // not a lifetime file counter. Ambiguous overlong base64 runs block.
        inspect(
            self.scanner,
            &mut self.native,
            self.record.get(..self.used).ok_or(ScanError::Budget)?,
            0,
            &mut self.budget,
        )?;
        self.record
            .get_mut(..self.used)
            .ok_or(ScanError::Budget)?
            .zeroize();
        self.used = 0;
        self.line_start = 0;
        self.budget = Budget::default();
        Ok(())
    }
}

#[derive(Default)]
struct Budget {
    bytes: usize,
    candidates: usize,
}

impl Budget {
    fn charge(&mut self, bytes: usize, depth: usize) -> Result<(), ScanError> {
        self.bytes = self.bytes.checked_add(bytes).ok_or(ScanError::Budget)?;
        self.candidates += 1;
        if self.bytes > DECODE_BYTES || self.candidates > CANDIDATES || depth >= DEPTH {
            return Err(ScanError::Budget);
        }
        Ok(())
    }
}

fn inspect(
    scanner: &Scanner,
    native: &mut BlockScanner<'_>,
    bytes: &[u8],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), ScanError> {
    if bytes.contains(&b'\\') || bytes.contains(&b'%') {
        for json in [true, false] {
            if (json && bytes.contains(&b'\\')) || (!json && bytes.contains(&b'%')) {
                budget.charge(bytes.len(), depth)?;
                let mut decoded = output(bytes.len());
                if unescape(bytes, json, &mut decoded)? {
                    check(scanner, native, &decoded, depth, budget)?;
                }
            }
        }
    }
    // NUL/BOM is a probe, not a finding. Try both byte orders and alignments;
    // prefixes and short read splits cannot hide an ASCII credential in UTF16.
    let utf16 = bytes.windows(2).any(|pair| {
        pair == [0xff, 0xfe]
            || pair == [0xfe, 0xff]
            || (pair.first() == Some(&0) && pair.get(1).is_some_and(u8::is_ascii_graphic))
            || (pair.get(1) == Some(&0) && pair.first().is_some_and(u8::is_ascii_graphic))
    });
    if utf16 {
        for little in [true, false] {
            for offset in [0, 1] {
                budget.charge(bytes.len(), depth)?;
                let mut decoded = output(bytes.len().saturating_mul(3) / 2);
                let pairs = bytes
                    .get(offset..)
                    .ok_or(ScanError::Budget)?
                    .as_chunks::<2>()
                    .0;
                let mut units = Zeroizing::new(vec![0_u16; pairs.len()]);
                for (unit, pair) in units.iter_mut().zip(pairs) {
                    *unit = if little {
                        u16::from_le_bytes(*pair)
                    } else {
                        u16::from_be_bytes(*pair)
                    };
                }
                for item in char::decode_utf16(units.iter().copied()) {
                    // Standard-library checked conversion; invalid units become
                    // separators, never a lossy deletion joining unrelated bytes.
                    let ch = item.unwrap_or(char::REPLACEMENT_CHARACTER);
                    let mut utf8 = Zeroizing::new([0; 4]);
                    append(&mut decoded, ch.encode_utf8(&mut *utf8).as_bytes())?;
                }
                check(scanner, native, &decoded, depth, budget)?;
            }
        }
    }
    inspect_base64(scanner, native, bytes, depth, budget)
}

fn inspect_base64(
    scanner: &Scanner,
    native: &mut BlockScanner<'_>,
    bytes: &[u8],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), ScanError> {
    let config = GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    let engine = GeneralPurpose::new(&alphabet::STANDARD, config);
    for candidate in bytes.split(|byte| !is_base64(*byte) && !b"\r\n".contains(byte)) {
        if candidate.len() < 8 {
            continue;
        }
        let mut canonical = output(candidate.len());
        for &byte in candidate {
            let byte = match byte {
                b'\r' | b'\n' => continue,
                b'-' => b'+',
                b'_' => b'/',
                _ => byte,
            };
            append(&mut canonical, &[byte])?;
        }
        // Four bounded alignment probes preserve payloads absorbed by an
        // identifier prefix, including mixed standard/URL-safe alphabets.
        for offset in 0..4 {
            let Some(candidate) = canonical.get(offset..).filter(|bytes| bytes.len() >= 8) else {
                continue;
            };
            // A suffix may leave one impossible trailing sextet. Omitting only
            // that sextet preserves all complete preceding credential bytes.
            let end = candidate.len() - usize::from(candidate.len() % 4 == 1);
            let candidate = candidate.get(..end).ok_or(ScanError::Budget)?;
            budget.charge(candidate.len(), depth)?;
            let mut decoded = output(candidate.len());
            // Fully initialized even on partial decoder errors; no reallocation.
            decoded.resize(candidate.len(), 0);
            if let Ok(used) = engine.decode_slice(candidate, &mut decoded) {
                decoded.get_mut(used..).ok_or(ScanError::Budget)?.zeroize();
                decoded.truncate(used);
                check(scanner, native, &decoded, depth, budget)?;
            }
        }
    }
    Ok(())
}

fn check(
    scanner: &Scanner,
    native: &mut BlockScanner<'_>,
    decoded: &[u8],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), ScanError> {
    if scanner.confirm_decoded(native, decoded)? {
        return Err(ScanError::UnsupportedEncoding);
    }
    inspect(scanner, native, decoded, depth + 1, budget)
}

fn output(capacity: usize) -> Zeroizing<Vec<u8>> {
    // Final capacity before any sensitive bytes are written. Each live decoded
    // level is <=1 MiB and nesting <=4; aggregate work has a separate 64 MiB cap.
    Zeroizing::new(Vec::with_capacity(capacity.min(CARRIER_BYTES)))
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ScanError> {
    let required = output.len().saturating_add(bytes.len());
    if required > CARRIER_BYTES || required > output.capacity() {
        return Err(ScanError::Budget);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn is_base64(byte: u8) -> bool {
    // Padding is not payload. Treat '=' as a separator so assignments/query
    // keys cannot absorb a carrier and make an internal-padding decode fail.
    // Indifferent padding mode also accepts the resulting unpadded payload.
    byte.is_ascii_alphanumeric() || b"+/-_".contains(&byte)
}

fn hex(byte: u8) -> Option<u32> {
    char::from(byte).to_digit(16)
}

fn unescape(input: &[u8], json: bool, output: &mut Vec<u8>) -> Result<bool, ScanError> {
    let mut at = 0;
    let mut changed = false;
    while let Some(&byte) = input.get(at) {
        if !json && byte == b'%' {
            if let Some(value) = input.get(at + 1..at + 3).and_then(|digits| {
                u8::try_from(hex(*digits.first()?)? * 16 + hex(*digits.get(1)?)?).ok()
            }) {
                append(output, &[value])?;
                changed = true;
                at += 3;
                continue;
            }
        } else if json && byte == b'\\' {
            if input.get(at + 1) == Some(&b'u') {
                if let Some(unit) = unicode_unit(input, at) {
                    let (scalar, used) = if (0xd800..=0xdbff).contains(&unit) {
                        let low =
                            unicode_unit(input, at + 6).ok_or(ScanError::UnsupportedEncoding)?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(ScanError::UnsupportedEncoding);
                        }
                        (0x10000 + ((unit - 0xd800) << 10) + low - 0xdc00, 12)
                    } else {
                        (unit, 6)
                    };
                    let ch = char::from_u32(scalar).ok_or(ScanError::UnsupportedEncoding)?;
                    let mut utf8 = Zeroizing::new([0; 4]);
                    append(output, ch.encode_utf8(&mut *utf8).as_bytes())?;
                    changed = true;
                    at += used;
                    continue;
                }
            } else if let Some(escaped) = input.get(at + 1).and_then(|byte| match byte {
                b'"' | b'\\' | b'/' => Some(*byte),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                b'b' => Some(8),
                b'f' => Some(12),
                _ => None,
            }) {
                append(output, &[escaped])?;
                changed = true;
                at += 2;
                continue;
            }
        }
        append(output, &[byte])?;
        at += 1;
    }
    Ok(changed)
}

fn unicode_unit(bytes: &[u8], at: usize) -> Option<u32> {
    if bytes.get(at..at + 2)? != b"\\u" {
        return None;
    }
    bytes
        .get(at + 2..at + 6)?
        .iter()
        .try_fold(0, |value, byte| Some(value * 16 + hex(*byte)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_work_budget_refuses_without_a_clean_result() {
        let mut byte_budget = Budget {
            bytes: DECODE_BYTES,
            candidates: 0,
        };
        assert_eq!(byte_budget.charge(1, 0), Err(ScanError::Budget));
        let mut candidate_budget = Budget {
            bytes: 0,
            candidates: CANDIDATES,
        };
        assert_eq!(candidate_budget.charge(1, 0), Err(ScanError::Budget));
        assert_eq!(Budget::default().charge(1, DEPTH), Err(ScanError::Budget));
    }

    #[test]
    fn initialized_partial_decode_and_tail_are_wipeable_on_error() -> Result<(), ScanError> {
        let engine = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::new());
        let mut decoded = Zeroizing::new(vec![0; 64]);
        // Valid groups followed by an invalid character exercise a decoder that
        // may already have written bytes before returning Err. Never log them.
        assert!(
            engine
                .decode_slice(b"c3ludGhldGljLXB1YmxpYy1vbmx5!!!!", &mut decoded)
                .is_err()
        );
        decoded.as_mut_slice().zeroize();
        assert!(decoded.iter().all(|byte| *byte == 0));
        let mut output = output(64);
        let original = output.capacity();
        assert!(unescape(br"%70%75%62%6c%69%63", false, &mut output)?);
        assert_eq!(output.capacity(), original);
        output.as_mut_slice().zeroize();
        assert!(output.iter().all(|byte| *byte == 0));
        assert_eq!(append(&mut output, &[0; 64]), Err(ScanError::Budget));
        Ok(())
    }
}
