//! Bounded counting of actual body data; AWS chunk headers/trailers are not payload.
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireError;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Size,
    Data(u64),
    DataCr,
    DataLf,
    Trailers,
    Done,
}

pub(crate) struct Payload {
    aws_chunked: bool,
    phase: Phase,
    line: Zeroizing<Vec<u8>>,
    trailer_bytes: usize,
    total: u64,
    declared: Option<u64>,
}

impl Payload {
    pub(crate) fn new(aws_chunked: bool, declared: Option<u64>) -> Self {
        Self {
            aws_chunked,
            phase: Phase::Size,
            line: Zeroizing::new(Vec::with_capacity(1024)),
            trailer_bytes: 0,
            total: 0,
            declared,
        }
    }

    pub(crate) fn consume(
        &mut self,
        bytes: &[u8],
        mut count: impl FnMut(u64) -> Result<(), WireError>,
    ) -> Result<(), WireError> {
        if !self.aws_chunked {
            return self.payload(bytes.len(), &mut count);
        }
        let mut at = 0;
        while let Some(&byte) = bytes.get(at) {
            match self.phase {
                Phase::Data(remaining) => {
                    let n = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len() - at);
                    self.payload(n, &mut count)?;
                    at += n;
                    let left = remaining - u64::try_from(n).map_err(|_| WireError)?;
                    self.phase = if left == 0 {
                        Phase::DataCr
                    } else {
                        Phase::Data(left)
                    };
                }
                Phase::DataCr | Phase::DataLf => {
                    let cr = self.phase == Phase::DataCr;
                    if byte != if cr { b'\r' } else { b'\n' } {
                        return Err(WireError);
                    }
                    self.phase = if cr { Phase::DataLf } else { Phase::Size };
                    at += 1;
                }
                Phase::Size | Phase::Trailers => {
                    if self.line.len() >= 1024 {
                        return Err(WireError);
                    }
                    self.line.push(byte);
                    at += 1;
                    if byte == b'\n' {
                        self.finish_line()?;
                    }
                }
                Phase::Done => return Err(WireError),
            }
        }
        Ok(())
    }

    fn payload(
        &mut self,
        bytes: usize,
        count: &mut impl FnMut(u64) -> Result<(), WireError>,
    ) -> Result<(), WireError> {
        let bytes = u64::try_from(bytes).map_err(|_| WireError)?;
        self.total = self.total.checked_add(bytes).ok_or(WireError)?;
        count(bytes)
    }

    fn finish_line(&mut self) -> Result<(), WireError> {
        if !self.line.ends_with(b"\r\n") {
            return Err(WireError);
        }
        let text = self.line.get(..self.line.len() - 2).ok_or(WireError)?;
        if self.phase == Phase::Size {
            let digits = text.split(|byte| *byte == b';').next().ok_or(WireError)?;
            if digits.is_empty() || digits.len() > 16 {
                return Err(WireError);
            }
            let size = digits
                .iter()
                .try_fold(0_u64, |value, byte| {
                    value
                        .checked_mul(16)?
                        .checked_add(u64::from(char::from(*byte).to_digit(16)?))
                })
                .ok_or(WireError)?;
            self.phase = if size == 0 {
                Phase::Trailers
            } else {
                Phase::Data(size)
            };
        } else {
            self.trailer_bytes = self
                .trailer_bytes
                .checked_add(self.line.len())
                .ok_or(WireError)?;
            if self.trailer_bytes > 65_536 || (!text.is_empty() && !text.contains(&b':')) {
                return Err(WireError);
            }
            if text.is_empty() {
                self.phase = Phase::Done;
            }
        }
        self.line.as_mut_slice().zeroize();
        self.line.clear();
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<(), WireError> {
        if (self.aws_chunked && self.phase != Phase::Done)
            || self.declared.is_some_and(|size| size != self.total)
        {
            return Err(WireError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_frames_and_aws_chunk_fragments_count_only_actual_payload() -> Result<(), WireError> {
        let encoded = b"3;chunk-signature=synthetic\r\nabc\r\n2\r\nde\r\n0\r\nx-amz-checksum-crc64nvme: synthetic\r\n\r\n";
        for width in 1..=encoded.len() {
            let mut parser = Payload::new(true, Some(5));
            let mut observed = 0;
            for frame in encoded.chunks(width) {
                parser.consume(frame, |n| {
                    observed += n;
                    Ok(())
                })?;
            }
            parser.finish()?;
            assert_eq!(observed, 5);
        }
        let mut parser = Payload::new(false, Some(4));
        let mut observed = 0;
        parser.consume(&[0, 255, 1, 2], |n| {
            observed += n;
            Ok(())
        })?;
        parser.finish()?;
        assert_eq!(observed, 4);
        Ok(())
    }

    #[test]
    fn invalid_partial_and_oversize_frames_never_certify_a_count() {
        for input in [
            &b"3\nabc\r\n0\r\n\r\n"[..],
            &b"3\r\nabcXX0\r\n\r\n"[..],
            &b"0\r\nnot-a-trailer\r\n\r\n"[..],
            &b"0\r\n\r\nextra"[..],
            &b"10000000000000000\r\n"[..],
            &b"3\r\nab"[..],
        ] {
            let mut parser = Payload::new(true, None);
            let parsed = parser
                .consume(input, |_| Ok(()))
                .and_then(|()| parser.finish());
            assert_eq!(parsed, Err(WireError));
        }
        let mut parser = Payload::new(true, None);
        assert_eq!(
            parser.consume(&vec![b'f'; 1025], |_| Ok(())),
            Err(WireError)
        );
        let mut parser = Payload::new(false, Some(5));
        assert!(parser.consume(b"four", |_| Ok(())).is_ok());
        assert_eq!(parser.finish(), Err(WireError));
        let mut parser = Payload::new(false, None);
        assert_eq!(
            parser.consume(b"public", |_| Err(WireError)),
            Err(WireError)
        );
    }
}
