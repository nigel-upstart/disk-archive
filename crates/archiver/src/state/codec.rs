//! Compact, lossless metadata encodings, with legacy JSON-number-array reads.

pub(super) mod path {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        if bytes.len() > 4096 {
            return Err(S::Error::custom("pathname budget"));
        }
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(
                *HEX.get(usize::from(byte >> 4))
                    .ok_or_else(|| S::Error::custom("pathname encoding"))?,
            ));
            encoded.push(char::from(
                *HEX.get(usize::from(byte & 15))
                    .ok_or_else(|| S::Error::custom("pathname encoding"))?,
            ));
        }
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Hex(String),
            Legacy(Vec<u8>),
        }
        let bytes = match Wire::deserialize(deserializer)? {
            Wire::Legacy(bytes) => bytes,
            Wire::Hex(text) => {
                if text.len() > 8192 || text.len() % 2 != 0 {
                    return Err(D::Error::custom("pathname budget"));
                }
                text.as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| {
                        let value = std::str::from_utf8(pair)
                            .map_err(|_| D::Error::custom("pathname encoding"))?;
                        u8::from_str_radix(value, 16)
                            .map_err(|_| D::Error::custom("pathname encoding"))
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
        };
        if bytes.len() > 4096 {
            return Err(D::Error::custom("pathname budget"));
        }
        Ok(bytes)
    }
}

pub(super) mod expected {
    use serde::{
        Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _,
    };
    use serde_json::value::RawValue;

    // LINT-JUSTIFICATION: Serde's `with` hook receives &Option<Vec<u8>>; an Option<&Vec<u8>> signature breaks derived serialization.
    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let Some(bytes) = bytes else {
            return serializer.serialize_none();
        };
        if bytes.len() > super::super::MAX_RECORD {
            return Err(S::Error::custom("expectation budget"));
        }
        let text = String::from_utf8(bytes.clone())
            .map_err(|_| S::Error::custom("expectation encoding"))?;
        let raw =
            RawValue::from_string(text).map_err(|_| S::Error::custom("expectation encoding"))?;
        if !raw.get().starts_with('{') {
            return Err(S::Error::custom("expectation object required"));
        }
        Some(raw).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let Some(raw) = Option::<Box<RawValue>>::deserialize(deserializer)? else {
            return Ok(None);
        };
        let bytes = if raw.get().starts_with('[') {
            serde_json::from_str::<Vec<u8>>(raw.get())
                .map_err(|_| D::Error::custom("legacy expectation encoding"))?
        } else if raw.get().starts_with('{') {
            if raw.get().len() > super::super::MAX_RECORD {
                return Err(D::Error::custom("expectation budget"));
            }
            raw.get().as_bytes().to_vec()
        } else {
            return Err(D::Error::custom("expectation object required"));
        };
        if bytes.len() > super::super::MAX_RECORD {
            return Err(D::Error::custom("expectation budget"));
        }
        Ok(Some(bytes))
    }
}
