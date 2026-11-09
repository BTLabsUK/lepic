// SPDX-License-Identifier: Apache-2.0
//! The field list shared by envelope content, cards and invites: `tag (u8) || length (u16) ||
//! value`, tags strictly increasing, unknown tags below 0x80 refused and from 0x80 up skipped,
//! the signature (when the format has one) last.

use crate::error::{DecodeError, EncodeError, Malformed};

/// Tags from here up are optional extensions a reader skips.
const FIRST_IGNORED_TAG: u8 = 0x80;

/// Known tags of every format fit below this.
const KNOWN_TAG_SLOTS: usize = 16;

/// How many extensions a list keeps for its reader; any after them are skipped unread.
const EXTENSION_SLOTS: usize = 8;

/// The fields of one decoded list, borrowed from the input.
pub struct Fields<'a> {
    values: [Option<&'a [u8]>; KNOWN_TAG_SLOTS],
    /// The first extension fields, from 0x80 up, that a reader may know, in tag order.
    extensions: [Option<(u8, &'a [u8])>; EXTENSION_SLOTS],
    signature: Option<&'a [u8]>,
    /// The encoded bytes before the signature field: what the signature covers.
    signed_prefix: &'a [u8],
}

impl<'a> Fields<'a> {
    /// Splits `bytes` into fields. `last_known` is the highest non-signature tag of the format
    /// below 0x80; `signature` is its signature tag, which must then be the last field when
    /// present.
    pub fn parse(
        bytes: &'a [u8],
        last_known: u8,
        signature: Option<u8>,
    ) -> Result<Self, DecodeError> {
        let mut values = [None; KNOWN_TAG_SLOTS];
        let mut signature_value = None;
        let mut extensions = [None; EXTENSION_SLOTS];
        let mut signed_prefix = bytes;
        let mut previous: Option<u8> = None;
        let mut rest = bytes;
        while let [tag, high, low, tail @ ..] = rest {
            let tag = *tag;
            if previous.is_some_and(|previous| tag <= previous) {
                return Err(Malformed::FieldOrder { tag }.into());
            }
            if previous.is_some() && previous == signature {
                return Err(Malformed::FieldAfterSignature.into());
            }
            let length = usize::from(u16::from_be_bytes([*high, *low]));
            let (value, tail) = tail.split_at_checked(length).ok_or(Malformed::Truncated)?;
            if Some(tag) == signature {
                let consumed = bytes.len().saturating_sub(rest.len());
                signed_prefix = bytes.get(..consumed).ok_or(Malformed::Truncated)?;
                signature_value = Some(value);
            } else if tag < FIRST_IGNORED_TAG {
                if tag == 0 || tag > last_known {
                    return Err(Malformed::UnknownField { tag }.into());
                }
                let slot = values
                    .get_mut(usize::from(tag))
                    .ok_or(Malformed::UnknownField { tag })?;
                *slot = Some(value);
            } else if let Some(slot) = extensions.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some((tag, value));
            }
            previous = Some(tag);
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(Malformed::Truncated.into());
        }
        Ok(Self {
            values,
            extensions,
            signature: signature_value,
            signed_prefix,
        })
    }

    pub fn get(&self, tag: u8) -> Option<&'a [u8]> {
        self.values.get(usize::from(tag)).copied().flatten()
    }

    pub fn require(&self, tag: u8) -> Result<&'a [u8], DecodeError> {
        self.get(tag)
            .ok_or_else(|| Malformed::MissingField { tag }.into())
    }

    /// The value of extension `tag`, from 0x80 up, when it is among the list's first
    /// extensions.
    pub fn extension(&self, tag: u8) -> Option<&'a [u8]> {
        self.extensions
            .iter()
            .flatten()
            .find(|(found, _)| *found == tag)
            .map(|(_, value)| *value)
    }

    /// The value of the signature field, when the list has one.
    pub fn signature(&self) -> Option<&'a [u8]> {
        self.signature
    }

    pub fn signed_prefix(&self) -> &'a [u8] {
        self.signed_prefix
    }

    pub fn require_array<const N: usize>(&self, tag: u8) -> Result<[u8; N], DecodeError> {
        array(tag, self.require(tag)?)
    }

    pub fn optional_array<const N: usize>(&self, tag: u8) -> Result<Option<[u8; N]>, DecodeError> {
        self.get(tag).map(|value| array(tag, value)).transpose()
    }

    pub fn require_u8(&self, tag: u8) -> Result<u8, DecodeError> {
        let [byte] = self.require_array::<1>(tag)?;
        Ok(byte)
    }

    pub fn require_u16(&self, tag: u8) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.require_array(tag)?))
    }

    pub fn require_u32(&self, tag: u8) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.require_array(tag)?))
    }

    pub fn require_u64(&self, tag: u8) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.require_array(tag)?))
    }

    pub fn optional_u8(&self, tag: u8) -> Result<Option<u8>, DecodeError> {
        Ok(self.optional_array::<1>(tag)?.map(|[byte]| byte))
    }

    pub fn optional_u64(&self, tag: u8) -> Result<Option<u64>, DecodeError> {
        Ok(self.optional_array(tag)?.map(u64::from_be_bytes))
    }
}

/// Refuses a list whose first field is a format byte above `known`, before the list is parsed:
/// a newer format may use tags this reader would reject as unknown.
pub fn check_format(bytes: &[u8], format_tag: u8, known: u8) -> Result<(), DecodeError> {
    match bytes {
        [tag, 0, 1, format, ..] if *tag == format_tag && *format > known => {
            Err(DecodeError::NewerVersion { found: *format })
        }
        [tag, 0, 1, format, ..] if *tag == format_tag && *format != known => {
            Err(Malformed::Version { found: *format }.into())
        }
        _ => Ok(()),
    }
}

fn array<const N: usize>(tag: u8, value: &[u8]) -> Result<[u8; N], DecodeError> {
    <[u8; N]>::try_from(value).map_err(|_| Malformed::FieldLength { tag }.into())
}

/// Builds a field list; the caller adds fields in increasing tag order.
#[derive(Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), EncodeError> {
        let length = u16::try_from(value.len()).map_err(|_| EncodeError::FieldTooLong { tag })?;
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub fn optional(&mut self, tag: u8, value: Option<&[u8]>) -> Result<(), EncodeError> {
        match value {
            Some(value) => self.field(tag, value),
            None => Ok(()),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> Result<Fields<'_>, DecodeError> {
        Fields::parse(bytes, 0x08, Some(0xff))
    }

    #[test]
    fn reads_known_fields_and_skips_high_tags() {
        let fields = parse(&[0x01, 0, 1, 7, 0x80, 0, 2, 1, 2, 0x81, 0, 0]).unwrap();
        assert_eq!(fields.get(0x01), Some(&[7][..]));
        assert_eq!(fields.get(0x02), None);
    }

    #[test]
    fn reads_every_extension_not_only_the_first() {
        let fields = parse(&[0x01, 0, 1, 7, 0x80, 0, 1, 1, 0x81, 0, 1, 2, 0x82, 0, 1, 3]).unwrap();
        assert_eq!(fields.extension(0x80), Some(&[1][..]));
        assert_eq!(fields.extension(0x81), Some(&[2][..]));
        assert_eq!(fields.extension(0x82), Some(&[3][..]));
        assert_eq!(fields.extension(0x83), None);
    }

    #[test]
    fn rejects_repeated_or_decreasing_tags() {
        assert_eq!(
            parse(&[0x02, 0, 0, 0x02, 0, 0]).err(),
            Some(Malformed::FieldOrder { tag: 0x02 }.into())
        );
        assert_eq!(
            parse(&[0x02, 0, 0, 0x01, 0, 0]).err(),
            Some(Malformed::FieldOrder { tag: 0x01 }.into())
        );
    }

    #[test]
    fn rejects_unknown_low_tags() {
        assert_eq!(
            parse(&[0x09, 0, 0]).err(),
            Some(Malformed::UnknownField { tag: 0x09 }.into())
        );
        assert_eq!(
            parse(&[0x00, 0, 0]).err(),
            Some(Malformed::UnknownField { tag: 0x00 }.into())
        );
    }

    #[test]
    fn nothing_follows_the_last_tag() {
        assert_eq!(
            parse(&[0xff, 0, 0, 0xff, 0, 0]).err(),
            Some(Malformed::FieldOrder { tag: 0xff }.into())
        );
    }

    #[test]
    fn rejects_truncated_lengths_and_headers() {
        assert_eq!(
            parse(&[0x01, 0, 2, 7]).err(),
            Some(Malformed::Truncated.into())
        );
        assert_eq!(parse(&[0x01, 0]).err(), Some(Malformed::Truncated.into()));
    }

    #[test]
    fn the_signed_prefix_ends_before_the_signature() {
        let bytes = [0x01, 0, 1, 7, 0x90, 0, 1, 8, 0xff, 0, 1, 9];
        let fields = parse(&bytes).unwrap();
        assert_eq!(fields.signed_prefix(), &bytes[..8]);
        assert_eq!(fields.signature(), Some(&[9][..]));
    }
}
