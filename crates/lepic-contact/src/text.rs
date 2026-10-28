// SPDX-License-Identifier: Apache-2.0
//! Text carried in cards, invites and envelopes, checked once when it is built or read.

use std::fmt;

use crate::error::TextError;

pub const MAX_NAME_LEN: usize = 48;
pub const MAX_REFERENCE_LEN: usize = 64;
pub const MAX_MAILBOX_LEN: usize = 128;
pub const MAX_HOST_LEN: usize = 255;

/// The characters of general category Cf (format), which hold every bidirectional embedding,
/// override and isolate, as inclusive ranges in order. Generated from the Unicode 16.0 database
/// the pairing kit reads (`unicodedata.category(c) == "Cf"` or `unicodedata.bidirectional(c)` one
/// of LRE, LRO, RLE, RLO, PDF, LRI, RLI, FSI, PDI); category Cs needs no entry, since a `char` is
/// never a surrogate. Names and references must refuse exactly what the kit refuses, or a card one
/// side accepts fails to pair with the other.
const FORMAT_CHARACTERS: [(char, char); 21] = [
    ('\u{00AD}', '\u{00AD}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{06DD}', '\u{06DD}'),
    ('\u{070F}', '\u{070F}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08E2}', '\u{08E2}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{202A}', '\u{202E}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{110BD}', '\u{110BD}'),
    ('\u{110CD}', '\u{110CD}'),
    ('\u{13430}', '\u{1343F}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

fn is_format(c: char) -> bool {
    FORMAT_CHARACTERS
        .binary_search_by(|(first, last)| {
            if *last < c {
                std::cmp::Ordering::Less
            } else if *first > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Control and format characters, and the line and paragraph separators (categories Zl and Zp),
/// which break a name over lines when it is shown.
fn is_hidden(c: char) -> bool {
    c.is_control() || is_format(c) || matches!(c, '\u{2028}' | '\u{2029}')
}

fn displayable(text: &str, max: usize) -> Result<(), TextError> {
    if text.is_empty() || text.len() > max {
        return Err(TextError::Length {
            found: text.len(),
            max,
        });
    }
    match text.chars().position(is_hidden) {
        Some(position) => Err(TextError::HiddenCharacter { position }),
        None => Ok(()),
    }
}

/// Address text is printable ASCII without spaces; anything else is refused before a transport
/// parses it further.
fn address_text(text: &str, max: usize) -> Result<(), TextError> {
    if text.is_empty() || text.len() > max {
        return Err(TextError::Length {
            found: text.len(),
            max,
        });
    }
    match text.bytes().position(|byte| !byte.is_ascii_graphic()) {
        Some(position) => Err(TextError::AddressCharacter { position }),
        None => Ok(()),
    }
}

macro_rules! text_type {
    ($name:ident) => {
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = Option<TextError>;

            /// `None` when the bytes are not UTF-8.
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                let text = std::str::from_utf8(bytes).map_err(|_| None)?;
                Self::new(text).map_err(Some)
            }
        }
    };
}

/// The name a card's owner chose: 1 to 48 bytes, no control or format characters.
/// It is the owner's claim, not a verified identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactName(String);

impl ContactName {
    pub fn new(text: &str) -> Result<Self, TextError> {
        displayable(text, MAX_NAME_LEN)?;
        Ok(Self(text.to_owned()))
    }
}

text_type!(ContactName);

/// A service's own reference for a deposit or withdrawal: shown, never trusted for crediting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference(String);

impl Reference {
    pub fn new(text: &str) -> Result<Self, TextError> {
        displayable(text, MAX_REFERENCE_LEN)?;
        Ok(Self(text.to_owned()))
    }
}

text_type!(Reference);

/// Epicbox address text, `key@domain[:port]`. The Epicbox crate parses it fully before use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxAddress(String);

impl MailboxAddress {
    pub fn new(text: &str) -> Result<Self, TextError> {
        address_text(text, MAX_MAILBOX_LEN)?;
        match text.split_once('@') {
            Some((key, domain))
                if !key.is_empty() && !domain.is_empty() && !domain.contains('@') =>
            {
                Ok(Self(text.to_owned()))
            }
            _ => Err(TextError::AddressShape),
        }
    }
}

text_type!(MailboxAddress);

/// A relay host, `domain[:port]`, or an onion domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHost(String);

impl RelayHost {
    pub fn new(text: &str) -> Result<Self, TextError> {
        address_text(text, MAX_HOST_LEN)?;
        match text
            .bytes()
            .position(|byte| matches!(byte, b'@' | b'/' | b'?' | b'#'))
        {
            Some(position) => Err(TextError::AddressCharacter { position }),
            None => Ok(Self(text.to_owned())),
        }
    }
}

text_type!(RelayHost);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_label_rule() {
        for (name, position) in [
            ("a\u{202E}b", 1),
            ("\u{200B}ab", 0),
            ("ab\u{2068}", 2),
            ("a\u{FEFF}", 1),
            ("a\tb", 1),
            ("a\nb", 1),
            ("a\u{2028}b", 1),
            ("\u{2029}ab", 0),
        ] {
            assert_eq!(
                ContactName::new(name),
                Err(TextError::HiddenCharacter { position }),
                "{name:?}"
            );
        }
        assert!(ContactName::new("Café – Łódź 🐼").is_ok());
    }

    #[test]
    fn names_refuse_every_format_character() {
        for hidden in [
            '\u{00AD}',
            '\u{0600}',
            '\u{180E}',
            '\u{200B}',
            '\u{200E}',
            '\u{202A}',
            '\u{2061}',
            '\u{2064}',
            '\u{2066}',
            '\u{206A}',
            '\u{206F}',
            '\u{FEFF}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{1D173}',
            '\u{E0001}',
            '\u{E0020}',
            '\u{E007F}',
            '\u{0085}',
            '\u{009F}',
        ] {
            let name = format!("a{hidden}b");
            assert_eq!(
                ContactName::new(&name),
                Err(TextError::HiddenCharacter { position: 1 }),
                "{:04X}",
                u32::from(hidden)
            );
            assert!(Reference::new(&name).is_err());
        }
        for shown in [
            '\u{00AC}',
            '\u{00AE}',
            '\u{2065}',
            '\u{FFFC}',
            '\u{E0000}',
            '\u{E0080}',
        ] {
            assert!(
                ContactName::new(&format!("a{shown}b")).is_ok(),
                "{:04X}",
                u32::from(shown)
            );
        }
    }

    #[test]
    fn format_table_is_ordered_and_disjoint() {
        for pair in FORMAT_CHARACTERS.windows(2) {
            let ((first, last), (next, _)) = (pair[0], pair[1]);
            let after = u32::from(last).checked_add(1).unwrap();
            assert!(first <= last && after < u32::from(next), "{pair:?}");
        }
    }

    #[test]
    fn names_are_one_to_48_bytes() {
        assert_eq!(
            ContactName::new(""),
            Err(TextError::Length { found: 0, max: 48 })
        );
        assert!(ContactName::new(&"a".repeat(48)).is_ok());
        assert_eq!(
            ContactName::new(&"a".repeat(49)),
            Err(TextError::Length { found: 49, max: 48 })
        );
        // 16 three-byte characters are 48 bytes; one more is over.
        assert!(ContactName::new(&"€".repeat(16)).is_ok());
        assert!(ContactName::new(&"€".repeat(17)).is_err());
    }

    #[test]
    fn mailbox_needs_key_at_domain() {
        assert!(MailboxAddress::new("es5abc@epicbox.example.org:443").is_ok());
        for bad in ["nodomain", "@domain", "key@", "a@b@c"] {
            assert_eq!(
                MailboxAddress::new(bad),
                Err(TextError::AddressShape),
                "{bad}"
            );
        }
        assert_eq!(
            MailboxAddress::new("a b@c"),
            Err(TextError::AddressCharacter { position: 1 })
        );
    }

    #[test]
    fn hosts_refuse_url_parts() {
        assert!(RelayHost::new("epicbox.example.org:443").is_ok());
        assert!(RelayHost::new("relay.example.org/path").is_err());
        assert!(RelayHost::new("user@relay").is_err());
    }
}
