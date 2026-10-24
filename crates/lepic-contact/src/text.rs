//! Text carried in cards, invites and envelopes, checked once when it is built or read.

use std::fmt;

use crate::error::TextError;

pub const MAX_NAME_LEN: usize = 48;
pub const MAX_REFERENCE_LEN: usize = 64;
pub const MAX_MAILBOX_LEN: usize = 128;
pub const MAX_HOST_LEN: usize = 255;

/// Characters that would make text display differently from what it holds: bidirectional
/// formatting, line and paragraph separators and zero-width characters. The same list as the
/// wallet's labels, so a contact's name follows the label rule.
const HIDDEN_FORMATTING: [char; 19] = [
    '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{2028}', '\u{2029}', '\u{200B}', '\u{200C}',
    '\u{200D}', '\u{2060}', '\u{FEFF}',
];

fn is_hidden(c: char) -> bool {
    c.is_control() || HIDDEN_FORMATTING.contains(&c)
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

/// The name a card's owner chose: 1 to 48 bytes, no control or hidden formatting characters.
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
