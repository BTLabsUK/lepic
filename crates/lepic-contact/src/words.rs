//! Pairing words (RFC 0002 7.7): five SAS-table entries that find and open an invite posted to a
//! rendezvous mailbox, for when there is nothing to scan or paste.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{SasTableError, WordsError};
use crate::hash::hmac_sha256;
use crate::invite::Invite;
use crate::network::Network;
use crate::sas::{SasSymbol, symbol};

pub const WORD_COUNT: usize = 5;
/// The longest posted text that is opened; an invite is far shorter.
pub const MAX_POSTED_LEN: usize = 4096;

const DOMAIN: &[u8] = b"epic-pair/1 words";
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_LANES: u32 = 1;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const NONCE: [u8; 12] = [0; 12];

/// Five random bytes, each an index into the SAS table. Wiped on drop and never printed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairingWords([u8; WORD_COUNT]);

impl PairingWords {
    pub fn from_bytes(bytes: [u8; WORD_COUNT]) -> Self {
        Self(bytes)
    }

    pub fn expose_bytes(&self) -> &[u8; WORD_COUNT] {
        &self.0
    }

    /// The five entries shown to the user.
    pub fn symbols(&self) -> Result<[SasSymbol; WORD_COUNT], SasTableError> {
        let [a, b, c, d, e] = self.0;
        Ok([symbol(a)?, symbol(b)?, symbol(c)?, symbol(d)?, symbol(e)?])
    }

    /// The words the user typed: each a table name in any case, or its emoji.
    pub fn parse<S: AsRef<str>>(typed: &[S]) -> Result<Self, WordsError> {
        let [a, b, c, d, e] = typed else {
            return Err(WordsError::Unknown);
        };
        Ok(Self([
            parse_word(a.as_ref())?,
            parse_word(b.as_ref())?,
            parse_word(c.as_ref())?,
            parse_word(d.as_ref())?,
            parse_word(e.as_ref())?,
        ]))
    }

    /// `k = Argon2id(words, salt = "epic-pair/1 words" || net, t = 3, m = 64 MiB, p = 1)`.
    pub fn stretch(&self, network: Network) -> Result<WordsKey, WordsError> {
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_LANES,
            Some(KEY_LEN),
        )
        .map_err(|_| WordsError::Derivation)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(&self.0, &aad(network), key.as_mut_slice())
            .map_err(|_| WordsError::Derivation)?;
        Ok(WordsKey(key))
    }
}

impl fmt::Debug for PairingWords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingWords(<redacted>)")
    }
}

fn parse_word(typed: &str) -> Result<u8, WordsError> {
    let name = fold(typed);
    let emoji = typed.trim_matches(is_space);
    (0..=u8::MAX)
        .find(|index| symbol(*index).is_ok_and(|entry| entry.name == name || entry.emoji == emoji))
        .ok_or(WordsError::Unknown)
}

/// Whitespace as Python's `str.strip` sees it, which the kit's reading (NFC, strip, casefold)
/// uses: Unicode `White_Space` plus the four information separators.
fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// The typed name folded so it equals a table name exactly when NFC, strip and full case folding
/// of it would. Table names are lowercase ASCII and table emoji are already NFC, so only the
/// characters whose normalisation or folding yields ASCII letters need mapping by hand.
fn fold(typed: &str) -> String {
    let mut folded = String::with_capacity(typed.len());
    for c in typed.trim_matches(is_space).chars() {
        match c {
            '\u{df}' | '\u{1e9e}' => folded.push_str("ss"),
            '\u{17f}' => folded.push('s'),
            '\u{fb00}' => folded.push_str("ff"),
            '\u{fb01}' => folded.push_str("fi"),
            '\u{fb02}' => folded.push_str("fl"),
            '\u{fb03}' => folded.push_str("ffi"),
            '\u{fb04}' => folded.push_str("ffl"),
            '\u{fb05}' | '\u{fb06}' => folded.push_str("st"),
            other => folded.extend(other.to_lowercase()),
        }
    }
    folded
}

fn aad(network: Network) -> [u8; 18] {
    let mut aad = [0u8; 18];
    let (domain, net) = aad.split_at_mut(DOMAIN.len());
    domain.copy_from_slice(DOMAIN);
    if let [net] = net {
        *net = network.byte();
    }
    aad
}

/// `k`, the stretched words. Wiped on drop and never printed.
pub struct WordsKey(Zeroizing<[u8; KEY_LEN]>);

impl WordsKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// `s = HKDF-Expand(k, "mailbox", 16)`: the seed of the rendezvous mailbox, whose keys are
    /// the pairing mailbox keys of RFC 0002 8.1.
    pub fn mailbox_seed(&self) -> Zeroizing<[u8; 16]> {
        let block = Zeroizing::new(self.expand(b"mailbox"));
        let mut seed = Zeroizing::new([0u8; 16]);
        for (out, byte) in seed.iter_mut().zip(block.iter()) {
            *out = *byte;
        }
        seed
    }

    /// The text A posts to the rendezvous mailbox for `invite`.
    pub fn seal_invite(&self, invite: &Invite) -> Result<String, WordsError> {
        let mut sealed = invite.as_bytes().to_vec();
        let tag = self
            .cipher()
            .encrypt_inout_detached(
                &NONCE.into(),
                &aad(invite.network()),
                sealed.as_mut_slice().into(),
            )
            .map_err(|_| WordsError::Encryption)?;
        sealed.extend_from_slice(&tag);
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }

    /// The invite bytes in posted text. Any failure is [`WordsError::CannotOpen`]; decoding the
    /// invite is the caller's next step.
    pub fn open_invite(&self, network: Network, text: &str) -> Result<Vec<u8>, WordsError> {
        let text = text.trim_matches(is_space);
        if text.chars().count() > MAX_POSTED_LEN {
            return Err(WordsError::CannotOpen);
        }
        let mut sealed = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| WordsError::CannotOpen)?;
        let split = sealed
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(WordsError::CannotOpen)?;
        let tag = Tag::try_from(sealed.split_off(split).as_slice())
            .map_err(|_| WordsError::CannotOpen)?;
        self.cipher()
            .decrypt_inout_detached(
                &NONCE.into(),
                &aad(network),
                sealed.as_mut_slice().into(),
                &tag,
            )
            .map_err(|_| WordsError::CannotOpen)?;
        Ok(sealed)
    }

    /// `HKDF-Expand(k, info, 32)`: with `k` as the PRK, the first output block is
    /// `HMAC(k, info || 0x01)`.
    fn expand(&self, info: &[u8]) -> [u8; KEY_LEN] {
        hmac_sha256(&self.0, &[info, &[0x01]].concat())
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        let key = Zeroizing::new(self.expand(b"invite"));
        ChaCha20Poly1305::new(&(*key).into())
    }
}

impl fmt::Debug for WordsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WordsKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_what_full_case_folding_folds_to_ascii() {
        assert_eq!(fold(" KiTTY\t"), "kitty");
        assert_eq!(fold("\u{1c}kitty\u{1f}"), "kitty");
        assert_eq!(fold("\u{212a}itty"), "kitty");
        assert_eq!(fold("gra\u{df}"), "grass");
        assert_eq!(fold("\u{17f}quid"), "squid");
        assert_eq!(fold("pu\u{fb00}er"), "puffer");
    }

    #[test]
    fn parses_names_in_any_case_and_emoji() {
        let words = PairingWords::from_bytes([0, 1, 2, 3, 255]);
        let symbols = words.symbols().unwrap();
        let typed = [
            symbols[0].name.to_uppercase(),
            symbols[1].emoji.to_owned(),
            format!("  {} ", symbols[2].name),
            symbols[3].name.to_owned(),
            symbols[4].emoji.to_owned(),
        ];
        assert_eq!(PairingWords::parse(&typed).unwrap(), words);
    }

    #[test]
    fn refuses_unknown_words_and_wrong_counts() {
        let name = symbol(7).unwrap().name;
        assert_eq!(
            PairingWords::parse(&[name; 4]).unwrap_err(),
            WordsError::Unknown
        );
        assert_eq!(
            PairingWords::parse(&[name; 6]).unwrap_err(),
            WordsError::Unknown
        );
        assert_eq!(
            PairingWords::parse(&[name, name, name, name, "abandon"]).unwrap_err(),
            WordsError::Unknown
        );
        assert_eq!(
            PairingWords::parse(&[name, name, name, name, ""]).unwrap_err(),
            WordsError::Unknown
        );
    }

    #[test]
    fn debug_is_redacted() {
        let shown = format!(
            "{:?} {:?}",
            PairingWords::from_bytes([0xab; 5]),
            WordsKey::from_bytes([0xab; 32])
        );
        assert!(!shown.contains("ab,") && !shown.contains("171"));
        assert!(shown.contains("redacted"));
    }
}
