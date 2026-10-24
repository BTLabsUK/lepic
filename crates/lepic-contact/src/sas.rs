//! The short authentication string both screens show after pairing (RFC 0002 7.5).

use crate::card::ContactCard;
use crate::error::SasTableError;
use crate::hash::sha256;
use crate::network::Network;
use crate::pairing::Nonce;

const SAS_DOMAIN: &[u8] = b"epic-pair/1 sas";

/// 256 lines of `<emoji>\t<name>`. Frozen once released: a change is a new table and a new SAS
/// domain string.
const EMOJI_V1: &str = include_str!("../../../testdata/sas/emoji-v1.txt");

/// One entry of the SAS table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SasSymbol {
    pub emoji: &'static str,
    pub name: &'static str,
}

/// Four bytes, each an index into the SAS table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sas([u8; 4]);

impl Sas {
    /// `H("epic-pair/1 sas" || net || H(cardA) || H(cardB) || nA || nB)[0..4]`, with `inviter`
    /// as card A.
    pub fn compute(
        network: Network,
        inviter: &ContactCard,
        invitee: &ContactCard,
        inviter_nonce: &Nonce,
        invitee_nonce: &Nonce,
    ) -> Self {
        let [a, b, c, d, ..] = sha256(&[
            SAS_DOMAIN,
            &[network.byte()],
            &inviter.digest(),
            &invitee.digest(),
            inviter_nonce.expose_bytes(),
            invitee_nonce.expose_bytes(),
        ]);
        Self([a, b, c, d])
    }

    /// In person both nonces are zero and card A is the one with the lower sig key, so both
    /// phones compute the same value from the two scanned cards.
    pub fn in_person(network: Network, one: &ContactCard, other: &ContactCard) -> Self {
        let (first, second) = if one.sig_key().as_bytes() <= other.sig_key().as_bytes() {
            (one, other)
        } else {
            (other, one)
        };
        Self::compute(network, first, second, &Nonce::zero(), &Nonce::zero())
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    pub fn symbols(&self) -> Result<[SasSymbol; 4], SasTableError> {
        let [a, b, c, d] = self.0;
        Ok([symbol(a)?, symbol(b)?, symbol(c)?, symbol(d)?])
    }
}

/// The entry at `index` of the v1 table.
pub fn symbol(index: u8) -> Result<SasSymbol, SasTableError> {
    let line = EMOJI_V1
        .lines()
        .nth(usize::from(index))
        .ok_or(SasTableError::MissingLine { index })?;
    let (emoji, name) = line
        .split_once('\t')
        .ok_or(SasTableError::BadLine { index })?;
    if emoji.is_empty() || name.is_empty() {
        return Err(SasTableError::BadLine { index });
    }
    Ok(SasSymbol { emoji, name })
}
