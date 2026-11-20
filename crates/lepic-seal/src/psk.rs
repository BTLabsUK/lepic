// SPDX-License-Identifier: Apache-2.0
//! HPKE PSK mode of the envelope (RFC 0002, private pairing). The key itself and how it is
//! derived belong to the pairing flow in lepic-contact; the envelope only needs its bytes.

/// The HPKE suite of a private pairing's envelopes: the suite of [`crate::SUITE`] in PSK mode.
/// RFC 0002's kit keeps suite 2 as an unknown suite, so this one lies apart.
pub const SUITE_PSK: u8 = 0x41;

/// The HPKE PSK id of every private pairing key.
pub const PSK_ID: &[u8] = b"epic-private/1";

/// A 32-byte HPKE pre-shared key an envelope can be sealed and opened under.
pub trait PresharedKey {
    fn psk_bytes(&self) -> &[u8; 32];
}
