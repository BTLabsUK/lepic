// SPDX-License-Identifier: Apache-2.0
//! The sealed envelope format (RFC 0002 3, RFC 0003 5): the header, HPKE to an X25519 key with
//! the key class's info, the inner TLV fields and their signature, padding, the armors and the
//! classifier of payment text. It also holds what the inner fields carry: contact cards, domain
//! claims, names and addresses, the invite id. Pure: callers pass keys, the RNG and the time in.
//!
//! The format lives apart from the pairing flows of `lepic-contact`, so the direct endpoint and
//! epic1 seal and open envelopes without them. `lepic-contact` re-exports every item here at the
//! path it had before the split.

mod armor;
mod card;
mod domain;
mod envelope;
mod error;
mod hash;
mod hint;
mod keys;
mod link;
mod network;
mod pairing_id;
mod psk;
mod text;
mod tlv;

pub use armor::{MAX_ARMOR_LEN, SEALED_FILE_EXTENSION, armor, dearmor, looks_sealed};
pub use card::{CARD_FORMAT, Capabilities, CardFields, ContactCard, ContactKind, MAX_CARD_LEN};
pub use domain::{DOMAIN_TAG, DomainClaim, DomainError, DomainKey, DomainName, MAX_DOMAIN_LEN};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use envelope::{
    Content, ENVELOPE_VERSION, HEADER_LEN, MAGIC, MAX_ENVELOPE_LEN, MessageType, Opened, Purpose,
    SUITE, SealedEnvelope, decode_content, seal, seal_psk,
};
pub use error::{DecodeError, EncodeError, KeyError, Malformed, TextError};
pub use hint::{Hint, HintRule};
pub use keys::{EncPublicKey, EncSecretKey, HintKey};
pub use network::Network;
pub use pairing_id::{InviteId, PairingCode};
pub use psk::{PresharedKey, SUITE_PSK};
pub use text::{
    ContactName, MAX_HOST_LEN, MAX_MAILBOX_LEN, MAX_NAME_LEN, MAX_REFERENCE_LEN, MailboxAddress,
    Reference, RelayHost,
};

/// The building blocks of the formats above, for the formats `lepic-contact` builds on the
/// envelope: hashes, the TLV reader and writer, the checked base64 of links, key checks.
#[doc(hidden)]
pub mod wire {
    pub use crate::hash::{checksum, first8, hmac_sha256, sha256};
    pub use crate::keys::{sig_key, verifying_key};
    pub use crate::link::{LinkKind, decode_checked, decode_link, encode_checked, encode_link};
    pub use crate::psk::PSK_ID;
    pub use crate::tlv::{Fields, Writer, check_format};
}
