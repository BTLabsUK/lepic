// SPDX-License-Identifier: Apache-2.0
//! Contact pairing formats (RFC 0002): the sealed envelope and its armor, contact cards,
//! invites, the pairing reply and confirm, the key check, the SAS and pairing words. Pure:
//! callers pass keys, the RNG and the time in.

mod armor;
mod card;
mod envelope;
mod error;
mod hash;
mod hint;
mod invite;
mod keycheck;
mod keys;
mod link;
mod network;
mod pairing;
mod private;
mod sas;
mod text;
mod tlv;
mod words;

pub use armor::{MAX_ARMOR_LEN, SEALED_FILE_EXTENSION, armor, dearmor, looks_sealed};
pub use card::{CARD_FORMAT, Capabilities, CardFields, ContactCard, ContactKind, MAX_CARD_LEN};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use envelope::{
    Content, ENVELOPE_VERSION, HEADER_LEN, MAGIC, MAX_ENVELOPE_LEN, MessageType, Opened, Purpose,
    SUITE, SealedEnvelope, decode_content, seal, seal_psk,
};
pub use error::{
    DecodeError, EncodeError, KeyError, Malformed, SasTableError, TextError, WordsError,
};
pub use hint::{Hint, HintRule};
pub use invite::{INVITE_FORMAT, Invite, InviteFields, MAILBOX_KEY_LEN, MAX_INVITE_LEN};
pub use keycheck::{
    KeyCheck, KeyCheckAnswer, KeyCheckProof, accept_found, accept_restored, key_check_tag,
    open_contact_update, open_key_check, open_key_check_answer, seal_contact_update,
    seal_contact_update_with, seal_found, seal_key_check, seal_not_found, seal_restored,
};
pub use keys::{EncPublicKey, EncSecretKey, HintKey};
pub use network::Network;
pub use pairing::{
    Commitment, Confirm, ConfirmBody, ConfirmCode, InviteId, MAX_PAIRING_ENVELOPE_LEN, Nonce,
    PairingCode, PairingExtras, PairingLink, Refusal, ReplyBody, open_confirm, open_confirm_with,
    open_private_confirm, open_reply, open_reply_with, pairing_envelope_from_link,
    pairing_envelope_link, seal_confirm, seal_confirm_with_extras, seal_private_confirm,
    seal_private_refusal, seal_refusal, seal_reply, seal_reply_with,
};
pub use private::{
    ChannelKey, PairingClass, PrivateSecret, SUITE_PSK, open_private_reply, private_sas,
    seal_private_reply,
};
pub use sas::{Sas, SasSymbol, symbol};
pub use text::{
    ContactName, MAX_HOST_LEN, MAX_MAILBOX_LEN, MAX_NAME_LEN, MAX_REFERENCE_LEN, MailboxAddress,
    Reference, RelayHost,
};
pub use words::{MAX_POSTED_LEN, PairingWords, WORD_COUNT, WordsKey, WordsWindow};
