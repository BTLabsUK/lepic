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
mod sas;
mod text;
mod tlv;
mod words;

pub use armor::{MAX_ARMOR_LEN, SEALED_FILE_EXTENSION, armor, dearmor, looks_sealed};
pub use card::{CARD_FORMAT, Capabilities, CardFields, ContactCard, ContactKind, MAX_CARD_LEN};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use envelope::{
    Content, ENVELOPE_VERSION, MAGIC, MAX_ENVELOPE_LEN, MessageType, Opened, Purpose, SUITE,
    SealedEnvelope, seal,
};
pub use error::{
    DecodeError, EncodeError, KeyError, Malformed, SasTableError, TextError, WordsError,
};
pub use hint::{Hint, HintRule};
pub use invite::{INVITE_FORMAT, Invite, InviteFields, MAX_INVITE_LEN};
pub use keycheck::{
    KeyCheckBody, KeyCheckStatus, open_contact_update, open_key_check, open_key_check_answer,
    seal_contact_update, seal_key_check, seal_key_check_answer,
};
pub use keys::{EncPublicKey, EncSecretKey, HintKey};
pub use network::Network;
pub use pairing::{
    Commitment, ConfirmBody, ConfirmCode, ConfirmStatus, InviteId, MAX_PAIRING_ENVELOPE_LEN, Nonce,
    PairingCode, PairingLink, ReplyBody, open_confirm, open_reply, pairing_envelope_from_link,
    pairing_envelope_link, seal_confirm, seal_reply,
};
pub use sas::{Sas, SasSymbol, symbol};
pub use text::{
    ContactName, MAX_HOST_LEN, MAX_MAILBOX_LEN, MAX_NAME_LEN, MAX_REFERENCE_LEN, MailboxAddress,
    Reference, RelayHost,
};
pub use words::{MAX_POSTED_LEN, PairingWords, WORD_COUNT, WordsKey};
