// SPDX-License-Identifier: Apache-2.0
//! Contact pairing (RFC 0002): invites, the pairing reply and confirm, private pairing, the key
//! check, the SAS and pairing words. Pure: callers pass keys, the RNG and the time in.
//!
//! The sealed envelope, its armor, contact cards and the other formats the envelope carries
//! live in `lepic-seal`, so the direct endpoint and epic1 use them without the pairing flows.
//! They are re-exported here at the paths they always had.

mod error;
mod invite;
mod keycheck;
mod pairing;
mod private;
mod sas;
mod words;

pub use error::{
    DecodeError, EncodeError, KeyError, Malformed, SasTableError, TextError, WordsError,
};
pub use invite::{INVITE_FORMAT, Invite, InviteFields, MAILBOX_KEY_LEN, MAX_INVITE_LEN};
pub use keycheck::{
    KeyCheck, KeyCheckAnswer, KeyCheckProof, accept_found, accept_restored, key_check_tag,
    open_contact_update, open_key_check, open_key_check_answer, seal_contact_update,
    seal_contact_update_with, seal_found, seal_key_check, seal_not_found, seal_restored,
};
pub use lepic_seal::wire::verifying_key;
pub use lepic_seal::{
    CARD_FORMAT, Capabilities, CardFields, ContactCard, ContactKind, ContactName, Content,
    DOMAIN_TAG, DomainClaim, DomainError, DomainKey, DomainName, ENVELOPE_VERSION, EncPublicKey,
    EncSecretKey, HEADER_LEN, Hint, HintKey, HintRule, KeyClass, MAGIC, MAX_ARMOR_LEN,
    MAX_BODY_LEN, MAX_CARD_LEN, MAX_DOMAIN_LEN, MAX_ENVELOPE_LEN, MAX_HOST_LEN, MAX_MAILBOX_LEN,
    MAX_NAME_LEN, MAX_REFERENCE_LEN, MailboxAddress, MessageType, NATIVE_SLATE, Network, Opened,
    PaymentFile, Purpose, Reference, RelayHost, SEALED_FILE_EXTENSION, SUITE, SealedEnvelope,
    SigningKey, TxContent, TxKey, TxOpened, VerifyingKey, armor, armor_tx, classify, dearmor,
    decode_content, looks_sealed, seal, seal_padded, seal_psk, seal_psk_padded, seal_tx,
};
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
pub use words::{MAX_POSTED_LEN, PairingWords, WORD_COUNT, WordsKey, WordsWindow};
