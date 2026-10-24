//! Contact pairing formats (RFC 0002): the sealed envelope and its armor, contact cards,
//! invites, the pairing reply and confirm, and the SAS. Pure: callers pass keys, the RNG and the
//! time in.

mod error;
mod keys;
mod text;

pub use error::{DecodeError, EncodeError, KeyError, Malformed, SasTableError, TextError};
pub use keys::{EncPublicKey, EncSecretKey, HintKey};
pub use text::{
    ContactName, MAX_HOST_LEN, MAX_MAILBOX_LEN, MAX_NAME_LEN, MAX_REFERENCE_LEN, MailboxAddress,
    Reference, RelayHost,
};
