// SPDX-License-Identifier: Apache-2.0
//! The seal key each native endpoint showed the first time this wallet sent to it (EPICTX
//! 5.15), kept under the account that sent and the endpoint's origin, so a later key for the
//! same origin is not taken in silence.

use jiff::Timestamp;

use crate::account::AccountIndex;
use crate::error::StoreError;

pub const PIN_KEY_LEN: usize = 32;
/// The longest origin a pin is kept under, in bytes.
pub const MAX_PIN_ORIGIN_LEN: usize = 300;

/// The key one origin showed to one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPin {
    pub account: AccountIndex,
    /// The normalised origin: `scheme://host:port`, or the onion name alone.
    pub origin: String,
    pub seal_key: [u8; PIN_KEY_LEN],
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

pub trait PeerPinRepository {
    /// Stores `pin`, replacing the pin with the same account and origin. Fails with
    /// [`StoreError::OutOfRange`] for an empty origin or one longer than
    /// [`MAX_PIN_ORIGIN_LEN`].
    fn put_peer_pin(&mut self, pin: &PeerPin) -> Result<(), StoreError>;

    fn peer_pin(&self, account: AccountIndex, origin: &str) -> Result<Option<PeerPin>, StoreError>;

    /// Every pin of `account`, in origin order.
    fn peer_pins(&self, account: AccountIndex) -> Result<Vec<PeerPin>, StoreError>;

    /// Deletes the pin of `account` for `origin`, and returns whether there was one.
    fn forget_peer_pin(&mut self, account: AccountIndex, origin: &str) -> Result<bool, StoreError>;
}

pub(crate) fn check_origin(origin: &str) -> Result<(), StoreError> {
    if origin.is_empty() || origin.len() > MAX_PIN_ORIGIN_LEN {
        return Err(StoreError::OutOfRange {
            field: "pin origin",
        });
    }
    Ok(())
}
