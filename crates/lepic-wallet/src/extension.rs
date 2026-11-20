// SPDX-License-Identifier: Apache-2.0
//! What crates that build features on the engine plug in. `lepic-wallet-contacts` is the one
//! user: it drives the engine through the public wallet calls, the unlocked [`Session`], the
//! event stream and the hooks here, so the engine itself holds no contact code.
//!
//! [`Session`]: crate::lifecycle::Session

use futures_util::future::BoxFuture;
use lepic_store::ContactId;

use crate::notice::Notice;
use crate::ports::StoreOpener;
use crate::wallet::Wallet;

/// Seals a notice about a slate exchanged with a paired contact into that contact's mailbox,
/// instead of sending it in the clear over Epicbox (RFC 0002 11). Without a hook installed with
/// [`crate::Wallet::set_contact_notices`] such a notice is withheld.
pub trait ContactNotices<N, S: StoreOpener, V>: Send + Sync {
    /// Queues `notice` for the mailbox of `contact`; the contact engine's next outbox run
    /// delivers it.
    fn queue<'a>(
        &'a self,
        wallet: &'a Wallet<N, S, V>,
        contact: ContactId,
        notice: Notice,
    ) -> BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>>;

    /// Queues `notice` about an epic1 payment this wallet sent for the address it paid, sealed
    /// to its seal key (RFC 0003 5.9); nothing for a slate that is no such payment.
    fn queue_to_address<'a>(
        &'a self,
        wallet: &'a Wallet<N, S, V>,
        notice: Notice,
    ) -> BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>>;
}
