// SPDX-License-Identifier: Apache-2.0
//! What crates that build features on the engine plug in. `lepic-wallet-contacts` is the one
//! user: it drives the engine through the public wallet calls, the unlocked [`Session`], the
//! event stream and the hooks here, so the engine itself holds no contact code.
//!
//! [`Session`]: crate::lifecycle::Session

use futures_util::future::BoxFuture;
use lepic_keychain::Keychain;
use lepic_primitives::params::Network;
use lepic_store::{AccountIndex, ContactId};

use crate::notice::Notice;
use crate::ports::StoreOpener;
use crate::wallet::Wallet;

/// Supplies the one-time reply key a file or paste S1 and an I1 carry in the LEPIC marker, so a
/// LEPIC peer can answer them sealed (RFC 0002 5). Stock wallets ignore the marker. Without a
/// hook installed with [`crate::Wallet::set_reply_keys`] those slates carry no marker.
pub trait ReplyKeys: Send + Sync {
    /// The X25519 public key the peer seals its answer to the slate `slate_id` of `account`
    /// to, or `None` when none can be derived.
    fn reply_public_key(
        &self,
        keychain: &Keychain,
        network: Network,
        account: AccountIndex,
        slate_id: [u8; 16],
    ) -> Option<[u8; 32]>;
}

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
}

/// Takes a pairing request another wallet sent to this wallet's payments address. It is
/// stored, or dropped by the contact engine's rules, before the relay message is acknowledged.
/// Without a hook installed with [`crate::Wallet::set_pair_requests`] a request is ignored.
pub trait PairRequests<N, S: StoreOpener, V>: Send + Sync {
    /// Takes the request with `invite_link` from `sender`, the address the relay reported.
    /// An error keeps the message on the relay for another try.
    fn take<'a>(
        &'a self,
        wallet: &'a Wallet<N, S, V>,
        sender: &'a str,
        invite_link: String,
    ) -> BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>>;
}
