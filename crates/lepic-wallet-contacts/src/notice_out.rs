// SPDX-License-Identifier: Apache-2.0
//! The one way a notice goes out (ADR 0067): sealed for where it goes and stored as an outbox
//! row marked as a notice, which the outbox posts with the back-off of any row. A notice has
//! no slate stage and no delivery state, and no outbox report counts it. The host's `app`
//! notice goes this way too, as the app payload message type it always had.

use jiff::Timestamp;
use lepic_contact::Reference;
use lepic_epic1::{MethodId, RouteEntry};
use lepic_methods::epicbox::NOTICE_LENGTHS;
use lepic_primitives::params::Network;
use lepic_seal::{Content, EncPublicKey, HintRule, MessageType, armor, seal, seal_epic1_notice};
use lepic_store::{AccountIndex, ContactRecord, NativeOutboxId, Repositories, WalletStore};
use lepic_wallet::notice::{Notice, notice_length};
use uuid::Uuid;

use super::delivery::outbox::{self, Owed, Sender};
use super::keys::contact_network;
use super::outbox::peer_route;
use super::{ContactError, LockedRng};

/// Where a notice goes, and how it is sealed.
pub(crate) enum NoticeTo<'a> {
    /// A paired contact, to its mailbox key: padded, sealed and signed to its card.
    Contact {
        record: &'a ContactRecord,
        keychain: &'a lepic_keychain::Keychain,
    },
    /// The payee of an epic1 payment from `account`, to the delivery mailbox `mailbox` the
    /// payment went to: sealed to the seal key of the address it paid (RFC 0003 5.9).
    Address {
        account: AccountIndex,
        seal_key: &'a EncPublicKey,
        mailbox: String,
    },
    /// The payer of a payment to `account`, on `route` to the reply slot the payment named, on
    /// the mailbox the payment was read from: sealed to its reply key.
    ReplyKey {
        account: AccountIndex,
        reply_key: &'a EncPublicKey,
        route: RouteEntry,
    },
}

/// Seals `notice` for `to` and stores it as a queued notice row, due at once, in the caller's
/// write. The row's id is the notice's slate, an `app` notice's own id, or a new id for any
/// other notice. `None` when a contact has no peer card or mailbox to send to, and for an `app`
/// notice to anything but a pairing.
pub(crate) fn send_notice(
    repos: &mut dyn Repositories,
    (network, rng): (Network, &mut LockedRng<'_>),
    notice: &Notice,
    to: NoticeTo<'_>,
    now: Timestamp,
) -> Result<Option<NativeOutboxId>, ContactError> {
    let net = contact_network(network);
    let (sender, route, envelope) = match to {
        NoticeTo::Contact { record, keychain } => {
            let Some(mailbox) = repos.contact_mailbox(record.contact_id)? else {
                return Ok(None);
            };
            if record.peer.is_none() {
                return Ok(None);
            }
            let class = super::private::class_of(repos, record)?;
            let content = match notice {
                // The app payload message type, unpadded, under its id, byte for byte as before.
                Notice::App { id, body } => Content {
                    reference: Some(Reference::new(&id.to_string()).map_err(ContactError::Name)?),
                    ..Content::new(MessageType::AppPayload, body.clone())
                },
                _ => {
                    let length = notice_length(&NOTICE_LENGTHS, rng);
                    let text = notice.to_padded_text(&NOTICE_LENGTHS, length);
                    Content::new(MessageType::Notice, text.into_bytes())
                }
            };
            let envelope = super::invoices::seal_to_record(
                keychain, network, record, &class, content, false, now, rng,
            )?;
            let route = epicbox(peer_route(&mailbox.peer_mailbox).to_owned());
            (Sender::Contact(record.contact_id), route, envelope)
        }
        NoticeTo::Address { .. } | NoticeTo::ReplyKey { .. }
            if matches!(notice, Notice::App { .. }) =>
        {
            return Ok(None);
        }
        NoticeTo::Address {
            account,
            seal_key,
            mailbox,
        } => {
            let text = notice.to_text().into_bytes();
            let envelope =
                seal_epic1_notice(net, seal_key, &text, rng).map_err(ContactError::Encode)?;
            (Sender::Payer(account), epicbox(mailbox), envelope)
        }
        NoticeTo::ReplyKey {
            account,
            reply_key,
            route,
        } => {
            let content = Content::new(MessageType::Notice, notice.to_text().into_bytes());
            let envelope = seal(net, reply_key, HintRule::ReplyKey, &content, None, rng)
                .map_err(ContactError::Encode)?;
            (Sender::Payee(account), route, envelope)
        }
    };
    let payment_id = match (notice, notice.slate_id()) {
        (Notice::App { id, .. }, _) => *id,
        (_, Some(slate_id)) => Uuid::from_bytes(*slate_id.as_bytes()),
        (_, None) => Uuid::from_bytes(super::new_id(rng)),
    };
    let owed = Owed {
        payment_id,
        sender,
        route,
        envelope: armor(&envelope),
        cutoff: None,
        stage: None,
        notice: true,
    };
    Ok(Some(outbox::enqueue(repos, &owed, now)?))
}

fn epicbox(value: String) -> RouteEntry {
    RouteEntry {
        method: MethodId::Epicbox,
        value,
    }
}

impl<N, S, V> crate::ContactBook<'_, N, S, V>
where
    N: lepic_node::NodeApi + 'static,
    S: lepic_wallet::ports::StoreOpener + 'static,
    V: lepic_wallet::ports::SecretVault + 'static,
{
    /// [`send_notice`] of `notice` to the contact of `contact_id`, in a write of its own. The
    /// next outbox run delivers it.
    ///
    /// Fails with [`ContactError::UnknownContact`] when there is no such contact.
    pub(crate) async fn send_contact_notice(
        &self,
        contact_id: lepic_store::ContactId,
        notice: Notice,
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let kind = notice.kind();
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                // The store before the RNG, the order every other path takes them in.
                let mut rng = LockedRng(&mut **ports.rng.lock());
                let record = repos
                    .contact(contact_id)?
                    .ok_or(ContactError::UnknownContact)?;
                let to = NoticeTo::Contact {
                    record: &record,
                    keychain: &session.keychain,
                };
                send_notice(repos, (network, &mut rng), &notice, to, now)?;
                Ok(())
            })
        })
        .await?;
        tracing::debug!(kind, "notice queued for a contact");
        Ok(())
    }
}
