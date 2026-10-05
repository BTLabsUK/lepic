//! Notices over Epicbox in the engine (ADR 0016): which peers may be sent one, what a received
//! one does, and who sends which.
//!
//! A peer is proven to run LEPIC once a slate from it carried the LEPIC marker, or it sent a
//! notice this wallet accepted; only then does it get a notice, because a stock listener never
//! acknowledges a payload that is not a slate. A notice is accepted only from the recorded
//! counterparty of its slate, and it never moves funds or unlocks anything: it deletes a parked
//! invoice at most, and otherwise only tells the host.

use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{EpicboxAddress, Network as RelayNetwork, TRANSPORT_ID};
use lepic_node::NodeApi;
use lepic_slate::model::SlateId;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    PeerCapability, PeerSupport, PendingInvoiceStatus, Repositories, SlateStage, StoreError,
    TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::transport::{Destination, Outbound, Transport};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::epicbox_invoice::stored_codecs;
use crate::event::{DeclinedInvoice, Event, PostedInvoice, WithdrawnInvoice};
use crate::inbox::{ErrorChain, Handled, Hold, relay_network};
use crate::notice::{Notice, NoticeKind};
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::final_kernel;
use crate::wallet::Wallet;

/// What an accepted notice changed, for the event it raises.
enum Effect {
    Posted {
        tx_id: TxId,
        excess: lepic_crypto::Commitment,
    },
    Declined {
        tx_id: TxId,
    },
    Withdrawn {
        tx_id: Option<TxId>,
    },
    /// Accepted, with nothing left to tell the host.
    Noted,
    /// Not from the counterparty of the slate, or about nothing this wallet holds.
    Dropped,
}

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

/// The key of the address text, as the store keys peers.
fn key_of(address: &str, network: RelayNetwork) -> Option<String> {
    EpicboxAddress::parse(address, network)
        .ok()
        .map(|address| address.key_text())
}

fn counterparty_key(
    repos: &dyn Repositories,
    tx_id: TxId,
    network: RelayNetwork,
) -> Result<Option<String>, StoreError> {
    Ok(repos
        .counterparty(tx_id)?
        .and_then(|address| key_of(&address, network)))
}

/// Whether the peer with `key` proved that it runs LEPIC.
fn proven(repos: &dyn Repositories, key: &str) -> Result<bool, StoreError> {
    Ok(repos
        .peer_capability(key)?
        .is_some_and(|capability| capability.support == PeerSupport::Lepic))
}

/// Records that the peer with `key` runs LEPIC.
pub(crate) fn record_lepic(
    repos: &mut dyn Repositories,
    key: String,
    now: jiff::Timestamp,
) -> Result<(), StoreError> {
    repos.put_peer_capability(&PeerCapability {
        key,
        support: PeerSupport::Lepic,
        learned_at: now,
    })
}

/// The transaction over Epicbox for `slate_id` in `direction` that stored `stage`, when its
/// counterparty is the peer with `from`.
fn transaction_with(
    repos: &dyn Repositories,
    slate_id: Uuid,
    direction: TxDirection,
    stage: SlateStage,
    from: &str,
    network: RelayNetwork,
) -> Result<Option<(TxId, TxState)>, StoreError> {
    let Some(stored) = repos.transaction_by_slate(slate_id, direction)? else {
        return Ok(None);
    };
    if stored.entry.transport.as_deref() != Some(TRANSPORT_ID.as_str())
        || repos.slate(slate_id, stage)?.is_none()
        || counterparty_key(repos, stored.id, network)?.as_deref() != Some(from)
    {
        return Ok(None);
    }
    Ok(Some((stored.id, stored.entry.state)))
}

fn apply_notice(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    network: RelayNetwork,
    notice: Notice,
    from: String,
    now: jiff::Timestamp,
) -> Result<Effect, StoreError> {
    let slate_id = uuid(notice.slate_id);
    let effect = match notice.kind {
        NoticeKind::Posted { excess } => {
            let payment = transaction_with(
                repos,
                slate_id,
                TxDirection::Outgoing,
                SlateStage::Invoice2,
                &from,
                network,
            )?;
            match payment {
                Some((tx_id, _))
                    if final_kernel(repos, codecs, tx_id, slate_id)?
                        .is_some_and(|(expected, _)| expected == excess) =>
                {
                    Effect::Posted { tx_id, excess }
                }
                _ => Effect::Dropped,
            }
        }
        NoticeKind::Declined => match transaction_with(
            repos,
            slate_id,
            TxDirection::Incoming,
            SlateStage::Invoice1,
            &from,
            network,
        )? {
            Some((tx_id, _)) => Effect::Declined { tx_id },
            None => Effect::Dropped,
        },
        NoticeKind::Withdrawn => withdraw(repos, slate_id, &from, network)?,
    };
    if !matches!(effect, Effect::Dropped) {
        record_lepic(repos, from, now)?;
    }
    Ok(effect)
}

/// A parked invoice that is not paid is deleted; a paid one is only reported while its payment
/// waits for the issuer.
fn withdraw(
    repos: &mut dyn Repositories,
    slate_id: Uuid,
    from: &str,
    network: RelayNetwork,
) -> Result<Effect, StoreError> {
    if let Some(parked) = repos.pending_invoice(slate_id)?
        && parked.sender_key == from
        && parked.status != PendingInvoiceStatus::Paid
    {
        repos.delete_pending_invoice(slate_id)?;
        return Ok(Effect::Withdrawn { tx_id: None });
    }
    Ok(
        match transaction_with(
            repos,
            slate_id,
            TxDirection::Outgoing,
            SlateStage::Invoice2,
            from,
            network,
        )? {
            Some((tx_id, TxState::Sent)) => Effect::Withdrawn { tx_id: Some(tx_id) },
            Some(_) => Effect::Noted,
            None => Effect::Dropped,
        },
    )
}

/// Where a `withdrawn` for the cancelled transaction `tx_id` goes: the address an invoice over
/// Epicbox was issued to, while no payment of it was finalized.
fn withdrawal_target(
    repos: &dyn Repositories,
    tx_id: TxId,
) -> Result<Option<(SlateId, Destination)>, StoreError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(None);
    };
    let Some(slate_id) = entry.slate_id else {
        return Ok(None);
    };
    if entry.direction != TxDirection::Incoming
        || entry.transport.as_deref() != Some(TRANSPORT_ID.as_str())
        || repos.slate(slate_id, SlateStage::Invoice1)?.is_none()
        || repos.slate(slate_id, SlateStage::Invoice3)?.is_some()
    {
        return Ok(None);
    }
    Ok(repos.counterparty(tx_id)?.map(|to| {
        (
            SlateId::from_bytes(slate_id.into_bytes()),
            Destination::new(to),
        )
    }))
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes a notice that arrived from `reply_to`, and raises the event it calls for.
    pub(crate) async fn take_notice(
        &self,
        notice: Notice,
        reply_to: &Destination,
    ) -> Result<Handled, Hold> {
        let network = relay_network(self.config().network);
        let Some(from) = key_of(reply_to.as_str(), network) else {
            return Ok(Handled::Dropped);
        };
        let codecs = stored_codecs(self.config().network);
        let effect = self
            .inbox_write(move |repos, now| apply_notice(repos, &codecs, network, notice, from, now))
            .await?;
        let slate_id = notice.slate_id;
        let event = match effect {
            Effect::Dropped => {
                debug!(slate_id = %slate_id, "notice dropped");
                return Ok(Handled::Dropped);
            }
            Effect::Noted => None,
            Effect::Posted { tx_id, excess } => Some(Event::InvoicePosted(PostedInvoice {
                tx_id,
                slate_id,
                excess,
            })),
            Effect::Declined { tx_id } => {
                Some(Event::InvoiceDeclined(DeclinedInvoice { tx_id, slate_id }))
            }
            Effect::Withdrawn { tx_id } => Some(Event::InvoiceWithdrawn(WithdrawnInvoice {
                slate_id,
                tx_id,
            })),
        };
        info!(slate_id = %slate_id, "notice received");
        if let Some(event) = event {
            self.emit(event);
        }
        Ok(Handled::Notice)
    }

    /// Records that the senders of a marked payment of an invoice this wallet issued run
    /// LEPIC: the key the payment came from, and the key the invoice went to, whose holder
    /// is the only one that could answer it.
    pub(crate) async fn record_paying_peer(&self, tx_id: TxId, reply_to: &Destination) {
        let network = relay_network(self.config().network);
        let from = key_of(reply_to.as_str(), network);
        let recorded = self
            .inbox_write(move |repos, now| {
                let invoiced = counterparty_key(repos, tx_id, network)?;
                for key in [from, invoiced].into_iter().flatten() {
                    record_lepic(repos, key, now)?;
                }
                Ok(())
            })
            .await;
        if let Err(error) = recorded {
            warn!(tx_id = %tx_id, error = %ErrorChain(&error), "peer capability not recorded");
        }
    }

    /// Tells the payer that the paid invoice `tx_id` was pushed with `excess`.
    pub(crate) async fn notify_posted(
        &self,
        tx_id: TxId,
        slate_id: SlateId,
        excess: lepic_crypto::Commitment,
    ) {
        let to = match self.counterparty_of(tx_id).await {
            Ok(Some(to)) => to,
            Ok(None) => return,
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
                return;
            }
        };
        let notice = Notice {
            slate_id,
            kind: NoticeKind::Posted { excess },
        };
        self.send_notice(None, &to, notice).await;
    }

    /// Tells the payer that the invoice `tx_id`, just cancelled, is withdrawn, when it was one
    /// issued over Epicbox.
    pub(crate) async fn notify_withdrawn(&self, tx_id: TxId) {
        let target = async {
            let session = self.session()?;
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| withdrawal_target(repos, tx_id))?)
            })
            .await
        };
        let (slate_id, to) = match target.await {
            Ok(Some(target)) => target,
            Ok(None) => return,
            Err(error) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&error), "notice not sent");
                return;
            }
        };
        let notice = Notice {
            slate_id,
            kind: NoticeKind::Withdrawn,
        };
        self.send_notice(None, &to, notice).await;
    }

    /// Tells the issuer of the parked invoice `slate_id` that it was declined, from the invoice
    /// address it was issued to.
    pub(crate) async fn notify_declined(&self, epicbox: &EpicboxTransport, slate_id: SlateId) {
        let to = async {
            let session = self.session()?;
            self.blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.pending_invoice(uuid(slate_id)))?)
            })
            .await
        };
        let to = match to.await {
            Ok(Some(parked)) => Destination::new(parked.sender_address),
            Ok(None) => return,
            Err(error) => {
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "notice not sent");
                return;
            }
        };
        let identity = self
            .invoice_address_index()
            .map_err(crate::inbox::InboxError::from)
            .and_then(|index| self.identity_at(epicbox, index));
        let client = match identity {
            Ok(identity) => epicbox.client_for(identity),
            Err(error) => {
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "notice not sent");
                return;
            }
        };
        let notice = Notice {
            slate_id,
            kind: NoticeKind::Declined,
        };
        self.send_notice(Some(&client as &dyn Outbound), &to, notice)
            .await;
    }

    async fn counterparty_of(
        &self,
        tx_id: TxId,
    ) -> Result<Option<Destination>, crate::error::WalletError> {
        let session = self.session()?;
        self.blocking(move |_, _| {
            Ok(session
                .store
                .read(|repos| repos.counterparty(tx_id))?
                .map(Destination::new))
        })
        .await
    }

    /// Sends `notice` to `to`, through `sender` or else the registered Epicbox transport, when
    /// the peer proved it runs LEPIC. Returns whether it was sent. Notices are advisory, so a
    /// failure is logged and not returned.
    async fn send_notice(
        &self,
        sender: Option<&dyn Outbound>,
        to: &Destination,
        notice: Notice,
    ) -> bool {
        let slate_id = notice.slate_id;
        let network = relay_network(self.config().network);
        let Some(key) = key_of(to.as_str(), network) else {
            return false;
        };
        let proof = async {
            let session = self.session()?;
            self.blocking(move |_, _| Ok(session.store.read(|repos| proven(repos, &key))?))
                .await
        };
        match proof.await {
            Ok(true) => {}
            Ok(false) => {
                debug!(slate_id = %slate_id, "notice withheld from a peer not proven to run lepic");
                return false;
            }
            Err(error) => {
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "notice not sent");
                return false;
            }
        }
        let registered = self
            .ports()
            .transports
            .get(TRANSPORT_ID)
            .and_then(Transport::outbound);
        let Some(outbound) = sender.or(registered) else {
            warn!(slate_id = %slate_id, "notice not sent");
            return false;
        };
        match outbound.deliver(to, &notice.encode()).await {
            Ok(()) => {
                info!(slate_id = %slate_id, "notice sent");
                true
            }
            Err(error) => {
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "notice not sent");
                false
            }
        }
    }
}
