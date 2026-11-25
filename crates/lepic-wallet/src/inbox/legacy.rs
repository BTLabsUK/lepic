use std::sync::Arc;

use lepic_crypto::SecretKey;
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::codec::WireSlate;
use lepic_slate::model::Slate;
use lepic_slate::stage::Stage;
use lepic_store::{AccountIndex, InboxStatus, SlateStage, WalletStore};
use lepic_transport::error::TransportError;
use lepic_transport::method::Method;
use lepic_transport::transport::{Destination, Envelope, RelayTxId};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::account;
use crate::error::WalletError;
use crate::event::{Event, SlateId, UndeliveredReply, UnknownSlate};
use crate::finalize::{Answerer, FinalizeError};
use crate::namespace::{self, Listing};
use crate::ports::{SecretVault, StoreOpener};
use crate::receipt_cap::{NoRoom, Pool, Sender};
use crate::receive::{ReceiveError, ReceiveRequest};
use crate::twin_answer::{self, Refused, Step};
use crate::wallet::Wallet;

use super::ledger::begin_inbox;
use super::{Arrival, Handled, Hold, Outcome, Refusal, Requeue, Settlement, finalize_is_permanent};

/// `epic-wallet` always uses the address key at index 0 of the account.
const ADDRESS_INDEX: u32 = 0;

/// The account whose address key is the wallet's address identity.
const ADDRESS_ACCOUNT: AccountIndex = AccountIndex(0);

/// `epic-wallet`'s Epicbox listener posts finalized transactions without fluff.
const POST_PROPAGATION: Propagation = Propagation::Stem;

/// Failures of receiving an S1 that the same message would meet again: the slate itself is
/// wrong. Local and node failures pass.
fn receive_is_permanent(error: &ReceiveError) -> bool {
    match error {
        ReceiveError::Wallet(_)
        | ReceiveError::UnknownTransport { .. }
        | ReceiveError::Node(_)
        | ReceiveError::Codecs(_)
        | ReceiveError::OpenReceipts(_) => false,
        ReceiveError::Decode(_)
        | ReceiveError::WrongStage { .. }
        | ReceiveError::ZeroAmount
        | ReceiveError::AboveSupply { .. }
        | ReceiveError::AlreadyReceived { .. }
        | ReceiveError::Expired { .. }
        | ReceiveError::AheadOfTip { .. }
        | ReceiveError::FeeBelowMinimum { .. }
        | ReceiveError::FeeOverflow
        | ReceiveError::MessageSignature { .. }
        | ReceiveError::ForeignProofAddress
        | ReceiveError::Output(_)
        | ReceiveError::Signing(_)
        | ReceiveError::Excess(_)
        | ReceiveError::Slate(_)
        | ReceiveError::Encode(_)
        | ReceiveError::Refused => true,
    }
}

/// Reply failures that delivering the same reply again would meet: the method refused the
/// post, or the reply cannot be sealed for or sent to the address. A [`TransportError::Backend`]
/// failure is the method's to judge.
fn reply_is_permanent(method: &dyn Method, hold: &Hold) -> bool {
    let Hold::Reply(error) = hold else {
        return false;
    };
    match error {
        TransportError::UnsupportedLocation { .. }
        | TransportError::UnknownDestination { .. }
        | TransportError::InvalidDestination { .. } => true,
        TransportError::Backend { .. } => method.delivery_is_permanent(error),
        _ => false,
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The address key of the default account at index 0, as `epic-wallet` derives it: the
    /// secret of the wallet's payments address. Its one caller is the Epicbox method in
    /// `lepic-methods`, which connects to the relay as that address; no other caller should
    /// read it.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn address_secret(&self) -> Result<SecretKey, WalletError> {
        let session = self.session()?;
        let parent = account::parent_key_id(ADDRESS_ACCOUNT)?;
        Ok(session.keychain.address_key(&parent, ADDRESS_INDEX)?)
    }

    /// The secret key of `listing`'s address. It connects to the relay as the listing's
    /// address and signs for the listing: the Epicbox method in `lepic-methods` connects and
    /// signs a service listing with it, and the FFI signs an app's message with it, which needs
    /// no relay. Nothing else should read it.
    ///
    /// Fails with [`WalletError::Locked`].
    pub fn listing_secret(&self, listing: &Listing) -> Result<SecretKey, WalletError> {
        namespace::listing_key(&self.session()?.seed, listing)
    }

    /// Takes one message a method received, on its try `arrival.attempt`, counted from 1: the
    /// message id is recorded before the slate is applied, and a message whose id settled
    /// before is [`Handled::Repeated`] at once. A message refused for good is logged and
    /// [`Handled::Rejected`]. An answer goes back through `method`'s outbound.
    ///
    /// Fails with [`Outcome::Hold`] when the message is to stay for the method to deliver
    /// again, and with [`Outcome::Requeue`] when it is to go back to the address for another
    /// install; the loop then calls [`Wallet::requeued`] or [`Wallet::requeue_failed`].
    pub async fn arrived(
        &self,
        method: &Arc<dyn Method>,
        arrival: Arrival<'_>,
    ) -> Result<Handled, Outcome> {
        let Arrival {
            msg_id,
            envelope,
            attempt,
            listing,
        } = arrival;
        if let Some(msg_id) = msg_id.map(str::to_owned) {
            let previous = self
                .inbox_write(move |repos, now| begin_inbox(repos, &msg_id, now))
                .await
                .map_err(|error| Outcome::Hold(error.into()))?;
            if matches!(
                previous,
                Some(InboxStatus::Processed | InboxStatus::Acknowledged | InboxStatus::Rejected)
            ) {
                debug!("epicbox message already settled");
                return Ok(Handled::Repeated);
            }
        }
        let applied = match listing {
            None => self.apply(method, msg_id, envelope, attempt).await,
            Some(listing) => {
                self.apply_at_listing(method, msg_id, envelope, attempt, listing)
                    .await
            }
        };
        match applied {
            Ok(handled) => Ok(handled),
            Err(Settlement::Hold(hold)) => Err(Outcome::Hold(hold)),
            Err(Settlement::Requeue(answer)) => Err(Outcome::Requeue(answer)),
            Err(Settlement::Refuse(refusal)) => {
                warn!(
                    msg_id = msg_id.unwrap_or(""),
                    error = %ErrorChain(&refusal),
                    "epicbox message rejected"
                );
                Ok(Handled::Rejected)
            }
        }
    }

    /// Takes a stock slate at the payments address: an S1 is answered and an S2 finalized.
    /// Anything else, as a notice, a sealed slate, an invoice or a pairing request, is not a
    /// stock slate of this lane and is dropped.
    async fn apply(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        envelope: &Envelope,
        attempt: u32,
    ) -> Result<Handled, Settlement> {
        let reply_to = envelope.reply_to().ok_or(Refusal::NoReplyAddress)?;
        let Ok(slate) = method.decode(self.config().network, envelope.wire()) else {
            return Ok(dropped(msg_id, None));
        };
        match slate.stage() {
            Stage::S1 => {
                self.answer(method, msg_id, attempt, envelope, &slate, reply_to, None)
                    .await
            }
            Stage::S2 => {
                self.complete(method, msg_id, envelope, &slate, reply_to)
                    .await
            }
            stage => Ok(dropped(msg_id, Some(stage))),
        }
    }

    /// Tells the host that an answer arrived for a slate this store does not know: it may
    /// belong to another install of the same wallet (ADR 0016).
    fn unknown_slate(&self, slate_id: SlateId, stage: Stage, sender: &Destination) {
        self.emit(Event::UnknownSlate(UnknownSlate {
            slate_id,
            stage,
            sender: sender.as_str().to_owned(),
        }));
    }

    /// Settles the message `msg_id` of `answer`, an S2 for a slate this store does not
    /// know, as `twin_answer` decides: held, requeued for another install, or refused
    /// with `refusal`. [`Event::UnknownSlate`] is raised the first time the answer is seen,
    /// and when it is refused without being held. An answer is requeued only while every input
    /// it spends is still unspent on chain: once one is spent, the sender's transaction was
    /// completed elsewhere, or never can be, and the answer is refused. A node that cannot be
    /// asked does not stop the requeue.
    async fn unknown_answer(
        &self,
        msg_id: Option<&str>,
        answer: &Slate,
        stage: Stage,
        sender: &Destination,
        refusal: Refusal,
    ) -> Result<Handled, Settlement> {
        let slate_id = answer.id();
        let uuid = Uuid::from_bytes(*slate_id.as_bytes());
        let arrived = self.first_arrival(msg_id).await?;
        let step = self
            .inbox_write(move |repos, now| twin_answer::step(repos, uuid, stage, arrived, now))
            .await
            .map_err(Hold::from)?;
        let first = match step {
            Step::Hold { first } | Step::Requeue { first } => first,
            Step::Refuse(_) => false,
        };
        if first {
            info!(
                slate_id = %slate_id,
                stage = stage.as_str(),
                msg_id = msg_id.unwrap_or(""),
                "answer for an unknown slate held for another install"
            );
            self.unknown_slate(slate_id, stage, sender);
        }
        match step {
            Step::Hold { .. } => Err(Hold::UnknownSlate.into()),
            Step::Requeue { .. } => {
                if self.inputs_spent(answer).await {
                    info!(
                        slate_id = %slate_id,
                        stage = stage.as_str(),
                        msg_id = msg_id.unwrap_or(""),
                        "answer for an unknown slate refused as settled elsewhere"
                    );
                    self.inbox_write(move |repos, _| twin_answer::forget(repos, uuid, stage))
                        .await
                        .map_err(Hold::from)?;
                    return Err(refusal.into());
                }
                Err(Settlement::Requeue(Requeue {
                    slate_id,
                    stage,
                    refusal,
                }))
            }
            Step::Refuse(Refused::Crowded) => {
                info!(
                    slate_id = %slate_id,
                    stage = stage.as_str(),
                    msg_id = msg_id.unwrap_or(""),
                    "answer for an unknown slate refused"
                );
                self.unknown_slate(slate_id, stage, sender);
                Err(refusal.into())
            }
            Step::Refuse(Refused::WindowPassed) => {
                info!(
                    slate_id = %slate_id,
                    stage = stage.as_str(),
                    msg_id = msg_id.unwrap_or(""),
                    "answer for an unknown slate refused after its requeue window"
                );
                Err(refusal.into())
            }
        }
    }

    /// Whether an input `answer` spends is not unspent on chain, as two answers of the node
    /// agree. `false` when the node cannot be asked.
    async fn inputs_spent(&self, answer: &Slate) -> bool {
        let inputs: Vec<_> = answer
            .inputs()
            .iter()
            .map(|input| input.commitment)
            .collect();
        if inputs.is_empty() {
            return false;
        }
        let node = &self.ports().node;
        let mut missing = inputs;
        for _ in 0..2 {
            match node.get_outputs(&missing).await {
                Ok(found) => {
                    missing.retain(|commitment| {
                        !found
                            .iter()
                            .any(|location| location.commitment == *commitment)
                    });
                }
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "inputs of an unknown slate not checked");
                    return false;
                }
            }
            if missing.is_empty() {
                return false;
            }
        }
        true
    }

    /// Receives an S1 and replies with S2, or replies again with the S2 stored for it. A
    /// different S1 under a slate id received before is refused, and so is a new one over the
    /// open receipt caps, or at the payments address of a wallet that refuses payments nobody
    /// asked for. A reply that cannot be delivered is given up at the hold bound.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn answer(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        attempt: u32,
        envelope: &Envelope,
        proposal: &Slate,
        reply_to: &Destination,
        listing: Option<Listing>,
    ) -> Result<Handled, Settlement> {
        // The caps are checked and the S1 received under one turn, as
        // [`crate::Wallet::receive_unsolicited`] does, so two listeners at the last free place
        // cannot both take it. The answer goes out after the turn is given back.
        let received = {
            let _turn = self.unsolicited_turn().await;
            self.make_room_for(method, proposal, reply_to, listing)
                .await?;
            self.receive_from(
                method,
                envelope.wire(),
                ReceiveRequest::default(),
                Some(reply_to.clone()),
                listing,
            )
            .await
        };
        match received {
            Ok(received) => {
                // A payment answers only from the address it came in on: the S1 of a listing
                // payment that arrives again at the payments address, or the other way round,
                // gets no answer from there.
                let stored = self.receive_listing_of(received.tx_id).await?;
                if stored != listing {
                    debug!(tx_id = %received.tx_id, "answer withheld at another address");
                    return Ok(Handled::Repeated);
                }
                // The answer goes under the relay transaction id the S1 came under, so either
                // party can cancel the payment on the relay; an S1 without one gets a plain
                // answer.
                let txid = match envelope.relay_txid() {
                    Some(txid) => self
                        .file_relay_txid(received.slate.id(), txid.clone())
                        .await
                        .map_err(Hold::Wallet)?,
                    None => None,
                };
                match self
                    .reply(
                        &**method,
                        reply_to,
                        &received.reply,
                        txid.as_ref(),
                        listing.is_some(),
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(Hold::Reply(source)) if method.delivery_cancelled_on_relay(&source) => {
                        info!(tx_id = %received.tx_id, "answer refused, the payment was cancelled on the relay");
                        self.cancelled_on_relay(received.slate.id()).await;
                    }
                    Err(hold)
                        if reply_is_permanent(&**method, &hold)
                            || self.hold_exhausted(msg_id, attempt).await? =>
                    {
                        warn!(tx_id = %received.tx_id, error = %ErrorChain(&hold), "slate reply undelivered");
                        self.emit(Event::ReplyUndelivered(UndeliveredReply {
                            tx_id: received.tx_id,
                            slate_id: received.slate.id(),
                        }));
                    }
                    Err(hold) => return Err(hold.into()),
                }
                Ok(if received.repeated {
                    Handled::Repeated
                } else {
                    Handled::Received
                })
            }
            Err(ReceiveError::AlreadyReceived { .. }) => Err(Refusal::SlateIdReused.into()),
            Err(error @ ReceiveError::Expired { cutoff, .. }) => {
                if self.expired_for_good(msg_id, attempt, cutoff).await? {
                    Err(Refusal::Receive(error).into())
                } else {
                    Err(Hold::Receive(error).into())
                }
            }
            Err(error) if receive_is_permanent(&error) => Err(Refusal::Receive(error).into()),
            Err(error) => Err(Hold::Receive(error).into()),
        }
    }

    /// Delivers the answer `wire` to `to` through `method`'s outbound, under the relay
    /// transaction id `txid` when there is one, which sends from a listing's address when the
    /// message came in `at_listing`.
    async fn reply(
        &self,
        method: &dyn Method,
        to: &Destination,
        wire: &WireSlate,
        txid: Option<&RelayTxId>,
        at_listing: bool,
    ) -> Result<(), Hold> {
        let outbound = method.outbound().ok_or(Hold::NoOutbound {
            transport: method.id(),
        })?;
        outbound
            .deliver_tx(to, wire, txid)
            .await
            .map_err(Hold::Reply)?;
        if at_listing {
            info!(stage = Stage::S2.as_str(), "slate sent from a listing");
        } else {
            info!(stage = Stage::S2.as_str(), "slate sent");
        }
        Ok(())
    }

    /// Finalizes an S2 and posts it. A transaction that was finalized but not posted is
    /// settled: it waits in state `finalized` for [`Wallet::post`].
    /// An S2 finalized before, which arrives again when the receiver resent it, counts as
    /// repeated; finalizing it again posts only if the first post did not succeed.
    async fn complete(
        &self,
        method: &Arc<dyn Method>,
        msg_id: Option<&str>,
        envelope: &Envelope,
        reply: &Slate,
        reply_to: &Destination,
    ) -> Result<Handled, Settlement> {
        let session = self.session().map_err(Hold::from)?;
        let slate_id = Uuid::from_bytes(*reply.id().as_bytes());
        let finalized_before = self
            .blocking(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.slate(slate_id, SlateStage::Standard3))?
                    .is_some())
            })
            .await
            .map_err(Hold::from)?;
        let handled = if finalized_before {
            Handled::Repeated
        } else {
            Handled::Finalized
        };
        let finalized = self
            .finalize_from(
                method,
                envelope.wire(),
                POST_PROPAGATION,
                Answerer::From(reply_to.clone()),
            )
            .await;
        match finalized {
            Ok(_) => Ok(handled),
            Err(
                FinalizeError::NotPosted { tx_id, source }
                | FinalizeError::InputsReorged { tx_id, source },
            ) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&source), "finalized transaction not posted");
                Ok(handled)
            }
            // Not reachable over Epicbox today: new Epicbox slates go out in the V2 shape,
            // which carries no TTL, so no S2 with a cutoff comes back. It becomes reachable
            // once an Epicbox codec that carries the TTL is used for new slates.
            Err(error @ FinalizeError::Expired { cutoff, .. }) => {
                if self.confirmed_at(cutoff).await? {
                    Err(Refusal::Finalize(error).into())
                } else {
                    Err(Hold::Finalize(error).into())
                }
            }
            Err(error @ FinalizeError::UnknownSlate { .. }) => {
                self.unknown_answer(msg_id, reply, Stage::S2, reply_to, Refusal::Finalize(error))
                    .await
            }
            Err(error) if finalize_is_permanent(&error) => Err(Refusal::Finalize(error).into()),
            Err(error) => Err(Hold::Finalize(error).into()),
        }
    }

    /// Checks the open receipt caps before a new S1 from `reply_to` is received. A slate id
    /// received before passes, so its stored S2 is sent again. Over the sender's cap or at
    /// [`crate::config::WalletPolicy::max_open_receipts`] the S1 is refused; nothing is
    /// cancelled to make room. At the payments address, not a listing, a wallet that refuses
    /// payments nobody asked for refuses every new S1 and sends nothing back (ADR 0062).
    async fn make_room_for(
        &self,
        method: &Arc<dyn Method>,
        proposal: &Slate,
        reply_to: &Destination,
        listing: Option<Listing>,
    ) -> Result<(), Settlement> {
        let slate_id = Uuid::from_bytes(*proposal.id().as_bytes());
        let network = self.config().network;
        // The key part of an address alone identifies a sender; text that is no address of
        // the method is compared whole.
        let key_of = |address: &str| {
            method
                .peer_key(network, address)
                .unwrap_or_else(|_| address.to_owned())
        };
        let key = key_of(reply_to.as_str());
        let sender = Sender {
            key: &key,
            key_of: &key_of,
        };
        let refuse = listing.is_none() && self.config().policy.refuse_unsolicited_payments;
        match self
            .make_room(Pool::Transport(method.id()), slate_id, Some(sender), refuse)
            .await
        {
            Ok(()) => Ok(()),
            Err(NoRoom::Refused) => {
                info!(slate_id = %proposal.id(), "payment nobody asked for refused");
                Err(Refusal::Unsolicited.into())
            }
            Err(NoRoom::FromSender) => Err(Refusal::OpenReceiptsFromSender.into()),
            Err(NoRoom::Full) => Err(Refusal::OpenReceipts.into()),
            Err(NoRoom::Wallet(error)) => Err(Hold::Wallet(error).into()),
        }
    }
}

/// Settles a message that is not a stock slate of this lane: acknowledged and dropped, with one
/// line that leaves its content out. `stage` is the stage of a slate that decoded.
pub(super) fn dropped(msg_id: Option<&str>, stage: Option<Stage>) -> Handled {
    debug!(
        reason = "not a stock slate",
        msg_id = msg_id.unwrap_or(""),
        stage = stage.map_or("", |stage| stage.as_str()),
        "epicbox message dropped"
    );
    Handled::Dropped
}
