// SPDX-License-Identifier: Apache-2.0
//! One drain or listen of a source for a wallet: [`Run`] takes each message in order, hands it
//! to the engine until it settles, and acknowledges it.

use std::sync::{Arc, Mutex, PoisonError};

use lepic_epicbox::{Backoff, RELAY_RETENTION};
use lepic_node::NodeApi;
use lepic_primitives::error_chain::ErrorChain;
use lepic_transport::method::Method;
use lepic_transport::transport::Envelope;
use lepic_wallet::inbox::{
    Arrival, Handled, Hold, InboxError, InboxSummary, ListenHandle, Outcome, Requeue,
};
use lepic_wallet::namespace::Listing;
use lepic_wallet::{SecretVault, StoreOpener, Wallet};
use tracing::{debug, info, warn};

use super::source::{Item, Source};

/// When one drain or listen last pruned the relay inbox as a message settled.
#[derive(Default)]
pub(in crate::epicbox) struct PruneSchedule(Mutex<Option<jiff::Timestamp>>);

impl PruneSchedule {
    fn last(&self) -> Option<jiff::Timestamp> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, at: jiff::Timestamp) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(at);
    }
}

/// Settled messages are acknowledged; a held one is left for the relay to deliver again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Settled(Handled),
    Held,
}

/// One drain or listen of a source for a wallet.
///
/// A drain (`listen` is `None`) ends when the source has nothing more and stops at the first
/// held message. A listen goes on until its handle is stopped and retries a held message with
/// backoff.
pub(in crate::epicbox) struct Run<'a, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    wallet: &'a Wallet<N, S, V>,
    /// The method the engine answers over: at a listing, one that sends from its address.
    method: Arc<dyn Method>,
    source: Source<'a>,
    listen: Option<&'a ListenHandle>,
    /// The relay client's reconnect backoff also paces the retries of a held message.
    backoff: Backoff,
    pruning: PruneSchedule,
    listing: Option<Listing>,
}

impl<'a, N, S, V> Run<'a, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// A drain of `source` for the wallet's payments address.
    pub(in crate::epicbox) fn new(
        wallet: &'a Wallet<N, S, V>,
        method: Arc<dyn Method>,
        source: Source<'a>,
        backoff: Backoff,
    ) -> Self {
        Self {
            wallet,
            method,
            source,
            listen: None,
            backoff,
            pruning: PruneSchedule::default(),
            listing: None,
        }
    }

    /// Makes the run a listen that lasts until `handle` is stopped, or `None` for a drain.
    pub(in crate::epicbox) fn listening(mut self, handle: Option<&'a ListenHandle>) -> Self {
        self.listen = handle;
        self
    }

    /// Makes the run take the messages of the wallet's `listing` address.
    pub(in crate::epicbox) fn at_listing(mut self, listing: Listing) -> Self {
        self.listing = Some(listing);
        self
    }

    /// Takes and settles messages until the source has no more, the listen is stopped, or a
    /// message is held (a drain) or the listen is abandoned while retrying one. Fails when the
    /// source's connection fails.
    pub(in crate::epicbox) async fn consume(&self) -> Result<InboxSummary, InboxError> {
        let mut summary = InboxSummary::default();
        while let Some(item) = self.next_item().await? {
            match self.settle(&item).await {
                Some(handled) => summary.count(handled),
                None => {
                    self.source.keep(&item);
                    summary.held = summary.held.saturating_add(1);
                    break;
                }
            }
        }
        Ok(summary)
    }

    /// The next message to handle, rejections first. `None` when the run is over: a drain's
    /// source is empty, or a listen was stopped or its source ended.
    async fn next_item(&self) -> Result<Option<Item>, InboxError> {
        loop {
            if let Some(rejection) = self.source.next_rejection() {
                return Ok(Some(rejection));
            }
            let Some(handle) = self.listen else {
                if let Some(item) = self.source.next_envelope().await? {
                    return Ok(Some(item));
                }
                // A rejection may have arrived while no envelope did.
                return Ok(self.source.next_rejection());
            };
            let next = tokio::select! {
                biased;
                () = handle.stopped() => return Ok(None),
                next = self.source.next_envelope() => next,
            };
            if let Some(item) = next? {
                return Ok(Some(item));
            }
            tokio::select! {
                biased;
                () = handle.stopped() => return Ok(None),
                () = self.source.delivery_available() => {}
            }
            if self.source.has_ended() {
                return Ok(None);
            }
        }
    }

    /// Handles `item` until it settles, then acknowledges it. Returns `None` when it is held:
    /// at once in a drain, and in a listen once the listen is stopped while retrying.
    async fn settle(&self, item: &Item) -> Option<Handled> {
        let mut retries: u32 = 0;
        let handled = loop {
            let try_number = retries.saturating_add(1);
            let disposition = match self.listen {
                None => self.handle(item, try_number).await,
                Some(handle) => tokio::select! {
                    biased;
                    () = handle.abandoned() => return None,
                    disposition = self.handle(item, try_number) => disposition,
                },
            };
            match (disposition, self.listen) {
                (Disposition::Settled(handled), _) => break handled,
                (Disposition::Held, None) => return None,
                (Disposition::Held, Some(handle)) => {
                    retries = retries.saturating_add(1);
                    debug!(
                        attempt = retries,
                        msg_id = item.msg_id().unwrap_or(""),
                        "epicbox message retry scheduled"
                    );
                    tokio::select! {
                        biased;
                        () = handle.stopped() => return None,
                        () = tokio::time::sleep(self.backoff.ceiling(retries)) => {}
                    }
                }
            }
        };
        self.acknowledge(item, handled).await;
        Some(handled)
    }

    /// Acknowledges a settled item and tells the wallet. A listen tries again until the relay
    /// accepts it, because the relay delivers nothing else to the address while a message is
    /// unacknowledged. A drain whose acknowledgement fails has lost its connection; the relay
    /// delivers the message again later and its inbox entry settles it at once.
    async fn acknowledge(&self, item: &Item, handled: Handled) {
        let msg_id = item.msg_id().unwrap_or("");
        let mut attempt: u32 = 0;
        while let Err(error) = self.source.acknowledge(item).await {
            warn!(msg_id, error = %ErrorChain(&*error), "epicbox acknowledgement failed");
            let Some(handle) = self.listen else {
                return;
            };
            attempt = attempt.saturating_add(1);
            tokio::select! {
                biased;
                () = handle.abandoned() => return,
                () = tokio::time::sleep(self.backoff.ceiling(attempt)) => {}
            }
        }
        debug!(msg_id, "epicbox message settled");
        if let Some(msg_id) = item.msg_id() {
            self.wallet.arrival_acknowledged(msg_id, handled).await;
        }
    }

    /// Handles `item` on its try number `attempt`, counted from 1, and records how it settled.
    async fn handle(&self, item: &Item, attempt: u32) -> Disposition {
        let msg_id = item.msg_id();
        let log_id = msg_id.unwrap_or("");
        let outcome = match item {
            Item::Rejection(rejected) => {
                debug!(msg_id = log_id, error = ?rejected.reason, "epicbox rejection recorded");
                Ok(Handled::Rejected)
            }
            Item::Envelope(envelope, _) => self.handle_envelope(item, envelope, attempt).await,
        };
        let handled = match outcome {
            Ok(handled) => handled,
            Err(Hold::UnknownSlate) => {
                debug!(msg_id = log_id, "epicbox message held for another install");
                return Disposition::Held;
            }
            Err(hold) => {
                warn!(msg_id = log_id, error = %ErrorChain(&hold), "epicbox message held");
                return Disposition::Held;
            }
        };
        if let Some(msg_id) = msg_id {
            let recorded = self
                .wallet
                .arrival_settled(msg_id, handled, self.pruning.last(), RELAY_RETENTION)
                .await;
            match recorded {
                Ok(Some(pruned_at)) => self.pruning.record(pruned_at),
                Ok(None) => {}
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "epicbox message held");
                    return Disposition::Held;
                }
            }
        }
        Disposition::Settled(handled)
    }

    async fn handle_envelope(
        &self,
        item: &Item,
        envelope: &Envelope,
        attempt: u32,
    ) -> Result<Handled, Hold> {
        let arrival = Arrival {
            msg_id: item.msg_id(),
            envelope,
            attempt,
            listing: self.listing,
        };
        match self.wallet.arrived(&self.method, arrival).await {
            Ok(handled) => Ok(handled),
            Err(Outcome::Hold(hold)) => Err(hold),
            Err(Outcome::Requeue(answer)) => self.requeue(item, answer).await,
        }
    }

    /// Posts the message of `answer` back to the source's address for another install,
    /// then lets it be acknowledged. A post that fails holds the message, until it first
    /// arrived the engine's hold patience ago: then it is refused for good.
    async fn requeue(&self, item: &Item, answer: Requeue) -> Result<Handled, Hold> {
        let msg_id = item.msg_id().unwrap_or("");
        match self.source.requeue(item).await {
            Ok(()) => {
                let count = self.wallet.requeued(&answer).await;
                info!(
                    slate_id = %answer.slate_id,
                    stage = answer.stage.as_str(),
                    msg_id,
                    count,
                    "answer for an unknown slate requeued for another install"
                );
                Ok(Handled::Requeued)
            }
            Err(error) => {
                if !self.wallet.requeue_failed(item.msg_id()).await? {
                    return Err(Hold::Requeue(error));
                }
                warn!(
                    slate_id = %answer.slate_id,
                    stage = answer.stage.as_str(),
                    msg_id,
                    error = %ErrorChain(&*error),
                    "answer for an unknown slate not requeued"
                );
                warn!(
                    msg_id,
                    error = %ErrorChain(answer.refusal()),
                    "epicbox message rejected"
                );
                Ok(Handled::Rejected)
            }
        }
    }
}
