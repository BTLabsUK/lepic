// SPDX-License-Identifier: Apache-2.0
//! Two in-memory transports wired to each other, for engine tests. What one delivers, the
//! other receives, with the relay's acknowledgement rules: an envelope handed out but not
//! acknowledged comes back after [`LoopbackTransport::redeliver_unacknowledged`].

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lepic_slate::codec::WireSlate;

use crate::error::TransportError;
use crate::method::{Carries, Method};
use crate::policy::FormatPolicy;
use crate::transport::{
    AckToken, BoxFuture, Destination, Envelope, Inbound, Outbound, Transport, TransportId,
};

/// One end of a loopback pair.
pub struct LoopbackTransport {
    id: TransportId,
    policy: Arc<dyn FormatPolicy>,
    address: Destination,
    peer_address: Destination,
    inbox: Arc<Mailbox>,
    peer_inbox: Arc<Mailbox>,
}

impl LoopbackTransport {
    /// Two ends with the given addresses, both under `id` and `policy`.
    pub fn pair(
        id: TransportId,
        policy: Arc<dyn FormatPolicy>,
        first_address: Destination,
        second_address: Destination,
    ) -> (Self, Self) {
        let first_inbox = Arc::new(Mailbox::default());
        let second_inbox = Arc::new(Mailbox::default());
        let first = Self {
            id,
            policy: Arc::clone(&policy),
            address: first_address.clone(),
            peer_address: second_address.clone(),
            inbox: Arc::clone(&first_inbox),
            peer_inbox: Arc::clone(&second_inbox),
        };
        let second = Self {
            id,
            policy,
            address: second_address,
            peer_address: first_address,
            inbox: second_inbox,
            peer_inbox: first_inbox,
        };
        (first, second)
    }

    pub const fn address(&self) -> &Destination {
        &self.address
    }

    /// Returns every envelope handed out but not acknowledged to the front of the inbox, in
    /// delivery order, as a relay does when a client reconnects.
    pub fn redeliver_unacknowledged(&self) {
        let mut state = self.inbox.lock();
        let mut returned = std::mem::take(&mut state.in_flight);
        returned.append(&mut state.queued);
        state.queued = returned;
    }

    /// Envelopes delivered to this end and not yet acknowledged.
    pub fn unacknowledged(&self) -> usize {
        let state = self.inbox.lock();
        state.queued.len().saturating_add(state.in_flight.len())
    }
}

impl std::fmt::Debug for LoopbackTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackTransport")
            .field("id", &self.id)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Method for LoopbackTransport {
    fn carries(&self) -> Carries {
        Carries::default()
    }

    fn notice_lengths(&self) -> &'static [usize] {
        &[]
    }
}

impl Transport for LoopbackTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    fn policy(&self) -> &dyn FormatPolicy {
        self.policy.as_ref()
    }

    fn outbound(&self) -> Option<&dyn Outbound> {
        Some(self)
    }

    fn inbound(&self) -> Option<&dyn Inbound> {
        Some(self)
    }
}

impl Outbound for LoopbackTransport {
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if *to != self.peer_address {
                return Err(TransportError::UnknownDestination { transport: self.id });
            }
            self.peer_inbox.deliver(self.address.clone(), wire.clone());
            Ok(())
        })
    }
}

impl Inbound for LoopbackTransport {
    fn next_envelope(&self) -> BoxFuture<'_, Result<Option<Envelope>, TransportError>> {
        Box::pin(async move { Ok(self.inbox.hand_out()) })
    }

    fn acknowledge<'a>(&'a self, token: &'a AckToken) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if self.inbox.acknowledge(token) {
                Ok(())
            } else {
                Err(TransportError::UnknownAcknowledgement { transport: self.id })
            }
        })
    }
}

#[derive(Default)]
struct Mailbox {
    state: Mutex<MailboxState>,
}

#[derive(Default)]
struct MailboxState {
    queued: VecDeque<Envelope>,
    in_flight: VecDeque<Envelope>,
    delivered: u64,
}

impl Mailbox {
    // A panic while the lock is held leaves the queues consistent, so a poisoned lock is
    // still safe to use.
    fn lock(&self) -> MutexGuard<'_, MailboxState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn deliver(&self, from: Destination, wire: WireSlate) {
        let mut state = self.lock();
        state.delivered = state.delivered.wrapping_add(1);
        let token = AckToken::new(state.delivered.to_string());
        state
            .queued
            .push_back(Envelope::new(token, Some(from), wire));
    }

    fn hand_out(&self) -> Option<Envelope> {
        let mut state = self.lock();
        let envelope = state.queued.pop_front()?;
        state.in_flight.push_back(envelope.clone());
        Some(envelope)
    }

    fn acknowledge(&self, token: &AckToken) -> bool {
        let mut state = self.lock();
        let Some(index) = state
            .in_flight
            .iter()
            .position(|envelope| envelope.ack_token() == token)
        else {
            return false;
        };
        state.in_flight.remove(index).is_some()
    }
}

#[cfg(test)]
mod tests {
    use lepic_slate::codec::MediaType;

    use super::*;
    use crate::file::FilePolicy;

    fn pair() -> (LoopbackTransport, LoopbackTransport) {
        LoopbackTransport::pair(
            TransportId::new("loopback"),
            Arc::new(FilePolicy),
            Destination::new("alice".to_owned()),
            Destination::new("bob".to_owned()),
        )
    }

    fn wire(text: &str) -> WireSlate {
        WireSlate::text(MediaType::JSON, text.to_owned())
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn delivered_slate_reaches_the_peer_with_the_sender_as_reply_address() {
        block_on(async {
            let (alice, bob) = pair();
            alice.deliver(bob.address(), &wire("one")).await.unwrap();

            let envelope = bob.next_envelope().await.unwrap().unwrap();
            assert_eq!(envelope.wire(), &wire("one"));
            assert_eq!(envelope.reply_to(), Some(alice.address()));
            assert!(bob.next_envelope().await.unwrap().is_none());
            assert!(alice.next_envelope().await.unwrap().is_none());
        });
    }

    #[test]
    fn rejects_delivery_to_an_unknown_destination() {
        block_on(async {
            let (alice, _bob) = pair();
            let error = alice
                .deliver(&Destination::new("carol".to_owned()), &wire("one"))
                .await
                .unwrap_err();
            assert!(matches!(error, TransportError::UnknownDestination { .. }));
        });
    }

    #[test]
    fn unacknowledged_envelopes_are_redelivered_in_order_and_acknowledged_ones_are_not() {
        block_on(async {
            let (alice, bob) = pair();
            for text in ["one", "two", "three"] {
                alice.deliver(bob.address(), &wire(text)).await.unwrap();
            }
            let one = bob.next_envelope().await.unwrap().unwrap();
            let two = bob.next_envelope().await.unwrap().unwrap();
            bob.acknowledge(one.ack_token()).await.unwrap();
            assert_eq!(bob.unacknowledged(), 2);

            bob.redeliver_unacknowledged();
            assert_eq!(bob.next_envelope().await.unwrap(), Some(two));
            let three = bob.next_envelope().await.unwrap().unwrap();
            assert_eq!(three.wire(), &wire("three"));
            assert!(bob.next_envelope().await.unwrap().is_none());
        });
    }

    #[test]
    fn rejects_an_acknowledgement_twice_or_before_hand_out() {
        block_on(async {
            let (alice, bob) = pair();
            alice.deliver(bob.address(), &wire("one")).await.unwrap();
            let early = AckToken::new("1".to_owned());
            assert!(matches!(
                bob.acknowledge(&early).await.unwrap_err(),
                TransportError::UnknownAcknowledgement { .. }
            ));

            let envelope = bob.next_envelope().await.unwrap().unwrap();
            bob.acknowledge(envelope.ack_token()).await.unwrap();
            assert!(matches!(
                bob.acknowledge(envelope.ack_token()).await.unwrap_err(),
                TransportError::UnknownAcknowledgement { .. }
            ));
            assert_eq!(bob.unacknowledged(), 0);
        });
    }
}
