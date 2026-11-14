// SPDX-License-Identifier: Apache-2.0
//! What a subscription shares with its handle: the messages and rejections waiting to be
//! handed out, and what was acknowledged.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};

use lepic_slate::codec::WireSlate;
use lepic_transport::transport::{AckToken, Destination, Envelope};
use tokio::sync::{Notify, mpsc, watch};

use crate::client::ClientError;
use crate::frame::RelayMessageId;
use crate::session::ProtocolVersion;

use super::manager::Command;
use super::{
    ConnectionState, Disconnect, DrainConnection, InboxCounters, Mode, Rejection, RejectionReason,
};

/// Acknowledged message ids remembered per subscription, so a redelivery after a lost `Made`
/// is acknowledged again instead of handed out twice.
const REMEMBERED_ACKNOWLEDGEMENTS: usize = 4096;

/// Received messages and rejections waiting to be handed out. Beyond this a relay that pushes
/// faster than the wallet consumes gets no acknowledgement, so it keeps the message for later.
const MAX_READY: usize = 64;

/// Bytes of received messages waiting to be handed out. A message is admitted while the queue
/// is empty or its encrypted text still fits, so one message of the largest size always gets
/// through and a phone never holds much more than this in decrypted messages.
const MAX_READY_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct Shared {
    pub(super) inbox: Mutex<InboxState>,
    pub(super) changed: Notify,
    pub(super) commands: mpsc::UnboundedSender<Command>,
    pub(super) status: watch::Sender<ConnectionState>,
    pub(super) disconnect: Mutex<Option<Disconnect>>,
    /// The connection a quiet drain handed back, until [`Subscription::take_connection`](super::Subscription::take_connection).
    pub(super) carried: Mutex<Option<DrainConnection>>,
}

impl Shared {
    // Every update leaves the state consistent before it can panic, so a poisoned lock is still
    // safe to use.
    pub(super) fn lock(&self) -> MutexGuard<'_, InboxState> {
        self.inbox.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn update<T>(&self, change: impl FnOnce(&mut InboxState) -> T) -> T {
        let result = change(&mut self.lock());
        self.changed.notify_waiters();
        result
    }

    pub(super) fn set_state(&self, state: ConnectionState) {
        self.update(|inbox| inbox.state = state);
        self.status.send_replace(state);
    }
}

/// What a handed-out token stands for. A message the relay stored is acknowledged by its relay id;
/// one it sent without an id has only a local number and nothing to acknowledge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Delivery {
    Relay(RelayMessageId),
    Local(u64),
}

impl Delivery {
    pub(super) fn relay_id(&self) -> Option<&RelayMessageId> {
        match self {
            Self::Relay(msg_id) => Some(msg_id),
            Self::Local(_) => None,
        }
    }

    /// A relay message's token is its id. A local token contains `:`, which no
    /// [`RelayMessageId`] contains, so the two never collide.
    pub(super) fn ack_token(&self) -> AckToken {
        match self {
            Self::Relay(msg_id) => AckToken::new(msg_id.to_string()),
            Self::Local(number) => AckToken::new(format!("local:{number}")),
        }
    }
}

/// The `from`, `str` and `signature` of a received `Slate` frame, as the relay sent them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Signed {
    pub(super) from: String,
    pub(super) str: String,
    pub(super) signature: String,
}

/// How a received message id relates to what this subscription has seen.
pub(super) enum Seen {
    New,
    Held,
    Acknowledged,
}

pub(super) struct InboxState {
    pub(super) state: ConnectionState,
    pub(super) counters: InboxCounters,
    /// Whether the relay may still deliver without the caller doing anything.
    pub(super) expecting: bool,
    pub(super) relay_version: Option<ProtocolVersion>,
    pub(super) ready: VecDeque<(Delivery, Envelope, Signed)>,
    /// The total length of the slates in `ready`.
    pub(super) ready_bytes: usize,
    pub(super) rejected: VecDeque<Rejection>,
    /// Handed-out envelopes and rejections by token, with what acknowledging them means.
    pub(super) handed_out: HashMap<AckToken, Delivery>,
    /// The message as its sender signed it, for each handed-out envelope.
    pub(super) signed: HashMap<AckToken, Signed>,
    pub(super) acknowledged: HashSet<RelayMessageId>,
    pub(super) acknowledged_order: VecDeque<RelayMessageId>,
    pub(super) local_tokens: u64,
}

impl InboxState {
    pub(super) fn new() -> Self {
        Self {
            state: ConnectionState::Connecting { attempt: 1 },
            counters: InboxCounters::default(),
            expecting: true,
            relay_version: None,
            ready: VecDeque::new(),
            ready_bytes: 0,
            rejected: VecDeque::new(),
            handed_out: HashMap::new(),
            signed: HashMap::new(),
            acknowledged: HashSet::new(),
            acknowledged_order: VecDeque::new(),
            local_tokens: 0,
        }
    }

    pub(super) fn take_envelope(
        &mut self,
        mode: Mode,
    ) -> Option<Result<Option<Envelope>, ClientError>> {
        if let Some((delivery, envelope, signed)) = self.ready.pop_front() {
            self.ready_bytes = self.ready_bytes.saturating_sub(envelope.wire().len());
            self.handed_out
                .insert(envelope.ack_token().clone(), delivery);
            self.signed.insert(envelope.ack_token().clone(), signed);
            return Some(Ok(Some(envelope)));
        }
        match self.state {
            ConnectionState::Stopped | ConnectionState::Drained => Some(Ok(None)),
            ConnectionState::Failed => Some(Err(ClientError::Ended)),
            ConnectionState::Subscribed if !self.expecting => Some(Ok(None)),
            ConnectionState::Waiting { .. } if mode == Mode::Listen => Some(Ok(None)),
            _ => None,
        }
    }

    pub(super) fn seen(&self, msg_id: &RelayMessageId) -> Seen {
        if self.acknowledged.contains(msg_id) {
            Seen::Acknowledged
        } else if self
            .handed_out
            .values()
            .chain(self.ready.iter().map(|(delivery, _, _)| delivery))
            .chain(self.rejected.iter().map(|rejection| &rejection.delivery))
            .any(|delivery| delivery.relay_id() == Some(msg_id))
        {
            Seen::Held
        } else {
            Seen::New
        }
    }

    pub(super) fn delivery_for(&mut self, msg_id: Option<RelayMessageId>) -> Delivery {
        match msg_id {
            Some(msg_id) => Delivery::Relay(msg_id),
            None => {
                self.local_tokens = self.local_tokens.wrapping_add(1);
                Delivery::Local(self.local_tokens)
            }
        }
    }

    pub(super) fn push(
        &mut self,
        msg_id: Option<RelayMessageId>,
        reply_to: Destination,
        wire: WireSlate,
        signed: Signed,
    ) {
        let delivery = self.delivery_for(msg_id);
        self.ready_bytes = self.ready_bytes.saturating_add(wire.len());
        let envelope = Envelope::new(delivery.ack_token(), Some(reply_to), wire);
        self.ready.push_back((delivery, envelope, signed));
    }

    pub(super) fn push_rejection(
        &mut self,
        msg_id: Option<RelayMessageId>,
        sender: Option<String>,
        reason: RejectionReason,
    ) {
        let delivery = self.delivery_for(msg_id);
        self.rejected.push_back(Rejection {
            ack_token: delivery.ack_token(),
            delivery,
            sender,
            reason,
        });
    }

    pub(super) fn waiting(&self) -> usize {
        self.ready.len().saturating_add(self.rejected.len())
    }

    /// Whether a message whose encrypted text is `sealed_len` bytes long fits. Its plaintext is
    /// shorter than that, so the check needs no decryption.
    pub(super) fn has_room_for(&self, sealed_len: usize) -> bool {
        self.waiting() < MAX_READY
            && (self.ready.is_empty()
                || self.ready_bytes.saturating_add(sealed_len) <= MAX_READY_BYTES)
    }

    pub(super) fn record_acknowledged(&mut self, msg_id: &RelayMessageId) {
        self.handed_out
            .retain(|_, delivery| delivery.relay_id() != Some(msg_id));
        let handed_out = &self.handed_out;
        self.signed
            .retain(|token, _| handed_out.contains_key(token));
        if self.acknowledged.insert(msg_id.clone()) {
            self.acknowledged_order.push_back(msg_id.clone());
        }
        while self.acknowledged_order.len() > REMEMBERED_ACKNOWLEDGEMENTS {
            if let Some(oldest) = self.acknowledged_order.pop_front() {
                self.acknowledged.remove(&oldest);
            }
        }
    }

    /// Nothing is waiting to be handed out or acknowledged.
    pub(super) fn is_settled(&self) -> bool {
        self.ready.is_empty() && self.rejected.is_empty() && self.handed_out.is_empty()
    }
}
