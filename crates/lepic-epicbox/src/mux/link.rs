// SPDX-License-Identifier: Apache-2.0
//! One socket and what is lost with it: the requests waiting for an answer, the mail in
//! flight and the acknowledgements not yet sent.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use tokio::time::{Instant, Interval, sleep_until, timeout};

use crate::client::{Awaiting, ClientError};
use crate::frame::RelayMessageId;
use crate::mux_frame::{MuxChallenge, MuxClientFrame, MuxLimits};
use crate::session::{Connection, deadline_after};

use super::negotiate::Negotiated;

/// Requests sent and not yet answered. A relay that lets this many pile up is not answering.
const MAX_PENDING: usize = 1024;

/// Message ids kept to recognise a redelivery after an acknowledgement was lost.
const STORED_IDS: usize = 4096;

/// Ids of messages the handler stored, to recognise a redelivery after a lost acknowledgement.
#[derive(Default)]
pub(super) struct StoredIds {
    pub(super) order: VecDeque<RelayMessageId>,
    pub(super) set: HashSet<RelayMessageId>,
}

impl StoredIds {
    pub(super) fn contains(&self, id: &RelayMessageId) -> bool {
        self.set.contains(id)
    }

    pub(super) fn insert(&mut self, id: RelayMessageId) {
        if self.set.insert(id.clone()) {
            self.order.push_back(id);
            if self.order.len() > STORED_IDS
                && let Some(oldest) = self.order.pop_front()
            {
                self.set.remove(&oldest);
            }
        }
    }
}

/// Why a socket was given up.
pub(super) enum Lost {
    Client(ClientError),
    /// Waiting mail was never pushed.
    Stalled,
    /// The relay is draining.
    Shutdown,
    /// The connector's route changed.
    Rerouted,
    RateLimited {
        retry_after: Duration,
    },
}

impl From<ClientError> for Lost {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "{}", ErrorChain(error)),
            Self::Stalled => f.write_str("waiting mail was not pushed"),
            Self::Shutdown => f.write_str("relay is shutting down"),
            Self::Rerouted => f.write_str("route changed"),
            Self::RateLimited { retry_after } => {
                write!(f, "relay rate limited the session for {retry_after:?}")
            }
        }
    }
}

pub(super) enum PendingKind {
    Attach { indexes: Vec<usize> },
    Resume,
    Detach,
    Ack { ids: Vec<RelayMessageId> },
    Hold,
    Waiting,
}

pub(super) struct Pending {
    pub(super) kind: PendingKind,
    pub(super) deadline: Instant,
}

/// One socket's state. Lost with the socket.
pub(super) struct Link {
    pub(super) connection: Connection,
    pub(super) challenge: MuxChallenge,
    pub(super) limits: MuxLimits,
    pub(super) response_timeout: Duration,
    pub(super) pending: BTreeMap<u64, Pending>,
    pub(super) next_ref: u64,
    /// Mailboxes the relay accepted on this socket.
    pub(super) attached: HashSet<usize>,
    /// Messages handed to the handler and not yet acknowledged or held, by mailbox.
    pub(super) inflight: HashMap<RelayMessageId, usize>,
    pub(super) acks: Vec<RelayMessageId>,
    pub(super) ack_due: Option<Instant>,
    /// The first answer to an attach or resume has been seen.
    pub(super) ready: bool,
    pub(super) resume_pending: bool,
    /// A resume was refused: attach every mailbox with signatures.
    pub(super) fallback_attach: bool,
    pub(super) mails_seen: u64,
    /// The number of mails seen at the first of two suspicious checks.
    pub(super) stuck_at: Option<u64>,
    pub(super) probe_outstanding: bool,
}

impl Link {
    pub(super) fn new(
        connection: Connection,
        negotiated: Negotiated,
        response_timeout: Duration,
    ) -> Self {
        Self {
            connection,
            challenge: negotiated.challenge,
            limits: negotiated.limits,
            response_timeout,
            pending: BTreeMap::new(),
            next_ref: 0,
            attached: HashSet::new(),
            inflight: HashMap::new(),
            acks: Vec::new(),
            ack_due: None,
            ready: false,
            resume_pending: false,
            fallback_attach: false,
            mails_seen: 0,
            stuck_at: None,
            probe_outstanding: false,
        }
    }

    /// Sends the frame `build` makes, numbered, and expects an answer to it.
    pub(super) async fn send(
        &mut self,
        build: impl FnOnce(Option<String>) -> MuxClientFrame,
        kind: PendingKind,
    ) -> Result<(), Lost> {
        if self.pending.len() >= MAX_PENDING {
            return Err(Lost::Client(ClientError::Timeout {
                awaiting: Awaiting::Answer,
            }));
        }
        self.next_ref = self.next_ref.saturating_add(1);
        let reference = self.next_ref;
        let text = build(Some(reference.to_string()))
            .to_json()
            .map_err(|error| Lost::Client(ClientError::Frame(error)))?;
        timeout(self.response_timeout, self.connection.send_text(text))
            .await
            .map_err(|_| {
                Lost::Client(ClientError::Timeout {
                    awaiting: Awaiting::Answer,
                })
            })??;
        self.pending.insert(
            reference,
            Pending {
                kind,
                deadline: deadline_after(self.response_timeout),
            },
        );
        Ok(())
    }

    pub(super) fn take_pending(&mut self, reference: Option<&str>) -> Option<Pending> {
        let reference = reference?.parse::<u64>().ok()?;
        self.pending.remove(&reference)
    }

    pub(super) fn next_expiry(&self) -> Option<Instant> {
        self.pending.values().map(|pending| pending.deadline).min()
    }

    pub(super) fn forget_mailbox(&mut self, index: usize) -> bool {
        self.inflight.retain(|_, owner| *owner != index);
        self.attached.remove(&index)
    }
}

pub(super) async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

pub(super) async fn tick_opt(interval: &mut Option<Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}
