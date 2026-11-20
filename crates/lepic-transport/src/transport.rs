// SPDX-License-Identifier: Apache-2.0
//! The capabilities a transaction method offers (ADR 0003). A method implements [`Transport`]
//! and returns the capability traits it supports; the engine asks for the one it needs.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use lepic_slate::codec::WireSlate;

use crate::error::TransportError;
use crate::policy::FormatPolicy;

/// A future returned by the capability traits. Boxed so the traits stay usable as trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Stable name of a transaction method, stored with transactions and used in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportId(&'static str);

impl TransportId {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for TransportId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Where a delivering transport sends a slate, in that transport's own address syntax. The
/// transport parses it; nothing else interprets it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Destination(String);

impl Destination {
    pub const fn new(address: String) -> Self {
        Self(address)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Names one received envelope to its transport, so it can be acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AckToken(String);

impl AckToken {
    pub const fn new(token: String) -> Self {
        Self(token)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The id under which a relay keeps the messages of one transaction, so that either party can
/// cancel the transaction there. The sender of the first slate makes it with
/// [`Outbound::new_relay_txid`] and the other party answers under the same id. It is not the
/// slate id, and only the transport that made it reads it; the text is whatever that transport
/// checked it to be.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelayTxId(String);

impl RelayTxId {
    /// Keeps `id` as a relay transaction id. The transport that hands it out checks it first.
    pub const fn new(id: String) -> Self {
        Self(id)
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RelayTxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A wire slate received by an [`Inbound`] transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    ack_token: AckToken,
    reply_to: Option<Destination>,
    wire: WireSlate,
    relay_txid: Option<RelayTxId>,
}

impl Envelope {
    pub const fn new(ack_token: AckToken, reply_to: Option<Destination>, wire: WireSlate) -> Self {
        Self {
            ack_token,
            reply_to,
            wire,
            relay_txid: None,
        }
    }

    /// The envelope with the relay transaction id the sender gave its slate, if any.
    #[must_use]
    pub fn with_relay_txid(mut self, relay_txid: Option<RelayTxId>) -> Self {
        self.relay_txid = relay_txid;
        self
    }

    /// The relay transaction id the sender gave the slate, when the transport passed one on. A
    /// reply goes out under the same id, so that either party can cancel on the relay.
    pub const fn relay_txid(&self) -> Option<&RelayTxId> {
        self.relay_txid.as_ref()
    }

    pub const fn ack_token(&self) -> &AckToken {
        &self.ack_token
    }

    /// Where the sender expects the reply, when the transport tells.
    pub const fn reply_to(&self) -> Option<&Destination> {
        self.reply_to.as_ref()
    }

    pub const fn wire(&self) -> &WireSlate {
        &self.wire
    }
}

/// The length of one post as a transport puts it on the wire, and the most the transport
/// posts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PostedSize {
    /// The bytes posted.
    pub bytes: usize,
    /// The most bytes one post may have.
    pub limit: usize,
}

impl PostedSize {
    /// Whether the post is within the limit.
    pub const fn fits(&self) -> bool {
        self.bytes <= self.limit
    }
}

/// Delivers a wire slate to a destination.
pub trait Outbound: Send + Sync {
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>>;

    /// A fresh relay transaction id for a new transaction, or `None` when the transport keeps no
    /// transactions on a relay. The caller stores it before the first [`Self::deliver_tx`] and
    /// sends again under the same id.
    fn new_relay_txid(&self) -> Result<Option<RelayTxId>, TransportError> {
        Ok(None)
    }

    /// As [`Self::deliver`], with the slate filed under `txid` on a relay that keeps
    /// transactions. A transport or relay without them delivers it as [`Self::deliver`] does.
    fn deliver_tx<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
        txid: Option<&'a RelayTxId>,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        let _ = txid;
        self.deliver(to, wire)
    }

    /// The size of the post that carries a text of `len` bytes to `to`, or `None` when the
    /// transport posts without a limit or cannot tell (`to` is not one of its addresses).
    fn posted_size(&self, to: &Destination, len: usize) -> Option<PostedSize> {
        let _ = (to, len);
        None
    }

    /// The size of the post that carries a text of `len` bytes to this wallet's own address,
    /// as an answer comes back, or `None` as [`Self::posted_size`].
    fn reply_size(&self, len: usize) -> Option<PostedSize> {
        let _ = len;
        None
    }
}

/// How a cancel on the relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RelayCancelOutcome {
    /// The relay cancelled the transaction: it refuses its messages from now on and tells the
    /// other party.
    Cancelled,
    /// The relay did nothing: it does not know the transaction, or this address is not one of
    /// its parties.
    NotFoundOrNotParticipant,
    /// The relay cannot cancel transactions. Nothing was sent.
    Unsupported,
}

/// What a cancel on the relay reported.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RelayCancelReport {
    /// How the cancel ended.
    pub outcome: RelayCancelOutcome,
    /// Cancellations of other transactions the relay reported meanwhile. They stay
    /// unacknowledged on the relay, which reports them again to a listener.
    pub other_cancelled: Vec<RelayTxId>,
}

impl RelayCancelReport {
    pub const fn new(outcome: RelayCancelOutcome, other_cancelled: Vec<RelayTxId>) -> Self {
        Self {
            outcome,
            other_cancelled,
        }
    }
}

/// Cancels a transaction on the relay that keeps it, by the id it was delivered under.
pub trait RelayCancel: Send + Sync {
    fn cancel_on_relay<'a>(
        &'a self,
        txid: &'a RelayTxId,
    ) -> BoxFuture<'a, Result<RelayCancelReport, TransportError>>;
}

/// Hands out received envelopes. An envelope stays with the transport until it is
/// acknowledged, and one that is never acknowledged may be handed out again in a later session,
/// so the caller acknowledges only after the slate's effect is stored or it was rejected for good.
pub trait Inbound: Send + Sync {
    /// The next envelope, or `None` once every envelope available now has been handed out.
    fn next_envelope(&self) -> BoxFuture<'_, Result<Option<Envelope>, TransportError>>;

    fn acknowledge<'a>(&'a self, token: &'a AckToken) -> BoxFuture<'a, Result<(), TransportError>>;
}

/// Where a manual method puts or finds a slate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Location {
    File(PathBuf),
}

/// Export and import for methods where the user carries the slate, such as files.
pub trait Exchange: Send + Sync {
    fn export<'a>(
        &'a self,
        wire: &'a WireSlate,
        to: &'a Location,
    ) -> BoxFuture<'a, Result<(), TransportError>>;

    fn import<'a>(&'a self, from: &'a Location)
    -> BoxFuture<'a, Result<WireSlate, TransportError>>;
}

/// One transaction method: its id, its format policy and the capabilities it offers.
pub trait Transport: Send + Sync {
    fn id(&self) -> TransportId;

    fn policy(&self) -> &dyn FormatPolicy;

    fn outbound(&self) -> Option<&dyn Outbound> {
        None
    }

    fn inbound(&self) -> Option<&dyn Inbound> {
        None
    }

    fn exchange(&self) -> Option<&dyn Exchange> {
        None
    }

    /// Cancelling a transaction on the relay, for a transport whose relay keeps transactions.
    fn relay_cancel(&self) -> Option<&dyn RelayCancel> {
        None
    }
}
