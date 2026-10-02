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

/// A wire slate received by an [`Inbound`] transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    ack_token: AckToken,
    reply_to: Option<Destination>,
    wire: WireSlate,
}

impl Envelope {
    pub const fn new(ack_token: AckToken, reply_to: Option<Destination>, wire: WireSlate) -> Self {
        Self {
            ack_token,
            reply_to,
            wire,
        }
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

/// Delivers a wire slate to a destination.
pub trait Outbound: Send + Sync {
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>>;
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
}
