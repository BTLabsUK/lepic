// SPDX-License-Identifier: Apache-2.0
//! The port the engine uses a transaction method through: what the method's slates may carry,
//! how it encodes and decodes them, and how it tells peers apart. The engine calls a
//! [`Method`] and never names one.

use std::sync::Arc;

use lepic_primitives::params::Network;
/// What an encoder is told about the slate it encodes; a [`Method`] implementation takes it.
pub use lepic_slate::codec::EncodeContext;
use lepic_slate::codec::{CodecId, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;

#[cfg(feature = "legacy")]
use crate::codecs;
use crate::error::{FormatError, TransportError};
use crate::policy::encode_with;
use crate::transport::{Destination, Transport, TransportId};

/// What a slate this method carries may hold beyond the slate itself, decided before the
/// engine locks inputs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Carries {
    /// A LEPIC receiver may be given a key to seal its answer to (RFC 0002 5).
    pub reply_key: bool,
}

impl Carries {
    /// What a method's slates carry, from each fact.
    pub const fn new(reply_key: bool) -> Self {
        Self { reply_key }
    }
}

/// What the engine knows when it encodes a slate it built.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Sending {
    /// The wallet's network.
    pub network: Network,
    /// What this wallet's marker claims.
    pub features: u32,
    /// Derived only when [`Carries::reply_key`] is set.
    pub reply_key: Option<[u8; 32]>,
}

impl Sending {
    /// What the engine knows when it encodes, from each fact.
    pub const fn new(network: Network, features: u32, reply_key: Option<[u8; 32]>) -> Self {
        Self {
            network,
            features,
            reply_key,
        }
    }
}

/// What a received wire says about the wallet that sent it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SenderFacts {
    /// The wire carries the LEPIC marker: the sender runs LEPIC.
    pub marked: bool,
    /// The marker's claimed features.
    pub features: Option<u32>,
    /// The key the sender asks to be answered under.
    pub reply_key: Option<[u8; 32]>,
}

impl SenderFacts {
    /// What a wire says about its sender, from each fact.
    pub const fn new(marked: bool, features: Option<u32>, reply_key: Option<[u8; 32]>) -> Self {
        Self {
            marked,
            features,
            reply_key,
        }
    }
}

/// A slate as it goes out, with the codec the engine records next to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// The encoded slate.
    pub wire: WireSlate,
    /// The codec that wrote it.
    pub codec: CodecId,
}

/// The codecs the [`Method`] defaults use: the plain legacy codecs at the network's base fee.
#[cfg(feature = "legacy")]
fn default_codecs(network: Network) -> CodecRegistry {
    codecs::legacy(network.params().default_base_fee())
}

/// Without the legacy formats the defaults hold no codec: decoding reports an unknown format
/// and encoding a codec that is not registered.
#[cfg(not(feature = "legacy"))]
fn default_codecs(_network: Network) -> CodecRegistry {
    CodecRegistry::new()
}

/// The method's side of a slate. The defaults speak plain legacy slates through the method's
/// format policy; a method with marker codecs overrides the encoders.
pub trait Method: Transport {
    /// What the method's slates may carry.
    fn carries(&self) -> Carries;

    /// Decodes `wire` with the method's detection order at the network's base fee.
    fn decode(&self, network: Network, wire: &WireSlate) -> Result<Slate, DecodeError> {
        self.policy().decode(&default_codecs(network), wire)
    }

    /// What `wire` says about its sender.
    fn sender_facts(&self, _wire: &WireSlate) -> SenderFacts {
        SenderFacts::default()
    }

    /// A slate this wallet starts: an S1 or an I1.
    fn encode_new(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
    ) -> Result<Encoded, FormatError> {
        let codecs = default_codecs(sending.network);
        let encoding = self.policy().for_new_slate(slate, context);
        let wire = encode_with(&codecs, encoding, slate, context)?;
        Ok(Encoded {
            wire,
            codec: encoding.codec,
        })
    }

    /// The answer to a received slate: an S2 or an I2, in the shape of what it answers.
    fn encode_reply(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
        _from: &SenderFacts,
    ) -> Result<Encoded, FormatError> {
        let codecs = default_codecs(sending.network);
        let encoding = self.policy().for_reply(slate, context);
        let wire = encode_with(&codecs, encoding, slate, context)?;
        Ok(Encoded {
            wire,
            codec: encoding.codec,
        })
    }

    /// The lengths a notice sent over this method is padded to, one drawn per notice so its
    /// size does not tell it from a payment. Empty when the method sends no notices: the
    /// engine then withholds them.
    fn notice_lengths(&self) -> &'static [usize];

    /// The key an address of this method names, as peers are told apart. Fails with
    /// [`TransportError::UnknownDestination`] when the method has no notion of a peer key, and
    /// with [`TransportError::InvalidDestination`] for an address it cannot read.
    fn peer_key(&self, _network: Network, _address: &str) -> Result<String, TransportError> {
        Err(TransportError::UnknownDestination {
            transport: self.id(),
        })
    }

    /// Whether `to` and `allowed` name the same peer. A method with no peer key never matches.
    fn same_payee(&self, network: Network, to: &Destination, allowed: &str) -> bool {
        match (
            self.peer_key(network, to.as_str()),
            self.peer_key(network, allowed),
        ) {
            (Ok(to), Ok(allowed)) => to == allowed,
            _ => false,
        }
    }

    /// Whether a [`TransportError::Backend`] failure of this method's delivery would meet the
    /// same reply again, so holding the message for another try gains nothing. The engine
    /// decides the other variants itself.
    fn delivery_is_permanent(&self, _error: &TransportError) -> bool {
        false
    }
}

/// The methods a consumer offers, as the engine finds the one a stored payment went over.
pub trait MethodLookup: Send + Sync {
    /// The method whose id reads `name`, as a payment stores it.
    fn method_named(&self, name: &str) -> Option<Arc<dyn Method>>;

    /// The method registered under `id`.
    fn method(&self, id: &TransportId) -> Option<Arc<dyn Method>> {
        self.method_named(id.as_str())
    }
}
