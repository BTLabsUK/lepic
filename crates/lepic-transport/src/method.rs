// SPDX-License-Identifier: Apache-2.0
//! The port the engine uses a transaction method through: what the method's slates may carry,
//! how it encodes and decodes them, and how it tells peers apart. The engine calls a
//! [`Method`] and never names one.

use lepic_primitives::params::Network;
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;

use crate::codecs;
use crate::error::FormatError;
use crate::policy::encode_with;
use crate::transport::{Destination, Transport};

/// What a slate this method carries may hold beyond the slate itself, decided before the
/// engine locks inputs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Carries {
    /// A LEPIC receiver may be given a key to seal its answer to (RFC 0002 5).
    pub reply_key: bool,
}

/// What the engine knows when it encodes a slate it built.
#[derive(Debug, Clone, Copy)]
pub struct Sending {
    /// The wallet's network.
    pub network: Network,
    /// What this wallet's marker claims.
    pub features: u32,
    /// Derived only when [`Carries::reply_key`] is set.
    pub reply_key: Option<[u8; 32]>,
}

/// What a received wire says about the wallet that sent it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SenderFacts {
    /// The wire carries the LEPIC marker: the sender runs LEPIC.
    pub marked: bool,
    /// The marker's claimed features.
    pub features: Option<u32>,
    /// The key the sender asks to be answered under.
    pub reply_key: Option<[u8; 32]>,
}

/// A slate as it goes out, with the codec the engine records next to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// The encoded slate.
    pub wire: WireSlate,
    /// The codec that wrote it.
    pub codec: CodecId,
}

/// The method's side of a slate. The defaults speak plain legacy slates through the method's
/// format policy; a method with marker codecs overrides the encoders.
pub trait Method: Transport {
    /// What the method's slates may carry.
    fn carries(&self) -> Carries;

    /// Decodes `wire` with the method's detection order at the network's base fee.
    fn decode(&self, network: Network, wire: &WireSlate) -> Result<Slate, DecodeError> {
        self.policy()
            .decode(&codecs::legacy(network.params().default_base_fee()), wire)
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
        let codecs = codecs::legacy(sending.network.params().default_base_fee());
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
        let codecs = codecs::legacy(sending.network.params().default_base_fee());
        let encoding = self.policy().for_reply(slate, context);
        let wire = encode_with(&codecs, encoding, slate, context)?;
        Ok(Encoded {
            wire,
            codec: encoding.codec,
        })
    }

    /// The key an address of this method names, as peers are told apart. `None` when the
    /// method has no notion of a peer key.
    fn peer_key(&self, _network: Network, _address: &str) -> Option<String> {
        None
    }

    /// Whether `to` and `allowed` name the same peer. A method with no peer key never matches.
    fn same_payee(&self, network: Network, to: &Destination, allowed: &str) -> bool {
        let key = self.peer_key(network, to.as_str());
        key.is_some() && key == self.peer_key(network, allowed)
    }
}
