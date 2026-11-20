// SPDX-License-Identifier: Apache-2.0
//! A sender check the engine supplies for an address that accepts only known senders.

use lepic_crypto::PublicKey;

/// What a [`Prefilter`] decided about a received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Admission {
    Accept,
    /// Acknowledge the message and forget it.
    Drop,
}

/// Decides from the sender's key alone whether a received message is worth opening.
///
/// It runs before the signature check, key agreement and decryption, so it sees the key the
/// message claims to come from, not a proven one. It runs on the subscription's task for every
/// message, so it must answer from memory without blocking. A message whose `from` is not an
/// address on the client's network is dropped without asking.
pub trait Prefilter: Send + Sync {
    fn admit(&self, sender: &PublicKey) -> Admission;
}

impl<F> Prefilter for F
where
    F: Fn(&PublicKey) -> Admission + Send + Sync,
{
    fn admit(&self, sender: &PublicKey) -> Admission {
        self(sender)
    }
}
