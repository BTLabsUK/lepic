//! Peers the wallet knows by their Epicbox key: the invoice allowlist and what each peer is
//! proven to support.
//!
//! Both are keyed by the public key alone, because the relay authenticates the key of a message
//! and never its domain.

use jiff::Timestamp;

use crate::encoding::stored_enum;
use crate::error::StoreError;

/// A sender whose invoices the invoice address accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedPeer {
    pub key: String,
    /// The full address the user added, where replies and notices go.
    pub address: String,
    pub label: String,
    pub added_at: Timestamp,
}

stored_enum! {
    /// What a peer's own messages proved it supports.
    pub enum PeerSupport {
        /// A message from it carried the LEPIC marker, so it accepts LEPIC notices.
        Lepic => "lepic",
        /// It returned an invoice unchanged, so it neither pays invoices nor accepts notices.
        NoInvoices => "no-invoices",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCapability {
    pub key: String,
    pub support: PeerSupport,
    pub learned_at: Timestamp,
}

pub trait PeerRepository {
    /// Inserts the entry, or replaces the one with the same key.
    fn put_allowed_peer(&mut self, peer: &AllowedPeer) -> Result<(), StoreError>;

    fn allowed_peer(&self, key: &str) -> Result<Option<AllowedPeer>, StoreError>;

    /// Every entry, in the order they were added.
    fn allowed_peers(&self) -> Result<Vec<AllowedPeer>, StoreError>;

    /// Removes the entry, and returns whether one was stored.
    fn remove_allowed_peer(&mut self, key: &str) -> Result<bool, StoreError>;

    /// Inserts the capability, or replaces the one learned earlier for the same key.
    fn put_peer_capability(&mut self, capability: &PeerCapability) -> Result<(), StoreError>;

    fn peer_capability(&self, key: &str) -> Result<Option<PeerCapability>, StoreError>;
}
