//! What each peer is proven to support, keyed by its Epicbox public key alone, because the relay
//! authenticates the key of a message and never its domain.

use jiff::Timestamp;

use crate::encoding::stored_enum;
use crate::error::StoreError;

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
    /// Inserts the capability, or replaces the one learned earlier for the same key.
    fn put_peer_capability(&mut self, capability: &PeerCapability) -> Result<(), StoreError>;

    fn peer_capability(&self, key: &str) -> Result<Option<PeerCapability>, StoreError>;
}
