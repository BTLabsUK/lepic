// SPDX-License-Identifier: Apache-2.0
//! Invoices received on the invoice address and waiting for the user, and that address's index.
//!
//! The slate bytes of a pending invoice are sealed under the private context key, with the slate
//! id and the sender key as associated data, so a row edited to name another sender does not open.

use std::fmt;

use jiff::Timestamp;
use uuid::Uuid;

use crate::context::{self, ContextKey, SealFailure};
use crate::encoding::stored_enum;
use crate::error::{Record, StoreError};

/// Parked invoices kept at once, over every sender. Parking one more fails with
/// [`StoreError::InvoiceCapReached`].
pub const MAX_PARKED_INVOICES: usize = 100;

/// Parked invoices kept at once from one sender key.
pub const MAX_PARKED_INVOICES_PER_SENDER: usize = 10;

stored_enum! {
    pub enum PendingInvoiceStatus {
        /// Received and stored; nothing was paid.
        Parked => "parked",
        /// The user paid it; the reply may still need delivering.
        Paid => "paid",
        /// The user declined it.
        Declined => "declined",
    }
}

/// Which cap refused a parked invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceCap {
    Total,
    PerSender,
}

impl fmt::Display for InvoiceCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Total => "total",
            Self::PerSender => "per-sender",
        })
    }
}

/// An invoice slate received from an allowlisted sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInvoice {
    pub slate_id: Uuid,
    /// The Epicbox public key the relay authenticated the message with.
    pub sender_key: String,
    /// The full address the sender is known by, where replies go.
    pub sender_address: String,
    pub received_at: Timestamp,
    pub status: PendingInvoiceStatus,
    pub codec: String,
    pub bytes: Vec<u8>,
}

/// An Epicbox address index of the invoice identity. Index 0 is the payments address, so it is
/// never an invoice address index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvoiceAddressIndex(u32);

impl InvoiceAddressIndex {
    pub const FIRST: Self = Self(1);

    /// `None` for index 0.
    pub const fn new(index: u32) -> Option<Self> {
        if index == 0 { None } else { Some(Self(index)) }
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    /// The index rotation moves to; `None` past `u32::MAX`.
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(index) => Some(Self(index)),
            None => None,
        }
    }
}

pub trait InvoiceRepository {
    /// Stores a received invoice, whose status must be [`PendingInvoiceStatus::Parked`]. Fails
    /// with [`StoreError::Duplicate`] when one with the slate id is stored, with
    /// [`StoreError::InvalidStatus`] for any other status, and with
    /// [`StoreError::InvoiceCapReached`] when parking it would pass [`MAX_PARKED_INVOICES`] or
    /// [`MAX_PARKED_INVOICES_PER_SENDER`].
    fn park_invoice(&mut self, invoice: &PendingInvoice) -> Result<(), StoreError>;

    fn pending_invoice(&self, slate_id: Uuid) -> Result<Option<PendingInvoice>, StoreError>;

    /// Every stored invoice, oldest first.
    fn pending_invoices(&self) -> Result<Vec<PendingInvoice>, StoreError>;

    /// Moves a parked invoice to paid or declined. Fails with [`StoreError::NotFound`] when no
    /// invoice with the slate id is stored, and with [`StoreError::InvalidStatus`] for any other
    /// change, so a settled invoice never counts against the caps again.
    fn set_pending_invoice_status(
        &mut self,
        slate_id: Uuid,
        status: PendingInvoiceStatus,
    ) -> Result<(), StoreError>;

    /// Removes the invoice if it is stored.
    fn delete_pending_invoice(&mut self, slate_id: Uuid) -> Result<(), StoreError>;

    /// Removes every parked invoice received before `received_before`, and returns how many were
    /// removed. Paid and declined ones stay.
    fn prune_parked_invoices(&mut self, received_before: Timestamp) -> Result<usize, StoreError>;

    /// The current invoice address index, `None` until one is set.
    fn invoice_address_index(&self) -> Result<Option<InvoiceAddressIndex>, StoreError>;

    fn set_invoice_address_index(&mut self, index: InvoiceAddressIndex) -> Result<(), StoreError>;
}

const INVALID_STATUS: StoreError = StoreError::InvalidStatus {
    record: Record::PendingInvoice,
};

/// Checks the status and the caps against the parked invoices already stored, before `invoice`
/// joins them.
pub(crate) fn check_parkable(
    invoice: &PendingInvoice,
    parked_total: usize,
    parked_from_sender: usize,
) -> Result<(), StoreError> {
    if invoice.status != PendingInvoiceStatus::Parked {
        return Err(INVALID_STATUS);
    }
    if parked_total >= MAX_PARKED_INVOICES {
        return Err(StoreError::InvoiceCapReached {
            cap: InvoiceCap::Total,
        });
    }
    if parked_from_sender >= MAX_PARKED_INVOICES_PER_SENDER {
        return Err(StoreError::InvoiceCapReached {
            cap: InvoiceCap::PerSender,
        });
    }
    Ok(())
}

/// Only a parked invoice changes status, and only to paid or declined.
pub(crate) fn check_status_change(
    from: PendingInvoiceStatus,
    to: PendingInvoiceStatus,
) -> Result<(), StoreError> {
    match (from, to) {
        (
            PendingInvoiceStatus::Parked,
            PendingInvoiceStatus::Paid | PendingInvoiceStatus::Declined,
        ) => Ok(()),
        _ => Err(INVALID_STATUS),
    }
}

const ASSOCIATED_DATA_DOMAIN: &[u8] = b"lepic-store pending invoice v1";

fn associated_data(slate_id: Uuid, sender_key: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        ASSOCIATED_DATA_DOMAIN
            .len()
            .saturating_add(16)
            .saturating_add(sender_key.len()),
    );
    data.extend_from_slice(ASSOCIATED_DATA_DOMAIN);
    data.extend_from_slice(slate_id.as_bytes());
    data.extend_from_slice(sender_key.as_bytes());
    data
}

fn sealing_error(failure: SealFailure) -> StoreError {
    let record = Record::PendingInvoice;
    match failure {
        SealFailure::Randomness(error) => StoreError::Randomness(error),
        SealFailure::Unsealable => StoreError::Unsealable { record },
        SealFailure::Malformed => StoreError::Corrupt {
            record,
            field: "sealed bytes",
        },
        SealFailure::Undecryptable => StoreError::Undecryptable { record },
    }
}

pub(crate) fn seal(key: &ContextKey, invoice: &PendingInvoice) -> Result<Vec<u8>, StoreError> {
    context::seal_bytes(
        key,
        &associated_data(invoice.slate_id, &invoice.sender_key),
        &invoice.bytes,
    )
    .map_err(sealing_error)
}

/// Fails with [`StoreError::Undecryptable`] under another key, or when the row was altered.
pub(crate) fn open(
    key: &ContextKey,
    slate_id: Uuid,
    sender_key: &str,
    sealed: &[u8],
) -> Result<Vec<u8>, StoreError> {
    context::open_bytes(key, &associated_data(slate_id, sender_key), sealed).map_err(sealing_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_zero_is_not_an_invoice_address_index() {
        assert_eq!(InvoiceAddressIndex::new(0), None);
        assert_eq!(
            InvoiceAddressIndex::new(1),
            Some(InvoiceAddressIndex::FIRST)
        );
        assert_eq!(
            InvoiceAddressIndex::FIRST
                .next()
                .map(InvoiceAddressIndex::get),
            Some(2)
        );
        assert_eq!(
            InvoiceAddressIndex::new(u32::MAX).and_then(InvoiceAddressIndex::next),
            None
        );
    }
}
