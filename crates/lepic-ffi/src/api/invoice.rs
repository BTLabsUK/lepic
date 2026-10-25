//! The expiry of invoices. Invoices come only from paired contacts and go only to them (RFC
//! 0002 section 11.5): issuing, paying and declining them is in [`crate::api::contact`]. The
//! invoice address, its allowlist and invoices to Epicbox addresses are retired. An invoice by
//! file is issued, paid and finalized as any slate file is.

use crate::api::error::WalletError;
use crate::api::types::InvoiceSweep;
use crate::api::wallet::EpicWallet;

impl EpicWallet {
    /// Expires what invoices left unpaid; run it from time to time, for example after
    /// collecting. Invoices from contacts received more than `expiry_secs` ago and still
    /// waiting are deleted, and invoices this wallet issued that long ago and not paid are
    /// cancelled, each with an `InvoiceExpired` event. Payments of invoices whose time to live
    /// passed with the transaction neither on chain nor in the node's pool are listed in
    /// `cancellable`, unchanged.
    ///
    /// `expiry_secs` defaults to a day and may be at most two days. Fails with
    /// `InvalidArgument` for 0 or more than two days, `NodeUnreachable` when a payment past its
    /// time to live cannot be looked up, and as `cancel_transaction` does.
    pub async fn sweep_invoices(
        &self,
        expiry_secs: Option<u64>,
    ) -> Result<InvoiceSweep, WalletError> {
        self.run("sweep_invoices", |session| async move {
            session.sweep_invoices(expiry_secs).await
        })
        .await
    }
}
