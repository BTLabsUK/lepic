//! Invoices by file, and the expiry of invoices. Invoices over Epicbox come only from paired
//! contacts and go only to them (RFC 0002 section 11.5): issuing, paying and declining those is
//! in [`crate::api::contact`]. Issuing by file is open to anyone: the I1 goes out as a file or
//! text, the payer answers with [`EpicWallet::pay_invoice_slate`] or
//! [`EpicWallet::pay_invoice_file`], and the issuer finalizes the I2 with
//! [`EpicWallet::finalize_and_post`] or [`EpicWallet::finalize_file`], as for a send.
//! [`crate::api::wallet::inspect_slate`] tells an I1 and an I2 apart from an S1 and an S2.

use std::path::PathBuf;

use crate::api::error::WalletError;
use crate::api::types::{InvoiceSweep, IssuedInvoice, PaidInvoiceSlate, SendOptions, Slate};
use crate::api::wallet::EpicWallet;

impl EpicWallet {
    /// Issuer side: issues an invoice for `amount`, what this wallet receives, and returns the
    /// I1 text for the payer, whose answer goes to [`EpicWallet::finalize_and_post`]. The
    /// invoice is stored as an incoming transaction waiting for payment;
    /// `cancel_transaction` withdraws it and [`EpicWallet::sweep_invoices`] expires it unpaid.
    ///
    /// `message` goes to the payer signed with the invoice, cut to its first 256 bytes on a
    /// character boundary.
    ///
    /// The I1 carries a time to live of 1,440 blocks, a day, from the node's tip: a payer
    /// refuses the invoice from then on, this wallet refuses to finalize a payment of it, and a
    /// refresh expires it unpaid.
    ///
    /// Fails with `InvalidArgument` for an amount of 0 and `NodeUnreachable` when the node's
    /// tip cannot be read; nothing is stored then.
    pub async fn issue_invoice_slate(
        &self,
        amount: u64,
        message: Option<String>,
    ) -> Result<Slate, WalletError> {
        self.run("issue_invoice_slate", |session| async move {
            session.issue_invoice_slate(amount, message).await
        })
        .await
    }

    /// [`EpicWallet::issue_invoice_slate`] writing the I1 to the file at `path`. Fails with
    /// `NotDelivered` when the file cannot be written; the invoice is stored then, and
    /// `cancel_transaction` withdraws it.
    pub async fn issue_invoice_file(
        &self,
        amount: u64,
        path: String,
        message: Option<String>,
    ) -> Result<IssuedInvoice, WalletError> {
        self.run("issue_invoice_file", |session| async move {
            session
                .issue_invoice_file(amount, PathBuf::from(path), message)
                .await
        })
        .await
    }

    /// Payer side: pays the invoice in the I1 text `slate_json` and returns the I2 for the
    /// issuer. Call it only after the user approved `amount`, which must be the invoiced amount;
    /// the fee comes on top. `minimum_confirmations`, `message` and `options` are as in
    /// `create_send_slate`. The inputs stay locked until the issuer posts the transaction or
    /// the payment is cancelled with `cancel_transaction`.
    ///
    /// An I1 from LEPIC may carry a reply key: `sealed_answer_to_marker` with the I1 and the
    /// returned I2 seals the answer to it.
    ///
    /// Fails with `InvalidSlate` for text that is not an I1 or whose message signature does not
    /// verify, `AmountMismatch`, `InvoiceAlreadyPaid` for an invoice this wallet paid before,
    /// `PaymentExpired` when the chain reached the invoice's time to live,
    /// `InvoiceNotForThisChain` when the invoice was made for another network or at a wrong
    /// height, `InvoiceLockedAboveTip`, `NotEnoughFunds` and `NodeUnreachable`. Nothing is
    /// stored then. A payment the issuer never finalizes, for example the second payment of one
    /// request, expires once the chain reaches the invoice's time to live, and a refresh then
    /// releases its inputs unless the node holds the transaction.
    pub async fn pay_invoice_slate(
        &self,
        slate_json: String,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PaidInvoiceSlate, WalletError> {
        self.run("pay_invoice_slate", |session| async move {
            session
                .pay_invoice_slate(slate_json, amount, minimum_confirmations, message, options)
                .await
        })
        .await
    }

    /// [`EpicWallet::pay_invoice_slate`] for the I1 file at `path`. The I2 is also written to
    /// `<path>.response`, as `epic-wallet` names it. Fails with `TransportFailed` when the file
    /// cannot be read, or when the response cannot be written; the payment is stored then, its
    /// I2 is in `contact_plain_fallback(tx_id)` and `cancel_transaction` gives it up.
    pub async fn pay_invoice_file(
        &self,
        path: String,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PaidInvoiceSlate, WalletError> {
        self.run("pay_invoice_file", |session| async move {
            session
                .pay_invoice_file(
                    &PathBuf::from(path),
                    amount,
                    minimum_confirmations,
                    message,
                    options,
                    true,
                )
                .await
        })
        .await
    }

    /// Expires what invoices left unpaid; run it from time to time, for example after
    /// collecting. Invoices from contacts received more than `expiry_secs` ago and still
    /// waiting are deleted, and invoices this wallet issued that long ago, to a contact or by
    /// file, and not paid are cancelled, each with an `InvoiceExpired` event. Payments of
    /// invoices whose time to live passed with the transaction neither on chain nor in the
    /// node's pool are listed in `cancellable`, unchanged.
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
