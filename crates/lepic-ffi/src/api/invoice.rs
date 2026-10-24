//! Invoices over Epicbox. A service issues an invoice, the payer pays it with one call, and the
//! service finalizes and posts. Nothing that arrives ever pays: paying is always
//! [`EpicWallet::pay_invoice`].
//!
//! The invoice address and its allowlist are retired (RFC 0002 section 11.5): invoices come only
//! from paired contacts. Their calls stay in the binding until it is generated again and always
//! fail with `Unsupported`.
//!
//! The two sides tell each other what happened with short notices, which only LEPIC wallets
//! read: the issuer reports `posted` and `withdrawn`, the payer `declined`. They arrive with
//! drains and the listener as the `InvoicePosted`, `InvoiceWithdrawn` and `InvoiceDeclined`
//! events, are advisory, and never move funds. A notice goes only to a wallet that proved it
//! runs LEPIC in an earlier invoice exchange, so a stock wallet is never sent one.
//!
//! Every call here except [`EpicWallet::pending_invoices`] and [`EpicWallet::peer_capability`]
//! fails with `Unsupported` when the configuration names no relay, and every call fails with
//! `Locked` on a locked wallet.

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{
    IncomingInvoice, InvoiceReport, InvoiceSender, InvoiceSweep, IssuedInvoice, PaidInvoice,
    PeerCapability, SendOptions,
};
use crate::api::wallet::EpicWallet;

fn retired() -> WalletError {
    WalletError::new(
        WalletErrorKind::Unsupported,
        "the invoice address is retired; invoices come from paired contacts",
    )
}

impl EpicWallet {
    /// Retired with the invoice address; always fails with `Unsupported`.
    pub async fn invoice_address(&self) -> Result<String, WalletError> {
        Err(retired())
    }

    /// Retired with the invoice address; always fails with `Unsupported`.
    pub async fn invoice_address_index(&self) -> Result<u32, WalletError> {
        Err(retired())
    }

    /// Retired with the invoice address; always fails with `Unsupported`.
    pub async fn set_invoice_address_index(&self, index: u32) -> Result<(), WalletError> {
        let _ = index;
        Err(retired())
    }

    /// Retired with the invoice address; always fails with `Unsupported`.
    pub async fn rotate_invoice_address(&self) -> Result<String, WalletError> {
        Err(retired())
    }

    /// What this wallet learned about the peer at `address`, `<key>@<relay>[:port]`, from
    /// its own messages: `Lepic` once it proved it runs LEPIC, `NoInvoices` once it sent an
    /// invoice back unpaid, `Unknown` before either. Only the key is matched. Warn before
    /// invoicing a `NoInvoices` peer. Reads only the wallet database.
    ///
    /// Fails with `InvalidArgument` for any other address.
    pub async fn peer_capability(&self, address: String) -> Result<PeerCapability, WalletError> {
        self.run("peer_capability", |session| async move {
            session.peer_capability(&address)
        })
        .await
    }

    /// Retired with the invoice allowlist; always fails with `Unsupported`.
    pub async fn invoice_senders(&self) -> Result<Vec<InvoiceSender>, WalletError> {
        Err(retired())
    }

    /// Retired with the invoice allowlist; always fails with `Unsupported`.
    pub async fn allow_invoice_sender(
        &self,
        address: String,
        label: String,
    ) -> Result<InvoiceSender, WalletError> {
        let _ = (address, label);
        Err(retired())
    }

    /// Retired with the invoice allowlist; always fails with `Unsupported`.
    pub async fn remove_invoice_sender(&self, address: String) -> Result<bool, WalletError> {
        let _ = address;
        Err(retired())
    }

    /// Issues an invoice for `amount` to the payer at `address` over Epicbox.
    /// The payer pays `amount` plus the fee. Its payment arrives on this wallet's payments
    /// address, where [`EpicWallet::drain_epicbox`] or the listener finalizes and posts it, with
    /// an `InvoiceFinalized` event, and the payer gets a `posted` notice. `message` is signed
    /// into the invoice as [`EpicWallet::create_send_slate`] signs it. Withdraw an unpaid
    /// invoice with `cancel_transaction`, which sends the payer a `withdrawn` notice.
    ///
    /// Fails with `InvalidArgument`, storing nothing, for an address
    /// `validate_epicbox_address` refuses, and with `NotDelivered` when the
    /// invoice was stored but the relay did not take it.
    pub async fn issue_invoice_epicbox(
        &self,
        amount: u64,
        address: String,
        message: Option<String>,
    ) -> Result<IssuedInvoice, WalletError> {
        self.run("issue_invoice_epicbox", |session| async move {
            session
                .issue_invoice_epicbox(amount, address, message)
                .await
        })
        .await
    }

    /// Retired with the invoice address; always fails with `Unsupported`.
    pub async fn drain_invoices(&self) -> Result<InvoiceReport, WalletError> {
        Err(retired())
    }

    /// The invoices waiting to be paid or declined, oldest first, with when a sweep with
    /// `expiry_secs` deletes them. `expiry_secs` is as in [`EpicWallet::sweep_invoices`].
    pub async fn pending_invoices(
        &self,
        expiry_secs: Option<u64>,
    ) -> Result<Vec<IncomingInvoice>, WalletError> {
        self.run("pending_invoices", |session| async move {
            session.pending_invoices(expiry_secs)
        })
        .await
    }

    /// Pays the waiting invoice `slate_id` and delivers the payment over Epicbox to the
    /// sender's address, and to the relay the invoice came from when that differs.
    /// `amount` is what the user typed: an invoice for any other amount is refused, as
    /// `epic-wallet pay` refuses it. Inputs need `minimum_confirmations`; `message` goes to the
    /// sender signed and `options` choose the inputs and change, as in
    /// [`EpicWallet::create_send_slate`].
    ///
    /// Fails with `InvoiceNotFound` when no invoice with that id waits, `AmountMismatch`,
    /// `PaymentExpired`, `NotEnoughFunds`, `InvalidSlate`, `InvoiceAlreadyPaid` when this
    /// invoice was paid before, `InvoiceLockedAboveTip` when it is locked above the chain tip,
    /// `NodeUnreachable`, and with
    /// `NotDelivered` when the payment was stored but the relay did not take it: deliver it
    /// with [`EpicWallet::resend_invoice_payment`] or give up with `cancel_transaction`.
    pub async fn pay_invoice(
        &self,
        slate_id: String,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PaidInvoice, WalletError> {
        self.run("pay_invoice", |session| async move {
            session
                .pay_invoice(&slate_id, amount, minimum_confirmations, message, options)
                .await
        })
        .await
    }

    /// Declines the waiting invoice `slate_id`: it is never paid and leaves
    /// [`EpicWallet::pending_invoices`]. The sender gets a `declined` notice when it proved
    /// that it runs LEPIC; a failure to send it is not reported. Fails with `InvoiceNotFound`
    /// when no invoice with that id waits.
    pub async fn decline_invoice(&self, slate_id: String) -> Result<(), WalletError> {
        self.run("decline_invoice", |session| async move {
            session.decline_invoice(&slate_id).await
        })
        .await
    }

    /// Delivers the stored payment `tx_id` of an invoice again, to the sender's address and, when it differs, the relay the invoice came from, after
    /// [`EpicWallet::pay_invoice`] failed with `NotDelivered` or nothing came of it. Fails with
    /// `InvalidArgument` for a transaction that is not an undelivered payment of an invoice,
    /// and with `TransportFailed` when the relay fails again.
    pub async fn resend_invoice_payment(&self, tx_id: u32) -> Result<(), WalletError> {
        self.run("resend_invoice_payment", |session| async move {
            session.resend_invoice_payment(tx_id).await
        })
        .await
    }

    /// Expires what invoices left unpaid; run it from time to time, for example after a drain.
    /// Waiting and declined invoices received more than `expiry_secs` ago are deleted, and
    /// invoices this wallet issued over Epicbox that long ago and not paid are cancelled, each
    /// with an `InvoiceExpired` event. Payments of invoices whose time to live passed with the
    /// transaction neither on chain nor in the node's pool are listed in `cancellable`,
    /// unchanged.
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
