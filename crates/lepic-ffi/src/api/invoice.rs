//! Invoices over Epicbox. A service issues an invoice to the payer's invoice address, the
//! payer pays it with one call, and the service finalizes and posts.
//!
//! The invoice address is the wallet's Epicbox identity at address index 1 or higher, beside
//! the payments address of [`EpicWallet::epicbox_address`]. It hears only from senders the
//! user allowed; everything else is acknowledged and dropped unopened. The app reads it with
//! [`EpicWallet::drain_invoices`]; no listener runs on it. Nothing that arrives ever pays:
//! paying is always [`EpicWallet::pay_invoice`].
//!
//! The two sides tell each other what happened with short notices, which only LEPIC wallets
//! read: the issuer reports `posted` and `withdrawn`, the payer `declined`. They arrive with
//! drains and the listener as the `InvoicePosted`, `InvoiceWithdrawn` and `InvoiceDeclined`
//! events, are advisory, and never move funds. A notice goes only to a wallet that proved it
//! runs LEPIC in an earlier invoice exchange, so a stock wallet is never sent one.
//!
//! Every call here except [`EpicWallet::pending_invoices`], [`EpicWallet::peer_capability`]
//! and the allowlist calls fails with
//! `Unsupported` when the configuration names no relay, and every call fails with `Locked` on
//! a locked wallet.

use crate::api::error::WalletError;
use crate::api::types::{
    IncomingInvoice, InvoiceReport, InvoiceSender, InvoiceSweep, IssuedInvoice, PaidInvoice,
    PeerCapability, SendOptions,
};
use crate::api::wallet::EpicWallet;

impl EpicWallet {
    /// The invoice address, `<key>@<domain>[:port]`, to give to services that invoice this
    /// wallet. Its index starts at 1, also after a restore; see
    /// [`EpicWallet::set_invoice_address_index`].
    pub async fn invoice_address(&self) -> Result<String, WalletError> {
        self.run("invoice_address", |session| async move {
            session.invoice_address()
        })
        .await
    }

    /// The address index of the invoice address, 1 or higher.
    pub async fn invoice_address_index(&self) -> Result<u32, WalletError> {
        self.run("invoice_address_index", |session| async move {
            session.invoice_address_index()
        })
        .await
    }

    /// Sets the address index of the invoice address, for example to the one the app kept
    /// before the wallet was restored from its phrase, which does not record it. Messages to
    /// the previous invoice address are no longer read. Fails with `InvalidArgument` for 0,
    /// the payments address.
    pub async fn set_invoice_address_index(&self, index: u32) -> Result<(), WalletError> {
        self.run("set_invoice_address_index", |session| async move {
            session.set_invoice_address_index(index)
        })
        .await
    }

    /// Moves the invoice address to the next index and returns it. The old address is
    /// abandoned: messages to it are no longer read, so give the new one to every service.
    pub async fn rotate_invoice_address(&self) -> Result<String, WalletError> {
        self.run("rotate_invoice_address", |session| async move {
            session.rotate_invoice_address()
        })
        .await
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

    /// The senders the invoice address accepts, in the order they were added.
    pub async fn invoice_senders(&self) -> Result<Vec<InvoiceSender>, WalletError> {
        self.run("invoice_senders", |session| async move {
            session.invoice_senders()
        })
        .await
    }

    /// Accepts invoices from the service at `address`, the full address it shows,
    /// `<key>@<relay>[:port]` as `validate_epicbox_address` accepts it.
    /// Only the key is matched, because the relay vouches for the key of a message and never
    /// for its relay part; payments of its invoices go to `address` as added. Adding a key
    /// again replaces its address and label.
    ///
    /// Fails with `InvalidArgument` for any other address, and for a `label` longer than 64
    /// bytes or holding control characters.
    pub async fn allow_invoice_sender(
        &self,
        address: String,
        label: String,
    ) -> Result<InvoiceSender, WalletError> {
        self.run("allow_invoice_sender", |session| async move {
            session.allow_invoice_sender(&address, &label)
        })
        .await
    }

    /// Stops accepting invoices from the key of `address`, and returns whether it was
    /// accepted. Invoices it sent that wait already stay. Fails with `InvalidArgument` for an
    /// address that does not parse on this wallet's chain.
    pub async fn remove_invoice_sender(&self, address: String) -> Result<bool, WalletError> {
        self.run("remove_invoice_sender", |session| async move {
            session.remove_invoice_sender(&address)
        })
        .await
    }

    /// Issues an invoice for `amount` to the payer's invoice address `address` over Epicbox.
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

    /// Connects to the relay as the invoice address once, handles every pending message and
    /// disconnects. An invoice from an allowed sender is stored, with an `InvoiceReceived`
    /// event, before the relay is told it arrived; anything from another sender is dropped
    /// unopened. Notices from the senders of invoices this wallet holds raise their events. Fails
    /// as [`EpicWallet::drain_epicbox`] does.
    pub async fn drain_invoices(&self) -> Result<InvoiceReport, WalletError> {
        self.run("drain_invoices", |session| async move {
            session.drain_invoices().await
        })
        .await
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
    /// sender's allowed address. `amount` is what the user typed: an invoice for any other
    /// amount is refused, as `epic-wallet pay` refuses it. Inputs need `minimum_confirmations`;
    /// `message` goes to the sender signed and `options` choose the inputs and change, as in
    /// [`EpicWallet::create_send_slate`].
    ///
    /// Fails with `InvoiceNotFound` when no invoice with that id waits, `AmountMismatch`,
    /// `PaymentExpired`, `NotEnoughFunds`, `InvalidSlate`, `NodeUnreachable`, and with
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

    /// Delivers the stored payment `tx_id` of an invoice again, to the sender's allowed
    /// address, after [`EpicWallet::pay_invoice`] failed with `NotDelivered`. Fails with
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
