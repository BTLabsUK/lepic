//! Invoices over Epicbox: paying and declining parked invoices on the payer's side, issuing on
//! the issuer's side, and the expiry of both.

use std::time::Duration;

use lepic_epicbox::TRANSPORT_ID;
use lepic_primitives::amount::Amount;
use lepic_store::TxId;
use lepic_transport::transport::Destination;
use lepic_wallet::epicbox_invoice::{
    IncomingInvoice as EngineIncomingInvoice, InvoiceExpiry, PeerInvoiceSupport,
};
use lepic_wallet::event::SlateId;
use lepic_wallet::invoice::{InvoiceRequest, PayRequest};
use lepic_wallet::send::Delivery;

use super::{DEFAULT_ACCOUNT, Session, invalid, relay_address};
use crate::api::error::WalletError;
use crate::api::types::{
    IncomingInvoice, InvoiceSweep, IssuedInvoice, PaidInvoice, PeerCapability, SendOptions,
};

/// `seconds` as the window after which unpaid invoices expire; `None` is the default day.
fn expiry(seconds: Option<u64>) -> Result<InvoiceExpiry, WalletError> {
    match seconds {
        None => Ok(InvoiceExpiry::default()),
        Some(seconds) => Ok(InvoiceExpiry::new(Duration::from_secs(seconds))?),
    }
}

fn slate_id(text: &str) -> Result<SlateId, WalletError> {
    SlateId::parse(text).map_err(|_| invalid("not a slate id"))
}

fn incoming(invoice: EngineIncomingInvoice) -> IncomingInvoice {
    IncomingInvoice {
        slate_id: invoice.slate_id.to_string(),
        sender_address: invoice.sender.to_string(),
        amount: invoice.amount.value(),
        message: invoice.message,
        received_at_ms: invoice.received_at.as_millisecond(),
        expires_at_ms: invoice.expires_at.as_millisecond(),
    }
}

impl Session {
    pub(crate) fn peer_capability(&self, address: &str) -> Result<PeerCapability, WalletError> {
        relay_address(address, self.network)
            .ok_or_else(|| invalid("not an epicbox address with a relay on this network"))?;
        Ok(match self.engine.peer_capability(address)? {
            PeerInvoiceSupport::Unknown => PeerCapability::Unknown,
            PeerInvoiceSupport::Lepic => PeerCapability::Lepic,
            PeerInvoiceSupport::NoInvoices => PeerCapability::NoInvoices,
        })
    }

    pub(crate) async fn issue_invoice_epicbox(
        &self,
        amount: u64,
        address: String,
        message: Option<String>,
    ) -> Result<IssuedInvoice, WalletError> {
        let epicbox = self.epicbox()?;
        relay_address(&address, self.network)
            .ok_or_else(|| invalid("not an epicbox address with a relay on this network"))?;
        // The payer's I2 comes back to the payments address the I1 is sent from.
        self.engine.epicbox_attach(&epicbox)?;
        let issued = self
            .engine
            .issue_invoice(
                InvoiceRequest {
                    account: DEFAULT_ACCOUNT,
                    amount: Amount::new(amount),
                    message,
                },
                Delivery::Deliver {
                    transport: TRANSPORT_ID,
                    to: Destination::new(address),
                },
            )
            .await?;
        Ok(IssuedInvoice {
            tx_id: issued.tx_id.0,
            slate_id: issued.slate_id.to_string(),
            amount: issued.amount.value(),
        })
    }

    pub(crate) fn pending_invoices(
        &self,
        expiry_secs: Option<u64>,
    ) -> Result<Vec<IncomingInvoice>, WalletError> {
        Ok(self
            .engine
            .pending_invoices(expiry(expiry_secs)?)?
            .into_iter()
            .map(incoming)
            .collect())
    }

    pub(crate) async fn pay_invoice(
        &self,
        slate_id: &str,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PaidInvoice, WalletError> {
        let slate_id = self::slate_id(slate_id)?;
        let defaults = Self::send_request_with(amount, minimum_confirmations, message, options)?;
        // The payment goes out from the payments address, where the issuer's answers arrive.
        self.engine.epicbox_attach(&self.epicbox()?)?;
        let request = PayRequest {
            minimum_confirmations,
            strategy: defaults.strategy,
            change_outputs: defaults.change_outputs,
            message: defaults.message,
            ..PayRequest::new(DEFAULT_ACCOUNT, Amount::new(amount))
        };
        let paid = self.engine.pay_parked_invoice(slate_id, request).await?;
        Ok(PaidInvoice {
            tx_id: paid.tx_id.0,
            slate_id: paid.slate.id().to_string(),
            amount: paid.slate.amount().value(),
            fee: paid.slate.fee().value(),
        })
    }

    pub(crate) async fn decline_invoice(&self, slate_id: &str) -> Result<(), WalletError> {
        let slate_id = self::slate_id(slate_id)?;
        // The declined notice goes out from the payments address.
        self.engine.epicbox_attach(&self.epicbox()?)?;
        Ok(self.engine.decline_invoice(slate_id).await?)
    }

    pub(crate) async fn resend_invoice_payment(&self, tx_id: u32) -> Result<(), WalletError> {
        let epicbox = self.epicbox()?;
        let details = self.engine.transaction_details(TxId(tx_id)).await?;
        // Only a payment of a parked invoice records where it goes; anything else is refused
        // by the engine as not resendable.
        let to = details
            .counterparty
            .ok_or_else(|| invalid("transaction is not a payment of an invoice"))?;
        self.engine.epicbox_attach(&epicbox)?;
        Ok(self
            .engine
            .resend(
                TxId(tx_id),
                Delivery::Deliver {
                    transport: TRANSPORT_ID,
                    to,
                },
            )
            .await?)
    }

    pub(crate) async fn sweep_invoices(
        &self,
        expiry_secs: Option<u64>,
    ) -> Result<InvoiceSweep, WalletError> {
        let expiry = expiry(expiry_secs)?;
        self.attach_for_notices()?;
        let sweep = self.engine.sweep_invoices(expiry).await?;
        Ok(InvoiceSweep {
            deleted: sweep.deleted.iter().map(ToString::to_string).collect(),
            cancelled: sweep.cancelled.iter().map(|tx_id| tx_id.0).collect(),
            cancellable: sweep.cancellable.iter().map(|tx_id| tx_id.0).collect(),
        })
    }
}
