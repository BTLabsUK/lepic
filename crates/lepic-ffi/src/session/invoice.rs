//! Invoices over Epicbox: the invoice address and its allowlist on the payer's side, issuing
//! on the issuer's side, and the expiry of both.

use std::time::Duration;

use lepic_epicbox::TRANSPORT_ID;
use lepic_primitives::amount::Amount;
use lepic_store::TxId;
use lepic_transport::transport::Destination;
use lepic_wallet::epicbox_invoice::{
    AllowedSender, IncomingInvoice as EngineIncomingInvoice, InvoiceExpiry,
};
use lepic_wallet::event::SlateId;
use lepic_wallet::invoice::{InvoiceRequest, PayRequest};
use lepic_wallet::send::Delivery;

use super::{DEFAULT_ACCOUNT, Session, invalid, relay_address};
use crate::api::error::WalletError;
use crate::api::types::{
    IncomingInvoice, InvoiceReport, InvoiceSender, InvoiceSweep, IssuedInvoice, PaidInvoice,
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

fn sender(allowed: AllowedSender) -> InvoiceSender {
    InvoiceSender {
        address: allowed.address.to_string(),
        label: allowed.label,
        added_at_ms: allowed.added_at.as_millisecond(),
    }
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
    pub(crate) fn invoice_address(&self) -> Result<String, WalletError> {
        Ok(self.engine.invoice_address(self.epicbox()?)?.to_string())
    }

    pub(crate) fn invoice_address_index(&self) -> Result<u32, WalletError> {
        Ok(self.engine.invoice_address_index()?)
    }

    pub(crate) fn set_invoice_address_index(&self, index: u32) -> Result<(), WalletError> {
        self.epicbox()?;
        Ok(self.engine.set_invoice_address_index(index)?)
    }

    pub(crate) fn rotate_invoice_address(&self) -> Result<String, WalletError> {
        Ok(self
            .engine
            .rotate_invoice_address(self.epicbox()?)?
            .to_string())
    }

    pub(crate) fn invoice_senders(&self) -> Result<Vec<InvoiceSender>, WalletError> {
        Ok(self
            .engine
            .invoice_senders()?
            .into_iter()
            .map(sender)
            .collect())
    }

    pub(crate) fn allow_invoice_sender(
        &self,
        address: &str,
        label: &str,
    ) -> Result<InvoiceSender, WalletError> {
        relay_address(address, self.network)
            .ok_or_else(|| invalid("not an epicbox address with a relay on this network"))?;
        Ok(sender(self.engine.allow_invoice_sender(address, label)?))
    }

    pub(crate) fn remove_invoice_sender(&self, address: &str) -> Result<bool, WalletError> {
        Ok(self.engine.remove_invoice_sender(address)?)
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
        self.engine.epicbox_attach(epicbox)?;
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

    pub(crate) async fn drain_invoices(&self) -> Result<InvoiceReport, WalletError> {
        let summary = self.engine.epicbox_drain_invoices(self.epicbox()?).await?;
        Ok(InvoiceReport {
            parked: summary.parked,
            finalized: summary.finalized,
            repeated: summary.repeated,
            rejected: summary.rejected,
            held: summary.held,
            dropped: summary.dropped,
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
    ) -> Result<PaidInvoice, WalletError> {
        let slate_id = self::slate_id(slate_id)?;
        // The payment goes out from the payments address, where the issuer's answers arrive.
        self.engine.epicbox_attach(self.epicbox()?)?;
        let request = PayRequest {
            minimum_confirmations,
            message,
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

    pub(crate) fn decline_invoice(&self, slate_id: &str) -> Result<(), WalletError> {
        Ok(self.engine.decline_invoice(self::slate_id(slate_id)?)?)
    }

    pub(crate) async fn resend_invoice_payment(&self, tx_id: u32) -> Result<(), WalletError> {
        let epicbox = self.epicbox()?;
        let details = self.engine.transaction_details(TxId(tx_id)).await?;
        // Only a payment of a parked invoice records where it goes; anything else is refused
        // by the engine as not resendable.
        let to = details
            .counterparty
            .ok_or_else(|| invalid("transaction is not a payment of an invoice"))?;
        self.engine.epicbox_attach(epicbox)?;
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
        let sweep = self.engine.sweep_invoices(expiry(expiry_secs)?).await?;
        Ok(InvoiceSweep {
            deleted: sweep.deleted.iter().map(ToString::to_string).collect(),
            cancelled: sweep.cancelled.iter().map(|tx_id| tx_id.0).collect(),
            cancellable: sweep.cancellable.iter().map(|tx_id| tx_id.0).collect(),
        })
    }
}
