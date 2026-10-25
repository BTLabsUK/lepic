//! Invoices by file, issued to and paid by anyone (RFC 0002 11.5), and the expiry of invoices on
//! both sides.

use std::path::{Path, PathBuf};
use std::time::Duration;

use lepic_primitives::amount::Amount;
use lepic_transport::file::{FILE, FileTransport, response_path};
use lepic_transport::transport::{Exchange as _, Location};
use lepic_wallet::epicbox_invoice::InvoiceExpiry;
use lepic_wallet::invoice::InvoiceRequest;
use lepic_wallet::send::Delivery;

use super::{DEFAULT_ACCOUNT, ScratchFile, Session, invalid, transport_error};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{InvoiceSweep, IssuedInvoice, PaidInvoiceSlate, SendOptions, Slate};

/// `seconds` as the window after which unpaid invoices expire; `None` is the default day.
fn expiry(seconds: Option<u64>) -> Result<InvoiceExpiry, WalletError> {
    match seconds {
        None => Ok(InvoiceExpiry::default()),
        Some(seconds) => Ok(InvoiceExpiry::new(Duration::from_secs(seconds))?),
    }
}

impl Session {
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

    pub(crate) async fn issue_invoice_file(
        &self,
        amount: u64,
        path: PathBuf,
        message: Option<String>,
    ) -> Result<IssuedInvoice, WalletError> {
        if amount == 0 {
            return Err(invalid("an invoice asks for more than nothing"));
        }
        let issued = self
            .engine
            .issue_invoice(
                InvoiceRequest {
                    account: DEFAULT_ACCOUNT,
                    amount: Amount::new(amount),
                    message,
                },
                Delivery::Export {
                    transport: FILE,
                    to: Location::File(path),
                },
            )
            .await?;
        Ok(IssuedInvoice {
            tx_id: issued.tx_id.0,
            slate_id: issued.slate_id.to_string(),
            amount: issued.amount.value(),
        })
    }

    pub(crate) async fn issue_invoice_slate(
        &self,
        amount: u64,
        message: Option<String>,
    ) -> Result<Slate, WalletError> {
        let scratch = ScratchFile::new(&self.data_dir)?;
        let issued = self
            .issue_invoice_file(amount, scratch.path.clone(), message)
            .await?;
        let json = scratch.read().await?;
        Ok(Slate {
            tx_id: issued.tx_id,
            slate_id: issued.slate_id,
            json,
        })
    }

    /// Pays the I1 in the file at `path`. Returns the I2, also written next to the file as
    /// `epic-wallet` names a response, when `write_response` is set.
    pub(crate) async fn pay_invoice_file(
        &self,
        path: &Path,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        write_response: bool,
    ) -> Result<PaidInvoiceSlate, WalletError> {
        let request = Self::pay_request(amount, minimum_confirmations, message, options)?;
        let file = FileTransport::new();
        let wire = file
            .import(&Location::File(path.to_owned()))
            .await
            .map_err(|error| transport_error(&error))?;
        let paid = self.engine.pay_invoice(FILE, &wire, request).await?;
        if write_response {
            file.export(&paid.reply, &Location::File(response_path(path)))
                .await
                .map_err(|error| transport_error(&error))?;
        }
        let json = String::from_utf8(paid.reply.as_bytes().to_vec())
            .map_err(|_| WalletError::new(WalletErrorKind::InvalidSlate, "reply is not text"))?;
        Ok(PaidInvoiceSlate {
            tx_id: paid.tx_id.0,
            slate_id: paid.slate.id().to_string(),
            amount: paid.slate.amount().value(),
            fee: paid.slate.fee().value(),
            json,
        })
    }

    pub(crate) async fn pay_invoice_slate(
        &self,
        json: String,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PaidInvoiceSlate, WalletError> {
        let scratch = ScratchFile::with_contents(&self.data_dir, json).await?;
        self.pay_invoice_file(
            &scratch.path,
            amount,
            minimum_confirmations,
            message,
            options,
            false,
        )
        .await
    }
}
