// SPDX-License-Identifier: Apache-2.0
//! Invoices by file, issued to and paid by anyone (RFC 0002 11.5), and the expiry of invoices on
//! both sides.

use std::path::{Path, PathBuf};

use lepic_primitives::amount::Amount;
use lepic_transport::file::{FileTransport, response_path};
use lepic_transport::transport::{Exchange as _, Location};
use lepic_wallet::invoice::{InvoiceRequest, PaidInvoice};
use lepic_wallet::send::Delivery;
use lepic_wallet::slate::WireSlate;

use super::{DEFAULT_ACCOUNT, ScratchFile, Session, invalid, transport_error};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{InvoiceSweep, IssuedInvoice, PaidInvoiceSlate, SendOptions, Slate, SlateWire};

impl Session {
    pub(crate) async fn sweep_invoices(
        &self,
        expiry_secs: Option<u64>,
    ) -> Result<InvoiceSweep, WalletError> {
        let expiry = self.policy.invoice_expiry(expiry_secs)?;
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
                &self.file,
                InvoiceRequest {
                    account: DEFAULT_ACCOUNT,
                    amount: Amount::new(amount),
                    message,
                    ttl_blocks: Some(self.policy.invoice_ttl_blocks),
                },
                Delivery::Export {
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
        let file = FileTransport::new();
        let wire = file
            .import(&Location::File(path.to_owned()))
            .await
            .map_err(|error| transport_error(&error))?;
        let paid = self
            .pay_invoice_wire(&wire, amount, minimum_confirmations, message, options)
            .await?;
        if write_response {
            file.export(&paid.reply, &Location::File(response_path(path)))
                .await
                .map_err(|error| transport_error(&error))?;
        }
        paid_invoice_slate(&paid)
    }

    async fn pay_invoice_wire(
        &self,
        wire: &WireSlate,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PaidInvoice, WalletError> {
        let request = self
            .policy
            .pay_request(amount, minimum_confirmations, message, options)?;
        Ok(self.engine.pay_invoice(&self.file, wire, request).await?)
    }

    pub(crate) async fn pay_invoice_slate(
        &self,
        json: String,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PaidInvoiceSlate, WalletError> {
        let wire = super::slate_text_wire(json)?;
        paid_invoice_slate(
            &self
                .pay_invoice_wire(&wire, amount, minimum_confirmations, message, options)
                .await?,
        )
    }
}

fn paid_invoice_slate(paid: &PaidInvoice) -> Result<PaidInvoiceSlate, WalletError> {
    let json = String::from_utf8(paid.reply.as_bytes().to_vec())
        .map_err(|_| WalletError::new(WalletErrorKind::InvalidSlate, "reply is not text"))?;
    Ok(PaidInvoiceSlate {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate.id().to_string(),
        amount: paid.slate.amount().value(),
        fee: paid.slate.fee().value(),
        json,
        format: SlateWire::Legacy,
    })
}
