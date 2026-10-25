//! The expiry of invoices on both sides.

use std::time::Duration;

use lepic_wallet::epicbox_invoice::InvoiceExpiry;

use super::Session;
use crate::api::error::WalletError;
use crate::api::types::InvoiceSweep;

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
}
