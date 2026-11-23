// SPDX-License-Identifier: Apache-2.0
//! Payments to epic1 links (EPICTX), and sealed text opened as it arrived. Links and payments
//! belong to the default account.

use lepic_primitives::amount::Amount;
use lepic_store::TxId;
use lepic_wallet_contacts::{
    ContactError, Epic1LinkRequest, Epic1PayRequest, Epic1Receipt, MAX_RECEIPT_LEN, NotReadReason,
    ReceiptOnChain, ReceiptVerdict, WalletContacts, parse_mailbox,
};

use super::contact::slate_purpose;
use super::{DEFAULT_ACCOUNT, ScratchFile, Session};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{
    ContactRelayMode, Epic1AnswerView, Epic1Attempt, Epic1Link, Epic1LinkRead, Epic1NotRead,
    Epic1NotReadReason, Epic1Paid, Epic1Restored, EpictxView, PaymentProofCheck,
    PaymentProofVerdict, SendOptions, SlateWire,
};

/// The longest link text taken from the app; a link carries at most three entries and short
/// values, far below this.
const MAX_LINK_TEXT: usize = 8 * 1024;

/// The longest sealed text opened: the largest the wallet opens elsewhere.
const MAX_SEALED_TEXT: usize = 4 * 1024 * 1024;

fn bounded<'a>(text: &'a str, max: usize, what: &str) -> Result<&'a str, WalletError> {
    if text.len() > max {
        return Err(WalletError::new(
            WalletErrorKind::InvalidArgument,
            format!("{what} too long"),
        ));
    }
    Ok(text)
}

fn positive(amount: u64) -> Result<Amount, WalletError> {
    if amount == 0 {
        return Err(WalletError::new(
            WalletErrorKind::InvalidArgument,
            "amount must be more than zero",
        ));
    }
    Ok(Amount::new(amount))
}

/// The message a payment carries: the link's when none is given, none when the one given is
/// empty or only spaces.
fn chosen_message(given: Option<String>, asked: Option<String>) -> Option<String> {
    match given {
        None => asked,
        Some(given) if given.trim().is_empty() => None,
        Some(given) => Some(given),
    }
}

/// A count the app reads, capped at `u32::MAX`.
fn count(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn paid(paid: lepic_wallet_contacts::Epic1Paid) -> Epic1Paid {
    Epic1Paid {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate_id.to_string(),
        address: paid.address,
        attempts: paid
            .attempts
            .into_iter()
            .map(|attempt| Epic1Attempt {
                host: attempt.host,
                error: attempt.error,
                uncertain: attempt.uncertain,
            })
            .collect(),
        // At most three transports.
        posted: paid
            .posted
            .map(|index| u32::try_from(index).unwrap_or(u32::MAX)),
        uncertain: paid
            .uncertain
            .map(|index| u32::try_from(index).unwrap_or(u32::MAX)),
        format: SlateWire::Native,
    }
}

impl Session {
    pub(crate) fn epic1_address(&self) -> Result<Epic1Link, WalletError> {
        let address = self.engine.contact_book().epic1_address(DEFAULT_ACCOUNT)?;
        let link = lepic_wallet_contacts::Epic1Link::new(address);
        Ok(Epic1Link {
            link: link.to_uri(),
            qr: link.to_qr(),
            address: link.address.encode(),
        })
    }

    /// The relay list for a call that connects nowhere: making or reading a link checks the
    /// list's network and an entry's host against it.
    fn listed_relays(&self) -> Result<lepic_wallet_contacts::ContactRelays, WalletError> {
        self.contact_relays(ContactRelayMode::Offline)
    }

    pub(crate) fn epic1_link_make(
        &self,
        amount: Option<u64>,
        message: Option<String>,
    ) -> Result<Epic1Link, WalletError> {
        let amount = amount.map(positive).transpose()?;
        let contact_relays = self.listed_relays()?;
        let issued = self.engine.contact_book().epic1_link(
            &contact_relays,
            Epic1LinkRequest {
                account: DEFAULT_ACCOUNT,
                amount,
                message,
                entries: Vec::new(),
            },
        )?;
        let qr = lepic_wallet_contacts::Epic1Link::parse(&issued.link)
            .map_err(ContactError::Epic1Link)?
            .to_qr();
        Ok(Epic1Link {
            link: issued.link,
            qr,
            address: issued.address,
        })
    }

    pub(crate) fn epic1_link_read(&self, link: &str) -> Result<Epic1LinkRead, WalletError> {
        let link = bounded(link, MAX_LINK_TEXT, "link")?;
        let relays = self.listed_relays()?;
        let read = self.engine.contact_book().epic1_read(&relays, link)?;
        Ok(Epic1LinkRead {
            address: read.address,
            amount: read.amount.map(Amount::value),
            message: read.message,
            label: read.label,
            http_host: read.http_host,
            ignored_mailboxes: count(read.ignored_mailboxes),
        })
    }

    #[allow(clippy::too_many_arguments)] // The app's send form, one value per field.
    pub(crate) async fn epic1_pay(
        &self,
        link: String,
        amount: Option<u64>,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        mailboxes: Vec<String>,
        mode: ContactRelayMode,
        require_proof: bool,
    ) -> Result<Epic1Paid, WalletError> {
        bounded(&link, MAX_LINK_TEXT, "link")?;
        let mailboxes = mailboxes
            .iter()
            .map(|host| parse_mailbox(host))
            .collect::<Result<Vec<_>, _>>()?;
        let relays = self.contact_relays(mode)?;
        let book = self.engine.contact_book();
        let asked = match (amount, &message) {
            (Some(_), Some(_)) => None,
            _ => Some(book.epic1_read(&relays, &link)?),
        };
        let (asked_amount, asked_message) =
            asked.map_or((None, None), |read| (read.amount, read.message));
        let amount = amount.or(asked_amount.map(Amount::value)).ok_or_else(|| {
            WalletError::new(
                WalletErrorKind::InvalidArgument,
                "the link asks no amount: give one",
            )
        })?;
        positive(amount)?;
        let message = chosen_message(message, asked_message);
        let send =
            self.policy
                .send_request_with(amount, minimum_confirmations, message, options)?;
        let scratch = ScratchFile::new(&self.data_dir)?;
        let done = book
            .epic1_pay(
                &relays,
                Epic1PayRequest {
                    link,
                    send,
                    slate_file: scratch.path.clone(),
                    mailboxes,
                    require_receipt: require_proof,
                },
            )
            .await?;
        Ok(paid(done))
    }

    pub(crate) async fn epic1_proof(&self, tx_id: u32) -> Result<Option<String>, WalletError> {
        Ok(self
            .engine
            .contact_book()
            .epic1_receipt(TxId(tx_id))
            .await?
            .map(|receipt| receipt.to_text()))
    }

    pub(crate) async fn epic1_proof_verify(
        &self,
        proof: &str,
        on_chain: bool,
    ) -> Result<PaymentProofCheck, WalletError> {
        let receipt =
            Epic1Receipt::parse(bounded(proof, MAX_RECEIPT_LEN, "proof")?).ok_or_else(|| {
                WalletError::new(
                    WalletErrorKind::InvalidArgument,
                    "the text is not a payment proof this release reads",
                )
            })?;
        let mut verdict = match receipt.check(Some(super::relay_network(self.network))) {
            ReceiptVerdict::Valid => PaymentProofVerdict::Valid,
            ReceiptVerdict::BadSignature => PaymentProofVerdict::BadSignature,
            ReceiptVerdict::Malformed => PaymentProofVerdict::Malformed,
            ReceiptVerdict::WrongNetwork => PaymentProofVerdict::WrongNetwork,
        };
        let mut height = None;
        if on_chain && verdict == PaymentProofVerdict::Valid {
            match receipt
                .on_chain(&self.engine.ports().node)
                .await
                .map_err(lepic_wallet::WalletError::Node)?
            {
                Some(ReceiptOnChain::OnChain { height: at }) => height = Some(at.value()),
                // `check` held, so the excess decodes.
                Some(ReceiptOnChain::NotOnChain) | None => {
                    verdict = PaymentProofVerdict::NotOnChain;
                }
            }
        }
        Ok(PaymentProofCheck {
            verdict,
            network: receipt.network,
            address: receipt.address,
            amount: receipt.amount,
            kernel_excess: receipt.kernel_excess,
            slate_id: receipt.slate_id,
            height,
        })
    }

    pub(crate) async fn epic1_answers(&self) -> Result<Vec<Epic1AnswerView>, WalletError> {
        Ok(self
            .engine
            .contact_book()
            .epic1_answers()
            .await?
            .into_iter()
            .map(|view| Epic1AnswerView {
                tx_id: view.tx_id.0,
                slate_id: view.slate_id.to_string(),
                mailbox: view.mailbox,
                posted: view.posted,
            })
            .collect())
    }

    pub(crate) async fn epic1_restore(
        &self,
        mode: ContactRelayMode,
    ) -> Result<Epic1Restored, WalletError> {
        let relays = self.contact_relays(mode)?;
        let restored = self.engine.contact_book().epic1_restore(&relays).await?;
        Ok(Epic1Restored {
            taken: count(restored.taken),
            not_read: restored
                .not_read
                .into_iter()
                .map(|not_read| Epic1NotRead {
                    host: not_read.host,
                    reason: match not_read.reason {
                        NotReadReason::NoPush => Epic1NotReadReason::NoPush,
                        NotReadReason::SlotsLeftOut => Epic1NotReadReason::SlotsLeftOut,
                        _ => Epic1NotReadReason::NotAnswering,
                    },
                })
                .collect(),
        })
    }

    pub(crate) async fn epictx_open(&self, text: &str) -> Result<EpictxView, WalletError> {
        let text = bounded(text, MAX_SEALED_TEXT, "sealed text")?;
        let view = self.engine.contact_book().epictx_open(text).await?;
        // The value's `Display` writes it as compact JSON.
        let slate_json = view.slate.to_string();
        Ok(EpictxView {
            contact_id: view.contact_id.map(|id| id.to_string()),
            native: view.native,
            slate_json,
            purpose: view.purpose.map(slate_purpose),
            reference: view.reference,
            expires: view.expires,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_message_clears_the_one_the_link_asks() {
        let asked = || Some("for tea".to_owned());
        assert_eq!(chosen_message(None, asked()), asked());
        assert_eq!(chosen_message(Some(String::new()), asked()), None);
        assert_eq!(chosen_message(Some(" \t ".to_owned()), asked()), None);
        assert_eq!(
            chosen_message(Some("mine".to_owned()), asked()),
            Some("mine".to_owned())
        );
    }

    #[test]
    fn a_zero_amount_is_refused() {
        assert_eq!(
            positive(0).map_err(|e| e.kind),
            Err(WalletErrorKind::InvalidArgument)
        );
    }

    #[test]
    fn text_past_the_limit_is_refused() {
        let long = "x".repeat(MAX_LINK_TEXT + 1);
        assert_eq!(
            bounded(&long, MAX_LINK_TEXT, "link").map_err(|e| e.kind),
            Err(WalletErrorKind::InvalidArgument)
        );
    }
}
