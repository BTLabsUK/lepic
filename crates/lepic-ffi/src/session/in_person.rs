// SPDX-License-Identifier: Apache-2.0
//! In-person invoices and sends (EPICTX): codes shown as raw `lepic.v1` slates, answers sealed
//! to the code's reply key and posted to its reply mailbox or shown back, and the answer the
//! user picks by its check code finalized. Codes and answers belong to the default account.

use lepic_primitives::amount::{Amount, Fee};
use lepic_transport::host_rule::{HostClass, HostReport};
use lepic_wallet::ReceiveRequest;
use lepic_wallet::send::SendRequest;
use lepic_wallet_contacts::{ContactError, InPersonInvoiceRequest, WalletContacts};

use super::contact::{ms, slate_id, stage};
use super::{DEFAULT_ACCOUNT, Session};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{
    ContactRelayMode, FinalizedTx, InPersonAnswerView, InPersonCode, InPersonCodeView,
    InPersonHost, InPersonRead, InPersonReply, InPersonTaken, SendOptions,
};

/// The longest code or answer taken from the app: the largest slate envelope, as bytes or as
/// its `BEGINEPICTX.` text.
const MAX_IN_PERSON_INPUT: usize = 128 * 1024;

/// Refuses input longer than any in-person code or answer before the engine reads it.
fn bounded(bytes: &[u8]) -> Result<&[u8], WalletError> {
    if bytes.len() > MAX_IN_PERSON_INPUT {
        return Err(WalletError::new(
            WalletErrorKind::InvalidSlate,
            "longer than any in-person code or answer",
        ));
    }
    Ok(bytes)
}

/// Bytes that are no envelope are a damaged slate here, not pairing text.
fn in_person_error(error: ContactError) -> WalletError {
    match error {
        ContactError::Decode(decode) => {
            WalletError::chained(WalletErrorKind::InvalidSlate, &decode)
        }
        other => other.into(),
    }
}

fn host(report: HostReport) -> InPersonHost {
    InPersonHost {
        host: report.host,
        port: report.port,
        in_relay_list: report.in_relay_list,
        local_network: matches!(report.class, HostClass::LocalNetwork),
    }
}

fn code(code: lepic_wallet_contacts::InPersonCode) -> InPersonCode {
    InPersonCode {
        tx_id: code.tx_id.0,
        slate_id: code.slate_id.to_string(),
        bytes: code.bytes,
        ttl_cutoff: code.ttl_cutoff,
        mailbox: code.mailbox,
    }
}

fn reply(paid: lepic_wallet_contacts::InPersonPaid) -> InPersonReply {
    InPersonReply {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate_id.to_string(),
        armored: lepic_wallet_contacts::armor_tx(&paid.envelope),
        envelope: paid.envelope,
        check_code: paid.check_code,
        mailbox: paid.mailbox.map(host),
    }
}

fn taken(taken: lepic_wallet_contacts::InPersonTaken) -> InPersonTaken {
    InPersonTaken {
        tx_id: taken.tx_id.0,
        slate_id: taken.slate_id.to_string(),
        stage: stage(taken.stage),
        answer: taken.answer,
        check_code: taken.check_code,
        same_code: taken.same_code,
        duplicate: taken.duplicate,
    }
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

impl Session {
    pub(crate) async fn in_person_invoice(
        &self,
        amount: u64,
        message: Option<String>,
        ttl_blocks: Option<u64>,
        mode: ContactRelayMode,
    ) -> Result<InPersonCode, WalletError> {
        let amount = positive(amount)?;
        let relays = self.contact_relays(mode)?;
        let shown = self
            .engine
            .contact_book()
            .in_person_invoice(
                &relays,
                InPersonInvoiceRequest {
                    account: DEFAULT_ACCOUNT,
                    amount,
                    message,
                    ttl_blocks,
                },
            )
            .await
            .map_err(in_person_error)?;
        Ok(code(shown))
    }

    pub(crate) async fn in_person_send(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        ttl_blocks: Option<u64>,
        mode: ContactRelayMode,
    ) -> Result<InPersonCode, WalletError> {
        positive(amount)?;
        let relays = self.contact_relays(mode)?;
        let request = SendRequest {
            ttl_blocks,
            ..self
                .policy
                .send_request_with(amount, minimum_confirmations, message, options)?
        };
        let shown = self
            .engine
            .contact_book()
            .in_person_send(&relays, request)
            .await
            .map_err(in_person_error)?;
        Ok(code(shown))
    }

    pub(crate) async fn in_person_read(
        &self,
        bytes: Vec<u8>,
        minimum_confirmations: u64,
        options: Option<SendOptions>,
        mode: ContactRelayMode,
    ) -> Result<InPersonRead, WalletError> {
        let bytes = bounded(&bytes)?;
        let relays = self.contact_relays(mode)?;
        let options = self
            .policy
            .send_request_with(0, minimum_confirmations, None, options)?
            .selection_options();
        let read = self
            .engine
            .contact_book()
            .in_person_read(&relays, options, bytes)
            .await
            .map_err(in_person_error)?;
        Ok(InPersonRead {
            slate_id: read.slate_id.to_string(),
            stage: stage(read.stage),
            amount: read.amount.value(),
            fee: read.fee.map(Fee::value),
            message: read.message,
            ttl_cutoff: read.ttl_cutoff,
            mailbox: read.mailbox.map(host),
        })
    }

    pub(crate) async fn in_person_pay(
        &self,
        bytes: Vec<u8>,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        mode: ContactRelayMode,
    ) -> Result<InPersonReply, WalletError> {
        let bytes = bounded(&bytes)?;
        positive(amount)?;
        let relays = self.contact_relays(mode)?;
        let request = self
            .policy
            .pay_request(amount, minimum_confirmations, message, options)?;
        let paid = self
            .engine
            .contact_book()
            .in_person_pay(&relays, bytes, request)
            .await
            .map_err(in_person_error)?;
        Ok(reply(paid))
    }

    pub(crate) async fn in_person_receive(
        &self,
        bytes: Vec<u8>,
        message: Option<String>,
        mode: ContactRelayMode,
    ) -> Result<InPersonReply, WalletError> {
        let bytes = bounded(&bytes)?;
        let relays = self.contact_relays(mode)?;
        let received = self
            .engine
            .contact_book()
            .in_person_receive(
                &relays,
                bytes,
                ReceiveRequest {
                    account: None,
                    message,
                    ..ReceiveRequest::default()
                },
            )
            .await
            .map_err(in_person_error)?;
        Ok(reply(received))
    }

    pub(crate) async fn in_person_post(
        &self,
        slate: &str,
        relay_ok: bool,
        mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        let id = slate_id(slate)?;
        let relays = self.contact_relays(mode)?;
        self.engine
            .contact_book()
            .in_person_post(&relays, id, relay_ok)
            .await
            .map_err(in_person_error)
    }

    pub(crate) async fn in_person_take(
        &self,
        answer: Vec<u8>,
    ) -> Result<InPersonTaken, WalletError> {
        let answer = bounded(&answer)?;
        let done = self
            .engine
            .contact_book()
            .in_person_take(answer)
            .await
            .map_err(in_person_error)?;
        Ok(taken(done))
    }

    pub(crate) async fn in_person_take_qr(
        &self,
        parts: Vec<String>,
    ) -> Result<InPersonTaken, WalletError> {
        // Read for its errors first: the engine reports any decode failure as one kind.
        crate::ur_slate::decode_binary(&parts)?;
        let done = self
            .engine
            .contact_book()
            .in_person_take_ur(&parts)
            .await
            .map_err(in_person_error)?;
        Ok(taken(done))
    }

    pub(crate) async fn in_person_answers(
        &self,
        slate: &str,
    ) -> Result<InPersonCodeView, WalletError> {
        let id = slate_id(slate)?;
        let view = self
            .engine
            .contact_book()
            .in_person_answers(id)
            .await
            .map_err(in_person_error)?;
        Ok(InPersonCodeView {
            tx_id: view.tx_id.0,
            slate_id: view.slate_id.to_string(),
            stage: stage(view.stage),
            ttl_cutoff: view.ttl_cutoff,
            mailbox: view.mailbox,
            closed: view.closed,
            finalized: view.finalized,
            answers: view
                .answers
                .into_iter()
                .map(|answer| InPersonAnswerView {
                    number: answer.number,
                    check_code: answer.check_code,
                    same_code: answer.same_code,
                    received_at_ms: ms(answer.received_at),
                })
                .collect(),
        })
    }

    pub(crate) async fn in_person_finalize(
        &self,
        slate: &str,
        answer: u32,
    ) -> Result<FinalizedTx, WalletError> {
        let id = slate_id(slate)?;
        let finalized = self
            .engine
            .contact_book()
            .in_person_finalize(id, answer, lepic_node::Propagation::Fluff)
            .await
            .map_err(in_person_error)?;
        Ok(FinalizedTx {
            tx_id: finalized.tx_id.0,
            slate_id: finalized.slate.id().to_string(),
            posted: !self.offline,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_past_the_largest_answer_is_refused() {
        let long = vec![0u8; MAX_IN_PERSON_INPUT + 1];
        let refused = bounded(&long).map(<[u8]>::len);
        assert_eq!(
            refused.map_err(|e| e.kind),
            Err(WalletErrorKind::InvalidSlate)
        );
        let fits = vec![0u8; MAX_IN_PERSON_INPUT];
        assert_eq!(
            bounded(&fits).map(<[u8]>::len).ok(),
            Some(MAX_IN_PERSON_INPUT)
        );
    }

    #[test]
    fn a_zero_amount_is_refused() {
        assert_eq!(
            positive(0).map_err(|e| e.kind),
            Err(WalletErrorKind::InvalidArgument)
        );
        assert_eq!(positive(5).ok(), Some(Amount::new(5)));
    }
}
