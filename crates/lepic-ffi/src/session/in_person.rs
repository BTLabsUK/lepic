// SPDX-License-Identifier: Apache-2.0
//! In-person invoices and sends (EPICTX): codes shown as raw `lepic.v1` slates, answers sealed
//! to the code's reply key and posted to its reply mailbox or shown back, and the answer the
//! user picks by its check code finalized. Codes and answers belong to the default account.

use lepic_primitives::amount::{Amount, Fee};
use lepic_transport::host_rule::{HostClass, HostReport};
use lepic_wallet::ReceiveRequest;
use lepic_wallet::send::SendRequest;
use lepic_wallet_contacts::{
    ClaimSigner, ContactError, InPersonInvoiceRequest, InvoiceLinkError, MethodId, RequestVerdict,
    RouteEntry, WalletContacts,
};

use super::contact::{ms, slate_id, stage};
use super::{DEFAULT_ACCOUNT, Session};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{
    ContactRelayMode, FinalizedTx, InPersonAnswerView, InPersonClaim, InPersonCode,
    InPersonCodeView, InPersonDomainCheck, InPersonDomainState, InPersonHost,
    InPersonInvoiceOptions, InPersonPostOutcome, InPersonPosted, InPersonRead, InPersonReply,
    InPersonRoute, InPersonRoutePost, InPersonTaken, SendOptions, SlateWire,
};

/// The longest code or answer taken from the app: the largest slate envelope, as bytes or as
/// its `BEGINEPICTX.` text.
const MAX_IN_PERSON_INPUT: usize = 128 * 1024;

/// Refuses input longer than any in-person code or answer before the engine reads it.
pub(crate) fn bounded(bytes: &[u8]) -> Result<&[u8], WalletError> {
    if bytes.len() > MAX_IN_PERSON_INPUT {
        return Err(WalletError::new(
            WalletErrorKind::InvalidSlate,
            "longer than any in-person code or answer",
        ));
    }
    Ok(bytes)
}

/// A link that is not an invoice link is a wrong argument; one that is, but does not hold an
/// invoice code, a damaged slate.
pub(crate) fn link_error(error: &InvoiceLinkError) -> WalletError {
    let kind = match error {
        InvoiceLinkError::TooLong | InvoiceLinkError::Prefix => WalletErrorKind::InvalidArgument,
        _ => WalletErrorKind::InvalidSlate,
    };
    WalletError::chained(kind, error)
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

fn route(entry: RouteEntry) -> InPersonRoute {
    InPersonRoute {
        method: entry.method.to_string(),
        value: entry.value,
    }
}

/// A direct route from the app; the engine checks the address when it issues the code.
fn route_entry(route: InPersonRoute) -> Result<RouteEntry, WalletError> {
    let method = route.method.parse::<MethodId>().map_err(|_| {
        WalletError::new(
            WalletErrorKind::InvalidArgument,
            "a direct route's method is not http or tor",
        )
    })?;
    Ok(RouteEntry {
        method,
        value: route.value,
    })
}

fn route_post(post: lepic_wallet_contacts::InPersonRoutePost) -> InPersonRoutePost {
    use lepic_wallet_contacts::InPersonPostOutcome as Outcome;
    let (outcome, reason) = match post.outcome {
        Outcome::Accepted => (InPersonPostOutcome::Accepted, None),
        Outcome::Refused { reason } => (InPersonPostOutcome::Refused, reason),
        Outcome::Failed { reason } => (InPersonPostOutcome::Failed, Some(reason)),
    };
    InPersonRoutePost {
        route: route(post.route),
        outcome,
        reason,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        },
    )
}

/// A code's domain claim as checked against the domain's well-known file.
pub(crate) fn domain_check(verdict: RequestVerdict) -> InPersonDomainCheck {
    match verdict {
        RequestVerdict::Unsigned => InPersonDomainCheck {
            state: InPersonDomainState::Unsigned,
            domain: None,
            reason: None,
        },
        RequestVerdict::Checked { domain } => InPersonDomainCheck {
            state: InPersonDomainState::Checked,
            domain: Some(domain.as_str().to_owned()),
            reason: None,
        },
        RequestVerdict::Refused { domain, reason } => InPersonDomainCheck {
            state: InPersonDomainState::Refused,
            domain: Some(domain.as_str().to_owned()),
            reason: Some(reason.as_str().to_owned()),
        },
    }
}

fn code(code: lepic_wallet_contacts::InPersonCode) -> InPersonCode {
    InPersonCode {
        tx_id: code.tx_id.0,
        slate_id: code.slate_id.to_string(),
        bytes: code.bytes,
        ttl_cutoff: code.ttl_cutoff,
        mailbox: code.mailbox,
        format: SlateWire::Native,
    }
}

fn reply(paid: lepic_wallet_contacts::InPersonPaid) -> InPersonReply {
    InPersonReply {
        tx_id: paid.tx_id.0,
        slate_id: paid.slate_id.to_string(),
        armored: lepic_wallet_contacts::armor_tx(&paid.envelope),
        envelope: paid.envelope,
        mailbox: paid.mailbox.map(host),
        format: SlateWire::Native,
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
        options: InPersonInvoiceOptions,
        mode: ContactRelayMode,
    ) -> Result<InPersonCode, WalletError> {
        let amount = positive(amount)?;
        let slate_id = options.slate_id.as_deref().map(slate_id).transpose()?;
        let direct = options
            .direct
            .into_iter()
            .map(route_entry)
            .collect::<Result<Vec<_>, _>>()?;
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
                    slate_id,
                    direct,
                    claim: options.claim_domain.map(|domain| ClaimSigner { domain }),
                    shared_slot: options.shared_slot,
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
            claim: read.claim.map(|claim| InPersonClaim {
                domain: claim.domain.as_str().to_owned(),
                key: hex(claim.key.as_bytes()),
                issued_at: claim.issued_at,
            }),
            direct: read.direct.into_iter().map(route).collect(),
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
        mode: ContactRelayMode,
    ) -> Result<InPersonPosted, WalletError> {
        let id = slate_id(slate)?;
        let relays = self.contact_relays(mode)?;
        let posted = self
            .engine
            .contact_book()
            .in_person_post(&relays, id)
            .await
            .map_err(in_person_error)?;
        Ok(InPersonPosted {
            check_code: posted.check_code,
            // An in-person answer is always `lepic.v1`.
            format: SlateWire::Native,
            routes: posted.routes.into_iter().map(route_post).collect(),
        })
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
