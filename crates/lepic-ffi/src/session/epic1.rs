// SPDX-License-Identifier: Apache-2.0
//! Payments to epic1 links (EPICTX), and sealed text opened as it arrived. Links and payments
//! belong to the default account.

use lepic_primitives::amount::Amount;
use lepic_transport::host_rule::{HostClass, HostReport};
use lepic_wallet_contacts::{
    Epic1LinkKind as EngineKind, Epic1LinkRequest, Epic1PayRequest, WalletContacts,
};

use super::contact::{ms, slate_id, slate_purpose};
use super::{DEFAULT_ACCOUNT, ScratchFile, Session};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{
    ContactRelayMode, Epic1AnswerView, Epic1Attempt, Epic1Host, Epic1Link, Epic1LinkKind,
    Epic1LinkRead, Epic1LinkView, Epic1Paid, EpictxView, HostClassView, SendOptions, SlateWire,
};

/// The longest link text taken from the app; a link carries at most three relays and short
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

const fn engine_kind(kind: Epic1LinkKind) -> EngineKind {
    match kind {
        Epic1LinkKind::OnScreen => EngineKind::OnScreen,
        Epic1LinkKind::Printed => EngineKind::Printed,
    }
}

const fn link_kind(kind: EngineKind) -> Epic1LinkKind {
    match kind {
        EngineKind::OnScreen => Epic1LinkKind::OnScreen,
        EngineKind::Printed => Epic1LinkKind::Printed,
    }
}

fn host(report: HostReport) -> Epic1Host {
    Epic1Host {
        host: report.host,
        port: report.port,
        class: match report.class {
            HostClass::Public => HostClassView::Public,
            HostClass::LocalNetwork => HostClassView::LocalNetwork,
        },
        in_relay_list: report.in_relay_list,
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
            })
            .collect(),
        // At most three transports.
        posted: paid
            .posted
            .map(|index| u32::try_from(index).unwrap_or(u32::MAX)),
        format: SlateWire::Native,
    }
}

impl Session {
    pub(crate) fn epic1_address(&self) -> Result<String, WalletError> {
        Ok(self
            .engine
            .contact_book()
            .epic1_address(DEFAULT_ACCOUNT)?
            .encode())
    }

    pub(crate) async fn epic1_link_make(
        &self,
        amount: Option<u64>,
        message: Option<String>,
        kind: Epic1LinkKind,
        relays: Vec<String>,
        mode: ContactRelayMode,
    ) -> Result<Epic1Link, WalletError> {
        let amount = amount.map(positive).transpose()?;
        if relays.iter().any(|relay| relay.len() > MAX_LINK_TEXT) {
            return Err(WalletError::new(
                WalletErrorKind::Epic1RelayInvalid,
                "link relay too long",
            ));
        }
        let contact_relays = self.contact_relays(mode)?;
        let issued = self
            .engine
            .contact_book()
            .epic1_link(
                &contact_relays,
                Epic1LinkRequest {
                    account: DEFAULT_ACCOUNT,
                    // The app's link pays the account's first address.
                    index: 0,
                    amount,
                    message,
                    kind: engine_kind(kind),
                    relays,
                },
            )
            .await?;
        Ok(Epic1Link {
            link: issued.link,
            address: issued.address,
            kind: link_kind(issued.kind),
            n: issued.n,
        })
    }

    pub(crate) async fn epic1_links(&self) -> Result<Vec<Epic1LinkView>, WalletError> {
        Ok(self
            .engine
            .contact_book()
            .epic1_links()
            .await?
            .into_iter()
            .filter(|view| view.account == DEFAULT_ACCOUNT)
            .map(|view| Epic1LinkView {
                kind: link_kind(view.kind),
                n: view.n,
                issued_at_ms: ms(view.issued_at),
                used_at_ms: view.used_at.map(ms),
                relays: view.relays,
            })
            .collect())
    }

    pub(crate) async fn epic1_link_retire(&self, n: u32) -> Result<(), WalletError> {
        Ok(self
            .engine
            .contact_book()
            .epic1_retire(DEFAULT_ACCOUNT, n)
            .await?)
    }

    pub(crate) fn epic1_link_read(
        &self,
        link: &str,
        mode: ContactRelayMode,
    ) -> Result<Epic1LinkRead, WalletError> {
        let link = bounded(link, MAX_LINK_TEXT, "link")?;
        let relays = self.contact_relays(mode)?;
        let read = self.engine.contact_book().epic1_read(&relays, link)?;
        Ok(Epic1LinkRead {
            address: read.address,
            amount: read.amount.map(Amount::value),
            message: read.message,
            label: read.label,
            hosts: read.hosts.into_iter().map(host).collect(),
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
        proof: bool,
        hosts_ok: bool,
        mode: ContactRelayMode,
    ) -> Result<Epic1Paid, WalletError> {
        bounded(&link, MAX_LINK_TEXT, "link")?;
        let relays = self.contact_relays(mode)?;
        let book = self.engine.contact_book();
        let amount = match amount {
            Some(amount) => amount,
            None => book
                .epic1_read(&relays, &link)?
                .amount
                .map(Amount::value)
                .ok_or_else(|| {
                    WalletError::new(
                        WalletErrorKind::InvalidArgument,
                        "the link asks no amount: give one",
                    )
                })?,
        };
        positive(amount)?;
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
                    proof,
                    slate_file: scratch.path.clone(),
                },
                hosts_ok,
            )
            .await?;
        Ok(paid(done))
    }

    pub(crate) async fn epic1_post_next(
        &self,
        slate: &str,
        hosts_ok: bool,
        mode: ContactRelayMode,
    ) -> Result<Epic1Paid, WalletError> {
        let id = slate_id(slate)?;
        let relays = self.contact_relays(mode)?;
        let done = self
            .engine
            .contact_book()
            .epic1_post_next(&relays, id, hosts_ok)
            .await?;
        Ok(paid(done))
    }

    pub(crate) async fn epic1_answers(
        &self,
        mode: ContactRelayMode,
    ) -> Result<Vec<Epic1AnswerView>, WalletError> {
        let relays = self.contact_relays(mode)?;
        Ok(self
            .engine
            .contact_book()
            .epic1_answers(&relays)
            .await?
            .into_iter()
            .map(|view| Epic1AnswerView {
                tx_id: view.tx_id.0,
                slate_id: view.slate_id.to_string(),
                mailbox: view.mailbox,
                host: view.report.map(host),
                posted: view.posted,
            })
            .collect())
    }

    pub(crate) async fn epic1_post_answer(
        &self,
        slate: &str,
        relay_ok: bool,
        mode: ContactRelayMode,
    ) -> Result<SlateWire, WalletError> {
        let id = slate_id(slate)?;
        let relays = self.contact_relays(mode)?;
        self.engine
            .contact_book()
            .epic1_post_answer(&relays, id, relay_ok)
            .await?;
        // An epic1 answer is always `lepic.v1`.
        Ok(SlateWire::Native)
    }

    pub(crate) async fn epic1_restore(&self, mode: ContactRelayMode) -> Result<u32, WalletError> {
        let relays = self.contact_relays(mode)?;
        let taken = self.engine.contact_book().epic1_restore(&relays).await?;
        Ok(u32::try_from(taken).unwrap_or(u32::MAX))
    }

    pub(crate) async fn epic1_issuing(&self) -> Result<bool, WalletError> {
        Ok(self.engine.contact_book().epic1_issuing().await?)
    }

    pub(crate) async fn epic1_issue_here(&self) -> Result<(), WalletError> {
        Ok(self.engine.contact_book().epic1_issue_here().await?)
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
    fn link_kinds_map_both_ways() {
        for kind in [Epic1LinkKind::OnScreen, Epic1LinkKind::Printed] {
            assert_eq!(link_kind(engine_kind(kind)), kind);
        }
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
