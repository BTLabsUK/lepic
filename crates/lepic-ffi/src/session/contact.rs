//! Contact pairing, sealed slates and invoices between paired contacts (RFC 0002), over the
//! engine's contact calls. Contacts belong to the default account, as invoices do.

use lepic_primitives::amount::Amount;
use lepic_store::{ContactId, ContactOutboxId, ContactOutboxState, ContactState, SealMode, TxId};
use lepic_transport::file::FILE;
use lepic_transport::transport::Location;
use lepic_wallet::ReceiveRequest;
use lepic_wallet::contact::{
    AcceptRequest, CardRequest, CollectTrigger as EngineTrigger, ContactKind as EngineKind,
    ContactRelays, ContactView as EngineContactView, InviteExpiry as EngineExpiry,
    InvitePreview as EnginePreview, InviteRequest, InvoiceDetails,
    KeysDecision as EngineKeysDecision, LinkOutcome, PairingFailure, PairingRole, Purpose,
    RelayMode, SasDecision as EngineSasDecision, SasSymbol, SealedAnswer as EngineAnswer,
};
use lepic_wallet::event::{ContactEvent, ContactSlateEvent, OutboxNews, SlateId};
use lepic_wallet::invoice::{InvoiceRequest, PayRequest};
use lepic_wallet::send::{Delivery, SendError};
use lepic_wallet::slate::{Slate, Stage, WireSlate};
use tracing::{info, warn};

use super::{DEFAULT_ACCOUNT, ScratchFile, Session, invalid};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{
    CollectTrigger, ContactCollectReport, ContactImportSummary, ContactInvoiceView, ContactKind,
    ContactRelayMode, ContactView, FailedPairing, FinalizedTx, FoundInvite, InviteExpiry,
    InvitePreview, IssuedInvoice, KeysDecision, OutboxEntryView, OutboxReport, OutboxState,
    PaidInvoice, PairingAnswer, PairingCard, PairingFailureReason, PairingInvite,
    PairingLinkOutcome, PairingLinkResult, PairingState, PendingPairingView, SasDecision, SasEntry,
    SealState, SealedAnswer, SealedSlateView, SendOptions, SentTx, SlateMessage, SlatePurpose,
    SlateStage, WalletEvent, WalletEventKind,
};

/// The longest sealed text taken from the app: a slate with its envelope and armor fits many
/// times over.
const MAX_SEALED_TEXT: usize = 4 * 1024 * 1024;

/// The longest pairing link, card or reply taken from the app.
const MAX_LINK_TEXT: usize = 16 * 1024;

/// Pairing words a user types; more is never a pairing.
const MAX_TYPED_WORDS: usize = 16;

pub(super) fn contact_id(text: &str) -> Result<ContactId, WalletError> {
    let text = text.trim();
    let mut id = [0u8; 16];
    if text.len() != 32 {
        return Err(invalid("not a contact id"));
    }
    for (slot, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| invalid("not a contact id"))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| invalid("not a contact id"))?;
    }
    Ok(ContactId(id))
}

fn slate_id(text: &str) -> Result<SlateId, WalletError> {
    SlateId::parse(text).map_err(|_| invalid("not a slate id"))
}

fn bounded<'a>(text: &'a str, max: usize, what: &str) -> Result<&'a str, WalletError> {
    if text.len() > max {
        return Err(WalletError::new(
            WalletErrorKind::InvalidPairingText,
            format!("{what} is longer than any LEPIC {what}"),
        ));
    }
    Ok(text)
}

fn ms(time: jiff::Timestamp) -> i64 {
    time.as_millisecond()
}

fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

const fn relay_mode(mode: ContactRelayMode) -> RelayMode {
    match mode {
        ContactRelayMode::Online => RelayMode::Online,
        ContactRelayMode::Offline => RelayMode::Offline,
        ContactRelayMode::EpicboxOff => RelayMode::EpicboxOff,
    }
}

const fn engine_kind(kind: ContactKind) -> EngineKind {
    match kind {
        ContactKind::Person => EngineKind::Person,
        ContactKind::Shop => EngineKind::Shop,
        ContactKind::Exchange => EngineKind::Exchange,
    }
}

const fn kind(kind: EngineKind) -> ContactKind {
    match kind {
        EngineKind::Person => ContactKind::Person,
        EngineKind::Shop => ContactKind::Shop,
        EngineKind::Exchange => ContactKind::Exchange,
    }
}

pub(super) const fn slate_purpose(purpose: Purpose) -> SlatePurpose {
    match purpose {
        Purpose::Payment => SlatePurpose::Payment,
        Purpose::DepositRequest => SlatePurpose::DepositRequest,
        Purpose::Withdrawal => SlatePurpose::Withdrawal,
        Purpose::Refund => SlatePurpose::Refund,
        Purpose::Request => SlatePurpose::Request,
    }
}

const fn engine_purpose(purpose: SlatePurpose) -> Purpose {
    match purpose {
        SlatePurpose::Payment => Purpose::Payment,
        SlatePurpose::DepositRequest => Purpose::DepositRequest,
        SlatePurpose::Withdrawal => Purpose::Withdrawal,
        SlatePurpose::Refund => Purpose::Refund,
        SlatePurpose::Request => Purpose::Request,
    }
}

pub(super) const fn failure_reason(failure: PairingFailure) -> PairingFailureReason {
    match failure {
        PairingFailure::ChangedOnTheWay => PairingFailureReason::ChangedOnTheWay,
        PairingFailure::Expired => PairingFailureReason::Expired,
        PairingFailure::Refused(_) => PairingFailureReason::Refused,
    }
}

const fn state(state: ContactState) -> PairingState {
    match state {
        ContactState::PendingInvite => PairingState::PendingInvite,
        ContactState::PendingReply => PairingState::PendingReply,
        ContactState::Paired => PairingState::Paired,
        ContactState::Verified => PairingState::Verified,
        ContactState::KeysChanged => PairingState::KeysChanged,
    }
}

const fn stage(stage: Stage) -> SlateStage {
    match stage {
        Stage::S1 => SlateStage::S1,
        Stage::S2 => SlateStage::S2,
        Stage::S3 => SlateStage::S3,
        Stage::I1 => SlateStage::I1,
        Stage::I2 => SlateStage::I2,
        Stage::I3 => SlateStage::I3,
    }
}

const fn stored_stage(stage: lepic_store::SlateStage) -> SlateStage {
    use lepic_store::SlateStage as S;
    match stage {
        S::Standard1 => SlateStage::S1,
        S::Standard2 => SlateStage::S2,
        S::Standard3 => SlateStage::S3,
        S::Invoice1 => SlateStage::I1,
        S::Invoice2 => SlateStage::I2,
        S::Invoice3 => SlateStage::I3,
    }
}

fn sas_entries(symbols: &[SasSymbol]) -> Vec<SasEntry> {
    symbols
        .iter()
        .map(|symbol| SasEntry {
            emoji: symbol.emoji.to_owned(),
            name: symbol.name.to_owned(),
        })
        .collect()
}

fn view(view: EngineContactView) -> ContactView {
    ContactView {
        contact_id: view.contact_id.to_string(),
        label: view.label,
        claimed_name: view.claimed_name,
        kind: view.kind.map(kind),
        state: state(view.state),
        sas: view
            .sas
            .as_ref()
            .map(|symbols| sas_entries(symbols))
            .unwrap_or_default(),
        verified_at_ms: view.verified_at.map(ms),
        allow_invoices: view.allow_invoices,
        seal: match view.seal {
            SealMode::On => SealState::On,
            SealMode::Off => SealState::Off,
            SealMode::Degraded => SealState::Degraded,
        },
        app_contact: view.app_contact,
        home_relay: view.home_relay,
        imported_from_backup: view.imported_from_backup,
        lapsed: view.lapsed,
        created_at_ms: ms(view.created_at),
    }
}

fn preview(preview: EnginePreview) -> InvitePreview {
    InvitePreview {
        claimed_name: preview.claimed_name,
        kind: kind(preview.kind),
        expires_at_ms: ms(preview.expires_at),
        home_relay: preview.home_relay,
        service: preview.service,
    }
}

fn wire_text(wire: &WireSlate) -> Result<String, WalletError> {
    wire.as_text()
        .map(str::to_owned)
        .ok_or_else(|| WalletError::new(WalletErrorKind::InvalidSlate, "slate is not text"))
}

fn answer(tx_id: TxId, slate: &Slate, answer: EngineAnswer) -> Result<SealedAnswer, WalletError> {
    let (answer, sealed) = match answer {
        EngineAnswer::Sealed(text) => (text, true),
        EngineAnswer::Plain(wire) => (wire_text(&wire)?, false),
    };
    Ok(SealedAnswer {
        tx_id: tx_id.0,
        slate_id: slate.id().to_string(),
        amount: slate.amount().value(),
        fee: slate.fee().value(),
        answer,
        sealed,
    })
}

pub(super) fn contact_event(kind: WalletEventKind, news: &ContactEvent) -> WalletEvent {
    WalletEvent {
        contact_id: Some(news.contact_id.to_string()),
        ..WalletEvent::of(kind)
    }
}

pub(super) fn slate_event(kind: WalletEventKind, slate: &ContactSlateEvent) -> WalletEvent {
    WalletEvent {
        contact_id: Some(slate.contact_id.to_string()),
        tx_id: Some(slate.tx_id.0),
        slate_id: Some(slate.slate_id.to_string()),
        amount: Some(slate.amount.value()),
        ..WalletEvent::of(kind)
    }
}

pub(super) fn outbox_event(kind: WalletEventKind, news: &OutboxNews) -> WalletEvent {
    WalletEvent {
        contact_id: Some(news.contact_id.to_string()),
        slate_id: Some(news.slate_id.to_string()),
        ..WalletEvent::of(kind)
    }
}

impl Session {
    /// The relays contact calls reach, from the wallet's Epicbox transport.
    fn contact_relays(&self, mode: ContactRelayMode) -> Result<ContactRelays, WalletError> {
        Ok(ContactRelays::new(self.epicbox()?, relay_mode(mode)))
    }

    pub(super) fn pay_request(
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PayRequest, WalletError> {
        let defaults = Self::send_request_with(amount, minimum_confirmations, message, options)?;
        Ok(PayRequest {
            minimum_confirmations,
            strategy: defaults.strategy,
            change_outputs: defaults.change_outputs,
            message: defaults.message,
            ..PayRequest::new(DEFAULT_ACCOUNT, Amount::new(amount))
        })
    }

    pub(crate) async fn pairing_invite(
        &self,
        name: String,
        kind: ContactKind,
        expiry: InviteExpiry,
        offer_words: bool,
        mode: ContactRelayMode,
    ) -> Result<PairingInvite, WalletError> {
        let relays = self.contact_relays(mode)?;
        let offer = self
            .engine
            .pairing_invite(
                &relays,
                InviteRequest {
                    account: DEFAULT_ACCOUNT,
                    name,
                    kind: engine_kind(kind),
                    expiry: match expiry {
                        InviteExpiry::OneHour => EngineExpiry::OneHour,
                        InviteExpiry::OneDay => EngineExpiry::OneDay,
                        InviteExpiry::SevenDays => EngineExpiry::SevenDays,
                    },
                    offer_words,
                },
            )
            .await?;
        Ok(PairingInvite {
            contact_id: offer.contact_id.to_string(),
            link: offer.link,
            expires_at_ms: ms(offer.expires_at),
            words: offer
                .words
                .as_ref()
                .map(|words| sas_entries(words))
                .unwrap_or_default(),
        })
    }

    pub(crate) fn pairing_preview(&self, link: &str) -> Result<InvitePreview, WalletError> {
        let link = bounded(link, MAX_LINK_TEXT, "link")?;
        Ok(preview(self.engine.pairing_preview(link)?))
    }

    pub(crate) async fn pairing_find_words(
        &self,
        words: Vec<String>,
        mode: ContactRelayMode,
    ) -> Result<FoundInvite, WalletError> {
        if words.len() > MAX_TYPED_WORDS || words.iter().any(|word| word.len() > MAX_LINK_TEXT) {
            return Err(WalletError::new(
                WalletErrorKind::InvalidPairingWords,
                "too many or too long pairing words",
            ));
        }
        let relays = self.contact_relays(mode)?;
        let link = self.engine.pairing_find_words(&relays, &words).await?;
        let preview = preview(self.engine.pairing_preview(&link)?);
        Ok(FoundInvite { link, preview })
    }

    pub(crate) async fn pairing_accept(
        &self,
        link: String,
        name: String,
        by_hand: bool,
        mode: ContactRelayMode,
    ) -> Result<PairingAnswer, WalletError> {
        bounded(&link, MAX_LINK_TEXT, "link")?;
        let relays = self.contact_relays(mode)?;
        let outcome = self
            .engine
            .pairing_accept(
                &relays,
                AcceptRequest {
                    link,
                    account: DEFAULT_ACCOUNT,
                    name,
                    by_hand,
                },
            )
            .await?;
        Ok(PairingAnswer {
            contact_id: outcome.contact_id.to_string(),
            reply_link: outcome.reply_link,
            posted: outcome.posted,
        })
    }

    pub(crate) async fn pairing_enter_link(
        &self,
        text: &str,
        mode: ContactRelayMode,
    ) -> Result<PairingLinkResult, WalletError> {
        let text = bounded(text, MAX_LINK_TEXT, "link")?;
        let relays = self.contact_relays(mode)?;
        Ok(match self.engine.pairing_enter_link(&relays, text).await? {
            LinkOutcome::Confirm { contact_id, link } => PairingLinkResult {
                outcome: PairingLinkOutcome::Confirm,
                contact_id: Some(contact_id.to_string()),
                link: Some(link),
            },
            LinkOutcome::Paired { contact_id } => PairingLinkResult {
                outcome: PairingLinkOutcome::Paired,
                contact_id: Some(contact_id.to_string()),
                link: None,
            },
            LinkOutcome::Ignored => PairingLinkResult {
                outcome: PairingLinkOutcome::Ignored,
                contact_id: None,
                link: None,
            },
        })
    }

    pub(crate) async fn pairing_show_card(
        &self,
        name: String,
        kind: ContactKind,
        mode: ContactRelayMode,
    ) -> Result<PairingCard, WalletError> {
        let relays = self.contact_relays(mode)?;
        let offer = self
            .engine
            .pairing_show_card(
                &relays,
                CardRequest {
                    account: DEFAULT_ACCOUNT,
                    name,
                    kind: engine_kind(kind),
                },
            )
            .await?;
        Ok(PairingCard {
            contact_id: offer.contact_id.to_string(),
            link: offer.link,
        })
    }

    pub(crate) async fn pairing_scan_card(
        &self,
        contact_id: &str,
        link: &str,
        mode: ContactRelayMode,
    ) -> Result<ContactView, WalletError> {
        let id = self::contact_id(contact_id)?;
        let link = bounded(link, MAX_LINK_TEXT, "link")?;
        let relays = self.contact_relays(mode)?;
        Ok(view(
            self.engine.pairing_scan_card(&relays, id, link).await?,
        ))
    }

    pub(crate) async fn pairing_sas(
        &self,
        contact_id: &str,
        decision: SasDecision,
        mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        let relays = self.contact_relays(mode)?;
        let decision = match decision {
            SasDecision::Match => EngineSasDecision::Match,
            SasDecision::Mismatch => EngineSasDecision::Mismatch,
            SasDecision::Skip => EngineSasDecision::Skip,
        };
        Ok(self.engine.pairing_sas(&relays, id, decision).await?)
    }

    pub(crate) async fn contacts_collect(
        &self,
        trigger: CollectTrigger,
        mode: ContactRelayMode,
    ) -> Result<ContactCollectReport, WalletError> {
        let relays = self.contact_relays(mode)?;
        let trigger = match trigger {
            CollectTrigger::Open => EngineTrigger::Open,
            CollectTrigger::Foreground => EngineTrigger::Foreground,
            CollectTrigger::Pull => EngineTrigger::Pull,
            CollectTrigger::Push => EngineTrigger::Push,
        };
        let report = self.engine.contacts_collect(&relays, trigger).await?;
        Ok(ContactCollectReport {
            mailboxes: count(report.mailboxes),
            messages: count(report.messages),
            paired: count(report.paired),
            failed: report
                .failed
                .iter()
                .map(|failed| FailedPairing {
                    contact_id: failed.contact_id.to_string(),
                    reason: failure_reason(failed.reason),
                })
                .collect(),
            delivered: count(report.delivered),
            unreachable: report.unreachable,
        })
    }

    pub(crate) async fn contacts(&self) -> Result<Vec<ContactView>, WalletError> {
        Ok(self
            .engine
            .contacts()
            .await?
            .into_iter()
            .map(view)
            .collect())
    }

    pub(crate) async fn contact(&self, contact_id: &str) -> Result<ContactView, WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(view(self.engine.contact(id).await?))
    }

    pub(crate) async fn pairings_for_app_contact(
        &self,
        app_contact: &str,
    ) -> Result<Vec<ContactView>, WalletError> {
        Ok(self
            .engine
            .contacts()
            .await?
            .into_iter()
            .filter(|contact| contact.app_contact.as_deref() == Some(app_contact))
            .map(view)
            .collect())
    }

    pub(crate) async fn pairings_pending(&self) -> Result<Vec<PendingPairingView>, WalletError> {
        Ok(self
            .engine
            .pairings_pending()
            .await?
            .into_iter()
            .map(|pending| PendingPairingView {
                contact_id: pending.contact_id.to_string(),
                inviter: pending.role == PairingRole::Inviter,
                invite_name: pending.invite_name,
                label: pending.label,
                expires_at_ms: ms(pending.expires_at),
                created_at_ms: ms(pending.created_at),
            })
            .collect())
    }

    pub(crate) async fn pairing_cancel(&self, contact_id: &str) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        let pending = self.engine.pairings_pending().await?;
        if !pending.iter().any(|pairing| pairing.contact_id == id) {
            return Err(WalletError::new(
                WalletErrorKind::PairingNotFound,
                "no such pairing in progress",
            ));
        }
        self.engine.contact_remove(id).await?;
        Ok(())
    }

    pub(crate) async fn contact_remove(&self, contact_id: &str) -> Result<bool, WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self.engine.contact_remove(id).await?)
    }

    pub(crate) async fn contact_set_label(
        &self,
        contact_id: &str,
        label: String,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self.engine.contact_set_label(id, label).await?)
    }

    pub(crate) async fn contact_set_seal(
        &self,
        contact_id: &str,
        seal: bool,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self.engine.contact_set_seal(id, seal).await?)
    }

    pub(crate) async fn contact_set_allow_invoices(
        &self,
        contact_id: &str,
        allow: bool,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self.engine.contact_set_allow_invoices(id, allow).await?)
    }

    pub(crate) async fn contact_attach(
        &self,
        contact_id: &str,
        app_contact: Option<String>,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self.engine.contact_attach(id, app_contact).await?)
    }

    pub(crate) async fn contact_key_check(
        &self,
        new: &str,
        old: &str,
        mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        let (new, old) = (contact_id(new)?, contact_id(old)?);
        let relays = self.contact_relays(mode)?;
        Ok(self.engine.contact_key_check(&relays, new, old).await?)
    }

    pub(crate) async fn contact_keys_resolve(
        &self,
        new: &str,
        decision: KeysDecision,
    ) -> Result<(), WalletError> {
        let new = contact_id(new)?;
        let decision = match decision {
            KeysDecision::KeepOld => EngineKeysDecision::KeepOld,
            KeysDecision::UseNew => EngineKeysDecision::UseNew,
        };
        Ok(self.engine.contact_keys_resolve(new, decision).await?)
    }

    pub(crate) async fn contact_seal_slate(
        &self,
        contact_id: &str,
        tx_id: u32,
        purpose: Option<SlatePurpose>,
    ) -> Result<String, WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self
            .engine
            .contact_seal_slate(id, TxId(tx_id), purpose.map(engine_purpose))
            .await?)
    }

    pub(crate) async fn contact_post_slate(
        &self,
        contact_id: &str,
        tx_id: u32,
        purpose: Option<SlatePurpose>,
        mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        let relays = self.contact_relays(mode)?;
        Ok(self
            .engine
            .contact_post_slate(&relays, id, TxId(tx_id), purpose.map(engine_purpose))
            .await?)
    }

    /// Checks the contact first, so a send it cannot take locks nothing, and cancels the send
    /// when it cannot be queued after all.
    #[allow(clippy::too_many_arguments)] // The app's send form, one value per field.
    pub(crate) async fn contact_send(
        &self,
        contact_id: &str,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        purpose: Option<SlatePurpose>,
        mode: ContactRelayMode,
    ) -> Result<SentTx, WalletError> {
        let id = self::contact_id(contact_id)?;
        let relays = self.contact_relays(mode)?;
        self.engine.contact_check_mailbox_send(id).await?;
        let scratch = ScratchFile::new(&self.data_dir)?;
        let sent = match self
            .engine
            .send(
                Self::send_request_with(amount, minimum_confirmations, message, options)?,
                Delivery::Export {
                    transport: FILE,
                    to: Location::File(scratch.path.clone()),
                },
            )
            .await
        {
            Ok(sent) => super::sent_tx(&sent),
            // Stored and locked, but the scratch file was not written: nothing reaches the
            // contact, so the send is given up rather than left holding its inputs.
            Err(error @ SendError::Undelivered { tx_id, .. }) => {
                if let Err(cancel) = self.engine.cancel(tx_id).await {
                    warn!(tx_id = %tx_id, error = %cancel, "send to a contact not written nor cancelled");
                }
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        let tx_id = TxId(sent.tx_id);
        if let Err(error) = self
            .engine
            .contact_post_slate(&relays, id, tx_id, purpose.map(engine_purpose))
            .await
        {
            match self.engine.cancel(tx_id).await {
                Ok(()) => info!(tx_id = %tx_id, "send to a contact cancelled, it was not queued"),
                Err(cancel) => {
                    warn!(tx_id = %tx_id, error = %cancel, "send to a contact not queued nor cancelled");
                }
            }
            return Err(error.into());
        }
        Ok(sent)
    }

    pub(crate) async fn sealed_open(&self, text: &str) -> Result<SealedSlateView, WalletError> {
        let text = bounded(text, MAX_SEALED_TEXT, "sealed text")?;
        let sealed = self.engine.sealed_open(text).await?;
        let info = crate::inspect::inspect(wire_text(&sealed.wire)?, self.network)?;
        Ok(SealedSlateView {
            contact_id: sealed.contact_id.map(|id| id.to_string()),
            stage: stage(sealed.stage),
            slate_id: info.slate_id,
            amount: info.amount,
            fee: info.fee,
            purpose: sealed.purpose.map(slate_purpose),
            reference: sealed.reference,
            expires: sealed.expires,
            messages: sealed
                .messages
                .iter()
                .map(|message| SlateMessage {
                    role: message.role.into(),
                    text: message.text.clone(),
                })
                .collect(),
        })
    }

    pub(crate) async fn sealed_receive(
        &self,
        text: &str,
        message: Option<String>,
    ) -> Result<SealedAnswer, WalletError> {
        let text = bounded(text, MAX_SEALED_TEXT, "sealed text")?;
        let done = self
            .engine
            .sealed_receive(
                text,
                ReceiveRequest {
                    account: None,
                    message,
                },
            )
            .await?;
        answer(done.received.tx_id, &done.received.slate, done.answer)
    }

    pub(crate) async fn sealed_pay(
        &self,
        text: &str,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SealedAnswer, WalletError> {
        let text = bounded(text, MAX_SEALED_TEXT, "sealed text")?;
        let request = Self::pay_request(amount, minimum_confirmations, message, options)?;
        let done = self.engine.sealed_pay(text, request).await?;
        answer(done.paid.tx_id, &done.paid.slate, done.answer)
    }

    pub(crate) async fn sealed_finalize(&self, text: &str) -> Result<FinalizedTx, WalletError> {
        let text = bounded(text, MAX_SEALED_TEXT, "sealed text")?;
        let finalized = self
            .engine
            .sealed_finalize(text, lepic_node::Propagation::Fluff)
            .await?;
        Ok(FinalizedTx {
            tx_id: finalized.tx_id.0,
            slate_id: finalized.slate.id().to_string(),
        })
    }

    pub(crate) fn sealed_answer_to_marker(
        &self,
        incoming: String,
        reply: String,
    ) -> Result<Option<String>, WalletError> {
        bounded(&incoming, MAX_SEALED_TEXT, "slate")?;
        bounded(&reply, MAX_SEALED_TEXT, "slate")?;
        let incoming = WireSlate::text(lepic_wallet::slate::MediaType::JSON, incoming);
        let reply = WireSlate::text(lepic_wallet::slate::MediaType::JSON, reply);
        Ok(self.engine.sealed_answer_to_marker(&incoming, &reply)?)
    }

    pub(crate) async fn contact_plain_fallback(&self, tx_id: u32) -> Result<String, WalletError> {
        wire_text(&self.engine.contact_plain_fallback(TxId(tx_id)).await?)
    }

    pub(crate) async fn contact_of_transaction(
        &self,
        tx_id: u32,
    ) -> Result<Option<String>, WalletError> {
        Ok(self
            .engine
            .contact_of_transaction(TxId(tx_id))
            .await?
            .map(|id| id.to_string()))
    }

    #[allow(clippy::too_many_arguments)] // Mirrors the app's invoice form, one value per field.
    pub(crate) async fn contact_issue_invoice(
        &self,
        contact_id: &str,
        amount: u64,
        message: Option<String>,
        purpose: SlatePurpose,
        reference: Option<String>,
        expires: Option<u64>,
        mode: ContactRelayMode,
    ) -> Result<IssuedInvoice, WalletError> {
        let id = self::contact_id(contact_id)?;
        let relays = self.contact_relays(mode)?;
        let issued = self
            .engine
            .contact_issue_invoice(
                &relays,
                id,
                InvoiceRequest {
                    account: DEFAULT_ACCOUNT,
                    amount: Amount::new(amount),
                    message,
                },
                InvoiceDetails {
                    purpose: engine_purpose(purpose),
                    reference,
                    expires,
                },
            )
            .await?;
        Ok(IssuedInvoice {
            tx_id: issued.tx_id.0,
            slate_id: issued.slate_id.to_string(),
            amount: issued.amount.value(),
        })
    }

    pub(crate) async fn contact_invoices(&self) -> Result<Vec<ContactInvoiceView>, WalletError> {
        Ok(self
            .engine
            .contact_invoices()
            .await?
            .into_iter()
            .map(|invoice| ContactInvoiceView {
                slate_id: invoice.slate_id.to_string(),
                contact_id: invoice.contact_id.to_string(),
                amount: invoice.amount.value(),
                purpose: invoice.purpose.map(slate_purpose),
                reference: invoice.reference,
                expires: invoice.expires,
                message: invoice.message,
                received_at_ms: ms(invoice.received_at),
                same_amount: invoice
                    .same_amount
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            })
            .collect())
    }

    pub(crate) async fn contact_pay_invoice(
        &self,
        slate_id: &str,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        mode: ContactRelayMode,
    ) -> Result<PaidInvoice, WalletError> {
        let slate_id = self::slate_id(slate_id)?;
        let request = Self::pay_request(amount, minimum_confirmations, message, options)?;
        let relays = self.contact_relays(mode)?;
        let paid = self
            .engine
            .contact_pay_invoice(&relays, slate_id, request)
            .await?;
        Ok(PaidInvoice {
            tx_id: paid.tx_id.0,
            slate_id: paid.slate.id().to_string(),
            amount: paid.slate.amount().value(),
            fee: paid.slate.fee().value(),
        })
    }

    pub(crate) async fn contact_decline_invoice(&self, slate_id: &str) -> Result<(), WalletError> {
        let slate_id = self::slate_id(slate_id)?;
        Ok(self.engine.contact_decline_invoice(slate_id).await?)
    }

    pub(crate) async fn contact_outbox(
        &self,
        contact_id: &str,
    ) -> Result<Vec<OutboxEntryView>, WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self
            .engine
            .contact_outbox(id)
            .await?
            .into_iter()
            .map(|entry| OutboxEntryView {
                id: entry.id.0,
                contact_id: entry.contact_id.to_string(),
                slate_id: entry.slate_id.to_string(),
                stage: stored_stage(entry.stage),
                state: match entry.state {
                    ContactOutboxState::Queued => OutboxState::Queued,
                    ContactOutboxState::Delivered => OutboxState::Delivered,
                    ContactOutboxState::Stuck => OutboxState::Stuck,
                },
                attempts: entry.attempts,
                created_at_ms: ms(entry.created_at),
                delivered_at_ms: entry.delivered_at.map(ms),
                not_posted_yet: entry.not_posted_yet,
            })
            .collect())
    }

    pub(crate) async fn contact_outbox_resend(
        &self,
        id: u64,
        mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        let relays = self.contact_relays(mode)?;
        Ok(self
            .engine
            .contact_outbox_resend(&relays, ContactOutboxId(id))
            .await?)
    }

    pub(crate) async fn contacts_outbox_deliver(
        &self,
        mode: ContactRelayMode,
    ) -> Result<OutboxReport, WalletError> {
        let relays = self.contact_relays(mode)?;
        let report = self.engine.contacts_outbox_deliver(&relays).await?;
        Ok(OutboxReport {
            delivered: count(report.delivered),
            failed: count(report.failed),
            stuck: count(report.stuck),
        })
    }

    pub(crate) async fn contacts_export(&self) -> Result<String, WalletError> {
        Ok(self.engine.contacts_export().await?)
    }

    pub(crate) async fn contacts_import(
        &self,
        document: String,
    ) -> Result<ContactImportSummary, WalletError> {
        let summary = self.engine.contacts_import(document).await?;
        Ok(ContactImportSummary {
            imported: count(summary.imported),
            skipped_existing: count(summary.skipped_existing),
            skipped_conflict: count(summary.skipped_conflict),
        })
    }
}

#[cfg(test)]
mod tests {
    use lepic_wallet::Event;
    use lepic_wallet::event::{ContactInvoiceEvent, FailedPairing, UnreachableRelay};

    use super::*;

    fn mapped(event: &Event) -> WalletEvent {
        super::super::wallet_event(event).unwrap()
    }

    #[test]
    fn contact_events_carry_ids_and_labels_only() {
        let contact_id = ContactId([7; 16]);
        let id = contact_id.to_string();
        let slate_id = SlateId::from_bytes([9; 16]);
        let news = ContactEvent { contact_id };
        for (event, kind) in [
            (Event::PairingReplied(news), WalletEventKind::PairingReplied),
            (
                Event::PairingConfirmed(news),
                WalletEventKind::PairingConfirmed,
            ),
            (Event::ContactUpdated(news), WalletEventKind::ContactUpdated),
            (
                Event::ContactKeysRestored(news),
                WalletEventKind::ContactKeysRestored,
            ),
            (
                Event::ContactKeysChanged(news),
                WalletEventKind::ContactKeysChanged,
            ),
            (
                Event::SealedUnopenable(news),
                WalletEventKind::SealedUnopenable,
            ),
        ] {
            let mapped = mapped(&event);
            assert_eq!(mapped.kind, kind);
            assert_eq!(mapped.contact_id.as_deref(), Some(id.as_str()));
            assert_eq!(mapped.slate_id, None);
        }

        let failed = mapped(&Event::PairingFailed(FailedPairing {
            contact_id,
            reason: PairingFailure::Refused(lepic_wallet::contact::Refusal::AlreadyUsed),
        }));
        assert_eq!(failed.kind, WalletEventKind::PairingFailed);
        assert_eq!(failed.pairing_failure, Some(PairingFailureReason::Refused));

        let relay = mapped(&Event::HomeRelayUnreachable(UnreachableRelay {
            relay: "relay.example:443".to_owned(),
        }));
        assert_eq!(relay.kind, WalletEventKind::HomeRelayUnreachable);
        assert_eq!(relay.relay.as_deref(), Some("relay.example:443"));

        let invoice = mapped(&Event::InvoiceFromContact(ContactInvoiceEvent {
            contact_id,
            slate_id,
            amount: Amount::new(5),
            purpose: Some(Purpose::DepositRequest),
            reference: Some("order-1".to_owned()),
            expires: Some(99),
            message: Some("for order 1".to_owned()),
        }));
        assert_eq!(invoice.kind, WalletEventKind::InvoiceFromContact);
        assert_eq!(invoice.amount, Some(5));
        assert_eq!(invoice.purpose, Some(SlatePurpose::DepositRequest));
        assert_eq!(invoice.reference.as_deref(), Some("order-1"));
        assert_eq!(invoice.expires, Some(99));
        assert_eq!(invoice.message.as_deref(), Some("for order 1"));

        let slate = ContactSlateEvent {
            contact_id,
            tx_id: TxId(3),
            slate_id,
            amount: Amount::new(8),
        };
        for (event, kind) in [
            (
                Event::SealedReceived(slate),
                WalletEventKind::SealedReceived,
            ),
            (
                Event::WithdrawalFromContact(slate),
                WalletEventKind::WithdrawalFromContact,
            ),
            (
                Event::ContactPaymentFinalized(slate),
                WalletEventKind::ContactPaymentFinalized,
            ),
        ] {
            let mapped = mapped(&event);
            assert_eq!(mapped.kind, kind);
            assert_eq!((mapped.tx_id, mapped.amount), (Some(3), Some(8)));
            assert_eq!(mapped.contact_id.as_deref(), Some(id.as_str()));
            assert_eq!(mapped.slate_id, Some(slate_id.to_string()));
        }
        let outbox = OutboxNews {
            contact_id,
            slate_id,
        };
        for (event, kind) in [
            (
                Event::OutboxDelivered(outbox),
                WalletEventKind::OutboxDelivered,
            ),
            (Event::OutboxStuck(outbox), WalletEventKind::OutboxStuck),
        ] {
            let mapped = mapped(&event);
            assert_eq!(mapped.kind, kind);
            assert_eq!(mapped.slate_id, Some(slate_id.to_string()));
        }
    }

    #[test]
    fn contact_ids_are_32_hex_characters() {
        let id = ContactId([0xab; 16]);
        assert_eq!(contact_id(&id.to_string()).unwrap(), id);
        for text in [
            "",
            "ab",
            &"g".repeat(32),
            &"ab".repeat(17),
            "é".repeat(16).as_str(),
        ] {
            assert_eq!(
                contact_id(text).unwrap_err().kind,
                WalletErrorKind::InvalidArgument,
                "{text:?}"
            );
        }
    }
}
