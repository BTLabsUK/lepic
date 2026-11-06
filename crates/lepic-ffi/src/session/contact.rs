// SPDX-License-Identifier: Apache-2.0
//! Contact pairing, sealed slates and invoices between paired contacts (RFC 0002), over the
//! engine's contact calls. Contacts belong to the default account, as invoices do.

use lepic_primitives::amount::Amount;
use lepic_store::{ContactId, ContactOutboxId, ContactOutboxState, ContactState, SealMode, TxId};
use lepic_wallet::ReceiveRequest;
use lepic_wallet::event::{ContactEvent, ContactSlateEvent, OutboxNews, SlateId};
use lepic_wallet::invoice::InvoiceRequest;
use lepic_wallet::slate::{Slate, Stage, WireSlate};
use lepic_wallet_contacts::{
    AcceptRequest, CardRequest, CollectTrigger as EngineTrigger, ContactKind as EngineKind,
    ContactRelays, ContactView as EngineContactView, InviteExpiry as EngineExpiry,
    InvitePreview as EnginePreview, InviteRequest, InvoiceDetails,
    KeyCheckStart as EngineKeyCheckStart, KeysDecision as EngineKeysDecision, LinkOutcome,
    PairingClass as EngineClass, PairingFailure, PairingRole, Purpose, RelayMode,
    SasDecision as EngineSasDecision, SasSymbol, SealedAnswer as EngineAnswer, WalletContacts,
};

use super::{DEFAULT_ACCOUNT, ScratchFile, Session, invalid};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{
    CollectTrigger, ContactChange as FfiChange, ContactCollectReport, ContactImportSummary,
    ContactInvoiceView, ContactKind, ContactPayloadView, ContactRelayMode, ContactView,
    DomainVerdict, EndedPairing, FailedPairing, FinalizedTx, FoundInvite, InviteExpiry,
    InvitePreview, IssuedInvoice, KeyCheckStart, KeysDecision, OutboxEntryView, OutboxReport,
    OutboxState, PaidInvoice, PairRequestView, PairingAnswer, PairingCard, PairingClass,
    PairingEndReason as FfiEndReason, PairingFailureReason, PairingInvite, PairingLinkOutcome,
    PairingLinkResult, PairingState, PairingStatus as FfiStatus, PendingPairingView, SasDecision,
    SasEntry, SealState, SealedAnswer, SealedSlateView, SendOptions, SentTx, SlateMessage,
    SlatePurpose, SlateStage, WalletEvent, WalletEventKind,
};

/// The longest sealed text taken from the app: a slate with its envelope and armor fits many
/// times over.
const MAX_SEALED_TEXT: usize = 4 * 1024 * 1024;

/// The longest pairing link, card or reply taken from the app.
const MAX_LINK_TEXT: usize = 16 * 1024;

/// Contact ids one collect may be limited to.
const MAX_COLLECT_ONLY: usize = 64;

/// A relay host, `domain[:port]`, is at most this long.
const MAX_RELAY_HOST: usize = 260;

/// Pairing words a user types; more is never a pairing.
const MAX_TYPED_WORDS: usize = 16;

/// Refuses an address that is not an Epicbox address of `network`.
fn check_address(
    address: Option<&str>,
    network: lepic_primitives::params::Network,
) -> Result<(), WalletError> {
    match address {
        Some(address) if super::relay_address(address, network).is_none() => {
            Err(invalid("not an Epicbox address of this network"))
        }
        _ => Ok(()),
    }
}

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

/// Refuses a home relay longer than a relay host can be before the engine parses it.
fn check_home_relay(host: Option<&str>) -> Result<(), WalletError> {
    if host.is_some_and(|host| host.len() > MAX_RELAY_HOST) {
        return Err(WalletError::new(
            WalletErrorKind::InvalidArgument,
            "home relay too long",
        ));
    }
    Ok(())
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
        PairingFailure::KindDiffers => PairingFailureReason::KindDiffers,
        PairingFailure::Expired => PairingFailureReason::Expired,
        PairingFailure::NotConfirmed => PairingFailureReason::NotConfirmed,
        PairingFailure::Refused(_) => PairingFailureReason::Refused,
        PairingFailure::OtherAddress => PairingFailureReason::OtherAddress,
        PairingFailure::AddressProofMissing => PairingFailureReason::AddressProofMissing,
        PairingFailure::Crossed => PairingFailureReason::Crossed,
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
        last_sealed_in_ms: view.last_sealed_in.map(ms),
        removed_by_peer: view.removed_by_peer,
        requested_relay: view.requested_relay,
        payments_address: view.payments_address,
        created_at_ms: ms(view.created_at),
        status: match view.status {
            lepic_wallet_contacts::PairingStatus::Waiting => FfiStatus::Waiting,
            lepic_wallet_contacts::PairingStatus::Paired => FfiStatus::Paired,
            lepic_wallet_contacts::PairingStatus::Verified => FfiStatus::Verified,
            lepic_wallet_contacts::PairingStatus::KeysChanged => FfiStatus::KeysChanged,
            lepic_wallet_contacts::PairingStatus::Ended => FfiStatus::Ended,
        },
        peer_heard_at_ms: view.peer_heard_at.map(ms),
        peer_verified_at_ms: view.peer_verified_at.map(ms),
        peer_features: view.peer_features,
        peer_profile: view.peer_profile,
        peer_domain: view.peer_domain,
        peer_domain_attestation: view.peer_domain_attestation,
        peer_enc_key: view.peer_enc_key.map(|key| key.to_vec()),
        ended_reason: view.ended_reason.map(end_reason),
        ended_at_ms: view.ended_at.map(ms),
    }
}

pub(super) const fn end_reason(reason: lepic_store::PairingEndReason) -> FfiEndReason {
    use lepic_store::PairingEndReason as R;
    match reason {
        R::Mismatch => FfiEndReason::Mismatch,
        R::PeerMismatch => FfiEndReason::PeerMismatch,
        R::Unpaired => FfiEndReason::Unpaired,
        R::NeverFinished => FfiEndReason::NeverFinished,
    }
}

/// The `ContactUpdated` event of `update`.
pub(super) fn update_event(update: &lepic_wallet::event::ContactUpdate) -> WalletEvent {
    use lepic_wallet::event::ContactChange as C;
    WalletEvent {
        contact_id: Some(update.contact_id.to_string()),
        contact_change: Some(match update.change {
            C::Card => FfiChange::Card,
            C::Address => FfiChange::Address,
            C::Heard => FfiChange::Heard,
            C::PeerVerified => FfiChange::PeerVerified,
            C::Ended => FfiChange::Ended,
        }),
        ended_reason: update.ended_reason.map(end_reason),
        ..WalletEvent::of(WalletEventKind::ContactUpdated)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A request id: 16 lowercase hex characters.
fn request_id(text: &str) -> Result<[u8; lepic_store::INVITE_ID_LEN], WalletError> {
    let wrong = || invalid("request id is not 16 hex characters");
    if text.len() != 16 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(wrong());
    }
    let mut id = [0u8; lepic_store::INVITE_ID_LEN];
    for (slot, pair) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| wrong())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| wrong())?;
    }
    Ok(id)
}

fn preview(preview: EnginePreview) -> InvitePreview {
    InvitePreview {
        claimed_name: preview.claimed_name,
        kind: kind(preview.kind),
        expires_at_ms: ms(preview.expires_at),
        home_relay: preview.home_relay,
        service: preview.service,
        pairing_class: match preview.class {
            EngineClass::Contact => PairingClass::Contact,
            EngineClass::Private => PairingClass::Private,
        },
        own: preview.own,
    }
}

pub(super) const fn engine_class(class: PairingClass) -> EngineClass {
    match class {
        PairingClass::Contact => EngineClass::Contact,
        PairingClass::Private => EngineClass::Private,
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

    /// The relays contact calls reach, with `meeting` as the meeting relays. With none the
    /// engine refuses pairing words after its online checks.
    fn meeting_relays(
        &self,
        mode: ContactRelayMode,
        meeting: &[String],
    ) -> Result<ContactRelays, WalletError> {
        let relays = self.contact_relays(mode)?;
        if meeting.is_empty() {
            return Ok(relays);
        }
        if meeting.iter().any(|host| host.len() > MAX_RELAY_HOST) {
            return Err(WalletError::new(
                WalletErrorKind::InvalidArgument,
                "meeting relay too long",
            ));
        }
        Ok(relays.with_meeting(lepic_wallet_contacts::meeting_relays(meeting)?))
    }

    #[allow(clippy::too_many_arguments)] // One argument per choice of the Dart call.
    pub(crate) async fn pairing_invite(
        &self,
        name: String,
        kind: ContactKind,
        expiry: InviteExpiry,
        offer_words: bool,
        mode: ContactRelayMode,
        meeting: Vec<String>,
        home_relay: Option<String>,
        class: PairingClass,
        expect_address: Option<String>,
    ) -> Result<PairingInvite, WalletError> {
        check_home_relay(home_relay.as_deref())?;
        check_address(expect_address.as_deref(), self.network)?;
        let relays = if offer_words {
            self.meeting_relays(mode, &meeting)?
        } else {
            self.contact_relays(mode)?
        };
        let offer = self
            .engine
            .contact_book()
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
                    home_relay,
                    class: engine_class(class),
                    expect_address,
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

    pub(crate) async fn pairing_preview(&self, link: &str) -> Result<InvitePreview, WalletError> {
        let link = bounded(link, MAX_LINK_TEXT, "link")?;
        Ok(preview(
            self.engine.contact_book().pairing_preview(link).await?,
        ))
    }

    pub(crate) async fn pairing_find_words(
        &self,
        words: Vec<String>,
        mode: ContactRelayMode,
        meeting: Vec<String>,
    ) -> Result<FoundInvite, WalletError> {
        if words.len() > MAX_TYPED_WORDS || words.iter().any(|word| word.len() > MAX_LINK_TEXT) {
            return Err(WalletError::new(
                WalletErrorKind::InvalidPairingWords,
                "too many or too long pairing words",
            ));
        }
        let relays = self.meeting_relays(mode, &meeting)?;
        let link = self
            .engine
            .contact_book()
            .pairing_find_words(&relays, &words)
            .await?;
        let preview = preview(self.engine.contact_book().pairing_preview(&link).await?);
        Ok(FoundInvite { link, preview })
    }

    pub(crate) async fn pairing_accept(
        &self,
        link: String,
        name: String,
        by_hand: bool,
        mode: ContactRelayMode,
        class: PairingClass,
        expect_address: Option<String>,
    ) -> Result<PairingAnswer, WalletError> {
        bounded(&link, MAX_LINK_TEXT, "link")?;
        check_address(expect_address.as_deref(), self.network)?;
        let relays = self.contact_relays(mode)?;
        let outcome = self
            .engine
            .contact_book()
            .pairing_accept(
                &relays,
                AcceptRequest {
                    link,
                    account: DEFAULT_ACCOUNT,
                    name,
                    by_hand,
                    class: engine_class(class),
                    expect_address,
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
        Ok(
            match self
                .engine
                .contact_book()
                .pairing_enter_link(&relays, text)
                .await?
            {
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
            },
        )
    }

    pub(crate) async fn pairing_show_card(
        &self,
        name: String,
        kind: ContactKind,
        mode: ContactRelayMode,
        home_relay: Option<String>,
    ) -> Result<PairingCard, WalletError> {
        check_home_relay(home_relay.as_deref())?;
        let relays = self.contact_relays(mode)?;
        let offer = self
            .engine
            .contact_book()
            .pairing_show_card(
                &relays,
                CardRequest {
                    account: DEFAULT_ACCOUNT,
                    name,
                    kind: engine_kind(kind),
                    home_relay,
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
            self.engine
                .contact_book()
                .pairing_scan_card(&relays, id, link)
                .await?,
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
        Ok(self
            .engine
            .contact_book()
            .pairing_sas(&relays, id, decision)
            .await?)
    }

    pub(crate) async fn contacts_collect(
        &self,
        trigger: CollectTrigger,
        mode: ContactRelayMode,
        only: Option<Vec<String>>,
    ) -> Result<ContactCollectReport, WalletError> {
        let only = only
            .map(|ids| {
                if ids.len() > MAX_COLLECT_ONLY {
                    return Err(WalletError::new(
                        WalletErrorKind::InvalidArgument,
                        "too many contact ids to collect",
                    ));
                }
                ids.iter()
                    .map(|id| contact_id(id))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let relays = self.contact_relays(mode)?;
        let trigger = match trigger {
            CollectTrigger::Open => EngineTrigger::Open,
            CollectTrigger::Foreground => EngineTrigger::Foreground,
            CollectTrigger::Pull => EngineTrigger::Pull,
            CollectTrigger::Push => EngineTrigger::Push,
        };
        let report = self
            .engine
            .contact_book()
            .contacts_collect_only(&relays, trigger, only.as_deref())
            .await?;
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
            ended: report
                .ended
                .iter()
                .map(|ended| EndedPairing {
                    contact_id: ended.contact_id.to_string(),
                    reason: end_reason(ended.reason),
                })
                .collect(),
        })
    }

    pub(crate) async fn contacts(&self) -> Result<Vec<ContactView>, WalletError> {
        Ok(self
            .engine
            .contact_book()
            .contacts()
            .await?
            .into_iter()
            .map(view)
            .collect())
    }

    pub(crate) async fn contact(&self, contact_id: &str) -> Result<ContactView, WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(view(self.engine.contact_book().contact(id).await?))
    }

    pub(crate) async fn pairings_for_app_contact(
        &self,
        app_contact: &str,
    ) -> Result<Vec<ContactView>, WalletError> {
        Ok(self
            .engine
            .contact_book()
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
            .contact_book()
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
                home_relay: pending.home_relay,
                expect_address: pending.expect_address,
            })
            .collect())
    }

    pub(crate) async fn pairing_standing_invite(
        &self,
        name: String,
    ) -> Result<PairingInvite, WalletError> {
        let relays = self.contact_relays(ContactRelayMode::Online)?;
        let offer = self
            .engine
            .contact_book()
            .pairing_standing_invite(&relays, DEFAULT_ACCOUNT, &name)
            .await?;
        Ok(PairingInvite {
            contact_id: offer.contact_id.to_string(),
            link: offer.link,
            expires_at_ms: ms(offer.expires_at),
            words: Vec::new(),
        })
    }

    pub(crate) async fn pairing_request_send(
        &self,
        to_address: String,
        name: String,
        mode: ContactRelayMode,
    ) -> Result<PendingPairingView, WalletError> {
        bounded(&to_address, MAX_LINK_TEXT, "address")?;
        if super::relay_address(&to_address, self.network).is_none() {
            return Err(invalid("not an Epicbox address of this network"));
        }
        let relays = self.contact_relays(mode)?;
        let offer = self
            .engine
            .contact_book()
            .pairing_request_send(&relays, DEFAULT_ACCOUNT, &to_address, &name)
            .await?;
        let id = offer.contact_id.to_string();
        self.pairings_pending()
            .await?
            .into_iter()
            .find(|pending| pending.contact_id == id)
            .ok_or_else(|| WalletError::new(WalletErrorKind::PairingNotFound, "request not kept"))
    }

    pub(crate) async fn pairing_requests(&self) -> Result<Vec<PairRequestView>, WalletError> {
        Ok(self
            .engine
            .contact_book()
            .pairing_requests()
            .await?
            .into_iter()
            .map(|request| PairRequestView {
                request_id: hex(&request.request_id),
                from_address: request.from_address,
                claimed_name: request.claimed_name,
                kind: kind(request.kind),
                received_at_ms: ms(request.received_at),
                expires_at_ms: ms(request.expires_at),
                invite_link: request.invite_link,
            })
            .collect())
    }

    pub(crate) async fn pairing_request_dismiss(
        &self,
        request_id: &str,
    ) -> Result<(), WalletError> {
        let id = self::request_id(request_id)?;
        self.engine
            .contact_book()
            .pairing_request_dismiss(id)
            .await
            .map_err(|error| match error {
                lepic_wallet_contacts::ContactError::UnknownPairing => {
                    WalletError::new(WalletErrorKind::PairingNotFound, "no such pairing request")
                }
                other => other.into(),
            })
    }

    pub(crate) async fn contacts_set_own_name(&self, name: String) -> Result<u32, WalletError> {
        let relays = self.contact_relays(ContactRelayMode::Online)?;
        Ok(self
            .engine
            .contact_book()
            .contacts_set_own_name(&relays, &name)
            .await?)
    }

    pub(crate) async fn contacts_move_home(
        &self,
        relay: String,
        drain_days: u32,
    ) -> Result<u32, WalletError> {
        if drain_days > 365 {
            return Err(WalletError::new(
                WalletErrorKind::InvalidArgument,
                "drain longer than 365 days",
            ));
        }
        let drain = std::time::Duration::from_secs(24 * 60 * 60).saturating_mul(drain_days);
        let relays = self.contact_relays(ContactRelayMode::Online)?;
        Ok(self
            .engine
            .contact_book()
            .contacts_move_home(&relays, &relay, drain)
            .await?)
    }

    pub(crate) async fn contact_check(&self, contact_id: &str) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        let relays = self.contact_relays(ContactRelayMode::Online)?;
        Ok(self
            .engine
            .contact_book()
            .contact_check(&relays, id)
            .await?)
    }

    pub(crate) async fn contact_domain_verify(
        &self,
        contact_id: &str,
        file: &[u8],
    ) -> Result<DomainVerdict, WalletError> {
        let id = self::contact_id(contact_id)?;
        let verdict = self.engine.contact_book().domain_verify(id, file).await?;
        Ok(match verdict {
            lepic_wallet_contacts::DomainVerdict::Proven => DomainVerdict {
                proven: true,
                refused: None,
            },
            lepic_wallet_contacts::DomainVerdict::Refused(reason) => DomainVerdict {
                proven: false,
                refused: Some(reason.to_string()),
            },
        })
    }

    pub(crate) async fn pairing_cancel(&self, contact_id: &str) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        let pending = self.engine.contact_book().pairings_pending().await?;
        if !pending.iter().any(|pairing| pairing.contact_id == id) {
            return Err(WalletError::new(
                WalletErrorKind::PairingNotFound,
                "no such pairing in progress",
            ));
        }
        self.engine.contact_book().pairing_cancel(id).await?;
        Ok(())
    }

    pub(crate) async fn contact_remove(&self, contact_id: &str) -> Result<bool, WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self.engine.contact_book().contact_remove(id).await?)
    }

    pub(crate) async fn contact_unpair(
        &self,
        contact_id: &str,
        mode: ContactRelayMode,
    ) -> Result<bool, WalletError> {
        let id = self::contact_id(contact_id)?;
        let relays = self.contact_relays(mode)?;
        Ok(self
            .engine
            .contact_book()
            .contact_unpair(&relays, id)
            .await?)
    }

    pub(crate) async fn contact_set_label(
        &self,
        contact_id: &str,
        label: String,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self
            .engine
            .contact_book()
            .contact_set_label(id, label)
            .await?)
    }

    pub(crate) async fn contact_apply_relay_move(
        &self,
        contact_id: &str,
        relay: &str,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self
            .engine
            .contact_book()
            .apply_relay_move(id, relay)
            .await?)
    }

    pub(crate) async fn contact_set_seal(
        &self,
        contact_id: &str,
        seal: bool,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self
            .engine
            .contact_book()
            .contact_set_seal(id, seal)
            .await?)
    }

    pub(crate) async fn contact_set_allow_invoices(
        &self,
        contact_id: &str,
        allow: bool,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self
            .engine
            .contact_book()
            .contact_set_allow_invoices(id, allow)
            .await?)
    }

    pub(crate) async fn contact_attach(
        &self,
        contact_id: &str,
        app_contact: Option<String>,
        app_address: Option<String>,
    ) -> Result<(), WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self
            .engine
            .contact_book()
            .contact_attach(id, app_contact, app_address)
            .await?)
    }

    pub(crate) async fn contact_key_check(
        &self,
        new: &str,
        old: &str,
        mode: ContactRelayMode,
    ) -> Result<KeyCheckStart, WalletError> {
        let (new, old) = (contact_id(new)?, contact_id(old)?);
        let relays = self.contact_relays(mode)?;
        Ok(
            match self
                .engine
                .contact_book()
                .contact_key_check(&relays, new, old)
                .await?
            {
                EngineKeyCheckStart::Sent => KeyCheckStart::Sent,
                EngineKeyCheckStart::KeysChanged => KeyCheckStart::KeysChanged,
            },
        )
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
        Ok(self
            .engine
            .contact_book()
            .contact_keys_resolve(new, decision)
            .await?)
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
            .contact_book()
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
            .contact_book()
            .contact_post_slate(&relays, id, TxId(tx_id), purpose.map(engine_purpose))
            .await?)
    }

    /// Pays a contact through its mailbox, as the engine's `contact_send` describes.
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
        let request =
            self.policy
                .send_request_with(amount, minimum_confirmations, message, options)?;
        let scratch = ScratchFile::new(&self.data_dir)?;
        let sent = self
            .engine
            .contact_book()
            .contact_send(
                &relays,
                id,
                request,
                scratch.path.clone(),
                purpose.map(engine_purpose),
            )
            .await?;
        Ok(super::sent_tx(&sent))
    }

    pub(crate) async fn sealed_open(&self, text: &str) -> Result<SealedSlateView, WalletError> {
        let text = bounded(text, MAX_SEALED_TEXT, "sealed text")?;
        let sealed = self.engine.contact_book().sealed_open(text).await?;
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
            .contact_book()
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
        let request = self
            .policy
            .pay_request(amount, minimum_confirmations, message, options)?;
        let done = self.engine.contact_book().sealed_pay(text, request).await?;
        answer(done.paid.tx_id, &done.paid.slate, done.answer)
    }

    pub(crate) async fn sealed_finalize(&self, text: &str) -> Result<FinalizedTx, WalletError> {
        let text = bounded(text, MAX_SEALED_TEXT, "sealed text")?;
        let finalized = self
            .engine
            .contact_book()
            .sealed_finalize(text, lepic_node::Propagation::Fluff)
            .await?;
        Ok(FinalizedTx {
            tx_id: finalized.tx_id.0,
            slate_id: finalized.slate.id().to_string(),
            posted: !self.offline,
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
        Ok(self
            .engine
            .contact_book()
            .sealed_answer_to_marker(&incoming, &reply)?)
    }

    pub(crate) async fn contact_plain_fallback(&self, tx_id: u32) -> Result<String, WalletError> {
        wire_text(
            &self
                .engine
                .contact_book()
                .contact_plain_fallback(TxId(tx_id))
                .await?,
        )
    }

    pub(crate) async fn contact_of_transaction(
        &self,
        tx_id: u32,
    ) -> Result<Option<String>, WalletError> {
        Ok(self
            .engine
            .contact_book()
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
            .contact_book()
            .contact_issue_invoice(
                &relays,
                id,
                InvoiceRequest {
                    account: DEFAULT_ACCOUNT,
                    amount: Amount::new(amount),
                    message,
                    ttl_blocks: None,
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
            .contact_book()
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
        let request = self
            .policy
            .pay_request(amount, minimum_confirmations, message, options)?;
        let relays = self.contact_relays(mode)?;
        let paid = self
            .engine
            .contact_book()
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
        Ok(self
            .engine
            .contact_book()
            .contact_decline_invoice(slate_id)
            .await?)
    }

    pub(crate) async fn contact_outbox(
        &self,
        contact_id: &str,
    ) -> Result<Vec<OutboxEntryView>, WalletError> {
        let id = self::contact_id(contact_id)?;
        Ok(self
            .engine
            .contact_book()
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
            .contact_book()
            .contact_outbox_resend(&relays, ContactOutboxId(id))
            .await?)
    }

    pub(crate) async fn contact_post_payload(
        &self,
        contact_id: &str,
        payload: Vec<u8>,
        mode: ContactRelayMode,
    ) -> Result<String, WalletError> {
        let id = super::contact::contact_id(contact_id)?;
        if payload.len() > lepic_wallet_contacts::MAX_APP_PAYLOAD_LEN {
            return Err(WalletError::new(
                WalletErrorKind::InvalidArgument,
                "payload larger than one message carries",
            ));
        }
        let relays = self.contact_relays(mode)?;
        let sent = self
            .engine
            .contact_book()
            .contact_post_payload(&relays, id, payload)
            .await?;
        Ok(sent.id.to_string())
    }

    pub(crate) async fn private_pairings(&self) -> Result<Vec<ContactView>, WalletError> {
        Ok(self
            .engine
            .contact_book()
            .private_pairings()
            .await?
            .into_iter()
            .map(view)
            .collect())
    }

    pub(crate) async fn contact_payloads(&self) -> Result<Vec<ContactPayloadView>, WalletError> {
        Ok(self
            .engine
            .contact_book()
            .contact_payloads()
            .await?
            .into_iter()
            .map(|kept| ContactPayloadView {
                id: kept.id.to_string(),
                contact_id: kept.contact_id.to_string(),
                received_at_ms: ms(kept.received_at),
                payload: kept.payload,
            })
            .collect())
    }

    pub(crate) async fn contact_payloads_ack(&self, ids: Vec<String>) -> Result<u32, WalletError> {
        if ids.len() > lepic_wallet_contacts::MAX_KEPT_PAYLOADS {
            return Err(WalletError::new(
                WalletErrorKind::InvalidArgument,
                "more payload ids than are ever kept",
            ));
        }
        let ids = ids
            .iter()
            .map(|id| {
                lepic_wallet_contacts::PayloadId::parse(id).ok_or_else(|| {
                    WalletError::new(WalletErrorKind::InvalidArgument, "not a payload id")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(count(
            self.engine
                .contact_book()
                .contact_payloads_ack(&ids)
                .await?,
        ))
    }

    pub(crate) async fn contacts_outbox_deliver(
        &self,
        mode: ContactRelayMode,
    ) -> Result<OutboxReport, WalletError> {
        let relays = self.contact_relays(mode)?;
        let report = self
            .engine
            .contact_book()
            .contacts_outbox_deliver(&relays)
            .await?;
        Ok(OutboxReport {
            delivered: count(report.delivered),
            failed: count(report.failed),
            stuck: count(report.stuck),
        })
    }

    pub(crate) async fn contacts_export(&self) -> Result<String, WalletError> {
        Ok(self.engine.contact_book().contacts_export().await?)
    }

    pub(crate) async fn contacts_import(
        &self,
        document: String,
    ) -> Result<ContactImportSummary, WalletError> {
        let summary = self.engine.contact_book().contacts_import(document).await?;
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
    #[allow(clippy::too_many_lines)] // A test reads best as one table of cases.
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
            (
                Event::ContactUpdated(lepic_wallet::event::ContactUpdate::of(
                    contact_id,
                    lepic_wallet::event::ContactChange::Card,
                )),
                WalletEventKind::ContactUpdated,
            ),
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
            (
                Event::ContactPayloadsParked(news),
                WalletEventKind::ContactPayloadsParked,
            ),
        ] {
            let mapped = mapped(&event);
            assert_eq!(mapped.kind, kind);
            assert_eq!(mapped.contact_id.as_deref(), Some(id.as_str()));
            assert_eq!(mapped.slate_id, None);
        }

        let failed = mapped(&Event::PairingFailed(FailedPairing {
            contact_id,
            reason: PairingFailure::Refused(lepic_wallet_contacts::Refusal::AlreadyUsed),
        }));
        assert_eq!(failed.kind, WalletEventKind::PairingFailed);
        assert_eq!(failed.pairing_failure, Some(PairingFailureReason::Refused));

        let relay = mapped(&Event::HomeRelayUnreachable(UnreachableRelay {
            relay: "relay.example:443".to_owned(),
        }));
        assert_eq!(relay.kind, WalletEventKind::HomeRelayUnreachable);
        assert_eq!(relay.relay.as_deref(), Some("relay.example:443"));

        let moved = mapped(&Event::ContactRelayMoveRequested(
            lepic_wallet::event::RelayMoveRequest {
                contact_id,
                host: "relay2.example:443".to_owned(),
            },
        ));
        assert_eq!(moved.kind, WalletEventKind::ContactRelayMoveRequested);
        assert_eq!(moved.contact_id.as_deref(), Some(id.as_str()));
        assert_eq!(moved.relay.as_deref(), Some("relay2.example:443"));

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
