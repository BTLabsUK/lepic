// SPDX-License-Identifier: Apache-2.0
//! Contact pairing through the binding, between wallets on the mock relay: by link, by hand,
//! in person and by pairing words, the words check, the settings of a contact, sealed slates,
//! invoices between contacts, the outbox and the backup.

use std::sync::Arc;

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;

use super::kind;
use crate::api::diagnostics::LogLevel;
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{
    Chain, CollectTrigger, ContactKind, ContactRelayMode, FailedPairing, InviteExpiry,
    KeysDecision, OutboxState, PairingClass, PairingFailureReason, PairingLinkOutcome,
    PairingState, PairingStatus, SasDecision, SealState, SlateMessage, SlatePurpose, SlateRole,
    SlateStage, WalletConfig,
};
use crate::api::wallet::EpicWallet;

use ContactRelayMode::{EpicboxOff, Offline, Online};

pub(super) const EPIC: u64 = 100_000_000;

/// The wallets' relay and their meeting relay, so pairing words are offered; the mock relay
/// serves it.
pub(super) const RELAY: &str = "relay.example.org";

/// The meeting relays every pairing call names, as the app's settings would.
fn meeting() -> Vec<String> {
    vec![RELAY.to_owned()]
}

pub(super) struct World {
    pub(super) chain: MockChain,
    pub(super) runtime: LepicRuntime,
    _relay: MockRelay,
    dirs: Vec<tempfile::TempDir>,
}

impl World {
    pub(super) fn new() -> Self {
        let chain = MockChain::new(1).unwrap();
        let mut runtime = chain.runtime(LogLevel::Warn).unwrap();
        let relay = MockRelay::new(RelayNetwork::Floonet);
        Arc::get_mut(&mut runtime.inner).unwrap().relay = Some(relay.connector());
        Self {
            chain,
            runtime,
            _relay: relay,
            dirs: Vec::new(),
        }
    }

    pub(super) fn config(&mut self, epicbox_domain: &str) -> WalletConfig {
        let dir = tempfile::tempdir().unwrap();
        let config = WalletConfig {
            policy: Default::default(),
            data_dir: dir.path().to_string_lossy().into_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:1".to_owned(),
            node_api_secret: None,
            epicbox_domain: epicbox_domain.to_owned(),
            epicbox_port: 443,
            onion_routes: Vec::new(),
            tuning: crate::tuning::shipped(),
            offline: false,
            tor_wanted: false,
            host_features: 0,
            profile: 0,
            domain: None,
        };
        self.dirs.push(dir);
        config
    }

    async fn wallet_with(&mut self, mnemonic: Option<String>) -> EpicWallet {
        let config = self.config(RELAY);
        EpicWallet::create(
            &self.runtime,
            config,
            &AppSecretStore::in_memory(),
            mnemonic,
            None,
            "password".to_owned(),
        )
        .await
        .unwrap()
    }

    pub(super) async fn wallet(&mut self) -> EpicWallet {
        self.wallet_with(None).await
    }

    pub(super) async fn funded(&mut self) -> EpicWallet {
        let wallet = self.wallet().await;
        let phrase = wallet.mnemonic("password".to_owned()).await.unwrap();
        self.chain
            .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
            .unwrap();
        self.chain.set_height(20);
        wallet.session().scan_to_tip().await;
        wallet
    }
}

/// Pairs `anna` and `ben` by an invite link through the relay. Returns each side's id of the
/// other.
pub(super) async fn pair(anna: &EpicWallet, ben: &EpicWallet) -> (String, String) {
    let invite = anna
        .pairing_invite(
            "Anna".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            false,
            Online,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    let answer = ben
        .pairing_accept(
            invite.link,
            "Ben".to_owned(),
            false,
            Online,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    assert!(answer.posted);
    let collected = anna
        .contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    assert_eq!(collected.paired, 1);
    let collected = ben
        .contacts_collect(CollectTrigger::Pull, Online, None)
        .await
        .unwrap();
    assert_eq!(collected.paired, 1);
    // Anna hears that Ben finished.
    anna.contacts_collect(CollectTrigger::Pull, Online, None)
        .await
        .unwrap();
    (invite.contact_id, answer.contact_id)
}

/// Pairs and confirms the words on both sides.
async fn verified_pair(anna: &EpicWallet, ben: &EpicWallet) -> (String, String) {
    let (anna_side, ben_side) = pair(anna, ben).await;
    anna.pairing_sas(anna_side.clone(), SasDecision::Match, Online)
        .await
        .unwrap();
    ben.pairing_sas(ben_side.clone(), SasDecision::Match, Online)
        .await
        .unwrap();
    (anna_side, ben_side)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
async fn a_payload_goes_to_the_paired_contact_and_waits_for_its_ack() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let (contact, _) = pair(&anna, &ben).await;
    // A contact pairing carries payloads once paired, before the words check.
    let to_contact = anna
        .contact_post_payload(contact, vec![1], Online)
        .await
        .unwrap();
    let invite = anna
        .pairing_invite(
            "Phone".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            false,
            Online,
            meeting(),
            None,
            PairingClass::Private,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        anna.pairing_preview(invite.link.clone())
            .await
            .unwrap()
            .pairing_class,
        PairingClass::Private
    );
    assert_eq!(
        kind(
            ben.pairing_accept(
                invite.link.clone(),
                "Desk".to_owned(),
                false,
                Online,
                PairingClass::Contact,
                None
            )
            .await
        ),
        WalletErrorKind::WrongPairingClass
    );
    let answer = ben
        .pairing_accept(
            invite.link,
            "Desk".to_owned(),
            false,
            Online,
            PairingClass::Private,
            None,
        )
        .await
        .unwrap();
    anna.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    ben.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    let from_contact = ben.contact_payloads().await.unwrap();
    assert_eq!(from_contact.len(), 1);
    assert_eq!(
        (
            from_contact[0].id.as_str(),
            from_contact[0].payload.as_slice()
        ),
        (to_contact.as_str(), [1].as_slice())
    );
    assert_eq!(ben.contact_payloads_ack(vec![to_contact]).await.unwrap(), 1);
    let (anna_side, ben_side) = (invite.contact_id, answer.contact_id);
    for (wallet, id) in [(&anna, &anna_side), (&ben, &ben_side)] {
        let private = wallet.private_pairings().await.unwrap();
        assert_eq!(private.len(), 1);
        assert!(
            !wallet
                .contacts()
                .await
                .unwrap()
                .iter()
                .any(|view| view.contact_id == *id)
        );
        wallet
            .pairing_sas(id.clone(), SasDecision::Match, Online)
            .await
            .unwrap();
    }

    let id = anna
        .contact_post_payload(anna_side.clone(), vec![1, 2, 3], Online)
        .await
        .unwrap();
    assert_eq!(
        kind(
            anna.contact_post_payload(anna_side, vec![0; 64 * 1024 + 1], Online)
                .await
        ),
        WalletErrorKind::InvalidArgument
    );
    ben.contacts_collect(CollectTrigger::Pull, Online, Some(vec![ben_side.clone()]))
        .await
        .unwrap();

    let kept = ben.contact_payloads().await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(
        (kept[0].id.as_str(), kept[0].payload.as_slice()),
        (id.as_str(), [1, 2, 3].as_slice())
    );
    assert_eq!(kept[0].contact_id, ben_side);
    assert_eq!(ben.contact_payloads_ack(vec![id]).await.unwrap(), 1);
    assert!(ben.contact_payloads().await.unwrap().is_empty());
    assert_eq!(
        kind(ben.contact_payloads_ack(vec!["nope".to_owned()]).await),
        WalletErrorKind::InvalidArgument
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_wallets_pair_by_link_and_show_the_same_words() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let invite = anna
        .pairing_invite(
            "Anna".to_owned(),
            ContactKind::Shop,
            InviteExpiry::OneHour,
            false,
            Online,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    assert!(invite.link.starts_with("epiccash://pair/1/"));
    assert!(invite.words.is_empty());
    let preview = ben.pairing_preview(invite.link.clone()).await.unwrap();
    assert_eq!(preview.claimed_name, "Anna");
    assert_eq!(preview.kind, ContactKind::Person);
    assert_eq!(preview.home_relay, format!("{RELAY}:443"));
    assert!(!preview.service);
    // The link carries whole seconds.
    assert_eq!(preview.expires_at_ms / 1000, invite.expires_at_ms / 1000);

    let answer = ben
        .pairing_accept(
            invite.link,
            "Ben".to_owned(),
            false,
            Online,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    assert!(answer.reply_link.starts_with("epiccash://pair-reply/1/"));
    anna.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    ben.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();

    let anna_view = anna.contact(invite.contact_id.clone()).await.unwrap();
    let ben_view = ben.contact(answer.contact_id.clone()).await.unwrap();
    assert_eq!(anna_view.state, PairingState::Paired);
    assert_eq!(ben_view.state, PairingState::Paired);
    assert_eq!(anna_view.claimed_name.as_deref(), Some("Ben"));
    assert_eq!(ben_view.claimed_name.as_deref(), Some("Anna"));
    assert_eq!(ben_view.kind, Some(ContactKind::Person));
    assert_eq!(anna_view.sas.len(), 4);
    assert_eq!(anna_view.sas, ben_view.sas);
    assert_eq!(
        anna_view.home_relay.as_deref(),
        Some(format!("{RELAY}:443").as_str())
    );
    assert_eq!(anna_view.seal, SealState::On);
    assert_eq!(anna.contacts().await.unwrap(), vec![anna_view]);
    assert!(anna.pairings_pending().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_words_check_verifies_or_removes_the_pairing() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let carl = world.wallet().await;
    let (anna_side, ben_side) = pair(&anna, &ben).await;

    anna.pairing_sas(anna_side.clone(), SasDecision::Match, Online)
        .await
        .unwrap();
    let view = anna.contact(anna_side.clone()).await.unwrap();
    assert_eq!(view.state, PairingState::Verified);
    assert!(view.verified_at_ms.is_some());
    ben.pairing_sas(ben_side.clone(), SasDecision::Skip, Online)
        .await
        .unwrap();
    assert_eq!(
        ben.contact(ben_side).await.unwrap().state,
        PairingState::Paired
    );

    let (carl_side, _) = pair(&carl, &anna).await;
    carl.pairing_sas(carl_side.clone(), SasDecision::Mismatch, Offline)
        .await
        .unwrap();
    // A mismatch ends the pairing and keeps it; no later check changes it.
    assert!(carl.contact(carl_side.clone()).await.is_ok());
    assert_eq!(
        carl.contact(carl_side.clone()).await.unwrap().status,
        PairingStatus::Ended
    );
    assert_eq!(
        kind(
            carl.pairing_sas(carl_side, SasDecision::Match, Online)
                .await
        ),
        WalletErrorKind::PairingEnded
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pairing_by_hand_needs_no_relay() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let invite = anna
        .pairing_invite(
            "Anna".to_owned(),
            ContactKind::Person,
            InviteExpiry::SevenDays,
            false,
            Offline,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    let answer = ben
        .pairing_accept(
            invite.link,
            "Ben".to_owned(),
            true,
            Offline,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    assert!(!answer.posted);
    let pending = ben.pairings_pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert!(!pending[0].inviter);
    assert_eq!(pending[0].invite_name, "Anna");

    let confirm = anna
        .pairing_enter_link(answer.reply_link.clone(), Offline)
        .await
        .unwrap();
    assert_eq!(confirm.outcome, PairingLinkOutcome::Confirm);
    assert_eq!(
        confirm.contact_id.as_deref(),
        Some(invite.contact_id.as_str())
    );
    let paired = ben
        .pairing_enter_link(confirm.link.unwrap(), Offline)
        .await
        .unwrap();
    assert_eq!(paired.outcome, PairingLinkOutcome::Paired);
    assert_eq!(paired.contact_id, Some(answer.contact_id.clone()));
    assert_eq!(
        anna.contact(invite.contact_id).await.unwrap().sas,
        ben.contact(answer.contact_id).await.unwrap().sas
    );
    assert_eq!(
        kind(anna.pairing_enter_link("hello".to_owned(), Offline).await),
        WalletErrorKind::InvalidPairingText
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_phones_pair_in_person_offline() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let anna_card = anna
        .pairing_show_card("Anna".to_owned(), ContactKind::Person, Offline, None)
        .await
        .unwrap();
    let ben_card = ben
        .pairing_show_card("Ben".to_owned(), ContactKind::Person, Offline, None)
        .await
        .unwrap();
    assert!(anna_card.link.starts_with("epiccash://contact/1/"));

    let anna_view = anna
        .pairing_scan_card(anna_card.contact_id.clone(), ben_card.link.clone(), Offline)
        .await
        .unwrap();
    let ben_view = ben
        .pairing_scan_card(ben_card.contact_id.clone(), anna_card.link.clone(), Offline)
        .await
        .unwrap();
    assert_eq!(anna_view.state, PairingState::Paired);
    assert_eq!(anna_view.claimed_name.as_deref(), Some("Ben"));
    assert_eq!(anna_view.sas, ben_view.sas);
    assert_eq!(
        kind(
            anna.pairing_scan_card(anna_card.contact_id, ben_card.link, Offline)
                .await
        ),
        WalletErrorKind::ContactNotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_words_find_the_invite_once() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let invite = anna
        .pairing_invite(
            "Anna".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            true,
            Online,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    assert_eq!(invite.words.len(), 5);
    assert!(invite.words.iter().all(|word| !word.emoji.is_empty()));
    let words: Vec<String> = invite.words.iter().map(|word| word.name.clone()).collect();

    assert_eq!(
        kind(
            ben.pairing_find_words(vec!["nonsense".to_owned(); 5], Online, meeting())
                .await
        ),
        WalletErrorKind::InvalidPairingWords
    );
    assert_eq!(
        kind(
            ben.pairing_find_words(words.clone(), Offline, meeting())
                .await
        ),
        WalletErrorKind::ContactsOffline
    );
    let found = ben
        .pairing_find_words(words.clone(), Online, meeting())
        .await
        .unwrap();
    assert_eq!(found.preview.claimed_name, "Anna");
    assert_eq!(
        kind(ben.pairing_find_words(words, Online, meeting()).await),
        WalletErrorKind::PairingWordsNotFound
    );
    ben.pairing_accept(
        found.link,
        "Ben".to_owned(),
        false,
        Online,
        PairingClass::Contact,
        None,
    )
    .await
    .unwrap();
    anna.contacts_collect(CollectTrigger::Push, Online, None)
        .await
        .unwrap();
    assert_eq!(
        anna.contact(invite.contact_id).await.unwrap().state,
        PairingState::Paired
    );
}

/// Words go to the built-in relays whatever relay the wallet uses (the owner's report utc3fhjj:
/// a wallet on another relay was refused words, read as "can't reach the relay"); the reply
/// still comes back on the inviter's own relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn words_are_offered_whatever_relay_the_wallet_uses() {
    let mut world = World::new();
    let config = world.config("relay.example");
    let anna = EpicWallet::create(
        &world.runtime,
        config,
        &AppSecretStore::in_memory(),
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let ben = world.wallet().await;
    let invite = anna
        .pairing_invite(
            "Anna".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            true,
            Online,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    let words: Vec<String> = invite.words.iter().map(|word| word.name.clone()).collect();
    assert_eq!(words.len(), 5);
    let found = ben
        .pairing_find_words(words, Online, meeting())
        .await
        .unwrap();
    assert_eq!(found.preview.home_relay, "relay.example:443");
    ben.pairing_accept(
        found.link,
        "Ben".to_owned(),
        false,
        Online,
        PairingClass::Contact,
        None,
    )
    .await
    .unwrap();
    anna.contacts_collect(CollectTrigger::Push, Online, None)
        .await
        .unwrap();
    assert_eq!(
        anna.contact(invite.contact_id).await.unwrap().state,
        PairingState::Paired
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_invite_is_listed_until_cancelled() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let invite = anna
        .pairing_invite(
            "Anna".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            false,
            EpicboxOff,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    // The link is a secret: Debug never shows it.
    let shown = format!("{invite:?}");
    assert!(
        !shown.contains("epiccash:") && !shown.contains(&invite.link),
        "{shown}"
    );
    let pending = anna.pairings_pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].inviter);
    assert_eq!(pending[0].contact_id, invite.contact_id);
    assert_eq!(pending[0].expires_at_ms, invite.expires_at_ms);

    anna.pairing_cancel(invite.contact_id.clone())
        .await
        .unwrap();
    assert!(anna.pairings_pending().await.unwrap().is_empty());
    assert_eq!(
        kind(anna.pairing_cancel(invite.contact_id.clone()).await),
        WalletErrorKind::PairingNotFound
    );
    // The cancelled invite is kept, hidden, to refuse a late reply; removing it ends that.
    assert!(anna.contact_remove(invite.contact_id).await.unwrap());
    assert_eq!(
        kind(anna.pairing_cancel("not an id".to_owned()).await),
        WalletErrorKind::InvalidArgument
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_mode_and_bad_input_are_refused_before_anything_happens() {
    let mut world = World::new();
    let anna = world.wallet().await;
    assert_eq!(
        kind(
            anna.contacts_collect(CollectTrigger::Open, Offline, None)
                .await
        ),
        WalletErrorKind::ContactsOffline
    );
    assert_eq!(
        kind(
            anna.contacts_collect(CollectTrigger::Open, EpicboxOff, None)
                .await
        ),
        WalletErrorKind::EpicboxOff
    );
    assert_eq!(
        kind(anna.contacts_outbox_deliver(Offline).await),
        WalletErrorKind::ContactsOffline
    );
    assert_eq!(
        kind(
            anna.pairing_preview("epiccash://pair/1/AAAA".to_owned())
                .await
        ),
        WalletErrorKind::InvalidPairingText
    );
    assert_eq!(
        kind(anna.pairing_preview("x".repeat(20_000)).await),
        WalletErrorKind::InvalidPairingText
    );
    assert_eq!(
        kind(
            anna.pairing_invite(
                String::new(),
                ContactKind::Person,
                InviteExpiry::OneDay,
                false,
                Online,
                meeting(),
                None,
                PairingClass::Contact,
                None
            )
            .await
        ),
        WalletErrorKind::InvalidContactName
    );
    assert_eq!(
        kind(anna.contact("00".repeat(16)).await),
        WalletErrorKind::ContactNotFound
    );
    assert_eq!(
        kind(anna.contact("zz".repeat(16)).await),
        WalletErrorKind::InvalidArgument
    );

    // Without an Epicbox relay nothing that needs one is offered.
    let config = world.config("");
    let bare = EpicWallet::create(
        &world.runtime,
        config,
        &AppSecretStore::in_memory(),
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    assert_eq!(
        kind(
            bare.contacts_collect(CollectTrigger::Open, Online, None)
                .await
        ),
        WalletErrorKind::Unsupported
    );
    assert!(bare.contacts().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contacts_settings_and_address_book_entry_are_kept() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let (anna_side, _) = pair(&anna, &ben).await;

    anna.contact_set_label(anna_side.clone(), "Benjamin".to_owned())
        .await
        .unwrap();
    anna.contact_set_seal(anna_side.clone(), false)
        .await
        .unwrap();
    assert_eq!(
        kind(
            anna.contact_set_allow_invoices(anna_side.clone(), true)
                .await
        ),
        WalletErrorKind::ContactNotVerified
    );
    anna.contact_attach(anna_side.clone(), Some("book-7".to_owned()), None)
        .await
        .unwrap();
    let view = anna.contact(anna_side.clone()).await.unwrap();
    assert_eq!(view.label, "Benjamin");
    assert_eq!(view.seal, SealState::Off);
    assert!(!view.allow_invoices);
    assert_eq!(view.app_contact.as_deref(), Some("book-7"));
    assert_eq!(
        anna.pairings_for_app_contact("book-7".to_owned())
            .await
            .unwrap(),
        vec![view]
    );
    assert!(
        anna.pairings_for_app_contact("book-8".to_owned())
            .await
            .unwrap()
            .is_empty()
    );

    anna.pairing_sas(anna_side.clone(), SasDecision::Match, Online)
        .await
        .unwrap();
    anna.contact_set_allow_invoices(anna_side.clone(), true)
        .await
        .unwrap();
    assert!(
        anna.contact(anna_side.clone())
            .await
            .unwrap()
            .allow_invoices
    );
    anna.contact_attach(anna_side.clone(), None, None)
        .await
        .unwrap();
    assert!(
        anna.pairings_for_app_contact("book-7".to_owned())
            .await
            .unwrap()
            .is_empty()
    );

    assert!(anna.contact_remove(anna_side.clone()).await.unwrap());
    assert!(anna.contacts().await.unwrap().is_empty());
    assert_eq!(
        kind(anna.contact_set_label(anna_side, "x".to_owned()).await),
        WalletErrorKind::ContactNotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_check_needs_two_pairings_and_keys_resolve_one_in_keys_changed() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let (anna_side, _) = pair(&anna, &ben).await;
    let unknown = "00".repeat(16);
    assert_eq!(
        kind(
            anna.contact_key_check(anna_side.clone(), unknown.clone(), Online)
                .await
        ),
        WalletErrorKind::ContactNotFound
    );
    assert_eq!(
        kind(
            anna.contact_keys_resolve(anna_side.clone(), KeysDecision::KeepOld)
                .await
        ),
        WalletErrorKind::ContactNotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_payment_is_opened_received_and_finalized_by_paste() {
    let mut world = World::new();
    let anna = world.funded().await;
    let ben = world.wallet().await;
    let (anna_side, ben_side) = pair(&anna, &ben).await;

    let slate = anna
        .create_send_slate(EPIC, 1, Some("lunch".to_owned()), None)
        .await
        .unwrap();
    let sealed = anna
        .contact_seal_slate(anna_side.clone(), slate.tx_id, None)
        .await
        .unwrap();
    assert!(!sealed.contains(&slate.slate_id));
    assert_eq!(
        anna.contact_of_transaction(slate.tx_id).await.unwrap(),
        Some(anna_side.clone())
    );

    // The same slate plain, for a contact that cannot open sealed text.
    let plain = anna.contact_plain_fallback(slate.tx_id).await.unwrap();
    assert!(plain.contains(&slate.slate_id));
    assert_eq!(
        anna.contact(anna_side.clone()).await.unwrap().seal,
        SealState::Degraded
    );

    let opened = ben.sealed_open(sealed.clone()).await.unwrap();
    assert_eq!(opened.contact_id, Some(ben_side));
    assert_eq!(opened.stage, SlateStage::S1);
    assert_eq!(opened.slate_id, slate.slate_id);
    assert_eq!(opened.amount, EPIC);
    assert_eq!(opened.purpose, Some(SlatePurpose::Payment));
    assert_eq!(
        opened.messages,
        vec![SlateMessage {
            role: SlateRole::Sender,
            text: "lunch".to_owned(),
        }]
    );
    assert_eq!(
        kind(ben.sealed_finalize(sealed.clone()).await),
        WalletErrorKind::InvalidSlate
    );
    assert_eq!(
        kind(world.wallet().await.sealed_open(sealed.clone()).await),
        WalletErrorKind::SealedForAnotherWallet
    );

    let answer = ben
        .sealed_receive(sealed, Some("thanks".to_owned()))
        .await
        .unwrap();
    assert!(answer.sealed);
    assert_eq!(answer.slate_id, slate.slate_id);
    assert_eq!(answer.amount, EPIC);
    let finalized = anna.sealed_finalize(answer.answer).await.unwrap();
    assert_eq!(finalized.tx_id, slate.tx_id);
    assert_eq!(world.chain.pushed_count(), 1);

    // Once finalized there is no slate left to send plain.
    assert_eq!(
        kind(anna.contact_plain_fallback(slate.tx_id).await),
        WalletErrorKind::NoSlateToSend
    );
    assert_eq!(
        kind(anna.sealed_open("not sealed".to_owned()).await),
        WalletErrorKind::InvalidPairingText
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slate_sent_through_the_mailbox_is_answered_through_the_outbox() {
    let mut world = World::new();
    let anna = world.funded().await;
    let ben = world.wallet().await;
    let (anna_side, ben_side) = pair(&anna, &ben).await;
    let slate = anna.create_send_slate(EPIC, 1, None, None).await.unwrap();

    anna.contact_post_slate(anna_side.clone(), slate.tx_id, None, Online)
        .await
        .unwrap();
    let outbox = anna.contact_outbox(anna_side.clone()).await.unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].slate_id, slate.slate_id);
    assert_eq!(outbox[0].stage, SlateStage::S1);
    assert_eq!(outbox[0].state, OutboxState::Delivered);

    // The cycle sends the answer itself and says so.
    let collected = ben
        .contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    assert_eq!(collected.delivered, 1);
    assert_eq!(
        ben.contact_outbox(ben_side).await.unwrap()[0].state,
        OutboxState::Delivered
    );
    anna.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    assert_eq!(world.chain.pushed_count(), 1);

    // The payment was finalized, so its slate is not sent again.
    assert_eq!(
        kind(anna.contact_outbox_resend(outbox[0].id, Online).await),
        WalletErrorKind::NoSlateToSend
    );
    assert_eq!(
        kind(anna.contact_outbox_resend(outbox[0].id + 100, Online).await),
        WalletErrorKind::NoSlateToSend
    );
    assert_eq!(
        anna.contacts_outbox_deliver(Online).await.unwrap().failed,
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contacts_invoice_waits_and_is_declined_or_paid() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.funded().await;
    let (anna_side, ben_side) = verified_pair(&anna, &ben).await;
    ben.contact_set_allow_invoices(ben_side.clone(), true)
        .await
        .unwrap();

    let issue = |reference: &str| {
        anna.contact_issue_invoice(
            anna_side.clone(),
            2 * EPIC,
            Some("deposit".to_owned()),
            SlatePurpose::DepositRequest,
            Some(reference.to_owned()),
            None,
            Online,
        )
    };
    let first = issue("order-1").await.unwrap();
    assert_eq!(first.amount, 2 * EPIC);
    ben.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    let invoices = ben.contact_invoices().await.unwrap();
    assert_eq!(invoices.len(), 1);
    assert_eq!(invoices[0].slate_id, first.slate_id);
    assert_eq!(invoices[0].contact_id, ben_side);
    assert_eq!(invoices[0].purpose, Some(SlatePurpose::DepositRequest));
    assert_eq!(invoices[0].reference.as_deref(), Some("order-1"));
    assert_eq!(invoices[0].message.as_deref(), Some("deposit"));

    ben.contact_decline_invoice(first.slate_id.clone())
        .await
        .unwrap();
    assert!(ben.contact_invoices().await.unwrap().is_empty());
    assert_eq!(
        kind(ben.contact_decline_invoice(first.slate_id).await),
        WalletErrorKind::InvoiceNotFound
    );

    let second = issue("order-2").await.unwrap();
    ben.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    assert_eq!(
        kind(
            ben.contact_pay_invoice(second.slate_id.clone(), EPIC, 1, None, None, Online)
                .await
        ),
        WalletErrorKind::AmountMismatch
    );
    let paid = ben
        .contact_pay_invoice(second.slate_id.clone(), 2 * EPIC, 1, None, None, Online)
        .await
        .unwrap();
    assert_eq!(paid.slate_id, second.slate_id);
    assert_eq!(paid.amount, 2 * EPIC);
    anna.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    assert_eq!(world.chain.pushed_count(), 1);
    assert_eq!(
        kind(
            ben.contact_pay_invoice(second.slate_id, 2 * EPIC, 1, None, None, Online)
                .await
        ),
        WalletErrorKind::InvoiceNotFound
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_backup_brings_the_pairings_back_on_another_install() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let (anna_side, _) = pair(&anna, &ben).await;
    let document = anna.contacts_export().await.unwrap();
    assert!(!document.contains("password"));
    // Nothing learned about the contact's wallet goes in; its proven address does.
    for field in ["peer_features", "peer_heard_at", "peer_verified_at"] {
        assert!(!document.contains(field), "{document}");
    }
    let address = anna
        .contact(anna_side.clone())
        .await
        .unwrap()
        .payments_address;
    assert!(address.is_some());

    let phrase = anna.mnemonic("password".to_owned()).await.unwrap();
    let restored = world.wallet_with(Some(phrase)).await;
    let summary = restored.contacts_import(document.clone()).await.unwrap();
    assert_eq!(
        (
            summary.imported,
            summary.skipped_existing,
            summary.skipped_conflict
        ),
        (1, 0, 0)
    );
    let view = restored.contact(anna_side.clone()).await.unwrap();
    assert!(view.imported_from_backup);
    assert_eq!(view.sas, anna.contact(anna_side).await.unwrap().sas);
    assert_eq!(view.payments_address, address);
    assert_eq!(view.peer_features, 0);
    assert_eq!(
        restored
            .contacts_import(document)
            .await
            .unwrap()
            .skipped_existing,
        1
    );
    assert!(restored.contacts_import("{}".to_owned()).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_reply_is_named_in_the_collect_report() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let carl = world.wallet().await;
    let invite = anna
        .pairing_invite(
            "Anna".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            false,
            Online,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    ben.pairing_accept(
        invite.link.clone(),
        "Ben".to_owned(),
        false,
        Online,
        PairingClass::Contact,
        None,
    )
    .await
    .unwrap();
    let late = carl
        .pairing_accept(
            invite.link,
            "Carl".to_owned(),
            false,
            Online,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        anna.contacts_collect(CollectTrigger::Open, Online, None)
            .await
            .unwrap()
            .paired,
        1
    );

    let collected = carl
        .contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    assert_eq!(
        collected.failed,
        vec![FailedPairing {
            contact_id: late.contact_id,
            reason: PairingFailureReason::Refused,
        }]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn labels_follow_the_name_rule_and_marker_texts_are_bounded() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let (anna_side, _) = pair(&anna, &ben).await;
    assert_eq!(
        kind(
            anna.contact_set_label(anna_side.clone(), "Ben\u{202E}gnp.exe".to_owned())
                .await
        ),
        WalletErrorKind::InvalidContactName
    );
    anna.contact_set_label(anna_side, "Ben".to_owned())
        .await
        .unwrap();
    let huge = "x".repeat(5 * 1024 * 1024);
    assert_eq!(
        kind(anna.sealed_answer_to_marker(huge, "{}".to_owned()).await),
        WalletErrorKind::InvalidPairingText
    );
}

/// Drains what the wallet raised so far.
pub(super) fn raised(
    events: &mut tokio::sync::broadcast::Receiver<lepic_wallet::Event>,
) -> Vec<lepic_wallet::Event> {
    let mut raised = Vec::new();
    while let Ok(event) = events.try_recv() {
        raised.push(event);
    }
    raised
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contact_with_only_a_pairing_is_paid_through_its_mailbox_with_sealing_off() {
    let mut world = World::new();
    let anna = world.funded().await;
    let ben = world.wallet().await;
    let (anna_side, ben_side) = pair(&anna, &ben).await;
    // "Seal payments" governs files and pastes; the mailbox carries only sealed slates.
    anna.contact_set_seal(anna_side.clone(), false)
        .await
        .unwrap();
    assert_eq!(
        kind(
            anna.contact_send("00".repeat(16), EPIC, 1, None, None, None, Online)
                .await
        ),
        WalletErrorKind::ContactNotFound
    );
    let mut anna_events = anna.session().subscribe();

    let sent = anna
        .contact_send(
            anna_side.clone(),
            EPIC,
            1,
            Some("rent".to_owned()),
            None,
            None,
            Online,
        )
        .await
        .unwrap();
    assert_eq!(sent.amount, EPIC);
    assert_eq!(
        kind(
            anna.contact_seal_slate(anna_side.clone(), sent.tx_id, None)
                .await
        ),
        WalletErrorKind::SealingOff
    );
    let outbox = anna.contact_outbox(anna_side.clone()).await.unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].slate_id, sent.slate_id);
    assert_eq!(outbox[0].state, OutboxState::Delivered);

    ben.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    assert_eq!(ben.contact_outbox(ben_side).await.unwrap().len(), 1);
    anna.contacts_collect(CollectTrigger::Foreground, Online, None)
        .await
        .unwrap();
    assert_eq!(world.chain.pushed_count(), 1);
    let finalized: Vec<_> = raised(&mut anna_events)
        .into_iter()
        .filter_map(|event| match event {
            lepic_wallet::Event::ContactPaymentFinalized(slate) => Some(slate),
            _ => None,
        })
        .collect();
    assert_eq!(finalized.len(), 1);
    assert_eq!(finalized[0].contact_id.to_string(), anna_side);
    assert_eq!(finalized[0].tx_id.0, sent.tx_id);
    assert_eq!(finalized[0].slate_id.to_string(), sent.slate_id);
    assert_eq!(finalized[0].amount.value(), EPIC);

    // The receiver hears that it was posted, as over Epicbox, through the same mailbox.
    let mut ben_events = ben.session().subscribe();
    ben.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    let posted = raised(&mut ben_events)
        .into_iter()
        .filter(|event| matches!(event, lepic_wallet::Event::PaymentPosted(_)))
        .count();
    assert_eq!(posted, 1);
    let received = ben
        .transactions()
        .await
        .unwrap()
        .into_iter()
        .find(|tx| tx.slate_id.as_deref() == Some(sent.slate_id.as_str()))
        .unwrap();
    assert!(received.sender_reported_posted_at_ms.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mailbox_send_the_contact_never_answers_is_cancelled_and_its_late_answer_refused() {
    let mut world = World::new();
    let anna = world.funded().await;
    let ben = world.wallet().await;
    let (anna_side, _) = pair(&anna, &ben).await;
    let sent = anna
        .contact_send(anna_side, 9 * EPIC, 1, None, None, None, Online)
        .await
        .unwrap();
    anna.cancel_transaction(sent.tx_id).await.unwrap();
    // The inputs are free again.
    anna.create_send_slate(9 * EPIC, 1, None, None)
        .await
        .unwrap();

    ben.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    anna.contacts_collect(CollectTrigger::Open, Online, None)
        .await
        .unwrap();
    assert_eq!(world.chain.pushed_count(), 0);
    assert_eq!(
        anna.transaction(sent.tx_id).await.unwrap().status,
        crate::api::types::TxStatus::Cancelled
    );
}

/// A send given up after its slate could not be handed over is cancelled and frees its inputs;
/// when the cancel fails too, the error names the transaction and the failed cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_given_up_is_cancelled_and_a_failed_cancel_is_never_silent() {
    let mut world = World::new();
    let anna = world.funded().await;
    let session = anna.session();
    let slate = anna
        .create_send_slate(9 * EPIC, 1, None, None)
        .await
        .unwrap();
    let first = lepic_store::TxId(slate.tx_id);
    let stopped = || WalletError::new(WalletErrorKind::TransportFailed, "not written");

    let error = session.give_up_send(first, stopped()).await;
    assert_eq!(error.kind, WalletErrorKind::TransportFailed);
    assert_eq!(error.tx_id, None);
    assert_eq!(
        anna.transaction(slate.tx_id).await.unwrap().status,
        crate::api::types::TxStatus::Cancelled
    );
    // The inputs are free again.
    let again = anna
        .create_send_slate(9 * EPIC, 1, None, None)
        .await
        .unwrap();

    // A transaction the wallet cannot cancel: the error says so and names it.
    let unknown = lepic_store::TxId(9_999);
    let error = session.give_up_send(unknown, stopped()).await;
    assert_eq!(error.kind, WalletErrorKind::TransportFailed);
    assert_eq!(error.tx_id, Some(9_999));
    assert!(error.message.contains("could not be cancelled"), "{error}");
    assert!(error.message.contains("not written"), "{error}");
    // The other send is untouched.
    assert_ne!(again.tx_id, slate.tx_id);
}

fn transport_failure() -> lepic_transport::error::TransportError {
    lepic_transport::error::TransportError::UnknownDestination {
        transport: lepic_transport::transport::TransportId::new("test"),
    }
}

/// A stored payment that was left behind is named in the error that reports it.
#[test]
fn an_error_names_the_stored_send_it_leaves_behind() {
    let tx_id = lepic_store::TxId(12);
    let undelivered = lepic_wallet::send::SendError::Undelivered {
        tx_id,
        slate_id: lepic_wallet::event::SlateId::from_bytes([7; 16]),
        source: transport_failure(),
    };
    let error = WalletError::from(undelivered);
    assert_eq!(error.kind, WalletErrorKind::TransportFailed);
    assert_eq!(error.tx_id, Some(12));

    let not_cancelled = lepic_wallet_contacts::ContactError::NotCancelled {
        tx_id,
        cause: Box::new(lepic_wallet_contacts::ContactError::Post(
            transport_failure(),
        )),
        cancel: lepic_wallet::error::WalletError::UnknownTransaction(tx_id),
    };
    let error = WalletError::from(not_cancelled);
    assert_eq!(error.kind, WalletErrorKind::TransportFailed);
    assert_eq!(error.tx_id, Some(12));
    assert!(error.message.contains("could not be cancelled"), "{error}");

    assert_eq!(WalletError::new(WalletErrorKind::Other, "x").tx_id, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_v3_calls_keep_their_contract() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;

    let standing = anna
        .pairing_standing_invite("Anna".to_owned())
        .await
        .unwrap();
    let again = anna
        .pairing_standing_invite("Anna".to_owned())
        .await
        .unwrap();
    assert_eq!(standing.link, again.link);
    assert!(anna.pairings_pending().await.unwrap().is_empty());
    assert_eq!(
        kind(anna.pairing_standing_invite(String::new()).await),
        WalletErrorKind::InvalidContactName
    );

    let ben_address = ben.epicbox_address().await.unwrap();
    assert_eq!(
        kind(
            anna.pairing_request_send(ben_address, "Anna".to_owned(), Online)
                .await
        ),
        WalletErrorKind::PeerNotProven
    );
    assert_eq!(
        kind(
            anna.pairing_request_send("not an address".to_owned(), "Anna".to_owned(), Online)
                .await
        ),
        WalletErrorKind::InvalidArgument
    );

    assert!(ben.pairing_requests().await.unwrap().is_empty());
    assert_eq!(
        kind(ben.pairing_request_dismiss("00".to_owned()).await),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(
            ben.pairing_request_dismiss("0011223344556677".to_owned())
                .await
        ),
        WalletErrorKind::PairingNotFound
    );
    assert_eq!(
        anna.contacts_set_own_name("Anna B".to_owned())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preview_knows_this_wallets_own_invites_after_a_reopen() {
    let mut world = World::new();
    let config = world.config(RELAY);
    let store = AppSecretStore::in_memory();
    let anna = EpicWallet::create(
        &world.runtime,
        config.clone(),
        &store,
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let ben = world.wallet().await;

    let standing = anna
        .pairing_standing_invite("Anna".to_owned())
        .await
        .unwrap();
    let cancelled = anna
        .pairing_invite(
            "Anna".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            false,
            Online,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    anna.pairing_cancel(cancelled.contact_id).await.unwrap();
    let theirs = ben
        .pairing_invite(
            "Ben".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            false,
            Online,
            meeting(),
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    anna.pairing_accept(
        theirs.link.clone(),
        "Anna".to_owned(),
        true,
        Online,
        PairingClass::Contact,
        None,
    )
    .await
    .unwrap();
    assert!(
        anna.pairings_pending()
            .await
            .unwrap()
            .iter()
            .all(|p| !p.inviter)
    );

    // A new session over the same store, as after a restart.
    drop(anna);
    let anna = EpicWallet::open(&world.runtime, config, &store, "password".to_owned())
        .await
        .unwrap();
    for link in [&standing.link, &cancelled.link] {
        assert!(
            anna.pairing_preview(link.clone()).await.unwrap().own,
            "{link}"
        );
    }
    // An invite this wallet answered is the other wallet's.
    assert!(!anna.pairing_preview(theirs.link).await.unwrap().own);
    assert!(!ben.pairing_preview(standing.link).await.unwrap().own);
}
