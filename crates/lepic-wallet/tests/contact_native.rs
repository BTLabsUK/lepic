// SPDX-License-Identifier: Apache-2.0
//! Native slates between paired contacts (RFC 0003, ADR 0052 step 6): `lepic.v1` in a type `0A`
//! envelope through the contacts' mailboxes, sent when the host turns it on and the contact
//! claims to take them, and always read.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "pairing/helpers.rs"]
mod helpers;
mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use helpers::{HOUR, accept, invite_request, relays};
use lepic_contact::{
    ContactCard, ContactKind, EncSecretKey, KeyClass, MessageType, Network as ContactNetwork,
    Purpose, SealedEnvelope, SigningKey, TxContent, TxKey, armor_tx, dearmor, seal_tx,
};
use lepic_epicbox::{EpicboxAddress, Identity, MailboxClient, Network as RelayNetwork};
use lepic_node::Propagation;
use lepic_primitives::amount::Amount;
use lepic_store::{ContactId, SlateStage, TxId, TxState, WalletStore};
use lepic_transport::marker::features::NATIVE_SLATES;
use lepic_wallet::invoice::{InvoiceRequest, IssuedInvoice};
use lepic_wallet::receive::ReceiveRequest;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{SlateFormat, WalletPolicy};
use lepic_wallet_contacts::{
    InvoiceDetails, QuarantineReason, SasDecision, SealedAnswer, WalletContacts,
};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, FUNDING, Party, World, pay_request};

/// The armor of a `lepic.v1` slate envelope; every other envelope keeps `BEGINEPICSEALED.`.
const TX_ARMOR: &str = "BEGINEPICTX. ";
const SEALED_ARMOR: &str = "BEGINEPICSEALED. ";

/// What an outbox entry holds.
#[derive(Debug, PartialEq, Eq)]
enum Format {
    /// A type `0A` envelope, armored as a transaction.
    Native,
    /// A V3 slate envelope with these bytes.
    V3(Vec<u8>),
}

/// The payer and the issuer, both with native slates as `native` says, paired; the payer
/// verifies the SAS and allows the issuer's invoices. Returns the issuer's and the payer's
/// contact ids.
fn paired(native: (bool, bool), issuer_policy: WalletPolicy) -> (World, ContactId, ContactId) {
    let world = World::with_native(native.0, native.1, issuer_policy);
    let link = world
        .block_on(world.issuer.wallet.contact_book().pairing_invite(
            &relays(&world.issuer),
            lepic_wallet_contacts::InviteRequest {
                kind: ContactKind::Exchange,
                ..invite_request("Shop")
            },
        ))
        .unwrap()
        .link;
    let ben_side = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap()
        .contact_id;
    world.collect(&world.issuer);
    world.collect(&world.payer);
    world.collect(&world.issuer);
    let shop_side = world.only_contact(&world.issuer);
    world
        .block_on(world.payer.wallet.contact_book().pairing_sas(
            &relays(&world.payer),
            ben_side,
            SasDecision::Match,
        ))
        .unwrap();
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .contact_set_allow_invoices(ben_side, true),
        )
        .unwrap();
    world.collect(&world.issuer);
    (world, shop_side, ben_side)
}

/// The party's keys for its contact `contact`, as the wallet derives them.
fn keys_for(party: &Party, contact: ContactId) -> lepic_wallet_contacts::ContactKeys {
    let record = party.read(|repos| repos.contact(contact)).unwrap();
    lepic_wallet_contacts::contact_root(
        &party.keychain(),
        &lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap(),
        lepic_primitives::params::Network::Floonet,
    )
    .unwrap()
    .contact_keys(record.slot, record.box_salt)
    .unwrap()
}

/// The armored payload `from` queued for its contact `contact` at `stage`.
fn payload(from: &Party, contact: ContactId, stage: SlateStage) -> String {
    from.read(|repos| repos.contact_outbox(contact))
        .into_iter()
        .rev()
        .find(|row| row.entry.stage == stage)
        .unwrap_or_else(|| panic!("no {stage:?} in the outbox"))
        .entry
        .payload
}

/// What `from` sent its contact `contact` at `stage`, opened with the keys of `to` for its
/// contact `to_contact`.
fn format_of(
    from: &Party,
    contact: ContactId,
    stage: SlateStage,
    to: &Party,
    to_contact: ContactId,
) -> Format {
    let text = payload(from, contact, stage);
    let bytes = dearmor(&text).unwrap();
    let sealed = SealedEnvelope::decode(&bytes, ContactNetwork::Floonet).unwrap();
    let key = EncSecretKey::from_bytes(*keys_for(to, to_contact).expose_enc_secret());
    match sealed.open(&key) {
        Ok(opened) => {
            assert!(text.starts_with(SEALED_ARMOR));
            assert_eq!(opened.content.kind, MessageType::Slate);
            Format::V3(opened.content.body)
        }
        Err(_) => {
            assert!(text.starts_with(TX_ARMOR));
            sealed.open_tx(&key, KeyClass::Seal).unwrap();
            Format::Native
        }
    }
}

/// The stored V3 JSON of the slate `slate_id` at `stage`, on `party`.
fn stored(party: &Party, slate_id: uuid::Uuid, stage: SlateStage) -> Vec<u8> {
    party
        .read(|repos| repos.slate(slate_id, stage))
        .unwrap()
        .bytes
}

/// The slate of V3 JSON `bytes` without the `lepic` field a sender adds for the reply.
fn slate_json(bytes: &[u8]) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    value.as_object_mut().unwrap().remove("lepic");
    value
}

/// Whether `party` sends new slates to `contact` as native slates, as its contact view says.
fn native_slates(world: &World, party: &Party, contact: ContactId) -> bool {
    world
        .block_on(party.wallet.contact_book().contact(contact))
        .unwrap()
        .native_slates
}

fn slate_id_of(party: &Party, tx_id: TxId) -> uuid::Uuid {
    party
        .read(|repos| repos.transaction(tx_id))
        .unwrap()
        .slate_id
        .unwrap()
}

fn tx_state(party: &Party, tx_id: TxId) -> TxState {
    party.read(|repos| repos.transaction(tx_id)).unwrap().state
}

/// The payer posts an S1 for `AMOUNT` to its contact `contact`; returns the transaction.
fn send_s1(world: &World, contact: ContactId) -> TxId {
    let sent = world
        .block_on(world.payer.wallet.send(
            &crate::support::file(),
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                to: lepic_transport::transport::Location::File(
                    tempfile::tempdir().unwrap().keep().join("s1.tx"),
                ),
            },
        ))
        .unwrap();
    world
        .block_on(world.payer.wallet.contact_book().contact_post_slate(
            &relays(&world.payer),
            contact,
            sent.tx_id,
            Some(Purpose::Withdrawal),
        ))
        .unwrap();
    sent.tx_id
}

fn issue(world: &World, shop_side: ContactId) -> IssuedInvoice {
    world
        .block_on(world.issuer.wallet.contact_book().contact_issue_invoice(
            &relays(&world.issuer),
            shop_side,
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: None,
                ttl_blocks: None,
            },
            InvoiceDetails {
                purpose: Purpose::DepositRequest,
                reference: Some("deposit".to_owned()),
                expires: Some(1_800_000_000),
            },
        ))
        .unwrap()
}

fn pay(world: &World, issued: &IssuedInvoice) -> TxId {
    world
        .block_on(world.payer.wallet.contact_book().contact_pay_invoice(
            &relays(&world.payer),
            issued.slate_id,
            pay_request(),
        ))
        .unwrap()
        .0
        .tx_id
}

/// A withdrawal from the payer: the formats of its S1 and S2, the payment posted.
fn send_flow(world: &World, shop_side: ContactId, ben_side: ContactId) -> (Format, Format) {
    let pushed = world.node.pushed_transactions().len();
    let tx_id = send_s1(world, ben_side);
    let s1 = format_of(
        &world.payer,
        ben_side,
        SlateStage::Standard1,
        &world.issuer,
        shop_side,
    );
    world.collect(&world.issuer);
    let s2 = format_of(
        &world.issuer,
        shop_side,
        SlateStage::Standard2,
        &world.payer,
        ben_side,
    );
    world.collect(&world.payer);
    assert_eq!(world.node.pushed_transactions().len(), pushed + 1);
    assert_eq!(tx_state(&world.payer, tx_id), TxState::Posted);
    let slate_id = slate_id_of(&world.payer, tx_id);
    let as_stored = |format: Format, party: &Party, stage| match format {
        Format::V3(bytes) => {
            assert_eq!(
                slate_json(&bytes),
                slate_json(&stored(party, slate_id, stage))
            );
            Format::V3(Vec::new())
        }
        Format::Native => Format::Native,
    };
    (
        as_stored(s1, &world.payer, SlateStage::Standard1),
        as_stored(s2, &world.issuer, SlateStage::Standard2),
    )
}

/// An invoice from the issuer, parked and paid by the payer: the formats of its I1 and I2, the
/// payment posted.
fn invoice_flow(world: &World, shop_side: ContactId, ben_side: ContactId) -> (Format, Format) {
    let pushed = world.node.pushed_transactions().len();
    let issued = issue(world, shop_side);
    let i1 = format_of(
        &world.issuer,
        shop_side,
        SlateStage::Invoice1,
        &world.payer,
        ben_side,
    );
    world.collect(&world.payer);
    // Parked until the user pays it, some time later.
    world.payer.clock.advance(HOUR);
    world.collect(&world.payer);
    pay(world, &issued);
    let i2 = format_of(
        &world.payer,
        ben_side,
        SlateStage::Invoice2,
        &world.issuer,
        shop_side,
    );
    world.collect(&world.issuer);
    assert_eq!(world.node.pushed_transactions().len(), pushed + 1);
    assert_eq!(tx_state(&world.issuer, issued.tx_id), TxState::Posted);
    let slate_id = uuid::Uuid::from_bytes(*issued.slate_id.as_bytes());
    let as_stored = |format: Format, party: &Party, stage| match format {
        Format::V3(bytes) => {
            assert_eq!(
                slate_json(&bytes),
                slate_json(&stored(party, slate_id, stage))
            );
            Format::V3(Vec::new())
        }
        Format::Native => Format::Native,
    };
    (
        as_stored(i1, &world.issuer, SlateStage::Invoice1),
        as_stored(i2, &world.payer, SlateStage::Invoice2),
    )
}

const V3: Format = Format::V3(Vec::new());

#[test]
fn both_wallets_on_exchange_native_slates_in_both_flows() {
    let (world, shop_side, ben_side) = paired((true, true), WalletPolicy::default());
    world.payer.fund(1, FUNDING);
    assert!(native_slates(&world, &world.issuer, shop_side));
    assert!(native_slates(&world, &world.payer, ben_side));

    assert_eq!(
        send_flow(&world, shop_side, ben_side),
        (Format::Native, Format::Native)
    );
    assert_eq!(
        invoice_flow(&world, shop_side, ben_side),
        (Format::Native, Format::Native)
    );
    // Engine storage stays V3 JSON.
    let stages = world.payer.read(|repos| {
        let rows = repos.transactions(ACCOUNT)?;
        let mut codecs = Vec::new();
        for row in rows {
            for slate in repos.slates(row.entry.slate_id.unwrap())? {
                codecs.push(slate.codec);
            }
        }
        Ok(codecs)
    });
    assert!(!stages.is_empty());
    assert!(stages.iter().all(|codec| codec == "legacy-v3"));
}

/// A send to a contact reports the format it was sealed in, not the slate file's.
#[test]
fn a_contact_send_reports_the_format_it_sealed() {
    for (native, expected) in [
        ((true, true), SlateFormat::Native),
        ((false, false), SlateFormat::Legacy),
    ] {
        let (world, _, ben_side) = paired(native, WalletPolicy::default());
        world.payer.fund(1, FUNDING);
        let sent = world
            .block_on(world.payer.wallet.contact_book().contact_send(
                &relays(&world.payer),
                ben_side,
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                tempfile::tempdir().unwrap().keep().join("s1.tx"),
                Some(Purpose::Payment),
            ))
            .unwrap();
        assert_eq!(sent.format, expected);
    }
}

/// Off by default: V3 envelopes as before, and no contact claims native slates, because a wallet
/// claims them in its pairing only while its own switch is on.
#[test]
fn both_wallets_off_send_v3_slates_as_stored() {
    let (world, shop_side, ben_side) = paired((false, false), WalletPolicy::default());
    world.payer.fund(1, FUNDING);
    for (party, contact) in [(&world.payer, ben_side), (&world.issuer, shop_side)] {
        let record = party.read(|repos| repos.contact(contact)).unwrap();
        assert_eq!(record.facts.peer_features & NATIVE_SLATES, 0);
        assert!(!native_slates(&world, party, contact));
    }

    assert_eq!(send_flow(&world, shop_side, ben_side), (V3, V3));
    assert_eq!(invoice_flow(&world, shop_side, ben_side), (V3, V3));
}

/// A contact file holds a type `0A` envelope both ways when both wallets send native slates,
/// and a type `01` one when they do not.
#[test]
fn contact_files_follow_the_native_slate_setting() {
    for (native, armor) in [(true, TX_ARMOR), (false, SEALED_ARMOR)] {
        let (world, _, ben_side) = paired((native, native), WalletPolicy::default());
        world.payer.fund(1, FUNDING);
        let sent = world
            .block_on(world.payer.wallet.send(
                &crate::support::file(),
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Export {
                    to: lepic_transport::transport::Location::File(
                        tempfile::tempdir().unwrap().keep().join("s1.tx"),
                    ),
                },
            ))
            .unwrap();
        let s1 = world
            .block_on(world.payer.wallet.contact_book().contact_seal_slate(
                ben_side,
                sent.tx_id,
                Some(Purpose::Withdrawal),
            ))
            .unwrap();
        assert!(s1.starts_with(armor), "{native}: {s1}");
        assert_eq!(lepic_wallet_contacts::is_epictx(&s1), native);

        let received = world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .sealed_receive(&s1, ReceiveRequest::default()),
            )
            .unwrap();
        let SealedAnswer::Sealed(s2) = received.answer else {
            panic!("{native}: a plain answer");
        };
        assert!(s2.starts_with(armor), "{native}: {s2}");
        assert_eq!(lepic_wallet_contacts::is_epictx(&s2), native);

        let finalized = world
            .block_on(
                world
                    .payer
                    .wallet
                    .contact_book()
                    .sealed_finalize(&s2, Propagation::Stem),
            )
            .unwrap();
        assert!(finalized.pushed);
    }
}

/// Records that the contact `contact` of `party` claims native slates, as one paired while its
/// wallet had them on does.
fn claim_native(party: &Party, contact: ContactId) {
    let mut record = party.read(|repos| repos.contact(contact)).unwrap();
    record.facts.peer_features |= NATIVE_SLATES;
    party
        .store()
        .write(|repos| repos.put_contact(&record))
        .unwrap();
}

/// A reply takes the format of its request, whatever its own wallet sends.
#[test]
fn a_reply_takes_the_format_of_its_request() {
    // The payer sends native slates, the issuer does not. The issuer, paired with its switch
    // off, claims none; its contact is recorded as claiming them, as after a later update.
    let (world, shop_side, ben_side) = paired((false, true), WalletPolicy::default());
    claim_native(&world.payer, ben_side);
    world.payer.fund(1, FUNDING);
    assert_eq!(
        send_flow(&world, shop_side, ben_side),
        (Format::Native, Format::Native)
    );
    assert_eq!(invoice_flow(&world, shop_side, ben_side), (V3, V3));

    // The issuer sends native slates, the payer does not; its invoice waits parked.
    let (world, shop_side, ben_side) = paired((true, false), WalletPolicy::default());
    claim_native(&world.issuer, shop_side);
    world.payer.fund(1, FUNDING);
    assert_eq!(send_flow(&world, shop_side, ben_side), (V3, V3));
    assert_eq!(
        invoice_flow(&world, shop_side, ben_side),
        (Format::Native, Format::Native)
    );
}

#[test]
fn a_contact_that_does_not_claim_native_slates_gets_v3() {
    let (world, shop_side, ben_side) = paired((true, true), WalletPolicy::default());
    for (party, contact) in [(&world.payer, ben_side), (&world.issuer, shop_side)] {
        let mut record = party.read(|repos| repos.contact(contact)).unwrap();
        assert_ne!(record.facts.peer_features & NATIVE_SLATES, 0);
        record.facts.peer_features &= !NATIVE_SLATES;
        party
            .store()
            .write(|repos| repos.put_contact(&record))
            .unwrap();
    }
    world.payer.fund(1, FUNDING);
    assert!(!native_slates(&world, &world.issuer, shop_side));

    assert_eq!(send_flow(&world, shop_side, ben_side), (V3, V3));
    assert_eq!(invoice_flow(&world, shop_side, ben_side), (V3, V3));
}

/// The mailbox `party` posts to for its contact `contact`.
fn peer_mailbox(party: &Party, contact: ContactId) -> EpicboxAddress {
    let mailbox = party.read(|repos| repos.contact_mailbox(contact)).unwrap();
    EpicboxAddress::parse(&mailbox.peer_mailbox, RelayNetwork::Floonet).unwrap()
}

/// Seals `body` as a native slate from `from` to its contact `contact`, signed, with the rest
/// of `content`, and posts it from the party's mailbox for that contact to the contact's.
fn post_native(world: &World, from: &Party, contact: ContactId, content: &TxContent) {
    let keys = keys_for(from, contact);
    let signer = SigningKey::from_bytes(&keys.expose_signing_key().to_bytes());
    let record = from.read(|repos| repos.contact(contact)).unwrap();
    let peer = ContactCard::decode(&record.peer.unwrap().bytes, ContactNetwork::Floonet).unwrap();
    let envelope = seal_tx(
        ContactNetwork::Floonet,
        peer.enc_key(),
        TxKey::Seal(peer.hint_rule()),
        content,
        Some(&signer),
        &mut rand::rngs::StdRng::seed_from_u64(23),
    )
    .unwrap();
    let mailbox = from.read(|repos| repos.contact_mailbox(contact)).unwrap();
    let identity = Identity::new(
        keys.expose_box_secret().clone(),
        EpicboxAddress::parse(&mailbox.our_mailbox, RelayNetwork::Floonet).unwrap(),
    )
    .unwrap();
    world
        .block_on(
            MailboxClient::new(world::settings(), world.relay.connector()).post(
                &identity,
                &peer_mailbox(from, contact),
                &armor_tx(&envelope),
            ),
        )
        .unwrap();
}

/// The content of the native slate `from` holds for its contact `contact` at `stage`, opened
/// with the keys of `to` for its contact `to_contact`.
fn native_content(
    from: &Party,
    contact: ContactId,
    stage: SlateStage,
    to: &Party,
    to_contact: ContactId,
) -> TxContent {
    let bytes = dearmor(&payload(from, contact, stage)).unwrap();
    let sealed = SealedEnvelope::decode(&bytes, ContactNetwork::Floonet).unwrap();
    let key = EncSecretKey::from_bytes(*keys_for(to, to_contact).expose_enc_secret());
    sealed.open_tx(&key, KeyClass::Seal).unwrap().content
}

/// Offsets in the fixed header of `lepic.v1` (RFC 0003 5.10).
const NETWORK_AT: usize = 5;
const HEADER_VERSION_AT: usize = 9;
const HEIGHT_AT: usize = 43;

fn keeping() -> WalletPolicy {
    WalletPolicy {
        quarantine_max_bytes: Some(1024 * 1024),
        ..WalletPolicy::default()
    }
}

/// The payer's native S1, held back from the issuer, changed by `change` and posted; the
/// issuer receives nothing and keeps the message as an undecodable slate.
fn changed_s1_is_kept(change: impl FnOnce(&mut Vec<u8>)) {
    let (world, shop_side, ben_side) = paired((true, true), keeping());
    let issuer_mailbox = peer_mailbox(&world.payer, ben_side);
    world.relay.set_post_refused(&issuer_mailbox);
    send_s1(&world, ben_side);
    let mut content = native_content(
        &world.payer,
        ben_side,
        SlateStage::Standard1,
        &world.issuer,
        shop_side,
    );
    change(&mut content.body);
    world.relay.set_post_accepted(&issuer_mailbox);
    post_native(&world, &world.payer, ben_side, &content);

    let report = world.collect(&world.issuer);

    assert_eq!(report.quarantined, 1);
    let kept = world
        .block_on(world.issuer.wallet.contact_book().contact_quarantine())
        .unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].reason, QuarantineReason::UndecodableSlate);
    assert!(
        world
            .issuer
            .read(|repos| repos.transactions(ACCOUNT))
            .is_empty()
    );
}

#[test]
fn a_native_slate_for_another_network_is_refused() {
    changed_s1_is_kept(|body| body[NETWORK_AT] = 0);
}

#[test]
fn a_native_slate_with_another_header_version_is_refused() {
    changed_s1_is_kept(|body| body[HEADER_VERSION_AT + 1] ^= 1);
}

#[test]
fn a_malformed_native_slate_is_refused() {
    changed_s1_is_kept(|body| body.truncate(body.len() - 1));
    changed_s1_is_kept(|body| body.push(0));
}

/// The issuer's native S2, held back from the payer, changed by `change` and posted; the payer
/// does not finalize it.
fn changed_s2_is_refused(change: impl FnOnce(&mut Vec<u8>)) {
    let (world, shop_side, ben_side) = paired((true, true), WalletPolicy::default());
    let tx_id = send_s1(&world, ben_side);
    let payer_mailbox = peer_mailbox(&world.issuer, shop_side);
    world.relay.set_post_refused(&payer_mailbox);
    world.collect(&world.issuer);
    let mut content = native_content(
        &world.issuer,
        shop_side,
        SlateStage::Standard2,
        &world.payer,
        ben_side,
    );
    change(&mut content.body);
    world.relay.set_post_accepted(&payer_mailbox);
    post_native(&world, &world.issuer, shop_side, &content);

    world.collect(&world.payer);

    assert!(world.node.pushed_transactions().is_empty());
    assert_ne!(tx_state(&world.payer, tx_id), TxState::Posted);
    let slate_id = slate_id_of(&world.payer, tx_id);
    assert!(
        world
            .payer
            .read(|repos| repos.slate(slate_id, SlateStage::Standard2))
            .is_none()
    );
}

#[test]
fn a_native_answer_at_another_height_is_refused() {
    changed_s2_is_refused(|body| body[HEIGHT_AT + 7] ^= 1);
}

#[test]
fn a_native_answer_with_another_header_version_is_refused() {
    changed_s2_is_refused(|body| body[HEADER_VERSION_AT + 1] ^= 1);
}

/// The unchanged S2 of the same set-up is taken, so the refusals above come from the change.
#[test]
fn an_unchanged_native_answer_held_back_and_posted_is_taken() {
    let (world, shop_side, ben_side) = paired((true, true), WalletPolicy::default());
    let tx_id = send_s1(&world, ben_side);
    let payer_mailbox = peer_mailbox(&world.issuer, shop_side);
    world.relay.set_post_refused(&payer_mailbox);
    world.collect(&world.issuer);
    let content = native_content(
        &world.issuer,
        shop_side,
        SlateStage::Standard2,
        &world.payer,
        ben_side,
    );
    world.relay.set_post_accepted(&payer_mailbox);
    post_native(&world, &world.issuer, shop_side, &content);

    world.collect(&world.payer);

    assert_eq!(world.node.pushed_transactions().len(), 1);
    assert_eq!(tx_state(&world.payer, tx_id), TxState::Posted);
}
