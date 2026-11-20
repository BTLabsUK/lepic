// SPDX-License-Identifier: Apache-2.0
//! Pairing mail on the relays of the list: the reply, the confirm, the status and unpaired
//! notices and a refusal go to each usable relay of the list and to the invite's or card's
//! relay when the list lacks it, are read on the same relays, and are applied once however many
//! copies come in. A relay of the list that did not take a copy is owed one, and the outbox's
//! back-off posts it there until the mail is answered or ends.

// Test helpers may unwrap, index and panic (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use super::helpers::{self, MINUTE, accept, events, invite_request, relays};
use super::{confirm_mailbox, failures};
use crate::epicbox_world::{Party, World};
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork, RelayEndpoint, Security};
use lepic_store::{ContactId, OutboxState, StoredNativeOutbox};
use lepic_wallet::Event;
use lepic_wallet::event::{ContactChange, ContactEvent, ContactUpdate};
use lepic_wallet_contacts::{
    CollectTrigger, ContactRelays, PairingFailure, SasDecision, WalletContacts,
};

/// The party's relays with relay2.test added: a list of two relays.
fn with_relay2(party: &Party) -> ContactRelays {
    helpers::adding(
        relays(party),
        vec![RelayEndpoint::new(
            Domain::parse("relay2.test").unwrap(),
            Some(80),
            Security::Plain,
        )],
    )
}

fn collect_on(
    world: &World,
    party: &Party,
    list: &ContactRelays,
    trigger: CollectTrigger,
) -> lepic_wallet_contacts::CollectReport {
    world
        .block_on(party.wallet.contact_book().contacts_collect(list, trigger))
        .unwrap()
}

/// `inviter` invites on its list, `invitee` answers on its own, and both collect on their
/// lists until both are paired and the inviter heard the invitee finish. Returns the two
/// contact ids, the inviter's first.
fn pair_on(
    world: &World,
    (inviter, inviter_list): (&Party, &ContactRelays),
    (invitee, invitee_list): (&Party, &ContactRelays),
) -> (ContactId, ContactId) {
    let link = world
        .block_on(
            inviter
                .wallet
                .contact_book()
                .pairing_invite(inviter_list, invite_request("Anna")),
        )
        .unwrap()
        .link;
    let answered = world
        .block_on(
            invitee
                .wallet
                .contact_book()
                .pairing_accept(invitee_list, accept(&link, "Ben", false)),
        )
        .unwrap();
    assert!(answered.posted);
    let open = CollectTrigger::Open;
    assert_eq!(collect_on(world, inviter, inviter_list, open).paired, 1);
    assert_eq!(collect_on(world, invitee, invitee_list, open).paired, 1);
    collect_on(world, inviter, inviter_list, open);
    (world.only_contact(inviter), answered.contact_id)
}

/// The outbox rows of the pairing in progress of `contact`: an invitee's reply, an inviter's
/// confirm.
fn pairing_rows(party: &Party, contact: ContactId) -> Vec<StoredNativeOutbox> {
    let id: String = contact.0.iter().map(|byte| format!("{byte:02x}")).collect();
    party.read(|repos| repos.native_outbox_from(&format!("pairing:{id}")))
}

/// `address`'s key on relay `relay`, `host:port`.
fn on_relay(address: &EpicboxAddress, relay: &str) -> EpicboxAddress {
    EpicboxAddress::parse(
        &format!("{}@{relay}", address.key_text()),
        RelayNetwork::Floonet,
    )
    .unwrap()
}

/// The mailbox `party` reads its contact `contact`'s mail in, on relay.test.
fn own_mailbox(party: &Party, contact: ContactId) -> EpicboxAddress {
    let mailbox = party
        .read(|repos| repos.contact_mailbox(contact))
        .unwrap()
        .our_mailbox;
    on_relay(
        &EpicboxAddress::parse(&mailbox, RelayNetwork::Floonet).unwrap(),
        "relay.test:80",
    )
}

/// What waits on each relay for `address`'s key: relay.test's count first.
fn waiting(world: &World, address: &EpicboxAddress) -> (usize, usize) {
    (
        world.relay.pending(&on_relay(address, "relay.test:80")),
        world.relay.pending(&on_relay(address, "relay2.test:80")),
    )
}

fn posts_on(world: &World) -> (usize, usize) {
    (
        world.relay.received_on("relay.test", "PostSlate"),
        world.relay.received_on("relay2.test", "PostSlate"),
    )
}

/// The invite's relay is down when the invitee answers: the reply goes to the other relay of
/// the list, where the inviter reads its reply mailbox, and the pairing finishes there. The
/// confirm the other relay took is still owed to the invite's relay, and goes there once it is
/// back.
#[test]
fn a_pairing_finishes_when_the_invite_relay_is_down() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_list, payer_list) = (with_relay2(&world.issuer), with_relay2(&world.payer));
    let link = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .pairing_invite(&issuer_list, invite_request("Anna")),
        )
        .unwrap()
        .link;
    world.relay.set_domain_down("relay.test", true);

    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&payer_list, accept(&link, "Ben", false)),
        )
        .unwrap();
    assert!(answered.posted);
    let open = CollectTrigger::Open;
    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, open).paired,
        1
    );
    assert_eq!(
        collect_on(&world, &world.payer, &payer_list, open).paired,
        1
    );
    collect_on(&world, &world.issuer, &issuer_list, open);
    let (anna_side, ben_side) = (
        world.only_contact(&world.issuer),
        world.only_contact(&world.payer),
    );
    assert_eq!(answered.contact_id, ben_side);
    assert_eq!(
        world.sas(&world.issuer, anna_side),
        world.sas(&world.payer, ben_side)
    );
    assert_eq!(world.relay.received_on("relay.test", "PostSlate"), 0);
    // The inviter's confirm left by relay2 and waits for the invite's relay.
    let rows = pairing_rows(&world.issuer, anna_side);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].entry.state, OutboxState::Queued);
    assert!(rows[0].entry.route_value.ends_with("@relay.test:80"));

    // The app opens: the whole outbox is tried at once.
    world.relay.set_domain_down("relay.test", false);
    collect_on(&world, &world.issuer, &issuer_list, open);
    let rows = pairing_rows(&world.issuer, anna_side);
    assert_eq!(rows[0].entry.state, OutboxState::Posted);
    assert_eq!(posts_on(&world).0, 1);
}

/// The invite's relay is down when the invitee posts its reply, and a relay only the invitee's
/// list holds takes it. The reply is owed to the invite's relay, goes there alone once it is
/// back, and the pairing finishes on both sides. The relay that took the first copy gets no
/// second one.
#[test]
fn a_reply_taken_off_the_inviters_list_still_reaches_the_invite_relay() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_list, payer_list) = (relays(&world.issuer), with_relay2(&world.payer));
    let link = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .pairing_invite(&issuer_list, invite_request("Anna")),
        )
        .unwrap()
        .link;
    world.relay.set_domain_down("relay.test", true);

    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&payer_list, accept(&link, "Ben", false)),
        )
        .unwrap();
    assert!(answered.posted);
    let rows = pairing_rows(&world.payer, answered.contact_id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].entry.state, OutboxState::Queued);
    assert!(rows[0].entry.route_value.ends_with("@relay.test:80"));
    let reply_box =
        EpicboxAddress::parse(&rows[0].entry.route_value, RelayNetwork::Floonet).unwrap();
    assert_eq!(waiting(&world, &reply_box), (0, 1));

    world.relay.set_domain_down("relay.test", false);
    let open = CollectTrigger::Open;
    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, open).paired,
        0
    );
    world.payer.clock.advance(MINUTE);
    collect_on(
        &world,
        &world.payer,
        &payer_list,
        CollectTrigger::Foreground,
    );
    assert_eq!(waiting(&world, &reply_box), (1, 1));

    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, open).paired,
        1
    );
    assert_eq!(
        collect_on(&world, &world.payer, &payer_list, open).paired,
        1
    );
    assert!(pairing_rows(&world.payer, answered.contact_id).is_empty());
    assert_eq!(
        world.sas(&world.issuer, world.only_contact(&world.issuer)),
        world.sas(&world.payer, answered.contact_id)
    );
    assert_eq!(waiting(&world, &reply_box), (0, 1));
}

/// The invite's relay leaves the confirm unanswered, and a relay only the inviter's list holds
/// takes it. The confirm is owed to the invite's relay, goes there alone once it answers, and
/// the invitee, which reads only that relay, finishes.
#[test]
fn a_confirm_taken_off_the_invitees_list_still_reaches_the_invite_relay() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_list, payer_list) = (with_relay2(&world.issuer), relays(&world.payer));
    let link = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .pairing_invite(&issuer_list, invite_request("Anna")),
        )
        .unwrap()
        .link;
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&payer_list, accept(&link, "Ben", false)),
        )
        .unwrap();
    let confirm_box = confirm_mailbox(&world.payer);
    world.relay.set_domain_unanswered("relay.test");

    // The foreground tick keeps the back-off, so the confirm is not tried again in this pass.
    let foreground = CollectTrigger::Foreground;
    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, foreground).paired,
        1
    );
    let anna_side = world.only_contact(&world.issuer);
    let rows = pairing_rows(&world.issuer, anna_side);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].entry.state, OutboxState::Queued);
    assert!(rows[0].entry.route_value.ends_with("@relay.test:80"));
    assert_eq!(waiting(&world, &confirm_box), (0, 1));

    world.relay.set_domain_answered("relay.test");
    let open = CollectTrigger::Open;
    assert_eq!(
        collect_on(&world, &world.payer, &payer_list, open).paired,
        0
    );
    world.issuer.clock.advance(MINUTE);
    collect_on(&world, &world.issuer, &issuer_list, foreground);
    assert_eq!(waiting(&world, &confirm_box), (1, 1));
    let rows = pairing_rows(&world.issuer, anna_side);
    assert_eq!(rows[0].entry.state, OutboxState::Posted);

    assert_eq!(
        collect_on(&world, &world.payer, &payer_list, open).paired,
        1
    );
    assert_eq!(world.contact_ids(&world.payer).len(), 1);
    assert_eq!(waiting(&world, &confirm_box), (0, 1));
}

/// Both lists hold two relays, so the reply arrives twice: the inviter pairs and tells the
/// host once, and posts one confirm to each relay; the invitee pairs once.
#[test]
fn a_reply_read_on_two_relays_pairs_once_and_confirms_once() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_list, payer_list) = (with_relay2(&world.issuer), with_relay2(&world.payer));
    let link = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .pairing_invite(&issuer_list, invite_request("Anna")),
        )
        .unwrap()
        .link;
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&payer_list, accept(&link, "Ben", false)),
        )
        .unwrap();
    let confirm_box = confirm_mailbox(&world.payer);
    let mut issuer_events = world.issuer.wallet.subscribe();

    let open = CollectTrigger::Open;
    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, open).paired,
        1
    );
    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, open).paired,
        0
    );
    let replied = events(&mut issuer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::PairingReplied(_)))
        .count();
    assert_eq!(replied, 1);
    let anna_side = world.only_contact(&world.issuer);
    let rows = pairing_rows(&world.issuer, anna_side);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(waiting(&world, &confirm_box), (1, 1));

    assert_eq!(
        collect_on(&world, &world.payer, &payer_list, open).paired,
        1
    );
    assert_eq!(
        collect_on(&world, &world.payer, &payer_list, open).paired,
        0
    );
    assert_eq!(world.contact_ids(&world.payer).len(), 1);
}

/// The reply's copy on the second relay is read only once the first relay took the confirm: it
/// pairs nothing and queues no second confirm. The second relay gets the one confirm's owed copy.
#[test]
fn a_reply_read_after_its_confirm_was_taken_sends_no_second_confirm() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_list, payer_list) = (with_relay2(&world.issuer), with_relay2(&world.payer));
    let link = world
        .block_on(
            world
                .issuer
                .wallet
                .contact_book()
                .pairing_invite(&issuer_list, invite_request("Anna")),
        )
        .unwrap()
        .link;
    world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&payer_list, accept(&link, "Ben", false)),
        )
        .unwrap();
    let confirm_box = confirm_mailbox(&world.payer);
    let open = CollectTrigger::Open;

    world.relay.set_domain_down("relay2.test", true);
    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, open).paired,
        1
    );
    let anna_side = world.only_contact(&world.issuer);
    let rows = pairing_rows(&world.issuer, anna_side);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].entry.state, OutboxState::Posted);
    assert_eq!(waiting(&world, &confirm_box), (1, 0));

    world.relay.set_domain_down("relay2.test", false);
    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, open).paired,
        0
    );
    let rows = pairing_rows(&world.issuer, anna_side);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(waiting(&world, &confirm_box), (1, 1));
}

/// The invitee's list lacks the invite's relay: the reply goes there too, and the confirm and
/// the finished notice come back by it, so the pairing finishes.
#[test]
fn an_invite_whose_relay_is_outside_the_list_gets_its_reply_there() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issuer_list = relays(&world.issuer);
    let payer_list = helpers::only_relay2(&world, &world.payer);

    let (anna_side, ben_side) = pair_on(
        &world,
        (&world.issuer, &issuer_list),
        (&world.payer, &payer_list),
    );

    assert_eq!(
        world.sas(&world.issuer, anna_side),
        world.sas(&world.payer, ben_side)
    );
    // The invitee read the confirm on the invite's relay, so its pairing ended.
    assert!(
        world
            .payer
            .read(|repos| repos.pending_pairings())
            .is_empty()
    );
    let rows = pairing_rows(&world.issuer, anna_side);
    assert!(!rows.is_empty());
    assert!(
        rows.iter()
            .all(|row| row.entry.state == OutboxState::Posted)
    );
}

/// The match notice reaches both relays of the list: the contact applies it once and says so
/// once.
#[test]
fn a_match_notice_read_on_two_relays_is_applied_once() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_list, payer_list) = (with_relay2(&world.issuer), with_relay2(&world.payer));
    let (anna_side, ben_side) = pair_on(
        &world,
        (&world.issuer, &issuer_list),
        (&world.payer, &payer_list),
    );
    let ben_box = own_mailbox(&world.payer, ben_side);
    let mut payer_events = world.payer.wallet.subscribe();

    world
        .block_on(world.issuer.wallet.contact_book().pairing_sas(
            &issuer_list,
            anna_side,
            SasDecision::Match,
        ))
        .unwrap();
    assert_eq!(waiting(&world, &ben_box), (1, 1));
    collect_on(&world, &world.payer, &payer_list, CollectTrigger::Open);
    collect_on(&world, &world.payer, &payer_list, CollectTrigger::Open);

    let verified = events(&mut payer_events)
        .into_iter()
        .filter(|event| {
            *event
                == Event::ContactUpdated(ContactUpdate::of(ben_side, ContactChange::PeerVerified))
        })
        .count();
    assert_eq!(verified, 1);
    assert_eq!(waiting(&world, &ben_box), (0, 0));
}

/// The unpaired notice finds no relay that answers when the pairing is removed: the record goes
/// at once, the row stays, and a later run of the outbox posts the notice from the list's
/// relays, after which the row ends.
#[test]
fn an_unpaired_notice_is_posted_later_when_no_relay_answers_now() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let (issuer_list, payer_list) = (with_relay2(&world.issuer), with_relay2(&world.payer));
    let (anna_side, ben_side) = pair_on(
        &world,
        (&world.issuer, &issuer_list),
        (&world.payer, &payer_list),
    );
    let ben_box = own_mailbox(&world.payer, ben_side);
    let mut payer_events = world.payer.wallet.subscribe();
    world.relay.set_unroutable(&ben_box);

    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_unpair(&issuer_list, anna_side)
            )
            .unwrap()
    );
    assert!(world.contact_ids(&world.issuer).is_empty());
    let rows = helpers::mail_rows(&world.issuer, anna_side);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].entry.state, OutboxState::Uncertain);
    assert_eq!(waiting(&world, &ben_box), (0, 0));

    // Not due yet: the foreground tick keeps the back-off.
    world.relay.set_routable(&ben_box);
    let foreground = CollectTrigger::Foreground;
    collect_on(&world, &world.issuer, &issuer_list, foreground);
    assert_eq!(waiting(&world, &ben_box), (0, 0));
    assert_eq!(helpers::mail_rows(&world.issuer, anna_side).len(), 1);

    world.issuer.clock.advance(MINUTE);
    collect_on(&world, &world.issuer, &issuer_list, foreground);
    assert_eq!(waiting(&world, &ben_box), (1, 1));
    assert!(helpers::mail_rows(&world.issuer, anna_side).is_empty());

    collect_on(&world, &world.payer, &payer_list, CollectTrigger::Open);
    collect_on(&world, &world.payer, &payer_list, CollectTrigger::Open);
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact(ben_side))
            .unwrap()
            .removed_by_peer
    );
    let unpaired: Vec<_> = events(&mut payer_events)
        .into_iter()
        .filter(|event| matches!(event, Event::ContactUnpaired(_)))
        .collect();
    assert_eq!(
        unpaired,
        vec![Event::ContactUnpaired(ContactEvent {
            contact_id: ben_side
        })]
    );
}

/// The contact's relay is outside our list: the unpaired notice's first post goes there too,
/// while the record still names it. The contact invited on that relay, so its card names it, and
/// our list's only relay is down, so the contact's relay is the one that carries the notice.
#[test]
fn an_unpaired_notice_reaches_the_contacts_relay_outside_the_list_at_once() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issuer_list = relays(&world.issuer);
    let payer_list = helpers::only_relay2(&world, &world.payer);
    let (ben_side, anna_side) = pair_on(
        &world,
        (&world.payer, &payer_list),
        (&world.issuer, &issuer_list),
    );
    let before = posts_on(&world);
    let earlier = helpers::mail_rows(&world.issuer, anna_side).len();
    world.relay.set_domain_down("relay.test", true);

    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_unpair(&issuer_list, anna_side)
            )
            .unwrap()
    );

    let after = posts_on(&world);
    assert_eq!((after.0 - before.0, after.1 - before.1), (0, 1));
    // Taken on the first post: the row is posted, kept until the prune as delivered rows are.
    let rows = helpers::mail_rows(&world.issuer, anna_side);
    let added = &rows[earlier..];
    assert_eq!(added.len(), 1, "{rows:?}");
    assert_eq!(added[0].entry.state, OutboxState::Posted);
    collect_on(&world, &world.payer, &payer_list, CollectTrigger::Open);
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact(ben_side))
            .unwrap()
            .removed_by_peer
    );
}

/// The contact's relay is outside our list and down when the pairing is removed: our list's
/// relay takes the unpaired notice, the record goes, and the notice stays owed to the contact's
/// relay. Once that relay is back, the outbox posts the notice there, where the contact reads.
#[test]
fn an_unpaired_notice_reaches_the_contacts_relay_after_the_record_is_gone() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let issuer_list = relays(&world.issuer);
    let payer_list = helpers::only_relay2(&world, &world.payer);
    let (ben_side, anna_side) = pair_on(
        &world,
        (&world.payer, &payer_list),
        (&world.issuer, &issuer_list),
    );
    let earlier = helpers::mail_rows(&world.issuer, anna_side).len();
    world.relay.set_domain_down("relay2.test", true);

    assert!(
        world
            .block_on(
                world
                    .issuer
                    .wallet
                    .contact_book()
                    .contact_unpair(&issuer_list, anna_side)
            )
            .unwrap()
    );
    assert!(world.contact_ids(&world.issuer).is_empty());
    let rows = helpers::mail_rows(&world.issuer, anna_side);
    let added = &rows[earlier..];
    assert_eq!(added.len(), 1, "{rows:?}");
    assert_eq!(added[0].entry.state, OutboxState::Queued);
    assert!(added[0].entry.route_value.ends_with("@relay2.test:80"));
    let row = added[0].id;

    world.relay.set_domain_down("relay2.test", false);
    let before = posts_on(&world);
    world.issuer.clock.advance(MINUTE);
    collect_on(
        &world,
        &world.issuer,
        &issuer_list,
        CollectTrigger::Foreground,
    );
    let after = posts_on(&world);
    assert_eq!((after.0 - before.0, after.1 - before.1), (0, 1));
    // Taken by the contact's relay: the row of a removed record ends.
    assert!(
        world
            .issuer
            .read(|repos| repos.native_outbox_entry(row))
            .is_none()
    );

    collect_on(&world, &world.payer, &payer_list, CollectTrigger::Open);
    assert!(
        world
            .block_on(world.payer.wallet.contact_book().contact(ben_side))
            .unwrap()
            .removed_by_peer
    );
}

/// The invitee's reply row is posted once, taken by the invite's relay, and kept until the
/// confirm is taken: then the row ends with the pairing in progress.
#[test]
fn a_reply_row_ends_when_the_confirmation_is_taken() {
    let world = World::new();
    let link = world.invite(&world.issuer, "Anna");
    let answered = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    let rows = pairing_rows(&world.payer, answered.contact_id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].entry.state, OutboxState::Posted);

    assert_eq!(world.collect(&world.issuer).paired, 1);
    // The confirm is not taken yet: the row stays.
    assert_eq!(pairing_rows(&world.payer, answered.contact_id).len(), 1);

    assert_eq!(world.collect(&world.payer).paired, 1);
    assert!(pairing_rows(&world.payer, answered.contact_id).is_empty());
}

/// A match notice no relay answered is posted again by the outbox's run once its back-off is
/// due, and not before.
#[test]
fn a_status_notice_is_reposted_by_the_outbox_run_not_a_timer() {
    let world = World::new();
    let (anna_side, ben_side) = world.pair_by_link();
    let ben_box = own_mailbox(&world.payer, ben_side);
    let mut payer_events = world.payer.wallet.subscribe();
    world.relay.set_unroutable(&ben_box);

    world
        .block_on(world.issuer.wallet.contact_book().pairing_sas(
            &relays(&world.issuer),
            anna_side,
            SasDecision::Match,
        ))
        .unwrap();
    let rows = helpers::mail_rows(&world.issuer, anna_side);
    let row = rows
        .iter()
        .find(|row| row.entry.state != OutboxState::Posted)
        .unwrap();
    assert_eq!(row.entry.state, OutboxState::Uncertain);
    let unsent = row.id;

    world.relay.set_routable(&ben_box);
    let foreground = CollectTrigger::Foreground;
    collect_on(&world, &world.issuer, &relays(&world.issuer), foreground);
    assert_eq!(world.relay.pending(&ben_box), 0);

    world.issuer.clock.advance(MINUTE);
    collect_on(&world, &world.issuer, &relays(&world.issuer), foreground);
    assert_eq!(world.relay.pending(&ben_box), 1);
    let posted = world
        .issuer
        .read(|repos| repos.native_outbox_entry(unsent))
        .unwrap();
    assert_eq!(posted.entry.state, OutboxState::Posted);

    world.collect(&world.payer);
    let verified = events(&mut payer_events)
        .into_iter()
        .filter(|event| {
            *event
                == Event::ContactUpdated(ContactUpdate::of(ben_side, ContactChange::PeerVerified))
        })
        .count();
    assert_eq!(verified, 1);
}

/// The inviter's list lacks its invite's relay: a second reply is refused, and the refusal
/// reaches the asker on the invite's relay, where it reads.
#[test]
fn a_refusal_reaches_the_asker_on_a_relay_outside_the_list() {
    let world = World::new();
    world.relay.set_relays_apart(true);
    let link = world.invite(&world.issuer, "Anna");
    let issuer_list = helpers::only_relay2(&world, &world.issuer);
    let first = world
        .block_on(
            world
                .payer
                .wallet
                .contact_book()
                .pairing_accept(&relays(&world.payer), accept(&link, "Ben", false)),
        )
        .unwrap();
    let twin = world.payer_twin();
    let second = world
        .block_on(
            twin.wallet
                .contact_book()
                .pairing_accept(&relays(&twin), accept(&link, "Ben again", false)),
        )
        .unwrap();
    assert!(first.posted && second.posted);

    assert_eq!(
        collect_on(&world, &world.issuer, &issuer_list, CollectTrigger::Open).paired,
        1
    );
    assert_eq!(world.collect(&world.payer).paired, 1);
    let mut twin_events = twin.wallet.subscribe();
    let report = world.collect(&twin);
    assert_eq!(report.paired, 0);
    assert_eq!(
        failures(&events(&mut twin_events)),
        vec![PairingFailure::Refused(lepic_contact::Refusal::AlreadyUsed)]
    );
    assert!(world.contact_ids(&twin).is_empty());
}
