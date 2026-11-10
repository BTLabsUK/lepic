// SPDX-License-Identifier: Apache-2.0
//! Pairing v3 between two wallets on the mock relay: requests to a proven payments address
//! (Way 1), the address an answer must prove, crossed requests, the standing invite, what an
//! inviter waits for, and how a pairing ends.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

#[path = "pairing/helpers.rs"]
mod helpers;
mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::time::Duration;

use helpers::{accept, events, invite_request, relays};
use lepic_store::{AccountIndex, ContactState, PeerCompat, WalletStore};
use lepic_transport::marker::features::{LEPIC_FEATURES, PAIR_REQUESTS};
use lepic_wallet::event::{ContactChange, ContactUpdate};
use lepic_wallet::{Clock, Event};
use lepic_wallet_contacts::{
    AcceptRequest, ContactError, ContactRelays, PairingEndReason, PairingStatus, RelayMode,
    SasDecision, WalletContacts,
};
use world::{Party, World};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const HOUR: Duration = Duration::from_secs(60 * 60);

/// Records `peer` as a fresh LEPIC wallet that claims every feature of this build, as one marked
/// payment between the two leaves it.
fn proven(party: &Party, peer: &Party) {
    let now = party.clock.now();
    party
        .store()
        .write(|repos| {
            repos.put_peer_compat(
                &peer.address.key_text(),
                &PeerCompat {
                    last_marked_at: Some(now),
                    claimed: LEPIC_FEATURES,
                    works: 1,
                    features_at: Some(now),
                    ..PeerCompat::default()
                },
            )
        })
        .unwrap();
}

fn drain(world: &World, party: &Party) {
    world.block_on(party.epicbox.drain(&party.wallet)).unwrap();
}

fn status(world: &World, party: &Party, id: lepic_store::ContactId) -> PairingStatus {
    world
        .block_on(party.wallet.contact_book().contact(id))
        .unwrap()
        .status
}

fn send_request(
    world: &World,
    from: &Party,
    to: &Party,
) -> Result<lepic_store::ContactId, ContactError> {
    world
        .block_on(from.wallet.contact_book().pairing_request_send(
            &relays(from),
            AccountIndex(0),
            &to.address.to_string(),
            "Anna",
        ))
        .map(|offer| offer.contact_id)
}

fn accept_request(
    world: &World,
    party: &Party,
    link: &str,
    from: &Party,
) -> Result<lepic_store::ContactId, ContactError> {
    world
        .block_on(party.wallet.contact_book().pairing_accept(
            &relays(party),
            AcceptRequest {
                expect_address: Some(from.address.to_string()),
                ..accept(link, "Ben", false)
            },
        ))
        .map(|outcome| outcome.contact_id)
}

#[test]
fn a_request_to_a_proven_contact_pairs_both_sides_verified() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    proven(anna, ben);
    let mut ben_events = ben.wallet.subscribe();

    let anna_side = send_request(&world, anna, ben).unwrap();
    drain(&world, ben);

    let requests = world
        .block_on(ben.wallet.contact_book().pairing_requests())
        .unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].from_address, anna.address.to_string());
    assert!(events(&mut ben_events).iter().any(|event| matches!(
        event,
        Event::PairingRequested(news) if news.request_id == requests[0].request_id
    )));
    assert_eq!(
        world.relay.pending(&ben.address),
        0,
        "acknowledged once stored"
    );

    let ben_side = accept_request(&world, ben, &requests[0].invite_link, anna).unwrap();
    world.collect(anna);
    world.collect(ben);
    world.collect(anna);

    assert_eq!(status(&world, anna, anna_side), PairingStatus::Verified);
    assert_eq!(status(&world, ben, ben_side), PairingStatus::Verified);
    assert!(
        world
            .block_on(ben.wallet.contact_book().pairing_requests())
            .unwrap()
            .is_empty(),
        "an answered request is no longer listed"
    );
    // The answer shows that pair requests work with Ben's key.
    assert_ne!(works(anna, ben) & PAIR_REQUESTS, 0);
}

fn works(party: &Party, peer: &Party) -> u32 {
    party
        .store()
        .read(|repos| repos.peer_compat(&peer.address.key_text()))
        .unwrap()
        .unwrap()
        .works
}

#[test]
fn an_invite_expecting_an_address_but_not_sent_as_a_request_proves_no_pair_requests() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    proven(anna, ben);
    let offer = world
        .block_on(anna.wallet.contact_book().pairing_invite(
            &relays(anna),
            lepic_wallet_contacts::InviteRequest {
                expect_address: Some(ben.address.to_string()),
                ..invite_request("Anna")
            },
        ))
        .unwrap();
    world
        .block_on(
            ben.wallet
                .contact_book()
                .pairing_accept(&relays(ben), accept(&offer.link, "Ben", false)),
        )
        .unwrap();
    world.collect(anna);
    world.collect(ben);
    world.collect(anna);

    assert_eq!(
        status(&world, anna, offer.contact_id),
        PairingStatus::Verified
    );
    assert_eq!(works(anna, ben) & PAIR_REQUESTS, 0);
}

#[test]
fn no_request_reaches_an_unproven_or_stale_key() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    let posts = world.relay.received("PostSlate");

    assert!(matches!(
        send_request(&world, anna, ben),
        Err(ContactError::PeerNotProven)
    ));
    proven(anna, ben);
    anna.clock.advance(31 * DAY);
    assert!(matches!(
        send_request(&world, anna, ben),
        Err(ContactError::PeerNotProven)
    ));

    assert_eq!(world.relay.received("PostSlate"), posts);
    assert!(
        world
            .block_on(anna.wallet.contact_book().pairings_pending())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn an_answer_from_another_wallet_than_expected_stores_nothing_and_the_invite_waits() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    let stranger = world.stranger();
    let mut anna_events = anna.wallet.subscribe();
    let offer = world
        .block_on(anna.wallet.contact_book().pairing_invite(
            &relays(anna),
            lepic_wallet_contacts::InviteRequest {
                expect_address: Some(stranger.address.to_string()),
                ..invite_request("Anna")
            },
        ))
        .unwrap();

    world
        .block_on(
            ben.wallet
                .contact_book()
                .pairing_accept(&relays(ben), accept(&offer.link, "Ben", false)),
        )
        .unwrap();
    world.collect(anna);

    // The answer is refused, and the pairing keeps waiting for the wallet it expects.
    assert!(
        !events(&mut anna_events)
            .iter()
            .any(|event| matches!(event, Event::PairingFailed(_)))
    );
    assert!(
        world
            .block_on(anna.wallet.contact_book().contacts())
            .unwrap()
            .iter()
            .all(|contact| contact.claimed_name.is_none())
    );
    let pending = world
        .block_on(anna.wallet.contact_book().pairings_pending())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].contact_id, offer.contact_id);

    // The expected wallet's answer still pairs.
    world
        .block_on(
            stranger
                .wallet
                .contact_book()
                .pairing_accept(&relays(&stranger), accept(&offer.link, "Sam", false)),
        )
        .unwrap();
    world.collect(anna);
    let contact = world
        .block_on(anna.wallet.contact_book().contact(offer.contact_id))
        .unwrap();
    assert_eq!(
        contact.payments_address.as_deref(),
        Some(stranger.address.to_string().as_str())
    );
}

#[test]
fn a_dismissed_request_stays_hidden_and_a_newer_one_shows() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    proven(anna, ben);
    let first = send_request(&world, anna, ben).unwrap();
    drain(&world, ben);
    let requests = world
        .block_on(ben.wallet.contact_book().pairing_requests())
        .unwrap();
    world
        .block_on(
            ben.wallet
                .contact_book()
                .pairing_request_dismiss(requests[0].request_id),
        )
        .unwrap();
    assert!(
        world
            .block_on(ben.wallet.contact_book().pairing_requests())
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        accept_request(&world, ben, &requests[0].invite_link, anna),
        Err(ContactError::InviteDismissed)
    ));

    // Anna withdraws and asks again: the newer request shows.
    world
        .block_on(anna.wallet.contact_book().pairing_cancel(first))
        .unwrap();
    anna.clock.advance(Duration::from_secs(60));
    send_request(&world, anna, ben).unwrap();
    drain(&world, ben);
    let again = world
        .block_on(ben.wallet.contact_book().pairing_requests())
        .unwrap();
    assert_eq!(again.len(), 1);
    assert_ne!(again[0].request_id, requests[0].request_id);
}

#[test]
fn a_sent_request_is_listed_and_withdrawing_it_frees_a_new_one() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    proven(anna, ben);
    let first = send_request(&world, anna, ben).unwrap();
    let sent = world
        .block_on(anna.wallet.contact_book().pairing_requests_sent())
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].contact_id, first);
    assert_eq!(
        sent[0].expect_address.as_deref(),
        Some(ben.address.to_string().as_str())
    );
    assert!(matches!(
        send_request(&world, anna, ben),
        Err(ContactError::PairingInProgress)
    ));

    world
        .block_on(anna.wallet.contact_book().pairing_request_cancel(first))
        .unwrap();
    assert!(
        world
            .block_on(anna.wallet.contact_book().pairing_requests_sent())
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        world.block_on(anna.wallet.contact_book().pairing_request_cancel(first)),
        Err(ContactError::UnknownPairing)
    ));
    anna.clock.advance(Duration::from_secs(60));
    send_request(&world, anna, ben).unwrap();
}

#[test]
fn crossed_requests_keep_the_invite_of_the_lower_key() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    proven(anna, ben);
    proven(ben, anna);
    send_request(&world, anna, ben).unwrap();
    send_request(&world, ben, anna).unwrap();
    drain(&world, anna);
    drain(&world, ben);
    let at_anna = world
        .block_on(anna.wallet.contact_book().pairing_requests())
        .unwrap();
    let at_ben = world
        .block_on(ben.wallet.contact_book().pairing_requests())
        .unwrap();
    let anna_lower = anna.address.public_key().to_bytes() < ben.address.public_key().to_bytes();
    let (low, high, at_low, at_high) = if anna_lower {
        (anna, ben, &at_anna, &at_ben)
    } else {
        (ben, anna, &at_ben, &at_anna)
    };

    // The lower key's own request wins: it waits for that answer.
    assert!(matches!(
        accept_request(&world, low, &at_low[0].invite_link, high),
        Err(ContactError::Crossed)
    ));
    // The higher key answers the lower key's request and withdraws its own.
    accept_request(&world, high, &at_high[0].invite_link, low).unwrap();
    assert!(
        world
            .block_on(high.wallet.contact_book().pairings_pending())
            .unwrap()
            .iter()
            .all(|pending| pending.role == lepic_store::PairingRole::Invitee)
    );
    world.collect(low);
    world.collect(high);
    world.collect(low);
    let paired = |party: &Party| {
        world
            .block_on(party.wallet.contact_book().contacts())
            .unwrap()
    };
    assert_eq!(paired(low).len(), 1);
    assert_eq!(paired(high).len(), 1);
    assert_eq!(paired(low)[0].status, PairingStatus::Verified);
}

#[test]
fn the_standing_invite_stays_until_answered_or_renamed() {
    let world = World::new();
    let anna = &world.issuer;
    let standing = |name: &str| {
        world
            .block_on(anna.wallet.contact_book().pairing_standing_invite(
                &relays(anna),
                AccountIndex(0),
                name,
            ))
            .unwrap()
    };
    let first = standing("Anna");
    assert_eq!(standing("Anna"), first, "the same invite while it stands");
    assert!(
        world
            .block_on(anna.wallet.contact_book().pairings_pending())
            .unwrap()
            .is_empty(),
        "the standing invite is not a pending row"
    );
    let renamed = standing("Anna B");
    assert_ne!(renamed.contact_id, first.contact_id);
    // Less than a day left: a new one.
    anna.clock.advance(6 * DAY + Duration::from_secs(60));
    assert_ne!(standing("Anna B").contact_id, renamed.contact_id);
}

#[test]
fn an_inviter_waits_until_it_hears_the_invitee_finished() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    let mut anna_events = anna.wallet.subscribe();
    let link = world.invite(anna, "Anna");
    world
        .block_on(
            ben.wallet
                .contact_book()
                .pairing_accept(&relays(ben), accept(&link, "Ben", false)),
        )
        .unwrap();
    world.collect(anna);
    let anna_side = world.only_contact(anna);
    assert_eq!(status(&world, anna, anna_side), PairingStatus::Waiting);
    assert!(matches!(
        world.block_on(
            anna.wallet
                .contact_book()
                .contact_set_allow_invoices(anna_side, true)
        ),
        Err(ContactError::Waiting)
    ));

    world.collect(ben);
    world.collect(anna);

    assert_eq!(status(&world, anna, anna_side), PairingStatus::Paired);
    assert!(
        events(&mut anna_events).contains(&Event::ContactUpdated(ContactUpdate::of(
            anna_side,
            ContactChange::Heard
        )))
    );
}

#[test]
fn an_inviter_never_heard_ends_after_seven_days_of_collecting() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    let link = world.invite(anna, "Anna");
    world
        .block_on(
            ben.wallet
                .contact_book()
                .pairing_accept(&relays(ben), accept(&link, "Ben", false)),
        )
        .unwrap();
    world.collect(anna);
    let anna_side = world.only_contact(anna);

    // Ten days without collecting count for nothing.
    anna.clock.advance(10 * DAY);
    world.collect(anna);
    assert_eq!(status(&world, anna, anna_side), PairingStatus::Waiting);
    // Seven days of collecting at least hourly end it.
    for _ in 0..7 * 24 {
        anna.clock.advance(HOUR);
        world.collect(anna);
    }
    let view = world
        .block_on(anna.wallet.contact_book().contact(anna_side))
        .unwrap();
    assert_eq!(view.status, PairingStatus::Ended);
    assert_eq!(view.ended_reason, Some(PairingEndReason::NeverFinished));
}

#[test]
fn days_the_app_was_closed_do_not_count_as_collecting() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    let link = world.invite(anna, "Anna");
    world
        .block_on(
            ben.wallet
                .contact_book()
                .pairing_accept(&relays(ben), accept(&link, "Ben", false)),
        )
        .unwrap();
    world.collect(anna);
    let anna_side = world.only_contact(anna);
    // The first collect after the reply sets the mark; the gap after it is the app closed.
    world.collect(anna);
    anna.clock.advance(8 * DAY);
    world.collect(anna);
    assert_eq!(status(&world, anna, anna_side), PairingStatus::Waiting);
}

#[test]
fn a_mismatch_ends_both_sides_and_finalizes_nothing() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    let (anna_side, ben_side) = world.pair(anna, ben);
    world
        .block_on(anna.wallet.contact_book().pairing_sas(
            &relays(anna),
            anna_side,
            SasDecision::Mismatch,
        ))
        .unwrap();
    world.collect(ben);

    let anna_view = world
        .block_on(anna.wallet.contact_book().contact(anna_side))
        .unwrap();
    let ben_view = world
        .block_on(ben.wallet.contact_book().contact(ben_side))
        .unwrap();
    assert_eq!(anna_view.ended_reason, Some(PairingEndReason::Mismatch));
    assert_eq!(ben_view.ended_reason, Some(PairingEndReason::PeerMismatch));
    assert!(matches!(
        world.block_on(anna.wallet.contact_book().pairing_sas(
            &relays(anna),
            anna_side,
            SasDecision::Match
        )),
        Err(ContactError::Ended)
    ));
}

#[test]
fn a_pairing_by_hand_with_epicbox_off_ends_paired_on_both_sides() {
    let world = World::new();
    let (anna, ben) = (&world.issuer, &world.payer);
    let off = |party: &Party| ContactRelays {
        mode: RelayMode::EpicboxOff,
        ..relays(party)
    };
    let offer = world
        .block_on(
            anna.wallet
                .contact_book()
                .pairing_invite(&off(anna), invite_request("Anna")),
        )
        .unwrap();
    let answer = world
        .block_on(
            ben.wallet
                .contact_book()
                .pairing_accept(&off(ben), accept(&offer.link, "Ben", true)),
        )
        .unwrap();
    let confirm = match world
        .block_on(
            anna.wallet
                .contact_book()
                .pairing_enter_link(&off(anna), &answer.reply_link),
        )
        .unwrap()
    {
        lepic_wallet_contacts::LinkOutcome::Confirm { link, .. } => link,
        other => panic!("{other:?}"),
    };
    world
        .block_on(
            ben.wallet
                .contact_book()
                .pairing_enter_link(&off(ben), &confirm),
        )
        .unwrap();

    let anna_view = world
        .block_on(anna.wallet.contact_book().contact(offer.contact_id))
        .unwrap();
    let ben_view = world
        .block_on(ben.wallet.contact_book().contact(answer.contact_id))
        .unwrap();
    // No status notice can travel: the reply taken by hand counts as hearing the invitee.
    assert_eq!(anna_view.status, PairingStatus::Paired);
    assert_eq!(ben_view.status, PairingStatus::Paired);
    assert_eq!(ben_view.state, ContactState::Paired);
}

#[test]
fn a_mismatch_while_a_sealed_answer_waits_finalizes_nothing_and_the_send_cancels() {
    use lepic_primitives::amount::Amount;
    use lepic_wallet::selection::SelectionStrategy;
    use lepic_wallet::send::{Delivery, SendRequest};
    let world = World::new();
    let (payer, issuer) = (&world.payer, &world.issuer);
    let (payer_side, _) = world.pair(payer, issuer);
    let sent = world
        .block_on(payer.wallet.send(
            &crate::support::file(),
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(world::ACCOUNT, Amount::new(world::AMOUNT))
            },
            Delivery::Export {
                to: lepic_transport::transport::Location::File(
                    tempfile::tempdir().unwrap().keep().join("s1.tx"),
                ),
            },
        ))
        .unwrap();
    world
        .block_on(payer.wallet.contact_book().contact_post_slate(
            &relays(payer),
            payer_side,
            sent.tx_id,
            None,
        ))
        .unwrap();
    // The receiver answers; its S2 waits in the payer's mailbox.
    world.collect(issuer);
    let slate_id = uuid::Uuid::from_bytes(*sent.slate_id.as_bytes());
    assert!(
        issuer
            .read(|repos| repos.transaction_by_slate(slate_id, lepic_store::TxDirection::Incoming))
            .is_some()
    );
    let receiver_side = world.only_contact(issuer);
    let outbox = issuer.read(|repos| repos.contact_outbox(receiver_side));
    assert!(
        outbox
            .iter()
            .any(|stored| stored.entry.state == lepic_store::ContactOutboxState::Delivered),
        "the answer reached the relay"
    );

    world
        .block_on(payer.wallet.contact_book().pairing_sas(
            &relays(payer),
            payer_side,
            SasDecision::Mismatch,
        ))
        .unwrap();
    world.collect(payer);

    let state = |party: &Party| {
        party
            .read(|repos| repos.transaction(sent.tx_id))
            .unwrap()
            .state
    };
    assert_eq!(
        state(payer),
        lepic_store::TxState::Sent,
        "nothing finalized"
    );
    assert!(world.node.pushed_transactions().is_empty());
    world.block_on(payer.wallet.cancel(sent.tx_id)).unwrap();
    assert_eq!(state(payer), lepic_store::TxState::Cancelled);
}
