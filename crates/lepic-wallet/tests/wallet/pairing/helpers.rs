// SPDX-License-Identifier: Apache-2.0
//! Pairing two wallets of the test world, shared by the pairing and sealed slate tests.

// Test helpers may unwrap, index and panic (docs/rules.md).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::Duration;

use lepic_contact::ContactKind;
use lepic_epicbox::sessions::PushedConfig;
use lepic_epicbox::{
    Domain, EpicboxAddress, MuxOptions, Network as RelayNetwork, RelayEndpoint, Security,
};
use lepic_methods::epicbox::Epicbox;
use lepic_store::{AccountIndex, ContactId, MailClass, StoredNativeOutbox};
use lepic_wallet::Event;
use lepic_wallet_contacts::{
    AcceptRequest, CollectTrigger, ContactRelays, InviteExpiry, InviteRequest, MailboxList,
    PairingClass, RelayMode, WalletContacts,
};
use tokio::sync::broadcast::Receiver;

use crate::epicbox_world::{self as world, Party, World};

pub const HOUR: Duration = Duration::from_secs(60 * 60);
pub const MINUTE: Duration = Duration::from_secs(60);
/// The group of the contact sessions [`hold_acks`] configures.
pub const ACK_GROUP: &str = "contacts";

/// The outbox rows of the payments and messages `party` keeps for its contact `contact`,
/// oldest first: the rows a host lists, without the pairing mail of [`mail_rows`].
pub fn contact_rows(party: &Party, contact: ContactId) -> Vec<StoredNativeOutbox> {
    all_contact_rows(party, contact)
        .into_iter()
        .filter(|row| row.entry.stage.is_some())
        .collect()
}

/// The pairing mail and notices `party` keeps for its contact `contact`, oldest first: rows
/// that carry no stage.
pub fn mail_rows(party: &Party, contact: ContactId) -> Vec<StoredNativeOutbox> {
    all_contact_rows(party, contact)
        .into_iter()
        .filter(|row| row.entry.stage.is_none())
        .collect()
}

fn all_contact_rows(party: &Party, contact: ContactId) -> Vec<StoredNativeOutbox> {
    let from: String = contact.0.iter().map(|byte| format!("{byte:02x}")).collect();
    party.read(|repos| repos.native_outbox_from(&format!("contact:{from}")))
}

pub fn relays(party: &Party) -> ContactRelays {
    ContactRelays::new(party.epicbox.clone(), RelayMode::Online)
}

/// `relays` with `added` listed after its own relay.
pub fn adding(relays: ContactRelays, added: Vec<RelayEndpoint>) -> ContactRelays {
    let own = relays.epicbox.settings().endpoint.clone();
    let list = MailboxList::new(vec![own], added, Vec::new()).unwrap();
    relays.with_mailboxes(list)
}

/// `relays` on `epicbox`, whose relay is then its only one.
pub fn on(epicbox: Epicbox, relays: ContactRelays) -> ContactRelays {
    ContactRelays {
        tor: relays.tor,
        ..ContactRelays::new(epicbox, relays.mode)
    }
}

/// The party's relays with `relay2.test:80` as its own relay and no other: a list without
/// relay.test.
pub fn only_relay2(world: &World, party: &Party) -> ContactRelays {
    let mut settings = world::settings();
    settings.endpoint = RelayEndpoint::new(
        Domain::parse("relay2.test").unwrap(),
        Some(80),
        Security::Plain,
    );
    on(
        Epicbox::new(settings, RelayNetwork::Floonet, world.relay.connector()),
        relays(party),
    )
}

/// The rows `party` watches its contact `contact`'s mailboxes on, as (relay, class), sorted.
pub fn watched(party: &Party, contact: ContactId) -> Vec<(String, MailClass)> {
    let key_ref = format!(
        "contact:{}",
        contact
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let mut rows: Vec<(String, MailClass)> = party
        .read(|repos| repos.watch_set())
        .into_iter()
        .filter(|row| row.key_ref == key_ref)
        .map(|row| (row.relay, row.class))
        .collect();
    rows.sort_by_key(|(relay, class)| (relay.clone(), format!("{class:?}")));
    rows
}

pub fn row(relay: &str, class: MailClass) -> (String, MailClass) {
    (relay.to_owned(), class)
}

pub fn invite_request(name: &str) -> InviteRequest {
    InviteRequest {
        account: AccountIndex(0),
        name: name.to_owned(),
        kind: ContactKind::Person,
        expiry: InviteExpiry::OneDay,
        home_relay: None,
        class: PairingClass::Contact,
        expect_address: None,
    }
}

pub fn accept(link: &str, name: &str, by_hand: bool) -> AcceptRequest {
    AcceptRequest {
        link: link.to_owned(),
        account: AccountIndex(0),
        name: name.to_owned(),
        by_hand,
        class: PairingClass::Contact,
        expect_address: None,
    }
}

pub fn events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok()).collect()
}

/// Has the party's contact sessions started from now on hold each acknowledgement for an hour,
/// so a test can lose it with the socket.
pub fn hold_acks(party: &Party) {
    party.epicbox.pushed().clear();
    party.epicbox.pushed().set_contacts(Some(PushedConfig {
        group: ACK_GROUP.to_owned(),
        options: MuxOptions::default().with_ack_window(HOUR),
    }));
}

/// The relay closes every socket before `party`'s held acknowledgements leave, and returns the
/// wallet opened again on its store; the caller closes the old one.
pub fn lose_acks_and_reopen(world: &World, party: &Party) -> Party {
    // No task runs between the two: the sessions stop with the acknowledgements unsent.
    world.relay.disconnect_all();
    party.epicbox.pushed().clear();
    party.reopened(&world.node, &world.relay, &world.runtime)
}

/// Waits until the relay holds nothing for `mailbox`.
pub fn wait_gone(world: &World, mailbox: &EpicboxAddress) {
    world.block_on(world.within(world.relay.wait_until(|relay| relay.pending(mailbox) == 0)));
}

/// Runs `post` and waits until the party's contact session on `relay` has queued what it
/// brought.
pub fn queued_after(world: &World, party: &Party, relay: &str, post: impl FnOnce()) {
    let session = party
        .epicbox
        .pushed()
        .get(relay, ACK_GROUP)
        .expect("a contacts session on the relay");
    let mut queued = session.queued();
    post();
    world.block_on(world.within(queued.changed())).unwrap();
}

impl World {
    pub fn invite(&self, party: &Party, name: &str) -> String {
        self.block_on(
            party
                .wallet
                .contact_book()
                .pairing_invite(&relays(party), invite_request(name)),
        )
        .unwrap()
        .link
    }

    pub fn collect(&self, party: &Party) -> lepic_wallet_contacts::CollectReport {
        self.block_on(
            party
                .wallet
                .contact_book()
                .contacts_collect(&relays(party), CollectTrigger::Open),
        )
        .unwrap()
    }

    /// The issuer invites, the payer answers through the relay, and both collect.
    pub fn pair_by_link(&self) -> (ContactId, ContactId) {
        let link = self.invite(&self.issuer, "Anna");
        let answered = self
            .block_on(
                self.payer
                    .wallet
                    .contact_book()
                    .pairing_accept(&relays(&self.payer), accept(&link, "Ben", false)),
            )
            .unwrap();
        assert!(answered.posted);
        assert_eq!(self.collect(&self.issuer).paired, 1);
        assert_eq!(self.collect(&self.payer).paired, 1);
        // The inviter hears that the invitee finished.
        self.collect(&self.issuer);
        let issuer_contact = self.only_contact(&self.issuer);
        assert_eq!(answered.contact_id, self.only_contact(&self.payer));
        (issuer_contact, answered.contact_id)
    }

    /// `inviter` invites by link, `invitee` answers, and both collect. Returns the two new
    /// contact ids, the inviter's first.
    pub fn pair(&self, inviter: &Party, invitee: &Party) -> (ContactId, ContactId) {
        let before = self.contact_ids(inviter);
        let link = self.invite(inviter, "Anna");
        let answered = self
            .block_on(
                invitee
                    .wallet
                    .contact_book()
                    .pairing_accept(&relays(invitee), accept(&link, "Ben", false)),
            )
            .unwrap();
        assert_eq!(self.collect(inviter).paired, 1);
        assert_eq!(self.collect(invitee).paired, 1);
        // The inviter hears that the invitee finished.
        self.collect(inviter);
        let ours = self
            .contact_ids(inviter)
            .into_iter()
            .find(|id| !before.contains(id))
            .unwrap();
        (ours, answered.contact_id)
    }

    /// The party's one paired contact other than `old`.
    pub fn only_new(&self, party: &Party, old: ContactId) -> ContactId {
        let others: Vec<ContactId> = self
            .contact_ids(party)
            .into_iter()
            .filter(|id| *id != old)
            .collect();
        assert_eq!(others.len(), 1, "{others:?}");
        others[0]
    }

    pub fn contact_ids(&self, party: &Party) -> Vec<ContactId> {
        self.block_on(party.wallet.contact_book().contacts())
            .unwrap()
            .into_iter()
            .map(|view| view.contact_id)
            .collect()
    }

    pub fn only_contact(&self, party: &Party) -> ContactId {
        let contacts = self
            .block_on(party.wallet.contact_book().contacts())
            .unwrap();
        assert_eq!(contacts.len(), 1, "{contacts:?}");
        contacts[0].contact_id
    }

    pub fn sas(&self, party: &Party, contact: ContactId) -> Vec<&'static str> {
        self.block_on(party.wallet.contact_book().contact(contact))
            .unwrap()
            .sas
            .unwrap()
            .iter()
            .map(|symbol| symbol.name)
            .collect()
    }
}
