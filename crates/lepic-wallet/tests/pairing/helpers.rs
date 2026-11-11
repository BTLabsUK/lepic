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
use lepic_store::{AccountIndex, ContactId};
use lepic_wallet::Event;
use lepic_wallet_contacts::{
    AcceptRequest, CollectTrigger, ContactRelays, InviteExpiry, InviteRequest, PairingClass,
    RelayMode, WalletContacts,
};
use tokio::sync::broadcast::Receiver;

use crate::world::{Party, World};

pub const HOUR: Duration = Duration::from_secs(60 * 60);
pub const MINUTE: Duration = Duration::from_secs(60);

pub fn relays(party: &Party) -> ContactRelays {
    ContactRelays {
        epicbox: party.epicbox.clone(),
        meeting: Vec::new(),
        mode: RelayMode::Online,
    }
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
