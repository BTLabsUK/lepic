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
use lepic_wallet::contact::{
    AcceptRequest, CollectTrigger, ContactRelays, InviteExpiry, InviteRequest, RelayMode,
};
use tokio::sync::broadcast::Receiver;

use crate::world::{Party, World};

pub const HOUR: Duration = Duration::from_secs(60 * 60);
pub const MINUTE: Duration = Duration::from_secs(60);

pub fn relays(party: &Party) -> ContactRelays {
    ContactRelays {
        epicbox: party.epicbox.clone(),
        built_in: Vec::new(),
        mode: RelayMode::Online,
    }
}

pub fn invite_request(name: &str) -> InviteRequest {
    InviteRequest {
        account: AccountIndex(0),
        name: name.to_owned(),
        kind: ContactKind::Person,
        expiry: InviteExpiry::OneDay,
        offer_words: false,
    }
}

pub fn accept(link: &str, name: &str, by_hand: bool) -> AcceptRequest {
    AcceptRequest {
        link: link.to_owned(),
        account: AccountIndex(0),
        name: name.to_owned(),
        by_hand,
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
                .pairing_invite(&relays(party), invite_request(name)),
        )
        .unwrap()
        .link
    }

    pub fn collect(&self, party: &Party) -> lepic_wallet::contact::CollectReport {
        self.block_on(
            party
                .wallet
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
                    .pairing_accept(&relays(&self.payer), accept(&link, "Ben", false)),
            )
            .unwrap();
        assert!(answered.posted);
        assert_eq!(self.collect(&self.issuer).paired, 1);
        assert_eq!(self.collect(&self.payer).paired, 1);
        let issuer_contact = self.only_contact(&self.issuer);
        assert_eq!(answered.contact_id, self.only_contact(&self.payer));
        (issuer_contact, answered.contact_id)
    }

    pub fn only_contact(&self, party: &Party) -> ContactId {
        let contacts = self.block_on(party.wallet.contacts()).unwrap();
        assert_eq!(contacts.len(), 1, "{contacts:?}");
        contacts[0].contact_id
    }

    pub fn sas(&self, party: &Party, contact: ContactId) -> Vec<&'static str> {
        self.block_on(party.wallet.contact(contact))
            .unwrap()
            .sas
            .unwrap()
            .iter()
            .map(|symbol| symbol.name)
            .collect()
    }
}
