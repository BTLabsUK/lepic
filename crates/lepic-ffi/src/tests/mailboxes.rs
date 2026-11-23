// SPDX-License-Identifier: Apache-2.0
//! The mailbox list through the binding: the app sets it from its shipped list and the user's
//! changes, each change hands the user's changes back to store, a mailbox is tested before it is
//! added, and an epic1 payment goes through the list or through the mailboxes the user gives.

use super::contact::{EPIC, RELAY, World};
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::types::{
    ContactRelayMode, Epic1NotReadReason, MailboxChanges, MailboxOrigin, MailboxProbeStep,
};
use crate::api::wallet::EpicWallet;

use ContactRelayMode::Online;

/// The hosts of the list in use with their origins.
fn listed(wallet: &EpicWallet) -> Vec<(String, MailboxOrigin)> {
    wallet
        .mailbox_list()
        .unwrap()
        .into_iter()
        .map(|mailbox| (mailbox.host, mailbox.origin))
        .collect()
}

fn hosts(hosts: &[&str]) -> Vec<String> {
    hosts.iter().map(|host| (*host).to_owned()).collect()
}

fn changes(added: &[&str], removed: &[&str]) -> MailboxChanges {
    MailboxChanges {
        added: hosts(added),
        removed: hosts(removed),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_app_sets_the_list_and_stores_what_each_change_hands_back() {
    let mut world = World::new();
    let anna = world.wallet().await;
    // Before the app sets it, the list is the wallet's own relay, and nothing changes it.
    assert_eq!(listed(&anna), [(RELAY.to_owned(), MailboxOrigin::Shipped)]);
    assert_eq!(
        kind(anna.mailbox_remove(RELAY.to_owned())),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(anna.mailbox_add("b.example.org".to_owned(), true).await),
        WalletErrorKind::InvalidArgument
    );

    anna.mailbox_set(
        hosts(&[RELAY, "second.example.org"]),
        hosts(&["Third.Example.org:5443"]),
        hosts(&["second.example.org"]),
    )
    .unwrap();
    let kept = vec![
        (RELAY.to_owned(), MailboxOrigin::Shipped),
        ("third.example.org:5443".to_owned(), MailboxOrigin::Added),
    ];
    assert_eq!(listed(&anna), kept);

    // A refused list changes nothing.
    for (bad, refused) in [
        ("not a host", WalletErrorKind::MailboxInvalid),
        ("fourth.example.org:0", WalletErrorKind::MailboxInvalid),
        ("127.0.0.1", WalletErrorKind::MailboxNotPublic),
        ("relay.lan", WalletErrorKind::MailboxNotPublic),
    ] {
        let set = anna.mailbox_set(hosts(&[RELAY]), hosts(&[bad]), Vec::new());
        let error = set.unwrap_err();
        assert_eq!(error.kind, refused, "{bad}");
        assert!(error.message.starts_with(bad), "{bad}: {}", error.message);
        assert_eq!(listed(&anna), kept, "{bad}");
    }
    let many: Vec<String> = (0..16).map(|n| format!("m{n}.example.org")).collect();
    assert_eq!(
        kind(anna.mailbox_set(hosts(&[RELAY]), many.clone(), Vec::new())),
        WalletErrorKind::MailboxListFull
    );
    assert_eq!(
        kind(anna.mailbox_set(hosts(&[RELAY]), Vec::new(), hosts(&[RELAY]))),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(listed(&anna), kept);
    anna.mailbox_set(Vec::new(), many, Vec::new()).unwrap();
    assert_eq!(anna.mailbox_list().unwrap().len(), 16);
    assert_eq!(
        kind(anna.mailbox_add("m16.example.org".to_owned(), true).await),
        WalletErrorKind::MailboxListFull
    );

    // Each change hands back the user's changes to the shipped list.
    anna.mailbox_set(
        hosts(&[RELAY, "second.example.org"]),
        hosts(&["third.example.org:5443"]),
        hosts(&["second.example.org"]),
    )
    .unwrap();
    let removed = anna
        .mailbox_remove("third.example.org:5443".to_owned())
        .unwrap();
    assert!(removed.removed);
    assert_eq!(removed.changes, changes(&[], &["second.example.org"]));
    let absent = anna.mailbox_remove("gone.example.org".to_owned()).unwrap();
    assert!(!absent.removed);
    assert_eq!(absent.changes, removed.changes);
    assert_eq!(
        kind(anna.mailbox_remove(RELAY.to_owned())),
        WalletErrorKind::LastMailbox
    );
    assert_eq!(
        kind(anna.mailbox_remove("localhost".to_owned())),
        WalletErrorKind::MailboxNotPublic
    );
    assert_eq!(listed(&anna), [(RELAY.to_owned(), MailboxOrigin::Shipped)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mailbox_that_fails_its_test_is_added_only_anyway() {
    let mut world = World::new();
    let anna = world.wallet().await;
    anna.mailbox_set(hosts(&[RELAY]), Vec::new(), Vec::new())
        .unwrap();

    let probe = anna
        .mailbox_probe("Mailbox.Example.org:443".to_owned())
        .await
        .unwrap();
    assert_eq!(probe.host, "mailbox.example.org");
    assert_eq!(probe.tls, MailboxProbeStep::Passed);
    assert_eq!(probe.greeting, MailboxProbeStep::Passed);
    assert_eq!(probe.push, MailboxProbeStep::Passed);
    assert_eq!(probe.failure, None);
    assert!(probe.passed);
    assert_eq!(listed(&anna).len(), 1, "a test changes nothing");
    let added = anna
        .mailbox_add("mailbox.example.org".to_owned(), false)
        .await
        .unwrap();
    assert!(added.added);
    assert!(added.probe.passed);
    assert_eq!(added.changes, changes(&["mailbox.example.org"], &[]));

    // A mailbox without push fails its test: it is added only on the user's choice.
    world.relay.offer_mux(false);
    let refused = anna
        .mailbox_add("plain.example.org".to_owned(), false)
        .await
        .unwrap();
    assert!(!refused.added);
    assert!(!refused.probe.passed);
    assert_eq!(refused.probe.push, MailboxProbeStep::Failed);
    assert!(refused.probe.failure.is_some(), "{:?}", refused.probe);
    assert_eq!(refused.changes, added.changes);
    assert_eq!(listed(&anna).len(), 2);
    let anyway = anna
        .mailbox_add("plain.example.org".to_owned(), true)
        .await
        .unwrap();
    assert!(anyway.added);
    assert!(!anyway.probe.passed);
    assert_eq!(
        anyway.changes,
        changes(&["mailbox.example.org", "plain.example.org"], &[])
    );
    assert_eq!(
        listed(&anna).last(),
        Some(&("plain.example.org".to_owned(), MailboxOrigin::Added))
    );

    // A host on this device or a private network is refused, anyway or not, and never tested.
    for bad in ["localhost", "127.0.0.1:8443", "relay.lan"] {
        assert_eq!(
            kind(anna.mailbox_add(bad.to_owned(), true).await),
            WalletErrorKind::MailboxNotPublic,
            "{bad}"
        );
        assert_eq!(
            kind(anna.mailbox_probe(bad.to_owned()).await),
            WalletErrorKind::MailboxNotPublic,
            "{bad}"
        );
    }
    assert_eq!(listed(&anna).len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payer_sharing_no_mailbox_pays_only_through_a_mailbox_it_gives() {
    let mut world = World::new();
    world.relay.set_relays_apart(true);
    let anna = world.wallet().await;
    let ben = world.funded().await;
    // Ben's list keeps none of its shipped mailboxes.
    ben.mailbox_set(
        hosts(&[RELAY]),
        hosts(&["mine.example.org"]),
        hosts(&[RELAY]),
    )
    .unwrap();
    let link = anna
        .epic1_link_make(Some(EPIC), Some("coffee".to_owned()))
        .await
        .unwrap();
    let before = ben.transactions().await.unwrap().len();

    let refused = ben
        .epic1_pay(
            link.link.clone(),
            None,
            1,
            None,
            None,
            Vec::new(),
            Online,
            false,
        )
        .await;
    let error = refused.unwrap_err();
    assert_eq!(error.kind, WalletErrorKind::NoSharedMailbox);
    assert!(error.message.contains(RELAY), "{}", error.message);
    assert_eq!(ben.transactions().await.unwrap().len(), before);
    assert_eq!(
        kind(
            ben.epic1_pay(
                link.link.clone(),
                None,
                1,
                None,
                None,
                hosts(&["relay.lan"]),
                Online,
                false
            )
            .await
        ),
        WalletErrorKind::MailboxNotPublic
    );

    // Given the payee's mailbox, the payment goes there alone; an empty message clears the one
    // the link asks.
    let paid = ben
        .epic1_pay(
            link.link,
            None,
            1,
            Some("  ".to_owned()),
            None,
            hosts(&[RELAY]),
            Online,
            false,
        )
        .await
        .unwrap();
    assert_eq!(paid.posted, Some(0));
    assert_eq!(world.relay.received_on(RELAY, "PostSlate"), 1);
    assert_eq!(world.relay.received_on("mine.example.org", "PostSlate"), 0);
    let sent = ben.transaction(paid.tx_id).await.unwrap();
    assert!(
        sent.messages.iter().all(|message| message.text != "coffee"),
        "{:?}",
        sent.messages
    );

    // The payee's restore takes the payment and names no mailbox it could not read.
    let restored = anna.epic1_restore(Online).await.unwrap();
    assert_eq!(restored.taken, 1);
    assert!(restored.not_read.is_empty(), "{:?}", restored.not_read);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_names_each_mailbox_it_could_not_read() {
    let mut world = World::new();
    world.relay.set_relays_apart(true);
    let anna = world.wallet().await;
    anna.mailbox_set(hosts(&[RELAY, "down.example.org"]), Vec::new(), Vec::new())
        .unwrap();
    world.relay.set_domain_down("down.example.org", true);
    let restored = anna.epic1_restore(Online).await.unwrap();
    assert_eq!(restored.taken, 0);
    assert_eq!(restored.not_read.len(), 1, "{:?}", restored.not_read);
    assert!(
        restored.not_read[0].host.starts_with("down.example.org"),
        "{:?}",
        restored.not_read
    );
    assert_eq!(
        restored.not_read[0].reason,
        Epic1NotReadReason::NotAnswering
    );

    // With no mailbox read, the restore fails.
    let mut world = World::new();
    let ben = world.wallet().await;
    world.relay.offer_mux(false);
    assert_eq!(
        kind(ben.epic1_restore(Online).await),
        WalletErrorKind::TransportFailed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_read_counts_the_mailboxes_it_names_and_uses_none() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;
    let address = anna.epic1_address().await.unwrap().address;
    let plain = ben
        .epic1_link_read(format!("epic:{address}"))
        .await
        .unwrap();
    assert_eq!(plain.ignored_mailboxes, 0);
    let named = ben
        .epic1_link_read(format!(
            "epic:{address}?mailbox=a.example.org&mailbox=b.example.org"
        ))
        .await
        .unwrap();
    assert_eq!(named.ignored_mailboxes, 2);
    assert_eq!(named.address, address);
}
