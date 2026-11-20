// SPDX-License-Identifier: Apache-2.0
//! Epic1 links and sealed text through the binding, between wallets on the mock relay: a link
//! issued, read and paid, the payment taken and answered by the payee, the answer finalized by
//! the payer's delivery tick, and sealed text between contacts.

use lepic_epicbox::mock_relay::Unanswered;
use lepic_wallet_contacts::WalletContacts as _;

use super::contact::{EPIC, RELAY, World, pair, raised};
use super::kind;
use crate::api::contact::sealed_file_extension;
use crate::api::epic1::ListenerSocket;
use crate::api::error::WalletErrorKind;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{Chain, ContactRelayMode, DeliveryState, WalletEventKind};
use crate::api::wallet::EpicWallet;

use ContactRelayMode::{Offline, Online};

/// A relay apart from [`RELAY`], served by the same mock relay.
const SECOND: &str = "second.example.org";

/// One tick of the wallet's delivery layer, as the app's wake runs it.
async fn wake(wallet: &EpicWallet) {
    wallet.delivery_wake(false).await.unwrap();
}

/// How many mailboxes another socket took over from `wallet`'s push sessions.
fn replaced(wallet: &EpicWallet) -> usize {
    let epicbox = wallet.session().epicbox().unwrap();
    let pushed = epicbox.pushed();
    pushed
        .infos()
        .iter()
        .filter_map(|info| pushed.get(&info.relay, &info.group))
        .map(|session| session.replaced_keys().len())
        .sum()
}

/// Two installs of one phrase on the epic1 mailbox: the one that woke last holds it. A wake
/// without `open` leaves it there; a wake with `open` takes it back at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wake_on_open_takes_the_mailbox_back_and_a_pull_leaves_it() {
    let mut world = World::new();
    let anna = world.wallet().await;
    anna.delivery_wake(true).await.unwrap();
    let phrase = anna.mnemonic("password".to_owned()).await.unwrap();
    let twin = world.wallet_with(Some(phrase)).await;
    twin.delivery_wake(true).await.unwrap();
    assert!(super::eventually(|| replaced(&anna) > 0).await);
    let taken = replaced(&anna);

    let attaches = world.relay.received("Attach");
    anna.delivery_wake(false).await.unwrap();
    assert_eq!(world.relay.received("Attach"), attaches);
    assert_eq!(replaced(&anna), taken);

    anna.delivery_wake(true).await.unwrap();
    assert!(world.relay.received("Attach") > attaches);
    assert_eq!(replaced(&anna), 0);
    assert!(super::eventually(|| replaced(&twin) == taken).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epic1_at_the_listeners_is_off_by_default_and_saved_per_socket() {
    let mut world = World::new();
    let config = world.config(RELAY);
    let store = AppSecretStore::in_memory();
    let wallet = world.wallet().await;
    assert!(!wallet.epic1_at_listener(ListenerSocket::Web));
    assert!(!wallet.epic1_at_listener(ListenerSocket::Onion));
    wallet
        .set_epic1_at_listener(ListenerSocket::Onion, true)
        .unwrap();
    assert!(wallet.epic1_at_listener(ListenerSocket::Onion));
    assert!(!wallet.epic1_at_listener(ListenerSocket::Web));
    // Setting it twice either way is safe.
    wallet
        .set_epic1_at_listener(ListenerSocket::Onion, true)
        .unwrap();
    wallet
        .set_epic1_at_listener(ListenerSocket::Web, false)
        .unwrap();
    assert!(wallet.epic1_at_listener(ListenerSocket::Onion));
    wallet
        .set_epic1_at_listener(ListenerSocket::Onion, false)
        .unwrap();
    assert!(!wallet.epic1_at_listener(ListenerSocket::Onion));
    // Each wallet keeps its own.
    wallet
        .set_epic1_at_listener(ListenerSocket::Web, true)
        .unwrap();
    let other = EpicWallet::create(
        &world.runtime,
        config,
        &store,
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    assert!(!other.epic1_at_listener(ListenerSocket::Web));
    assert!(wallet.epic1_at_listener(ListenerSocket::Web));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
async fn a_link_paid_is_answered_by_the_payee_and_finalized_by_the_payers_collect() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.funded().await;

    let address = anna.epic1_address().await.unwrap();
    let link = anna
        .epic1_link_make(Some(EPIC), Some("coffee".to_owned()))
        .await
        .unwrap();
    assert_eq!(link.address, address.address);

    let read = ben.epic1_link_read(link.link.clone()).await.unwrap();
    assert_eq!(read.address, link.address);
    assert_eq!(read.amount, Some(EPIC));
    assert_eq!(read.message.as_deref(), Some("coffee"));
    // A link without entries goes to the payee's mailbox: no host to show.
    assert_eq!(read.http_host, None);
    let elsewhere = format!("epic:{}?http=shop.example", link.address);
    let read = ben.epic1_link_read(elsewhere).await.unwrap();
    assert_eq!(read.http_host.as_deref(), Some("shop.example"));

    let paid = ben
        .epic1_pay(link.link.clone(), None, 1, None, None, Vec::new(), Online)
        .await
        .unwrap();
    assert_eq!(paid.address, link.address);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);
    assert_eq!(paid.attempts[0].error, None);
    // Paid without a message, the payment carries the one the link asks.
    let sent = ben.transaction(paid.tx_id).await.unwrap();
    assert!(
        sent.messages.iter().any(|message| message.text == "coffee"),
        "{:?}",
        sent.messages
    );
    // The payment is stored under its slate id, so a caller can find it again.
    let book = ben.session().engine_wallet().contact_book();
    let slate_id = lepic_wallet::event::SlateId::parse(&paid.slate_id).unwrap();
    let stored = book.epic1_payment(slate_id).await.unwrap().unwrap();
    assert_eq!(stored.tx_id.0, paid.tx_id);
    assert_eq!(stored.address, link.address);
    assert_eq!(stored.posted, Some(0));
    assert!(stored.attempts.is_empty());
    let other = lepic_wallet::event::SlateId::from_bytes([4; 16]);
    assert_eq!(book.epic1_payment(other).await.unwrap(), None);

    // The payee takes the payment and posts its answer in the same tick.
    wake(&anna).await;
    let answers = anna.epic1_answers().await.unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].slate_id, paid.slate_id);
    assert!(answers[0].posted);
    assert_eq!(world.chain.pushed_count(), 0);
    // The payee's receive says it came to the epic1 address; the payer's send does not.
    let received = anna.transactions().await.unwrap();
    let received = received
        .iter()
        .find(|transaction| transaction.slate_id.as_deref() == Some(paid.slate_id.as_str()))
        .unwrap();
    assert!(received.received_at_epic1);
    assert!(!ben.transaction(paid.tx_id).await.unwrap().received_at_epic1);
    // The payer's tick finalizes.
    wake(&ben).await;
    assert_eq!(world.chain.pushed_count(), 1);

    // The payment is answered once.
    wake(&anna).await;
    assert_eq!(anna.epic1_answers().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_link_and_the_address_carry_their_qr_text() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.wallet().await;

    // The public address: a bare link, its QR text in upper case.
    let public = anna.epic1_address().await.unwrap();
    assert!(public.address.starts_with("tepic1"));
    assert_eq!(public.link, format!("epic:{}", public.address));
    assert_eq!(public.qr, public.link.to_ascii_uppercase());
    // The same call gives the same address.
    assert_eq!(anna.epic1_address().await.unwrap(), public);
    // A reader takes the upper-case text as the same address.
    let read = ben.epic1_link_read(public.qr.clone()).await.unwrap();
    assert_eq!(read.address, public.address);

    // A link that asks an amount keeps lower case and leaves the message out.
    let link = anna
        .epic1_link_make(Some(EPIC), Some("coffee".to_owned()))
        .await
        .unwrap();
    assert_eq!(link.qr, format!("epic:{}?amount=1", link.address));
    assert!(link.link.contains("coffee"));
    let read = ben.epic1_link_read(link.qr).await.unwrap();
    assert_eq!(read.address, link.address);
    assert_eq!(read.amount, Some(EPIC));
    assert_eq!(read.message, None);

    // A link that asks nothing is the bare address.
    let any = anna.epic1_link_make(None, None).await.unwrap();
    assert_eq!(any, public);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_change_is_an_event_and_in_the_details() {
    let mut world = World::new();
    let anna = world.wallet().await;
    // The payer gives up waiting for the relay's answer after a second.
    let mut config = world.config(RELAY);
    config.tuning.epicbox.response_timeout_s = 1;
    let ben = EpicWallet::create(
        &world.runtime,
        config,
        &AppSecretStore::in_memory(),
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let phrase = ben.mnemonic("password".to_owned()).await.unwrap();
    world
        .chain
        .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
        .unwrap();
    world.chain.set_height(20);
    ben.session().scan_to_tip().await;
    let link = anna.epic1_link_make(Some(EPIC), None).await.unwrap();
    let mut events = ben.session().subscribe();

    // The relay stores the post but its answer is lost: the payer cannot tell it arrived.
    world.relay.set_unanswered(Unanswered::PostAnswer, true);
    let paid = ben
        .epic1_pay(link.link, None, 1, None, None, Vec::new(), Online)
        .await
        .unwrap();
    world.relay.set_unanswered(Unanswered::PostAnswer, false);
    assert_eq!(paid.uncertain, Some(0));

    let changes: Vec<_> = raised(&mut events)
        .iter()
        .filter_map(crate::session::wallet_event)
        .filter(|event| event.kind == WalletEventKind::DeliveryChanged)
        .collect();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].slate_id.as_deref(), Some(paid.slate_id.as_str()));
    assert_eq!(changes[0].delivery_state, Some(DeliveryState::Uncertain));
    // The route of a link without entries: the payee's mailbox, which the attempt names too.
    assert_eq!(paid.attempts.len(), 1);
    assert!(paid.attempts[0].uncertain);
    assert_eq!(
        changes[0].relay.as_deref(),
        Some(paid.attempts[0].host.as_str())
    );

    let details = ben.transaction(paid.tx_id).await.unwrap();
    let delivery = details.delivery.unwrap();
    assert_eq!(delivery.state, DeliveryState::Uncertain);
    assert!(delivery.updated_at_ms > 0);
    // Nothing went to the node yet.
    assert_eq!(details.post, None);
    // The list carries the same record.
    let listed = ben.transactions().await.unwrap();
    let listed = listed
        .iter()
        .find(|transaction| transaction.tx_id == paid.tx_id)
        .unwrap();
    assert_eq!(
        listed.delivery.as_ref().map(|view| view.state),
        Some(DeliveryState::Uncertain)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_link_requests_are_refused() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.funded().await;

    let printed = anna.epic1_link_make(None, None).await.unwrap();

    // A link that asks no amount is paid only with one.
    assert_eq!(
        ben.epic1_link_read(printed.link.clone())
            .await
            .unwrap()
            .amount,
        None
    );
    assert_eq!(
        kind(
            ben.epic1_pay(
                printed.link.clone(),
                None,
                1,
                None,
                None,
                Vec::new(),
                Online
            )
            .await
        ),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(
            ben.epic1_pay(printed.link, Some(0), 1, None, None, Vec::new(), Online)
                .await
        ),
        WalletErrorKind::InvalidArgument
    );

    assert_eq!(
        kind(anna.epic1_link_make(Some(0), None).await),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(ben.epic1_link_read("not a link".to_owned()).await),
        WalletErrorKind::NotAnEpic1Link
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contacts_seal_epicsealed() {
    let mut world = World::new();
    let carl = world.funded().await;
    let dana = world.wallet().await;
    let (carl_side, _) = pair(&carl, &dana).await;
    let slate = carl.create_send_slate(EPIC, 1, None, None).await.unwrap();
    let sealed = carl
        .contact_seal_slate(carl_side, slate.tx_id, None)
        .await
        .unwrap();
    assert!(sealed.starts_with("BEGINEPICSEALED."));
    assert_eq!(sealed_file_extension(sealed.clone()).unwrap(), "epicsealed");
    let opened = dana.epictx_open(sealed).await.unwrap();
    assert!(!opened.native);
    assert!(opened.slate_json.contains(&slate.slate_id));

    assert_eq!(
        kind(dana.epictx_open("not sealed".to_owned()).await),
        WalletErrorKind::InvalidPairingText
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payment_through_the_session_is_posted_to_every_relay_of_the_list() {
    let mut world = World::new();
    world.relay.set_relays_apart(true);
    let anna = world.wallet().await;
    let ben = world.funded().await;
    ben.mailbox_set(vec![RELAY.to_owned()], vec![SECOND.to_owned()], Vec::new())
        .unwrap();
    let link = anna.epic1_link_make(Some(EPIC), None).await.unwrap();

    let paid = ben
        .epic1_pay(link.link, None, 1, None, None, Vec::new(), Online)
        .await
        .unwrap();
    assert_eq!(paid.posted, Some(0));
    assert_eq!(world.relay.received_on(RELAY, "PostSlate"), 1);
    assert_eq!(world.relay.received_on(SECOND, "PostSlate"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mailbox_list_shows_which_mailbox_offered_push() {
    let mut world = World::new();
    let anna = world.wallet().await;
    anna.mailbox_set(
        vec![RELAY.to_owned()],
        vec!["b.example.org".to_owned(), "a.example.org:5443".to_owned()],
        Vec::new(),
    )
    .unwrap();
    let names = |wallet: &EpicWallet| -> Vec<(String, Option<bool>)> {
        wallet
            .mailbox_list()
            .unwrap()
            .into_iter()
            .map(|mailbox| (mailbox.host, mailbox.push))
            .collect()
    };
    // No socket greeted them yet: not known, and no loop runs.
    assert_eq!(
        names(&anna),
        [
            (RELAY.to_owned(), None),
            ("b.example.org".to_owned(), None),
            ("a.example.org:5443".to_owned(), None),
        ]
    );
    // The loop's first tick greets each mailbox of the list, and each offers mux/1.
    anna.set_delivery(Online).unwrap();
    let greeted = [
        (RELAY.to_owned(), Some(true)),
        ("b.example.org".to_owned(), Some(true)),
        ("a.example.org:5443".to_owned(), Some(true)),
    ];
    assert!(
        super::eventually(|| names(&anna) == greeted).await,
        "{:?}",
        anna.mailbox_list()
    );
    // A mailbox taken out leaves the list.
    let removed = anna
        .mailbox_remove("a.example.org:5443".to_owned())
        .unwrap();
    assert_eq!(removed.changes.added, ["b.example.org"]);
    assert_eq!(
        names(&anna),
        [
            (RELAY.to_owned(), Some(true)),
            ("b.example.org".to_owned(), Some(true)),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_is_posted_over_the_sessions_transport_and_not_with_the_relay_off() {
    let mut world = World::new();
    world.relay.set_relays_apart(true);
    let anna = world.wallet().await;
    anna.mailbox_set(vec![RELAY.to_owned()], vec![SECOND.to_owned()], Vec::new())
        .unwrap();
    // The payer's only mailbox is one the payee added.
    let config = world.config(SECOND);
    let ben = EpicWallet::create(
        &world.runtime,
        config,
        &AppSecretStore::in_memory(),
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let phrase = ben.mnemonic("password".to_owned()).await.unwrap();
    world
        .chain
        .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
        .unwrap();
    world.chain.set_height(20);
    ben.session().scan_to_tip().await;
    let link = anna.epic1_link_make(Some(EPIC), None).await.unwrap();
    let paid = ben
        .epic1_pay(link.link, None, 1, None, None, Vec::new(), Online)
        .await
        .unwrap();
    assert_eq!(paid.posted, Some(0));
    assert_eq!(world.relay.received_on(SECOND, "PostSlate"), 1);

    // With the relay off, nothing is read and nothing posted.
    let reads =
        || world.relay.received_on(SECOND, "Subscribe") + world.relay.received_on(SECOND, "Attach");
    let read_before = reads();
    anna.set_delivery(Offline).unwrap();
    assert_eq!(
        kind(anna.delivery_wake(false).await),
        WalletErrorKind::ContactsOffline
    );
    assert!(anna.epic1_answers().await.unwrap().is_empty());
    assert_eq!(world.relay.received_on(SECOND, "PostSlate"), 1);
    assert_eq!(reads(), read_before);
    assert_eq!(world.relay.received_on(RELAY, "PostSlate"), 0);

    // Online, the payee reads the payment on the mailbox it added and answers there and on each
    // other mailbox of its list, in the loop's first tick or in the wake, whichever runs first.
    anna.set_delivery(Online).unwrap();
    wake(&anna).await;
    assert!(reads() > read_before);
    let answers = anna.epic1_answers().await.unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].slate_id, paid.slate_id);
    assert!(answers[0].posted);
    assert!(
        answers[0].mailbox.contains(SECOND),
        "{}",
        answers[0].mailbox
    );
    assert_eq!(world.relay.received_on(SECOND, "PostSlate"), 2);
    assert_eq!(world.relay.received_on(RELAY, "PostSlate"), 1);
    // The payer's tick on its own relay finalizes.
    wake(&ben).await;
    assert_eq!(world.chain.pushed_count(), 1);
}
