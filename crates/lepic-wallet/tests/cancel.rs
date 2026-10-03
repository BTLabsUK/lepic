//! Cancelling a send, before and after its slate was delivered: inputs become spendable again,
//! change and private context are dropped, and a second cancel changes nothing.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod send_support;
mod support;

use lepic_keychain::Seed;
use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_slate::model::SlateId;
use lepic_store::{OutboxStatus, OutputStatus, TxId, TxState, WalletStore};
use lepic_transport::transport::Destination;
use lepic_wallet::WalletError;
use lepic_wallet::event::{Event, TransactionState};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use lepic_wallet::state::InvalidTransition;
use lepic_wallet::{ReceiveRequest, StoreOpener};
use send_support::{ACCOUNT, PEER, Sender, context_key, uuid};
use support::{Harness, LOOPBACK, TestVault, password};
use tokio::sync::broadcast::error::TryRecvError;

fn request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(100_000_000))
    }
}

fn to(destination: &str) -> Delivery {
    Delivery::Deliver {
        transport: LOOPBACK,
        to: Destination::new(destination.to_owned()),
    }
}

/// The wallet is back where it was before the send, apart from the cancelled entry and the
/// output key the change used.
fn assert_cancelled(sender: &Sender, slate_id: SlateId) {
    let transactions = sender.transactions();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].entry.state, TxState::Cancelled);
    let outputs = sender.outputs();
    assert_eq!(outputs.len(), 1, "the change output is dropped");
    assert_eq!(outputs[0].status, OutputStatus::Unspent);
    assert!(!sender.has_sender_context(uuid(slate_id)));
    assert!(sender.outbox(OutboxStatus::Pending).is_empty());
}

fn assert_cancel_event(events: &mut tokio::sync::broadcast::Receiver<Event>, tx_id: TxId) {
    assert_eq!(
        events.try_recv(),
        Ok(Event::Transaction(TransactionState {
            tx_id,
            from: TxState::Sent,
            to: TxState::Cancelled,
        }))
    );
    assert_eq!(events.try_recv(), Err(TryRecvError::Empty));
}

#[test]
fn cancel_before_delivery_releases_the_inputs_and_drops_the_pending_delivery() {
    let sender = Sender::new();
    let error = sender
        .harness
        .block_on(sender.wallet.send(request(), to("nobody")))
        .unwrap_err();
    let SendError::Undelivered {
        tx_id, slate_id, ..
    } = error
    else {
        panic!("{error:?}");
    };
    assert_eq!(sender.outbox(OutboxStatus::Pending).len(), 1);

    let mut events = sender.wallet.subscribe();
    sender
        .harness
        .block_on(sender.wallet.cancel(tx_id))
        .unwrap();
    assert_cancelled(&sender, slate_id);
    assert_cancel_event(&mut events, tx_id);
}

#[test]
fn cancel_after_delivery_releases_the_inputs_for_the_next_send() {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(), to(PEER)))
        .unwrap();
    let mut events = sender.wallet.subscribe();
    sender
        .harness
        .block_on(sender.wallet.cancel(sent.tx_id))
        .unwrap();
    assert_cancelled(&sender, sent.slate_id);
    assert_cancel_event(&mut events, sent.tx_id);

    let next = sender
        .harness
        .block_on(sender.wallet.send(request(), to(PEER)))
        .unwrap();
    assert_ne!(next.tx_id, sent.tx_id);
    assert!(
        sender
            .outputs()
            .iter()
            .any(|output| output.status == OutputStatus::Locked && output.tx == Some(next.tx_id))
    );
}

#[test]
fn cancelling_twice_changes_nothing_the_second_time() {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(), to(PEER)))
        .unwrap();
    sender
        .harness
        .block_on(sender.wallet.cancel(sent.tx_id))
        .unwrap();
    let after_first = (sender.transactions(), sender.outputs());
    let mut events = sender.wallet.subscribe();
    sender
        .harness
        .block_on(sender.wallet.cancel(sent.tx_id))
        .unwrap();
    assert_eq!((sender.transactions(), sender.outputs()), after_first);
    assert_eq!(events.try_recv(), Err(TryRecvError::Empty));
}

#[test]
fn rejects_cancelling_a_confirmed_or_unknown_transaction() {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(), to(PEER)))
        .unwrap();
    sender
        .store
        .write(|repos| {
            let mut entry = repos.transaction(sent.tx_id)?.unwrap();
            entry.state = TxState::Confirmed;
            repos.update_transaction(sent.tx_id, &entry)
        })
        .unwrap();
    let outputs = sender.outputs();
    let error = sender
        .harness
        .block_on(sender.wallet.cancel(sent.tx_id))
        .unwrap_err();
    assert!(
        matches!(
            error,
            WalletError::Transition(InvalidTransition {
                from: TxState::Confirmed,
                to: TxState::Cancelled,
            })
        ),
        "{error:?}"
    );
    assert_eq!(sender.outputs(), outputs);
    assert!(sender.has_sender_context(uuid(sent.slate_id)));

    let unknown = sender
        .harness
        .block_on(sender.wallet.cancel(TxId(99)))
        .unwrap_err();
    assert!(
        matches!(unknown, WalletError::UnknownTransaction(TxId(99))),
        "{unknown:?}"
    );
}

#[test]
fn cancel_of_a_received_transaction_drops_its_output_and_context() {
    const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal \
        winner thank year wave sausage worth useful legal winner thank year wave sausage worth \
        title";
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(), to(PEER)))
        .unwrap();
    let (wire, _) = sender.received().unwrap();

    let harness = Harness::new();
    let receiver = harness.wallet_with(harness.config(Network::Floonet), TestVault::default());
    harness
        .block_on(receiver.restore(password("receiver"), RECEIVER_MNEMONIC))
        .unwrap();
    let received = harness
        .block_on(receiver.receive(LOOPBACK, &wire, ReceiveRequest::default()))
        .unwrap();
    let store = harness
        .stores
        .open(
            &harness.data_dir,
            context_key(&Seed::from_mnemonic(RECEIVER_MNEMONIC).unwrap()),
        )
        .unwrap();
    let read = |repos: &dyn lepic_store::Repositories| -> Result<_, lepic_store::StoreError> {
        Ok((
            repos.transaction(received.tx_id)?.unwrap().state,
            repos.outputs(ACCOUNT, None)?,
            repos
                .context(uuid(sent.slate_id), lepic_store::ParticipantId(1))?
                .is_some(),
        ))
    };
    let (state, outputs, has_context) = store.read(read).unwrap();
    assert_eq!(state, TxState::Received);
    assert_eq!(outputs.len(), 1);
    assert!(has_context);

    harness.block_on(receiver.cancel(received.tx_id)).unwrap();
    let (state, outputs, has_context) = store.read(read).unwrap();
    assert_eq!(state, TxState::Cancelled);
    assert!(outputs.is_empty());
    assert!(!has_context);
}
