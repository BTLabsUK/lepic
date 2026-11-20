// SPDX-License-Identifier: Apache-2.0
//! No notice affects the engine (ADR 0067) but one: every kind from every source leaves every
//! transaction's state and the balance as they were, and a source the table refuses is refused.
//! The exception is a `declined` from its receiver of a send not answered yet: the send never
//! happened, so it is erased and its inputs unlocked.

use lepic_crypto::Commitment;
use lepic_slate::model::SlateId;
use lepic_store::{TxId, VERDICT_LEN};
use lepic_wallet::event::Balance;
use lepic_wallet::notice::Notice;
use lepic_wallet::{NoticeFrom, Taken, accepts};

use super::*;

fn every_kind(slate_id: SlateId) -> Vec<Notice> {
    vec![
        Notice::Posted {
            slate_id,
            excess: Commitment::commit_value(1).unwrap(),
        },
        Notice::Cancelled { slate_id },
        Notice::Declined {
            slate_id,
            reason: None,
        },
        Notice::Withdrawn { slate_id },
        Notice::PairFinished,
        Notice::PairMatch {
            sas: [1; VERDICT_LEN],
        },
        Notice::PairMismatch {
            sas: [2; VERDICT_LEN],
        },
        Notice::Unpaired,
        Notice::App {
            id: uuid::Uuid::from_u128(1),
            body: vec![1],
        },
    ]
}

type Snapshot = (Vec<(TxId, TxState, Option<uuid::Uuid>)>, Balance);

fn snapshot(party: &Party) -> Snapshot {
    let transactions = party
        .read(|repos| repos.transactions(ACCOUNT))
        .into_iter()
        .map(|tx| (tx.id, tx.entry.state, tx.entry.slate_id))
        .collect();
    (transactions, party.wallet.balance(ACCOUNT).unwrap())
}

/// Takes every kind for every slate the party holds from every source.
fn take_everything(world: &World, party: &Party, contact: ContactId) {
    let (transactions, _) = snapshot(party);
    for (tx_id, _, slate) in transactions {
        let slate_id = SlateId::from_bytes(slate.unwrap().into_bytes());
        for notice in every_kind(slate_id) {
            for from in [
                NoticeFrom::AddressKey(tx_id),
                NoticeFrom::ReplyKey(slate_id),
                NoticeFrom::Pairing(contact),
                NoticeFrom::PrivatePairing(contact),
            ] {
                let accepted = accepts(&notice, &from);
                let taken = world
                    .block_on(party.wallet.take_notice(notice.clone(), from))
                    .unwrap();
                assert_eq!(
                    taken == Taken::Refused,
                    !accepted,
                    "{notice:?} from {from:?} was {taken:?}"
                );
            }
        }
    }
}

#[test]
fn no_notice_from_any_source_changes_a_transaction_or_the_balance() {
    let world = World::new();
    let (shop_side, ben_side) = world.pair_for_invoices(ContactKind::Exchange);
    // A paid contact invoice, posted by its issuer.
    let issued = world.invoice_contact(shop_side, "table");
    world.collect(&world.payer);
    world.pay_contact(&issued);
    world.collect(&world.issuer);
    // The invoice payment is posted, not confirmed: its inputs stay locked.
    let (_, paid) = snapshot(&world.payer);
    // A payment to the same contact through its mailbox, not answered yet: its inputs are locked.
    world.payer.fund(10, world::FUNDING);
    let sent = send_through_mailbox(&world, &relays(&world.payer), ben_side);
    let payer = snapshot(&world.payer);
    let issuer = snapshot(&world.issuer);
    assert_eq!(payer.0.len(), 2);
    assert_ne!(payer.1.locked, paid.locked);

    take_everything(&world, &world.payer, ben_side);
    take_everything(&world, &world.issuer, shop_side);

    // The unanswered payment was declined by its receiver: it is gone and its inputs are free.
    let (transactions, balance) = snapshot(&world.payer);
    let kept: Vec<_> = payer.0.into_iter().filter(|(id, ..)| *id != sent).collect();
    assert_eq!(transactions, kept);
    assert_eq!(balance.locked, paid.locked);
    assert_eq!(balance.awaiting_finalization, paid.awaiting_finalization);
    // The invoice its payer declined is only marked.
    assert_eq!(snapshot(&world.issuer), issuer);
}
