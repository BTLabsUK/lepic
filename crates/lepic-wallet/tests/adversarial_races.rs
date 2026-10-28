// SPDX-License-Identifier: Apache-2.0
//! Operations a peer, a relay and the user can start at the same moment on one transaction:
//! finalize against cancel, two finalizes of one S2, two sends from one coin. Each pair runs with
//! the second operation started after a sweep of scheduler yields, so the store writes of the two
//! interleave at every point the engine awaits. Whatever the order, the wallet ends in one
//! consistent state: a posted transaction keeps its inputs spent, a cancelled one was never
//! pushed, nothing is pushed twice and no coin is locked by two transactions.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod send_support;
mod support;

use std::collections::BTreeMap;

use lepic_node::Propagation;
use lepic_primitives::amount::Amount;
use lepic_slate::codec::WireSlate;
use lepic_store::{OutputStatus, ParticipantId, SlateStage, TxId, TxState};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, PEER, Sender, TIP, uuid};
use support::LOOPBACK;

const AMOUNT: u64 = 100_000_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// How many scheduler yields the second operation waits, swept from 0 to this.
const SWEEP: usize = 24;

fn request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

fn to_peer() -> Delivery {
    Delivery::Deliver {
        transport: LOOPBACK,
        to: Destination::new(PEER.to_owned()),
    }
}

async fn after_yields(count: usize) {
    for _ in 0..count {
        tokio::task::yield_now().await;
    }
}

struct Exchange {
    sender: Sender,
    tx_id: TxId,
    slate_id: lepic_slate::model::SlateId,
    s2: WireSlate,
}

fn exchange() -> Exchange {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(), to_peer()))
        .unwrap();
    let (s1, _) = sender.received().unwrap();
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    let s2 = receiver
        .receive(FILE, s1.as_text().unwrap(), None)
        .unwrap()
        .reply;
    Exchange {
        sender,
        tx_id: sent.tx_id,
        slate_id: sent.slate_id,
        s2,
    }
}

impl Exchange {
    fn state(&self) -> TxState {
        self.sender
            .read(|repos| repos.transaction(self.tx_id))
            .unwrap()
            .state
    }

    fn funding_status(&self) -> OutputStatus {
        self.sender
            .outputs()
            .into_iter()
            .find(|output| output.amount.value() == FUNDING)
            .unwrap()
            .status
    }

    /// The single consistent end state, whichever operation won.
    fn assert_consistent(&self, round: usize) {
        let pushed = self.sender.harness.node.pushed_transactions();
        let state = self.state();
        let has_s3 = self
            .sender
            .read(|repos| repos.slate(uuid(self.slate_id), SlateStage::Standard3))
            .is_some();
        let has_context = self
            .sender
            .read(|repos| repos.context(uuid(self.slate_id), ParticipantId(0)))
            .is_some();
        match state {
            TxState::Posted | TxState::Finalized => {
                assert!(has_s3, "round {round}: finalized without its S3");
                assert!(
                    !has_context,
                    "round {round}: finalized but kept its context"
                );
                assert_ne!(
                    self.funding_status(),
                    OutputStatus::Unspent,
                    "round {round}: a finalized send gave its input back"
                );
                // Two finalizes racing may both post; the node takes the same transaction once.
                assert!(
                    pushed.windows(2).all(|pair| pair[0] == pair[1]),
                    "round {round}: two different transactions were pushed for one slate"
                );
            }
            TxState::Cancelled => {
                assert!(
                    pushed.is_empty(),
                    "round {round}: a cancelled send was pushed"
                );
                assert_eq!(
                    self.funding_status(),
                    OutputStatus::Unspent,
                    "round {round}: a cancel left its input locked"
                );
                // A send cancelled after it was finalized keeps its S3: the release watch reads
                // its kernel from it, to confirm the send if the chain mines it after all. It is
                // never pushed again.
                if has_s3 {
                    let reposted = self
                        .sender
                        .harness
                        .block_on(self.sender.wallet.post(self.tx_id, Propagation::Stem));
                    assert!(
                        reposted.is_err(),
                        "round {round}: a cancelled send was posted again"
                    );
                    assert!(
                        self.sender.harness.node.pushed_transactions().is_empty(),
                        "round {round}: a cancelled send was pushed again"
                    );
                }
            }
            other => panic!("round {round}: ended in {other:?}"),
        }
    }
}

#[test]
fn finalize_and_cancel_at_once_end_in_one_consistent_state() {
    let mut outcomes = BTreeMap::new();
    for round in 0..=SWEEP {
        for cancel_first in [false, true] {
            let exchange = exchange();
            let wallet = &exchange.sender.wallet;
            let (finalized, cancelled) = exchange.sender.harness.block_on(async {
                if cancel_first {
                    let (cancelled, finalized) =
                        tokio::join!(wallet.cancel(exchange.tx_id), async {
                            after_yields(round).await;
                            wallet
                                .finalize(LOOPBACK, &exchange.s2, Propagation::Stem)
                                .await
                        });
                    (finalized, cancelled)
                } else {
                    tokio::join!(
                        wallet.finalize(LOOPBACK, &exchange.s2, Propagation::Stem),
                        async {
                            after_yields(round).await;
                            wallet.cancel(exchange.tx_id).await
                        }
                    )
                }
            });
            assert!(
                finalized.is_ok() || cancelled.is_ok(),
                "round {round}: both refused: {finalized:?} {cancelled:?}"
            );
            exchange.assert_consistent(round);
            // A finalize that won must not be undone by a later cancel, nor a cancel by a
            // later finalize.
            let state = exchange.state();
            let again = exchange
                .sender
                .harness
                .block_on(wallet.cancel(exchange.tx_id));
            if state == TxState::Posted {
                assert!(again.is_err(), "round {round}: a posted send was cancelled");
            }
            let refinalized = exchange.sender.harness.block_on(wallet.finalize(
                LOOPBACK,
                &exchange.s2,
                Propagation::Stem,
            ));
            if state == TxState::Cancelled {
                assert!(
                    refinalized.is_err(),
                    "round {round}: a cancelled send was finalized"
                );
            }
            exchange.assert_consistent(round);
            *outcomes.entry(format!("{state:?}")).or_insert(0) += 1;
        }
    }
    eprintln!("end states over the sweep: {outcomes:?}");
}

#[test]
fn two_finalizes_of_one_s2_at_once_push_only_that_transaction() {
    for round in 0..=SWEEP {
        let exchange = exchange();
        let wallet = &exchange.sender.wallet;
        let (first, second) = exchange.sender.harness.block_on(async {
            tokio::join!(
                wallet.finalize(LOOPBACK, &exchange.s2, Propagation::Stem),
                async {
                    after_yields(round).await;
                    wallet
                        .finalize(LOOPBACK, &exchange.s2, Propagation::Stem)
                        .await
                }
            )
        });
        assert!(first.is_ok() || second.is_ok(), "round {round}");
        let pushed = exchange.sender.harness.node.pushed_transactions();
        assert!(!pushed.is_empty(), "round {round}: nothing pushed");
        assert!(
            pushed.windows(2).all(|pair| pair[0] == pair[1]),
            "round {round}: two different transactions were pushed for one slate"
        );
        exchange.assert_consistent(round);
        let entries = exchange.sender.transactions();
        assert_eq!(entries.len(), 1, "round {round}: a second entry appeared");
    }
}

#[test]
fn two_sends_at_once_never_lock_one_coin_twice() {
    for round in 0..=SWEEP {
        let sender = Sender::new();
        let wallet = &sender.wallet;
        let (first, second) = sender.harness.block_on(async {
            tokio::join!(wallet.send(request(), to_peer()), async {
                after_yields(round).await;
                wallet.send(request(), to_peer()).await
            })
        });
        // One coin of 14.6 EPIC pays two sends of 1 EPIC only one at a time.
        let succeeded = usize::from(first.is_ok()) + usize::from(second.is_ok());
        assert_eq!(succeeded, 1, "round {round}: {first:?} {second:?}");
        let funding = sender
            .outputs()
            .into_iter()
            .filter(|output| output.amount.value() == FUNDING)
            .collect::<Vec<_>>();
        assert_eq!(funding.len(), 1);
        assert_eq!(funding[0].status, OutputStatus::Locked, "round {round}");
        let open_sends = sender
            .transactions()
            .into_iter()
            .filter(|stored| stored.entry.state == TxState::Sent)
            .count();
        assert_eq!(open_sends, 1, "round {round}: two sends hold one coin");
    }
}

#[test]
fn cancel_and_send_at_once_never_spend_a_coin_the_other_released() {
    for round in 0..=SWEEP {
        let sender = Sender::new();
        let wallet = &sender.wallet;
        let first = sender
            .harness
            .block_on(wallet.send(request(), to_peer()))
            .unwrap();
        let (cancelled, second) = sender.harness.block_on(async {
            tokio::join!(wallet.cancel(first.tx_id), async {
                after_yields(round).await;
                wallet.send(request(), to_peer()).await
            })
        });
        cancelled.unwrap();
        let states: Vec<_> = sender
            .transactions()
            .into_iter()
            .map(|stored| (stored.id, stored.entry.state))
            .collect();
        let funding = sender
            .outputs()
            .into_iter()
            .find(|output| output.amount.value() == FUNDING)
            .unwrap();
        match second {
            Ok(sent) => {
                assert_eq!(funding.status, OutputStatus::Locked, "round {round}");
                assert_eq!(funding.tx, Some(sent.tx_id), "round {round}: {states:?}");
            }
            Err(_) => {
                assert_eq!(
                    funding.status,
                    OutputStatus::Unspent,
                    "round {round}: {states:?}"
                );
            }
        }
    }
}
