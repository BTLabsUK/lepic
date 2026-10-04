//! Releasing a send the network never took. A send becomes releasable once a refresh at or
//! above `RELEASE_AFTER_BLOCKS` past its finalizing height misses its kernel, and the release
//! asks the node once more before it cancels the send.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
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

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use jiff::{SignedDuration, Timestamp};
use lepic_node::mock::{ChainOutput, MockFailure};
use lepic_node::{LocatedKernel, NodeError, Propagation, RejectionKind};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::Transaction;
use lepic_slate::codec::WireSlate;
use lepic_slate::model::Slate;
use lepic_store::{
    AccountRecord, MemoryStore, OutputRecord, OutputStatus, SlateStage, StoreError, TxId, TxState,
    WalletStore,
};
use lepic_transport::file::FILE;
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::event::TransactionState;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet::release::{RELEASE_AFTER_BLOCKS, ReleaseRefusal};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Clock, Event, Ports, StoreOpener, Wallet, WalletError};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, NEXT_CHILD, PEER, SENDER_MNEMONIC, TIP, context_key, output};
use support::{Harness, LOOPBACK, MemoryStores, TestVault, TestWallet, fixed_time, password};

const AMOUNT: u64 = 100_000_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// The height from which a send finalized at [`TIP`] is releasable.
const RELEASABLE_FROM: u64 = TIP + RELEASE_AFTER_BLOCKS;

/// A clock the test moves forward, so a tip a day of blocks later is plausible.
#[derive(Clone)]
struct MovableClock(Arc<Mutex<Timestamp>>);

impl MovableClock {
    fn advance(&self, by: SignedDuration) {
        let mut now = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.checked_add(by).unwrap();
    }
}

impl Clock for MovableClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A range proof of the right size. The mock chain serves `get_outputs` without proofs, so any
/// one will do for an output that only a refresh asks about.
fn some_proof() -> lepic_crypto::RangeProof {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/primitives/tx_valid_plain_1_in_2_out.json");
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = vector["expected"]["serialized_v2"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect();
    Transaction::decode(&bytes, ProtocolVersion::V2)
        .unwrap()
        .outputs()[0]
        .proof
        .clone()
}

/// The funded `send_file_plain` sender, its coinbase input on the mock chain, with a send to
/// the peer answered.
struct Releasing {
    harness: Harness,
    clock: MovableClock,
    wallet: TestWallet,
    store: MemoryStore,
    tx_id: TxId,
    funding: OutputRecord,
    s2: WireSlate,
}

impl Releasing {
    /// A send the node accepted, now `posted`.
    fn posted() -> Self {
        let releasing = Self::answered();
        releasing.finalize().unwrap();
        assert_eq!(releasing.state(), TxState::Posted);
        releasing
    }

    /// A send the node refused, now `finalized`.
    fn refused() -> Self {
        let releasing = Self::answered();
        releasing.harness.node.fail_next(
            "push_transaction",
            MockFailure::Rejected(RejectionKind::Internal),
        );
        let error = releasing.finalize().unwrap_err();
        assert!(
            matches!(error, FinalizeError::NotPosted { .. }),
            "{error:?}"
        );
        assert_eq!(releasing.state(), TxState::Finalized);
        releasing
    }

    fn answered() -> Self {
        let harness = Harness::new();
        let clock = MovableClock(Arc::new(Mutex::new(fixed_time())));
        let ports: Ports<_, MemoryStores, TestVault> = Ports {
            clock: Arc::new(clock.clone()),
            ..harness.ports(TestVault::default())
        };
        let wallet = Wallet::new(harness.config(Network::Floonet), ports).unwrap();
        harness
            .block_on(wallet.restore(password("sender"), SENDER_MNEMONIC))
            .unwrap();
        harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(TIP));
        support::complete_restore_scan(&harness.runtime, &wallet);
        let seed = lepic_keychain::Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
        let store = harness
            .stores
            .open(&harness.data_dir, context_key(&seed))
            .unwrap();
        let keychain = lepic_keychain::Keychain::from_seed(&seed, Network::Floonet).unwrap();
        let funding = output(&keychain, 0, FUNDING, OutputFeatures::Coinbase);
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: ACCOUNT,
                    label: "default".to_owned(),
                    next_child: NEXT_CHILD,
                })?;
                repos.put_output(&funding)
            })
            .unwrap();
        harness.node.update_chain(|chain| {
            chain.outputs.push(ChainOutput {
                commitment: funding.id.commitment,
                features: OutputFeatures::Coinbase,
                proof: some_proof(),
                height: Height::new(1),
                mmr_index: 1,
                spent: false,
            });
        });

        let sent = harness
            .block_on(wallet.send(
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Deliver {
                    transport: LOOPBACK,
                    to: Destination::new(PEER.to_owned()),
                },
            ))
            .unwrap();
        let peer = harness.peer.lock().unwrap().take().unwrap();
        let s1 = harness
            .block_on(peer.next_envelope())
            .unwrap()
            .unwrap()
            .wire()
            .clone();
        let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
            .receive(FILE, s1.as_text().unwrap(), None)
            .unwrap()
            .reply;
        Self {
            harness,
            clock,
            wallet,
            store,
            tx_id: sent.tx_id,
            funding,
            s2,
        }
    }

    fn finalize(&self) -> Result<lepic_wallet::Finalized, FinalizeError> {
        self.harness
            .block_on(self.wallet.finalize(LOOPBACK, &self.s2, Propagation::Stem))
    }

    fn state(&self) -> TxState {
        self.store
            .read(|repos| Ok::<_, StoreError>(repos.transaction(self.tx_id)?.unwrap().state))
            .unwrap()
    }

    fn outputs(&self) -> Vec<OutputRecord> {
        self.store
            .read(|repos| repos.outputs(ACCOUNT, None))
            .unwrap()
    }

    fn final_slate(&self) -> Slate {
        let stored = self
            .store
            .read(|repos| {
                let entry = repos.transaction(self.tx_id)?.unwrap();
                repos.slate(entry.slate_id.unwrap(), SlateStage::Standard3)
            })
            .unwrap()
            .unwrap();
        send_support::legacy_codecs()
            .decode(&WireSlate::binary(
                lepic_slate::codec::MediaType::JSON,
                stored.bytes,
            ))
            .unwrap()
    }

    /// The node's tip moves to `height`, a day and an hour later by the clock.
    fn chain_reaches(&self, height: u64) {
        self.clock.advance(SignedDuration::from_hours(25));
        self.harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(height));
    }

    /// Refreshes until the tip is confirmed: the first refresh after a long jump holds the tip
    /// as pending, the second at the same tip confirms it.
    fn refresh_twice(&self) {
        self.refresh();
        self.refresh();
    }

    fn refresh(&self) {
        let outcome = self.harness.block_on(self.wallet.refresh()).unwrap();
        assert!(
            matches!(outcome, RefreshOutcome::Refreshed(_)),
            "{outcome:?}"
        );
    }

    fn releasable(&self) -> bool {
        self.harness
            .block_on(self.wallet.transaction_details(self.tx_id))
            .unwrap()
            .releasable
    }

    /// A send whose kernel a refresh at the release height missed. The first refresh after
    /// the jump holds the tip as pending, which a release check does not count.
    fn made_releasable(self) -> Self {
        self.chain_reaches(RELEASABLE_FROM);
        self.refresh();
        assert!(!self.releasable(), "a tip held as pending counts");
        self.refresh();
        assert!(self.releasable());
        self
    }

    fn release(&self) -> Result<(), WalletError> {
        self.harness.block_on(self.wallet.release(self.tx_id))
    }

    fn kernel_at(&self, height: u64) -> LocatedKernel {
        LocatedKernel {
            kernel: self.final_slate().kernel().unwrap(),
            height: Height::new(height),
            mmr_index: 9,
        }
    }

    /// Nothing changed: the send keeps its state, its input stays locked, its change stays.
    fn assert_untouched(&self, state: TxState, outputs: &[OutputRecord]) {
        assert_eq!(self.state(), state);
        assert_eq!(self.outputs(), outputs);
    }
}

fn transaction_events(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
) -> Vec<(TxState, TxState)> {
    let mut changes = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::Transaction(TransactionState { from, to, .. }) = event {
            changes.push((from, to));
        }
    }
    changes
}

#[test]
fn a_posted_send_whose_kernel_stays_missing_is_released() {
    let releasing = Releasing::posted();
    let before = releasing
        .harness
        .block_on(releasing.wallet.transaction_details(releasing.tx_id))
        .unwrap();
    assert_eq!(before.releasable_from, Some(Height::new(RELEASABLE_FROM)));
    assert!(!before.releasable);
    let releasing = releasing.made_releasable();
    let listed = releasing
        .harness
        .block_on(releasing.wallet.transactions(ACCOUNT))
        .unwrap();
    assert!(listed[0].releasable);
    let mut events = releasing.wallet.subscribe();

    releasing.release().unwrap();

    assert_eq!(releasing.state(), TxState::Cancelled);
    let outputs = releasing.outputs();
    assert_eq!(outputs.len(), 1, "the change output is dropped");
    assert_eq!(outputs[0].id, releasing.funding.id);
    assert_eq!(outputs[0].status, OutputStatus::Unspent);
    assert_eq!(
        transaction_events(&mut events),
        vec![(TxState::Posted, TxState::Cancelled)]
    );
    let after = releasing
        .harness
        .block_on(releasing.wallet.transaction_details(releasing.tx_id))
        .unwrap();
    assert_eq!((after.releasable_from, after.releasable), (None, false));
}

#[test]
fn a_finalized_send_the_node_refused_is_released() {
    let releasing = Releasing::refused().made_releasable();
    let mut events = releasing.wallet.subscribe();

    releasing.release().unwrap();

    assert_eq!(releasing.state(), TxState::Cancelled);
    assert_eq!(
        transaction_events(&mut events),
        vec![(TxState::Finalized, TxState::Cancelled)]
    );
}

#[test]
fn refuses_a_release_before_a_refresh_missed_the_kernel_at_the_release_height() {
    let releasing = Releasing::posted();
    let too_early = |error: WalletError| {
        matches!(
            error,
            WalletError::NotReleasable {
                reason: ReleaseRefusal::TooEarly { from },
                ..
            } if from == Height::new(RELEASABLE_FROM)
        )
    };

    let error = releasing.release().unwrap_err();
    assert!(too_early(error));

    // One block short of the release height, a refresh that misses the kernel is not enough.
    releasing.chain_reaches(RELEASABLE_FROM - 1);
    releasing.refresh_twice();
    let outputs = releasing.outputs();
    let error = releasing.release().unwrap_err();
    assert!(too_early(error));

    // The node's tip passing the height is not enough either before a refresh looks.
    releasing
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(RELEASABLE_FROM));
    let error = releasing.release().unwrap_err();
    assert!(too_early(error));
    releasing.assert_untouched(TxState::Posted, &outputs);
}

#[test]
fn a_refresh_that_finds_the_kernel_confirms_the_send_instead() {
    let releasing = Releasing::posted();
    let mined = releasing.kernel_at(TIP + 1);
    releasing
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(mined));
    releasing.chain_reaches(RELEASABLE_FROM);

    releasing.refresh_twice();

    assert_eq!(releasing.state(), TxState::Confirmed);
    let error = releasing.release().unwrap_err();
    assert!(
        matches!(
            error,
            WalletError::NotReleasable {
                reason: ReleaseRefusal::NotPendingSend {
                    state: TxState::Confirmed
                },
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn refuses_a_release_when_the_kernel_reached_the_chain_since() {
    let releasing = Releasing::posted().made_releasable();
    let outputs = releasing.outputs();
    let mined = releasing.kernel_at(RELEASABLE_FROM);
    releasing
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(mined));

    let error = releasing.release().unwrap_err();

    assert!(
        matches!(error, WalletError::OnChain(id) if id == releasing.tx_id),
        "{error:?}"
    );
    releasing.assert_untouched(TxState::Posted, &outputs);
}

#[test]
fn refuses_a_release_when_the_node_pool_holds_the_transaction() {
    let releasing = Releasing::posted().made_releasable();
    let outputs = releasing.outputs();
    let pushed = releasing.harness.node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    releasing
        .harness
        .node
        .update_chain(|chain| chain.pool = pushed);

    let error = releasing.release().unwrap_err();

    assert!(
        matches!(error, WalletError::InPool(id) if id == releasing.tx_id),
        "{error:?}"
    );
    releasing.assert_untouched(TxState::Posted, &outputs);
}

#[test]
fn refuses_a_release_when_the_node_cannot_be_asked() {
    let releasing = Releasing::posted().made_releasable();
    let outputs = releasing.outputs();
    for method in ["get_tip", "get_kernel", "get_unconfirmed_transactions"] {
        releasing
            .harness
            .node
            .fail_next(method, MockFailure::Unreachable);

        let error = releasing.release().unwrap_err();

        assert!(
            matches!(error, WalletError::Node(NodeError::Connect(_))),
            "{method}: {error:?}"
        );
        releasing.assert_untouched(TxState::Posted, &outputs);
    }
    releasing.release().unwrap();
    assert_eq!(releasing.state(), TxState::Cancelled);
}

#[test]
fn refuses_to_release_a_send_that_is_not_finalized_or_posted() {
    let releasing = Releasing::answered();

    let error = releasing.release().unwrap_err();

    assert!(
        matches!(
            error,
            WalletError::NotReleasable {
                tx_id,
                reason: ReleaseRefusal::NotPendingSend {
                    state: TxState::Sent
                },
            } if tx_id == releasing.tx_id
        ),
        "{error:?}"
    );
    let unknown = releasing
        .harness
        .block_on(releasing.wallet.release(TxId(99)))
        .unwrap_err();
    assert!(
        matches!(unknown, WalletError::UnknownTransaction(TxId(99))),
        "{unknown:?}"
    );
}
