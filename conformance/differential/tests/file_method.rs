//! Differential tests of the file method: an upstream `epic-wallet` v4.0.2 and a LEPIC wallet
//! exchange slate files on one in-process test chain, in both directions, for the standard and
//! invoice flows, in the V2 and V3 shapes, with and without TTL, payment proof and messages.
//!
//! Each case runs twice on fresh chains with the same story: once with LEPIC as the subject, and
//! once with an upstream wallet from the same mnemonic in its place. At every checkpoint both
//! the upstream peer and the subject must report in the LEPIC run what they report in the
//! reference run: the same balance in every category, the same outputs and statuses, and the
//! same transaction state, LEPIC's mapped through `docs/compat/states.md`. The mined
//! transaction must have the same inputs, outputs and kernel in both runs.

// Test code may unwrap, panic and use plain arithmetic and indexing (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use support::view::differences;
use support::{AMOUNT, Offer, Pay, SlateShape, SubjectKind, TTL_BLOCKS, Who, World};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Standard,
    Invoice,
}

/// One combination. The initiator sends in the standard flow and issues in the invoice flow.
#[derive(Debug, Clone, Copy)]
struct Case {
    flow: Flow,
    initiator: Who,
    ttl: bool,
    payment_proof: bool,
    messages: bool,
    peer_writes: SlateShape,
}

impl Case {
    fn name(&self) -> String {
        let flow = match self.flow {
            Flow::Standard => "standard",
            Flow::Invoice => "invoice",
        };
        let direction = match self.initiator {
            Who::Subject => "lepic-initiates",
            Who::Peer => "upstream-initiates",
        };
        let mut name = format!("{flow}-{direction}");
        if self.ttl {
            name.push_str("-ttl");
        }
        if self.payment_proof {
            name.push_str("-proof");
        }
        if self.messages {
            name.push_str("-messages");
        }
        if self.peer_writes == SlateShape::V3 {
            name.push_str("-upstream-writes-v3");
        }
        name
    }
}

/// Every combination the file method allows. Upstream has no payment proof on invoices. The V3
/// shape without TTL or payment proof comes only from wallets that always write V3, so it is
/// tried as the shape the upstream peer writes.
fn cases(flow: Flow, initiator: Who) -> Vec<Case> {
    let mut cases = Vec::new();
    let proofs: &[bool] = match flow {
        Flow::Standard => &[false, true],
        Flow::Invoice => &[false],
    };
    for &ttl in &[false, true] {
        for &payment_proof in proofs {
            for &messages in &[false, true] {
                let shapes: &[SlateShape] = if ttl || payment_proof {
                    &[SlateShape::FileMethod]
                } else {
                    &[SlateShape::FileMethod, SlateShape::V3]
                };
                for &peer_writes in shapes {
                    cases.push(Case {
                        flow,
                        initiator,
                        ttl,
                        payment_proof,
                        messages,
                        peer_writes,
                    });
                }
            }
        }
    }
    cases
}

fn other(who: Who) -> Who {
    match who {
        Who::Peer => Who::Subject,
        Who::Subject => Who::Peer,
    }
}

fn message(case: &Case, who: Who) -> Option<String> {
    case.messages.then(|| match who {
        Who::Peer => "from the upstream wallet".to_owned(),
        Who::Subject => "from the subject wallet".to_owned(),
    })
}

/// Runs one case and returns the world after the last checkpoint.
fn run(case: &Case, kind: SubjectKind) -> World {
    let mut world = World::start(&case.name(), kind, case.peer_writes);
    let initiator = case.initiator;
    let responder = other(initiator);
    let ttl_blocks = case.ttl.then_some(TTL_BLOCKS);
    let (first, second) = match case.flow {
        Flow::Standard => (world.file("case.tx"), world.file("case.tx.response")),
        Flow::Invoice => (world.file("case.invoice"), world.file("case.paid")),
    };

    let slate_id = match case.flow {
        Flow::Standard => {
            let offer = Offer {
                amount: AMOUNT,
                ttl_blocks,
                message: message(case, initiator),
                proof_to: case.payment_proof.then(|| world.proof_address(responder)),
            };
            world.party(initiator).send(&first, &offer)
        }
        Flow::Invoice => {
            let note = message(case, initiator);
            world
                .party(initiator)
                .issue_invoice(&first, AMOUNT, note.as_deref())
        }
    };
    world.checkpoint("initiated", &slate_id);

    let responded = match case.flow {
        Flow::Standard => {
            let note = message(case, responder);
            world
                .party(responder)
                .receive(&first, &second, note.as_deref())
        }
        Flow::Invoice => {
            let pay = Pay {
                amount: AMOUNT,
                ttl_blocks,
                message: message(case, responder),
            };
            world.party(responder).pay_invoice(&first, &second, &pay)
        }
    };
    assert_eq!(
        responded,
        slate_id,
        "{}: the reply keeps the slate id",
        case.name()
    );
    world.checkpoint("responded", &slate_id);

    match case.flow {
        Flow::Standard => world.party(initiator).finalize_and_post(&second),
        Flow::Invoice => world.party(initiator).finalize_invoice_and_post(&second),
    }
    assert_eq!(world.pool_len(), 1, "{}: the finalizer posted", case.name());
    world.checkpoint("posted", &slate_id);

    world.mine(1);
    world.checkpoint("mined", &slate_id);
    world.mine(9);
    world.checkpoint("spendable", &slate_id);

    let mined = world.mined.first().cloned().unwrap();
    let height = world.kernel_height(&mined);
    assert!(
        height.is_some(),
        "{}: the chain holds the kernel",
        case.name()
    );
    world
}

/// The file the subject wrote, and whether the subject created the slate in it.
fn subject_file(case: &Case) -> (&'static str, bool) {
    match (case.flow, case.initiator) {
        (Flow::Standard, Who::Subject) => ("case.tx", true),
        (Flow::Standard, Who::Peer) => ("case.tx.response", false),
        (Flow::Invoice, Who::Subject) => ("case.invoice", true),
        (Flow::Invoice, Who::Peer) => ("case.paid", false),
    }
}

/// The shape of a slate file: its header and its top-level keys, which tell V2 from V3.
fn file_shape(world: &World, case: &Case) -> (Vec<Option<u64>>, Vec<String>) {
    let (file, created) = subject_file(case);
    let text = std::fs::read_to_string(world.file(file)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let header = |key: &str| {
        value
            .pointer(&format!("/version_info/{key}"))
            .and_then(serde_json::Value::as_u64)
    };
    let mut version = vec![header("version"), header("orig_version")];
    // A new slate records the block header version of the creator's network at the tip, and
    // the test chain changes header version far earlier than floonet, where LEPIC runs. A reply
    // carries the header it received, so there the whole header is compared.
    if !created {
        version.push(header("block_header_version"));
    }
    let keys = value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    (version, keys)
}

/// The peer, when it recorded a kernel, recorded the one the chain mined.
fn check_kernel(world: &World) -> Option<String> {
    let mined = support::hex(&world.mined[0].body.kernels[0].excess.0);
    let recorded = world
        .checkpoints
        .last()?
        .peer
        .tx
        .as_ref()?
        .kernel_excess
        .clone()??;
    (recorded != mined).then(|| format!("peer recorded kernel {recorded}, the chain mined {mined}"))
}

fn check(case: &Case) -> Vec<String> {
    let name = case.name();
    let reference = run(case, SubjectKind::Reference);
    let lepic = run(case, SubjectKind::Lepic);
    let mut found = Vec::new();
    for (observed, expected) in lepic.checkpoints.iter().zip(&reference.checkpoints) {
        // The initiator records the transaction at once, the responder once it has replied.
        if observed.label != "initiated"
            && (observed.peer.tx.is_none() || observed.subject.tx.is_none())
        {
            found.push(format!("{name} {}: a wallet has no entry", observed.label));
        }
        for difference in differences(&observed.peer, &expected.peer) {
            found.push(format!("{name} {}: peer {difference}", observed.label));
        }
        for difference in differences(&observed.subject, &expected.subject) {
            found.push(format!("{name} {}: subject {difference}", observed.label));
        }
    }
    if lepic.mined_shapes() != reference.mined_shapes() {
        found.push(format!(
            "{name}: mined {:?}, reference {:?}",
            lepic.mined_shapes(),
            reference.mined_shapes()
        ));
    }
    if lepic.height() != reference.height() {
        found.push(format!("{name}: chain heights differ"));
    }
    let (shape, reference_shape) = (file_shape(&lepic, case), file_shape(&reference, case));
    if shape != reference_shape {
        found.push(format!(
            "{name}: subject wrote {shape:?}, reference {reference_shape:?}"
        ));
    }
    found.extend(check_kernel(&lepic).map(|d| format!("{name}: {d}")));
    found
}

fn check_all(flow: Flow, initiator: Who) {
    let mut found = Vec::new();
    let all = cases(flow, initiator);
    for case in &all {
        found.extend(check(case));
    }
    assert!(
        found.is_empty(),
        "{} differences across {} cases:\n{}",
        found.len(),
        all.len(),
        found.join("\n")
    );
}

#[test]
fn lepic_sends_to_upstream_over_files() {
    check_all(Flow::Standard, Who::Subject);
}

#[test]
fn upstream_sends_to_lepic_over_files() {
    check_all(Flow::Standard, Who::Peer);
}

#[test]
fn lepic_invoices_upstream_over_files() {
    check_all(Flow::Invoice, Who::Subject);
}

#[test]
fn upstream_invoices_lepic_over_files() {
    check_all(Flow::Invoice, Who::Peer);
}

mod comparison {
    use lepic_store::{TxDirection, TxState};

    use super::support::view::{BalanceView, PartyView, TxView, differences, upstream_states};

    fn view(states: Vec<(String, bool)>, spendable: u64) -> PartyView {
        PartyView {
            balance: BalanceView {
                total: spendable,
                spendable,
                awaiting_confirmation: 0,
                awaiting_finalization: 0,
                immature: 0,
                locked: 0,
            },
            outputs: Vec::new(),
            tx: Some(TxView {
                upstream_states: states,
                amount_credited: 0,
                amount_debited: 5,
                fee: Some(1),
                ttl_cutoff_height: None,
                stored_tx: None,
                messages: None,
                kernel_excess: None,
            }),
        }
    }

    fn upstream(tx_type: &str, confirmed: bool) -> Vec<(String, bool)> {
        vec![(tx_type.to_owned(), confirmed)]
    }

    #[test]
    fn accepts_a_lepic_state_that_maps_to_the_reference_state() {
        let posted = upstream_states(TxDirection::Outgoing, TxState::Posted);
        assert!(
            differences(
                &view(posted.clone(), 4),
                &view(upstream("TxSentCreated", false), 4)
            )
            .is_empty()
        );
        assert!(
            differences(&view(posted, 4), &view(upstream("TxSentMempool", false), 4)).is_empty()
        );
    }

    #[test]
    fn reports_a_state_the_mapping_does_not_allow() {
        let sent = upstream_states(TxDirection::Outgoing, TxState::Sent);
        assert_eq!(
            differences(&view(sent, 4), &view(upstream("TxSent", true), 4)).len(),
            1
        );
    }

    #[test]
    fn reports_a_balance_difference() {
        let sent = upstream_states(TxDirection::Outgoing, TxState::Sent);
        assert_eq!(
            differences(&view(sent, 4), &view(upstream("TxSentCreated", false), 5)).len(),
            1
        );
    }

    #[test]
    fn maps_every_state_a_direction_can_reach() {
        let outgoing = [
            TxState::Sent,
            TxState::Finalized,
            TxState::Posted,
            TxState::Confirmed,
            TxState::Cancelled,
            TxState::Expired,
        ];
        let incoming = [
            TxState::Received,
            TxState::Finalized,
            TxState::Posted,
            TxState::Confirmed,
            TxState::Cancelled,
            TxState::Expired,
        ];
        for state in outgoing {
            assert!(
                !upstream_states(TxDirection::Outgoing, state).is_empty(),
                "{state:?}"
            );
        }
        for state in incoming {
            assert!(
                !upstream_states(TxDirection::Incoming, state).is_empty(),
                "{state:?}"
            );
        }
    }
}
