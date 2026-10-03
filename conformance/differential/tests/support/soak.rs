//! One soak iteration: the scenario of a seed, run once with LEPIC as the subject and once
//! with the reference wallet in its place, then compared.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::compare::{SubjectFile, compare};
use super::faults::CrashPoint;
use super::lepic::{Recovery, SendRetry};
use super::scenario::{Flow, Scenario, Step, Stop};
use super::{Offer, Pay, SubjectKind, Who, World};

/// Faults the tests plant in the LEPIC run to show the soak reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sabotage {
    None,
    /// LEPIC's balance at the last checkpoint is reported one freeman higher than it is.
    MisreportedBalance,
    /// After a send stopped with its slate stored, the retry sends again instead of delivering
    /// the stored slate, so the step runs twice.
    SendTwice,
}

/// What a run did besides the checkpoints it recorded.
pub struct Run {
    pub world: World,
    /// How the stopped step ended, when the run stopped LEPIC.
    pub recovery: Option<Recovery>,
}

/// The outcome of one seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub scenario: Scenario,
    pub recovery: Option<Recovery>,
    /// Empty when the runs agree.
    pub differences: Vec<String>,
}

/// Runs the scenario of `seed` and compares. A run that panics, which the harness does on any
/// step a wallet refuses, counts as one difference carrying the panic message.
pub fn check_seed(seed: u64, sabotage: Sabotage) -> Outcome {
    check(Scenario::generate(seed), sabotage)
}

pub fn check(scenario: Scenario, sabotage: Sabotage) -> Outcome {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let reference = run(&scenario, SubjectKind::Reference, Sabotage::None);
        let lepic = run(&scenario, SubjectKind::Lepic, sabotage);
        compare_runs(&scenario, &lepic, &reference.world)
    }));
    match result {
        Ok((recovery, differences)) => Outcome {
            scenario,
            recovery,
            differences,
        },
        Err(panic) => {
            let message = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "a run panicked".to_owned());
            Outcome {
                scenario,
                recovery: None,
                differences: vec![format!("run panicked: {message}")],
            }
        }
    }
}

/// Compares a LEPIC run with the reference run of the same scenario.
pub fn compare_runs(
    scenario: &Scenario,
    lepic: &Run,
    reference: &World,
) -> (Option<Recovery>, Vec<String>) {
    let name = format!("seed {}", scenario.seed);
    let restarted = lepic.recovery == Some(Recovery::Refused);
    let differences = compare(
        &name,
        &lepic.world,
        reference,
        subject_file(scenario),
        restarted,
    );
    (lepic.recovery, differences)
}

/// The file the subject wrote, and whether the subject created the slate in it.
fn subject_file(scenario: &Scenario) -> SubjectFile {
    let (name, created) = match (scenario.flow, scenario.initiator) {
        (Flow::Standard, Who::Subject) => ("case.tx", true),
        (Flow::Standard, Who::Peer) => ("case.tx.response", false),
        (Flow::Invoice, Who::Subject) => ("case.invoice", true),
        (Flow::Invoice, Who::Peer) => ("case.paid", false),
    };
    SubjectFile { name, created }
}

fn message(scenario: &Scenario, who: Who) -> Option<String> {
    if who == scenario.initiator {
        scenario.initiator_message.clone()
    } else {
        scenario.responder_message.clone()
    }
}

/// The scenario's stop, in the LEPIC run only, at `step`.
fn stop_at(scenario: &Scenario, kind: SubjectKind, step: Step) -> Option<CrashPoint> {
    match (kind, scenario.stop) {
        (SubjectKind::Lepic, Some(Stop { step: at, point })) if at == step => Some(point),
        _ => None,
    }
}

/// Runs the scenario's story and returns the world after the last checkpoint.
pub fn run(scenario: &Scenario, kind: SubjectKind, sabotage: Sabotage) -> Run {
    let label = format!("soak-{}-{kind:?}", scenario.seed);
    let mut world = World::start_with(&label, kind, scenario.peer_writes, &scenario.setup);
    let initiator = scenario.initiator;
    let responder = scenario.responder();
    let mut recovery = None;
    let (first, second) = match scenario.flow {
        Flow::Standard => (world.file("case.tx"), world.file("case.tx.response")),
        Flow::Invoice => (world.file("case.invoice"), world.file("case.paid")),
    };

    let offer = match scenario.flow {
        Flow::Standard => Some(Offer {
            amount: scenario.amount,
            ttl_blocks: scenario.ttl_blocks,
            message: message(scenario, initiator),
            proof_to: scenario
                .payment_proof
                .then(|| world.proof_address(responder)),
            spend: scenario.spend,
        }),
        Flow::Invoice => None,
    };
    let mut slate_id = match (&offer, stop_at(scenario, kind, Step::Send)) {
        (Some(offer), Some(point)) => {
            let retry = match sabotage {
                Sabotage::SendTwice => SendRetry::SendAgain,
                Sabotage::None | Sabotage::MisreportedBalance => SendRetry::ResendWaiting,
            };
            let lepic = world.lepic().unwrap();
            let (slate_id, recovered) = lepic.send_stopped(&first, offer, point, retry);
            recovery = Some(recovered);
            slate_id
        }
        (Some(offer), None) => world.party(initiator).send(&first, offer),
        (None, _) => {
            let note = message(scenario, initiator);
            world
                .party(initiator)
                .issue_invoice(&first, scenario.amount, note.as_deref())
        }
    };
    world.checkpoint("initiated", &slate_id);

    let note = message(scenario, responder);
    let responded = match (&offer, stop_at(scenario, kind, Step::Receive)) {
        (Some(offer), Some(point)) => {
            let lepic = world.lepic().unwrap();
            let (received, recovered) =
                lepic.receive_stopped(&first, &second, note.as_deref(), point);
            recovery = Some(recovered);
            match received {
                Some(received) => received,
                None => {
                    // LEPIC cannot reply to the slate any more, so the sender cancels it and
                    // sends again.
                    world.party(initiator).cancel(&slate_id);
                    slate_id = world.party(initiator).send(&first, offer);
                    world
                        .party(responder)
                        .receive(&first, &second, note.as_deref())
                }
            }
        }
        (Some(_), None) => world
            .party(responder)
            .receive(&first, &second, note.as_deref()),
        (None, _) => {
            let pay = Pay {
                amount: scenario.amount,
                ttl_blocks: scenario.ttl_blocks,
                message: note,
                spend: scenario.spend,
            };
            world.party(responder).pay_invoice(&first, &second, &pay)
        }
    };
    assert_eq!(responded, slate_id, "the reply keeps the slate id");
    world.checkpoint("responded", &slate_id);

    match (scenario.flow, stop_at(scenario, kind, Step::Finalize)) {
        (Flow::Standard, Some(point)) => {
            let lepic = world.lepic().unwrap();
            recovery = Some(lepic.finalize_stopped(&second, point));
        }
        (Flow::Standard, None) => world.party(initiator).finalize_and_post(&second),
        (Flow::Invoice, _) => world.party(initiator).finalize_invoice_and_post(&second),
    }
    assert_eq!(world.pool_len(), 1, "the finalizer posted once");
    world.checkpoint("posted", &slate_id);

    world.mine(1);
    world.checkpoint("mined", &slate_id);
    world.mine(9);
    world.checkpoint("spendable", &slate_id);

    if sabotage == Sabotage::MisreportedBalance
        && let Some(last) = world.checkpoints.last_mut()
    {
        last.subject.balance.spendable += 1;
    }
    let mined = world.mined.first().cloned().unwrap();
    assert!(
        world.kernel_height(&mined).is_some(),
        "the chain holds the kernel"
    );
    Run { world, recovery }
}
