//! The randomized differential soak: seeded scenarios run against an upstream `epic-wallet`
//! v4.1.0 peer, once with LEPIC as the subject and once with an upstream wallet in its place,
//! compared as `file_method.rs` compares its fixed cases. Half the standard-flow scenarios stop
//! LEPIC at a persistence point of its send, receive or finalize, reopen it and let it retry.
//!
//! `cargo xtask soak --iterations <n> [--seed <s>]` runs the ignored `soak` test, which reads
//! `LEPIC_SOAK_ITERATIONS`, `LEPIC_SOAK_SEED` and `LEPIC_SOAK_JOBS`. Iteration `i` runs seed
//! `s + i`, so `--iterations 1 --seed <failed seed>` replays a failure.

// Test code may unwrap, panic and use plain arithmetic and indexing (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use support::faults::CrashPoint;
use support::lepic::Recovery;
use support::scenario::{Flow, Scenario, Step, Stop};
use support::soak::{Outcome, Sabotage, check, check_seed};
use support::{AMOUNT, Funding, Setup, SlateShape, Spend, Who};

const DEFAULT_JOBS: u64 = 4;
/// How often the soak reports progress, in finished iterations.
const PROGRESS_EVERY: u64 = 25;

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().map(|value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name}={value} is not a number"))
    })
}

#[test]
#[ignore = "long; run through `cargo xtask soak`"]
fn soak() {
    let iterations = env_u64("LEPIC_SOAK_ITERATIONS").unwrap_or(1);
    let first_seed = env_u64("LEPIC_SOAK_SEED").unwrap_or(0);
    let jobs = env_u64("LEPIC_SOAK_JOBS").unwrap_or(DEFAULT_JOBS).max(1);
    eprintln!("soak: {iterations} iterations from seed {first_seed} on {jobs} threads");
    let started = Instant::now();
    let next = AtomicU64::new(0);
    let done = AtomicU64::new(0);
    let failed: Mutex<Vec<Outcome>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    if index >= iterations {
                        break;
                    }
                    let seed = first_seed.wrapping_add(index);
                    let outcome = check_seed(seed, Sabotage::None);
                    if !outcome.differences.is_empty() {
                        eprintln!(
                            "soak: seed {seed} FAILED\n{}",
                            outcome.differences.join("\n")
                        );
                        failed.lock().unwrap().push(outcome);
                    }
                    let finished = done.fetch_add(1, Ordering::SeqCst) + 1;
                    if finished.is_multiple_of(PROGRESS_EVERY) || finished == iterations {
                        eprintln!(
                            "soak: {finished}/{iterations} done, {} failed, {}s",
                            failed.lock().unwrap().len(),
                            started.elapsed().as_secs()
                        );
                    }
                }
            });
        }
    });
    let failed = failed.into_inner().unwrap();
    let mut seeds: Vec<u64> = failed.iter().map(|o| o.scenario.seed).collect();
    seeds.sort_unstable();
    assert!(
        seeds.is_empty(),
        "{} of {iterations} iterations failed, seeds {seeds:?}; replay one with \
         `cargo xtask soak --iterations 1 --seed <seed>`",
        seeds.len()
    );
    eprintln!(
        "soak: all {iterations} iterations from seed {first_seed} passed in {}s",
        started.elapsed().as_secs()
    );
}

#[test]
fn a_seed_always_generates_the_same_scenario() {
    for seed in [0, 1, 42, u64::MAX] {
        assert_eq!(Scenario::generate(seed), Scenario::generate(seed));
    }
    assert_ne!(Scenario::generate(1), Scenario::generate(2));
}

/// A thousand seeds, the length of a soak run, reach every choice the generator makes.
#[test]
fn a_thousand_seeds_reach_every_choice() {
    let scenarios: Vec<Scenario> = (0..1_000).map(Scenario::generate).collect();
    let any = |what: &str, check: &dyn Fn(&Scenario) -> bool| {
        assert!(scenarios.iter().any(check), "no scenario has {what}");
    };
    for flow in [Flow::Standard, Flow::Invoice] {
        for initiator in [Who::Subject, Who::Peer] {
            any("each flow in each direction", &|s| {
                s.flow == flow && s.initiator == initiator
            });
        }
    }
    any("a ttl", &|s| s.ttl_blocks.is_some());
    any("no ttl", &|s| s.ttl_blocks.is_none());
    any("a payment proof", &|s| s.payment_proof);
    any("a v3 peer", &|s| s.peer_writes == SlateShape::V3);
    any("all inputs spent", &|s| s.spend.use_all);
    any("smallest inputs spent", &|s| !s.spend.use_all);
    for change in 1..=3 {
        any("each change output count", &|s| {
            s.spend.change_outputs == change
        });
    }
    any("ten confirmations", &|s| {
        s.spend.minimum_confirmations == 10
    });
    any("a message cut by upstream", &|s| {
        s.initiator_message.as_ref().is_some_and(|m| m.len() > 256)
    });
    any("an unfunded receiver", &|s| {
        let other = support::scenario::other(s.payer());
        !s.setup.fundings.iter().any(|f| f.to == other)
    });
    any("a payer with four outputs", &|s| {
        s.setup
            .fundings
            .iter()
            .filter(|f| f.to == s.payer())
            .count()
            == 4
    });
    any("a tiny amount", &|s| s.amount <= 1_000);
    for step in [Step::Send, Step::Receive, Step::Finalize] {
        for commits in 0..=2 {
            any("each stop", &|s| {
                s.stop
                    == Some(Stop {
                        step,
                        point: CrashPoint { commits },
                    })
            });
        }
    }
    for s in &scenarios {
        assert!(s.amount > 0, "seed {} pays nothing", s.seed);
        assert!(
            s.stop.is_none() || s.flow == Flow::Standard,
            "seed {} stops an invoice",
            s.seed
        );
    }
}

/// A standard-flow scenario on the fixed setup, initiated by `initiator`, stopped as `stop`.
fn fixed(initiator: Who, stop: Option<Stop>) -> Scenario {
    Scenario {
        seed: 0,
        flow: Flow::Standard,
        initiator,
        setup: Setup::standard(),
        amount: AMOUNT,
        spend: Spend::default(),
        ttl_blocks: None,
        payment_proof: false,
        initiator_message: None,
        responder_message: None,
        peer_writes: SlateShape::FileMethod,
        stop,
    }
}

/// Stops LEPIC at each persistence point of `step` in turn, from before the first write to
/// after the last, until a point lies past the step's writes. Returns how each stop ended.
fn every_persistence_point(initiator: Who, step: Step) -> Vec<Recovery> {
    let mut recoveries = Vec::new();
    for commits in 0.. {
        let stop = Stop {
            step,
            point: CrashPoint { commits },
        };
        let outcome = check(fixed(initiator, Some(stop)), Sabotage::None);
        assert!(
            outcome.differences.is_empty(),
            "{step:?} stopped after {commits} writes:\n{}",
            outcome.differences.join("\n")
        );
        let recovery = outcome.recovery.unwrap();
        if recovery == Recovery::NotStopped {
            break;
        }
        recoveries.push(recovery);
    }
    recoveries
}

#[test]
fn a_send_stopped_at_any_persistence_point_completes_once() {
    let recoveries = every_persistence_point(Who::Subject, Step::Send);
    assert_eq!(recoveries, [Recovery::Completed, Recovery::Completed]);
}

#[test]
fn a_finalize_stopped_at_any_persistence_point_completes_once() {
    let recoveries = every_persistence_point(Who::Subject, Step::Finalize);
    assert_eq!(
        recoveries,
        [
            Recovery::Completed,
            Recovery::Completed,
            Recovery::Completed
        ]
    );
}

/// A receive stopped before its write receives again. One stopped after storing its reply
/// receives the same file again and gets the stored reply back, where `epic-wallet` refuses a
/// slate it received before, so the payment completes once either way.
#[test]
fn a_receive_stopped_at_any_persistence_point_completes_once() {
    let recoveries = every_persistence_point(Who::Peer, Step::Receive);
    assert_eq!(recoveries, [Recovery::Completed, Recovery::Completed]);
}

#[test]
fn the_soak_reports_a_misreported_balance_with_its_seed() {
    let outcome = check(fixed(Who::Subject, None), Sabotage::MisreportedBalance);
    assert_eq!(outcome.differences.len(), 1, "{:?}", outcome.differences);
    assert!(
        outcome.differences[0].starts_with("seed 0 spendable: subject balance"),
        "{:?}",
        outcome.differences
    );
}

#[test]
fn the_soak_reports_a_send_that_ran_twice() {
    let stop = Stop {
        step: Step::Send,
        point: CrashPoint { commits: 1 },
    };
    // A second output, so the second send finds inputs the first did not lock.
    let mut scenario = fixed(Who::Subject, Some(stop));
    scenario.setup.fundings.push(Funding {
        to: Who::Subject,
        amount: AMOUNT * 2,
        gap_blocks: 0,
    });
    let outcome = check(scenario, Sabotage::SendTwice);
    assert!(
        outcome
            .differences
            .iter()
            .any(|d| d.contains("subject 4 log entries, reference 3")),
        "{:?}",
        outcome.differences
    );
}
