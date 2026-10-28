// SPDX-License-Identifier: Apache-2.0
//! Seeded scenarios for the differential soak. One seed decides everything a case varies: the
//! flow and its direction, the outputs each party holds and how deep they are buried, the
//! amount, how the payer selects inputs and change, the minimum confirmations, TTL, payment
//! proof, messages, the slate shape the upstream peer writes, and where LEPIC is stopped.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use super::faults::CrashPoint;
use super::{EPIC, Funding, Setup, SlateShape, Spend, Who};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Standard,
    Invoice,
}

/// A step of LEPIC's in the standard flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Send,
    Receive,
    Finalize,
}

/// Where the LEPIC run stops LEPIC and reopens it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stop {
    pub step: Step,
    pub point: CrashPoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    pub seed: u64,
    pub flow: Flow,
    /// Sends in the standard flow, issues the invoice in the invoice flow.
    pub initiator: Who,
    pub setup: Setup,
    pub amount: u64,
    /// How the paying party selects.
    pub spend: Spend,
    pub ttl_blocks: Option<u64>,
    pub payment_proof: bool,
    pub initiator_message: Option<String>,
    pub responder_message: Option<String>,
    pub peer_writes: SlateShape,
    pub stop: Option<Stop>,
}

/// Every output the miner pays is at least this much, so a payer always holds enough for a
/// small amount and the fee.
const MIN_FUNDING: u64 = EPIC / 5;
const MAX_FUNDING: u64 = 5 * EPIC;
/// Kept free of the amount for the fee, which stays below 0.02 EPIC for any transaction a
/// scenario builds.
const FEE_MARGIN: u64 = EPIC / 10;
const MAX_TTL_BLOCKS: u64 = 60;
/// Longer than the 256 bytes upstream keeps, so truncation is exercised.
const MAX_MESSAGE_LEN: usize = 300;
/// The highest crash point tried; a step with fewer writes is then not stopped.
const MAX_CRASH_COMMITS: u32 = 2;

impl Scenario {
    pub fn generate(seed: u64) -> Scenario {
        let mut rng = StdRng::seed_from_u64(seed);
        let flow = if rng.random_bool(0.5) {
            Flow::Standard
        } else {
            Flow::Invoice
        };
        let initiator = if rng.random_bool(0.5) {
            Who::Subject
        } else {
            Who::Peer
        };
        let payer = match flow {
            Flow::Standard => initiator,
            Flow::Invoice => other(initiator),
        };
        let setup = setup(&mut rng, payer);
        let mut spend = Spend {
            minimum_confirmations: rng.random_range(1..=10),
            use_all: rng.random_bool(0.5),
            change_outputs: rng.random_range(1..=3),
        };
        let mut eligible = eligible(&setup, payer, spend.minimum_confirmations);
        if eligible < MIN_FUNDING {
            // Every funding output has at least one confirmation when the case starts.
            spend.minimum_confirmations = 1;
            eligible = eligible_all(&setup, payer);
        }
        let amount = amount(&mut rng, eligible - FEE_MARGIN);
        let ttl_blocks = rng
            .random_bool(0.5)
            .then(|| rng.random_range(1..=MAX_TTL_BLOCKS));
        // Upstream offers no payment proof on invoices.
        let payment_proof = flow == Flow::Standard && rng.random_bool(0.5);
        let initiator_message = message(&mut rng);
        let responder_message = message(&mut rng);
        // The file method writes V3 whenever TTL or payment proof need it, so the V3 shape is
        // a choice only without them.
        let peer_writes = if ttl_blocks.is_none() && !payment_proof && rng.random_bool(0.3) {
            SlateShape::V3
        } else {
            SlateShape::FileMethod
        };
        let stop = (flow == Flow::Standard && rng.random_bool(0.5)).then(|| {
            let step = match initiator {
                Who::Subject if rng.random_bool(0.5) => Step::Send,
                Who::Subject => Step::Finalize,
                Who::Peer => Step::Receive,
            };
            Stop {
                step,
                point: CrashPoint {
                    commits: rng.random_range(0..=MAX_CRASH_COMMITS),
                },
            }
        });
        Scenario {
            seed,
            flow,
            initiator,
            setup,
            amount,
            spend,
            ttl_blocks,
            payment_proof,
            initiator_message,
            responder_message,
            peer_writes,
            stop,
        }
    }

    pub fn responder(&self) -> Who {
        other(self.initiator)
    }

    /// The party whose inputs pay: the sender, or the payer of an invoice.
    pub fn payer(&self) -> Who {
        match self.flow {
            Flow::Standard => self.initiator,
            Flow::Invoice => self.responder(),
        }
    }
}

pub fn other(who: Who) -> Who {
    match who {
        Who::Peer => Who::Subject,
        Who::Subject => Who::Peer,
    }
}

/// One to four outputs for the payer and up to three for the other party, interleaved, with
/// gaps between them, so outputs of every age from fresh to well buried are on offer.
fn setup(rng: &mut StdRng, payer: Who) -> Setup {
    let mut fundings = Vec::new();
    let payer_outputs = rng.random_range(1..=4);
    let other_outputs = rng.random_range(0..=3);
    for (to, count) in [(payer, payer_outputs), (other(payer), other_outputs)] {
        for _ in 0..count {
            fundings.push(Funding {
                to,
                amount: rng.random_range(MIN_FUNDING..=MAX_FUNDING),
                gap_blocks: rng.random_range(0..=2),
            });
        }
    }
    for i in (1..fundings.len()).rev() {
        let j = rng.random_range(0..=i);
        fundings.swap(i, j);
    }
    Setup {
        fundings,
        settle_blocks: rng.random_range(0..=11),
    }
}

/// What `who` may spend at the start of the case with `minimum_confirmations`, counted as
/// `epic-wallet` counts confirmations: the block holding the output is the first.
fn eligible(setup: &Setup, who: Who, minimum_confirmations: u64) -> u64 {
    let (heights, tip) = setup.heights();
    setup
        .fundings
        .iter()
        .zip(heights)
        .filter(|(funding, height)| funding.to == who && tip + 1 - height >= minimum_confirmations)
        .map(|(funding, _)| funding.amount)
        .sum()
}

fn eligible_all(setup: &Setup, who: Who) -> u64 {
    eligible(setup, who, 1)
}

/// Mostly anywhere in the range, sometimes a few freeman, sometimes all of it.
fn amount(rng: &mut StdRng, max: u64) -> u64 {
    match rng.random_range(0..8) {
        0 => rng.random_range(1..=1_000.min(max)),
        1 => max,
        _ => rng.random_range(1..=max),
    }
}

/// Letters, digits and spaces: the message text this soak varies is its length, not its
/// character set.
fn message(rng: &mut StdRng) -> Option<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
    rng.random_bool(0.4).then(|| {
        let len = rng.random_range(1..=MAX_MESSAGE_LEN);
        (0..len)
            .map(|_| char::from(ALPHABET[rng.random_range(0..ALPHABET.len())]))
            .collect()
    })
}
