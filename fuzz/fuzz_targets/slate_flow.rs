// SPDX-License-Identifier: Apache-2.0
//! The slate builders a peer's slate reaches, run on valid but adversarial slates: an honest
//! send and invoice are built once, and each input changes one of their slates
//! ([`mutate_slate`]) before the next party's builder takes it. A builder may refuse the slate;
//! one that accepts it must not have let the peer change what was agreed.
//!
//! The first byte picks the step:
//! - 0: a changed S1 to the receiver (`build_s2`), and its S2 to the sender (`build_s3`);
//! - 1: a changed S2 to the sender (`build_s3`);
//! - 2: a changed I1 to the payer (`build_i2`), and its I2 to the issuer (`build_i3`);
//! - 3: a changed I2 to the issuer (`build_i3`).
//!
//! The rest are the edits.

#![no_main]

use std::sync::LazyLock;

use lepic_fuzz::{BASE_FEE, CountingRng, donor_strings, mutate_slate};
use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_slate::model::{KernelLock, ProofAddress, Slate};
use lepic_slate::stage::Stage;
use lepic_store::{AccountIndex, KeyId, OutputRecord, OutputStatus};
use lepic_wallet::finalize::build_s3;
use lepic_wallet::invoice::{
    BuiltI1, I1Plan, I1Randomness, I2Plan, I2Randomness, build_i1, build_i2, build_i3,
};
use lepic_wallet::receive::build_s2;
use lepic_wallet::send::{BuiltS1, ChangeOutput, S1Plan, S1Randomness, build_s1};
use libfuzzer_sys::fuzz_target;

const NETWORK: Network = Network::Floonet;
const ACCOUNT: AccountIndex = AccountIndex(0);
const EPIC: u64 = 100_000_000;
const FUNDS: u64 = 10 * EPIC;
const AMOUNT: u64 = 3 * EPIC;

/// The two wallets and the honest slates of one send and one invoice between them.
struct Flows {
    /// Sends the payment and pays the invoice.
    payer: Keychain,
    /// Receives the payment and issues the invoice.
    payee: Keychain,
    s1: BuiltS1,
    s2: Slate,
    i1: BuiltI1,
    i2: Slate,
    donors: Vec<String>,
}

fn keychain(first: u8) -> Keychain {
    let entropy: Vec<u8> = (first..first.wrapping_add(32)).collect();
    let seed = Seed::from_entropy(&entropy).expect("32 bytes of entropy make a seed");
    Keychain::from_seed(&seed, NETWORK).expect("a fixed seed makes a keychain")
}

fn account() -> Identifier {
    Identifier::new(2, [ACCOUNT.0, 0, 0, 0]).expect("the account path is valid")
}

fn key(index: u32) -> Identifier {
    Identifier::new(3, [ACCOUNT.0, index, 0, 0]).expect("an output path is valid")
}

/// Ample for one input, two outputs and the kernel.
fn fee() -> Fee {
    Fee::new(BASE_FEE.value().saturating_mul(20))
}

/// The payer's one unspent output, of [`FUNDS`] at key 1.
fn funds(payer: &Keychain) -> OutputRecord {
    let id = key(1);
    let commitment = payer
        .commit(FUNDS, &id, SwitchCommitment::Regular)
        .expect("the funds commit");
    OutputRecord {
        id: OutputIdentifier::new(OutputFeatures::Plain, commitment),
        key_id: KeyId(id.to_bytes()),
        account: ACCOUNT,
        amount: Amount::new(FUNDS),
        status: OutputStatus::Unspent,
        height: Height::new(1),
        lock_height: Height::ZERO,
        mmr_index: None,
        tx: None,
    }
}

fn change() -> Vec<ChangeOutput> {
    vec![ChangeOutput {
        key_id: key(2),
        amount: Amount::new(FUNDS - AMOUNT - fee().value()),
    }]
}

static FLOWS: LazyLock<Flows> = LazyLock::new(|| {
    let payer = keychain(0);
    let payee = keychain(100);
    let mut rng = CountingRng::new(1);
    let proof_key = payee
        .payment_proof_key(&account(), 0)
        .expect("the payee has a proof key");
    let plan = S1Plan {
        account: ACCOUNT,
        amount: Amount::new(AMOUNT),
        fee: fee(),
        height: Height::new(1000),
        lock: KernelLock::NONE,
        ttl_cutoff_height: Some(Height::new(2000)),
        inputs: vec![funds(&payer)],
        change: change(),
        message: Some("for the fuzzer".to_owned()),
        payment_proof_recipient: Some(
            ProofAddress::from_bytes(proof_key.public_key()).expect("a proof address"),
        ),
    };
    let randomness = S1Randomness::draw(&mut rng).expect("randomness");
    let s1 = build_s1(&payer, &plan, randomness).expect("the honest s1 builds");
    let (s2, _) = build_s2(
        &payee,
        &s1.slate,
        key(1),
        account(),
        Some("thanks"),
        BASE_FEE,
        &mut rng,
    )
    .expect("the honest s2 builds");
    let s3 = build_s3(&payer, BASE_FEE, &s1, &s2).expect("the honest s3 builds");

    let i1 = build_i1(
        &payee,
        &I1Plan {
            account: ACCOUNT,
            amount: Amount::new(AMOUNT),
            height: Height::new(1000),
            ttl_cutoff_height: Some(Height::new(2000)),
            key_id: key(2),
            message: Some("invoice".to_owned()),
        },
        I1Randomness::draw(&mut rng).expect("randomness"),
    )
    .expect("the honest i1 builds");
    let i2 = build_i2(
        &payer,
        &i1.slate,
        &i2_plan(&payer),
        &I2Randomness::draw(&mut rng).expect("randomness"),
    )
    .expect("the honest i2 builds");
    let i3 = build_i3(BASE_FEE, &i1, &i2).expect("the honest i3 builds");
    let donors = donor_strings(&[&s1.slate, &s2, &s3.slate, &i1.slate, &i2, &i3.slate]);
    Flows {
        payer,
        payee,
        s1,
        s2,
        i1,
        i2,
        donors,
    }
});

fn i2_plan(payer: &Keychain) -> I2Plan {
    I2Plan {
        fee: fee(),
        height: Height::new(1001),
        ttl_cutoff_height: None,
        inputs: vec![funds(payer)],
        change: change(),
        message: Some("paid".to_owned()),
    }
}

/// What a finalized slate must still say: the amount, fee and id the finalizing party agreed.
fn assert_agreed(finalized: &Slate, agreed: &Slate, step: &str) {
    assert_eq!(finalized.id(), agreed.id(), "{step}: the slate id changed");
    assert_eq!(
        finalized.amount(),
        agreed.amount(),
        "{step}: the amount changed"
    );
    assert_eq!(finalized.fee(), agreed.fee(), "{step}: the fee changed");
}

fuzz_target!(|data: &[u8]| {
    let Some((step, edits)) = data.split_first() else {
        return;
    };
    let flows = &*FLOWS;
    let mut rng = CountingRng::new(u64::from(*step));
    match step % 4 {
        0 => {
            let Some(s1) = mutate_slate(&flows.s1.slate, edits, &flows.donors) else {
                return;
            };
            let Ok((s2, output)) = build_s2(
                &flows.payee,
                &s1,
                key(1),
                account(),
                None,
                BASE_FEE,
                &mut rng,
            ) else {
                return;
            };
            assert_eq!(
                s2.stage(),
                Stage::S2,
                "build_s2 answered with another stage"
            );
            assert_eq!(s2.amount(), s1.amount(), "build_s2 changed the amount");
            let expected = flows
                .payee
                .commit(s1.amount().value(), &key(1), SwitchCommitment::Regular)
                .expect("the output commits");
            assert_eq!(
                output.commitment, expected,
                "the output is not for the slate amount"
            );
            assert!(
                s2.outputs().contains(&output),
                "the output is not in the s2"
            );
            if let Ok(s3) = build_s3(&flows.payer, BASE_FEE, &flows.s1, &s2) {
                assert_agreed(&s3.slate, &flows.s1.slate, "build_s3 of a changed s1");
            }
        }
        1 => {
            let Some(s2) = mutate_slate(&flows.s2, edits, &flows.donors) else {
                return;
            };
            if let Ok(s3) = build_s3(&flows.payer, BASE_FEE, &flows.s1, &s2) {
                assert_agreed(&s3.slate, &flows.s1.slate, "build_s3 of a changed s2");
            }
        }
        2 => {
            let Some(i1) = mutate_slate(&flows.i1.slate, edits, &flows.donors) else {
                return;
            };
            let plan = i2_plan(&flows.payer);
            let Ok(randomness) = I2Randomness::draw(&mut rng) else {
                return;
            };
            let Ok(i2) = build_i2(&flows.payer, &i1, &plan, &randomness) else {
                return;
            };
            assert_eq!(
                i2.stage(),
                Stage::I2,
                "build_i2 answered with another stage"
            );
            assert_eq!(i2.amount(), i1.amount(), "build_i2 paid another amount");
            assert_eq!(i2.fee(), plan.fee, "build_i2 paid another fee");
            if let Ok(i3) = build_i3(BASE_FEE, &flows.i1, &i2) {
                assert_eq!(
                    i3.slate.id(),
                    flows.i1.slate.id(),
                    "build_i3 of a changed i1"
                );
                assert_eq!(
                    i3.slate.amount(),
                    flows.i1.slate.amount(),
                    "build_i3 of a changed i1: the amount changed"
                );
            }
        }
        _ => {
            let Some(i2) = mutate_slate(&flows.i2, edits, &flows.donors) else {
                return;
            };
            if let Ok(i3) = build_i3(BASE_FEE, &flows.i1, &i2) {
                assert_agreed(&i3.slate, &flows.i2, "build_i3 of a changed i2");
            }
        }
    }
});
