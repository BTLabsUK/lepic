// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap and index (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use lepic_crypto::{Commitment, ProofMessage, RangeProof};
use lepic_keychain::proof::{create_output, create_proof, rewind};
use lepic_keychain::{
    Identifier, Keychain, LegacyProofBuilder, OutputRewinder, ProofBuild, ProofBuilder,
    RewoundOutput, SwitchCommitment,
};
use lepic_primitives::params::Network;
use lepic_telemetry::{assert_no_secrets, capture};
use proptest::prelude::*;

const PHRASE: &str = "pipe stock song coast pair always emotion member joy sting dash theory";
const OTHER_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn wallet(phrase: &str) -> Keychain {
    Keychain::from_mnemonic(phrase, Network::Mainnet).unwrap()
}

fn output_id(index: u32) -> Identifier {
    Identifier::new(3, [0, 0, index, 0]).unwrap()
}

#[test]
fn created_output_verifies_and_rewinds_to_its_key() {
    let keychain = wallet(PHRASE);
    let builder = ProofBuilder::new(&keychain).unwrap();
    let id = output_id(7);
    let output = create_output(&keychain, &builder, 5_000, &id, SwitchCommitment::Regular).unwrap();

    assert!(!output.is_coinbase());
    assert_eq!(output.proof.verify(&output.commitment), Ok(()));
    assert_eq!(
        rewind(&builder, &output.commitment, &output.proof),
        Ok(Some(RewoundOutput {
            amount: 5_000,
            identifier: id,
            switch: SwitchCommitment::Regular,
        }))
    );
}

#[test]
fn rewinder_falls_back_to_the_legacy_builder() {
    let keychain = wallet(PHRASE);
    let legacy = LegacyProofBuilder::new(&keychain).unwrap();
    let id = output_id(2);
    let output = create_output(&keychain, &legacy, 42, &id, SwitchCommitment::Regular).unwrap();

    let current = ProofBuilder::new(&keychain).unwrap();
    assert_eq!(
        rewind(&current, &output.commitment, &output.proof),
        Ok(None)
    );
    let rewinder = OutputRewinder::new(&keychain).unwrap();
    assert_eq!(
        rewinder.rewind(&output.commitment, &output.proof),
        Ok(Some(RewoundOutput {
            amount: 42,
            identifier: id,
            switch: SwitchCommitment::Regular,
        }))
    );
}

#[test]
fn another_wallets_output_rewinds_to_none() {
    let mine = wallet(PHRASE);
    let theirs = wallet(OTHER_PHRASE);
    let rewinder = OutputRewinder::new(&mine).unwrap();
    for builder_output in [
        create_output(
            &theirs,
            &ProofBuilder::new(&theirs).unwrap(),
            9,
            &output_id(0),
            SwitchCommitment::Regular,
        ),
        create_output(
            &theirs,
            &LegacyProofBuilder::new(&theirs).unwrap(),
            9,
            &output_id(0),
            SwitchCommitment::Regular,
        ),
    ] {
        let output = builder_output.unwrap();
        assert_eq!(rewinder.rewind(&output.commitment, &output.proof), Ok(None));
    }
}

#[test]
fn proof_under_a_different_commitment_rewinds_to_none() {
    let keychain = wallet(PHRASE);
    let builder = ProofBuilder::new(&keychain).unwrap();
    let id = output_id(1);
    let proof = create_proof(&keychain, &builder, 10, &id, SwitchCommitment::Regular).unwrap();
    let other_commit = keychain.commit(11, &id, SwitchCommitment::Regular).unwrap();
    assert_eq!(rewind(&builder, &other_commit, &proof), Ok(None));
}

#[test]
fn proof_of_the_wrong_length_rewinds_to_none() {
    let keychain = wallet(PHRASE);
    let builder = ProofBuilder::new(&keychain).unwrap();
    let commit = keychain
        .commit(10, &output_id(1), SwitchCommitment::Regular)
        .unwrap();
    let short = RangeProof::from_bytes(&[1; 64]).unwrap();
    assert_eq!(rewind(&builder, &commit, &short), Ok(None));
}

fn message(bytes: [(usize, u8); 3], id: &Identifier) -> ProofMessage {
    let mut message = [0u8; ProofMessage::LEN];
    message[3..].copy_from_slice(&id.to_bytes());
    for (index, byte) in bytes {
        message[index] = byte;
    }
    ProofMessage::from(message)
}

#[test]
fn check_output_rejects_reserved_bytes_and_unknown_switch_types() {
    let keychain = wallet(PHRASE);
    let builder = ProofBuilder::new(&keychain).unwrap();
    let id = output_id(4);
    let commit = keychain.commit(3, &id, SwitchCommitment::Regular).unwrap();
    let valid = message([(0, 0), (1, 0), (2, 1)], &id);
    assert_eq!(
        builder.check_output(&commit, 3, &valid),
        Ok(Some((id, SwitchCommitment::Regular)))
    );
    for bad in [
        message([(0, 1), (1, 0), (2, 1)], &id),
        message([(0, 0), (1, 1), (2, 1)], &id),
        message([(0, 0), (1, 0), (2, 2)], &id),
    ] {
        assert_eq!(builder.check_output(&commit, 3, &bad), Ok(None));
    }
}

#[test]
fn check_output_clamps_the_message_depth_to_four() {
    let keychain = wallet(PHRASE);
    let builder = ProofBuilder::new(&keychain).unwrap();
    let id = Identifier::new(4, [0, 0, 0, 3]).unwrap();
    let commit = keychain.commit(3, &id, SwitchCommitment::None).unwrap();
    let too_deep = message([(0, 0), (2, 0), (3, 9)], &id);
    assert_eq!(
        builder.check_output(&commit, 3, &too_deep),
        Ok(Some((id, SwitchCommitment::None)))
    );
}

#[test]
fn legacy_check_output_requires_four_zero_bytes() {
    let keychain = wallet(PHRASE);
    let legacy = LegacyProofBuilder::new(&keychain).unwrap();
    let id = output_id(5);
    let commit = keychain.commit(3, &id, SwitchCommitment::Regular).unwrap();
    let valid = legacy.proof_message(&id, SwitchCommitment::Regular);
    assert_eq!(
        legacy.check_output(&commit, 3, &valid),
        Ok(Some((id, SwitchCommitment::Regular)))
    );
    let mut bytes = *valid.as_bytes();
    bytes[3] = 3;
    assert_eq!(
        legacy.check_output(&commit, 3, &ProofMessage::from(bytes)),
        Ok(None)
    );
}

#[test]
fn builders_and_nonces_stay_out_of_logs_and_debug() {
    let keychain = wallet(PHRASE);
    let builder = ProofBuilder::new(&keychain).unwrap();
    let legacy = LegacyProofBuilder::new(&keychain).unwrap();
    let rewinder = OutputRewinder::new(&keychain).unwrap();
    let commit: Commitment = keychain
        .commit(1, &output_id(0), SwitchCommitment::Regular)
        .unwrap();
    let rewind_nonce = builder.rewind_nonce(&commit).unwrap();
    let private_nonce = builder.private_nonce(&commit).unwrap();
    let legacy_nonce = legacy.rewind_nonce(&commit).unwrap();

    let ((), captured) = capture(|| {
        tracing::debug!(
            builder = ?builder,
            legacy = ?legacy,
            rewinder = ?rewinder,
            rewind_nonce = ?rewind_nonce,
            private_nonce = ?private_nonce,
            legacy_nonce = ?legacy_nonce,
            "proof builders created"
        );
    });
    assert_eq!(captured.records.len(), 1);
    let secrets: [&[u8]; 3] = [
        rewind_nonce.expose_bytes(),
        private_nonce.expose_bytes(),
        legacy_nonce.expose_bytes(),
    ];
    assert_eq!(assert_no_secrets(&captured.records, &secrets), Ok(()));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn own_outputs_rewind_and_foreign_outputs_do_not(
        amount in any::<u64>(),
        index in any::<u32>(),
        regular in any::<bool>(),
    ) {
        let switch = if regular { SwitchCommitment::Regular } else { SwitchCommitment::None };
        let mine = wallet(PHRASE);
        let theirs = wallet(OTHER_PHRASE);
        let id = output_id(index);
        let output = create_output(&mine, &ProofBuilder::new(&mine).unwrap(), amount, &id, switch)
            .unwrap();
        prop_assert_eq!(
            OutputRewinder::new(&mine).unwrap().rewind(&output.commitment, &output.proof),
            Ok(Some(RewoundOutput { amount, identifier: id, switch }))
        );
        prop_assert_eq!(
            OutputRewinder::new(&theirs).unwrap().rewind(&output.commitment, &output.proof),
            Ok(None)
        );
    }
}
