// SPDX-License-Identifier: Apache-2.0
//! Valid crypto values and slates for the model tests. None of them verify as a transaction;
//! the model checks structure, not signatures.

#![allow(dead_code)] // Each test target uses a different subset.

use lepic_crypto::{Commitment, PublicKey, RangeProof, SecretKey, Signature};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::input::Input;
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_slate::model::{
    FinalKernel, KernelLock, Participant, ParticipantMessage, Payment, PaymentProof, ProofAddress,
    ProofSignature, Proposal, Receipt, Slate, SlateId,
};
use lepic_slate::stage::Flow;

pub fn secret(seed: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes[31] = seed;
    SecretKey::from_array(bytes).unwrap()
}

pub fn public_key(seed: u8) -> PublicKey {
    PublicKey::from_secret_key(&secret(seed)).unwrap()
}

pub fn signature(seed: u8) -> Signature {
    let mut bytes = [0u8; 64];
    bytes[31] = seed.max(1);
    bytes[63] = seed.max(1);
    Signature::from_compact(&bytes).unwrap()
}

pub fn commitment(seed: u8) -> Commitment {
    Commitment::commit(u64::from(seed), &secret(seed)).unwrap()
}

pub fn input(seed: u8) -> Input {
    Input::new(OutputFeatures::Plain, commitment(seed))
}

pub fn output(seed: u8) -> Output {
    let proof = RangeProof::from_bytes(&[seed; RangeProof::BULLETPROOF_LEN]).unwrap();
    Output::new(OutputFeatures::Plain, commitment(seed), proof)
}

pub fn participant(seed: u8) -> Participant {
    Participant::new(public_key(seed), public_key(seed.wrapping_add(100)))
}

pub fn signed(mut participant: Participant, seed: u8) -> Participant {
    participant.partial_signature = Some(signature(seed));
    participant
}

pub fn with_message(mut participant: Participant, text: &str, seed: u8) -> Participant {
    participant.message = Some(ParticipantMessage::new(text.to_owned(), signature(seed)).unwrap());
    participant
}

// Addresses taken from the G-03 payment proof vectors.
pub fn sender_address() -> ProofAddress {
    address("fd5c6c0ad1e51fbc1d58ca746c29585795368ec6727ae4a74b9082cda91e7fd0")
}

pub fn receiver_address() -> ProofAddress {
    address("b03c84d7f781b536c96668d93b37768c7812b76449c17aaf0a9d11a003c3c737")
}

fn address(hex: &str) -> ProofAddress {
    lepic_slate::validate::parse_proof_address(hex).unwrap()
}

pub fn proof_signature(seed: u8) -> ProofSignature {
    ProofSignature::from_bytes([seed; 64])
}

pub fn payment_proof() -> PaymentProof {
    PaymentProof {
        sender_address: sender_address(),
        receiver_address: receiver_address(),
        receiver_signature: None,
    }
}

pub fn final_kernel(seed: u8) -> FinalKernel {
    FinalKernel {
        excess: commitment(seed),
        excess_sig: signature(seed),
    }
}

pub fn offset() -> BlindingFactor {
    BlindingFactor::from_array([0x42; 32])
}

pub fn send_proposal() -> Proposal {
    Proposal {
        id: SlateId::from_bytes([7; 16]),
        amount: Amount::new(100_000_000),
        fee: Fee::new(800_000),
        height: Height::new(4),
        lock: KernelLock::NONE,
        ttl_cutoff_height: None,
        offset: offset(),
        inputs: vec![input(1)],
        outputs: vec![output(2)],
        payment_proof: None,
    }
}

pub fn invoice_proposal() -> Proposal {
    Proposal {
        fee: Fee::ZERO,
        inputs: Vec::new(),
        outputs: vec![output(3)],
        ..send_proposal()
    }
}

pub fn s1() -> Slate {
    Slate::propose(Flow::Standard, send_proposal(), participant(10)).unwrap()
}

pub fn s2() -> Slate {
    s1().receive(receipt()).unwrap()
}

pub fn s3() -> Slate {
    s2().finalize(signature(12), final_kernel(13)).unwrap()
}

pub fn i1() -> Slate {
    Slate::propose(Flow::Invoice, invoice_proposal(), participant(20)).unwrap()
}

pub fn i2() -> Slate {
    i1().pay(payment()).unwrap()
}

pub fn i3() -> Slate {
    i2().finalize(signature(22), final_kernel(23)).unwrap()
}

pub fn receipt() -> Receipt {
    Receipt {
        receiver: signed(participant(11), 11),
        outputs: vec![output(4)],
        proof_signature: None,
    }
}

pub fn payment() -> Payment {
    Payment {
        sender: signed(participant(21), 21),
        inputs: vec![input(5)],
        outputs: vec![output(6)],
        fee: Fee::new(800_000),
        height: Height::new(5),
        ttl_cutoff_height: None,
    }
}
