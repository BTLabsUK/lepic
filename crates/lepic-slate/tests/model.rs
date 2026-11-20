// SPDX-License-Identifier: Apache-2.0
//! Invariants of the slate model and its stage transitions.

#![cfg(test)]

mod model_fixtures;

use lepic_crypto::Commitment;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::input::Input;
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_primitives::params::{
    BLOCK_INPUT_WEIGHT, BLOCK_KERNEL_WEIGHT, BLOCK_OUTPUT_WEIGHT, MAX_TX_WEIGHT,
};
use lepic_slate::error::{SlateError, Transition};
use lepic_slate::model::{
    KernelLock, MAX_MESSAGE_LEN, Participant, ParticipantMessage, Payment, PaymentProof, Proposal,
    Receipt, Slate, SlateId, SlateParts,
};
use lepic_slate::role::Role;
use lepic_slate::stage::{Flow, Stage, Step};
use model_fixtures::*;
use proptest::prelude::*;

fn participant_in(parts: &SlateParts, role: Role) -> Option<&Participant> {
    match role {
        Role::Sender => parts.sender.as_ref(),
        Role::Receiver => parts.receiver.as_ref(),
    }
}

/// The invariants, stated independently of the implementation.
fn invariants_hold(parts: &SlateParts) -> bool {
    let stage = parts.stage;
    let flow = stage.flow();
    let initiator = participant_in(parts, flow.initiator());
    let responder = participant_in(parts, flow.responder());
    let unsigned = |p: Option<&Participant>| p.is_some_and(|p| p.partial_signature.is_none());
    let signed = |p: Option<&Participant>| p.is_some_and(|p| p.partial_signature.is_some());
    let participants = match stage.step() {
        Step::Proposed => unsigned(initiator) && responder.is_none(),
        Step::Responded => unsigned(initiator) && signed(responder),
        Step::Finalized => signed(initiator) && signed(responder),
    };
    let kernel = parts.kernel.is_some() == stage.is_final();
    let proof = parts.payment_proof.as_ref().is_none_or(|proof| {
        flow == Flow::Standard && proof.receiver_signature.is_some() == (stage != Stage::S1)
    });
    let fee = stage != Stage::I1 || parts.fee == Fee::ZERO;
    let weight = (parts.inputs.len() as u64)
        .saturating_mul(BLOCK_INPUT_WEIGHT)
        .saturating_add((parts.outputs.len() as u64).saturating_mul(BLOCK_OUTPUT_WEIGHT))
        .saturating_add(BLOCK_KERNEL_WEIGHT);
    participants && kernel && proof && fee && weight <= MAX_TX_WEIGHT
}

fn assert_consistent(slate: &Slate) {
    let parts = slate.clone().into_parts();
    assert!(invariants_hold(&parts), "{:?}", slate.stage());
    assert_eq!(Slate::from_parts(parts).as_ref(), Ok(slate));
    assert_eq!(slate.kernel().is_some(), slate.stage().is_final());
    let order: Vec<Role> = slate.participants().map(|(role, _)| role).collect();
    assert_eq!(order.first(), Some(&slate.flow().initiator()));
}

fn assert_only_allowed_transitions(slate: &Slate) {
    let stage = slate.stage();
    let invalid = |transition| Err(SlateError::InvalidTransition { stage, transition });
    if stage != Stage::S1 {
        assert_eq!(slate.receive(receipt()), invalid(Transition::Receive));
    }
    if stage != Stage::I1 {
        assert_eq!(slate.pay(payment()), invalid(Transition::Pay));
    }
    if stage.step() != Step::Responded {
        assert_eq!(
            slate.finalize(signature(1), final_kernel(1)),
            invalid(Transition::Finalize)
        );
    }
}

#[derive(Debug, Clone)]
struct FlowCase {
    flow: Flow,
    amount: u64,
    fee: u64,
    lock_height: u64,
    ttl: Option<u64>,
    initiator_inputs: u8,
    initiator_outputs: u8,
    responder_inputs: u8,
    responder_outputs: u8,
    payer_ttl: Option<u64>,
    messages: (Option<String>, Option<String>),
    payment_proof: bool,
}

fn message() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(proptest::string::string_regex("[a-zé ]{0,128}").unwrap())
}

fn flow_case() -> impl Strategy<Value = FlowCase> {
    (
        prop_oneof![Just(Flow::Standard), Just(Flow::Invoice)],
        any::<u64>(),
        any::<u64>(),
        prop_oneof![Just(0u64), 1..u64::MAX],
        proptest::option::of(any::<u64>()),
        (0u8..4, 0u8..4, 0u8..4, 0u8..4),
        proptest::option::of(any::<u64>()),
        (message(), message()),
        any::<bool>(),
    )
        .prop_map(
            |(flow, amount, fee, lock_height, ttl, counts, payer_ttl, messages, payment_proof)| {
                FlowCase {
                    flow,
                    amount,
                    fee,
                    lock_height,
                    ttl,
                    initiator_inputs: counts.0,
                    initiator_outputs: counts.1,
                    responder_inputs: counts.2,
                    responder_outputs: counts.3,
                    payer_ttl,
                    messages,
                    payment_proof,
                }
            },
        )
}

fn inputs(count: u8, base: u8) -> Vec<lepic_primitives::input::Input> {
    (0..count).map(|n| input(base.wrapping_add(n))).collect()
}

fn outputs(count: u8, base: u8) -> Vec<lepic_primitives::output::Output> {
    (0..count).map(|n| output(base.wrapping_add(n))).collect()
}

fn maybe_message(participant: Participant, text: &Option<String>, seed: u8) -> Participant {
    match text {
        Some(text) => with_message(participant, ParticipantMessage::truncate(text), seed),
        None => participant,
    }
}

/// Runs a whole flow through the public transitions and returns every stage it produced.
fn run_flow(case: &FlowCase) -> Vec<Slate> {
    let standard = case.flow == Flow::Standard;
    let proposal = Proposal {
        id: SlateId::from_random_bytes([case.amount.to_le_bytes()[0]; 16]),
        amount: Amount::new(case.amount),
        fee: if standard {
            Fee::new(case.fee)
        } else {
            Fee::ZERO
        },
        height: Height::new(4),
        lock: KernelLock::at_height(Height::new(case.lock_height)),
        ttl_cutoff_height: case.ttl.map(Height::new),
        offset: offset(),
        inputs: inputs(case.initiator_inputs, 30),
        outputs: outputs(case.initiator_outputs, 40),
        payment_proof: (standard && case.payment_proof).then(payment_proof),
    };
    let initiator = maybe_message(participant(50), &case.messages.0, 51);
    let first = Slate::propose(case.flow, proposal, initiator).unwrap();
    let responder = signed(maybe_message(participant(60), &case.messages.1, 61), 62);
    let second = if standard {
        first
            .receive(Receipt {
                receiver: responder,
                outputs: outputs(case.responder_outputs, 70),
                proof_signature: case.payment_proof.then(|| proof_signature(9)),
            })
            .unwrap()
    } else {
        first
            .pay(Payment {
                sender: responder,
                inputs: inputs(case.responder_inputs, 80),
                outputs: outputs(case.responder_outputs, 90),
                fee: Fee::new(case.fee),
                height: Height::new(5),
                ttl_cutoff_height: case.payer_ttl.map(Height::new),
            })
            .unwrap()
    };
    let third = second.finalize(signature(63), final_kernel(64)).unwrap();
    vec![first, second, third]
}

proptest! {
    #[test]
    fn every_slate_built_by_transitions_satisfies_the_invariants(case in flow_case()) {
        let stages = run_flow(&case);
        let expected: Vec<Stage> =
            [Step::Proposed, Step::Responded, Step::Finalized].map(|step| Stage::new(case.flow, step)).to_vec();
        prop_assert_eq!(stages.iter().map(Slate::stage).collect::<Vec<_>>(), expected);
        for slate in &stages {
            assert_consistent(slate);
            assert_only_allowed_transitions(slate);
            prop_assert_eq!(slate.id(), stages[0].id());
            prop_assert_eq!(slate.amount(), Amount::new(case.amount));
            prop_assert_eq!(slate.offset(), stages[0].offset());
        }
        let last = &stages[2];
        let added_outputs = usize::from(case.initiator_outputs)
            .saturating_add(usize::from(case.responder_outputs));
        prop_assert_eq!(last.outputs().len(), added_outputs);
        prop_assert_eq!(last.fee(), Fee::new(case.fee));
        prop_assert_eq!(last.kernel().map(|k| k.features), Some(last.lock().kernel_features(last.fee())));
        if case.flow == Flow::Invoice {
            prop_assert_eq!(stages[0].fee(), Fee::ZERO);
            prop_assert_eq!(last.height(), Height::new(5));
            let ttl = case.payer_ttl.or(case.ttl).map(Height::new);
            prop_assert_eq!(last.ttl_cutoff_height(), ttl);
        }
    }

    #[test]
    fn from_parts_accepts_exactly_the_slates_that_satisfy_the_invariants(
        stage in proptest::sample::select(Stage::ALL.to_vec()),
        sender in proptest::option::of(any::<bool>()),
        receiver in proptest::option::of(any::<bool>()),
        kernel in any::<bool>(),
        proof in proptest::option::of(any::<bool>()),
        fee in prop_oneof![Just(0u64), 1..u64::MAX],
        input_count in 0u8..3,
        output_count in 0u8..3,
    ) {
        let party = |signed_state: Option<bool>, seed| signed_state.map(|is_signed| {
            if is_signed { signed(participant(seed), seed) } else { participant(seed) }
        });
        let parts = SlateParts {
            id: SlateId::from_bytes([1; 16]),
            stage,
            amount: Amount::new(5),
            fee: Fee::new(fee),
            height: Height::new(1),
            lock: KernelLock::NONE,
            ttl_cutoff_height: None,
            offset: offset(),
            sender: party(sender, 1),
            receiver: party(receiver, 2),
            inputs: inputs(input_count, 3),
            outputs: outputs(output_count, 6),
            kernel: kernel.then(|| final_kernel(9)),
            payment_proof: proof.map(|has_signature| PaymentProof {
                receiver_signature: has_signature.then(|| proof_signature(1)),
                ..payment_proof()
            }),
            origin: None,
        };
        let valid = invariants_hold(&parts);
        let result = Slate::from_parts(parts);
        prop_assert_eq!(result.is_ok(), valid, "{:?}", result.err());
    }

    #[test]
    fn participant_messages_are_bounded(text in proptest::string::string_regex(".{0,300}").unwrap()) {
        let result = ParticipantMessage::new(text.clone(), signature(1));
        if text.len() <= MAX_MESSAGE_LEN {
            prop_assert_eq!(result.map(|m| m.text().to_owned()), Ok(text.clone()));
        } else {
            prop_assert_eq!(result, Err(SlateError::MessageTooLong { len: text.len(), max: MAX_MESSAGE_LEN }));
        }
        let cut = ParticipantMessage::truncate(&text);
        prop_assert!(cut.len() <= MAX_MESSAGE_LEN && text.starts_with(cut));
    }
}

#[test]
fn fixture_slates_are_consistent_at_every_stage() {
    for slate in [s1(), s2(), s3(), i1(), i2(), i3()] {
        assert_consistent(&slate);
        assert_only_allowed_transitions(&slate);
    }
}

#[test]
fn invoice_is_started_by_the_receiver_and_listed_first() {
    let slate = i2();
    let order: Vec<Role> = slate.participants().map(|(role, _)| role).collect();
    assert_eq!(order, [Role::Receiver, Role::Sender]);
    assert!(i1().participant(Role::Sender).is_none());
}

#[test]
fn rejects_responder_data_at_stage_one() {
    let mut parts = s1().into_parts();
    parts.receiver = Some(participant(1));
    assert_eq!(
        Slate::from_parts(parts),
        Err(SlateError::UnexpectedParticipant {
            stage: Stage::S1,
            role: Role::Receiver
        })
    );
}

#[test]
fn rejects_receipt_without_a_partial_signature() {
    let receipt = Receipt {
        receiver: participant(11),
        ..receipt()
    };
    assert_eq!(
        s1().receive(receipt),
        Err(SlateError::MissingPartialSignature {
            stage: Stage::S2,
            role: Role::Receiver
        })
    );
}

#[test]
fn rejects_payment_without_a_partial_signature() {
    let payment = Payment {
        sender: participant(21),
        ..payment()
    };
    assert_eq!(
        i1().pay(payment),
        Err(SlateError::MissingPartialSignature {
            stage: Stage::I2,
            role: Role::Sender
        })
    );
}

#[test]
fn rejects_signed_initiator_before_the_final_stage() {
    let mut parts = s2().into_parts();
    parts.sender = Some(signed(participant(10), 1));
    assert_eq!(
        Slate::from_parts(parts),
        Err(SlateError::UnexpectedPartialSignature {
            stage: Stage::S2,
            role: Role::Sender
        })
    );
}

#[test]
fn rejects_final_stage_without_kernel_excess() {
    let mut parts = s3().into_parts();
    parts.kernel = None;
    assert_eq!(
        Slate::from_parts(parts),
        Err(SlateError::MissingKernelExcess { stage: Stage::S3 })
    );
}

#[test]
fn rejects_kernel_excess_before_the_final_stage() {
    let mut parts = i2().into_parts();
    parts.kernel = Some(final_kernel(1));
    assert_eq!(
        Slate::from_parts(parts),
        Err(SlateError::UnexpectedKernelExcess { stage: Stage::I2 })
    );
}

#[test]
fn rejects_fee_on_an_unpaid_invoice() {
    let proposal = Proposal {
        fee: Fee::new(1),
        ..invoice_proposal()
    };
    assert_eq!(
        Slate::propose(Flow::Invoice, proposal, participant(1)),
        Err(SlateError::FeeBeforeSender {
            stage: Stage::I1,
            fee: Fee::new(1)
        })
    );
}

#[test]
fn rejects_payment_proof_in_the_invoice_flow() {
    let proposal = Proposal {
        payment_proof: Some(payment_proof()),
        ..invoice_proposal()
    };
    assert_eq!(
        Slate::propose(Flow::Invoice, proposal, participant(1)),
        Err(SlateError::PaymentProofInInvoice)
    );
}

#[test]
fn payment_proof_is_signed_by_the_receiver() {
    let proposal = Proposal {
        payment_proof: Some(payment_proof()),
        ..send_proposal()
    };
    let s1 = Slate::propose(Flow::Standard, proposal, participant(10)).unwrap();
    assert_eq!(
        s1.receive(receipt()),
        Err(SlateError::MissingProofSignature { stage: Stage::S2 })
    );
    let s2 = s1
        .receive(Receipt {
            proof_signature: Some(proof_signature(3)),
            ..receipt()
        })
        .unwrap();
    assert_eq!(
        s2.payment_proof()
            .and_then(|proof| proof.receiver_signature),
        Some(proof_signature(3))
    );

    let mut early = s1.into_parts();
    early.payment_proof = Some(PaymentProof {
        receiver_signature: Some(proof_signature(3)),
        ..payment_proof()
    });
    assert_eq!(
        Slate::from_parts(early),
        Err(SlateError::UnexpectedProofSignature { stage: Stage::S1 })
    );
}

#[test]
fn rejects_proof_signature_without_a_payment_proof() {
    let receipt = Receipt {
        proof_signature: Some(proof_signature(3)),
        ..receipt()
    };
    assert_eq!(
        s1().receive(receipt),
        Err(SlateError::UnexpectedProofSignature { stage: Stage::S2 })
    );
}

#[test]
fn rejects_body_above_the_transaction_weight_limit() {
    let fitting = MAX_TX_WEIGHT - BLOCK_KERNEL_WEIGHT;
    let mut parts = s1().into_parts();
    parts.outputs = Vec::new();
    let distinct_input = |n: u64| {
        Input::new(
            OutputFeatures::Plain,
            Commitment::commit_value(n + 1).unwrap(),
        )
    };
    parts.inputs = (0..fitting).map(distinct_input).collect();
    assert!(Slate::from_parts(parts.clone()).is_ok());
    parts.inputs.push(distinct_input(fitting));
    assert_eq!(
        Slate::from_parts(parts),
        Err(SlateError::BodyTooHeavy {
            weight: MAX_TX_WEIGHT + 1,
            max: MAX_TX_WEIGHT
        })
    );
}

#[test]
fn rejects_a_coinbase_output() {
    let mut parts = s1().into_parts();
    parts.outputs = vec![Output {
        features: OutputFeatures::Coinbase,
        ..output(1)
    }];
    assert_eq!(Slate::from_parts(parts), Err(SlateError::CoinbaseOutput));
}

#[test]
fn rejects_duplicate_input_commitments() {
    let mut parts = s1().into_parts();
    parts.inputs = vec![input(1), input(2), input(1)];
    parts.outputs = vec![output(3)];
    assert_eq!(
        Slate::from_parts(parts),
        Err(SlateError::DuplicateInput {
            commitment: commitment(1)
        })
    );
}

#[test]
fn rejects_duplicate_output_commitments() {
    let mut parts = s1().into_parts();
    parts.inputs = vec![input(1)];
    parts.outputs = vec![output(2), output(3), output(2)];
    assert_eq!(
        Slate::from_parts(parts),
        Err(SlateError::DuplicateOutput {
            commitment: commitment(2)
        })
    );
}

#[test]
fn rejects_a_commitment_that_is_both_input_and_output() {
    let mut parts = s1().into_parts();
    parts.inputs = vec![input(1), input(2)];
    parts.outputs = vec![output(3), output(2)];
    assert_eq!(
        Slate::from_parts(parts),
        Err(SlateError::InputSpendsOutput {
            commitment: commitment(2)
        })
    );
}

#[test]
fn accepts_a_coinbase_input() {
    let mut parts = s1().into_parts();
    parts.inputs = vec![Input::new(OutputFeatures::Coinbase, commitment(1))];
    parts.outputs = vec![output(2)];
    assert!(Slate::from_parts(parts).is_ok());
}

#[test]
fn origin_does_not_affect_the_invariants() {
    use lepic_slate::codec::CodecId;
    use lepic_slate::origin::{LegacyHeader, WireOrigin};
    let header = LegacyHeader {
        version: 3,
        orig_version: 3,
        block_header_version: 6,
    };
    let origin = WireOrigin::legacy(CodecId::new("test"), header);
    let slate = s2().with_origin(Some(origin));
    assert_eq!(slate.origin(), Some(&origin));
    assert_eq!(
        slate.origin().and_then(WireOrigin::legacy_header),
        Some(header)
    );
    assert_eq!(
        slate
            .finalize(signature(12), final_kernel(13))
            .unwrap()
            .origin(),
        Some(&origin)
    );
}
