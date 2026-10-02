//! Rejections and orderings of `Transaction::validate` that the golden vectors do not cover.

use lepic_crypto::{
    Commitment, CryptoError, Item, ProofMessage, PublicKey, RangeProof, SecretKey, aggsig,
};
use lepic_primitives::amount::{Fee, Height};
use lepic_primitives::committed::{self, KernelSumError};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::input::Input;
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_primitives::params::MAX_TX_WEIGHT;
use lepic_primitives::tx::{Transaction, TransactionBody, TxError};
use lepic_primitives::validate::ValidationError;

#[cfg(test)]
fn key(byte: u8) -> SecretKey {
    SecretKey::from_array([byte; 32]).unwrap()
}

#[cfg(test)]
fn output(value: u64, blind: u8) -> Output {
    let blind = key(blind);
    Output::new(
        OutputFeatures::Plain,
        Commitment::commit(value, &blind).unwrap(),
        RangeProof::create(
            value,
            &blind,
            &key(0x41),
            &key(0x42),
            &ProofMessage::from([0; 20]),
        )
        .unwrap(),
    )
}

#[cfg(test)]
fn input(value: u64, blind: u8) -> Input {
    Input::new(
        OutputFeatures::Plain,
        Commitment::commit(value, &key(blind)).unwrap(),
    )
}

/// A kernel whose excess is `commit(0, excess)`, signed by `excess` as upstream signs kernels.
#[cfg(test)]
fn kernel(features: KernelFeatures, excess: &SecretKey) -> TxKernel {
    let pubkey = PublicKey::from_secret_key(excess).unwrap();
    let signature = aggsig::sign_single(
        &features.signature_message(),
        excess,
        &key(0x51),
        Some(&pubkey),
    )
    .unwrap();
    TxKernel::new(features, Commitment::commit(0, excess).unwrap(), signature)
}

/// Spends 1000 at blind 0x11 into 600 at 0x21 and 390 at 0x22 with a fee of 10, offset by
/// `offset`.
#[cfg(test)]
fn balanced(offset: &BlindingFactor) -> Transaction {
    let mut negative = vec![key(0x11)];
    if !offset.is_zero() {
        negative.push(offset.to_secret_key().unwrap());
    }
    let excess = SecretKey::sum(&[key(0x21), key(0x22)], &negative).unwrap();
    let features = KernelFeatures::Plain { fee: Fee::new(10) };
    Transaction::new(
        offset.clone(),
        TransactionBody::new(
            vec![input(1000, 0x11)],
            vec![output(600, 0x21), output(390, 0x22)],
            vec![kernel(features, &excess)],
        ),
    )
}

#[cfg(test)]
fn offset(byte: u8) -> BlindingFactor {
    BlindingFactor::from_array([byte; 32])
}

#[test]
fn accepts_balanced_transaction_with_offset() {
    assert_eq!(balanced(&offset(0x31)).validate(), Ok(()));
}

#[test]
fn accepts_balanced_transaction_without_offset() {
    assert_eq!(balanced(&BlindingFactor::zero()).validate(), Ok(()));
}

#[test]
fn rejects_transaction_whose_fee_differs_from_its_balance() {
    let tx = balanced(&offset(0x31));
    let (tx_offset, body) = tx.into_parts();
    let (inputs, outputs, _) = body.into_parts();
    let excess = SecretKey::sum(
        &[key(0x21), key(0x22)],
        &[key(0x11), tx_offset.to_secret_key().unwrap()],
    )
    .unwrap();
    let kernels = vec![kernel(KernelFeatures::Plain { fee: Fee::new(11) }, &excess)];
    let tx = Transaction::new(tx_offset, TransactionBody::new(inputs, outputs, kernels));
    assert_eq!(
        tx.validate(),
        Err(ValidationError::KernelSum(KernelSumError::Mismatch))
    );
}

#[test]
fn rejects_offset_not_below_the_curve_order() {
    let (_, body) = balanced(&offset(0x31)).into_parts();
    let tx = Transaction::new(offset(0xff), body);
    assert_eq!(
        tx.validate(),
        Err(ValidationError::KernelSum(KernelSumError::InvalidOffset(
            CryptoError::InvalidSecretKey
        )))
    );
}

#[test]
fn names_the_kernel_whose_signature_fails() {
    let features = KernelFeatures::Plain { fee: Fee::new(1) };
    let good = kernel(features, &key(0x61));
    let mut bad = kernel(features, &key(0x62));
    bad.excess_sig = good.excess_sig;
    let body = TransactionBody::new(vec![], vec![], vec![good, bad]);
    let bad_index = body
        .kernels()
        .iter()
        .position(|kernel| kernel.excess == bad.excess)
        .unwrap();
    assert_eq!(
        Transaction::new(BlindingFactor::zero(), body).validate(),
        Err(ValidationError::KernelSignature {
            index: bad_index,
            source: CryptoError::SignatureMismatch,
        })
    );
}

#[test]
fn rejects_kernel_excesses_that_cancel_out() {
    let excess = key(0x71);
    let negated = SecretKey::sum(&[], std::slice::from_ref(&excess)).unwrap();
    let features = KernelFeatures::HeightLocked {
        fee: Fee::ZERO,
        lock_height: Height::new(5),
    };
    let body = TransactionBody::new(
        vec![input(5, 0x11)],
        vec![output(5, 0x12)],
        vec![kernel(features, &excess), kernel(features, &negated)],
    );
    assert_eq!(
        Transaction::new(offset(0x31), body).validate(),
        Err(ValidationError::KernelSum(KernelSumError::Excesses(
            CryptoError::SumIsZero
        )))
    );
}

#[test]
fn rejects_empty_transaction() {
    assert_eq!(
        Transaction::default().validate(),
        Err(ValidationError::KernelSum(KernelSumError::Commitments(
            CryptoError::EmptyBatch {
                item: Item::Commitment
            }
        )))
    );
}

#[test]
fn rejects_transaction_over_the_weight_limit_before_checking_proofs() {
    let (tx_offset, body) = balanced(&offset(0x31)).into_parts();
    let (inputs, outputs, kernels) = body.into_parts();
    let heavy_outputs = outputs.iter().cycle().take(1904).cloned().collect();
    let tx = Transaction::new(
        tx_offset,
        TransactionBody::from_parts(inputs, heavy_outputs, kernels),
    );
    let weight = tx.body().counts().weight_as_block();
    assert!(weight > MAX_TX_WEIGHT);
    assert_eq!(
        tx.validate(),
        Err(ValidationError::Structure(TxError::TooHeavy {
            weight,
            max: MAX_TX_WEIGHT
        }))
    );
}

/// A transaction that breaks both its range proofs and its sums reports the proofs, because
/// upstream verifies them first.
#[test]
fn reports_range_proof_before_kernel_sum() {
    let (_, body) = balanced(&offset(0x31)).into_parts();
    let (inputs, mut outputs, kernels) = body.into_parts();
    let first_proof = outputs[0].proof.clone();
    outputs[0].proof = outputs[1].proof.clone();
    outputs[1].proof = first_proof;
    let tx = Transaction::new(
        offset(0x32),
        TransactionBody::from_parts(inputs, outputs, kernels),
    );
    assert_eq!(
        tx.validate(),
        Err(ValidationError::RangeProof(CryptoError::InvalidRangeProof))
    );
}

#[test]
fn overage_saturates_and_clamps_as_upstream() {
    let fee = |value| KernelFeatures::Plain {
        fee: Fee::new(value),
    };
    let body = TransactionBody::new(
        vec![],
        vec![],
        vec![
            kernel(fee(u64::MAX), &key(0x61)),
            kernel(fee(3), &key(0x62)),
            kernel(KernelFeatures::Coinbase, &key(0x63)),
        ],
    );
    assert_eq!(committed::overage(&body), i64::MAX.unsigned_abs());

    let (_, body) = balanced(&offset(0x31)).into_parts();
    assert_eq!(committed::overage(&body), 10);
}
