use lepic_crypto::{Commitment, PublicKey, RangeProof, SecretKey, Signature};
use lepic_primitives::amount::{ArithmeticError, Fee, Height};
use lepic_primitives::crypto_ser::{BlindingFactor, BlindingFactorError};
use lepic_primitives::hash::Hashed;
use lepic_primitives::input::Input;
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_primitives::ser::{ProtocolVersion, Readable, SerError, Writeable, deserialize, ser_vec};
use lepic_primitives::tx::{BodyPart, Transaction, TransactionBody, TxError};
use proptest::prelude::*;

const V1: ProtocolVersion = ProtocolVersion::V1;
const V2: ProtocolVersion = ProtocolVersion::V2;

#[cfg(test)]
fn key(byte: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    bytes[0] = 1;
    SecretKey::from_array(bytes).unwrap()
}

#[cfg(test)]
fn commit(value: u64, byte: u8) -> Commitment {
    Commitment::commit(value, &key(byte)).unwrap()
}

#[cfg(test)]
fn input(byte: u8) -> Input {
    Input::new(OutputFeatures::Plain, commit(1, byte))
}

#[cfg(test)]
fn output(byte: u8) -> Output {
    Output::new(
        OutputFeatures::Plain,
        commit(2, byte),
        RangeProof::from_bytes(&[byte; 675]).unwrap(),
    )
}

#[cfg(test)]
fn kernel(fee: u64, byte: u8) -> TxKernel {
    TxKernel::new(
        KernelFeatures::Plain { fee: Fee::new(fee) },
        commit(0, byte),
        Signature::from_raw(&[byte; 64]).unwrap(),
    )
}

#[cfg(test)]
fn transaction(inputs: Vec<Input>, outputs: Vec<Output>, kernels: Vec<TxKernel>) -> Transaction {
    Transaction::new(
        BlindingFactor::from_array([7; 32]),
        TransactionBody::new(inputs, outputs, kernels),
    )
}

#[cfg(test)]
fn round_trip<T: Readable + Writeable + PartialEq + std::fmt::Debug>(value: &T) {
    for version in [V1, V2] {
        let bytes = ser_vec(value, version);
        assert_eq!(deserialize::<T>(&bytes, version).as_ref(), Ok(value));
    }
}

#[cfg(test)]
fn assert_prefixes_fail<T: Readable + std::fmt::Debug>(bytes: &[u8], version: ProtocolVersion) {
    let mut prefix = bytes;
    while let Some((_, shorter)) = prefix.split_last() {
        prefix = shorter;
        let result = deserialize::<T>(prefix, version);
        assert!(
            matches!(result, Err(SerError::Truncated { .. })),
            "prefix of {} bytes gave {result:?}",
            prefix.len()
        );
    }
}

#[cfg(test)]
fn secret_key() -> impl Strategy<Value = SecretKey> {
    any::<[u8; 32]>().prop_filter_map("not a valid scalar", |bytes| {
        SecretKey::from_array(bytes).ok()
    })
}

#[cfg(test)]
fn commitment() -> impl Strategy<Value = Commitment> {
    (any::<u64>(), secret_key()).prop_filter_map("commits to infinity", |(value, key)| {
        Commitment::commit(value, &key).ok()
    })
}

#[cfg(test)]
fn output_features() -> impl Strategy<Value = OutputFeatures> {
    prop_oneof![Just(OutputFeatures::Plain), Just(OutputFeatures::Coinbase)]
}

#[cfg(test)]
fn kernel_features() -> impl Strategy<Value = KernelFeatures> {
    prop_oneof![
        any::<u64>().prop_map(|fee| KernelFeatures::Plain { fee: Fee::new(fee) }),
        Just(KernelFeatures::Coinbase),
        (any::<u64>(), any::<u64>()).prop_map(|(fee, height)| KernelFeatures::HeightLocked {
            fee: Fee::new(fee),
            lock_height: Height::new(height),
        }),
    ]
}

#[cfg(test)]
fn range_proof() -> impl Strategy<Value = RangeProof> {
    proptest::collection::vec(any::<u8>(), 1..=RangeProof::MAX_LEN)
        .prop_map(|bytes| RangeProof::from_bytes(&bytes).unwrap())
}

#[cfg(test)]
fn signature() -> impl Strategy<Value = Signature> {
    any::<[u8; 64]>().prop_map(|bytes| Signature::from_raw(&bytes).unwrap())
}

#[cfg(test)]
fn tx_kernel() -> impl Strategy<Value = TxKernel> {
    (kernel_features(), commitment(), signature())
        .prop_map(|(features, excess, sig)| TxKernel::new(features, excess, sig))
}

#[cfg(test)]
fn tx_output() -> impl Strategy<Value = Output> {
    (output_features(), commitment(), range_proof())
        .prop_map(|(features, commitment, proof)| Output::new(features, commitment, proof))
}

#[cfg(test)]
fn tx_input() -> impl Strategy<Value = Input> {
    (output_features(), commitment())
        .prop_map(|(features, commitment)| Input::new(features, commitment))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn kernel_features_round_trip(features in kernel_features()) {
        round_trip(&features);
    }

    #[test]
    fn kernels_round_trip(kernel in tx_kernel()) {
        round_trip(&kernel);
    }

    #[test]
    fn inputs_round_trip(input in tx_input()) {
        round_trip(&input);
    }

    #[test]
    fn outputs_round_trip(output in tx_output()) {
        round_trip(&output);
    }

    #[test]
    fn output_hash_ignores_the_proof(output in tx_output(), proof in range_proof()) {
        let other = Output::new(output.features, output.commitment, proof);
        prop_assert_eq!(output.hash(), other.hash());
        prop_assert_eq!(output.hash(), output.identifier().hash());
    }

    #[test]
    fn blinding_factors_round_trip(bytes in any::<[u8; 32]>()) {
        let factor = BlindingFactor::from_array(bytes);
        round_trip(&factor);
        prop_assert_eq!(BlindingFactor::from_hex(&factor.to_hex()), Ok(factor.clone()));
        prop_assert_eq!(BlindingFactor::from_hex(&factor.to_hex().to_uppercase()), Ok(factor));
    }

    #[test]
    fn public_keys_round_trip(key in secret_key()) {
        round_trip(&PublicKey::from_secret_key(&key).unwrap());
    }

    #[test]
    fn plain_transactions_round_trip(
        inputs in proptest::collection::vec(
            commitment().prop_map(|c| Input::new(OutputFeatures::Plain, c)), 0..4),
        outputs in proptest::collection::vec(
            (commitment(), range_proof())
                .prop_map(|(c, p)| Output::new(OutputFeatures::Plain, c, p)), 0..4),
        fees in proptest::collection::vec(any::<u32>(), 0..3),
        offset in any::<[u8; 32]>(),
    ) {
        let kernels = fees
            .iter()
            .zip(1u8..)
            .map(|(fee, byte)| kernel(u64::from(*fee), byte))
            .collect();
        let tx = Transaction::new(
            BlindingFactor::from_array(offset),
            TransactionBody::new(inputs, outputs, kernels),
        );
        prop_assume!(tx.verify_read().is_ok());
        for version in [V1, V2] {
            let bytes = ser_vec(&tx, version);
            prop_assert_eq!(Transaction::decode(&bytes, version), Ok(tx.clone()));
            prop_assert_eq!(deserialize::<Transaction>(&bytes, version), Ok(tx.clone()));
        }
    }
}

#[test]
fn rejects_truncated_parts() {
    let tx = transaction(vec![input(1)], vec![output(2)], vec![kernel(5, 3)]);
    for version in [V1, V2] {
        assert_prefixes_fail::<Input>(&ser_vec(&input(1), version), version);
        assert_prefixes_fail::<Output>(&ser_vec(&output(2), version), version);
        assert_prefixes_fail::<TxKernel>(&ser_vec(&kernel(5, 3), version), version);
        assert_prefixes_fail::<Transaction>(&ser_vec(&tx, version), version);
    }
}

#[test]
fn rejects_trailing_bytes() {
    let mut bytes = ser_vec(
        &transaction(vec![], vec![output(2)], vec![kernel(5, 3)]),
        V2,
    );
    bytes.push(0);
    assert_eq!(
        Transaction::decode(&bytes, V2),
        Err(TxError::Encoding(SerError::TrailingBytes { remaining: 1 }))
    );
}

#[test]
fn rejects_range_proof_longer_than_the_maximum() {
    let mut bytes = ser_vec(&u64::try_from(RangeProof::MAX_LEN + 1).unwrap(), V2);
    bytes.extend(vec![0u8; RangeProof::MAX_LEN + 1]);
    assert!(matches!(
        deserialize::<RangeProof>(&bytes, V2),
        Err(SerError::TooLarge { .. })
    ));
}

#[test]
fn rejects_range_proof_length_beyond_the_input() {
    let mut bytes = ser_vec(&675u64, V2);
    bytes.extend([0u8; 10]);
    assert!(matches!(
        deserialize::<RangeProof>(&bytes, V2),
        Err(SerError::Truncated { .. })
    ));
}

#[test]
fn rejects_empty_range_proof() {
    assert_eq!(
        deserialize::<RangeProof>(&ser_vec(&0u64, V2), V2),
        Err(SerError::Invalid {
            type_name: "range proof"
        })
    );
}

#[test]
fn rejects_commitment_that_is_not_a_curve_point() {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x08;
    bytes[32] = 5;
    assert_eq!(
        deserialize::<Commitment>(&bytes, V2),
        Err(SerError::Invalid {
            type_name: "commitment"
        })
    );
    let mut encoded = vec![0u8];
    encoded.extend(bytes);
    assert_eq!(
        deserialize::<Input>(&encoded, V2),
        Err(SerError::Invalid {
            type_name: "commitment"
        })
    );
}

#[test]
fn rejects_public_key_that_is_not_a_curve_point() {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x05;
    assert_eq!(
        deserialize::<PublicKey>(&bytes, V2),
        Err(SerError::Invalid {
            type_name: "public key"
        })
    );
}

#[test]
fn rejects_body_counts_above_the_block_weight() {
    let header = ser_vec(&(u64::MAX, u64::MAX, u64::MAX), V2);
    assert!(matches!(
        deserialize::<TransactionBody>(&header, V2),
        Err(SerError::TooLarge { .. })
    ));
}

#[test]
fn rejects_transaction_above_the_transaction_weight() {
    let inputs = vec![input(1); 39_974];
    let tx = Transaction::new(
        BlindingFactor::zero(),
        TransactionBody::from_parts(inputs, vec![], vec![kernel(1, 2)]),
    );
    assert_eq!(
        tx.verify_read(),
        Err(TxError::TooHeavy {
            weight: 39_977,
            max: 39_976
        })
    );
}

#[test]
fn rejects_unsorted_and_duplicate_parts() {
    let mut kernels = vec![kernel(1, 1), kernel(2, 2)];
    kernels.sort_by_cached_key(Hashed::hash);
    kernels.reverse();
    let unsorted = Transaction::new(
        BlindingFactor::zero(),
        TransactionBody::from_parts(vec![], vec![output(3)], kernels),
    );
    let expected = TxError::NotSorted {
        part: BodyPart::Kernels,
    };
    assert_eq!(unsorted.verify_read(), Err(expected));
    assert_eq!(
        Transaction::decode(&ser_vec(&unsorted, V2), V2),
        Err(expected)
    );
    assert_eq!(
        deserialize::<Transaction>(&ser_vec(&unsorted, V2), V2),
        Err(SerError::NotSorted)
    );

    let duplicate = Transaction::new(
        BlindingFactor::zero(),
        TransactionBody::from_parts(vec![input(4), input(4)], vec![], vec![kernel(1, 1)]),
    );
    let expected = TxError::Duplicate {
        part: BodyPart::Inputs,
    };
    assert_eq!(duplicate.verify_read(), Err(expected));
    assert_eq!(
        Transaction::decode(&ser_vec(&duplicate, V2), V2),
        Err(expected)
    );
}

#[test]
fn rejects_input_spending_an_output_of_the_same_transaction() {
    let spent = output(5);
    let tx = transaction(
        vec![Input::from(spent.identifier())],
        vec![spent],
        vec![kernel(1, 1)],
    );
    assert_eq!(tx.verify_read(), Err(TxError::CutThrough));
    assert_eq!(
        Transaction::decode(&ser_vec(&tx, V2), V2),
        Err(TxError::CutThrough)
    );
    assert_eq!(
        deserialize::<Transaction>(&ser_vec(&tx, V2), V2),
        Err(SerError::Invalid {
            type_name: "transaction"
        })
    );
}

#[test]
fn rejects_coinbase_outputs_and_kernels() {
    let mut coinbase_output = output(1);
    coinbase_output.features = OutputFeatures::Coinbase;
    let tx = transaction(vec![], vec![coinbase_output], vec![kernel(1, 1)]);
    assert_eq!(tx.verify_read(), Err(TxError::CoinbaseOutput));

    let mut coinbase_kernel = kernel(0, 1);
    coinbase_kernel.features = KernelFeatures::Coinbase;
    let tx = transaction(vec![], vec![output(1)], vec![coinbase_kernel]);
    assert_eq!(tx.verify_read(), Err(TxError::CoinbaseKernel));
}

#[test]
fn new_body_sorts_every_part() {
    let body = TransactionBody::new(
        (1..=5).map(input).collect(),
        (1..=5).map(output).collect(),
        (1..=5).map(|byte| kernel(1, byte)).collect(),
    );
    assert_eq!(body.verify_sorted(), Ok(()));
}

#[test]
fn fee_sums_kernel_fees_and_rejects_overflow() {
    let tx = transaction(vec![], vec![], vec![kernel(3, 1), kernel(4, 2)]);
    assert_eq!(tx.fee(), Ok(Fee::new(7)));

    let tx = transaction(vec![], vec![], vec![kernel(u64::MAX, 1), kernel(1, 2)]);
    assert_eq!(tx.fee(), Err(ArithmeticError::Overflow));
}

#[test]
fn lock_height_is_the_highest_kernel_lock_height() {
    let locked = |height, byte| {
        let mut kernel = kernel(1, byte);
        kernel.features = KernelFeatures::HeightLocked {
            fee: Fee::new(1),
            lock_height: Height::new(height),
        };
        kernel
    };
    let tx = transaction(
        vec![],
        vec![],
        vec![locked(9, 1), kernel(1, 2), locked(4, 3)],
    );
    assert_eq!(tx.lock_height(), Height::new(9));
    assert_eq!(
        transaction(vec![], vec![], vec![kernel(1, 2)]).lock_height(),
        Height::ZERO
    );
}

#[test]
fn blinding_factor_allows_zero_but_not_as_a_secret_key() {
    let zero = BlindingFactor::zero();
    assert!(zero.is_zero());
    assert_eq!(
        deserialize::<BlindingFactor>(&[0; 32], V2),
        Ok(zero.clone())
    );
    assert!(zero.to_secret_key().is_err());
    assert_eq!(
        BlindingFactor::from_secret_key(&key(9))
            .to_secret_key()
            .unwrap()
            .expose_bytes(),
        key(9).expose_bytes()
    );
}

#[test]
fn rejects_malformed_blinding_factors() {
    assert_eq!(
        BlindingFactor::from_bytes(&[1; 31]),
        Err(BlindingFactorError::WrongLength { actual: 31 })
    );
    assert_eq!(
        BlindingFactor::from_hex("00"),
        Err(BlindingFactorError::WrongHexLength { actual: 2 })
    );
    assert_eq!(
        BlindingFactor::from_hex(&"zz".repeat(32)),
        Err(BlindingFactorError::InvalidHex)
    );
}

#[test]
fn blinding_factor_debug_hides_bytes() {
    let factor = BlindingFactor::from_array([0xab; 32]);
    assert_eq!(format!("{factor:?}"), "BlindingFactor([redacted])");
    let tx = Transaction::new(factor, TransactionBody::default());
    assert!(!format!("{tx:?}").contains("ab"));
}
