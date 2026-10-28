// SPDX-License-Identifier: Apache-2.0
//! Golden vectors for serialization, hashing, transaction types, fees and chain parameters,
//! written by the G-02 generator from the Epic node at the commit each file records.

use std::path::PathBuf;

use lepic_crypto::{Commitment, CryptoError, Message, PublicKey, RangeProof, SecretKey, Signature};
use lepic_primitives::amount::{EPIC_BASE, Fee, Height, MILLI_EPIC};
use lepic_primitives::committed::KernelSumError;
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::hash::{Hash, Hashed, ZERO_HASH, blake2b_256, blake2b_256_keyed};
use lepic_primitives::input::Input;
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_primitives::params::{
    BLOCK_INPUT_WEIGHT, BLOCK_KERNEL_WEIGHT, BLOCK_OUTPUT_WEIGHT, Network,
};
use lepic_primitives::ser::{
    MAX_READ_LEN, ProtocolVersion, Reader, SerError, VecWriter, Writer, deserialize, ser_vec,
};
use lepic_primitives::ser::{Readable, Writeable};
use lepic_primitives::tx::{BodyPart, Transaction, TransactionBody, TxError};
use lepic_primitives::validate::ValidationError;
use serde_json::Value;

const V1: ProtocolVersion = ProtocolVersion::V1;
const V2: ProtocolVersion = ProtocolVersion::V2;
const UPSTREAM_REPO: &str = "https://github.com/EpicCash/epic";
const UPSTREAM_COMMIT: &str = "82fa7e813dc3b9bf137b9dd523d847f4210f5ba4";

// Helpers carry `cfg(test)` so the clippy test allowances (clippy.toml) cover them as they cover
// the `#[test]` functions that call them.

#[cfg(test)]
fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/primitives")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap();
    let vector: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(vector["schema"], 1, "{name}");
    assert_eq!(vector["area"], "primitives", "{name}");
    assert_eq!(vector["name"], name);
    assert_eq!(vector["upstream"]["repo"], UPSTREAM_REPO, "{name}");
    assert_eq!(vector["upstream"]["commit"], UPSTREAM_COMMIT, "{name}");
    vector
}

#[cfg(test)]
fn cases(vector: &Value) -> &[Value] {
    let cases = vector["expected"]["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    cases
}

#[cfg(test)]
fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {case}"))
}

#[cfg(test)]
fn bytes(case: &Value, key: &str) -> Vec<u8> {
    let hex = text(case, key);
    let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty(), "odd hex length for {key} in {case}");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(test)]
fn hash(case: &Value, key: &str) -> Hash {
    Hash::from_hex(text(case, key)).unwrap()
}

/// Splits a tuple value such as `(2,7000000,1000000)` into its fields.
#[cfg(test)]
fn fields(value: &str) -> Vec<&str> {
    value
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or_else(|| panic!("not a tuple: {value}"))
        .split(',')
        .collect()
}

/// Encodes a value of the vector's named type, then decodes the expected bytes back to it.
#[cfg(test)]
fn check_value(type_name: &str, value: &str, encoded: &[u8]) {
    macro_rules! check {
        ($value:expr) => {{
            let value = $value;
            assert_eq!(ser_vec(&value, V2), encoded, "{type_name} {value:?}");
            assert_eq!(deserialize(encoded, V2), Ok(value), "{type_name}");
        }};
    }
    match type_name {
        "u8" => check!(value.parse::<u8>().unwrap()),
        "u16" => check!(value.parse::<u16>().unwrap()),
        "u32" => check!(value.parse::<u32>().unwrap()),
        "i32" => check!(value.parse::<i32>().unwrap()),
        "u64" => check!(value.parse::<u64>().unwrap()),
        "i64" => check!(value.parse::<i64>().unwrap()),
        "protocol_version" => check!(ProtocolVersion::new(value.parse().unwrap())),
        "(u8,u64)" => match fields(value).as_slice() {
            [a, b] => check!((a.parse::<u8>().unwrap(), b.parse::<u64>().unwrap())),
            other => panic!("{type_name} with {other:?}"),
        },
        "(u8,u64,u64)" => match fields(value).as_slice() {
            [a, b, c] => check!((
                a.parse::<u8>().unwrap(),
                b.parse::<u64>().unwrap(),
                c.parse::<u64>().unwrap()
            )),
            other => panic!("{type_name} with {other:?}"),
        },
        "(u64,u64,u64)" => match fields(value).as_slice() {
            [a, b, c] => check!((
                a.parse::<u64>().unwrap(),
                b.parse::<u64>().unwrap(),
                c.parse::<u64>().unwrap()
            )),
            other => panic!("{type_name} with {other:?}"),
        },
        other => panic!("unhandled type {other}"),
    }
}

#[test]
fn ser_integers_match_upstream() {
    let vector = load("ser_integers");
    for case in cases(&vector) {
        check_value(
            text(case, "type"),
            text(case, "value"),
            &bytes(case, "encoded"),
        );
    }
}

#[test]
fn ser_composites_match_upstream() {
    let vector = load("ser_composites");
    for case in cases(&vector) {
        check_value(
            text(case, "type"),
            text(case, "value"),
            &bytes(case, "encoded"),
        );
    }
}

#[test]
fn ser_length_prefixed_bytes_match_upstream() {
    let vector = load("ser_length_prefixed_bytes");
    for case in cases(&vector) {
        assert_eq!(text(case, "type"), "bytes");
        let value = bytes(case, "value");
        let encoded = bytes(case, "encoded");

        let mut writer = VecWriter::new(V2);
        writer.write_bytes(&value);
        assert_eq!(writer.into_bytes(), encoded);

        let mut reader = Reader::new(&encoded, V2);
        assert_eq!(
            reader.read_bytes_len_prefix(MAX_READ_LEN),
            Ok(value.as_slice())
        );
        assert_eq!(reader.finish(), Ok(()));
    }
}

// Upstream reports a short read as `IOErr(UnexpectedEof)`; LEPIC reports `Truncated`.
#[test]
fn ser_truncated_reads_match_upstream() {
    let vector = load("ser_truncated_reads");
    for case in cases(&vector) {
        let input = bytes(case, "bytes");
        let outcome = match text(case, "type") {
            "u8" => deserialize::<u8>(&input, V2).map(drop),
            "u16" => deserialize::<u16>(&input, V2).map(drop),
            "u32" => deserialize::<u32>(&input, V2).map(drop),
            "u64" => deserialize::<u64>(&input, V2).map(drop),
            "(u8,u64)" => deserialize::<(u8, u64)>(&input, V2).map(drop),
            other => panic!("unhandled type {other}"),
        };
        match text(case, "outcome") {
            "ok" => assert_eq!(outcome, Ok(()), "{case}"),
            "IOErr(UnexpectedEof)" => assert!(
                matches!(outcome, Err(SerError::Truncated { .. })),
                "{case} gave {outcome:?}"
            ),
            other => panic!("unhandled outcome {other}"),
        }
    }
}

#[test]
fn hash_bytes_match_upstream() {
    let vector = load("hash_bytes");
    for case in cases(&vector) {
        assert_eq!(
            blake2b_256(&bytes(case, "data")),
            hash(case, "hash"),
            "{case}"
        );
    }
}

#[test]
fn keyed_hash_bytes_match_blake2_rfc() {
    let vector = load("hash_bytes_keyed");
    let mut key_lengths: Vec<usize> = Vec::new();
    for case in cases(&vector) {
        let key = bytes(case, "key");
        let result = blake2b_256_keyed(&key, &bytes(case, "data"));
        assert_eq!(result, Ok(hash(case, "hash")), "{case}");
        key_lengths.push(key.len());
    }
    key_lengths.sort_unstable();
    key_lengths.dedup();
    assert_eq!(key_lengths, [0, 1, 32, 33, 64]);
}

#[test]
fn hash_values_match_upstream() {
    let vector = load("hash_values");
    for case in cases(&vector) {
        let value = text(case, "value");
        let preimage = bytes(case, "preimage");
        let (encoded, hashed) = match text(case, "type") {
            "u8" => {
                let v: u8 = value.parse().unwrap();
                (ser_vec(&v, V2), v.hash())
            }
            "u64" => {
                let v: u64 = value.parse().unwrap();
                (ser_vec(&v, V2), v.hash())
            }
            "(u8,u64)" => {
                let [a, b] = fields(value)[..] else {
                    panic!("{value}")
                };
                let v = (a.parse::<u8>().unwrap(), b.parse::<u64>().unwrap());
                (ser_vec(&v, V2), v.hash())
            }
            "(u8,u64,u64)" => {
                let [a, b, c] = fields(value)[..] else {
                    panic!("{value}")
                };
                let v = (
                    a.parse::<u8>().unwrap(),
                    b.parse::<u64>().unwrap(),
                    c.parse::<u64>().unwrap(),
                );
                (ser_vec(&v, V2), v.hash())
            }
            "hash" => {
                let v = Hash::from_hex(value).unwrap();
                (ser_vec(&v, V2), v.hash())
            }
            "(hash,hash)" => {
                let [a, b] = fields(value)[..] else {
                    panic!("{value}")
                };
                let v = (Hash::from_hex(a).unwrap(), Hash::from_hex(b).unwrap());
                (ser_vec(&v, V2), v.hash())
            }
            other => panic!("unhandled type {other}"),
        };
        assert_eq!(encoded, preimage, "{case}");
        assert_eq!(hashed, hash(case, "hash"), "{case}");
    }
}

// Upstream `Hash + Hash` is the hash of the pair; LEPIC exposes it as `(a, b).hash()`.
#[test]
fn hash_operations_match_upstream() {
    let vector = load("hash_operations");
    let expected = &vector["expected"];
    let abc = blake2b_256(b"abc");
    assert_eq!(ZERO_HASH, hash(expected, "zero_hash"));
    assert_eq!((ZERO_HASH, abc).hash(), hash(expected, "zero_plus_abc"));
    assert_eq!(
        abc.to_u64(),
        text(expected, "abc_to_u64").parse::<u64>().unwrap()
    );
}

// Transaction types, fees and chain parameters (P-02).

#[cfg(test)]
fn decimal(case: &Value, key: &str) -> u64 {
    text(case, key).parse().unwrap()
}

#[cfg(test)]
fn number(case: &Value, key: &str) -> u64 {
    case[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} in {case}"))
}

#[cfg(test)]
fn output_features(name: &str) -> OutputFeatures {
    match name {
        "Plain" => OutputFeatures::Plain,
        "Coinbase" => OutputFeatures::Coinbase,
        other => panic!("unknown output features {other}"),
    }
}

#[cfg(test)]
fn kernel_features(value: &Value) -> KernelFeatures {
    match text(value, "kind") {
        "Plain" => KernelFeatures::Plain {
            fee: Fee::new(decimal(value, "fee")),
        },
        "Coinbase" => KernelFeatures::Coinbase,
        "HeightLocked" => KernelFeatures::HeightLocked {
            fee: Fee::new(decimal(value, "fee")),
            lock_height: Height::new(decimal(value, "lock_height")),
        },
        other => panic!("unknown kernel features {other}"),
    }
}

#[cfg(test)]
fn secret(case: &Value, key: &str) -> SecretKey {
    SecretKey::from_hex(text(case, key)).unwrap()
}

#[cfg(test)]
fn commitment(case: &Value, key: &str) -> Commitment {
    Commitment::from_hex(text(case, key)).unwrap()
}

#[cfg(test)]
fn version(case: &Value) -> ProtocolVersion {
    ProtocolVersion::new(u32::try_from(number(case, "protocol_version")).unwrap())
}

/// Writes `value` at both versions, checks the bytes, and reads each layout back to `value`.
#[cfg(test)]
fn check_both_versions<T>(value: &T, case: &Value)
where
    T: Readable + Writeable + PartialEq + std::fmt::Debug,
{
    for (key, version) in [("serialized_v1", V1), ("serialized_v2", V2)] {
        let encoded = bytes(case, key);
        assert_eq!(ser_vec(value, version), encoded, "{key} of {value:?}");
        assert_eq!(
            deserialize::<T>(&encoded, version).as_ref(),
            Ok(value),
            "{key}"
        );
    }
}

#[cfg(test)]
fn assert_corrupted<T: std::fmt::Debug>(result: &Result<T, SerError>, case: &Value) {
    assert!(
        matches!(result, Err(SerError::Invalid { .. })),
        "{case} gave {result:?}"
    );
}

#[test]
fn crypto_type_encodings_match_upstream() {
    let vector = load("crypto_types");
    let inputs = &vector["inputs"];
    let expected = &vector["expected"];
    let output = &inputs["output"];

    let blind = secret(output, "blind");
    let commit = Commitment::commit(decimal(output, "value"), &blind).unwrap();
    assert_eq!(commit, commitment(expected, "commitment"));
    assert_eq!(ser_vec(&commit, V2), bytes(expected, "commitment_ser"));
    assert_eq!(
        deserialize::<Commitment>(&bytes(expected, "commitment_ser"), V2),
        Ok(commit)
    );

    let factor = BlindingFactor::from_secret_key(&blind);
    assert_eq!(ser_vec(&factor, V2), bytes(expected, "blinding_factor_ser"));
    assert_eq!(
        deserialize::<BlindingFactor>(&bytes(expected, "blinding_factor_ser"), V2),
        Ok(factor.clone())
    );
    assert_eq!(factor.to_hex(), text(output, "blind"));
    assert_eq!(BlindingFactor::from_hex(text(output, "blind")), Ok(factor));

    let public = PublicKey::from_secret_key(&secret(inputs, "sig_key")).unwrap();
    assert_eq!(public.to_hex(), text(expected, "public_key"));
    assert_eq!(ser_vec(&public, V2), bytes(expected, "public_key_ser"));
    assert_eq!(
        deserialize::<PublicKey>(&bytes(expected, "public_key_ser"), V2),
        Ok(public)
    );

    let signature = Signature::from_compact_hex(text(expected, "signature_compact")).unwrap();
    assert_eq!(ser_vec(&signature, V2), bytes(expected, "signature_ser"));
    assert_eq!(
        deserialize::<Signature>(&bytes(expected, "signature_ser"), V2),
        Ok(signature)
    );

    let proof = RangeProof::from_hex(text(expected, "range_proof")).unwrap();
    assert_eq!(ser_vec(&proof, V2), bytes(expected, "range_proof_ser"));
    assert_eq!(
        deserialize::<RangeProof>(&bytes(expected, "range_proof_ser"), V2),
        Ok(proof)
    );
}

#[test]
fn output_feature_bytes_decode_as_upstream() {
    let vector = load("output_features");
    for case in cases(&vector) {
        let encoded = bytes(case, "byte");
        let result = deserialize::<OutputFeatures>(&encoded, V2);
        match text(case, "outcome") {
            "CorruptedData" => assert_corrupted(&result, case),
            name => {
                let features = output_features(name);
                assert_eq!(result, Ok(features), "{case}");
                assert_eq!(ser_vec(&features, V2), encoded);
            }
        }
    }
}

#[test]
fn inputs_match_upstream() {
    let vector = load("inputs");
    for case in cases(&vector) {
        let spec = &case["input"];
        let commit = Commitment::commit(decimal(spec, "value"), &secret(spec, "blind")).unwrap();
        assert_eq!(commit, commitment(case, "commit"));
        let input = Input::new(output_features(text(spec, "features")), commit);
        check_both_versions(&input, case);
        assert_eq!(input.hash(), hash(case, "hash"), "{case}");
    }
}

#[test]
fn outputs_match_upstream() {
    let vector = load("outputs");
    for case in cases(&vector) {
        let spec = &case["output"];
        let commit = Commitment::commit(decimal(spec, "value"), &secret(spec, "blind")).unwrap();
        assert_eq!(commit, commitment(case, "commit"));
        let proof = RangeProof::from_hex(text(case, "proof")).unwrap();
        let output = Output::new(output_features(text(spec, "features")), commit, proof);
        check_both_versions(&output, case);
        assert_eq!(output.hash(), hash(case, "hash"), "{case}");

        let identifier = output.identifier();
        assert_eq!(
            ser_vec(&identifier, V2),
            bytes(case, "identifier_serialized")
        );
        assert_eq!(identifier.hash(), hash(case, "identifier_hash"));
        assert_eq!(Input::from(identifier).hash(), output.hash());
    }
}

#[test]
fn kernel_features_and_signature_messages_match_upstream() {
    let vector = load("kernel_features");
    for case in cases(&vector) {
        let features = kernel_features(&case["features"]);
        check_both_versions(&features, case);
        assert_eq!(
            features.signature_message(),
            Message::from_hex(text(case, "sig_msg")).unwrap(),
            "{case}"
        );
    }
}

// Upstream `CorruptedData` is `Invalid` here and `IOErr(UnexpectedEof)` is `Truncated`.
#[test]
fn kernel_feature_decoding_matches_upstream() {
    let vector = load("kernel_features_decode");
    for case in cases(&vector) {
        let result = deserialize::<KernelFeatures>(&bytes(case, "bytes"), version(case));
        match case["error"].as_str() {
            None => assert_eq!(result, Ok(kernel_features(&case["features"])), "{case}"),
            Some("CorruptedData") => assert_corrupted(&result, case),
            Some("IOErr(UnexpectedEof)") => assert!(
                matches!(result, Err(SerError::Truncated { .. })),
                "{case} gave {result:?}"
            ),
            Some(other) => panic!("unhandled error {other}"),
        }
    }
}

#[test]
fn kernels_match_upstream() {
    let vector = load("kernels");
    for case in cases(&vector) {
        let excess = Commitment::commit(0, &secret(case, "excess_blind")).unwrap();
        assert_eq!(excess, commitment(case, "excess"));
        let kernel = TxKernel::new(
            kernel_features(&case["features"]),
            excess,
            Signature::from_compact_hex(text(case, "excess_sig")).unwrap(),
        );
        assert_eq!(
            kernel.signature_message(),
            Message::from_hex(text(case, "sig_msg")).unwrap()
        );
        check_both_versions(&kernel, case);
        assert_eq!(kernel.hash(), hash(case, "hash"), "{case}");
    }
}

#[test]
fn chain_parameters_match_upstream() {
    for network in Network::ALL {
        let vector = load(&format!("chain_params_{network}"));
        assert_eq!(vector["inputs"]["network"], network.as_str());
        let expected = &vector["expected"];
        let params = network.params();
        assert_eq!(params.network(), network);
        assert_eq!(
            params.coinbase_maturity(),
            decimal(expected, "coinbase_maturity")
        );
        assert_eq!(
            params.max_block_weight(),
            number(expected, "max_block_weight")
        );
        assert_eq!(params.max_tx_weight(), number(expected, "max_tx_weight"));
        assert_eq!(BLOCK_INPUT_WEIGHT, number(expected, "block_input_weight"));
        assert_eq!(BLOCK_OUTPUT_WEIGHT, number(expected, "block_output_weight"));
        assert_eq!(BLOCK_KERNEL_WEIGHT, number(expected, "block_kernel_weight"));
        assert_eq!(
            u64::from(params.protocol_version().value()),
            number(expected, "protocol_version")
        );
        assert_eq!(EPIC_BASE, decimal(expected, "epic_base"));
        assert_eq!(MILLI_EPIC, decimal(expected, "milli_epic"));
        assert_eq!(
            params.default_base_fee(),
            Fee::new(decimal(expected, "default_base_fee"))
        );
    }
}

#[test]
fn weights_and_fees_match_upstream_over_the_grid() {
    let vector = load("fee_grid");
    let base_fee = Network::Mainnet.params().default_base_fee();
    for case in cases(&vector) {
        let counts = BodyCounts::new(
            number(case, "inputs"),
            number(case, "outputs"),
            number(case, "kernels"),
        );
        assert_eq!(counts.tx_weight(), number(case, "weight"), "{case}");
        assert_eq!(
            counts.weight_as_block(),
            number(case, "weight_as_block"),
            "{case}"
        );
        assert_eq!(
            counts.tx_fee(base_fee),
            Ok(Fee::new(decimal(case, "fee"))),
            "{case}"
        );
        assert_eq!(
            counts.tx_fee(Fee::new(1)),
            Ok(Fee::new(decimal(case, "fee_base_1"))),
            "{case}"
        );
    }
}

/// `read_counts` is checked by decoding a body header with the case's counts and no items: a
/// count the reader accepts fails later as truncated input.
#[test]
fn weight_limits_match_upstream() {
    let vector = load("weight_limits");
    for case in cases(&vector) {
        let network = match text(case, "network") {
            "mainnet" => Network::Mainnet,
            "floonet" => Network::Floonet,
            other => panic!("unknown network {other}"),
        };
        let counts = BodyCounts::new(
            number(case, "inputs"),
            number(case, "outputs"),
            number(case, "kernels"),
        );
        let weight = counts.weight_as_block();
        assert_eq!(weight, number(case, "weight_as_block"), "{case}");
        let within_tx_limit = weight <= network.params().max_tx_weight();
        match text(case, "as_transaction") {
            "within_limit" => assert!(within_tx_limit, "{case}"),
            "too_heavy" => assert!(!within_tx_limit, "{case}"),
            other => panic!("unhandled outcome {other}"),
        }

        let header = ser_vec(&(counts.inputs, counts.outputs, counts.kernels), V2);
        let result = deserialize::<TransactionBody>(&header, V2);
        match text(case, "read_counts") {
            "within_limit" => assert!(
                matches!(result, Err(SerError::Truncated { .. })),
                "{case} gave {result:?}"
            ),
            "TooLargeReadErr" => assert!(
                matches!(result, Err(SerError::TooLarge { .. })),
                "{case} gave {result:?}"
            ),
            other => panic!("unhandled outcome {other}"),
        }
    }
}

const TX_VECTORS: [&str; 12] = [
    "tx_valid_plain_1_in_2_out",
    "tx_valid_height_locked_2_in_2_out",
    "tx_valid_spends_coinbase_1_in_1_out",
    "tx_valid_aggregate_two_kernels",
    "tx_invalid_coinbase_kernel",
    "tx_invalid_coinbase_output",
    "tx_invalid_cut_through",
    "tx_invalid_duplicate_outputs",
    "tx_invalid_kernel_signature",
    "tx_invalid_kernel_sum_offset",
    "tx_invalid_range_proof",
    "tx_invalid_unsorted_outputs",
];

/// A transaction vector added later must be listed in `TX_VECTORS`, or this fails.
#[test]
fn every_transaction_vector_is_replayed() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/primitives");
    let mut on_disk: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| {
            name.strip_prefix("tx_")
                .and_then(|rest| rest.strip_suffix(".json"))
                .map(|stem| format!("tx_{stem}"))
        })
        .collect();
    on_disk.sort_unstable();
    let mut listed: Vec<String> = TX_VECTORS.iter().map(ToString::to_string).collect();
    listed.sort_unstable();
    assert_eq!(on_disk, listed);
}

/// Builds the transaction exactly as listed, in the listed order.
#[cfg(test)]
fn transaction(value: &Value) -> Transaction {
    let parts = |key: &str| value[key].as_array().unwrap().iter();
    let inputs = parts("inputs")
        .map(|input| {
            Input::new(
                output_features(text(input, "features")),
                commitment(input, "commit"),
            )
        })
        .collect();
    let outputs = parts("outputs")
        .map(|output| {
            Output::new(
                output_features(text(output, "features")),
                commitment(output, "commit"),
                RangeProof::from_hex(text(output, "proof")).unwrap(),
            )
        })
        .collect();
    let kernels = parts("kernels")
        .map(|kernel| {
            TxKernel::new(
                kernel_features(&kernel["features"]),
                commitment(kernel, "excess"),
                Signature::from_compact_hex(text(kernel, "excess_sig")).unwrap(),
            )
        })
        .collect();
    Transaction::new(
        BlindingFactor::from_hex(text(value, "offset")).unwrap(),
        TransactionBody::from_parts(inputs, outputs, kernels),
    )
}

#[test]
fn transactions_encode_hash_and_weigh_as_upstream() {
    for name in TX_VECTORS {
        let vector = load(name);
        let expected = &vector["expected"];
        let tx = transaction(&expected["transaction"]);
        for (key, version) in [("serialized_v1", V1), ("serialized_v2", V2)] {
            assert_eq!(ser_vec(&tx, version), bytes(expected, key), "{name} {key}");
        }
        assert_eq!(tx.hash(), hash(expected, "hash"), "{name}");
        assert_eq!(tx.fee(), Ok(Fee::new(decimal(expected, "fee"))), "{name}");
        assert_eq!(tx.weight(), number(expected, "weight"), "{name}");
    }
}

/// Decoding runs the node's read checks. A transaction whose only fault is a proof, signature
/// or sum decodes; the others fail with the rule they break.
#[test]
fn transactions_decode_as_upstream() {
    for name in TX_VECTORS {
        let vector = load(name);
        let expected = &vector["expected"];
        let tx = transaction(&expected["transaction"]);
        let rule = expected["validation"]["rule"].as_str();
        for (key, version) in [("serialized_v1", V1), ("serialized_v2", V2)] {
            let encoded = bytes(expected, key);
            let decoded = Transaction::decode(&encoded, version);
            match text(expected, "decode_v2") {
                "ok" => {
                    assert_eq!(decoded.as_ref(), Ok(&tx), "{name} {key}");
                    assert_eq!(
                        deserialize::<Transaction>(&encoded, version),
                        Ok(tx.clone())
                    );
                }
                "CorruptedData" => {
                    let error = decoded.unwrap_err();
                    let expected_error = match rule {
                        Some("sort_order") => TxError::NotSorted {
                            part: BodyPart::Outputs,
                        },
                        Some("duplicate") => TxError::Duplicate {
                            part: BodyPart::Outputs,
                        },
                        Some("cut_through") => TxError::CutThrough,
                        Some("output_features") => TxError::CoinbaseOutput,
                        Some("kernel_features") => TxError::CoinbaseKernel,
                        other => panic!("{name}: no decode error for rule {other:?}"),
                    };
                    assert_eq!(error, expected_error, "{name} {key}");
                    assert!(deserialize::<Transaction>(&encoded, version).is_err());
                    assert_eq!(tx.verify_read(), Err(expected_error), "{name}");
                }
                other => panic!("unhandled outcome {other}"),
            }
        }
    }
}

/// Each valid transaction validates, and each invalid one fails with the rule upstream's
/// `Transaction::validate(Weighting::AsTransaction)` reported.
#[test]
fn transactions_validate_as_upstream() {
    for name in TX_VECTORS {
        let vector = load(name);
        let expected = &vector["expected"];
        let tx = transaction(&expected["transaction"]);
        let result = tx.validate();
        let expected_error = match expected["validation"]["rule"].as_str() {
            None => {
                assert_eq!(expected["validation"]["upstream_error"], Value::Null);
                assert_eq!(result, Ok(()), "{name}");
                continue;
            }
            Some("sort_order") => ValidationError::Structure(TxError::NotSorted {
                part: BodyPart::Outputs,
            }),
            Some("duplicate") => ValidationError::Structure(TxError::Duplicate {
                part: BodyPart::Outputs,
            }),
            Some("cut_through") => ValidationError::Structure(TxError::CutThrough),
            Some("range_proof") => ValidationError::RangeProof(CryptoError::InvalidRangeProof),
            Some("kernel_signature") => ValidationError::KernelSignature {
                index: 0,
                source: CryptoError::SignatureMismatch,
            },
            Some("output_features") => ValidationError::Structure(TxError::CoinbaseOutput),
            Some("kernel_features") => ValidationError::Structure(TxError::CoinbaseKernel),
            Some("kernel_sum") => ValidationError::KernelSum(KernelSumError::Mismatch),
            Some(other) => panic!("{name}: unhandled rule {other}"),
        };
        assert_eq!(result, Err(expected_error), "{name}");
    }
}
