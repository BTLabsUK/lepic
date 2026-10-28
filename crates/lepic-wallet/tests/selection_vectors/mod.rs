// SPDX-License-Identifier: Apache-2.0
//! The G-05 selection vectors (`testdata/vectors/engine/selection_*.json`): LEPIC selection over
//! the recorded UTXO set chooses the inputs, fee and change upstream chose, and the account's
//! next output keys are the change keys upstream derived.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use lepic_crypto::Commitment;
use lepic_primitives::amount::{Amount, Fee, Height, MILLI_EPIC};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_store::{
    AccountIndex, AccountRecord, CONTEXT_KEY_LEN, ContextKey, KEY_ID_LEN, KeyId, MemoryStore,
    OutputRecord, OutputStatus, WalletStore,
};
use lepic_wallet::WalletError;
use lepic_wallet::account::next_output_key;
use lepic_wallet::selection::{
    self, SelectionError, SelectionRequest, SelectionStrategy, eligible_to_spend,
};
use serde_json::Value;

const UPSTREAM_REPO: &str = "https://github.com/EpicCash/epic-wallet";
const UPSTREAM_COMMIT: &str = "845b3fcf4df12ed0139929c62157015447a9d063";
const ACCOUNT: AccountIndex = AccountIndex(0);

fn vectors() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/engine");
    let mut vectors: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            name.starts_with("selection_") && name.ends_with(".json")
        })
        .map(|path| {
            let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
            let vector = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            (name, vector)
        })
        .collect();
    vectors.sort_by(|a, b| a.0.cmp(&b.0));
    vectors
}

fn text<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("vector has no text at {pointer}"))
}

fn number(value: &Value, pointer: &str) -> u64 {
    text(value, pointer).parse().unwrap()
}

fn integer(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("vector has no integer at {pointer}"))
}

fn key_id(hex: &str) -> KeyId {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    KeyId(<[u8; KEY_ID_LEN]>::try_from(bytes).unwrap())
}

fn utxo(value: &Value) -> OutputRecord {
    let features = if value["is_coinbase"].as_bool().unwrap() {
        OutputFeatures::Coinbase
    } else {
        OutputFeatures::Plain
    };
    let status = match text(value, "/status") {
        "Unconfirmed" => OutputStatus::Unconfirmed,
        "Unspent" => OutputStatus::Unspent,
        "Locked" => OutputStatus::Locked,
        "Spent" => OutputStatus::Spent,
        other => panic!("unknown output status {other}"),
    };
    OutputRecord {
        id: OutputIdentifier::new(
            features,
            Commitment::from_hex(text(value, "/commit")).unwrap(),
        ),
        key_id: key_id(text(value, "/key_id")),
        account: ACCOUNT,
        amount: Amount::new(number(value, "/value")),
        status,
        height: Height::new(number(value, "/height")),
        lock_height: Height::new(number(value, "/lock_height")),
        mmr_index: None,
        tx: None,
    }
}

fn request(inputs: &Value) -> SelectionRequest {
    let strategy = match text(inputs, "/strategy") {
        "smallest" => SelectionStrategy::Smallest,
        "all" => SelectionStrategy::All,
        other => panic!("unknown strategy {other}"),
    };
    let count =
        |pointer| NonZeroUsize::new(usize::try_from(integer(inputs, pointer)).unwrap()).unwrap();
    SelectionRequest {
        account: ACCOUNT,
        amount: Amount::new(number(inputs, "/amount")),
        tip: Height::new(number(inputs, "/tip_height")),
        minimum_confirmations: number(inputs, "/minimum_confirmations"),
        max_outputs: count("/max_outputs"),
        change_outputs: count("/num_change_outputs"),
        strategy,
        base_fee: Fee::new(MILLI_EPIC),
    }
}

fn not_enough_funds(expected: &Value) -> SelectionError {
    SelectionError::NotEnoughFunds {
        available: Amount::new(number(expected, "/not_enough_funds/available")),
        needed: Amount::new(number(expected, "/not_enough_funds/needed")),
    }
}

/// The keys the account hands out next, when its counter follows the stored outputs as it does
/// in the upstream wallet the vector was recorded from.
fn next_change_keys(utxos: &[OutputRecord], count: usize) -> Vec<KeyId> {
    let store = MemoryStore::new(ContextKey::from_bytes([7; CONTEXT_KEY_LEN]));
    store
        .write(|repos| {
            repos.put_account(&AccountRecord {
                index: ACCOUNT,
                label: "default".to_owned(),
                next_child: u32::try_from(utxos.len()).unwrap(),
            })?;
            (0..count)
                .map(|_| next_output_key(repos, ACCOUNT).map(|id| KeyId(id.to_bytes())))
                .collect::<Result<Vec<_>, WalletError>>()
        })
        .unwrap()
}

fn check(name: &str, vector: &Value) {
    let inputs = &vector["inputs"];
    let utxos: Vec<OutputRecord> = inputs["utxos"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, value)| {
            assert_eq!(integer(value, "/index"), index as u64, "{name}: utxo order");
            utxo(value)
        })
        .collect();
    let request = request(inputs);

    let estimate = selection::estimate(&utxos, &request);
    let expected = &vector["expected"]["estimate"];
    if expected.get("not_enough_funds").is_some() {
        assert_eq!(
            estimate,
            Err(not_enough_funds(expected)),
            "{name}: estimate"
        );
    } else {
        let estimate = estimate.unwrap_or_else(|error| panic!("{name}: estimate: {error}"));
        assert_eq!(
            estimate.total.value(),
            number(expected, "/estimated/total"),
            "{name}: estimated total"
        );
        assert_eq!(
            estimate.fee.value(),
            number(expected, "/estimated/fee"),
            "{name}: estimated fee"
        );
    }

    let selected = selection::select(&utxos, &request);
    let expected = &vector["expected"]["send"];
    if expected.get("not_enough_funds").is_some() {
        assert_eq!(selected, Err(not_enough_funds(expected)), "{name}: send");
        return;
    }
    let selected = selected.unwrap_or_else(|error| panic!("{name}: send: {error}"));
    let expected = &expected["selected"];
    let input_indices: Vec<u64> = selected
        .inputs
        .iter()
        .map(|input| utxos.iter().position(|utxo| utxo == input).unwrap() as u64)
        .collect();
    let expected_indices: Vec<u64> = expected["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap())
        .collect();
    assert_eq!(input_indices, expected_indices, "{name}: inputs");
    assert_eq!(
        selected.amount.value(),
        number(expected, "/amount"),
        "{name}"
    );
    assert_eq!(
        selected.fee.value(),
        number(expected, "/fee"),
        "{name}: fee"
    );
    assert_eq!(
        selected.total.value(),
        number(expected, "/total"),
        "{name}: total"
    );

    let expected_change = expected["change"].as_array().unwrap();
    let change_values: Vec<u64> = selected.change.iter().map(|value| value.value()).collect();
    let expected_values: Vec<u64> = expected_change
        .iter()
        .map(|change| number(change, "/value"))
        .collect();
    assert_eq!(change_values, expected_values, "{name}: change values");
    let expected_keys: Vec<KeyId> = expected_change
        .iter()
        .map(|change| key_id(text(change, "/key_id")))
        .collect();
    assert_eq!(
        next_change_keys(&utxos, selected.change.len()),
        expected_keys,
        "{name}: change keys"
    );
}

#[test]
fn selection_vectors_reproduce_upstream_inputs_fee_and_change() {
    let vectors = vectors();
    assert!(
        vectors.len() >= 14,
        "found {} selection vectors",
        vectors.len()
    );
    for (name, vector) in &vectors {
        assert_eq!(text(vector, "/upstream/repo"), UPSTREAM_REPO, "{name}");
        assert_eq!(text(vector, "/upstream/commit"), UPSTREAM_COMMIT, "{name}");
        check(name, vector);
    }
}

#[test]
fn coinbase_vector_lock_heights_follow_the_recorded_maturity() {
    let vector = vectors()
        .into_iter()
        .find(|(name, _)| name == "selection_coinbase_maturity")
        .unwrap()
        .1;
    let inputs = &vector["inputs"];
    let maturity = number(inputs, "/coinbase_maturity");
    let tip = Height::new(number(inputs, "/tip_height"));
    let eligible: Vec<bool> = inputs["utxos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            let output = utxo(value);
            assert_eq!(output.lock_height.value(), output.height.value() + maturity);
            eligible_to_spend(&output, tip, 1)
        })
        .collect();
    assert_eq!(eligible, [true, false]);
}
