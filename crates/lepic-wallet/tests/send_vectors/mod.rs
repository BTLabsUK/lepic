//! The G-03 S1 vectors (`testdata/vectors/slates/send_*_s1_*.json`): selection over the
//! sender's recorded inputs, then `build_s1` with the values upstream's test RNG mode fixes,
//! gives the S1 upstream wrote, byte for byte, in every encoding a legacy method uses.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use lepic_crypto::SecretKey;
use lepic_keychain::{ExtKeyVersion, Identifier, Keychain, SwitchCommitment};
use lepic_primitives::amount::{Amount, Fee, Height, MILLI_EPIC};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{Codec, EncodeContext};
use lepic_slate::error::EncodeError;
use lepic_slate::model::{KernelLock, ProofAddress, Slate, SlateId};
use lepic_store::{AccountIndex, KeyId, OutputRecord, OutputStatus};
use lepic_transport::file::FilePolicy;
use lepic_transport::policy::FormatPolicy;
use lepic_wallet::selection::{self, SelectionRequest, SelectionStrategy};
use lepic_wallet::send::{ChangeOutput, S1Plan, S1Randomness, build_s1};
use serde_json::Value;

const UPSTREAM_REPO: &str = "https://github.com/EpicCash/epic-wallet";
const UPSTREAM_COMMIT: &str = "465d499f01aad7e570b6cc220d52c6bfcf6a9a44";
const ACCOUNT: AccountIndex = AccountIndex(0);
const BASE_FEE: Fee = Fee::new(MILLI_EPIC);

/// In test RNG mode upstream signs the kernel (`Context::new`) and the participant message
/// (`Slate::add_participant_info`) with this nonce.
const UPSTREAM_TEST_NONCE: [u8; 32] = [1; 32];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/slates")
}

fn load(name: &str) -> Option<Value> {
    let path = dir().join(format!("{name}.json"));
    path.exists()
        .then(|| serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap())
}

/// The cases with an S1, by name without stage and encoding.
fn send_cases() -> Vec<String> {
    let mut cases: Vec<String> = std::fs::read_dir(dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|name| {
            name.strip_suffix("_s1_v3.json")
                .filter(|case| case.starts_with("send_"))
                .map(str::to_owned)
        })
        .collect();
    cases.sort();
    cases
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

fn optional_text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn wallet<'a>(vector: &'a Value, role: &str) -> &'a Value {
    vector["inputs"]["wallets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|wallet| wallet["role"] == role)
        .unwrap_or_else(|| panic!("vector has no {role} wallet"))
}

fn keychain(wallet: &Value) -> Keychain {
    Keychain::from_mnemonic(text(wallet, "/mnemonic"), ExtKeyVersion::FLOONET).unwrap()
}

fn key_id(hex: &str) -> Identifier {
    Identifier::from_hex(hex).unwrap()
}

/// The sender's recorded inputs as the wallet stores them: unspent, confirmed and mature.
fn stored_inputs(
    keychain: &Keychain,
    sender: &Value,
    features: OutputFeatures,
) -> Vec<OutputRecord> {
    sender["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let id = key_id(text(input, "/key_id"));
            let value = number(input, "/value");
            OutputRecord {
                id: OutputIdentifier::new(
                    features,
                    keychain
                        .commit(value, &id, SwitchCommitment::Regular)
                        .unwrap(),
                ),
                key_id: KeyId(id.to_bytes()),
                account: ACCOUNT,
                amount: Amount::new(value),
                status: OutputStatus::Unspent,
                height: Height::new(1),
                lock_height: Height::ZERO,
                mmr_index: None,
                tx: None,
            }
        })
        .collect()
}

/// The receiver's payment proof address, derived from its recorded mnemonic as the receiver
/// derives it.
fn receiver_address(case: &str) -> ProofAddress {
    let s2 = load(&format!("{case}_s2_v3")).unwrap();
    let key = keychain(wallet(&s2, "receiver"))
        .payment_proof_key(&Identifier::new(2, [0, 0, 0, 0]).unwrap(), 0)
        .unwrap();
    ProofAddress::from_bytes(key.public_key()).unwrap()
}

/// Builds the case's S1 the way `Wallet::send` does, from what the vector records as inputs.
fn build(case: &str, v3: &Value) -> (Slate, EncodeContext) {
    let options = &v3["inputs"]["options"];
    let sender = wallet(v3, "sender");
    let keychain = keychain(sender);
    let expected: Value = serde_json::from_str(text(v3, "/expected/json")).unwrap();
    // The chain tip upstream saw is the height it wrote into the slate.
    let tip = Height::new(number(&expected, "/height"));
    let features = match text(options, "/funding") {
        "coinbase" => OutputFeatures::Coinbase,
        "change" => OutputFeatures::Plain,
        other => panic!("unknown funding {other}"),
    };
    let records = stored_inputs(&keychain, sender, features);
    let strategy = match text(options, "/selection_strategy") {
        "smallest" => SelectionStrategy::Smallest,
        "all" => SelectionStrategy::All,
        other => panic!("unknown strategy {other}"),
    };
    let amount = Amount::new(number(options, "/amount"));
    let change_outputs = usize::try_from(options["change_outputs"].as_u64().unwrap()).unwrap();
    let selected = selection::select(
        &records,
        &SelectionRequest {
            account: ACCOUNT,
            amount,
            tip,
            minimum_confirmations: number(options, "/minimum_confirmations"),
            max_outputs: NonZeroUsize::new(500).unwrap(),
            change_outputs: NonZeroUsize::new(change_outputs).unwrap(),
            strategy,
            base_fee: BASE_FEE,
        },
    )
    .unwrap();
    assert_eq!(selected.inputs, records, "{case}: inputs");

    // The change keys are the next keys of the account, which upstream recorded.
    let recorded_change = sender["outputs"].as_array().unwrap();
    assert_eq!(
        selected.change.len(),
        recorded_change.len(),
        "{case}: change"
    );
    let change = recorded_change
        .iter()
        .zip(&selected.change)
        .map(|(output, &value)| {
            assert_eq!(
                value.value(),
                number(output, "/value"),
                "{case}: change value"
            );
            ChangeOutput {
                key_id: key_id(text(output, "/key_id")),
                amount: value,
            }
        })
        .collect();

    let ttl_cutoff_height = optional_text(options, "/ttl_blocks")
        .map(|blocks| tip.checked_add_blocks(blocks.parse().unwrap()).unwrap());
    let plan = S1Plan {
        account: ACCOUNT,
        amount,
        fee: selected.fee,
        height: tip,
        lock: optional_text(options, "/lock_height").map_or(KernelLock::NONE, |height| {
            KernelLock::at_height(Height::new(height.parse().unwrap()))
        }),
        ttl_cutoff_height,
        inputs: selected.inputs,
        change,
        message: optional_text(options, "/initiator_message").map(str::to_owned),
        payment_proof_recipient: options["payment_proof"]
            .as_bool()
            .unwrap()
            .then(|| receiver_address(case)),
    };
    let randomness = S1Randomness {
        slate_id: SlateId::parse(text(v3, "/expected/slate_id")).unwrap(),
        offset: SecretKey::from_bytes(&bytes(text(&expected, "/tx/offset"))).unwrap(),
        nonce: SecretKey::from_array(UPSTREAM_TEST_NONCE).unwrap(),
        message_nonce: SecretKey::from_array(UPSTREAM_TEST_NONCE).unwrap(),
    };
    let built = build_s1(&keychain, &plan, randomness).unwrap();
    let block_header_version = v3["expected"]["header"]["block_header_version"]
        .as_u64()
        .unwrap();
    let context = EncodeContext {
        block_header_version: u16::try_from(block_header_version).unwrap(),
    };
    (built.slate, context)
}

fn expected_json(vector: &Value) -> &str {
    text(vector, "/expected/json")
}

fn assert_unrepresentable(result: &Result<impl std::fmt::Debug, EncodeError>, case: &str) {
    assert!(
        matches!(result, Err(EncodeError::Unrepresentable { .. })),
        "{case}: {result:?}"
    );
}

#[test]
fn s1_vectors_come_from_the_pinned_upstream() {
    let cases = send_cases();
    assert!(cases.len() >= 13, "{cases:?}");
    for case in cases {
        let vector = load(&format!("{case}_s1_v3")).unwrap();
        assert_eq!(text(&vector, "/upstream/repo"), UPSTREAM_REPO, "{case}");
        assert_eq!(text(&vector, "/upstream/commit"), UPSTREAM_COMMIT, "{case}");
        assert_eq!(text(&vector, "/inputs/stage"), "S1", "{case}");
        assert_eq!(
            vector["expected"]["randomized"],
            Value::Array(Vec::new()),
            "{case}"
        );
    }
}

#[test]
fn built_s1_matches_every_upstream_s1_encoding() {
    for case in send_cases() {
        let v3 = load(&format!("{case}_s1_v3")).unwrap();
        let (slate, context) = build(&case, &v3);
        let carries_v3_fields =
            slate.ttl_cutoff_height().is_some() || slate.payment_proof().is_some();

        let encoded = V3JsonCodec::new(BASE_FEE).encode(&slate, &context).unwrap();
        assert_eq!(
            encoded.as_text().unwrap(),
            expected_json(&v3),
            "{case}_s1_v3"
        );

        let v2 = V2JsonCodec::new(BASE_FEE).encode(&slate, &context);
        // Upstream's V2 conversion drops TTL and payment proof; LEPIC refuses instead.
        for name in [format!("{case}_s1_v2"), format!("{case}_s1_epicbox")] {
            let Some(vector) = load(&name) else { continue };
            if carries_v3_fields {
                assert_unrepresentable(&v2, &name);
            } else {
                assert_eq!(
                    v2.as_ref().unwrap().as_text().unwrap(),
                    expected_json(&vector),
                    "{name}"
                );
            }
        }

        if let Some(vector) = load(&format!("{case}_s1_file")) {
            let file = FilePolicy
                .encode_new_slate(&legacy_codecs(), &slate, &context)
                .unwrap();
            assert_eq!(
                file.as_text().unwrap(),
                expected_json(&vector),
                "{case}_s1_file"
            );
        }
    }
}

fn legacy_codecs() -> lepic_slate::registry::CodecRegistry {
    let mut codecs = lepic_slate::registry::CodecRegistry::new();
    codecs
        .register(Box::new(V2JsonCodec::new(BASE_FEE)))
        .unwrap();
    codecs
        .register(Box::new(V3JsonCodec::new(BASE_FEE)))
        .unwrap();
    codecs
}
