//! Finalize against the G-03 slate vectors: the sender's S1, rebuilt from what its method
//! delivered with the values upstream's test-RNG mode fixes, and the S2 the receiver returned
//! give the final transaction upstream mined and the S3 it wrote, in every encoding.

use lepic_crypto::SecretKey;
use lepic_keychain::{ExtKeyVersion, Identifier, Keychain, SwitchCommitment};
use lepic_primitives::amount::{Amount, Fee, Height, MILLI_EPIC};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::ser::{ProtocolVersion, ser_vec};
use lepic_slate::codec::legacy::v2_json::{LEGACY_V2_JSON, V2JsonCodec};
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::{EncodeError, Unrepresentable};
use lepic_slate::model::Slate;
use lepic_slate::origin::LegacyHeader;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{AccountIndex, KeyId, OutputRecord, OutputStatus};
use lepic_transport::error::FormatError;
use lepic_transport::file::FilePolicy;
use lepic_transport::policy::{Encoding, FormatPolicy, encode_with};
use lepic_wallet::finalize::build_s3;
use lepic_wallet::send::{ChangeOutput, S1Plan, S1Randomness, build_s1};
use serde_json::Value;

use crate::receive_harness::{has_vector, json, standard_cases, text, vector, wire};

const ACCOUNT: AccountIndex = AccountIndex(0);
const BASE_FEE: Fee = Fee::new(MILLI_EPIC);

/// Standard-flow cases G-03 records, each with an S2 and a final transaction.
const G03_STANDARD_CASES: usize = 14;

/// The protocol version of the node's `ProtocolVersion::local()`, which the vectors serialize
/// the final transaction at.
const LOCAL_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V2;

/// In test-RNG mode upstream signs the kernel and the participant message with this nonce.
const UPSTREAM_TEST_NONCE: [u8; 32] = [1; 32];

fn codecs() -> CodecRegistry {
    let mut codecs = CodecRegistry::new();
    codecs
        .register(Box::new(V3JsonCodec::new(BASE_FEE)))
        .unwrap();
    codecs
        .register(Box::new(V2JsonCodec::new(BASE_FEE)))
        .unwrap();
    codecs
}

fn decode(vector: &Value) -> Slate {
    codecs().decode(&wire(&json(vector))).unwrap()
}

fn sender(vector: &Value) -> &Value {
    vector["inputs"]["wallets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|wallet| wallet["role"] == "sender")
        .unwrap()
}

fn key_id(entry: &Value) -> Identifier {
    Identifier::from_hex(text(&entry["key_id"])).unwrap()
}

fn value(entry: &Value) -> u64 {
    text(&entry["value"]).parse().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The sender's S1 as `build_s1` makes it from the slate its method delivered: the recorded
/// inputs and change keys, and the slate id, offset and nonces upstream's test RNG fixed.
fn sender_s1(s1: &Value) -> (Keychain, lepic_wallet::send::BuiltS1) {
    let delivered = decode(s1).with_origin(None);
    let wallet = sender(s1);
    let keychain =
        Keychain::from_mnemonic(text(&wallet["mnemonic"]), ExtKeyVersion::FLOONET).unwrap();
    let features = match text(&s1["inputs"]["options"]["funding"]) {
        "coinbase" => OutputFeatures::Coinbase,
        "change" => OutputFeatures::Plain,
        other => panic!("unknown funding {other}"),
    };
    let inputs = wallet["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let id = key_id(input);
            let amount = value(input);
            OutputRecord {
                id: OutputIdentifier::new(
                    features,
                    keychain
                        .commit(amount, &id, SwitchCommitment::Regular)
                        .unwrap(),
                ),
                key_id: KeyId(id.to_bytes()),
                account: ACCOUNT,
                amount: Amount::new(amount),
                status: OutputStatus::Unspent,
                height: Height::new(1),
                lock_height: Height::ZERO,
                mmr_index: None,
                tx: None,
            }
        })
        .collect();
    let change = wallet["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|output| ChangeOutput {
            key_id: key_id(output),
            amount: Amount::new(value(output)),
        })
        .collect();
    let sender = delivered.participant(Role::Sender).unwrap();
    let plan = S1Plan {
        account: ACCOUNT,
        amount: delivered.amount(),
        fee: delivered.fee(),
        height: delivered.height(),
        lock: delivered.lock(),
        ttl_cutoff_height: delivered.ttl_cutoff_height(),
        inputs,
        change,
        message: sender
            .message
            .as_ref()
            .map(|message| message.text().to_owned()),
        payment_proof_recipient: delivered
            .payment_proof()
            .map(|proof| proof.receiver_address),
    };
    let randomness = S1Randomness {
        slate_id: delivered.id(),
        offset: delivered.offset().to_secret_key().unwrap(),
        nonce: SecretKey::from_array(UPSTREAM_TEST_NONCE).unwrap(),
        message_nonce: SecretKey::from_array(UPSTREAM_TEST_NONCE).unwrap(),
    };
    let built = build_s1(&keychain, &plan, randomness).unwrap();
    assert_eq!(built.slate, delivered, "rebuilt s1");
    (keychain, built)
}

/// Encodes `slate` as `codec` with the header a vector records.
fn encode(codec: CodecId, slate: &Slate, vector: &Value) -> Result<WireSlate, FormatError> {
    let header = &vector["expected"]["header"];
    let field = |name: &str| u16::try_from(header[name].as_u64().unwrap()).unwrap();
    let header = LegacyHeader {
        version: field("version"),
        orig_version: field("orig_version"),
        block_header_version: field("block_header_version"),
    };
    let context = EncodeContext {
        block_header_version: header.block_header_version,
    };
    let encoding = Encoding {
        codec,
        legacy_header: Some(header),
    };
    encode_with(&codecs(), encoding, slate, &context)
}

#[test]
fn each_g03_s2_finalized_with_the_recorded_randomness_yields_the_g03_final_transaction() {
    let cases = standard_cases();
    // Every case with a recorded final transaction is a standard case, and none is lost.
    assert_eq!(cases.len(), G03_STANDARD_CASES, "{cases:?}");
    for case in &cases {
        assert!(has_vector(&format!("{case}_s3_v3")), "{case}");
    }
    let (mut checked_v2, mut checked_file) = (0, 0);
    for case in &cases {
        let s3_v3 = vector(&format!("{case}_s3_v3"));
        let method = text(&s3_v3["inputs"]["method"]).to_owned();
        let (keychain, s1) = sender_s1(&vector(&format!("{case}_s1_{method}")));
        let s2 = decode(&vector(&format!("{case}_s2_{method}")));

        let finalized = build_s3(&keychain, BASE_FEE, &s1, &s2)
            .unwrap_or_else(|error| panic!("{case}: {error:?}"));

        assert_eq!(finalized.slate.stage(), Stage::S3, "{case}");
        assert_eq!(
            hex(&ser_vec(&finalized.transaction, LOCAL_PROTOCOL_VERSION)),
            text(&s3_v3["expected"]["final_tx"]["serialized"]),
            "{case}: final transaction"
        );
        assert_eq!(
            finalized.slate.kernel(),
            finalized.transaction.kernels().first().copied(),
            "{case}: kernel"
        );
        let encoded = encode(LEGACY_V3_JSON, &finalized.slate, &s3_v3).unwrap();
        assert_eq!(encoded.as_text().unwrap(), json(&s3_v3), "{case}: v3");

        let v2_name = format!("{case}_s3_v2");
        if has_vector(&v2_name) {
            let v2 = vector(&v2_name);
            match encode(LEGACY_V2_JSON, &finalized.slate, &v2) {
                Ok(encoded) => {
                    assert_eq!(encoded.as_text().unwrap(), json(&v2), "{case}: v2");
                    checked_v2 += 1;
                }
                // Upstream drops TTL and payment proof when it converts to V2; LEPIC refuses.
                Err(FormatError::Encode(EncodeError::Unrepresentable {
                    what: Unrepresentable::TimeToLive | Unrepresentable::PaymentProof,
                    ..
                })) => {}
                Err(error) => panic!("{case}: v2 {error:?}"),
            }
        }

        let file_name = format!("{case}_s3_file");
        if has_vector(&file_name) {
            let context = EncodeContext {
                block_header_version: s3_v3["expected"]["header"]["block_header_version"]
                    .as_u64()
                    .and_then(|version| u16::try_from(version).ok())
                    .unwrap(),
            };
            let encoded = FilePolicy
                .encode_reply(&codecs(), &finalized.slate, &context)
                .unwrap();
            assert_eq!(
                encoded.as_text().unwrap(),
                json(&vector(&file_name)),
                "{case}: file"
            );
            checked_file += 1;
        }
    }
    assert!(checked_v2 > 0 && checked_file > 0);
}
