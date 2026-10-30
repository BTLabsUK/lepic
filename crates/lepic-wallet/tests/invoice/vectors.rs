// SPDX-License-Identifier: Apache-2.0
//! The invoice flow against the G-03 invoice vectors (`testdata/vectors/slates/invoice_*`):
//! each stage, built with the values upstream's test-RNG mode fixes from the slate the previous
//! party's file carried, gives the slate upstream wrote in every encoding, and the I3 gives the
//! final transaction upstream mined. The payer's step is also replayed through the engine.

use std::num::NonZeroUsize;

use lepic_crypto::SecretKey;
use lepic_keychain::{Identifier, Keychain, SwitchCommitment};
use lepic_node::mock::{ChainState, MockNode};
use lepic_node::{NodeVersion, Tip};
use lepic_primitives::amount::{Amount, Fee, Height, MILLI_EPIC};
use lepic_primitives::hash::Hash;
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_primitives::ser::{ProtocolVersion, ser_vec};
use lepic_slate::codec::legacy::v2_json::{LEGACY_V2_JSON, V2JsonCodec};
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::{EncodeError, Unrepresentable};
use lepic_slate::model::{Slate, SlateId};
use lepic_slate::origin::LegacyHeader;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::stage::Stage;
use lepic_store::{KeyId, OutputRecord, OutputStatus, SlateStage, TxDirection, TxState};
use lepic_transport::error::FormatError;
use lepic_transport::file::FilePolicy;
use lepic_transport::policy::{Encoding, FormatPolicy, encode_with};
use lepic_wallet::invoice::{
    BuiltI1, I1Plan, I1Randomness, I2Plan, I2Randomness, InvoiceError, InvoiceField, PayRequest,
    build_i1, build_i2, build_i3,
};
use lepic_wallet::selection::{self, SelectionRequest, SelectionStrategy};
use lepic_wallet::send::ChangeOutput;
use serde_json::Value;
use uuid::Uuid;

use crate::invoice_harness::{ACCOUNT, FUNDING, Party};
use crate::receive_harness::{has_vector, json, text, vector, vector_dir, wire};
use crate::support::as_file_v3;

const BASE_FEE: Fee = Fee::new(MILLI_EPIC);

/// Invoice cases G-03 records.
const G03_INVOICE_CASES: usize = 4;

/// The protocol version of the node's `ProtocolVersion::local()`, which the vectors serialize
/// the final transaction at.
const LOCAL_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V2;

/// In test-RNG mode upstream signs the kernel and the participant message with this nonce.
const UPSTREAM_TEST_NONCE: [u8; 32] = [1; 32];

fn invoice_cases() -> Vec<String> {
    let mut cases: Vec<String> = std::fs::read_dir(vector_dir())
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            let case = name.strip_suffix("_i1_v3.json")?;
            case.starts_with("invoice_").then(|| case.to_owned())
        })
        .collect();
    cases.sort();
    cases
}

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

/// The slate a file of the case carried, read as the file method reads it.
fn read_file(case: &str, stage: &str) -> Slate {
    FilePolicy
        .decode(
            &codecs(),
            &wire(&json(&vector(&format!("{case}_{stage}_file")))),
        )
        .unwrap()
}

fn party<'a>(vector: &'a Value, role: &str) -> &'a Value {
    vector["inputs"]["wallets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|wallet| wallet["role"] == role)
        .unwrap_or_else(|| panic!("vector has no {role}"))
}

fn keychain(party: &Value) -> Keychain {
    Keychain::from_mnemonic(text(&party["mnemonic"]), Network::Floonet).unwrap()
}

fn key_id(entry: &Value) -> Identifier {
    Identifier::from_hex(text(&entry["key_id"])).unwrap()
}

fn value(entry: &Value) -> u64 {
    text(&entry["value"]).parse().unwrap()
}

fn option(vector: &Value, name: &str) -> Option<String> {
    vector["inputs"]["options"][name]
        .as_str()
        .map(str::to_owned)
}

fn slate_json(vector: &Value) -> Value {
    serde_json::from_str(&json(vector)).unwrap()
}

fn number(value: &Value) -> u64 {
    match value {
        Value::String(text) => text.parse().unwrap(),
        other => other.as_u64().unwrap(),
    }
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn header(vector: &Value) -> LegacyHeader {
    let header = &vector["expected"]["header"];
    let field = |name: &str| u16::try_from(header[name].as_u64().unwrap()).unwrap();
    LegacyHeader {
        version: field("version"),
        orig_version: field("orig_version"),
        block_header_version: field("block_header_version"),
    }
}

/// Encodes `slate` as `codec` with the header a vector records.
fn encode(codec: CodecId, slate: &Slate, vector: &Value) -> Result<WireSlate, FormatError> {
    let header = header(vector);
    let context = EncodeContext {
        block_header_version: header.block_header_version,
    };
    let encoding = Encoding {
        codec,
        legacy_header: Some(header),
    };
    encode_with(&codecs(), encoding, slate, &context)
}

/// Checks `slate` against the case's V3 and V2 vectors of `stage`, and `file` against the V3
/// vector with header 3 (ADR 0015). Upstream's V2 conversion drops a TTL; LEPIC refuses instead.
fn assert_encodings(case: &str, stage: &str, slate: &Slate, file: &WireSlate) {
    let v3 = vector(&format!("{case}_{stage}_v3"));
    let encoded = encode(LEGACY_V3_JSON, slate, &v3).unwrap();
    assert_eq!(encoded.as_text().unwrap(), json(&v3), "{case}_{stage}_v3");

    let v2 = vector(&format!("{case}_{stage}_v2"));
    match encode(LEGACY_V2_JSON, slate, &v2) {
        Ok(encoded) => assert_eq!(encoded.as_text().unwrap(), json(&v2), "{case}_{stage}_v2"),
        Err(FormatError::Encode(EncodeError::Unrepresentable {
            what: Unrepresentable::TimeToLive,
            ..
        })) => assert!(slate.ttl_cutoff_height().is_some(), "{case}_{stage}_v2"),
        Err(error) => panic!("{case}_{stage}_v2: {error:?}"),
    }

    assert_eq!(
        file.as_text().unwrap(),
        as_file_v3(&json(&v3)),
        "{case}_{stage}_file"
    );
}

/// The issuer's I1 of a case, with the slate id, offset and nonces upstream's test RNG fixed.
fn issue(case: &str) -> (BuiltI1, EncodeContext) {
    let v3 = vector(&format!("{case}_i1_v3"));
    let issuer = party(&v3, "issuer");
    let outputs = issuer["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 1, "{case}");
    let expected = slate_json(&v3);
    let plan = I1Plan {
        account: ACCOUNT,
        amount: Amount::new(number(&expected["amount"])),
        height: Height::new(number(&expected["height"])),
        ttl_cutoff_height: None,
        key_id: key_id(&outputs[0]),
        message: option(&v3, "initiator_message"),
    };
    assert_eq!(plan.amount.value(), value(&outputs[0]), "{case}: amount");
    let randomness = I1Randomness {
        slate_id: SlateId::parse(text(&v3["expected"]["slate_id"])).unwrap(),
        offset: SecretKey::from_bytes(&bytes(text(&expected["tx"]["offset"]))).unwrap(),
        nonce: SecretKey::from_array(UPSTREAM_TEST_NONCE).unwrap(),
        message_nonce: SecretKey::from_array(UPSTREAM_TEST_NONCE).unwrap(),
    };
    let built = build_i1(&keychain(issuer), &plan, randomness).unwrap();
    let context = EncodeContext {
        block_header_version: header(&v3).block_header_version,
    };
    (built, context)
}

/// The payer's recorded inputs as the wallet stores them: unspent, confirmed and mature.
fn stored_inputs(keychain: &Keychain, payer: &Value) -> Vec<OutputRecord> {
    payer["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let id = key_id(input);
            let amount = value(input);
            OutputRecord {
                id: OutputIdentifier::new(
                    OutputFeatures::Coinbase,
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
        .collect()
}

/// The payer's I2 of a case, built the way `Wallet::pay_invoice` builds it from the I1 file.
fn pay(case: &str, i1: &Slate) -> Slate {
    let v3 = vector(&format!("{case}_i2_v3"));
    let payer = party(&v3, "payer");
    let keychain = keychain(payer);
    let options = &v3["inputs"]["options"];
    assert_eq!(text(&options["selection_strategy"]), "smallest", "{case}");
    assert_eq!(text(&options["funding"]), "coinbase", "{case}");
    // The chain tip the payer saw is the height it wrote into the slate.
    let tip = Height::new(number(&slate_json(&v3)["height"]));
    let records = stored_inputs(&keychain, payer);
    let selected = selection::select(
        &records,
        &SelectionRequest {
            account: ACCOUNT,
            amount: i1.amount(),
            tip,
            minimum_confirmations: text(&options["minimum_confirmations"]).parse().unwrap(),
            max_outputs: NonZeroUsize::new(500).unwrap(),
            change_outputs: NonZeroUsize::new(
                usize::try_from(options["change_outputs"].as_u64().unwrap()).unwrap(),
            )
            .unwrap(),
            strategy: SelectionStrategy::Smallest,
            base_fee: BASE_FEE,
        },
    )
    .unwrap();
    assert_eq!(selected.inputs, records, "{case}: inputs");
    let recorded_change = payer["outputs"].as_array().unwrap();
    assert_eq!(selected.change.len(), recorded_change.len(), "{case}");
    let change = recorded_change
        .iter()
        .zip(&selected.change)
        .map(|(output, &amount)| {
            assert_eq!(amount.value(), value(output), "{case}: change value");
            ChangeOutput {
                key_id: key_id(output),
                amount,
            }
        })
        .collect();
    let plan = I2Plan {
        fee: selected.fee,
        height: tip,
        ttl_cutoff_height: option(&v3, "ttl_blocks")
            .map(|blocks| tip.checked_add_blocks(blocks.parse().unwrap()).unwrap()),
        inputs: selected.inputs,
        change,
        message: option(&v3, "responder_message"),
    };
    let randomness = I2Randomness {
        nonce: SecretKey::from_array(UPSTREAM_TEST_NONCE).unwrap(),
        message_nonce: SecretKey::from_array(UPSTREAM_TEST_NONCE).unwrap(),
    };
    build_i2(&keychain, i1, &plan, &randomness).unwrap()
}

#[test]
fn invoice_vectors_come_from_the_pinned_upstream_over_the_file_method() {
    let cases = invoice_cases();
    assert_eq!(cases.len(), G03_INVOICE_CASES, "{cases:?}");
    for case in &cases {
        for (stage, producer) in [("i1", "issuer"), ("i2", "payer"), ("i3", "issuer")] {
            for encoding in ["file", "v3", "v2"] {
                let vector = vector(&format!("{case}_{stage}_{encoding}"));
                assert_eq!(text(&vector["inputs"]["method"]), "file", "{case}");
                assert_eq!(text(&vector["inputs"]["producer"]), producer, "{case}");
                assert_eq!(
                    text(&vector["upstream"]["commit"]),
                    "845b3fcf4df12ed0139929c62157015447a9d063",
                    "{case}"
                );
                assert_eq!(vector["expected"]["randomized"], Value::Array(Vec::new()));
            }
        }
        assert!(!has_vector(&format!("{case}_i1_epicbox")), "{case}");
    }
}

#[test]
fn each_g03_invoice_is_reproduced_at_every_stage() {
    let cases = invoice_cases();
    assert_eq!(cases.len(), G03_INVOICE_CASES, "{cases:?}");
    let mut kept_ttl = 0;
    for case in &cases {
        let (issued, context) = issue(case);
        assert_eq!(issued.slate.stage(), Stage::I1, "{case}");
        let file = FilePolicy
            .encode_new_slate(&codecs(), &issued.slate, &context)
            .unwrap();
        assert_encodings(case, "i1", &issued.slate, &file);

        let i1 = read_file(case, "i1");
        let paid = pay(case, &i1);
        assert_eq!(paid.stage(), Stage::I2, "{case}");
        let reply = FilePolicy.encode_reply(&codecs(), &paid, &context).unwrap();
        assert_encodings(case, "i2", &paid, &reply);

        // The file method reads by header version. Upstream's V3-shaped I2 says 3, as LEPIC's
        // does, so the issuer reads the payer's TTL and finalizes with it.
        let i2 = read_file(case, "i2");
        if paid.ttl_cutoff_height().is_some() {
            assert_eq!(i2.ttl_cutoff_height(), paid.ttl_cutoff_height(), "{case}");
            let own = FilePolicy.decode(&codecs(), &reply).unwrap();
            assert_eq!(own.ttl_cutoff_height(), paid.ttl_cutoff_height(), "{case}");
            kept_ttl += 1;
        }
        let finalized =
            build_i3(BASE_FEE, &issued, &i2).unwrap_or_else(|error| panic!("{case}: {error:?}"));
        assert_eq!(finalized.slate.stage(), Stage::I3, "{case}");
        let i3 = vector(&format!("{case}_i3_v3"));
        assert_eq!(
            hex(&ser_vec(&finalized.transaction, LOCAL_PROTOCOL_VERSION)),
            text(&i3["expected"]["final_tx"]["serialized"]),
            "{case}: final transaction"
        );
        assert_eq!(
            finalized.slate.kernel(),
            finalized.transaction.kernels().first().copied(),
            "{case}: kernel"
        );
        let file = FilePolicy
            .encode_reply(&codecs(), &finalized.slate, &context)
            .unwrap();
        assert_encodings(case, "i3", &finalized.slate, &file);
    }
    assert_eq!(kept_ttl, 1);
}

fn node_at(height: u64) -> MockNode {
    MockNode::from_chain(ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 6,
        },
        Tip {
            height: Height::new(height),
            last_block_pushed: Hash::from_slice(&[0; 32]).unwrap(),
        },
    ))
}

#[test]
fn each_g03_i1_paid_through_the_engine_yields_the_g03_i2_as_a_v3_file() {
    for case in invoice_cases() {
        let i2 = vector(&format!("{case}_i2_file"));
        let payer_entry = party(&i2, "payer");
        let tip = number(&slate_json(&i2)["height"]);
        let payer = Party::new(text(&payer_entry["mnemonic"]), &node_at(tip));
        payer.fund(0, FUNDING);
        let change = payer_entry["outputs"].as_array().unwrap();
        payer.set_next_child(key_id(&change[0]).components()[2]);
        let options = &i2["inputs"]["options"];
        let request = PayRequest {
            minimum_confirmations: text(&options["minimum_confirmations"]).parse().unwrap(),
            strategy: SelectionStrategy::Smallest,
            ttl_blocks: option(&i2, "ttl_blocks").map(|blocks| blocks.parse().unwrap()),
            message: option(&i2, "responder_message"),
            ..PayRequest::new(ACCOUNT, Amount::new(number(&options["amount"])))
        };
        let i1 = wire(&json(&vector(&format!("{case}_i1_file"))));

        let paid = payer
            .pay(&i1, request)
            .unwrap_or_else(|error| panic!("{case}: {error:?}"));

        assert_eq!(
            paid.reply.as_text().unwrap(),
            as_file_v3(&json(&vector(&format!("{case}_i2_v3")))),
            "{case}"
        );
        let slate_id = Uuid::from_bytes(*paid.slate.id().as_bytes());
        let entry = payer
            .read(|repos| repos.transaction_by_slate(slate_id, TxDirection::Outgoing))
            .unwrap();
        assert_eq!(entry.id, paid.tx_id, "{case}");
        assert_eq!(entry.entry.state, TxState::Sent, "{case}");
        let stored = payer
            .read(|repos| repos.slate(slate_id, SlateStage::Invoice2))
            .unwrap();
        assert_eq!(stored.bytes, paid.reply.as_bytes(), "{case}");
    }
}

/// As for the send flow: an I2 under another slate id is not finalized.
#[test]
fn an_i2_under_another_slate_id_is_refused() {
    let case = &invoice_cases()[0];
    let (issued, _) = issue(case);
    let mut parts = read_file(case, "i2").into_parts();
    parts.id = SlateId::from_bytes([7; 16]);
    let i2 = Slate::from_parts(parts).unwrap();

    let error = build_i3(BASE_FEE, &issued, &i2).unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::Mismatch {
                field: InvoiceField::Id
            }
        ),
        "{error:?}"
    );
}
