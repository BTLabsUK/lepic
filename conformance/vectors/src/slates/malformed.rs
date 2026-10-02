//! Upstream's verdict on slates that differ from what it emits: each case mutates a slate the
//! flows produced and records whether the file method's parser (`Slate::deserialize_upgrade`) and
//! the Epicbox listener's parser (the untagged `VersionedSlate`) accept it, and what they make of
//! it.

use epic_wallet_libwallet::{Slate, SlateVersion, VersionedSlate};
use serde::Serialize;

use super::flows::{Case, FlowRecord, Stage};
use crate::{Error, Rendered, Upstream, render};

const AREA: &str = "slates";

struct Mutation {
    name: &'static str,
    base_case: &'static str,
    base_stage: Stage,
    description: &'static str,
    apply: fn(&str) -> Option<String>,
}

const PLAIN: &str = "send_file_plain";
const TTL: &str = "send_file_ttl";
const PROOF: &str = "send_file_payment_proof";

const MUTATIONS: &[Mutation] = &[
    Mutation {
        name: "v2_shape_with_header_3",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "V2 shape with version_info 3/3, as the Epicbox method sends it",
        apply: |t| {
            replace_once(
                t,
                r#""version":2,"orig_version":2"#,
                r#""version":3,"orig_version":3"#,
            )
        },
    },
    Mutation {
        name: "header_version_4",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "version_info.version and orig_version set to 4",
        apply: |t| {
            replace_once(
                t,
                r#""version":2,"orig_version":2"#,
                r#""version":4,"orig_version":4"#,
            )
        },
    },
    Mutation {
        name: "header_version_1",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "version_info.version and orig_version set to 1",
        apply: |t| {
            replace_once(
                t,
                r#""version":2,"orig_version":2"#,
                r#""version":1,"orig_version":1"#,
            )
        },
    },
    Mutation {
        name: "missing_version_info",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "version_info key removed",
        apply: |t| remove_object_member(t, r#""version_info":{"#),
    },
    Mutation {
        name: "amount_as_number",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "amount written as a JSON number instead of a string",
        apply: |t| {
            let amount = string_at(t, &["amount"])?;
            replace_once(
                t,
                &format!(r#""amount":"{amount}""#),
                &format!(r#""amount":{amount}"#),
            )
        },
    },
    Mutation {
        name: "amount_not_a_number",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "amount is a non-numeric string",
        apply: |t| replace_string_at(t, &["amount"], "amount", "ten"),
    },
    Mutation {
        name: "amount_negative",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "amount is a negative decimal string",
        apply: |t| replace_string_at(t, &["amount"], "amount", "-1"),
    },
    Mutation {
        name: "amount_above_u64",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "amount is 2^64",
        apply: |t| replace_string_at(t, &["amount"], "amount", "18446744073709551616"),
    },
    Mutation {
        name: "num_participants_as_string",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "num_participants written as a string",
        apply: |t| replace_once(t, r#""num_participants":2"#, r#""num_participants":"2""#),
    },
    Mutation {
        name: "num_participants_zero",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "num_participants is 0",
        apply: |t| replace_once(t, r#""num_participants":2"#, r#""num_participants":0"#),
    },
    Mutation {
        name: "participant_id_as_number",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "participant id written as a JSON number",
        apply: |t| replace_once(t, r#""id":"0""#, r#""id":0"#),
    },
    Mutation {
        name: "duplicate_participant_id",
        base_case: PLAIN,
        base_stage: Stage::S2,
        description: "both participants carry id 0",
        apply: |t| replace_once(t, r#""id":"1""#, r#""id":"0""#),
    },
    Mutation {
        name: "offset_too_short",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "tx.offset is one byte short",
        apply: |t| {
            let offset = string_at(t, &["tx", "offset"])?;
            let short = offset.get(2..)?;
            replace_once(
                t,
                &format!(r#""offset":"{offset}""#),
                &format!(r#""offset":"{short}""#),
            )
        },
    },
    Mutation {
        name: "input_commit_not_hex",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "the first input commitment starts with non-hex characters",
        apply: |t| corrupt_hex(t, &["tx", "body", "inputs", "0", "commit"]),
    },
    Mutation {
        name: "public_blind_excess_not_a_point",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "public_blind_excess has an x coordinate above the field prime",
        apply: |t| {
            let key = string_at(t, &["participant_data", "0", "public_blind_excess"])?;
            let bad = format!("02{}", "ff".repeat(32));
            replace_once(t, &format!(r#""{key}""#), &format!(r#""{bad}""#))
        },
    },
    Mutation {
        name: "part_sig_not_hex",
        base_case: PLAIN,
        base_stage: Stage::S2,
        description: "the receiver's part_sig starts with non-hex characters",
        apply: |t| corrupt_hex(t, &["participant_data", "1", "part_sig"]),
    },
    Mutation {
        name: "unknown_top_level_key",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "an extra top-level key",
        apply: |t| replace_first(t, "{", r#"{"lepic_unknown":1,"#),
    },
    Mutation {
        name: "v2_shape_with_ttl_key",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "V2 shape with header 2 plus a null ttl_cutoff_height key",
        apply: |t| replace_first(t, "{", r#"{"ttl_cutoff_height":null,"#),
    },
    Mutation {
        name: "truncated",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "the last byte removed",
        apply: |t| t.get(..t.len().checked_sub(1)?).map(str::to_owned),
    },
    Mutation {
        name: "empty_object",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "an empty JSON object",
        apply: |_| Some("{}".to_owned()),
    },
    Mutation {
        name: "not_json",
        base_case: PLAIN,
        base_stage: Stage::S1,
        description: "text that is not JSON",
        apply: |_| Some("not a slate".to_owned()),
    },
    Mutation {
        name: "v3_without_payment_proof_key",
        base_case: TTL,
        base_stage: Stage::S1,
        description: "V3 shape without the payment_proof key",
        apply: |t| remove_member_text(t, r#""payment_proof":null"#),
    },
    Mutation {
        name: "v3_ttl_as_number",
        base_case: TTL,
        base_stage: Stage::S1,
        description: "ttl_cutoff_height written as a JSON number",
        apply: |t| {
            let ttl = string_at(t, &["ttl_cutoff_height"])?;
            replace_once(
                t,
                &format!(r#""ttl_cutoff_height":"{ttl}""#),
                &format!(r#""ttl_cutoff_height":{ttl}"#),
            )
        },
    },
    Mutation {
        name: "v3_ttl_null",
        base_case: TTL,
        base_stage: Stage::S1,
        description: "ttl_cutoff_height set to null",
        apply: |t| {
            let ttl = string_at(t, &["ttl_cutoff_height"])?;
            replace_once(
                t,
                &format!(r#""ttl_cutoff_height":"{ttl}""#),
                r#""ttl_cutoff_height":null"#,
            )
        },
    },
    Mutation {
        name: "v3_without_ttl_key",
        base_case: TTL,
        base_stage: Stage::S1,
        description: "V3 shape with header 3 but without the ttl_cutoff_height key",
        apply: |t| {
            let ttl = string_at(t, &["ttl_cutoff_height"])?;
            remove_member_text(t, &format!(r#""ttl_cutoff_height":"{ttl}""#))
        },
    },
    Mutation {
        name: "v3_shape_with_header_2",
        base_case: TTL,
        base_stage: Stage::S1,
        description: "V3 shape with version_info 2/2",
        apply: |t| {
            replace_once(
                t,
                r#""version":3,"orig_version":3"#,
                r#""version":2,"orig_version":2"#,
            )
        },
    },
    Mutation {
        name: "payment_proof_address_not_hex",
        base_case: PROOF,
        base_stage: Stage::S1,
        description: "payment_proof.sender_address starts with non-hex characters",
        apply: |t| corrupt_hex(t, &["payment_proof", "sender_address"]),
    },
];

#[derive(Serialize)]
struct Inputs<'a> {
    base: String,
    flow: &'static str,
    stage: &'static str,
    producer: &'static str,
    mutation: &'a str,
    json: String,
}

#[derive(Serialize)]
struct Outcome {
    accepted: bool,
    /// The shape the parser read: from the header on the file method, from the keys on Epicbox.
    parsed_as: Option<&'static str>,
    error: Option<String>,
    /// What upstream writes back for the parsed slate in the V3 shape.
    reencoded_v3: Option<String>,
}

#[derive(Serialize)]
struct Expected {
    file_method: Outcome,
    epicbox_method: Outcome,
}

pub(super) fn generate(
    upstream: &Upstream,
    flows: &[(&Case, FlowRecord)],
) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for mutation in MUTATIONS {
        let base = base_text(flows, mutation)?;
        let json = (mutation.apply)(base.text).ok_or_else(|| Error::Reference {
            step: "mutating a slate",
            source: format!("mutation {} does not apply to {}", mutation.name, base.name).into(),
        })?;
        let expected = Expected {
            file_method: file_outcome(&json)?,
            epicbox_method: epicbox_outcome(&json)?,
        };
        let inputs = Inputs {
            base: base.name,
            flow: base.flow,
            stage: base.stage,
            producer: base.producer,
            mutation: mutation.description,
            json,
        };
        let name = format!("malformed_{}", mutation.name);
        vectors.push(render(AREA, &name, upstream, inputs, expected)?);
    }
    Ok(vectors)
}

struct Base<'a> {
    name: String,
    flow: &'static str,
    stage: &'static str,
    producer: &'static str,
    text: &'a str,
}

fn base_text<'a>(flows: &'a [(&Case, FlowRecord)], mutation: &Mutation) -> Result<Base<'a>, Error> {
    flows
        .iter()
        .filter(|(case, _)| case.name == mutation.base_case)
        .flat_map(|(case, record)| record.stages.iter().map(move |stage| (case, stage)))
        .filter(|(_, stage)| stage.stage.name() == mutation.base_stage.name())
        .find_map(|(case, stage)| {
            let wire = stage.wire.as_ref()?;
            let name = format!(
                "{}_{}_{}",
                case.name,
                stage.stage.name().to_lowercase(),
                wire.encoding
            );
            Some(Base {
                name,
                flow: case.flow.name(),
                stage: stage.stage.name(),
                producer: stage.producer.name(),
                text: wire.text.as_str(),
            })
        })
        .ok_or_else(|| Error::Reference {
            step: "finding a mutation base",
            source: format!("no wire slate for {}", mutation.base_case).into(),
        })
}

fn file_outcome(json: &str) -> Result<Outcome, Error> {
    match Slate::deserialize_upgrade(json) {
        Ok(slate) => {
            let parsed_as = match slate.version_info.version {
                3 => "V3",
                _ => "V2",
            };
            accepted(parsed_as, slate)
        }
        Err(error) => Ok(rejected(error.to_string())),
    }
}

fn epicbox_outcome(json: &str) -> Result<Outcome, Error> {
    match serde_json::from_str::<VersionedSlate>(json) {
        Ok(versioned) => {
            let parsed_as = match versioned.version() {
                SlateVersion::V3 => "V3",
                SlateVersion::V2 => "V2",
            };
            accepted(parsed_as, versioned.into())
        }
        Err(error) => Ok(rejected(error.to_string())),
    }
}

fn accepted(parsed_as: &'static str, slate: Slate) -> Result<Outcome, Error> {
    let reencoded = VersionedSlate::into_version(slate, SlateVersion::V3);
    Ok(Outcome {
        accepted: true,
        parsed_as: Some(parsed_as),
        error: None,
        reencoded_v3: Some(serde_json::to_string(&reencoded)?),
    })
}

fn rejected(error: String) -> Outcome {
    Outcome {
        accepted: false,
        parsed_as: None,
        error: Some(error),
        reencoded_v3: None,
    }
}

/// Replaces `from` when it occurs exactly once, so a mutation never lands somewhere unintended.
fn replace_once(text: &str, from: &str, to: &str) -> Option<String> {
    (text.matches(from).count() == 1).then(|| text.replacen(from, to, 1))
}

fn replace_first(text: &str, from: &str, to: &str) -> Option<String> {
    text.contains(from).then(|| text.replacen(from, to, 1))
}

/// Removes `"key":value` together with the comma that separates it from a neighbour.
fn remove_member_text(text: &str, member: &str) -> Option<String> {
    replace_once(text, &format!("{member},"), "")
        .or_else(|| replace_once(text, &format!(",{member}"), ""))
}

/// Removes an object-valued member whose value holds no nested objects.
fn remove_object_member(text: &str, opening: &str) -> Option<String> {
    let start = text.find(opening)?;
    let close = text.get(start..)?.find('}')?;
    let member = text.get(start..=start.checked_add(close)?)?;
    remove_member_text(text, member)
}

/// The string at a path of object keys and array indices.
fn string_at(text: &str, path: &[&str]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut node = &value;
    for step in path {
        node = match step.parse::<usize>() {
            Ok(index) => node.get(index)?,
            Err(_) => node.get(*step)?,
        };
    }
    node.as_str().map(str::to_owned)
}

fn replace_string_at(text: &str, path: &[&str], key: &str, to: &str) -> Option<String> {
    let from = string_at(text, path)?;
    replace_once(
        text,
        &format!(r#""{key}":"{from}""#),
        &format!(r#""{key}":"{to}""#),
    )
}

fn corrupt_hex(text: &str, path: &[&str]) -> Option<String> {
    let from = string_at(text, path)?;
    let to = format!("zz{}", from.get(2..)?);
    replace_once(text, &format!(r#""{from}""#), &format!(r#""{to}""#))
}
