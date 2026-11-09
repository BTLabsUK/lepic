// SPDX-License-Identifier: Apache-2.0
//! `slates_native` area: the `lepic.v1` form (EPICTX specification 5.10) of every slate the
//! flows produce, with the V3 JSON upstream writes for the same slate, and `lepic.v1` inputs a
//! decoder must refuse.
//!
//! `lepic.v1` has no upstream implementation. This module encodes it from the specification
//! alone, reading upstream's V3 JSON, and calls no LEPIC code; `upstream` names the wallet whose
//! flows produced the slates. Each case is written for mainnet and floonet. Slates built on the
//! test chain sit below both networks' first hard fork; the `after_fork` cases move the height
//! and TTL cutoff past it, so they carry block header version 7.

use epic_wallet_libwallet::{Slate, SlateVersion, VersionedSlate};
use serde::Serialize;
use serde_json::{Value, json};

use super::HEADER_6_BLOCKS;
use super::flows::{Case, FlowRecord, Stage, StageRecord};
use crate::{Error, Rendered, Upstream, hex, render_from};

const AREA: &str = "slates_native";
const MODULE: &str = "slates/native";

const MAGIC: [u8; 4] = [0x89, 0x45, 0x53, 0x4C];
const VERSION: u8 = 0x01;
const HEADER_LEN: usize = 51;

const FLAG_TTL: u8 = 0x02;
const FLAG_PROOF: u8 = 0x04;
const FLAG_SENDER_MESSAGE: u8 = 0x08;
const FLAG_RECEIVER_MESSAGE: u8 = 0x10;

const KERNEL_PLAIN: u8 = 0x00;
const KERNEL_HEIGHT_LOCKED: u8 = 0x02;

const RANGE_PROOF_LEN: usize = 675;

/// Upstream's participant ids: the sender is `0` and the receiver `1` in both flows.
const SENDER: &str = "0";
const RECEIVER: &str = "1";

/// Cases also written past the first hard fork, besides those built at header version 7.
const AFTER_FORK: &[&str] = &[
    "send_file_plain",
    "invoice_file_plain",
    "send_file_ttl_payment_proof_messages",
];

/// The X25519 base point, a valid reply key.
const REPLY_KEY: [u8; 32] = {
    let mut key = [0; 32];
    key[0] = 9;
    key
};
/// 20 bytes, the mailbox length of the QR sizes in specification 5.18.
const MAILBOX_ADDRESS: &str = "relay.example.net:80";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Network {
    Mainnet,
    Floonet,
}

const NETWORKS: [Network; 2] = [Network::Mainnet, Network::Floonet];

impl Network {
    fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Floonet => "floonet",
        }
    }

    fn byte(self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Floonet => 0x01,
        }
    }

    fn first_hard_fork(self) -> u64 {
        match self {
            Network::Mainnet => 9_000_000,
            Network::Floonet => 25_800,
        }
    }

    /// The header version rule: 6 below the first hard fork, 7 from it.
    fn header_version(self, height: u64) -> u16 {
        if height < self.first_hard_fork() {
            6
        } else {
            7
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Proposed,
    Responded,
    Finalized,
}

fn step(stage: Stage) -> Step {
    match stage {
        Stage::S1 | Stage::I1 => Step::Proposed,
        Stage::S2 | Stage::I2 => Step::Responded,
        Stage::S3 | Stage::I3 => Step::Finalized,
    }
}

fn stage_byte(stage: Stage) -> u8 {
    match stage {
        Stage::S1 => 0x01,
        Stage::S2 => 0x02,
        Stage::S3 => 0x03,
        Stage::I1 => 0x04,
        Stage::I2 => 0x05,
        Stage::I3 => 0x06,
    }
}

fn initiator(stage: Stage) -> &'static str {
    match stage {
        Stage::S1 | Stage::S2 | Stage::S3 => SENDER,
        Stage::I1 | Stage::I2 | Stage::I3 => RECEIVER,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Presence {
    Absent,
    Unsigned,
    Signed,
}

/// RFC 0001 section 3: the initiator proposes unsigned, the responder answers signed, and the
/// initiator signs last.
fn presence(stage: Stage, id: &str) -> Presence {
    match (step(stage), id == initiator(stage)) {
        (Step::Proposed | Step::Responded, true) => Presence::Unsigned,
        (Step::Proposed, false) => Presence::Absent,
        (Step::Responded, false) | (Step::Finalized, _) => Presence::Signed,
    }
}

/// What the encoder writes although the format leaves it out, for refusal cases.
#[derive(Clone, Copy, Default)]
struct Keep {
    body_at_proposal: bool,
    initiator_message: bool,
}

/// The bytes and the offsets the refusal cases patch.
struct Encoded {
    bytes: Vec<u8>,
    participants_at: usize,
    inputs_at: usize,
    outputs_at: usize,
}

fn bad(step: &'static str, what: impl Into<String>) -> Error {
    Error::Reference {
        step,
        source: what.into().into(),
    }
}

fn field<'a>(value: &'a Value, pointer: &str) -> Result<&'a Value, Error> {
    value
        .pointer(pointer)
        .ok_or_else(|| bad("reading the V3 slate", format!("{pointer} is missing")))
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, Error> {
    field(value, pointer)?
        .as_str()
        .ok_or_else(|| bad("reading the V3 slate", format!("{pointer} is not a string")))
}

fn number(value: &Value, pointer: &str) -> Result<u64, Error> {
    text(value, pointer)?
        .parse()
        .map_err(|_| bad("reading the V3 slate", format!("{pointer} is not a u64")))
}

fn optional_number(value: &Value, pointer: &str) -> Result<Option<u64>, Error> {
    match field(value, pointer)? {
        Value::Null => Ok(None),
        _ => number(value, pointer).map(Some),
    }
}

fn unhex(text: &str) -> Result<Vec<u8>, Error> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a' - 10),
        _ => None,
    };
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(bad("reading hex", format!("odd length in {text}")));
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[high, low]| Some(digit(*high)? << 4 | digit(*low)?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| bad("reading hex", format!("not lowercase hex: {text}")))
}

/// Appends the bytes of the hex at `pointer`, which must be `len` bytes long.
fn put_hex(out: &mut Vec<u8>, value: &Value, pointer: &str, len: usize) -> Result<(), Error> {
    let bytes = unhex(text(value, pointer)?)?;
    if bytes.len() != len {
        return Err(bad(
            "reading the V3 slate",
            format!("{pointer} is {} bytes, not {len}", bytes.len()),
        ));
    }
    out.extend_from_slice(&bytes);
    Ok(())
}

fn put_u16(out: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    let value = u16::try_from(value).map_err(|_| bad("encoding lepic.v1", "count over u16"))?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn features_byte(name: &str) -> Result<u8, Error> {
    match name {
        "Plain" => Ok(0x00),
        "Coinbase" => Ok(0x01),
        other => Err(bad("reading the V3 slate", format!("features {other}"))),
    }
}

fn participant<'a>(v3: &'a Value, id: &str) -> Result<Option<&'a Value>, Error> {
    let all = field(v3, "/participant_data")?
        .as_array()
        .ok_or_else(|| bad("reading the V3 slate", "participant_data is not a list"))?;
    let mut found = all
        .iter()
        .filter(|data| data.get("id").and_then(Value::as_str) == Some(id));
    let first = found.next();
    if found.next().is_some() {
        return Err(bad(
            "reading the V3 slate",
            format!("participant {id} twice"),
        ));
    }
    Ok(first)
}

fn list<'a>(v3: &'a Value, pointer: &str) -> Result<&'a [Value], Error> {
    field(v3, pointer)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| bad("reading the V3 slate", format!("{pointer} is not a list")))
}

/// Encodes the V3 slate `v3` at `stage` as `lepic.v1`, without a tail.
#[allow(clippy::too_many_lines)] // the layout, field by field, in wire order
fn encode(v3: &Value, stage: Stage, network: Network, keep: Keep) -> Result<Encoded, Error> {
    let height = number(v3, "/height")?;
    let lock_height = number(v3, "/lock_height")?;
    let ttl = optional_number(v3, "/ttl_cutoff_height")?;
    let proof = field(v3, "/payment_proof")?;
    let proof = (!proof.is_null()).then_some(proof);
    let kernel = list(v3, "/tx/body/kernels")?
        .first()
        .ok_or_else(|| bad("reading the V3 slate", "no kernel"))?;
    let kernel_features = match (text(kernel, "/features")?, lock_height) {
        ("Plain", 0) => KERNEL_PLAIN,
        ("HeightLocked", 1..) => KERNEL_HEIGHT_LOCKED,
        (features, _) => {
            return Err(bad(
                "reading the V3 slate",
                format!("kernel {features} with lock height {lock_height}"),
            ));
        }
    };
    let header_version = network.header_version(height);
    let v3_header_version = field(v3, "/version_info/block_header_version")?.as_u64();
    if v3_header_version != Some(u64::from(header_version)) {
        return Err(bad(
            "reading the V3 slate",
            format!("block header version {v3_header_version:?}, rule {header_version}"),
        ));
    }

    let mut parties = Vec::new();
    for id in [SENDER, RECEIVER] {
        let data = participant(v3, id)?;
        let presence = presence(stage, id);
        let data = match (presence, data) {
            (Presence::Absent, None) => continue,
            (Presence::Absent, Some(_)) | (_, None) => {
                return Err(bad(
                    "reading the V3 slate",
                    format!("participant {id} at {}", stage.name()),
                ));
            }
            (_, Some(data)) => data,
        };
        let signed = presence == Presence::Signed;
        if data.get("part_sig").is_none_or(Value::is_null) == signed {
            return Err(bad(
                "reading the V3 slate",
                format!("participant {id} signature at {}", stage.name()),
            ));
        }
        let leaves_out_message =
            step(stage) == Step::Responded && id == initiator(stage) && !keep.initiator_message;
        let message = data
            .get("message")
            .and_then(Value::as_str)
            .filter(|_| !leaves_out_message);
        parties.push((id, data, signed, message));
    }

    let mut flags = 0;
    if ttl.is_some() {
        flags |= FLAG_TTL;
    }
    if proof.is_some() {
        flags |= FLAG_PROOF;
    }
    for (id, _, _, message) in &parties {
        if message.is_some() {
            flags |= if *id == SENDER {
                FLAG_SENDER_MESSAGE
            } else {
                FLAG_RECEIVER_MESSAGE
            };
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(network.byte());
    out.push(stage_byte(stage));
    out.push(flags);
    out.push(kernel_features);
    out.extend_from_slice(&header_version.to_be_bytes());
    let id = text(v3, "/id")?.replace('-', "");
    let id = unhex(&id)?;
    if id.len() != 16 {
        return Err(bad("reading the V3 slate", "id is not 16 bytes"));
    }
    out.extend_from_slice(&id);
    out.extend_from_slice(&number(v3, "/amount")?.to_be_bytes());
    out.extend_from_slice(&number(v3, "/fee")?.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    debug_assert_eq!(out.len(), HEADER_LEN);

    if kernel_features == KERNEL_HEIGHT_LOCKED {
        out.extend_from_slice(&lock_height.to_be_bytes());
    }
    if let Some(ttl) = ttl {
        out.extend_from_slice(&ttl.to_be_bytes());
    }
    put_hex(&mut out, v3, "/tx/offset", 32)?;

    let participants_at = out.len();
    for (_, data, signed, message) in &parties {
        put_hex(&mut out, data, "/public_blind_excess", 33)?;
        put_hex(&mut out, data, "/public_nonce", 33)?;
        if *signed {
            put_hex(&mut out, data, "/part_sig", 64)?;
        }
        if let Some(message) = message {
            put_u16(&mut out, message.len())?;
            out.extend_from_slice(message.as_bytes());
            put_hex(&mut out, data, "/message_sig", 64)?;
        }
    }

    if let Some(proof) = proof {
        put_hex(&mut out, proof, "/sender_address", 32)?;
        put_hex(&mut out, proof, "/receiver_address", 32)?;
        let signature = proof.get("receiver_signature").filter(|s| !s.is_null());
        match (step(stage) == Step::Proposed, signature) {
            (true, None) => {}
            (false, Some(_)) => put_hex(&mut out, proof, "/receiver_signature", 64)?,
            _ => return Err(bad("reading the V3 slate", "receiver signature by stage")),
        }
    }

    let writes_body = step(stage) != Step::Proposed || keep.body_at_proposal;
    let (inputs, outputs) = if writes_body {
        (list(v3, "/tx/body/inputs")?, list(v3, "/tx/body/outputs")?)
    } else {
        (&[][..], &[][..])
    };
    let inputs_at = out.len();
    put_u16(&mut out, inputs.len())?;
    for input in inputs {
        out.push(features_byte(text(input, "/features")?)?);
        put_hex(&mut out, input, "/commit", 33)?;
    }
    let outputs_at = out.len();
    put_u16(&mut out, outputs.len())?;
    for output in outputs {
        out.push(features_byte(text(output, "/features")?)?);
        put_hex(&mut out, output, "/commit", 33)?;
        put_hex(&mut out, output, "/proof", RANGE_PROOF_LEN)?;
    }

    if step(stage) == Step::Finalized {
        put_hex(&mut out, kernel, "/excess", 33)?;
        put_hex(&mut out, kernel, "/excess_sig", 64)?;
    }
    Ok(Encoded {
        bytes: out,
        participants_at,
        inputs_at,
        outputs_at,
    })
}

fn insert(object: &mut Value, key: &str, value: Value) {
    if let Some(map) = object.as_object_mut() {
        map.insert(key.to_owned(), value);
    }
}

/// One tail record: `u8` type, `u16` length, value.
fn record(record_type: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![record_type];
    out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// The JSON view (the `lepic.v1` 1:1 view) of the V3 slate as `lepic.v1` carries it.
fn view(v3: &Value, stage: Stage, network: Network, tail: &TailInputs) -> Result<Value, Error> {
    let height = number(v3, "/height")?;
    let lock_height = number(v3, "/lock_height")?;
    let ttl = optional_number(v3, "/ttl_cutoff_height")?;
    let proof = field(v3, "/payment_proof")?;
    let mut flags = Vec::new();
    if ttl.is_some() {
        flags.push("ttl");
    }
    if !proof.is_null() {
        flags.push("proof");
    }
    let mut parties = serde_json::Map::new();
    for (id, name, flag) in [
        (SENDER, "sender", "sender_message"),
        (RECEIVER, "receiver", "receiver_message"),
    ] {
        let presence = presence(stage, id);
        let Some(data) = participant(v3, id)?.filter(|_| presence != Presence::Absent) else {
            continue;
        };
        let mut party = serde_json::Map::new();
        party.insert(
            "public_blind_excess".into(),
            field(data, "/public_blind_excess")?.clone(),
        );
        party.insert("public_nonce".into(), field(data, "/public_nonce")?.clone());
        if presence == Presence::Signed {
            party.insert(
                "partial_signature".into(),
                field(data, "/part_sig")?.clone(),
            );
        }
        let leaves_out = step(stage) == Step::Responded && id == initiator(stage);
        if let Some(message) = data.get("message").filter(|m| !m.is_null() && !leaves_out) {
            flags.push(flag);
            party.insert(
                "message".into(),
                json!({"text": message, "signature": field(data, "/message_sig")?}),
            );
        }
        parties.insert(name.into(), Value::Object(party));
    }
    let proposed = step(stage) == Step::Proposed;
    let body = |pointer: &str| -> Result<Vec<Value>, Error> {
        if proposed {
            return Ok(Vec::new());
        }
        list(v3, pointer)?
            .iter()
            .map(|entry| {
                let features = match text(entry, "/features")? {
                    "Plain" => "plain",
                    "Coinbase" => "coinbase",
                    other => return Err(bad("reading the V3 slate", other.to_owned())),
                };
                let mut item =
                    json!({"features": features, "commitment": field(entry, "/commit")?});
                if let Some(proof) = entry.get("proof") {
                    insert(&mut item, "proof", proof.clone());
                }
                Ok(item)
            })
            .collect()
    };
    let mut view = json!({
        "network": network.name(),
        "stage": stage.name(),
        "flags": flags,
        "kernel_features": if lock_height == 0 { "plain" } else { "height_locked" },
        "header_version": network.header_version(height),
        "id": field(v3, "/id")?,
        "amount": field(v3, "/amount")?,
        "fee": field(v3, "/fee")?,
        "height": field(v3, "/height")?,
        "offset": field(v3, "/tx/offset")?,
        "inputs": body("/tx/body/inputs")?,
        "outputs": body("/tx/body/outputs")?,
        "tail": tail.view(),
    });
    if lock_height != 0 {
        insert(&mut view, "lock_height", json!(lock_height.to_string()));
    }
    if let Some(ttl) = ttl {
        insert(&mut view, "ttl_cutoff_height", json!(ttl.to_string()));
    }
    for (name, party) in parties {
        insert(&mut view, &name, party);
    }
    if !proof.is_null() {
        let mut shown = json!({
            "sender_address": field(proof, "/sender_address")?,
            "receiver_address": field(proof, "/receiver_address")?,
        });
        if !proposed {
            insert(
                &mut shown,
                "receiver_signature",
                field(proof, "/receiver_signature")?.clone(),
            );
        }
        insert(&mut view, "payment_proof", shown);
    }
    if step(stage) == Step::Finalized {
        let kernel = list(v3, "/tx/body/kernels")?
            .first()
            .ok_or_else(|| bad("reading the V3 slate", "no kernel"))?;
        insert(
            &mut view,
            "kernel",
            json!({
                "excess": field(kernel, "/excess")?,
                "excess_sig": field(kernel, "/excess_sig")?,
            }),
        );
    }
    Ok(view)
}

/// The tail a case appends: the reply key, the reply mailbox and unknown records, in that order.
#[derive(Default, Serialize)]
struct TailInputs {
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_mailbox: Option<MailboxInputs>,
    unknown: Vec<UnknownInputs>,
}

#[derive(Serialize)]
struct MailboxInputs {
    key: String,
    address: String,
}

#[derive(Serialize)]
struct UnknownInputs {
    #[serde(rename = "type")]
    record_type: u8,
    hex: String,
}

impl TailInputs {
    fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        if let Some(key) = &self.reply_key {
            out.extend(record(0x01, &unhex(key)?));
        }
        if let Some(mailbox) = &self.reply_mailbox {
            let mut value = unhex(&mailbox.key)?;
            value.extend_from_slice(mailbox.address.as_bytes());
            out.extend(record(0x02, &value));
        }
        for unknown in &self.unknown {
            out.extend(record(unknown.record_type, &unhex(&unknown.hex)?));
        }
        Ok(out)
    }

    fn view(&self) -> Value {
        let mut view = json!({ "unknown": self.unknown });
        if let Some(key) = &self.reply_key {
            insert(&mut view, "reply_key", json!(key));
        }
        if let Some(mailbox) = &self.reply_mailbox {
            insert(&mut view, "reply_mailbox", json!(mailbox));
        }
        view
    }
}

#[derive(Serialize)]
struct CaseInputs<'a> {
    case: &'a str,
    stage: &'static str,
    network: &'static str,
    /// The `slates` vector this slate is, before any height shift.
    base: String,
    /// Added to the height and the TTL cutoff, and the V3 block header version set to 7.
    #[serde(skip_serializing_if = "Option::is_none")]
    height_shift: Option<String>,
    tail: TailInputs,
    v3_json: String,
}

#[derive(Serialize)]
struct CaseExpected {
    size: usize,
    lepic_v1: String,
    view: Value,
}

pub(super) fn generate(
    upstream: &Upstream,
    flows: &[(&Case, FlowRecord)],
) -> Result<Vec<Rendered>, Error> {
    let mut vectors = Vec::new();
    for (case, record) in flows {
        let below_fork = case.blocks_before == HEADER_6_BLOCKS;
        let after_fork = !below_fork || AFTER_FORK.contains(&case.name);
        for stage in &record.stages {
            for network in NETWORKS {
                if below_fork {
                    let slate = Shifted::new(stage, None)?;
                    vectors.push(render_case(upstream, case.name, &slate, network, None)?);
                }
                if after_fork {
                    let slate = Shifted::new(stage, Some(network.first_hard_fork()))?;
                    vectors.push(render_case(upstream, case.name, &slate, network, None)?);
                }
            }
        }
    }
    vectors.extend(tail_cases(upstream, flows)?);
    vectors.extend(malformed(upstream, flows)?);
    Ok(vectors)
}

/// A flow's slate, its height moved by `shift` when one is given.
struct Shifted {
    stage: Stage,
    shift: Option<u64>,
    json: String,
    value: Value,
}

impl Shifted {
    fn new(record: &StageRecord, shift: Option<u64>) -> Result<Self, Error> {
        let mut slate: Slate = record.slate.clone();
        if let Some(shift) = shift {
            if slate.lock_height != 0 {
                return Err(bad("shifting a slate", "a height-locked slate"));
            }
            let overflow = || bad("shifting a slate", "height overflow");
            slate.height = slate.height.checked_add(shift).ok_or_else(overflow)?;
            slate.ttl_cutoff_height = slate
                .ttl_cutoff_height
                .map(|ttl| ttl.checked_add(shift).ok_or_else(overflow))
                .transpose()?;
            slate.version_info.block_header_version = 7;
        }
        let json = serde_json::to_string(&VersionedSlate::into_version(slate, SlateVersion::V3))?;
        let value = serde_json::from_str(&json)?;
        Ok(Self {
            stage: record.stage,
            shift,
            json,
            value,
        })
    }
}

fn render_case(
    upstream: &Upstream,
    case: &str,
    slate: &Shifted,
    network: Network,
    tail: Option<(&str, TailInputs)>,
) -> Result<Rendered, Error> {
    let (label, tail) = tail.unwrap_or_default();
    let mut bytes = encode(&slate.value, slate.stage, network, Keep::default())?.bytes;
    bytes.extend(tail.bytes()?);
    let stage = slate.stage.name();
    let mut name = format!("{case}_{}_{}", stage.to_lowercase(), network.name());
    if slate.shift.is_some() {
        name.push_str("_after_fork");
    }
    if !label.is_empty() {
        name = format!("tail_{label}_{name}");
    }
    let expected = CaseExpected {
        size: bytes.len(),
        lepic_v1: hex(&bytes),
        view: view(&slate.value, slate.stage, network, &tail)?,
    };
    let inputs = CaseInputs {
        case,
        stage,
        network: network.name(),
        base: format!("slates/{case}_{}_v3", stage.to_lowercase()),
        height_shift: slate.shift.map(|shift| shift.to_string()),
        tail,
        v3_json: slate.json.clone(),
    };
    render_from(MODULE, AREA, &name, upstream, inputs, expected)
}

fn stage_of<'a>(
    flows: &'a [(&Case, FlowRecord)],
    case: &str,
    stage: Stage,
) -> Result<&'a StageRecord, Error> {
    flows
        .iter()
        .filter(|(c, _)| c.name == case)
        .flat_map(|(_, record)| &record.stages)
        .find(|record| record.stage.name() == stage.name())
        .ok_or_else(|| bad("finding a base slate", format!("{case} {}", stage.name())))
}

fn sender_excess(slate: &Shifted) -> Result<String, Error> {
    let data = participant(&slate.value, initiator(slate.stage))?
        .ok_or_else(|| bad("reading the V3 slate", "no initiator"))?;
    Ok(text(data, "/public_blind_excess")?.to_owned())
}

fn unknown(record_type: u8, value: &[u8]) -> UnknownInputs {
    UnknownInputs {
        record_type,
        hex: hex(value),
    }
}

/// Slates with a tail: ignorable records kept as they are, and the raw S1 and I1 with the reply
/// key, and with the reply key and mailbox.
fn tail_cases(upstream: &Upstream, flows: &[(&Case, FlowRecord)]) -> Result<Vec<Rendered>, Error> {
    let net = Network::Mainnet;
    let plain_s1 = Shifted::new(stage_of(flows, "send_file_plain", Stage::S1)?, None)?;
    let plain_s3 = Shifted::new(stage_of(flows, "send_file_plain", Stage::S3)?, None)?;
    let ttl_s1 = Shifted::new(stage_of(flows, "send_file_ttl", Stage::S1)?, None)?;
    let invoice_i1 = Shifted::new(stage_of(flows, "invoice_file_plain", Stage::I1)?, None)?;
    let mailbox = |slate: &Shifted| -> Result<MailboxInputs, Error> {
        Ok(MailboxInputs {
            key: sender_excess(slate)?,
            address: MAILBOX_ADDRESS.to_owned(),
        })
    };
    let cases = [
        (
            "send_file_plain",
            &plain_s1,
            "unknown",
            TailInputs {
                unknown: vec![unknown(0x80, b""), unknown(0xc3, b"lepic")],
                ..TailInputs::default()
            },
        ),
        (
            "send_file_plain",
            &plain_s3,
            "unknown",
            TailInputs {
                unknown: vec![unknown(0xff, &[1, 2, 3])],
                ..TailInputs::default()
            },
        ),
        (
            "send_file_ttl",
            &ttl_s1,
            "reply_key",
            TailInputs {
                reply_key: Some(hex(REPLY_KEY)),
                ..TailInputs::default()
            },
        ),
        (
            "send_file_ttl",
            &ttl_s1,
            "reply_mailbox",
            TailInputs {
                reply_key: Some(hex(REPLY_KEY)),
                reply_mailbox: Some(mailbox(&ttl_s1)?),
                ..TailInputs::default()
            },
        ),
        (
            "invoice_file_plain",
            &invoice_i1,
            "reply_mailbox_unknown",
            TailInputs {
                reply_key: Some(hex(REPLY_KEY)),
                reply_mailbox: Some(mailbox(&invoice_i1)?),
                unknown: vec![unknown(0x90, b"x")],
            },
        ),
    ];
    cases
        .into_iter()
        .map(|(case, slate, label, tail)| {
            render_case(upstream, case, slate, net, Some((label, tail)))
        })
        .collect()
}

#[derive(Serialize)]
struct MalformedInputs {
    base: String,
    mutation: &'static str,
    /// The network the decoder expects.
    decode_network: &'static str,
    lepic_v1: String,
}

#[derive(Serialize)]
struct MalformedExpected {
    /// The refusal: the error variant, `Tail.<variant>` for a tail error and `Model.<variant>`
    /// for one the slate model gives.
    error: &'static str,
}

struct Malformed {
    name: &'static str,
    mutation: &'static str,
    error: &'static str,
    base: (&'static str, Stage),
    after_fork: bool,
    encode_network: Network,
    decode_network: Network,
    keep: Keep,
    /// Changes the V3 slate before it is encoded.
    edit: fn(&mut Value) -> Option<()>,
    /// Changes the encoded bytes.
    patch: fn(&mut Encoded) -> Option<()>,
}

const PLAIN: &str = "send_file_plain";

const fn malformed_case(
    name: &'static str,
    mutation: &'static str,
    error: &'static str,
    patch: fn(&mut Encoded) -> Option<()>,
) -> Malformed {
    Malformed {
        name,
        mutation,
        error,
        base: (PLAIN, Stage::S1),
        after_fork: false,
        encode_network: Network::Mainnet,
        decode_network: Network::Mainnet,
        keep: Keep {
            body_at_proposal: false,
            initiator_message: false,
        },
        edit: |_| Some(()),
        patch,
    }
}

fn set(encoded: &mut Encoded, at: usize, byte: u8) -> Option<()> {
    *encoded.bytes.get_mut(at)? = byte;
    Some(())
}

fn append(encoded: &mut Encoded, bytes: &[u8]) -> Option<()> {
    encoded.bytes.extend_from_slice(bytes);
    Some(())
}

/// The value of a well-formed reply key record followed by a reply mailbox record.
fn reply_records(mailbox_key: &[u8], address: &[u8]) -> Vec<u8> {
    let mut out = record(0x01, &REPLY_KEY);
    let mut value = mailbox_key.to_vec();
    value.extend_from_slice(address);
    out.extend(record(0x02, &value));
    out
}

/// A valid compressed secp256k1 key: the generator point.
const SECP_G: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

#[allow(clippy::too_many_lines)] // one entry per refusal
fn malformed_cases() -> Vec<Malformed> {
    vec![
        malformed_case("magic", "first magic byte changed to 88", "Magic", |e| {
            set(e, 0, 0x88)
        }),
        malformed_case("version", "version 02", "Version", |e| set(e, 4, 0x02)),
        malformed_case(
            "unknown_network",
            "network byte 02",
            "UnknownNetwork",
            |e| set(e, 5, 0x02),
        ),
        Malformed {
            encode_network: Network::Floonet,
            ..malformed_case(
                "wrong_network",
                "a floonet slate decoded for mainnet",
                "WrongNetwork",
                |_| Some(()),
            )
        },
        malformed_case("stage_zero", "stage byte 00", "UnknownStage", |e| {
            set(e, 6, 0x00)
        }),
        malformed_case("stage_seven", "stage byte 07", "UnknownStage", |e| {
            set(e, 6, 0x07)
        }),
        malformed_case(
            "reserved_flag_bit_0",
            "flag bit 0 set",
            "ReservedFlag",
            |e| set(e, 7, 0x01),
        ),
        malformed_case(
            "reserved_flag_bit_5",
            "flag bit 5 set",
            "ReservedFlag",
            |e| set(e, 7, 0x20),
        ),
        malformed_case(
            "kernel_features_coinbase",
            "kernel features 01",
            "KernelFeatures",
            |e| set(e, 8, 0x01),
        ),
        malformed_case(
            "kernel_features_three",
            "kernel features 03",
            "KernelFeatures",
            |e| set(e, 8, 0x03),
        ),
        malformed_case(
            "header_version_7_below_fork",
            "header version 7 below the first hard fork",
            "HeaderVersion",
            |e| set(e, 10, 0x07),
        ),
        Malformed {
            after_fork: true,
            ..malformed_case(
                "header_version_6_after_fork",
                "header version 6 past the first hard fork",
                "HeaderVersion",
                |e| set(e, 10, 0x06),
            )
        },
        Malformed {
            base: ("send_file_height_locked", Stage::S1),
            ..malformed_case(
                "zero_lock_height",
                "a height-locked kernel with lock height zero",
                "ZeroLockHeight",
                |e| {
                    e.bytes.get_mut(HEADER_LEN..HEADER_LEN + 8)?.fill(0);
                    Some(())
                },
            )
        },
        Malformed {
            base: ("invoice_file_plain", Stage::I1),
            edit: |v3| {
                insert(
                    v3,
                    "payment_proof",
                    json!({
                        "sender_address": "fd5c6c0ad1e51fbc1d58ca746c29585795368ec6727ae4a74b9082cda91e7fd0",
                        "receiver_address": "b03c84d7f781b536c96668d93b37768c7812b76449c17aaf0a9d11a003c3c737",
                        "receiver_signature": null,
                    }),
                );
                Some(())
            },
            ..malformed_case(
                "proof_in_invoice",
                "an I1 with a payment proof",
                "ProofInInvoice",
                |_| Some(()),
            )
        },
        malformed_case(
            "message_without_participant",
            "an S1 with the receiver message flag",
            "MessageWithoutParticipant",
            |e| set(e, 7, FLAG_RECEIVER_MESSAGE),
        ),
        Malformed {
            base: ("send_file_messages", Stage::S2),
            keep: Keep {
                initiator_message: true,
                body_at_proposal: false,
            },
            ..malformed_case(
                "initiator_message",
                "an S2 that repeats the sender's message",
                "InitiatorMessage",
                |_| Some(()),
            )
        },
        malformed_case("truncated_header", "the first 40 bytes", "Truncated", |e| {
            e.bytes.truncate(40);
            Some(())
        }),
        Malformed {
            base: (PLAIN, Stage::S3),
            ..malformed_case(
                "truncated_kernel",
                "an S3 without the last byte",
                "Truncated",
                |e| {
                    e.bytes.pop()?;
                    Some(())
                },
            )
        },
        Malformed {
            keep: Keep {
                body_at_proposal: true,
                initiator_message: false,
            },
            ..malformed_case(
                "body_at_proposal",
                "an S1 with the sender's inputs and outputs",
                "BodyAtProposal",
                |_| Some(()),
            )
        },
        Malformed {
            base: (PLAIN, Stage::S2),
            ..malformed_case(
                "input_features",
                "input features 02",
                "OutputFeatures",
                |e| set(e, e.inputs_at.checked_add(2)?, 0x02),
            )
        },
        Malformed {
            base: (PLAIN, Stage::S2),
            ..malformed_case(
                "output_features",
                "output features 02",
                "OutputFeatures",
                |e| set(e, e.outputs_at.checked_add(2)?, 0x02),
            )
        },
        Malformed {
            base: (PLAIN, Stage::S2),
            ..malformed_case(
                "coinbase_output",
                "an output with coinbase features",
                "Model.CoinbaseOutput",
                |e| set(e, e.outputs_at.checked_add(2)?, 0x01),
            )
        },
        malformed_case(
            "excess_not_a_point",
            "sender excess prefix 05",
            "Crypto",
            |e| set(e, e.participants_at, 0x05),
        ),
        Malformed {
            base: (PLAIN, Stage::S2),
            ..malformed_case(
                "output_commitment_not_a_point",
                "output commitment prefix 07",
                "Crypto",
                |e| set(e, e.outputs_at.checked_add(3)?, 0x07),
            )
        },
        Malformed {
            base: ("send_file_payment_proof", Stage::S1),
            ..malformed_case(
                "proof_address_not_a_point",
                "sender proof address y = 2, not on the curve",
                "ProofAddress",
                |e| {
                    let at = e.inputs_at.checked_sub(64)?;
                    let address = e.bytes.get_mut(at..at.checked_add(32)?)?;
                    address.fill(0);
                    *address.first_mut()? = 2;
                    Some(())
                },
            )
        },
        Malformed {
            base: ("send_file_messages", Stage::S1),
            ..malformed_case(
                "message_too_long",
                "sender message length 257",
                "MessageTooLong",
                |e| {
                    let at = e.participants_at.checked_add(66)?;
                    e.bytes
                        .get_mut(at..at.checked_add(2)?)?
                        .copy_from_slice(&257u16.to_be_bytes());
                    Some(())
                },
            )
        },
        Malformed {
            base: ("send_file_messages", Stage::S1),
            ..malformed_case(
                "message_not_utf8",
                "sender message first byte ff",
                "MessageNotUtf8",
                |e| set(e, e.participants_at.checked_add(68)?, 0xff),
            )
        },
        Malformed {
            base: (PLAIN, Stage::S2),
            edit: |v3| {
                let inputs = v3.pointer_mut("/tx/body/inputs")?.as_array_mut()?;
                let first = inputs.first()?.clone();
                inputs.push(first);
                Some(())
            },
            ..malformed_case(
                "duplicate_input",
                "an S2 with its input twice",
                "Model.DuplicateInput",
                |_| Some(()),
            )
        },
        Malformed {
            base: (PLAIN, Stage::S2),
            edit: |v3| {
                let outputs = v3.pointer_mut("/tx/body/outputs")?.as_array_mut()?;
                let first = outputs.first()?.clone();
                outputs.push(first);
                Some(())
            },
            ..malformed_case(
                "duplicate_output",
                "an S2 with its first output twice",
                "Model.DuplicateOutput",
                |_| Some(()),
            )
        },
        Malformed {
            base: (PLAIN, Stage::S2),
            edit: |v3| {
                let commit = v3.pointer("/tx/body/outputs/0/commit")?.clone();
                let inputs = v3.pointer_mut("/tx/body/inputs")?.as_array_mut()?;
                inputs.push(json!({"features": "Plain", "commit": commit}));
                Some(())
            },
            ..malformed_case(
                "input_spends_output",
                "an S2 that spends its own first output",
                "Model.InputSpendsOutput",
                |_| Some(()),
            )
        },
        malformed_case(
            "tail_truncated_header",
            "a tail record of two bytes",
            "Tail.Truncated",
            |e| append(e, &[0x80, 0x00]),
        ),
        malformed_case(
            "tail_truncated_value",
            "a tail record of length 5 with 2 bytes",
            "Tail.Truncated",
            |e| append(e, &[0x80, 0x00, 0x05, 0x61, 0x62]),
        ),
        malformed_case("tail_order", "tail records 90 then 80", "Tail.Order", |e| {
            append(e, &[0x90, 0x00, 0x00, 0x80, 0x00, 0x00])
        }),
        malformed_case(
            "tail_repeated_type",
            "tail record 80 twice",
            "Tail.Order",
            |e| append(e, &[0x80, 0x00, 0x00, 0x80, 0x00, 0x00]),
        ),
        malformed_case(
            "tail_unknown_required",
            "unknown tail record 40",
            "Tail.UnknownRequired",
            |e| append(e, &[0x40, 0x00, 0x00]),
        ),
        malformed_case(
            "tail_reply_key_length",
            "a reply key of 31 bytes",
            "Tail.Length",
            |e| append(e, &record(0x01, &REPLY_KEY[..31])),
        ),
        malformed_case(
            "tail_mailbox_key",
            "a reply mailbox key with prefix 05",
            "Tail.MailboxKey",
            |e| {
                let mut key = SECP_G;
                key[0] = 0x05;
                append(e, &reply_records(&key, MAILBOX_ADDRESS.as_bytes()))
            },
        ),
        malformed_case(
            "tail_mailbox_address",
            "a reply mailbox address with an underscore",
            "Tail.MailboxAddress",
            |e| append(e, &reply_records(&SECP_G, b"relay_example.net")),
        ),
        malformed_case(
            "tail_mailbox_address_empty",
            "a reply mailbox of the key alone",
            "Tail.Length",
            |e| append(e, &reply_records(&SECP_G, b"")),
        ),
        malformed_case(
            "tail_mailbox_address_too_long",
            "a reply mailbox address of 129 bytes",
            "Tail.Length",
            |e| {
                let mut address = "a".repeat(125);
                address.push_str(".net");
                append(e, &reply_records(&SECP_G, address.as_bytes()))
            },
        ),
        malformed_case(
            "tail_mailbox_without_key",
            "a reply mailbox without a reply key",
            "Tail.MailboxWithoutKey",
            |e| {
                let mut value = SECP_G.to_vec();
                value.extend_from_slice(MAILBOX_ADDRESS.as_bytes());
                append(e, &record(0x02, &value))
            },
        ),
        Malformed {
            base: (PLAIN, Stage::S2),
            ..malformed_case(
                "tail_reply_key_at_s2",
                "an S2 with a reply key",
                "Tail.NotAllowed",
                |e| append(e, &record(0x01, &REPLY_KEY)),
            )
        },
    ]
}

fn malformed(upstream: &Upstream, flows: &[(&Case, FlowRecord)]) -> Result<Vec<Rendered>, Error> {
    malformed_cases()
        .into_iter()
        .map(|case| {
            let (base_case, base_stage) = case.base;
            let shift = case
                .after_fork
                .then(|| case.encode_network.first_hard_fork());
            let mut slate = Shifted::new(stage_of(flows, base_case, base_stage)?, shift)?;
            (case.edit)(&mut slate.value)
                .ok_or_else(|| bad("mutating a lepic.v1 slate", case.name))?;
            let mut encoded = encode(&slate.value, slate.stage, case.encode_network, case.keep)?;
            (case.patch)(&mut encoded)
                .ok_or_else(|| bad("mutating a lepic.v1 slate", case.name))?;
            let mut base = format!("slates/{base_case}_{}_v3", base_stage.name().to_lowercase());
            if shift.is_some() {
                base.push_str(", after the first hard fork");
            }
            let inputs = MalformedInputs {
                base,
                mutation: case.mutation,
                decode_network: case.decode_network.name(),
                lepic_v1: hex(&encoded.bytes),
            };
            let expected = MalformedExpected { error: case.error };
            render_from(
                MODULE,
                AREA,
                &format!("malformed_{}", case.name),
                upstream,
                inputs,
                expected,
            )
        })
        .collect()
}
