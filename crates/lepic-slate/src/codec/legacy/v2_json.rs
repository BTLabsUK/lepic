//! The V2 JSON slate as `epic-wallet` `v4.1.0` reads and writes it (`docs/compat/legacy-slates.md`).
//! It is the V3 shape without the `ttl_cutoff_height` and `payment_proof` keys, so a slate in it
//! carries neither.
//!
//! This module repeats most of `v3_json.rs` on purpose: ADR 0002 gives every codec its own wire
//! structs, and the legacy codecs are frozen. A fix to a shared part must be made in both files.

use lepic_crypto::{Commitment, Signature};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::input::Input;
use lepic_primitives::kernel::KernelFeatures;
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_primitives::params::MAX_TX_WEIGHT;
use serde::Deserialize;

use super::bounded::{self, Bounded, check_participants, only_kernel};
use super::fields::{
    ObjectWriter, Scalar, field_error, integer, missing, number, optional_parsed, optional_text,
    parsed, text, write_array, write_hex, write_integer_string, write_null, write_number,
    write_string,
};
use crate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use crate::error::{
    DecodeError, EncodeError, FieldProblem, SlateError, TextPosition, Unrepresentable,
    ValidationError,
};
use crate::model::{KernelLock, Participant, ParticipantMessage, Slate, SlateParts};
use crate::origin::{LegacyHeader, WireOrigin};
use crate::role::Role;
use crate::stage::Stage;
use crate::validate::{
    KERNEL_PLACEHOLDER, LEGACY_PARTICIPANTS, check_kernel_features, check_minimum_fee, check_size,
    decode_hex_array, kernel_from_wire, legacy_participant_id, legacy_stage, parse_commitment,
    parse_offset, parse_public_key, parse_range_proof, parse_signature, parse_slate_id,
    role_from_legacy_id,
};

pub const LEGACY_V2_JSON: CodecId = CodecId::new("legacy-v2");

/// The `orig_version` of a slate this codec starts. Upstream creates every slate at version 3.
const NEW_SLATE_VERSION: u16 = 3;

/// The `version` every V2-shaped slate carries. Upstream `v4.1.0` sets it to 2 whenever it
/// converts a slate to the V2 shape, and keeps `orig_version` and `block_header_version`.
const V2_SHAPE_VERSION: u16 = 2;

/// The V2 JSON codec. It refuses slates whose fee is below `base_fee` per unit of the final
/// transaction's fee weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2JsonCodec {
    base_fee: Fee,
}

impl V2JsonCodec {
    pub const fn new(base_fee: Fee) -> Self {
        Self { base_fee }
    }

    const fn syntax(position: Option<TextPosition>) -> DecodeError {
        DecodeError::Syntax {
            codec: LEGACY_V2_JSON,
            position,
        }
    }

    const fn unrepresentable(what: Unrepresentable) -> EncodeError {
        EncodeError::Unrepresentable {
            codec: LEGACY_V2_JSON,
            what,
        }
    }
}

impl Codec for V2JsonCodec {
    fn id(&self) -> CodecId {
        LEGACY_V2_JSON
    }

    fn detect(&self, wire: &WireSlate) -> bool {
        is_v2_shape(wire)
    }

    fn decode(&self, wire: &WireSlate) -> Result<Slate, DecodeError> {
        check_size(wire)?;
        let text = wire.as_text().ok_or(Self::syntax(None))?;
        let slate: SlateV2 = serde_json::from_str(text).map_err(|error| {
            Self::syntax((error.line() > 0).then(|| TextPosition {
                line: error.line(),
                column: error.column(),
            }))
        })?;
        // Upstream tells the shapes apart by this key alone; with it the slate is V3.
        if !matches!(slate.ttl_cutoff_height, Scalar::Absent) {
            return Err(DecodeError::NotRecognised {
                codec: LEGACY_V2_JSON,
            });
        }
        // Upstream's V2 parse ignores a payment proof; refusing one keeps decode lossless.
        if !matches!(slate.payment_proof, Scalar::Absent | Scalar::Null) {
            return Err(field_error("payment_proof", FieldProblem::Unexpected));
        }
        let slate = slate.into_slate()?;
        check_fee_covers_weight(&slate, self.base_fee)?;
        Ok(slate)
    }

    fn encode(&self, slate: &Slate, context: &EncodeContext) -> Result<WireSlate, EncodeError> {
        if slate.payment_proof().is_some() {
            return Err(Self::unrepresentable(Unrepresentable::PaymentProof));
        }
        if slate.ttl_cutoff_height().is_some() {
            return Err(Self::unrepresentable(Unrepresentable::TimeToLive));
        }
        let header = slate
            .origin()
            .and_then(WireOrigin::legacy_header)
            .unwrap_or(LegacyHeader {
                version: NEW_SLATE_VERSION,
                orig_version: NEW_SLATE_VERSION,
                block_header_version: context.block_header_version,
            });
        let header = LegacyHeader {
            version: V2_SHAPE_VERSION,
            ..header
        };
        Ok(WireSlate::text(MediaType::JSON, write_slate(slate, header)))
    }
}

/// A JSON object without a top-level `ttl_cutoff_height` key.
fn is_v2_shape(wire: &WireSlate) -> bool {
    #[derive(Deserialize)]
    struct ShapeProbe {
        #[serde(default)]
        ttl_cutoff_height: Scalar,
    }
    if check_size(wire).is_err() {
        return false;
    }
    let Some(text) = wire.as_text() else {
        return false;
    };
    text.trim_start().starts_with('{')
        && serde_json::from_str::<ShapeProbe>(text)
            .is_ok_and(|probe| matches!(probe.ttl_cutoff_height, Scalar::Absent))
}

// Wire structs. Every field defaults to absent so a missing key becomes a typed field error;
// unknown keys are ignored, as upstream ignores them. The two V3 keys are read only to tell a
// V3 slate apart.

#[derive(Deserialize, Default)]
#[serde(default)]
struct SlateV2 {
    version_info: Option<VersionInfoV2>,
    num_participants: Scalar,
    id: Scalar,
    tx: Option<TransactionV2>,
    amount: Scalar,
    fee: Scalar,
    height: Scalar,
    lock_height: Scalar,
    #[serde(deserialize_with = "bounded::participants")]
    participant_data: Option<Bounded<ParticipantDataV2>>,
    ttl_cutoff_height: Scalar,
    payment_proof: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VersionInfoV2 {
    version: Scalar,
    orig_version: Scalar,
    block_header_version: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TransactionV2 {
    offset: Scalar,
    body: Option<TransactionBodyV2>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TransactionBodyV2 {
    #[serde(deserialize_with = "bounded::inputs")]
    inputs: Option<Bounded<InputV2>>,
    #[serde(deserialize_with = "bounded::outputs")]
    outputs: Option<Bounded<OutputV2>>,
    #[serde(deserialize_with = "bounded::kernels")]
    kernels: Option<Bounded<TxKernelV2>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct InputV2 {
    features: Scalar,
    commit: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OutputV2 {
    features: Scalar,
    commit: Scalar,
    proof: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TxKernelV2 {
    features: Scalar,
    fee: Scalar,
    lock_height: Scalar,
    excess: Scalar,
    excess_sig: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ParticipantDataV2 {
    id: Scalar,
    public_blind_excess: Scalar,
    public_nonce: Scalar,
    part_sig: Scalar,
    message: Scalar,
    message_sig: Scalar,
}

impl SlateV2 {
    /// Counts and ids are checked before any key, point or proof is parsed, so the work spent
    /// on a slate that is refused stays bounded by its size.
    fn into_slate(self) -> Result<Slate, DecodeError> {
        let header = self.version_info.ok_or(missing("version_info"))?.parse()?;
        // Both values reach the V2 shape: upstream `v4.1.0` writes 2, and `v4.0.2`'s Epicbox
        // sender kept the 3 of the slate it converted.
        if !matches!(header.version, 2 | 3) {
            return Err(DecodeError::UnsupportedVersion {
                codec: LEGACY_V2_JSON,
                version: u64::from(header.version),
            });
        }
        let declared = number::<u64>("num_participants", &self.num_participants)?;
        let participant_data = self.participant_data.ok_or(missing("participant_data"))?;
        let ids = participant_data
            .kept()
            .iter()
            .map(|data| integer("participant_data.id", &data.id))
            .collect::<Result<Vec<_>, _>>()?;
        check_participants(declared, &participant_data, &ids)?;

        let tx = self.tx.ok_or(missing("tx"))?;
        let body = tx.body.ok_or(missing("tx.body"))?;
        let inputs = body.inputs.ok_or(missing("tx.body.inputs"))?;
        let outputs = body.outputs.ok_or(missing("tx.body.outputs"))?;
        let kernels = body.kernels.ok_or(missing("tx.body.kernels"))?;
        // The full counts, so a truncated input or output array is refused here.
        check_body_weight(inputs.len(), outputs.len(), kernels.len())?;
        let kernel = only_kernel(&kernels)?;

        let fee = Fee::new(integer("fee", &self.fee)?);
        let lock = KernelLock::at_height(Height::new(integer("lock_height", &self.lock_height)?));
        check_kernel_features(kernel.features()?, fee, lock)?;
        let (excess, excess_sig) = kernel.excess()?;

        let mut sender = None;
        let mut receiver = None;
        let mut entries = Vec::with_capacity(ids.len());
        for (data, id) in participant_data.kept().iter().zip(ids) {
            let role = role_from_legacy_id(id)?;
            let participant = data.parse()?;
            entries.push((role, participant.is_signed()));
            match role {
                Role::Sender => sender = Some(participant),
                Role::Receiver => receiver = Some(participant),
            }
        }
        let stage = legacy_stage(&entries)?;

        let slate = Slate::from_parts(SlateParts {
            id: parsed("id", &self.id, parse_slate_id)?,
            stage,
            amount: Amount::new(integer("amount", &self.amount)?),
            fee,
            height: Height::new(integer("height", &self.height)?),
            lock,
            ttl_cutoff_height: None,
            offset: parsed("tx.offset", &tx.offset, parse_offset)?,
            sender,
            receiver,
            inputs: inputs
                .kept()
                .iter()
                .map(InputV2::parse)
                .collect::<Result<_, _>>()?,
            outputs: outputs
                .kept()
                .iter()
                .map(OutputV2::parse)
                .collect::<Result<_, _>>()?,
            kernel: kernel_from_wire(&excess, &excess_sig)?,
            payment_proof: None,
            origin: Some(WireOrigin::legacy(LEGACY_V2_JSON, header)),
        })?;
        Ok(slate)
    }
}

impl VersionInfoV2 {
    fn parse(&self) -> Result<LegacyHeader, DecodeError> {
        Ok(LegacyHeader {
            version: number("version_info.version", &self.version)?,
            orig_version: number("version_info.orig_version", &self.orig_version)?,
            block_header_version: number(
                "version_info.block_header_version",
                &self.block_header_version,
            )?,
        })
    }
}

impl InputV2 {
    fn parse(&self) -> Result<Input, DecodeError> {
        Ok(Input::new(
            output_features("tx.body.inputs.features", &self.features)?,
            parsed("tx.body.inputs.commit", &self.commit, parse_commitment)?,
        ))
    }
}

impl OutputV2 {
    fn parse(&self) -> Result<Output, DecodeError> {
        Ok(Output::new(
            output_features("tx.body.outputs.features", &self.features)?,
            parsed("tx.body.outputs.commit", &self.commit, parse_commitment)?,
            parsed("tx.body.outputs.proof", &self.proof, parse_range_proof)?,
        ))
    }
}

impl TxKernelV2 {
    fn features(&self) -> Result<KernelFeatures, DecodeError> {
        const FIELD: &str = "tx.body.kernels.features";
        let fee = Fee::new(integer("tx.body.kernels.fee", &self.fee)?);
        let lock_height = Height::new(integer("tx.body.kernels.lock_height", &self.lock_height)?);
        match text(FIELD, &self.features)? {
            // Upstream drops the lock height of a plain kernel; refusing a non-zero one keeps
            // decode and encode inverse.
            "Plain" if lock_height == Height::ZERO => Ok(KernelFeatures::Plain { fee }),
            "Plain" => Err(ValidationError::KernelLockMismatch {
                slate: Height::ZERO,
                kernel: lock_height,
            }
            .into()),
            "HeightLocked" => Ok(KernelFeatures::HeightLocked { fee, lock_height }),
            "Coinbase" => Ok(KernelFeatures::Coinbase),
            _ => Err(field_error(FIELD, FieldProblem::UnsupportedValue)),
        }
    }

    fn excess(&self) -> Result<([u8; Commitment::LEN], [u8; Signature::LEN]), DecodeError> {
        Ok((
            parsed("tx.body.kernels.excess", &self.excess, |hex| {
                decode_hex_array(hex).map_err(FieldProblem::Hex)
            })?,
            parsed("tx.body.kernels.excess_sig", &self.excess_sig, |hex| {
                decode_hex_array(hex).map_err(FieldProblem::Hex)
            })?,
        ))
    }
}

impl ParticipantDataV2 {
    fn parse(&self) -> Result<Participant, DecodeError> {
        let mut participant = Participant::new(
            parsed(
                "participant_data.public_blind_excess",
                &self.public_blind_excess,
                parse_public_key,
            )?,
            parsed(
                "participant_data.public_nonce",
                &self.public_nonce,
                parse_public_key,
            )?,
        );
        participant.partial_signature =
            optional_parsed("participant_data.part_sig", &self.part_sig, parse_signature)?;
        participant.message = self.message()?;
        Ok(participant)
    }

    /// Upstream writes the message and its signature together, and reads a missing message
    /// key as no message.
    fn message(&self) -> Result<Option<ParticipantMessage>, DecodeError> {
        let text = match &self.message {
            Scalar::Absent => None,
            other => optional_text("participant_data.message", other)?,
        };
        let signature = optional_parsed(
            "participant_data.message_sig",
            &self.message_sig,
            parse_signature,
        )?;
        match (text, signature) {
            (Some(text), Some(signature)) => {
                Ok(Some(ParticipantMessage::new(text.to_owned(), signature)?))
            }
            (None, None) => Ok(None),
            (Some(_), None) => Err(missing("participant_data.message_sig")),
            (None, Some(_)) => Err(field_error(
                "participant_data.message_sig",
                FieldProblem::Unexpected,
            )),
        }
    }
}

fn output_features(field: &'static str, value: &Scalar) -> Result<OutputFeatures, DecodeError> {
    match text(field, value)? {
        "Plain" => Ok(OutputFeatures::Plain),
        "Coinbase" => Ok(OutputFeatures::Coinbase),
        _ => Err(field_error(field, FieldProblem::UnsupportedValue)),
    }
}

fn check_body_weight(inputs: usize, outputs: usize, kernels: usize) -> Result<(), SlateError> {
    let count = |len: usize| u64::try_from(len).unwrap_or(u64::MAX);
    let weight = BodyCounts::new(count(inputs), count(outputs), count(kernels)).weight_as_block();
    if weight > MAX_TX_WEIGHT {
        return Err(SlateError::BodyTooHeavy {
            weight,
            max: MAX_TX_WEIGHT,
        });
    }
    Ok(())
}

/// The fee covers the final transaction. An S1 slate lacks the one output the receiver adds,
/// and an I1 slate has no fee until the sender chooses it.
fn check_fee_covers_weight(slate: &Slate, base_fee: Fee) -> Result<(), ValidationError> {
    let missing_outputs = match slate.stage() {
        Stage::I1 => return Ok(()),
        Stage::S1 => 1,
        Stage::S2 | Stage::S3 | Stage::I2 | Stage::I3 => 0,
    };
    let count = |len: usize| u64::try_from(len).unwrap_or(u64::MAX);
    let counts = BodyCounts::new(
        count(slate.inputs().len()),
        count(slate.outputs().len()).saturating_add(missing_outputs),
        1,
    );
    check_minimum_fee(slate.fee(), counts, base_fee)
}

/// Writes the slate with upstream's key order and value forms: integers as strings except the
/// header and participant count, `null` for every absent optional value. The caller has checked
/// that the slate has no TTL and no payment proof.
fn write_slate(slate: &Slate, header: LegacyHeader) -> String {
    let mut out = String::new();
    let mut object = ObjectWriter::open(&mut out);
    write_header(object.key("version_info"), header);
    write_number(object.key("num_participants"), LEGACY_PARTICIPANTS);
    write_string(object.key("id"), &slate.id().to_string());
    write_transaction(object.key("tx"), slate);
    write_integer_string(object.key("amount"), slate.amount().value());
    write_integer_string(object.key("fee"), slate.fee().value());
    write_integer_string(object.key("height"), slate.height().value());
    write_integer_string(
        object.key("lock_height"),
        slate.lock().lock_height().value(),
    );
    write_array(
        object.key("participant_data"),
        slate.participants(),
        |out, (role, participant)| write_participant(out, role, participant),
    );
    object.close();
    out
}

fn write_header(out: &mut String, header: LegacyHeader) {
    let mut object = ObjectWriter::open(out);
    write_number(object.key("version"), u64::from(header.version));
    write_number(object.key("orig_version"), u64::from(header.orig_version));
    write_number(
        object.key("block_header_version"),
        u64::from(header.block_header_version),
    );
    object.close();
}

fn write_transaction(out: &mut String, slate: &Slate) {
    let mut tx = ObjectWriter::open(out);
    write_string(tx.key("offset"), &slate.offset().to_hex());
    let mut body = ObjectWriter::open(tx.key("body"));
    write_array(body.key("inputs"), slate.inputs(), |out, input| {
        let mut object = ObjectWriter::open(out);
        write_string(object.key("features"), output_features_name(input.features));
        write_hex(object.key("commit"), input.commitment.as_bytes());
        object.close();
    });
    write_array(body.key("outputs"), slate.outputs(), |out, output| {
        let mut object = ObjectWriter::open(out);
        write_string(
            object.key("features"),
            output_features_name(output.features),
        );
        write_hex(object.key("commit"), output.commitment.as_bytes());
        write_hex(object.key("proof"), output.proof.as_bytes());
        object.close();
    });
    write_array(body.key("kernels"), [slate], write_kernel);
    body.close();
    tx.close();
}

/// The kernel as upstream's `CompatKernelFeatures` writes it, with the all-zero placeholder
/// before the final stage.
fn write_kernel(out: &mut String, slate: &Slate) {
    let (name, fee, lock_height) = match slate.kernel_features() {
        KernelFeatures::Plain { fee } => ("Plain", fee, Height::ZERO),
        KernelFeatures::HeightLocked { fee, lock_height } => ("HeightLocked", fee, lock_height),
        KernelFeatures::Coinbase => ("Coinbase", Fee::ZERO, Height::ZERO),
    };
    let (excess, excess_sig) = slate.kernel().map_or(KERNEL_PLACEHOLDER, |kernel| {
        (*kernel.excess.as_bytes(), kernel.excess_sig.to_compact())
    });
    let mut object = ObjectWriter::open(out);
    write_string(object.key("features"), name);
    write_integer_string(object.key("fee"), fee.value());
    write_integer_string(object.key("lock_height"), lock_height.value());
    write_hex(object.key("excess"), &excess);
    write_hex(object.key("excess_sig"), &excess_sig);
    object.close();
}

fn write_participant(out: &mut String, role: Role, participant: &Participant) {
    let mut object = ObjectWriter::open(out);
    write_integer_string(object.key("id"), legacy_participant_id(role));
    write_hex(
        object.key("public_blind_excess"),
        &participant.public_blind_excess.to_bytes(),
    );
    write_hex(
        object.key("public_nonce"),
        &participant.public_nonce.to_bytes(),
    );
    match &participant.partial_signature {
        Some(signature) => write_hex(object.key("part_sig"), &signature.to_compact()),
        None => write_null(object.key("part_sig")),
    }
    match &participant.message {
        Some(message) => {
            write_string(object.key("message"), message.text());
            write_hex(object.key("message_sig"), &message.signature().to_compact());
        }
        None => {
            write_null(object.key("message"));
            write_null(object.key("message_sig"));
        }
    }
    object.close();
}

const fn output_features_name(features: OutputFeatures) -> &'static str {
    match features {
        OutputFeatures::Plain => "Plain",
        OutputFeatures::Coinbase => "Coinbase",
    }
}
