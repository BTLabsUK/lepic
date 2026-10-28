// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/slate_versions/v3.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! The V3 JSON slate as `epic-wallet` `v4.1.0` reads and writes it (`docs/compat/legacy-slates.md`).
//!
//! This module repeats most of `v2_json.rs` on purpose: ADR 0002 gives every codec its own wire
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
    ObjectWriter, Scalar, field_error, integer, missing, number, optional_integer, optional_parsed,
    optional_text, parsed, text, write_array, write_hex, write_integer_string, write_null,
    write_number, write_string,
};
use crate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use crate::error::{DecodeError, EncodeError, FieldProblem, SlateError, ValidationError};
use crate::model::{KernelLock, Participant, ParticipantMessage, PaymentProof, Slate, SlateParts};
use crate::origin::{LegacyHeader, WireOrigin};
use crate::role::Role;
use crate::stage::Stage;
use crate::validate::{
    KERNEL_PLACEHOLDER, LEGACY_PARTICIPANTS, check_kernel_features, check_minimum_fee, check_size,
    decode_hex_array, kernel_from_wire, legacy_participant_id, legacy_stage, parse_commitment,
    parse_offset, parse_proof_address, parse_proof_signature, parse_public_key, parse_range_proof,
    parse_signature, parse_slate_id, role_from_legacy_id,
};

pub const LEGACY_V3_JSON: CodecId = CodecId::new("legacy-v3");

/// The header of a slate this codec starts, rather than one that answers a received slate.
const NEW_SLATE_VERSION: u16 = 3;

/// The `version` every V3-shaped slate carries.
const V3_SHAPE_VERSION: u16 = 3;

/// The V3 JSON codec. It refuses slates whose fee is below `base_fee` per unit of the final
/// transaction's fee weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3JsonCodec {
    base_fee: Fee,
}

impl V3JsonCodec {
    pub const fn new(base_fee: Fee) -> Self {
        Self { base_fee }
    }

    const fn syntax(position: Option<crate::error::TextPosition>) -> DecodeError {
        DecodeError::Syntax {
            codec: LEGACY_V3_JSON,
            position,
        }
    }
}

impl Codec for V3JsonCodec {
    fn id(&self) -> CodecId {
        LEGACY_V3_JSON
    }

    fn detect(&self, wire: &WireSlate) -> bool {
        is_v3_shape(wire)
    }

    fn decode(&self, wire: &WireSlate) -> Result<Slate, DecodeError> {
        check_size(wire)?;
        let text = wire.as_text().ok_or(Self::syntax(None))?;
        let slate: SlateV3 = serde_json::from_str(text).map_err(|error| {
            Self::syntax((error.line() > 0).then(|| crate::error::TextPosition {
                line: error.line(),
                column: error.column(),
            }))
        })?;
        // Upstream tells the shapes apart by this key alone; without it the slate is V2.
        if matches!(slate.ttl_cutoff_height, Scalar::Absent) {
            return Err(DecodeError::NotRecognised {
                codec: LEGACY_V3_JSON,
            });
        }
        let slate = slate.into_slate()?;
        check_fee_covers_weight(&slate, self.base_fee)?;
        Ok(slate)
    }

    fn encode(&self, slate: &Slate, context: &EncodeContext) -> Result<WireSlate, EncodeError> {
        let header = slate
            .origin()
            .and_then(WireOrigin::legacy_header)
            .unwrap_or(LegacyHeader {
                version: NEW_SLATE_VERSION,
                orig_version: NEW_SLATE_VERSION,
                block_header_version: context.block_header_version,
            });
        // Upstream `v4.1.0` writes `version` 3 on every V3-shaped slate, whatever header it
        // read, and keeps `orig_version` and `block_header_version`.
        let header = LegacyHeader {
            version: V3_SHAPE_VERSION,
            ..header
        };
        Ok(WireSlate::text(MediaType::JSON, write_slate(slate, header)))
    }
}

/// A JSON object with a top-level `ttl_cutoff_height` key, whatever its value.
fn is_v3_shape(wire: &WireSlate) -> bool {
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
            .is_ok_and(|probe| !matches!(probe.ttl_cutoff_height, Scalar::Absent))
}

// Wire structs. Every field defaults to absent so a missing key becomes a typed field error;
// unknown keys are ignored, as upstream ignores them.

#[derive(Deserialize, Default)]
#[serde(default)]
struct SlateV3 {
    version_info: Option<VersionInfoV3>,
    num_participants: Scalar,
    id: Scalar,
    tx: Option<TransactionV3>,
    amount: Scalar,
    fee: Scalar,
    height: Scalar,
    lock_height: Scalar,
    ttl_cutoff_height: Scalar,
    #[serde(deserialize_with = "bounded::participants")]
    participant_data: Option<Bounded<ParticipantDataV3>>,
    payment_proof: Option<PaymentInfoV3>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VersionInfoV3 {
    version: Scalar,
    orig_version: Scalar,
    block_header_version: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TransactionV3 {
    offset: Scalar,
    body: Option<TransactionBodyV3>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TransactionBodyV3 {
    #[serde(deserialize_with = "bounded::inputs")]
    inputs: Option<Bounded<InputV3>>,
    #[serde(deserialize_with = "bounded::outputs")]
    outputs: Option<Bounded<OutputV3>>,
    #[serde(deserialize_with = "bounded::kernels")]
    kernels: Option<Bounded<TxKernelV3>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct InputV3 {
    features: Scalar,
    commit: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OutputV3 {
    features: Scalar,
    commit: Scalar,
    proof: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TxKernelV3 {
    features: Scalar,
    fee: Scalar,
    lock_height: Scalar,
    excess: Scalar,
    excess_sig: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ParticipantDataV3 {
    id: Scalar,
    public_blind_excess: Scalar,
    public_nonce: Scalar,
    part_sig: Scalar,
    message: Scalar,
    message_sig: Scalar,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PaymentInfoV3 {
    sender_address: Scalar,
    receiver_address: Scalar,
    receiver_signature: Scalar,
}

impl SlateV3 {
    /// Counts and ids are checked before any key, point or proof is parsed, so the work spent
    /// on a slate that is refused stays bounded by its size.
    fn into_slate(self) -> Result<Slate, DecodeError> {
        let header = self.version_info.ok_or(missing("version_info"))?.parse()?;
        if !matches!(header.version, 2 | 3) {
            return Err(DecodeError::UnsupportedVersion {
                codec: LEGACY_V3_JSON,
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
            ttl_cutoff_height: optional_integer("ttl_cutoff_height", &self.ttl_cutoff_height)?
                .map(Height::new),
            offset: parsed("tx.offset", &tx.offset, parse_offset)?,
            sender,
            receiver,
            inputs: inputs
                .kept()
                .iter()
                .map(InputV3::parse)
                .collect::<Result<_, _>>()?,
            outputs: outputs
                .kept()
                .iter()
                .map(OutputV3::parse)
                .collect::<Result<_, _>>()?,
            kernel: kernel_from_wire(&excess, &excess_sig)?,
            payment_proof: self.payment_proof.map(|proof| proof.parse()).transpose()?,
            origin: Some(WireOrigin::legacy(LEGACY_V3_JSON, header)),
        })?;
        Ok(slate)
    }
}

impl VersionInfoV3 {
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

impl InputV3 {
    fn parse(&self) -> Result<Input, DecodeError> {
        Ok(Input::new(
            output_features("tx.body.inputs.features", &self.features)?,
            parsed("tx.body.inputs.commit", &self.commit, parse_commitment)?,
        ))
    }
}

impl OutputV3 {
    fn parse(&self) -> Result<Output, DecodeError> {
        Ok(Output::new(
            output_features("tx.body.outputs.features", &self.features)?,
            parsed("tx.body.outputs.commit", &self.commit, parse_commitment)?,
            parsed("tx.body.outputs.proof", &self.proof, parse_range_proof)?,
        ))
    }
}

impl TxKernelV3 {
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

impl ParticipantDataV3 {
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

impl PaymentInfoV3 {
    fn parse(&self) -> Result<PaymentProof, DecodeError> {
        Ok(PaymentProof {
            sender_address: parsed(
                "payment_proof.sender_address",
                &self.sender_address,
                parse_proof_address,
            )?,
            receiver_address: parsed(
                "payment_proof.receiver_address",
                &self.receiver_address,
                parse_proof_address,
            )?,
            receiver_signature: optional_parsed(
                "payment_proof.receiver_signature",
                &self.receiver_signature,
                parse_proof_signature,
            )?,
        })
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
/// header and participant count, `null` for every absent optional value.
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
    match slate.ttl_cutoff_height() {
        Some(height) => write_integer_string(object.key("ttl_cutoff_height"), height.value()),
        None => write_null(object.key("ttl_cutoff_height")),
    }
    write_array(
        object.key("participant_data"),
        slate.participants(),
        |out, (role, participant)| write_participant(out, role, participant),
    );
    match slate.payment_proof() {
        Some(proof) => write_payment_proof(object.key("payment_proof"), proof),
        None => write_null(object.key("payment_proof")),
    }
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

fn write_payment_proof(out: &mut String, proof: &PaymentProof) {
    let mut object = ObjectWriter::open(out);
    write_hex(
        object.key("sender_address"),
        proof.sender_address.as_bytes(),
    );
    write_hex(
        object.key("receiver_address"),
        proof.receiver_address.as_bytes(),
    );
    match &proof.receiver_signature {
        Some(signature) => write_hex(object.key("receiver_signature"), signature.as_bytes()),
        None => write_null(object.key("receiver_signature")),
    }
    object.close();
}

const fn output_features_name(features: OutputFeatures) -> &'static str {
    match features {
        OutputFeatures::Plain => "Plain",
        OutputFeatures::Coinbase => "Coinbase",
    }
}
