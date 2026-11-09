// SPDX-License-Identifier: Apache-2.0
//! A slate with its extension tail, and its `lepic.v1` bytes.

use std::collections::HashSet;

use lepic_crypto::{Commitment, CryptoError, PublicKey, RangeProof, Signature};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::input::Input;
use lepic_primitives::kernel::KernelFeatures;
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_primitives::params::{MAX_TX_WEIGHT, Network};
use lepic_slate::codec::MAX_WIRE_SLATE_LEN;
use lepic_slate::error::SlateError;
use lepic_slate::model::{
    FinalKernel, KernelLock, MAX_MESSAGE_LEN, Participant, ParticipantMessage, PaymentProof,
    ProofAddress, ProofSignature, Slate, SlateId, SlateParts,
};
use lepic_slate::origin::WireOrigin;
use lepic_slate::role::Role;
use lepic_slate::stage::{Flow, Stage, Step};

use crate::error::NativeError;
use crate::tail::Tail;
use crate::wire::Reader;
use crate::{HEADER_LEN, MAGIC, NATIVE_V1, VERSION};

/// Flag bit 0, once `LOCK`; it must be zero.
pub const FLAG_RESERVED: u8 = 0x01;
pub const FLAG_TTL: u8 = 0x02;
pub const FLAG_PROOF: u8 = 0x04;
pub const FLAG_SENDER_MESSAGE: u8 = 0x08;
pub const FLAG_RECEIVER_MESSAGE: u8 = 0x10;
const KNOWN_FLAGS: u8 = FLAG_TTL | FLAG_PROOF | FLAG_SENDER_MESSAGE | FLAG_RECEIVER_MESSAGE;

const PLAIN: u8 = KernelFeatures::Plain { fee: Fee::ZERO }.as_u8();
const HEIGHT_LOCKED: u8 = KernelFeatures::HeightLocked {
    fee: Fee::ZERO,
    lock_height: Height::ZERO,
}
.as_u8();

/// Wire size of an input: features and commitment.
pub const INPUT_LEN: usize = 1 + Commitment::LEN;
/// Wire size of an output: features, commitment and a single bulletproof.
pub const OUTPUT_LEN: usize = 1 + Commitment::LEN + RangeProof::BULLETPROOF_LEN;

/// A slate as `lepic.v1` carries it, with its extension tail.
///
/// `lepic.v1` leaves out what the other party already has or does not need: the body of a
/// proposal (S1, I1) and the initiator's message once the responder answered (S2, I2).
/// [`NativeSlate::new`] drops both, so the slate held here is the one that decoding its bytes
/// gives back, and `encode(decode(x)) == x` for every accepted `x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSlate {
    slate: Slate,
    tail: Tail,
}

impl NativeSlate {
    /// Refuses known tail records outside a proposal, and range proofs of a length other than a
    /// single bulletproof's.
    pub fn new(slate: Slate, tail: Tail) -> Result<Self, NativeError> {
        tail.check_stage(slate.stage())?;
        check_proof_lengths(&slate)?;
        Ok(Self {
            slate: carried(slate)?,
            tail,
        })
    }

    /// Decodes a slate for `network`, refusing one for the other network.
    pub fn decode(network: Network, bytes: &[u8]) -> Result<Self, NativeError> {
        decode(Some(network), bytes).map(|(_, slate)| slate)
    }

    /// Decodes a slate for whichever network its header names.
    pub fn decode_any(bytes: &[u8]) -> Result<(Network, Self), NativeError> {
        decode(None, bytes)
    }

    /// The `lepic.v1` bytes of this slate on `network`, its tail last.
    pub fn encode(&self, network: Network) -> Vec<u8> {
        let mut out = encode_slate(&self.slate, network);
        self.tail.encode(&mut out);
        out
    }

    pub const fn slate(&self) -> &Slate {
        &self.slate
    }

    pub const fn tail(&self) -> &Tail {
        &self.tail
    }

    pub fn into_parts(self) -> (Slate, Tail) {
        (self.slate, self.tail)
    }
}

/// Whether a party is present at a stage, and whether it has signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    Absent,
    Unsigned,
    Signed,
}

/// The initiator proposes unsigned, the responder joins signed, and the initiator signs last.
fn presence(stage: Stage, role: Role) -> Presence {
    let is_initiator = stage.flow().initiator() == role;
    match (stage.step(), is_initiator) {
        (Step::Proposed | Step::Responded, true) => Presence::Unsigned,
        (Step::Proposed, false) => Presence::Absent,
        (Step::Responded, false) | (Step::Finalized, _) => Presence::Signed,
    }
}

/// Whether `lepic.v1` carries `role`'s message at `stage`: not for an absent party, and not for
/// the initiator once the responder answered, since the initiator already has its own.
fn carries_message(stage: Stage, role: Role) -> bool {
    presence(stage, role) != Presence::Absent
        && !(stage.step() == Step::Responded && stage.flow().initiator() == role)
}

const fn message_flag(role: Role) -> u8 {
    match role {
        Role::Sender => FLAG_SENDER_MESSAGE,
        Role::Receiver => FLAG_RECEIVER_MESSAGE,
    }
}

/// The parts of `slate` that `lepic.v1` carries.
fn carried(slate: Slate) -> Result<Slate, NativeError> {
    let stage = slate.stage();
    let strips_body = stage.step() == Step::Proposed
        && !(slate.inputs().is_empty() && slate.outputs().is_empty());
    let strips_message = Role::ALL.into_iter().any(|role| {
        !carries_message(stage, role)
            && slate
                .participant(role)
                .is_some_and(|data| data.message.is_some())
    });
    if !strips_body && !strips_message {
        return Ok(slate);
    }
    let mut parts = slate.into_parts();
    if stage.step() == Step::Proposed {
        parts.inputs.clear();
        parts.outputs.clear();
    }
    for role in Role::ALL {
        let data = match role {
            Role::Sender => parts.sender.as_mut(),
            Role::Receiver => parts.receiver.as_mut(),
        };
        if let Some(data) = data
            && !carries_message(stage, role)
        {
            data.message = None;
        }
    }
    Ok(Slate::from_parts(parts)?)
}

/// `lepic.v1` writes range proofs without a length, so each must be a single bulletproof.
pub(crate) fn check_proof_lengths(slate: &Slate) -> Result<(), NativeError> {
    if slate.stage().step() == Step::Proposed {
        return Ok(());
    }
    match slate
        .outputs()
        .iter()
        .map(|output| output.proof.as_bytes().len())
        .find(|len| *len != RangeProof::BULLETPROOF_LEN)
    {
        Some(len) => Err(NativeError::RangeProofLength {
            len,
            expected: RangeProof::BULLETPROOF_LEN,
        }),
        None => Ok(()),
    }
}

const fn stage_byte(stage: Stage) -> u8 {
    match stage {
        Stage::S1 => 1,
        Stage::S2 => 2,
        Stage::S3 => 3,
        Stage::I1 => 4,
        Stage::I2 => 5,
        Stage::I3 => 6,
    }
}

const fn stage_from_byte(byte: u8) -> Option<Stage> {
    match byte {
        1 => Some(Stage::S1),
        2 => Some(Stage::S2),
        3 => Some(Stage::S3),
        4 => Some(Stage::I1),
        5 => Some(Stage::I2),
        6 => Some(Stage::I3),
        _ => None,
    }
}

pub(crate) const fn network_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Floonet => 1,
    }
}

const fn network_from_byte(byte: u8) -> Option<Network> {
    match byte {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Floonet),
        _ => None,
    }
}

/// The flags byte `lepic.v1` writes for `slate`.
pub(crate) fn flags(slate: &Slate) -> u8 {
    let mut flags = 0;
    if slate.ttl_cutoff_height().is_some() {
        flags |= FLAG_TTL;
    }
    if slate.payment_proof().is_some() {
        flags |= FLAG_PROOF;
    }
    for role in Role::ALL {
        if carries_message(slate.stage(), role)
            && slate
                .participant(role)
                .is_some_and(|data| data.message.is_some())
        {
            flags |= message_flag(role);
        }
    }
    flags
}

/// Header version the slate's height takes on `network`.
pub(crate) const fn header_version(network: Network, height: Height) -> u16 {
    network.params().block_header_version(height)
}

/// Field names of one party, for errors.
struct Names {
    excess: &'static str,
    nonce: &'static str,
    partial_signature: &'static str,
    message_length: &'static str,
    message: &'static str,
    message_signature: &'static str,
}

const fn names(role: Role) -> Names {
    match role {
        Role::Sender => Names {
            excess: "sender.public_blind_excess",
            nonce: "sender.public_nonce",
            partial_signature: "sender.partial_signature",
            message_length: "sender.message_length",
            message: "sender.message",
            message_signature: "sender.message_signature",
        },
        Role::Receiver => Names {
            excess: "receiver.public_blind_excess",
            nonce: "receiver.public_nonce",
            partial_signature: "receiver.partial_signature",
            message_length: "receiver.message_length",
            message: "receiver.message",
            message_signature: "receiver.message_signature",
        },
    }
}

/// Only the one encoding each point writes back is accepted, so re-encoding gives the input.
fn public_key(bytes: &[u8; PublicKey::LEN], field: &'static str) -> Result<PublicKey, NativeError> {
    let key =
        PublicKey::from_bytes(bytes).map_err(|source| NativeError::Crypto { field, source })?;
    if key.to_bytes() != *bytes {
        return Err(NativeError::Crypto {
            field,
            source: CryptoError::InvalidPublicKey,
        });
    }
    Ok(key)
}

fn signature(bytes: &[u8; Signature::LEN], field: &'static str) -> Result<Signature, NativeError> {
    let signature =
        Signature::from_compact(bytes).map_err(|source| NativeError::Crypto { field, source })?;
    if signature.to_compact() != *bytes {
        return Err(NativeError::Crypto {
            field,
            source: CryptoError::InvalidSignature,
        });
    }
    Ok(signature)
}

fn commitment(bytes: &[u8], field: &'static str) -> Result<Commitment, NativeError> {
    let commitment =
        Commitment::from_bytes(bytes).map_err(|source| NativeError::Crypto { field, source })?;
    if commitment.as_bytes().as_slice() != bytes {
        return Err(NativeError::Crypto {
            field,
            source: CryptoError::InvalidCommitment,
        });
    }
    Ok(commitment)
}

fn proof_address(
    bytes: &[u8; ProofAddress::LEN],
    field: &'static str,
) -> Result<ProofAddress, NativeError> {
    ProofAddress::from_bytes(*bytes).map_err(|source| NativeError::ProofAddress { field, source })
}

fn output_features(byte: u8, field: &'static str) -> Result<OutputFeatures, NativeError> {
    OutputFeatures::from_u8(byte).ok_or(NativeError::OutputFeatures { field, byte })
}

fn participant(
    reader: &mut Reader<'_>,
    role: Role,
    signed: bool,
    has_message: bool,
) -> Result<Participant, NativeError> {
    let names = names(role);
    let mut data = Participant::new(
        public_key(reader.array(names.excess)?, names.excess)?,
        public_key(reader.array(names.nonce)?, names.nonce)?,
    );
    if signed {
        data.partial_signature = Some(signature(
            reader.array(names.partial_signature)?,
            names.partial_signature,
        )?);
    }
    if has_message {
        let len = usize::from(reader.u16(names.message_length)?);
        if len > MAX_MESSAGE_LEN {
            return Err(NativeError::MessageTooLong {
                role,
                len,
                max: MAX_MESSAGE_LEN,
            });
        }
        let text = std::str::from_utf8(reader.take(len, names.message)?)
            .map_err(|_| NativeError::MessageNotUtf8 { role })?;
        let sig = signature(
            reader.array(names.message_signature)?,
            names.message_signature,
        )?;
        data.message = Some(ParticipantMessage::new(text.to_owned(), sig)?);
    }
    Ok(data)
}

/// The byte ranges of a body, checked before anything is built from them.
struct Body<'a> {
    inputs: &'a [u8],
    outputs: &'a [u8],
}

impl Body<'_> {
    /// Refuses everything [`Slate::from_parts`] would refuse about the body, without building it.
    fn check(&self) -> Result<(), NativeError> {
        let mut inputs = HashSet::new();
        for input in self.inputs.as_chunks::<INPUT_LEN>().0 {
            let (&features, key) = input
                .split_first()
                .ok_or(NativeError::Truncated { field: "input" })?;
            output_features(features, "input.features")?;
            let commitment = commitment(key, "input.commitment")?;
            if !inputs.insert(commitment) {
                return Err(SlateError::DuplicateInput { commitment }.into());
            }
        }
        let mut outputs = HashSet::new();
        for output in self.outputs.as_chunks::<OUTPUT_LEN>().0 {
            let (&features, rest) = output
                .split_first()
                .ok_or(NativeError::Truncated { field: "output" })?;
            let key = rest
                .get(..Commitment::LEN)
                .ok_or(NativeError::Truncated { field: "output" })?;
            if output_features(features, "output.features")?.is_coinbase() {
                return Err(SlateError::CoinbaseOutput.into());
            }
            let commitment = commitment(key, "output.commitment")?;
            if !outputs.insert(commitment) {
                return Err(SlateError::DuplicateOutput { commitment }.into());
            }
            if inputs.contains(&commitment) {
                return Err(SlateError::InputSpendsOutput { commitment }.into());
            }
        }
        Ok(())
    }

    fn build(&self) -> Result<(Vec<Input>, Vec<Output>), NativeError> {
        let mut inputs = Vec::with_capacity(self.inputs.len() / INPUT_LEN);
        for input in self.inputs.as_chunks::<INPUT_LEN>().0 {
            let (&features, key) = input
                .split_first()
                .ok_or(NativeError::Truncated { field: "input" })?;
            inputs.push(Input::new(
                output_features(features, "input.features")?,
                commitment(key, "input.commitment")?,
            ));
        }
        let mut outputs = Vec::with_capacity(self.outputs.len() / OUTPUT_LEN);
        for output in self.outputs.as_chunks::<OUTPUT_LEN>().0 {
            let (&features, rest) = output
                .split_first()
                .ok_or(NativeError::Truncated { field: "output" })?;
            let (key, proof) = rest
                .split_at_checked(Commitment::LEN)
                .ok_or(NativeError::Truncated { field: "output" })?;
            outputs.push(Output::new(
                output_features(features, "output.features")?,
                commitment(key, "output.commitment")?,
                RangeProof::from_bytes(proof).map_err(|source| NativeError::Crypto {
                    field: "output.proof",
                    source,
                })?,
            ));
        }
        Ok((inputs, outputs))
    }
}

/// Byte length of `count` entries of `size` bytes; counts are `u16`, so this never overflows.
fn span(count: u16, size: usize) -> usize {
    usize::from(count).saturating_mul(size)
}

#[allow(clippy::too_many_lines)] // the layout, field by field, in wire order
fn decode(expected: Option<Network>, bytes: &[u8]) -> Result<(Network, NativeSlate), NativeError> {
    if bytes.len() > MAX_WIRE_SLATE_LEN {
        return Err(NativeError::TooLarge {
            len: bytes.len(),
            max: MAX_WIRE_SLATE_LEN,
        });
    }
    if !bytes.starts_with(&MAGIC) {
        return Err(NativeError::Magic);
    }
    let mut reader = Reader::new(bytes);
    reader.take(MAGIC.len(), "magic")?;
    let version = reader.u8("version")?;
    if version != VERSION {
        return Err(NativeError::Version { version });
    }
    if bytes.len() < HEADER_LEN {
        return Err(NativeError::Truncated { field: "header" });
    }
    let network_byte = reader.u8("network")?;
    let network = network_from_byte(network_byte)
        .ok_or(NativeError::UnknownNetwork { byte: network_byte })?;
    if let Some(expected) = expected
        && expected != network
    {
        return Err(NativeError::WrongNetwork {
            expected,
            found: network,
        });
    }
    let stage_byte = reader.u8("stage")?;
    let stage =
        stage_from_byte(stage_byte).ok_or(NativeError::UnknownStage { byte: stage_byte })?;
    let flags = reader.u8("flags")?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(NativeError::ReservedFlag { flags });
    }
    let features = reader.u8("kernel_features")?;
    let locked = match features {
        PLAIN => false,
        HEIGHT_LOCKED => true,
        byte => return Err(NativeError::KernelFeatures { byte }),
    };
    let found_version = reader.u16("header_version")?;
    let id = SlateId::from_bytes(*reader.array("id")?);
    let amount = Amount::new(reader.u64("amount")?);
    let fee = Fee::new(reader.u64("fee")?);
    let height = Height::new(reader.u64("height")?);
    let expected_version = header_version(network, height);
    if found_version != expected_version {
        return Err(NativeError::HeaderVersion {
            found: found_version,
            expected: expected_version,
        });
    }
    let lock = if locked {
        let lock_height = reader.u64("lock_height")?;
        if lock_height == 0 {
            return Err(NativeError::ZeroLockHeight);
        }
        KernelLock::at_height(Height::new(lock_height))
    } else {
        KernelLock::NONE
    };
    let ttl_cutoff_height = if flags & FLAG_TTL == 0 {
        None
    } else {
        Some(Height::new(reader.u64("ttl_cutoff_height")?))
    };
    let has_proof = flags & FLAG_PROOF != 0;
    if has_proof && stage.flow() == Flow::Invoice {
        return Err(NativeError::ProofInInvoice);
    }
    for role in Role::ALL {
        if flags & message_flag(role) == 0 {
            continue;
        }
        if presence(stage, role) == Presence::Absent {
            return Err(NativeError::MessageWithoutParticipant { stage, role });
        }
        if !carries_message(stage, role) {
            return Err(NativeError::InitiatorMessage { stage, role });
        }
    }
    let offset = BlindingFactor::from_array(*reader.array("offset")?);
    let mut sender = None;
    let mut receiver = None;
    for role in Role::ALL {
        let signed = match presence(stage, role) {
            Presence::Absent => continue,
            Presence::Unsigned => false,
            Presence::Signed => true,
        };
        let data = participant(&mut reader, role, signed, flags & message_flag(role) != 0)?;
        match role {
            Role::Sender => sender = Some(data),
            Role::Receiver => receiver = Some(data),
        }
    }
    let payment_proof = if has_proof {
        let sender_address = proof_address(
            reader.array("payment_proof.sender_address")?,
            "payment_proof.sender_address",
        )?;
        let receiver_address = proof_address(
            reader.array("payment_proof.receiver_address")?,
            "payment_proof.receiver_address",
        )?;
        let receiver_signature = if stage.step() == Step::Proposed {
            None
        } else {
            Some(ProofSignature::from_bytes(
                *reader.array("payment_proof.receiver_signature")?,
            ))
        };
        Some(PaymentProof {
            sender_address,
            receiver_address,
            receiver_signature,
        })
    } else {
        None
    };
    let input_count = reader.u16("input_count")?;
    let inputs = reader.take(span(input_count, INPUT_LEN), "inputs")?;
    let output_count = reader.u16("output_count")?;
    let outputs = reader.take(span(output_count, OUTPUT_LEN), "outputs")?;
    if stage.step() == Step::Proposed && (input_count != 0 || output_count != 0) {
        return Err(NativeError::BodyAtProposal { stage });
    }
    let weight =
        BodyCounts::new(u64::from(input_count), u64::from(output_count), 1).weight_as_block();
    if weight > MAX_TX_WEIGHT {
        return Err(NativeError::TooHeavy {
            weight,
            max: MAX_TX_WEIGHT,
        });
    }
    let kernel = if stage.is_final() {
        let excess = commitment(
            reader.take(Commitment::LEN, "kernel.excess")?,
            "kernel.excess",
        )?;
        let excess_sig = signature(reader.array("kernel.excess_sig")?, "kernel.excess_sig")?;
        Some(FinalKernel { excess, excess_sig })
    } else {
        None
    };
    let tail = Tail::decode(reader.rest(), stage)?;
    let body = Body { inputs, outputs };
    body.check()?;
    let (inputs, outputs) = body.build()?;
    let slate = Slate::from_parts(SlateParts {
        id,
        stage,
        amount,
        fee,
        height,
        lock,
        ttl_cutoff_height,
        offset,
        sender,
        receiver,
        inputs,
        outputs,
        kernel,
        payment_proof,
        origin: Some(WireOrigin::new(NATIVE_V1)),
    })?;
    Ok((network, NativeSlate { slate, tail }))
}

/// Counts fit `u16`: a slate's body is within `MAX_TX_WEIGHT`, which allows fewer than 40,000
/// inputs and 2,000 outputs.
fn write_count(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
}

/// The `lepic.v1` bytes of `slate` up to its tail, leaving out what the format does not carry.
pub(crate) fn encode_slate(slate: &Slate, network: Network) -> Vec<u8> {
    let stage = slate.stage();
    let flags = flags(slate);
    let lock = slate.lock();
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(network_byte(network));
    out.push(stage_byte(stage));
    out.push(flags);
    out.push(if lock.is_locked() {
        HEIGHT_LOCKED
    } else {
        PLAIN
    });
    out.extend_from_slice(&header_version(network, slate.height()).to_be_bytes());
    out.extend_from_slice(slate.id().as_bytes());
    out.extend_from_slice(&slate.amount().value().to_be_bytes());
    out.extend_from_slice(&slate.fee().value().to_be_bytes());
    out.extend_from_slice(&slate.height().value().to_be_bytes());
    if lock.is_locked() {
        out.extend_from_slice(&lock.lock_height().value().to_be_bytes());
    }
    if let Some(ttl) = slate.ttl_cutoff_height() {
        out.extend_from_slice(&ttl.value().to_be_bytes());
    }
    out.extend_from_slice(slate.offset().expose_bytes());
    for role in Role::ALL {
        let Some(data) = slate.participant(role) else {
            continue;
        };
        out.extend_from_slice(&data.public_blind_excess.to_bytes());
        out.extend_from_slice(&data.public_nonce.to_bytes());
        if let Some(sig) = &data.partial_signature {
            out.extend_from_slice(&sig.to_compact());
        }
        if let Some(message) = data
            .message
            .as_ref()
            .filter(|_| flags & message_flag(role) != 0)
        {
            write_count(&mut out, message.text().len());
            out.extend_from_slice(message.text().as_bytes());
            out.extend_from_slice(&message.signature().to_compact());
        }
    }
    if let Some(proof) = slate.payment_proof() {
        out.extend_from_slice(proof.sender_address.as_bytes());
        out.extend_from_slice(proof.receiver_address.as_bytes());
        if let Some(sig) = &proof.receiver_signature {
            out.extend_from_slice(sig.as_bytes());
        }
    }
    let (inputs, outputs) = if stage.step() == Step::Proposed {
        (&[][..], &[][..])
    } else {
        (slate.inputs(), slate.outputs())
    };
    write_count(&mut out, inputs.len());
    for input in inputs {
        out.push(input.features.as_u8());
        out.extend_from_slice(input.commitment.as_bytes());
    }
    write_count(&mut out, outputs.len());
    for output in outputs {
        out.push(output.features.as_u8());
        out.extend_from_slice(output.commitment.as_bytes());
        out.extend_from_slice(output.proof.as_bytes());
    }
    if let Some(kernel) = slate.kernel() {
        out.extend_from_slice(kernel.excess.as_bytes());
        out.extend_from_slice(&kernel.excess_sig.to_compact());
    }
    out
}
