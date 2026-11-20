// SPDX-License-Identifier: Apache-2.0
//! The JSON view of a `lepic.v1` slate, for tools and the API. It is never sent on the wire.
//!
//! The view names every field of the binary form, including the network, the flags, the kernel
//! features and the header version, and shows unknown tail records as type and hex. Integers of
//! 64 bits are decimal strings and bytes are lowercase hex. A view reads back only when it is
//! exactly the view of the slate it describes, so JSON and binary convert both ways without loss.

use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::input::Input;
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_primitives::params::Network;
use lepic_slate::model::{
    FinalKernel, KernelLock, Participant, ParticipantMessage, PaymentProof, Slate, SlateParts,
};
use lepic_slate::origin::WireOrigin;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_slate::validate::{
    decode_hex_array, decode_hex_bounded, encode_hex, parse_commitment, parse_offset,
    parse_proof_address, parse_proof_signature, parse_public_key, parse_range_proof,
    parse_signature, parse_slate_id,
};
use serde::{Deserialize, Serialize};

use crate::NATIVE_V1;
use crate::error::NativeError;
use crate::slate::{
    FLAG_PROOF, FLAG_RECEIVER_MESSAGE, FLAG_SENDER_MESSAGE, FLAG_TTL, NativeSlate, flags,
    header_version,
};
use crate::tail::{ReplyKey, ReplyMailbox, Tail, UnknownRecord};

const FLAG_NAMES: [(u8, &str); 4] = [
    (FLAG_TTL, "ttl"),
    (FLAG_PROOF, "proof"),
    (FLAG_SENDER_MESSAGE, "sender_message"),
    (FLAG_RECEIVER_MESSAGE, "receiver_message"),
];

/// Every field of a `lepic.v1` slate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlateView {
    pub network: String,
    pub stage: String,
    /// Names of the set flag bits, in bit order: `ttl`, `proof`, `sender_message`,
    /// `receiver_message`.
    pub flags: Vec<String>,
    /// `plain` or `height_locked`.
    pub kernel_features: String,
    pub header_version: u16,
    pub id: String,
    pub amount: String,
    pub fee: String,
    pub height: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_height: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_cutoff_height: Option<String>,
    pub offset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<ParticipantView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<ParticipantView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_proof: Option<PaymentProofView>,
    pub inputs: Vec<InputView>,
    pub outputs: Vec<OutputView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<KernelView>,
    pub tail: TailView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantView {
    pub public_blind_excess: String,
    pub public_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<MessageView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageView {
    pub text: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentProofView {
    pub sender_address: String,
    pub receiver_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputView {
    /// `plain` or `coinbase`.
    pub features: String,
    pub commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputView {
    /// `plain`; a slate never carries a coinbase output.
    pub features: String,
    pub commitment: String,
    pub proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelView {
    pub excess: String,
    pub excess_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_mailbox: Option<MailboxView>,
    #[serde(default)]
    pub unknown: Vec<UnknownRecordView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxView {
    pub key: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownRecordView {
    #[serde(rename = "type")]
    pub record_type: u8,
    pub hex: String,
}

const fn features_name(features: OutputFeatures) -> &'static str {
    match features {
        OutputFeatures::Plain => "plain",
        OutputFeatures::Coinbase => "coinbase",
    }
}

fn participant_view(data: &Participant, message: bool) -> ParticipantView {
    ParticipantView {
        public_blind_excess: data.public_blind_excess.to_hex(),
        public_nonce: data.public_nonce.to_hex(),
        partial_signature: data.partial_signature.map(|sig| sig.to_compact_hex()),
        message: data
            .message
            .as_ref()
            .filter(|_| message)
            .map(|message| MessageView {
                text: message.text().to_owned(),
                signature: message.signature().to_compact_hex(),
            }),
    }
}

impl SlateView {
    /// The view of `native` on `network`.
    pub fn new(network: Network, native: &NativeSlate) -> Self {
        let slate = native.slate();
        let flags = flags(slate);
        let lock = slate.lock();
        let message_flag = |role| match role {
            Role::Sender => flags & FLAG_SENDER_MESSAGE != 0,
            Role::Receiver => flags & FLAG_RECEIVER_MESSAGE != 0,
        };
        let participant = |role| {
            slate
                .participant(role)
                .map(|data| participant_view(data, message_flag(role)))
        };
        Self {
            network: network.as_str().to_owned(),
            stage: slate.stage().as_str().to_owned(),
            flags: FLAG_NAMES
                .iter()
                .filter(|(bit, _)| flags & bit != 0)
                .map(|(_, name)| (*name).to_owned())
                .collect(),
            kernel_features: if lock.is_locked() {
                "height_locked"
            } else {
                "plain"
            }
            .to_owned(),
            header_version: header_version(network, slate.height()),
            id: slate.id().to_string(),
            amount: slate.amount().value().to_string(),
            fee: slate.fee().value().to_string(),
            height: slate.height().value().to_string(),
            lock_height: lock
                .is_locked()
                .then(|| lock.lock_height().value().to_string()),
            ttl_cutoff_height: slate.ttl_cutoff_height().map(|ttl| ttl.value().to_string()),
            offset: encode_hex(slate.offset().expose_bytes()),
            sender: participant(Role::Sender),
            receiver: participant(Role::Receiver),
            payment_proof: slate.payment_proof().map(|proof| PaymentProofView {
                sender_address: encode_hex(proof.sender_address.as_bytes()),
                receiver_address: encode_hex(proof.receiver_address.as_bytes()),
                receiver_signature: proof
                    .receiver_signature
                    .map(|sig| encode_hex(sig.as_bytes())),
            }),
            inputs: slate
                .inputs()
                .iter()
                .map(|input| InputView {
                    features: features_name(input.features).to_owned(),
                    commitment: input.commitment.to_hex(),
                })
                .collect(),
            outputs: slate
                .outputs()
                .iter()
                .map(|output| OutputView {
                    features: features_name(output.features).to_owned(),
                    commitment: output.commitment.to_hex(),
                    proof: output.proof.to_hex(),
                })
                .collect(),
            kernel: slate.kernel().map(|kernel| KernelView {
                excess: kernel.excess.to_hex(),
                excess_sig: kernel.excess_sig.to_compact_hex(),
            }),
            tail: tail_view(native.tail()),
        }
    }

    /// The slate this view describes, refused unless the view is exactly its view.
    pub fn into_native(self) -> Result<(Network, NativeSlate), NativeError> {
        let network = match self.network.as_str() {
            "mainnet" => Network::Mainnet,
            "floonet" => Network::Floonet,
            _ => return Err(NativeError::View { field: "network" }),
        };
        let stage = Stage::ALL
            .into_iter()
            .find(|stage| stage.as_str() == self.stage)
            .ok_or(NativeError::View { field: "stage" })?;
        let lock = match &self.lock_height {
            Some(lock_height) => {
                KernelLock::at_height(Height::new(integer(lock_height, "lock_height")?))
            }
            None => KernelLock::NONE,
        };
        let parts = SlateParts {
            id: parse_slate_id(&self.id).map_err(|_| NativeError::View { field: "id" })?,
            stage,
            amount: Amount::new(integer(&self.amount, "amount")?),
            fee: Fee::new(integer(&self.fee, "fee")?),
            height: Height::new(integer(&self.height, "height")?),
            lock,
            ttl_cutoff_height: self
                .ttl_cutoff_height
                .as_deref()
                .map(|ttl| integer(ttl, "ttl_cutoff_height").map(Height::new))
                .transpose()?,
            offset: parse_offset(&self.offset)
                .map_err(|_| NativeError::View { field: "offset" })?,
            sender: self
                .sender
                .as_ref()
                .map(|view| participant(view, "sender"))
                .transpose()?,
            receiver: self
                .receiver
                .as_ref()
                .map(|view| participant(view, "receiver"))
                .transpose()?,
            inputs: self.inputs.iter().map(input).collect::<Result<_, _>>()?,
            outputs: self.outputs.iter().map(output).collect::<Result<_, _>>()?,
            kernel: self.kernel.as_ref().map(kernel).transpose()?,
            payment_proof: self.payment_proof.as_ref().map(payment_proof).transpose()?,
            origin: Some(WireOrigin::new(NATIVE_V1)),
        };
        let native = NativeSlate::new(Slate::from_parts(parts)?, tail(&self.tail)?)?;
        if Self::new(network, &native) != self {
            return Err(NativeError::ViewMismatch);
        }
        Ok((network, native))
    }
}

fn tail_view(tail: &Tail) -> TailView {
    TailView {
        reply_key: tail.reply_key().map(|key| encode_hex(key.as_bytes())),
        reply_mailbox: tail.reply_mailbox().map(|mailbox| MailboxView {
            key: mailbox.key().to_hex(),
            address: mailbox.address().to_owned(),
        }),
        unknown: tail
            .unknown()
            .iter()
            .map(|record| UnknownRecordView {
                record_type: record.record_type(),
                hex: encode_hex(record.value()),
            })
            .collect(),
    }
}

/// Decimal digits only, so each value has one spelling.
fn integer(text: &str, field: &'static str) -> Result<u64, NativeError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NativeError::View { field });
    }
    text.parse().map_err(|_| NativeError::View { field })
}

fn participant(view: &ParticipantView, role: &'static str) -> Result<Participant, NativeError> {
    let bad = || NativeError::View { field: role };
    let mut data = Participant::new(
        parse_public_key(&view.public_blind_excess).map_err(|_| bad())?,
        parse_public_key(&view.public_nonce).map_err(|_| bad())?,
    );
    data.partial_signature = view
        .partial_signature
        .as_deref()
        .map(|sig| parse_signature(sig).map_err(|_| bad()))
        .transpose()?;
    data.message = view
        .message
        .as_ref()
        .map(|message| {
            let signature = parse_signature(&message.signature).map_err(|_| bad())?;
            ParticipantMessage::new(message.text.clone(), signature).map_err(NativeError::from)
        })
        .transpose()?;
    Ok(data)
}

fn features(name: &str, field: &'static str) -> Result<OutputFeatures, NativeError> {
    match name {
        "plain" => Ok(OutputFeatures::Plain),
        "coinbase" => Ok(OutputFeatures::Coinbase),
        _ => Err(NativeError::View { field }),
    }
}

fn input(view: &InputView) -> Result<Input, NativeError> {
    Ok(Input::new(
        features(&view.features, "inputs")?,
        parse_commitment(&view.commitment).map_err(|_| NativeError::View { field: "inputs" })?,
    ))
}

fn output(view: &OutputView) -> Result<Output, NativeError> {
    let bad = || NativeError::View { field: "outputs" };
    Ok(Output::new(
        features(&view.features, "outputs")?,
        parse_commitment(&view.commitment).map_err(|_| bad())?,
        parse_range_proof(&view.proof).map_err(|_| bad())?,
    ))
}

fn kernel(view: &KernelView) -> Result<FinalKernel, NativeError> {
    let bad = || NativeError::View { field: "kernel" };
    Ok(FinalKernel {
        excess: parse_commitment(&view.excess).map_err(|_| bad())?,
        excess_sig: parse_signature(&view.excess_sig).map_err(|_| bad())?,
    })
}

fn payment_proof(view: &PaymentProofView) -> Result<PaymentProof, NativeError> {
    let bad = || NativeError::View {
        field: "payment_proof",
    };
    Ok(PaymentProof {
        sender_address: parse_proof_address(&view.sender_address).map_err(|_| bad())?,
        receiver_address: parse_proof_address(&view.receiver_address).map_err(|_| bad())?,
        receiver_signature: view
            .receiver_signature
            .as_deref()
            .map(|sig| parse_proof_signature(sig).map_err(|_| bad()))
            .transpose()?,
    })
}

fn tail(view: &TailView) -> Result<Tail, NativeError> {
    let bad = || NativeError::View { field: "tail" };
    let reply_key = view
        .reply_key
        .as_deref()
        .map(|key| decode_hex_array::<{ ReplyKey::LEN }>(key).map(ReplyKey::from_bytes))
        .transpose()
        .map_err(|_| bad())?;
    let reply_mailbox = view
        .reply_mailbox
        .as_ref()
        .map(|mailbox| {
            let key = parse_public_key(&mailbox.key).map_err(|_| bad())?;
            ReplyMailbox::new(key, mailbox.address.clone()).map_err(NativeError::from)
        })
        .transpose()?;
    let unknown = view
        .unknown
        .iter()
        .map(|record| {
            let value =
                decode_hex_bounded(&record.hex, 0, usize::from(u16::MAX)).map_err(|_| bad())?;
            UnknownRecord::new(record.record_type, value).map_err(NativeError::from)
        })
        .collect::<Result<_, _>>()?;
    Ok(Tail::new(reply_key, reply_mailbox, unknown)?)
}
