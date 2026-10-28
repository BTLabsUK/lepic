//! The version-free slate (ADR 0002): what two parties agree on while building a transaction,
//! independent of any wire format.
//!
//! A [`Slate`] can only be built through [`Slate::propose`], the stage transitions or
//! [`Slate::from_parts`], and each of them checks the invariants, so every `Slate` value is
//! consistent with its stage.

use lepic_crypto::{Commitment, PublicKey, Signature};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::input::Input;
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::output::Output;
use lepic_primitives::params::MAX_TX_WEIGHT;
use std::collections::HashSet;

use uuid::Uuid;

use crate::error::{ProofAddressError, SlateError, SlateIdError, Transition};
use crate::origin::WireOrigin;
use crate::role::Role;
use crate::stage::{Flow, Stage, Step};

/// Longest participant message, in bytes. Each party cuts its own message to this length
/// before signing it, as `epic-wallet` does.
pub const MAX_MESSAGE_LEN: usize = 256;

/// Identifies one slate across all its stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlateId(Uuid);

impl SlateId {
    /// Any 16 bytes. Upstream test wallets produce ids that are not version-4 UUIDs, and they
    /// must still be accepted.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    /// A version-4 UUID from caller-supplied random bytes, as `epic-wallet` creates new ids.
    pub const fn from_random_bytes(bytes: [u8; 16]) -> Self {
        Self(uuid::Builder::from_random_bytes(bytes).into_uuid())
    }

    /// Parses the hyphenated form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` in either case.
    pub fn parse(text: &str) -> Result<Self, SlateIdError> {
        if text.len() != uuid::fmt::Hyphenated::LENGTH {
            return Err(SlateIdError);
        }
        Uuid::try_parse(text).map(Self).map_err(|_| SlateIdError)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

/// Lowercase hyphenated, the form legacy slates carry.
impl std::fmt::Display for SlateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.hyphenated().fmt(f)
    }
}

/// The height before which the kernel may not be mined. A lock height of zero means unlocked,
/// which gives a `Plain` kernel; any other height gives a `HeightLocked` kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KernelLock(Height);

impl KernelLock {
    pub const NONE: Self = Self(Height::ZERO);

    pub const fn at_height(lock_height: Height) -> Self {
        Self(lock_height)
    }

    pub const fn lock_height(self) -> Height {
        self.0
    }

    pub const fn is_locked(self) -> bool {
        self.0.value() != 0
    }

    pub const fn kernel_features(self, fee: Fee) -> KernelFeatures {
        if self.is_locked() {
            KernelFeatures::HeightLocked {
                fee,
                lock_height: self.0,
            }
        } else {
            KernelFeatures::Plain { fee }
        }
    }
}

/// A participant's free-text message and their signature over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantMessage {
    text: String,
    signature: Signature,
}

impl ParticipantMessage {
    pub fn new(text: String, signature: Signature) -> Result<Self, SlateError> {
        if text.len() > MAX_MESSAGE_LEN {
            return Err(SlateError::MessageTooLong {
                len: text.len(),
                max: MAX_MESSAGE_LEN,
            });
        }
        Ok(Self { text, signature })
    }

    /// The longest prefix of `text` within [`MAX_MESSAGE_LEN`] bytes that ends on a character
    /// boundary: the text a party signs for its own message.
    pub fn truncate(text: &str) -> &str {
        let mut end = text.len().min(MAX_MESSAGE_LEN);
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        text.get(..end).unwrap_or_default()
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// One party's public contribution to the slate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    pub public_blind_excess: PublicKey,
    pub public_nonce: PublicKey,
    pub partial_signature: Option<Signature>,
    pub message: Option<ParticipantMessage>,
}

impl Participant {
    pub const fn new(public_blind_excess: PublicKey, public_nonce: PublicKey) -> Self {
        Self {
            public_blind_excess,
            public_nonce,
            partial_signature: None,
            message: None,
        }
    }

    pub const fn is_signed(&self) -> bool {
        self.partial_signature.is_some()
    }
}

/// An ed25519 public key that identifies a party in a payment proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProofAddress([u8; ProofAddress::LEN]);

impl ProofAddress {
    pub const LEN: usize = 32;

    /// Accepts only bytes that decompress to an ed25519 point of large order. `epic-wallet`
    /// accepts any point; no address it derives has small order.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Result<Self, ProofAddressError> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| ProofAddressError::NotAPoint)?;
        if key.is_weak() {
            return Err(ProofAddressError::WeakKey);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// The receiver's ed25519 signature over a payment proof, checked when the proof is verified.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProofSignature([u8; ProofSignature::LEN]);

impl ProofSignature {
    pub const LEN: usize = 64;

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl std::fmt::Debug for ProofSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProofSignature(..)")
    }
}

/// A request that the receiver sign for the payment, so the sender can later prove it paid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentProof {
    pub sender_address: ProofAddress,
    pub receiver_address: ProofAddress,
    pub receiver_signature: Option<ProofSignature>,
}

/// The kernel excess and its aggregate signature, known once the slate is finalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalKernel {
    pub excess: Commitment,
    pub excess_sig: Signature,
}

/// Every field of a slate, unchecked. Codecs fill it in and call [`Slate::from_parts`].
///
/// `inputs` and `outputs` are the part of the transaction body this slate carries. A format may
/// leave out what the receiving party does not need, such as the sender's own inputs and change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlateParts {
    pub id: SlateId,
    pub stage: Stage,
    pub amount: Amount,
    pub fee: Fee,
    /// Chain height when the slate was created, or when the payer joined an invoice.
    pub height: Height,
    pub lock: KernelLock,
    pub ttl_cutoff_height: Option<Height>,
    pub offset: BlindingFactor,
    pub sender: Option<Participant>,
    pub receiver: Option<Participant>,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub kernel: Option<FinalKernel>,
    pub payment_proof: Option<PaymentProof>,
    pub origin: Option<WireOrigin>,
}

/// What the initiator decides when it starts a slate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub id: SlateId,
    pub amount: Amount,
    pub fee: Fee,
    pub height: Height,
    pub lock: KernelLock,
    pub ttl_cutoff_height: Option<Height>,
    pub offset: BlindingFactor,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub payment_proof: Option<PaymentProof>,
}

/// What the receiver adds to a standard slate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub receiver: Participant,
    pub outputs: Vec<Output>,
    pub proof_signature: Option<ProofSignature>,
}

/// What the sender adds when it pays an invoice. The sender picks the fee, records the chain
/// height it saw, and may set a TTL; without one the receiver's TTL stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    pub sender: Participant,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub fee: Fee,
    pub height: Height,
    pub ttl_cutoff_height: Option<Height>,
}

/// A slate whose fields are consistent with its stage. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slate(SlateParts);

impl Slate {
    /// Starts a slate in the first stage of `flow`, with the initiator's unsigned data.
    pub fn propose(
        flow: Flow,
        proposal: Proposal,
        initiator: Participant,
    ) -> Result<Self, SlateError> {
        let (sender, receiver) = match flow.initiator() {
            Role::Sender => (Some(initiator), None),
            Role::Receiver => (None, Some(initiator)),
        };
        Self::from_parts(SlateParts {
            id: proposal.id,
            stage: flow.first_stage(),
            amount: proposal.amount,
            fee: proposal.fee,
            height: proposal.height,
            lock: proposal.lock,
            ttl_cutoff_height: proposal.ttl_cutoff_height,
            offset: proposal.offset,
            sender,
            receiver,
            inputs: proposal.inputs,
            outputs: proposal.outputs,
            kernel: None,
            payment_proof: proposal.payment_proof,
            origin: None,
        })
    }

    /// Checks every invariant and builds the slate.
    pub fn from_parts(parts: SlateParts) -> Result<Self, SlateError> {
        check_participants(&parts)?;
        check_kernel(&parts)?;
        check_payment_proof(&parts)?;
        check_fee(&parts)?;
        check_body(&parts)?;
        Ok(Self(parts))
    }

    pub fn into_parts(self) -> SlateParts {
        self.0
    }

    /// S1 to S2: the receiver adds its output, its signed data and, when asked for, its
    /// payment proof signature.
    pub fn receive(&self, receipt: Receipt) -> Result<Self, SlateError> {
        self.expect_stage(Stage::S1, Transition::Receive)?;
        let mut parts = self.0.clone();
        parts.stage = Stage::S2;
        parts.receiver = Some(receipt.receiver);
        parts.outputs.extend(receipt.outputs);
        match (&mut parts.payment_proof, receipt.proof_signature) {
            (Some(proof), signature) => proof.receiver_signature = signature,
            (None, Some(_)) => {
                return Err(SlateError::UnexpectedProofSignature { stage: Stage::S2 });
            }
            (None, None) => {}
        }
        Self::from_parts(parts)
    }

    /// I1 to I2: the sender adds its inputs, change, fee and signed data.
    pub fn pay(&self, payment: Payment) -> Result<Self, SlateError> {
        self.expect_stage(Stage::I1, Transition::Pay)?;
        let mut parts = self.0.clone();
        parts.stage = Stage::I2;
        parts.sender = Some(payment.sender);
        parts.inputs.extend(payment.inputs);
        parts.outputs.extend(payment.outputs);
        parts.fee = payment.fee;
        parts.height = payment.height;
        if payment.ttl_cutoff_height.is_some() {
            parts.ttl_cutoff_height = payment.ttl_cutoff_height;
        }
        Self::from_parts(parts)
    }

    /// S2 to S3 or I2 to I3: the initiator adds its partial signature and the final kernel.
    pub fn finalize(
        &self,
        initiator_signature: Signature,
        kernel: FinalKernel,
    ) -> Result<Self, SlateError> {
        if self.stage().step() != Step::Responded {
            return Err(SlateError::InvalidTransition {
                stage: self.stage(),
                transition: Transition::Finalize,
            });
        }
        let mut parts = self.0.clone();
        let flow = parts.stage.flow();
        parts.stage = Stage::new(flow, Step::Finalized);
        if let Some(initiator) = participant_mut(&mut parts, flow.initiator()) {
            initiator.partial_signature = Some(initiator_signature);
        }
        parts.kernel = Some(kernel);
        Self::from_parts(parts)
    }

    /// Replaces the wire origin, which no invariant depends on.
    pub fn with_origin(mut self, origin: Option<WireOrigin>) -> Self {
        self.0.origin = origin;
        self
    }

    pub const fn id(&self) -> SlateId {
        self.0.id
    }

    pub const fn stage(&self) -> Stage {
        self.0.stage
    }

    pub const fn flow(&self) -> Flow {
        self.0.stage.flow()
    }

    pub const fn amount(&self) -> Amount {
        self.0.amount
    }

    pub const fn fee(&self) -> Fee {
        self.0.fee
    }

    pub const fn height(&self) -> Height {
        self.0.height
    }

    pub const fn lock(&self) -> KernelLock {
        self.0.lock
    }

    pub const fn ttl_cutoff_height(&self) -> Option<Height> {
        self.0.ttl_cutoff_height
    }

    pub const fn offset(&self) -> &BlindingFactor {
        &self.0.offset
    }

    pub const fn participant(&self, role: Role) -> Option<&Participant> {
        match role {
            Role::Sender => self.0.sender.as_ref(),
            Role::Receiver => self.0.receiver.as_ref(),
        }
    }

    /// The parties present, initiator first: the order in which they joined.
    pub fn participants(&self) -> impl Iterator<Item = (Role, &Participant)> {
        let flow = self.flow();
        [flow.initiator(), flow.responder()]
            .into_iter()
            .filter_map(|role| self.participant(role).map(|data| (role, data)))
    }

    pub fn inputs(&self) -> &[Input] {
        &self.0.inputs
    }

    pub fn outputs(&self) -> &[Output] {
        &self.0.outputs
    }

    pub const fn kernel_features(&self) -> KernelFeatures {
        self.0.lock.kernel_features(self.0.fee)
    }

    /// The final kernel, present exactly when the stage is final.
    pub fn kernel(&self) -> Option<TxKernel> {
        self.0
            .kernel
            .map(|kernel| TxKernel::new(self.kernel_features(), kernel.excess, kernel.excess_sig))
    }

    pub const fn payment_proof(&self) -> Option<&PaymentProof> {
        self.0.payment_proof.as_ref()
    }

    pub const fn origin(&self) -> Option<&WireOrigin> {
        self.0.origin.as_ref()
    }

    fn expect_stage(&self, stage: Stage, transition: Transition) -> Result<(), SlateError> {
        if self.stage() == stage {
            Ok(())
        } else {
            Err(SlateError::InvalidTransition {
                stage: self.stage(),
                transition,
            })
        }
    }
}

fn participant(parts: &SlateParts, role: Role) -> Option<&Participant> {
    match role {
        Role::Sender => parts.sender.as_ref(),
        Role::Receiver => parts.receiver.as_ref(),
    }
}

fn participant_mut(parts: &mut SlateParts, role: Role) -> Option<&mut Participant> {
    match role {
        Role::Sender => parts.sender.as_mut(),
        Role::Receiver => parts.receiver.as_mut(),
    }
}

/// Whether a party must be absent, present without a partial signature, or present and signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Absent,
    Unsigned,
    Signed,
}

/// The initiator proposes unsigned, the responder joins signed, and the initiator signs last.
fn expected(stage: Stage, role: Role) -> Expected {
    let is_initiator = stage.flow().initiator() == role;
    match (stage.step(), is_initiator) {
        (Step::Proposed | Step::Responded, true) => Expected::Unsigned,
        (Step::Proposed, false) => Expected::Absent,
        (Step::Responded, false) | (Step::Finalized, _) => Expected::Signed,
    }
}

fn check_participants(parts: &SlateParts) -> Result<(), SlateError> {
    let stage = parts.stage;
    for role in Role::ALL {
        match (expected(stage, role), participant(parts, role)) {
            (Expected::Absent, None) => {}
            (Expected::Absent, Some(_)) => {
                return Err(SlateError::UnexpectedParticipant { stage, role });
            }
            (Expected::Unsigned | Expected::Signed, None) => {
                return Err(SlateError::MissingParticipant { stage, role });
            }
            (Expected::Unsigned, Some(data)) if data.is_signed() => {
                return Err(SlateError::UnexpectedPartialSignature { stage, role });
            }
            (Expected::Signed, Some(data)) if !data.is_signed() => {
                return Err(SlateError::MissingPartialSignature { stage, role });
            }
            (Expected::Unsigned | Expected::Signed, Some(_)) => {}
        }
    }
    Ok(())
}

fn check_kernel(parts: &SlateParts) -> Result<(), SlateError> {
    let stage = parts.stage;
    match (stage.is_final(), parts.kernel.is_some()) {
        (true, false) => Err(SlateError::MissingKernelExcess { stage }),
        (false, true) => Err(SlateError::UnexpectedKernelExcess { stage }),
        _ => Ok(()),
    }
}

// Upstream offers payment proofs only when sending, and the receiver always signs one it was
// asked for, so a standard slate past S1 without the signature cannot be finalized.
fn check_payment_proof(parts: &SlateParts) -> Result<(), SlateError> {
    let stage = parts.stage;
    let Some(proof) = &parts.payment_proof else {
        return Ok(());
    };
    match (
        stage.flow(),
        stage.step(),
        proof.receiver_signature.is_some(),
    ) {
        (Flow::Invoice, _, _) => Err(SlateError::PaymentProofInInvoice),
        (Flow::Standard, Step::Proposed, true) => {
            Err(SlateError::UnexpectedProofSignature { stage })
        }
        (Flow::Standard, Step::Responded | Step::Finalized, false) => {
            Err(SlateError::MissingProofSignature { stage })
        }
        (Flow::Standard, _, _) => Ok(()),
    }
}

// The sender pays the fee and chooses it, so an invoice carries none until the sender joins.
fn check_fee(parts: &SlateParts) -> Result<(), SlateError> {
    if parts.stage == Stage::I1 && parts.fee != Fee::ZERO {
        return Err(SlateError::FeeBeforeSender {
            stage: parts.stage,
            fee: parts.fee,
        });
    }
    Ok(())
}

fn check_body(parts: &SlateParts) -> Result<(), SlateError> {
    let counts = BodyCounts::new(count(parts.inputs.len()), count(parts.outputs.len()), 1);
    let weight = counts.weight_as_block();
    if weight > MAX_TX_WEIGHT {
        return Err(SlateError::BodyTooHeavy {
            weight,
            max: MAX_TX_WEIGHT,
        });
    }
    check_commitments(parts)
}

/// The node's read rules for a body that do not depend on order.
fn check_commitments(parts: &SlateParts) -> Result<(), SlateError> {
    if parts.outputs.iter().any(Output::is_coinbase) {
        return Err(SlateError::CoinbaseOutput);
    }
    let mut inputs = HashSet::with_capacity(parts.inputs.len());
    for input in &parts.inputs {
        if !inputs.insert(input.commitment) {
            return Err(SlateError::DuplicateInput {
                commitment: input.commitment,
            });
        }
    }
    let mut outputs = HashSet::with_capacity(parts.outputs.len());
    for output in &parts.outputs {
        if !outputs.insert(output.commitment) {
            return Err(SlateError::DuplicateOutput {
                commitment: output.commitment,
            });
        }
        if inputs.contains(&output.commitment) {
            return Err(SlateError::InputSpendsOutput {
                commitment: output.commitment,
            });
        }
    }
    Ok(())
}

/// Lengths of in-memory collections always fit `u64`.
fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::decode_hex_array;

    #[test]
    fn slate_id_displays_lowercase_hyphenated_and_parses_back() {
        let id = SlateId::parse("0436430C-2B02-624C-2032-570501212B00").unwrap();
        assert_eq!(id.to_string(), "0436430c-2b02-624c-2032-570501212b00");
        assert_eq!(SlateId::parse(&id.to_string()), Ok(id));
    }

    #[test]
    fn slate_id_rejects_forms_other_than_hyphenated() {
        for text in [
            "0436430c2b02624c2032570501212b00",
            "{0436430c-2b02-624c-2032-570501212b00}",
            "urn:uuid:0436430c-2b02-624c-2032-570501212b00",
            "0436430c-2b02-624c-2032-570501212b0g",
            "",
        ] {
            assert_eq!(SlateId::parse(text), Err(SlateIdError), "{text}");
        }
    }

    #[test]
    fn random_slate_id_is_version_4() {
        let id = SlateId::from_random_bytes([0xff; 16]);
        assert_eq!(id.0.get_version_num(), 4);
    }

    #[test]
    fn kernel_lock_of_zero_gives_a_plain_kernel() {
        let fee = Fee::new(7);
        assert_eq!(
            KernelLock::NONE.kernel_features(fee),
            KernelFeatures::Plain { fee }
        );
        let lock_height = Height::new(9);
        assert_eq!(
            KernelLock::at_height(lock_height).kernel_features(fee),
            KernelFeatures::HeightLocked { fee, lock_height }
        );
    }

    #[test]
    fn message_truncation_keeps_whole_characters() {
        let ascii = "a".repeat(300);
        assert_eq!(ParticipantMessage::truncate(&ascii).len(), MAX_MESSAGE_LEN);
        let wide = "é".repeat(200);
        let cut = ParticipantMessage::truncate(&wide);
        assert_eq!(cut.len(), MAX_MESSAGE_LEN);
        let odd = format!("a{wide}");
        assert_eq!(
            ParticipantMessage::truncate(&odd).len(),
            MAX_MESSAGE_LEN - 1
        );
        assert_eq!(ParticipantMessage::truncate("short"), "short");
    }

    #[test]
    fn proof_address_rejects_bytes_off_the_curve() {
        // y = 2 has no x on edwards25519.
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        assert_eq!(
            ProofAddress::from_bytes(bytes),
            Err(ProofAddressError::NotAPoint)
        );
    }

    #[test]
    fn proof_address_rejects_the_identity_point() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert_eq!(
            ProofAddress::from_bytes(bytes),
            Err(ProofAddressError::WeakKey)
        );
    }

    #[test]
    fn proof_address_rejects_a_point_of_order_eight() {
        let bytes = decode_hex_array::<32>(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        )
        .unwrap();
        assert_eq!(
            ProofAddress::from_bytes(bytes),
            Err(ProofAddressError::WeakKey)
        );
    }

    #[test]
    fn proof_address_accepts_a_derived_address() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        assert!(ProofAddress::from_bytes(key.to_bytes()).is_ok());
    }
}
