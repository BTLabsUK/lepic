//! Finalize and post, the sender's last step of the standard flow: the receiver's S2 becomes S3
//! and its transaction goes to the node, as `epic-wallet`'s `finalize_tx` and `post_tx` do it
//! (`docs/compat/legacy-slates.md`, "Lifecycle").
//!
//! [`build_s3`] is the construction on its own: it checks the S2 against the S1 this wallet
//! built, verifies the receiver's partial signature, message and payment proof, adds the
//! sender's partial signature, aggregates, builds the kernel and validates the transaction.
//!
//! [`crate::Wallet::finalize`] runs it against the stored S1 and private context, stores the S3
//! and drops the context in one store transaction, then posts. A post that fails leaves the
//! transaction `finalized`, from where [`crate::Wallet::post`] tries again. Finalizing the same
//! S2 again, or posting again, changes nothing that is stored.

use std::sync::Arc;

use ed25519_dalek::{Verifier, VerifyingKey};
use jiff::Timestamp;
use lepic_crypto::aggsig::{
    add_signatures, calculate_partial_sig, verify_completed_sig, verify_partial_sig,
};
use lepic_crypto::{Commitment, CryptoError, Message, PublicKey};
use lepic_keychain::{Keychain, KeychainError};
use lepic_node::{NodeApi, NodeError, NodeRejection, Propagation, RejectionKind};
use lepic_primitives::amount::{Fee, Height};
use lepic_primitives::committed::{KernelSumError, sum_commitments};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::hash::blake2b_256;
use lepic_primitives::params::Network;
use lepic_primitives::tx::{Transaction, TransactionBody};
use lepic_primitives::validate::ValidationError;
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_slate::codec::{Codec, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, EncodeError, RegistryError, SlateError};
use lepic_slate::model::{FinalKernel, ParticipantMessage, PaymentProof, Slate, SlateId};
use lepic_slate::origin::WireOrigin;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{
    Repositories, SlateStage, StoreError, StoredSlate, TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::transport::TransportId;
use thiserror::Error;
use tracing::field::Empty;
use tracing::{Span, debug, info, instrument, warn};
use uuid::Uuid;

use crate::account;
use crate::error::WalletError;
use crate::invoice::earliest_cutoff;
use crate::ports::{SecretVault, StoreOpener};
use crate::release::record_finalized;
use crate::send::{BuiltS1, SENDER_CONTEXT, SenderContext, block_header_version};
use crate::send_limit::effective_cutoff;
use crate::state::{StateChange, apply_transition, state_name};
use crate::wallet::Wallet;

/// A slate field the receiver may not change between S1 and S2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlateField {
    Amount,
    Fee,
    Height,
    Lock,
    TimeToLive,
    Offset,
    Inputs,
    Outputs,
    Sender,
    PaymentProof,
}

impl std::fmt::Display for SlateField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Amount => "amount",
            Self::Fee => "fee",
            Self::Height => "height",
            Self::Lock => "lock height",
            Self::TimeToLive => "ttl cutoff height",
            Self::Offset => "offset",
            Self::Inputs => "inputs",
            Self::Outputs => "outputs",
            Self::Sender => "sender data",
            Self::PaymentProof => "payment proof addresses",
        })
    }
}

/// Why a slate was not finalized or a transaction not posted.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FinalizeError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("transport {transport} is not registered")]
    UnknownTransport { transport: TransportId },
    #[error("slate could not be decoded")]
    Decode(#[source] DecodeError),
    #[error("slate at stage {stage} is not a reply to finalize")]
    WrongStage { stage: Stage },
    #[error("slate {slate_id} answers no transaction this wallet sent")]
    UnknownSlate { slate_id: SlateId },
    /// The transaction was finalized with another S2 under the same slate id.
    #[error("slate {slate_id} was already finalized as transaction {tx_id}")]
    AlreadyFinalized { slate_id: SlateId, tx_id: TxId },
    #[error("transaction {tx_id} is {} and cannot be finalized", state_name(*state))]
    NotFinalizable { tx_id: TxId, state: TxState },
    #[error("slate expired at height {cutoff}, the chain tip is at {tip}")]
    Expired { cutoff: Height, tip: Height },
    /// The S2 differs from the S1 this wallet sent in a field only the sender sets.
    #[error("reply changed the {field} of the slate")]
    Mismatch { field: SlateField },
    /// This wallet asked for a payment proof and the reply carries none.
    #[error("reply carries no payment proof")]
    MissingPaymentProof,
    #[error("payment proof sender address is not this wallet's")]
    ForeignSenderAddress,
    #[error("payment proof signature does not verify")]
    PaymentProofSignature,
    #[error("receiver message signature does not verify")]
    MessageSignature(#[source] CryptoError),
    #[error("receiver partial signature does not verify")]
    ReceiverSignature(#[source] CryptoError),
    #[error("fee is below the minimum for the transaction")]
    FeeBelowMinimum { fee: Fee, minimum: Fee },
    #[error("minimum fee could not be computed")]
    FeeOverflow,
    #[error("sender signature could not be created")]
    Signing(#[source] CryptoError),
    #[error("kernel excess could not be computed")]
    Excess(#[source] KernelSumError),
    #[error("final transaction is invalid")]
    InvalidTransaction(#[source] ValidationError),
    #[error("final slate could not be built")]
    Slate(#[source] SlateError),
    #[error("codec registration failed")]
    Codecs(#[source] RegistryError),
    #[error("final slate could not be stored")]
    Encode(#[source] EncodeError),
    #[error("stored slate is unreadable")]
    StoredSlate(#[source] DecodeError),
    #[error("private context of slate {slate_id} is missing")]
    MissingContext { slate_id: SlateId },
    #[error("stored private context is malformed")]
    MalformedContext,
    #[error("node request failed")]
    Node(#[source] NodeError),
    #[error("transaction {tx_id} is {} and has nothing to post", state_name(*state))]
    NotPostable { tx_id: TxId, state: TxState },
    /// The transaction is finalized and stored; [`crate::Wallet::post`] tries again.
    #[error("transaction {tx_id} is finalized but the node did not accept it")]
    NotPosted {
        tx_id: TxId,
        #[source]
        source: NodeError,
    },
    /// The node refused the transaction and no longer holds inputs of it that this wallet
    /// held: another wallet on the same recovery phrase spent them. The transaction was
    /// cancelled, its other inputs released, and a refresh ran.
    #[error("inputs of transaction {tx_id} were spent by another wallet")]
    InputsSpentElsewhere {
        tx_id: TxId,
        #[source]
        source: NodeError,
    },
}

impl From<StoreError> for FinalizeError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

impl From<KeychainError> for FinalizeError {
    fn from(error: KeychainError) -> Self {
        Self::Wallet(WalletError::Keychain(error))
    }
}

/// How a post ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posted {
    /// The node accepted the transaction, or its pool already held it.
    Accepted,
    /// The node refused the push, and its chain already holds the kernel, in the block at
    /// `height`.
    AlreadyOnChain { height: Height },
}

/// A finalized slate and the transaction it completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedSlate {
    pub slate: Slate,
    pub transaction: Transaction,
}

/// A transaction this wallet finalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalized {
    pub tx_id: TxId,
    pub slate: Slate,
    pub transaction: Transaction,
    /// This call pushed the transaction to the node; `false` when it was posted before.
    pub pushed: bool,
}

/// S2 to S3 for the sender of `s1`, on a network whose base fee is `base_fee`, as `complete_tx`
/// and `verify_slate_payment_proof` do it.
///
/// Fails with [`FinalizeError::Mismatch`] when the reply changed what the sender proposed, with
/// [`FinalizeError::MissingPaymentProof`] or [`FinalizeError::PaymentProofSignature`] when a
/// requested payment proof is absent or not signed by the receiver, with
/// [`FinalizeError::ReceiverSignature`] or [`FinalizeError::MessageSignature`] for a receiver
/// signature that does not verify, and with [`FinalizeError::InvalidTransaction`] when the
/// result fails the node's transaction validation.
pub fn build_s3(
    keychain: &Keychain,
    base_fee: Fee,
    s1: &BuiltS1,
    s2: &Slate,
) -> Result<FinalizedSlate, FinalizeError> {
    if s2.stage() != Stage::S2 {
        return Err(FinalizeError::WrongStage { stage: s2.stage() });
    }
    check_reply(&s1.slate, s2)?;
    let receiver = s2.participant(Role::Receiver).ok_or(FinalizeError::Slate(
        SlateError::MissingParticipant {
            stage: s2.stage(),
            role: Role::Receiver,
        },
    ))?;
    if let Some(message) = &receiver.message {
        verify_message(message, &receiver.public_blind_excess)
            .map_err(FinalizeError::MessageSignature)?;
    }
    check_fee(s2, base_fee)?;

    let context = &s1.context;
    let sender_excess = PublicKey::from_secret_key(&context.secret_key).map_err(signing)?;
    let sender_nonce = PublicKey::from_secret_key(&context.secret_nonce).map_err(signing)?;
    let nonce_sum = PublicKey::sum(&[sender_nonce, receiver.public_nonce]).map_err(signing)?;
    let excess_sum =
        PublicKey::sum(&[sender_excess, receiver.public_blind_excess]).map_err(signing)?;
    let message = s2.kernel_features().signature_message();
    let receiver_signature = receiver.partial_signature.ok_or(FinalizeError::Slate(
        SlateError::MissingPartialSignature {
            stage: s2.stage(),
            role: Role::Receiver,
        },
    ))?;
    verify_partial_sig(
        &receiver_signature,
        &nonce_sum,
        &receiver.public_blind_excess,
        Some(&excess_sum),
        &message,
    )
    .map_err(FinalizeError::ReceiverSignature)?;
    let sender_signature = calculate_partial_sig(
        &context.secret_key,
        &context.secret_nonce,
        &nonce_sum,
        Some(&excess_sum),
        &message,
    )
    .map_err(signing)?;
    let excess_sig =
        add_signatures(&[sender_signature, receiver_signature], &nonce_sum).map_err(signing)?;
    verify_completed_sig(&excess_sig, &excess_sum, Some(&excess_sum), &message).map_err(signing)?;

    let excess = kernel_excess(s2)?;
    if let Some(proof) = s2.payment_proof() {
        verify_payment_proof(keychain, context, proof, s2, &excess)?;
    }
    let slate = s2
        .finalize(sender_signature, FinalKernel { excess, excess_sig })
        .map_err(FinalizeError::Slate)?;
    let transaction = final_transaction(&slate)?;
    transaction
        .validate()
        .map_err(FinalizeError::InvalidTransaction)?;
    Ok(FinalizedSlate { slate, transaction })
}

fn signing(error: CryptoError) -> FinalizeError {
    FinalizeError::Signing(error)
}

/// The receiver adds its participant data, one output and, when asked, the payment proof
/// signature. Everything else is what the sender proposed.
fn check_reply(s1: &Slate, s2: &Slate) -> Result<(), FinalizeError> {
    let mismatch = |field| Err(FinalizeError::Mismatch { field });
    if s2.amount() != s1.amount() {
        return mismatch(SlateField::Amount);
    }
    if s2.fee() != s1.fee() {
        return mismatch(SlateField::Fee);
    }
    if s2.height() != s1.height() {
        return mismatch(SlateField::Height);
    }
    if s2.lock() != s1.lock() {
        return mismatch(SlateField::Lock);
    }
    if s2.ttl_cutoff_height() != s1.ttl_cutoff_height() {
        return mismatch(SlateField::TimeToLive);
    }
    if s2.offset() != s1.offset() {
        return mismatch(SlateField::Offset);
    }
    if s2.inputs() != s1.inputs() {
        return mismatch(SlateField::Inputs);
    }
    let outputs_kept = s2.outputs().len() == s1.outputs().len().saturating_add(1)
        && s1
            .outputs()
            .iter()
            .all(|output| s2.outputs().contains(output));
    if !outputs_kept {
        return mismatch(SlateField::Outputs);
    }
    if s2.participant(Role::Sender) != s1.participant(Role::Sender) {
        return mismatch(SlateField::Sender);
    }
    match (s1.payment_proof(), s2.payment_proof()) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(FinalizeError::MissingPaymentProof),
        (Some(asked), Some(answered))
            if asked.sender_address == answered.sender_address
                && asked.receiver_address == answered.receiver_address =>
        {
            Ok(())
        }
        (None | Some(_), Some(_)) => mismatch(SlateField::PaymentProof),
    }
}

/// Participant messages are signed over their BLAKE2b-256 hash, with the signer's public excess
/// as both the key and the challenge key.
fn verify_message(message: &ParticipantMessage, signer: &PublicKey) -> Result<(), CryptoError> {
    let digest = Message::from(*blake2b_256(message.text().as_bytes()).as_bytes());
    verify_completed_sig(message.signature(), signer, Some(signer), &digest)
}

/// Upstream checks the fee against the complete body before signing; the receiver's output is
/// in it now.
fn check_fee(slate: &Slate, base_fee: Fee) -> Result<(), FinalizeError> {
    let minimum = BodyCounts::new(count(slate.inputs().len()), count(slate.outputs().len()), 1)
        .tx_fee(base_fee)
        .map_err(|_| FinalizeError::FeeOverflow)?;
    if slate.fee() < minimum {
        return Err(FinalizeError::FeeBelowMinimum {
            fee: slate.fee(),
            minimum,
        });
    }
    Ok(())
}

/// `calc_excess`: the outputs plus the fee, less the inputs and the offset.
pub(crate) fn kernel_excess(slate: &Slate) -> Result<Commitment, FinalizeError> {
    let body = TransactionBody::from_parts(
        slate.inputs().to_vec(),
        slate.outputs().to_vec(),
        Vec::new(),
    );
    let total = sum_commitments(&body, slate.fee().value()).map_err(FinalizeError::Excess)?;
    let offset: &BlindingFactor = slate.offset();
    if offset.is_zero() {
        return Ok(total);
    }
    let offset = offset
        .to_secret_key()
        .map_err(|error| FinalizeError::Excess(KernelSumError::InvalidOffset(error)))?;
    let offset = Commitment::commit(0, &offset)
        .map_err(|error| FinalizeError::Excess(KernelSumError::Excesses(error)))?;
    Commitment::sum(&[total], &[offset])
        .map_err(|error| FinalizeError::Excess(KernelSumError::Excesses(error)))
}

/// The sender address must be the one this wallet derived for the proof, and the receiver must
/// have signed the amount, the kernel excess and that address.
fn verify_payment_proof(
    keychain: &Keychain,
    context: &SenderContext,
    proof: &PaymentProof,
    slate: &Slate,
    excess: &Commitment,
) -> Result<(), FinalizeError> {
    let index = context.payment_proof_index.ok_or(FinalizeError::Mismatch {
        field: SlateField::PaymentProof,
    })?;
    let key = keychain.payment_proof_key(&account::parent_key_id(context.account)?, index)?;
    if &key.public_key() != proof.sender_address.as_bytes() {
        return Err(FinalizeError::ForeignSenderAddress);
    }
    let signature = proof.receiver_signature.ok_or(FinalizeError::Slate(
        SlateError::MissingProofSignature {
            stage: slate.stage(),
        },
    ))?;
    let mut signed = Vec::with_capacity(8 + Commitment::LEN + 32);
    signed.extend_from_slice(&slate.amount().value().to_be_bytes());
    signed.extend_from_slice(excess.as_bytes());
    signed.extend_from_slice(proof.sender_address.as_bytes());
    let receiver = VerifyingKey::from_bytes(proof.receiver_address.as_bytes())
        .map_err(|_| FinalizeError::PaymentProofSignature)?;
    receiver
        .verify(
            &signed,
            &ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
        )
        .map_err(|_| FinalizeError::PaymentProofSignature)
}

/// The transaction of a final slate, its body in the order the node requires.
fn final_transaction(slate: &Slate) -> Result<Transaction, FinalizeError> {
    let kernel = slate
        .kernel()
        .ok_or(FinalizeError::Slate(SlateError::MissingKernelExcess {
            stage: slate.stage(),
        }))?;
    let body = TransactionBody::new(
        slate.inputs().to_vec(),
        slate.outputs().to_vec(),
        vec![kernel],
    );
    Ok(Transaction::new(slate.offset().clone(), body))
}

/// Lengths of in-memory collections always fit `u64`.
fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The codecs a legacy transport policy decodes with, at the network's base fee.
fn legacy_codecs(base_fee: Fee) -> Result<CodecRegistry, FinalizeError> {
    let mut codecs = CodecRegistry::new();
    codecs
        .register(Box::new(V3JsonCodec::new(base_fee)))
        .map_err(FinalizeError::Codecs)?;
    codecs
        .register(Box::new(V2JsonCodec::new(base_fee)))
        .map_err(FinalizeError::Codecs)?;
    Ok(codecs)
}

/// What the store transaction of a finalize runs with, so it needs no `Ports`.
struct FinalizeEnvironment {
    network: Network,
    tip: Height,
    now: Timestamp,
}

impl FinalizeEnvironment {
    fn base_fee(&self) -> Fee {
        self.network.params().default_base_fee()
    }
}

/// What a finalize stored, or found stored by an earlier one.
struct StoredS3 {
    tx_id: TxId,
    finalized: FinalizedSlate,
    change: Option<StateChange>,
    state: TxState,
}

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn decode_stored(base_fee: Fee, stored: StoredSlate) -> Result<Slate, FinalizeError> {
    V3JsonCodec::new(base_fee)
        .decode(&WireSlate::binary(MediaType::JSON, stored.bytes))
        .map_err(FinalizeError::StoredSlate)
}

/// The stored S3 of a sent transaction, and its transaction.
fn stored_s3(
    repos: &dyn Repositories,
    base_fee: Fee,
    slate_id: Uuid,
) -> Result<Option<FinalizedSlate>, FinalizeError> {
    stored_final(repos, base_fee, slate_id, SlateStage::Standard3)
}

/// The stored final slate at `stage`, S3 or I3, and its transaction.
fn stored_final(
    repos: &dyn Repositories,
    base_fee: Fee,
    slate_id: Uuid,
    stage: SlateStage,
) -> Result<Option<FinalizedSlate>, FinalizeError> {
    let Some(stored) = repos
        .slate(slate_id, stage)?
        .filter(|stored| stored.codec == LEGACY_V3_JSON.as_str())
    else {
        return Ok(None);
    };
    let slate = decode_stored(base_fee, stored)?;
    let transaction = final_transaction(&slate)?;
    Ok(Some(FinalizedSlate { slate, transaction }))
}

/// Whether `s3` was finalized from `s2`: the two agree on everything but what finalizing adds.
fn finalized_from(s3: &Slate, s2: &Slate) -> bool {
    let mut finalized = s3.clone().with_origin(None).into_parts();
    finalized.stage = Stage::S2;
    finalized.kernel = None;
    if let Some(sender) = &mut finalized.sender {
        sender.partial_signature = None;
    }
    finalized == s2.clone().with_origin(None).into_parts()
}

/// Finalizes `s2` against the stored S1 and context in the caller's store transaction: stores
/// S3, drops the context and moves the transaction to `finalized`. A transaction already
/// finalized from the same S2 is returned as stored.
fn finalize_stored(
    repos: &mut dyn Repositories,
    keychain: &Keychain,
    env: &FinalizeEnvironment,
    s2: &Slate,
) -> Result<StoredS3, FinalizeError> {
    let slate_id = s2.id();
    let slate_uuid = uuid(slate_id);
    let base_fee = env.base_fee();
    let entry = repos
        .transaction_by_slate(slate_uuid, TxDirection::Outgoing)?
        .ok_or(FinalizeError::UnknownSlate { slate_id })?;
    let tx_id = entry.id;
    match entry.entry.state {
        TxState::Sent => {}
        state @ (TxState::Finalized | TxState::Posted | TxState::Confirmed) => {
            return match stored_s3(repos, base_fee, slate_uuid)? {
                // Returned as the first finalize returned it: with the wire origin of the S2,
                // which a reply policy echoes, not that of the stored copy.
                Some(finalized) if finalized_from(&finalized.slate, s2) => {
                    // A finalized transaction is pushed again, which its cutoff forbids.
                    if state == TxState::Finalized {
                        check_cutoff(repos, tx_id, &finalized.slate, env.tip)?;
                    }
                    Ok(StoredS3 {
                        tx_id,
                        finalized: FinalizedSlate {
                            slate: finalized.slate.with_origin(s2.origin().copied()),
                            transaction: finalized.transaction,
                        },
                        change: None,
                        state,
                    })
                }
                _ => Err(FinalizeError::AlreadyFinalized { slate_id, tx_id }),
            };
        }
        state @ (TxState::Received | TxState::Cancelled | TxState::Expired) => {
            return Err(FinalizeError::NotFinalizable { tx_id, state });
        }
    }

    let s1 = repos
        .slate(slate_uuid, SlateStage::Standard1)?
        .filter(|stored| stored.codec == LEGACY_V3_JSON.as_str())
        .ok_or(FinalizeError::UnknownSlate { slate_id })?;
    let s1 = decode_stored(base_fee, s1)?.with_origin(None);
    check_cutoff(repos, tx_id, &s1, env.tip)?;
    let context = repos
        .context(slate_uuid, SENDER_CONTEXT)?
        .ok_or(FinalizeError::MissingContext { slate_id })?;
    let built = BuiltS1 {
        slate: s1,
        context: SenderContext::from_private(&context)
            .map_err(|_| FinalizeError::MalformedContext)?,
    };
    let finalized = build_s3(keychain, base_fee, &built, s2)?;

    let block_header_version = s2.origin().and_then(WireOrigin::legacy_header).map_or_else(
        || block_header_version(env.network, s2.height()),
        |header| header.block_header_version,
    );
    let encoded = V3JsonCodec::new(base_fee)
        .encode(
            &finalized.slate,
            &EncodeContext {
                block_header_version,
            },
        )
        .map_err(FinalizeError::Encode)?;
    repos.insert_slate(&StoredSlate {
        slate_id: slate_uuid,
        stage: SlateStage::Standard3,
        codec: LEGACY_V3_JSON.as_str().to_owned(),
        bytes: encoded.as_bytes().to_vec(),
    })?;
    // Upstream drops the context once the slate is final; nothing signs with it again.
    repos.delete_context(slate_uuid, SENDER_CONTEXT)?;
    let change = apply_transition(repos, tx_id, TxState::Finalized, env.now)?;
    record_finalized(repos, tx_id, env.tip)?;
    Ok(StoredS3 {
        tx_id,
        finalized,
        change,
        state: TxState::Finalized,
    })
}

/// Refuses with [`FinalizeError::Expired`] once `tip` reaches the transaction's cutoff: the
/// earlier of the TTL `slate` carries and the send's local cutoff.
fn check_cutoff(
    repos: &dyn Repositories,
    tx_id: TxId,
    slate: &Slate,
    tip: Height,
) -> Result<(), FinalizeError> {
    match effective_cutoff(repos, tx_id, slate.ttl_cutoff_height())? {
        Some(cutoff) if tip >= cutoff => Err(FinalizeError::Expired { cutoff, tip }),
        _ => Ok(()),
    }
}

/// A slate this wallet finalized from its own S2, by [`finalize_own`].
pub(crate) struct FinalizedOwn {
    pub(crate) tx_id: TxId,
    pub(crate) finalized: FinalizedSlate,
    pub(crate) change: Option<StateChange>,
}

/// Finalizes `s2`, the answer this wallet gave its own S1, in the caller's store transaction,
/// as [`Wallet::finalize`] stores it.
pub(crate) fn finalize_own(
    repos: &mut dyn Repositories,
    keychain: &Keychain,
    network: Network,
    tip: Height,
    now: Timestamp,
    s2: &Slate,
) -> Result<FinalizedOwn, FinalizeError> {
    let stored = finalize_stored(
        repos,
        keychain,
        &FinalizeEnvironment { network, tip, now },
        s2,
    )?;
    Ok(FinalizedOwn {
        tx_id: stored.tx_id,
        finalized: stored.finalized,
        change: stored.change,
    })
}

/// Why a push did not record the transaction as posted.
pub(crate) enum PushFailure {
    /// The node refused or could not be reached, and does not hold the kernel.
    NotPosted(NodeError),
    /// The node's pool refused it and inputs this wallet held are gone from the chain.
    InputsSpent(NodeError),
    Wallet(WalletError),
}

/// What the node's pool API answers, as `Error::Internal("Failed to update pool: ...")`, for
/// any transaction its pool refuses, among them one whose inputs are not in the UTXO set.
const POOL_REFUSED: &str = "Failed to update pool:";

/// Whether the node's pool refused a push, for whatever reason its text gives.
fn pool_refused(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::Rejected {
            rejection: NodeRejection {
                kind: RejectionKind::Internal,
                message: Some(message),
            },
            ..
        } if message.starts_with(POOL_REFUSED)
    )
}

/// What the node's pool API answers, as `Error::Internal("Failed to update pool: {PoolError}")`,
/// when its pool already holds the transaction: a repeated push of a transaction it accepted
/// before, for example after the first answer was lost.
const POOL_HOLDS_TRANSACTION: &str = "Failed to update pool: Duplicate tx";

/// Whether the node refused a push only because it already has the transaction. The text is the
/// node's own, but trusting it gives a node no power it lacks: it could as well answer `Ok`.
fn pool_holds_transaction(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::Rejected {
            rejection: NodeRejection {
                kind: RejectionKind::Internal,
                message: Some(message),
            },
            ..
        } if message == POOL_HOLDS_TRANSACTION
    )
}

/// The stored final slate and transaction of a transaction that may be posted, and the height
/// from which it may not, if any.
fn postable(
    repos: &dyn Repositories,
    base_fee: Fee,
    tx_id: TxId,
) -> Result<(FinalizedSlate, Option<Height>), FinalizeError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let not_postable = FinalizeError::NotPostable {
        tx_id,
        state: entry.state,
    };
    let (TxState::Finalized | TxState::Posted, Some(slate_id)) = (entry.state, entry.slate_id)
    else {
        return Err(not_postable);
    };
    // The sender of a standard flow and the issuer of an invoice finalize; each stores its own
    // final stage.
    let stage = match entry.direction {
        TxDirection::Outgoing => SlateStage::Standard3,
        TxDirection::Incoming => SlateStage::Invoice3,
    };
    let finalized = stored_final(repos, base_fee, slate_id, stage)?.ok_or(not_postable)?;
    // An invoice's cutoff is the earlier of its I3's and the one it was issued with; the payer
    // of one without a TTL may expect its issuer to post late.
    let cutoff = match entry.direction {
        TxDirection::Outgoing => {
            effective_cutoff(repos, tx_id, finalized.slate.ttl_cutoff_height())?
        }
        TxDirection::Incoming => {
            let issued = repos
                .slate(slate_id, SlateStage::Invoice1)?
                .filter(|stored| stored.codec == LEGACY_V3_JSON.as_str())
                .map(|stored| decode_stored(base_fee, stored))
                .transpose()?;
            earliest_cutoff(
                finalized.slate.ttl_cutoff_height(),
                issued.and_then(|slate| slate.ttl_cutoff_height()),
            )
        }
    };
    Ok((finalized, cutoff))
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Finalizes the receiver's S2, which arrived over `transport`, and posts the transaction:
    /// checks the reply against the S1 this wallet sent, verifies the receiver's signatures and
    /// payment proof, builds and validates the final transaction, stores S3 and drops the
    /// private context in one store transaction, then pushes the transaction to the node with
    /// `propagation`.
    ///
    /// Asks the node for its tip, and refuses with [`FinalizeError::Expired`] once it reaches the
    /// transaction's cutoff: the earlier of the slate's TTL cutoff and the local cutoff of
    /// [`crate::send::SendRequest::local_ttl_blocks`]. Finalizing an S2 a second time, also once
    /// its transaction is confirmed, returns the stored result and posts only if the first post
    /// did not succeed, which the cutoff refuses as well; another S2 under the same slate id
    /// fails with [`FinalizeError::AlreadyFinalized`]. Fails with
    /// [`FinalizeError::NotPosted`] when the slate was finalized and stored but the node refused or
    /// could not be reached; the transaction then waits in state `finalized` for [`Wallet::post`].
    /// A node whose pool or chain already holds the transaction counts as having accepted it. Every other
    /// failure stores nothing.
    #[instrument(skip_all, fields(
        wallet = %self.config().name,
        transport = %transport,
        slate_id = Empty,
        stage = Empty,
        tx_id = Empty,
    ))]
    pub async fn finalize(
        &self,
        transport: TransportId,
        wire: &WireSlate,
        propagation: Propagation,
    ) -> Result<Finalized, FinalizeError> {
        let session = self.session()?;
        let network = self.config().network;
        let base_fee = network.params().default_base_fee();
        let policy = self
            .ports()
            .transports
            .get(transport)
            .ok_or(FinalizeError::UnknownTransport { transport })?
            .policy();
        let s2 = policy
            .decode(&legacy_codecs(base_fee)?, wire)
            .map_err(FinalizeError::Decode)?;
        let span = Span::current();
        span.record("slate_id", tracing::field::display(s2.id()));
        span.record("stage", s2.stage().as_str());
        if s2.stage() != Stage::S2 {
            return Err(FinalizeError::WrongStage { stage: s2.stage() });
        }
        let tip = self
            .ports()
            .node
            .get_tip()
            .await
            .map_err(FinalizeError::Node)?
            .height;
        self.check_plausible_tip(&session, tip).await?;
        let stored = self
            .blocking(move |ports, _| {
                let env = FinalizeEnvironment {
                    network,
                    tip,
                    now: ports.clock.now(),
                };
                Ok(session
                    .store
                    .write(|repos| finalize_stored(repos, &session.keychain, &env, &s2)))
            })
            .await??;
        span.record("tx_id", stored.tx_id.0);
        match stored.change {
            Some(change) => {
                info!("slate finalized");
                self.emit(change.into());
            }
            None => debug!("slate already finalized"),
        }
        let pushed = stored.state == TxState::Finalized;
        if pushed {
            self.push(stored.tx_id, &stored.finalized, propagation)
                .await?;
        }
        Ok(Finalized {
            tx_id: stored.tx_id,
            slate: stored.finalized.slate,
            transaction: stored.finalized.transaction,
            pushed,
        })
    }

    /// Pushes the stored final transaction of `tx_id` to the node with `propagation` and
    /// records it as posted. Posting a posted transaction again sends it again and changes
    /// nothing that is stored.
    ///
    /// Fails with [`FinalizeError::Wallet`] carrying [`WalletError::UnknownTransaction`], with
    /// [`FinalizeError::NotPostable`] when the transaction is not `finalized` or `posted`,
    /// with [`FinalizeError::NotPosted`] when the node refuses or cannot be reached, and with
    /// [`FinalizeError::InputsSpentElsewhere`] when the node's pool refuses it and two answers
    /// of the node agree that inputs this wallet held are no longer unspent: another wallet on
    /// the phrase spent them. The transaction is then cancelled and a refresh runs. A send
    /// with a cutoff, the earlier of its slate's TTL cutoff and the local cutoff of
    /// [`crate::send::SendRequest::local_ttl_blocks`], has the node's tip asked for, and is
    /// refused with [`FinalizeError::Expired`] once the tip reaches it, also when it was posted
    /// before. So is an invoice this wallet issued, at the earlier of its I3's TTL cutoff and
    /// the one it was issued with. A node whose pool already holds the transaction counts as
    /// having accepted it. When the node refuses the push, the kernel is looked up; one already on chain gives
    /// [`Posted::AlreadyOnChain`], and the next refresh confirms the transaction.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn post(
        &self,
        tx_id: TxId,
        propagation: Propagation,
    ) -> Result<Posted, FinalizeError> {
        let session = self.session()?;
        let (finalized, cutoff) = {
            let session = Arc::clone(&session);
            self.blocking(move |_, config| {
                let base_fee = config.network.params().default_base_fee();
                Ok(session.store.read(|repos| postable(repos, base_fee, tx_id)))
            })
            .await??
        };
        if let Some(cutoff) = cutoff {
            let tip = self
                .ports()
                .node
                .get_tip()
                .await
                .map_err(FinalizeError::Node)?
                .height;
            self.check_plausible_tip(&session, tip).await?;
            if tip >= cutoff {
                return Err(FinalizeError::Expired { cutoff, tip });
            }
        }
        self.push(tx_id, &finalized, propagation).await
    }

    /// [`Self::push_final`], with its failures as [`FinalizeError`].
    pub(crate) async fn push(
        &self,
        tx_id: TxId,
        finalized: &FinalizedSlate,
        propagation: Propagation,
    ) -> Result<Posted, FinalizeError> {
        match self.push_final(finalized, tx_id, propagation).await {
            Ok(posted) => Ok(posted),
            Err(PushFailure::NotPosted(source)) => Err(FinalizeError::NotPosted { tx_id, source }),
            Err(PushFailure::InputsSpent(source)) => {
                self.end_spent_elsewhere(tx_id).await;
                Err(FinalizeError::InputsSpentElsewhere { tx_id, source })
            }
            Err(PushFailure::Wallet(error)) => Err(FinalizeError::Wallet(error)),
        }
    }

    /// Ends a transaction the node refused because another wallet spent its inputs: cancels it
    /// as a user's cancel does, releasing the inputs still unspent, and refreshes, which marks
    /// the spent ones spent and records the other wallet's spend. Both are best effort; what
    /// fails is logged and left to the next refresh.
    pub(crate) async fn end_spent_elsewhere(&self, tx_id: TxId) {
        match self.cancel(tx_id).await {
            Ok(()) => {
                let marked = match self.session() {
                    Ok(session) => {
                        self.blocking(move |_, _| {
                            Ok(session.store.write(|repos| {
                                crate::other_wallet::mark_inputs_lost(repos, tx_id)
                            })?)
                        })
                        .await
                    }
                    Err(error) => Err(error),
                };
                if let Err(error) = marked {
                    warn!(error = %crate::inbox::ErrorChain(&error), "send spent elsewhere not marked");
                }
            }
            Err(error) => {
                warn!(error = %crate::inbox::ErrorChain(&error), "send spent elsewhere not cancelled");
            }
        }
        if let Err(error) = self.refresh().await {
            warn!(error = %crate::inbox::ErrorChain(&error), "refresh after a send spent elsewhere failed");
        }
    }

    /// Whether inputs of `transaction` that this wallet holds are missing from the node's
    /// UTXO set in two answers, as a refresh decides an output was spent.
    async fn inputs_gone(&self, transaction: &lepic_primitives::tx::Transaction) -> bool {
        let Ok(session) = self.session() else {
            return false;
        };
        let inputs: Vec<Commitment> = transaction
            .body()
            .inputs()
            .iter()
            .map(|input| input.commitment)
            .collect();
        let ours = self
            .blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    let mut ours = Vec::new();
                    for commitment in inputs {
                        if repos.output(commitment.as_bytes())?.is_some() {
                            ours.push(commitment);
                        }
                    }
                    Ok::<_, StoreError>(ours)
                }))
            })
            .await;
        let Ok(Ok(mut missing)) = ours else {
            return false;
        };
        for _ in 0..2 {
            if missing.is_empty() {
                return false;
            }
            let Ok(held) = self.ports().node.get_outputs(&missing).await else {
                return false;
            };
            missing.retain(|commitment| !held.iter().any(|found| found.commitment == *commitment));
        }
        !missing.is_empty()
    }

    /// Hands the transaction to the node, then records the transaction as posted. A node whose
    /// pool already holds it counts as having accepted it; when the node refuses the push, the
    /// kernel is looked up, and one already on chain counts as posted too.
    pub(crate) async fn push_final(
        &self,
        finalized: &FinalizedSlate,
        tx_id: TxId,
        propagation: Propagation,
    ) -> Result<Posted, PushFailure> {
        let posted = match self
            .ports()
            .node
            .push_transaction(&finalized.transaction, propagation)
            .await
        {
            Ok(()) => Posted::Accepted,
            Err(error) if pool_holds_transaction(&error) => {
                debug!("transaction already in the node pool");
                Posted::Accepted
            }
            Err(source) => match self.kernel_height(&finalized.slate).await {
                Some(height) => {
                    debug!(height = %height, "kernel found on chain");
                    Posted::AlreadyOnChain { height }
                }
                None if pool_refused(&source) && self.inputs_gone(&finalized.transaction).await => {
                    info!("inputs spent by another wallet");
                    return Err(PushFailure::InputsSpent(source));
                }
                None => return Err(PushFailure::NotPosted(source)),
            },
        };
        let session = self.session().map_err(PushFailure::Wallet)?;
        let change = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                session
                    .store
                    .write(|repos| apply_transition(repos, tx_id, TxState::Posted, now))
            })
            .await
            .map_err(PushFailure::Wallet)?;
        match change {
            Some(change) => {
                info!("transaction posted");
                self.emit(change.into());
            }
            None => debug!("transaction posted again"),
        }
        Ok(posted)
    }

    /// The height of the block holding the slate's kernel, when the node has one. A failed
    /// lookup counts as not found, so the refused push is what gets reported.
    async fn kernel_height(&self, slate: &Slate) -> Option<Height> {
        let excess = slate.kernel()?.excess;
        self.ports()
            .node
            .get_kernel(&excess, Some(slate.height()), None)
            .await
            .ok()
            .flatten()
            .map(|located| located.height)
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and index (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use serde_json::Value;

    use super::*;

    const S1: &str = include_str!(
        "../../../testdata/vectors/slates/send_file_ttl_payment_proof_messages_s1_v3.json"
    );
    const S2: &str = include_str!(
        "../../../testdata/vectors/slates/send_file_ttl_payment_proof_messages_s2_v3.json"
    );
    const S3: &str = include_str!(
        "../../../testdata/vectors/slates/send_file_ttl_payment_proof_messages_s3_v3.json"
    );

    fn slate_json(vector: &str) -> Value {
        let vector: Value = serde_json::from_str(vector).unwrap();
        serde_json::from_str(vector["expected"]["json"].as_str().unwrap()).unwrap()
    }

    fn decode(json: &Value) -> Slate {
        V3JsonCodec::new(Network::Floonet.params().default_base_fee())
            .decode(&WireSlate::text(MediaType::JSON, json.to_string()))
            .unwrap()
    }

    type Change = Box<dyn FnOnce(&mut Value)>;

    fn changed(json: &Value, change: impl FnOnce(&mut Value)) -> Slate {
        let mut json = json.clone();
        change(&mut json);
        decode(&json)
    }

    #[test]
    fn the_g03_s2_answers_its_s1() {
        assert!(check_reply(&decode(&slate_json(S1)), &decode(&slate_json(S2))).is_ok());
    }

    #[test]
    fn a_reply_that_changes_what_the_sender_proposed_names_the_field() {
        let s1 = decode(&slate_json(S1));
        let s2 = slate_json(S2);
        let cases: [(SlateField, Change); 6] = [
            (
                SlateField::Amount,
                Box::new(|json| json["amount"] = Value::from("1")),
            ),
            (
                SlateField::Height,
                Box::new(|json| json["height"] = Value::from("3")),
            ),
            (
                SlateField::TimeToLive,
                Box::new(|json| json["ttl_cutoff_height"] = Value::from("99")),
            ),
            (
                SlateField::Offset,
                Box::new(|json| json["tx"]["offset"] = Value::from("01".repeat(32))),
            ),
            (
                SlateField::Sender,
                Box::new(|json| {
                    // Both parties used the same test nonce, so the excess tells them apart.
                    let receiver = json["participant_data"][1]["public_blind_excess"].clone();
                    json["participant_data"][0]["public_blind_excess"] = receiver;
                }),
            ),
            (
                SlateField::Outputs,
                Box::new(|json| {
                    json["tx"]["body"]["outputs"].as_array_mut().unwrap().pop();
                }),
            ),
        ];
        for (field, change) in cases {
            let reply = changed(&s2, change);
            let result = check_reply(&s1, &reply);
            assert!(
                matches!(result, Err(FinalizeError::Mismatch { field: got }) if got == field),
                "{field}"
            );
        }
        let without_proof = changed(&s2, |json| json["payment_proof"] = Value::Null);
        assert!(matches!(
            check_reply(&s1, &without_proof),
            Err(FinalizeError::MissingPaymentProof)
        ));
    }

    #[test]
    fn the_g03_s3_is_recognised_as_finalized_from_its_s2_only() {
        let s3 = decode(&slate_json(S3));
        let s2 = slate_json(S2);
        assert!(finalized_from(&s3, &decode(&s2)));
        let other = changed(&s2, |json| {
            json["participant_data"][1]["message"] = Value::from("another reply");
        });
        assert!(!finalized_from(&s3, &other));
    }
}

#[cfg(test)]
mod pool_answer_tests {
    use super::*;

    fn rejected(kind: RejectionKind, message: Option<&str>) -> NodeError {
        NodeError::Rejected {
            method: "push_transaction",
            rejection: NodeRejection {
                kind,
                message: message.map(str::to_owned),
            },
        }
    }

    #[test]
    fn only_the_pools_duplicate_answer_counts_as_posted() {
        assert!(pool_holds_transaction(&rejected(
            RejectionKind::Internal,
            Some("Failed to update pool: Duplicate tx"),
        )));
        for other in [
            rejected(
                RejectionKind::Internal,
                Some("Failed to update pool: Duplicate commitment"),
            ),
            rejected(RejectionKind::Internal, Some("Failed to get chain head")),
            rejected(RejectionKind::Internal, None),
            rejected(
                RejectionKind::Argument,
                Some("Failed to update pool: Duplicate tx"),
            ),
            NodeError::Timeout,
        ] {
            assert!(!pool_holds_transaction(&other), "{other:?}");
        }
    }
}
