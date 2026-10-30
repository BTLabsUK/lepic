// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/api_impl/owner.rs,
// libwallet/src/api_impl/foreign.rs, libwallet/src/internal/tx.rs,
// libwallet/src/internal/selection.rs, libwallet/src/slate.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! The three slates of the invoice flow on their own, with the randomness passed in, as
//! `epic-wallet` `v4.0.2` builds them: `owner::issue_invoice_tx` (I1), `owner::process_invoice_tx`
//! (I2) and `foreign::finalize_invoice_tx` (I3).

use lepic_crypto::aggsig::{
    add_signatures, calculate_partial_sig, create_secnonce, sign_single, verify_completed_sig,
    verify_partial_sig,
};
use lepic_crypto::{Commitment, CryptoError, Message, PublicKey, SecretKey};
use lepic_keychain::proof::create_output;
use lepic_keychain::{Identifier, Keychain, ProofBuilder, SwitchCommitment};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::committed::{KernelSumError, sum_commitments};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::hash::blake2b_256;
use lepic_primitives::input::Input;
use lepic_primitives::tx::{Transaction, TransactionBody};
use lepic_slate::error::SlateError;
use lepic_slate::model::{
    FinalKernel, KernelLock, Participant, ParticipantMessage, Payment, Proposal, Slate, SlateId,
};
use lepic_slate::role::Role;
use lepic_slate::stage::{Flow, Stage};
use lepic_store::{AccountIndex, OutputRecord, PrivateContext};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{InvoiceError, InvoiceField};
use crate::finalize::FinalizedSlate;
use crate::send::ChangeOutput;

/// Everything an I1 is built from once the issuer's output key is reserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I1Plan {
    pub account: AccountIndex,
    /// What the issuer asks to be paid; the payer adds the fee on top.
    pub amount: Amount,
    /// The chain tip the invoice is issued at.
    pub height: Height,
    /// The height from which a payer refuses the invoice and the issuer its payment.
    pub ttl_cutoff_height: Option<Height>,
    /// The key of the issuer's output.
    pub key_id: Identifier,
    /// Cut to [`lepic_slate::model::MAX_MESSAGE_LEN`] bytes, on a character boundary, before
    /// it is signed.
    pub message: Option<String>,
}

/// The random values of one I1. [`I1Randomness::draw`] takes them from the wallet's RNG; tests
/// pass the values upstream chose.
#[derive(Debug)]
pub struct I1Randomness {
    pub slate_id: SlateId,
    /// The kernel offset, split off the issuer's excess: the issuer adds data first.
    pub offset: SecretKey,
    pub nonce: SecretKey,
    pub message_nonce: SecretKey,
}

impl I1Randomness {
    pub fn draw(rng: &mut (impl CryptoRng + ?Sized)) -> Result<Self, CryptoError> {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Ok(Self {
            slate_id: SlateId::from_random_bytes(id),
            // Any valid scalar serves as an offset, which is what a nonce draw yields.
            offset: create_secnonce(rng)?,
            nonce: create_secnonce(rng)?,
            message_nonce: create_secnonce(rng)?,
        })
    }
}

/// What the issuer keeps secret between I1 and I3, sealed in the store under
/// [`super::ISSUER_CONTEXT`].
pub(crate) struct IssuerContext {
    /// The issuer's output key with the offset split off.
    pub(crate) secret_key: SecretKey,
    pub(crate) secret_nonce: SecretKey,
}

impl std::fmt::Debug for IssuerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuerContext([redacted])")
    }
}

impl IssuerContext {
    const FORMAT_V1: u8 = 1;
    const LEN_V1: usize = 1 + SecretKey::LEN + SecretKey::LEN;

    /// Format 1: format byte, secret key, secret nonce.
    pub(crate) fn to_private(&self) -> PrivateContext {
        let mut bytes = Zeroizing::new(Vec::with_capacity(Self::LEN_V1));
        bytes.push(Self::FORMAT_V1);
        bytes.extend_from_slice(self.secret_key.expose_bytes());
        bytes.extend_from_slice(self.secret_nonce.expose_bytes());
        PrivateContext::new(std::mem::take(&mut *bytes))
    }

    pub(crate) fn from_private(context: &PrivateContext) -> Result<Self, InvoiceError> {
        let Some((&Self::FORMAT_V1, rest)) = context.expose().split_first() else {
            return Err(InvoiceError::MalformedContext);
        };
        let (secret_key, rest) = rest
            .split_first_chunk::<{ SecretKey::LEN }>()
            .ok_or(InvoiceError::MalformedContext)?;
        let (secret_nonce, rest) = rest
            .split_first_chunk::<{ SecretKey::LEN }>()
            .ok_or(InvoiceError::MalformedContext)?;
        if !rest.is_empty() {
            return Err(InvoiceError::MalformedContext);
        }
        // Read from the borrowed context, so no copy of a key is left behind unwiped.
        let key = |bytes: &[u8; SecretKey::LEN]| {
            SecretKey::from_bytes(bytes).map_err(|_| InvoiceError::MalformedContext)
        };
        Ok(Self {
            secret_key: key(secret_key)?,
            secret_nonce: key(secret_nonce)?,
        })
    }
}

/// An I1 and the secrets the issuer needs to finalize it.
#[derive(Debug)]
pub struct BuiltI1 {
    pub slate: Slate,
    pub(crate) context: IssuerContext,
}

/// Builds the I1 of `plan` as `issue_invoice_tx` does: the issuer's output for the amount, the
/// kernel offset split off its key, its public excess and nonce and its signed message. No fee
/// or lock height: the payer sets the fee, and upstream issues invoices without a lock height.
/// Upstream issues them without a TTL too; `plan.ttl_cutoff_height` adds one.
pub fn build_i1(
    keychain: &Keychain,
    plan: &I1Plan,
    randomness: I1Randomness,
) -> Result<BuiltI1, InvoiceError> {
    let amount = plan.amount.value();
    let switch = SwitchCommitment::Regular;
    let builder = ProofBuilder::new(keychain).map_err(InvoiceError::Output)?;
    let output = create_output(keychain, &builder, amount, &plan.key_id, switch)
        .map_err(InvoiceError::Output)?;
    let output_key = keychain.derive_key(amount, &plan.key_id, switch)?;
    let secret_key = SecretKey::sum(&[output_key], std::slice::from_ref(&randomness.offset))
        .map_err(InvoiceError::Signing)?;

    let issuer = participant(
        &secret_key,
        &randomness.nonce,
        plan.message.as_deref(),
        &randomness.message_nonce,
    )?;
    let proposal = Proposal {
        id: randomness.slate_id,
        amount: plan.amount,
        fee: Fee::ZERO,
        height: plan.height,
        lock: KernelLock::NONE,
        ttl_cutoff_height: plan.ttl_cutoff_height,
        offset: BlindingFactor::from_secret_key(&randomness.offset),
        inputs: Vec::new(),
        outputs: vec![output],
        payment_proof: None,
    };
    let slate = Slate::propose(Flow::Invoice, proposal, issuer).map_err(InvoiceError::Slate)?;
    Ok(BuiltI1 {
        slate,
        context: IssuerContext {
            secret_key,
            secret_nonce: randomness.nonce,
        },
    })
}

/// Everything an I2 is built from once selection has chosen the payer's inputs and its change
/// keys are reserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I2Plan {
    pub fee: Fee,
    /// The chain tip the payer saw, which replaces the issuer's height.
    pub height: Height,
    /// The payer's TTL; without one the slate keeps the issuer's.
    pub ttl_cutoff_height: Option<Height>,
    pub inputs: Vec<OutputRecord>,
    pub change: Vec<ChangeOutput>,
    /// Cut to [`lepic_slate::model::MAX_MESSAGE_LEN`] bytes, on a character boundary, before
    /// it is signed.
    pub message: Option<String>,
}

/// The random values of one I2. The issuer drew the offset, so the payer draws only nonces.
#[derive(Debug)]
pub struct I2Randomness {
    pub nonce: SecretKey,
    pub message_nonce: SecretKey,
}

impl I2Randomness {
    pub fn draw(rng: &mut (impl CryptoRng + ?Sized)) -> Result<Self, CryptoError> {
        Ok(Self {
            nonce: create_secnonce(rng)?,
            message_nonce: create_secnonce(rng)?,
        })
    }
}

/// Builds the I2 of `plan` from `i1` as `process_invoice_tx` does: the payer's inputs and
/// change in the order the node requires, the fee, its public excess and nonce, its signed
/// message and its partial signature. The payer keeps no secret: the issuer finalizes.
///
/// Fails with [`InvoiceError::InputKeyMismatch`] when an input's stored commitment is not the
/// one its key and value derive.
pub fn build_i2(
    keychain: &Keychain,
    i1: &Slate,
    plan: &I2Plan,
    randomness: &I2Randomness,
) -> Result<Slate, InvoiceError> {
    if i1.stage() != Stage::I1 {
        return Err(InvoiceError::WrongStage { stage: i1.stage() });
    }
    let switch = SwitchCommitment::Regular;
    let mut inputs = Vec::with_capacity(plan.inputs.len());
    let mut input_keys = Vec::with_capacity(plan.inputs.len());
    for record in &plan.inputs {
        let key_id = Identifier::from_bytes(&record.key_id.0)?;
        let key = keychain.derive_key(record.amount.value(), &key_id, switch)?;
        let commitment =
            Commitment::commit(record.amount.value(), &key).map_err(InvoiceError::Signing)?;
        if commitment != record.id.commitment {
            return Err(InvoiceError::InputKeyMismatch);
        }
        inputs.push(Input::new(record.id.features, record.id.commitment));
        input_keys.push(key);
    }
    let builder = ProofBuilder::new(keychain).map_err(InvoiceError::Output)?;
    let mut outputs = Vec::with_capacity(plan.change.len());
    let mut change_keys = Vec::with_capacity(plan.change.len());
    for change in &plan.change {
        let amount = change.amount.value();
        change_keys.push(keychain.derive_key(amount, &change.key_id, switch)?);
        outputs.push(
            create_output(keychain, &builder, amount, &change.key_id, switch)
                .map_err(InvoiceError::Output)?,
        );
    }
    // The issuer split the offset off its own key, so the payer signs with its whole excess.
    let secret_key = SecretKey::sum(&change_keys, &input_keys).map_err(InvoiceError::Signing)?;
    let mut payer = participant(
        &secret_key,
        &randomness.nonce,
        plan.message.as_deref(),
        &randomness.message_nonce,
    )?;

    let issuer = initiator(i1)?;
    let nonce_sum = PublicKey::sum(&[issuer.public_nonce, payer.public_nonce])
        .map_err(InvoiceError::Signing)?;
    let excess_sum = PublicKey::sum(&[issuer.public_blind_excess, payer.public_blind_excess])
        .map_err(InvoiceError::Signing)?;
    let kernel_message = i1.lock().kernel_features(plan.fee).signature_message();
    payer.partial_signature = Some(
        calculate_partial_sig(
            &secret_key,
            &randomness.nonce,
            &nonce_sum,
            Some(&excess_sum),
            &kernel_message,
        )
        .map_err(InvoiceError::Signing)?,
    );

    let paid = i1
        .pay(Payment {
            sender: payer,
            inputs,
            outputs,
            fee: plan.fee,
            height: plan.height,
            ttl_cutoff_height: plan.ttl_cutoff_height,
        })
        .map_err(InvoiceError::Slate)?;
    sorted_body(paid)
}

/// I2 to I3 for the issuer of `i1`, on a network whose base fee is `base_fee`, as
/// `finalize_invoice_tx` does it: checks the payment against the invoice, verifies the payer's
/// message and partial signature, adds the issuer's, aggregates, builds the kernel and
/// validates the transaction.
///
/// Fails with [`InvoiceError::Mismatch`] when the payer changed what the issuer proposed, with
/// [`InvoiceError::PayerSignature`] or [`InvoiceError::MessageSignature`] for a payer signature
/// that does not verify, and with [`InvoiceError::InvalidTransaction`] when the result fails
/// the node's transaction validation.
pub fn build_i3(base_fee: Fee, i1: &BuiltI1, i2: &Slate) -> Result<FinalizedSlate, InvoiceError> {
    if i2.stage() != Stage::I2 {
        return Err(InvoiceError::WrongStage { stage: i2.stage() });
    }
    check_payment(&i1.slate, i2)?;
    let payer = i2.participant(Role::Sender).ok_or(InvoiceError::Slate(
        SlateError::MissingParticipant {
            stage: i2.stage(),
            role: Role::Sender,
        },
    ))?;
    if let Some(message) = &payer.message {
        verify_message(message, &payer.public_blind_excess).map_err(|source| {
            InvoiceError::MessageSignature {
                role: Role::Sender,
                source,
            }
        })?;
    }
    check_fee(i2, base_fee)?;

    let context = &i1.context;
    let issuer_excess =
        PublicKey::from_secret_key(&context.secret_key).map_err(InvoiceError::Signing)?;
    let issuer_nonce =
        PublicKey::from_secret_key(&context.secret_nonce).map_err(InvoiceError::Signing)?;
    let nonce_sum =
        PublicKey::sum(&[issuer_nonce, payer.public_nonce]).map_err(InvoiceError::Signing)?;
    let excess_sum = PublicKey::sum(&[issuer_excess, payer.public_blind_excess])
        .map_err(InvoiceError::Signing)?;
    let message = i2.kernel_features().signature_message();
    let payer_signature = payer.partial_signature.ok_or(InvoiceError::Slate(
        SlateError::MissingPartialSignature {
            stage: i2.stage(),
            role: Role::Sender,
        },
    ))?;
    verify_partial_sig(
        &payer_signature,
        &nonce_sum,
        &payer.public_blind_excess,
        Some(&excess_sum),
        &message,
    )
    .map_err(InvoiceError::PayerSignature)?;
    let issuer_signature = calculate_partial_sig(
        &context.secret_key,
        &context.secret_nonce,
        &nonce_sum,
        Some(&excess_sum),
        &message,
    )
    .map_err(InvoiceError::Signing)?;
    let excess_sig = add_signatures(&[issuer_signature, payer_signature], &nonce_sum)
        .map_err(InvoiceError::Signing)?;
    verify_completed_sig(&excess_sig, &excess_sum, Some(&excess_sum), &message)
        .map_err(InvoiceError::Signing)?;

    let excess = kernel_excess(i2)?;
    let slate = i2
        .finalize(issuer_signature, FinalKernel { excess, excess_sig })
        .map_err(InvoiceError::Slate)?;
    let transaction = final_transaction(&slate)?;
    transaction
        .validate()
        .map_err(InvoiceError::InvalidTransaction)?;
    Ok(FinalizedSlate { slate, transaction })
}

/// The public data of a party signing with `secret_key`, and its message signed under it.
fn participant(
    secret_key: &SecretKey,
    nonce: &SecretKey,
    message: Option<&str>,
    message_nonce: &SecretKey,
) -> Result<Participant, InvoiceError> {
    let public_blind_excess =
        PublicKey::from_secret_key(secret_key).map_err(InvoiceError::Signing)?;
    let public_nonce = PublicKey::from_secret_key(nonce).map_err(InvoiceError::Signing)?;
    let mut data = Participant::new(public_blind_excess, public_nonce);
    data.message = message
        .map(|text| {
            let text = ParticipantMessage::truncate(text);
            let signature = sign_single(
                &message_digest(text),
                secret_key,
                message_nonce,
                Some(&public_blind_excess),
            )
            .map_err(InvoiceError::Signing)?;
            ParticipantMessage::new(text.to_owned(), signature).map_err(InvoiceError::Slate)
        })
        .transpose()?;
    Ok(data)
}

fn initiator(slate: &Slate) -> Result<&Participant, InvoiceError> {
    let role = slate.flow().initiator();
    slate
        .participant(role)
        .ok_or(InvoiceError::Slate(SlateError::MissingParticipant {
            stage: slate.stage(),
            role,
        }))
}

/// Upstream inserts every input and output into the body in hash order, as the node requires.
fn sorted_body(slate: Slate) -> Result<Slate, InvoiceError> {
    let mut parts = slate.into_parts();
    let (inputs, outputs, _) = TransactionBody::new(
        std::mem::take(&mut parts.inputs),
        std::mem::take(&mut parts.outputs),
        Vec::new(),
    )
    .into_parts();
    parts.inputs = inputs;
    parts.outputs = outputs;
    Slate::from_parts(parts).map_err(InvoiceError::Slate)
}

/// Checks that `i2` pays `i1` as it was issued and that the payer's partial signature in it
/// verifies against the issuer's public excess and nonce in `i1`. Needs no issuer secret, so it
/// still answers once the issuer's context is gone.
pub(crate) fn check_signed_payment(i1: &Slate, i2: &Slate) -> Result<(), InvoiceError> {
    if i2.stage() != Stage::I2 {
        return Err(InvoiceError::WrongStage { stage: i2.stage() });
    }
    check_payment(i1, i2)?;
    let issuer = initiator(i1)?;
    let payer = i2.participant(Role::Sender).ok_or(InvoiceError::Slate(
        SlateError::MissingParticipant {
            stage: i2.stage(),
            role: Role::Sender,
        },
    ))?;
    let signature = payer.partial_signature.ok_or(InvoiceError::Slate(
        SlateError::MissingPartialSignature {
            stage: i2.stage(),
            role: Role::Sender,
        },
    ))?;
    let nonce_sum = PublicKey::sum(&[issuer.public_nonce, payer.public_nonce])
        .map_err(InvoiceError::Signing)?;
    let excess_sum = PublicKey::sum(&[issuer.public_blind_excess, payer.public_blind_excess])
        .map_err(InvoiceError::Signing)?;
    verify_partial_sig(
        &signature,
        &nonce_sum,
        &payer.public_blind_excess,
        Some(&excess_sum),
        &i2.kernel_features().signature_message(),
    )
    .map_err(InvoiceError::PayerSignature)
}

/// The payer adds its participant data, its inputs and change, the fee, its height and
/// optionally a TTL. Everything else is what the issuer proposed.
fn check_payment(i1: &Slate, i2: &Slate) -> Result<(), InvoiceError> {
    let mismatch = |field| Err(InvoiceError::Mismatch { field });
    if i2.id() != i1.id() {
        return mismatch(InvoiceField::Id);
    }
    if i2.amount() != i1.amount() {
        return mismatch(InvoiceField::Amount);
    }
    if i2.lock() != i1.lock() {
        return mismatch(InvoiceField::Lock);
    }
    if i2.offset() != i1.offset() {
        return mismatch(InvoiceField::Offset);
    }
    let outputs_kept = i1
        .outputs()
        .iter()
        .all(|output| i2.outputs().contains(output));
    if !outputs_kept {
        return mismatch(InvoiceField::Outputs);
    }
    if i2.participant(Role::Receiver) != i1.participant(Role::Receiver) {
        return mismatch(InvoiceField::Issuer);
    }
    Ok(())
}

/// Participant messages are signed over their BLAKE2b-256 hash, with the signer's public
/// excess as both the key and the challenge key.
fn message_digest(text: &str) -> Message {
    Message::from(*blake2b_256(text.as_bytes()).as_bytes())
}

pub(crate) fn verify_message(
    message: &ParticipantMessage,
    signer: &PublicKey,
) -> Result<(), CryptoError> {
    verify_completed_sig(
        message.signature(),
        signer,
        Some(signer),
        &message_digest(message.text()),
    )
}

/// Upstream checks the fee against the complete body before the issuer signs.
fn check_fee(slate: &Slate, base_fee: Fee) -> Result<(), InvoiceError> {
    let minimum = BodyCounts::new(count(slate.inputs().len()), count(slate.outputs().len()), 1)
        .tx_fee(base_fee)
        .map_err(|_| InvoiceError::FeeOverflow)?;
    if slate.fee() < minimum {
        return Err(InvoiceError::FeeBelowMinimum {
            fee: slate.fee(),
            minimum,
        });
    }
    Ok(())
}

/// `calc_excess`: the outputs plus the fee, less the inputs and the offset.
fn kernel_excess(slate: &Slate) -> Result<Commitment, InvoiceError> {
    let body = TransactionBody::from_parts(
        slate.inputs().to_vec(),
        slate.outputs().to_vec(),
        Vec::new(),
    );
    let total = sum_commitments(&body, slate.fee().value()).map_err(InvoiceError::Excess)?;
    if slate.offset().is_zero() {
        return Ok(total);
    }
    let offset = slate
        .offset()
        .to_secret_key()
        .map_err(|error| InvoiceError::Excess(KernelSumError::InvalidOffset(error)))?;
    let offset = Commitment::commit(0, &offset)
        .map_err(|error| InvoiceError::Excess(KernelSumError::Excesses(error)))?;
    Commitment::sum(&[total], &[offset])
        .map_err(|error| InvoiceError::Excess(KernelSumError::Excesses(error)))
}

/// The transaction of a final slate, its body in the order the node requires.
pub(crate) fn final_transaction(slate: &Slate) -> Result<Transaction, InvoiceError> {
    let kernel = slate
        .kernel()
        .ok_or(InvoiceError::Slate(SlateError::MissingKernelExcess {
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

#[cfg(test)]
mod tests {
    // Tests may unwrap and index (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn context() -> IssuerContext {
        IssuerContext {
            secret_key: key(3),
            secret_nonce: key(4),
        }
    }

    #[test]
    fn issuer_context_round_trips_through_its_sealed_form() {
        let read = IssuerContext::from_private(&context().to_private()).unwrap();
        assert_eq!(read.secret_key.expose_bytes(), &[3; 32]);
        assert_eq!(read.secret_nonce.expose_bytes(), &[4; 32]);
    }

    #[test]
    fn rejects_a_malformed_issuer_context() {
        let good = context().to_private();
        let mut unknown_format = good.expose().to_vec();
        unknown_format[0] = 2;
        let mut zero_key = good.expose().to_vec();
        zero_key[1..33].fill(0);
        let mut long = good.expose().to_vec();
        long.push(0);
        for bytes in [
            Vec::new(),
            good.expose()[..IssuerContext::LEN_V1 - 1].to_vec(),
            unknown_format,
            zero_key,
            long,
        ] {
            assert!(matches!(
                IssuerContext::from_private(&PrivateContext::new(bytes)),
                Err(InvoiceError::MalformedContext)
            ));
        }
    }

    #[test]
    fn issuer_context_debug_is_redacted() {
        assert_eq!(format!("{:?}", context()), "IssuerContext([redacted])");
    }
}
