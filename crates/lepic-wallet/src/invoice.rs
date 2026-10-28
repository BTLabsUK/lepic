// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/api_impl/owner.rs,
// libwallet/src/api_impl/foreign.rs, libwallet/src/internal/tx.rs,
// libwallet/src/internal/selection.rs, libwallet/src/slate.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! Invoice flow: the receiver asks to be paid. The issuer creates I1, the payer adds its
//! inputs and signs (I2), and the issuer finalizes (I3) and posts, as `epic-wallet` `v4.0.2`
//! does over the file method (`docs/compat/legacy-slates.md`, "Lifecycle"). Upstream has no
//! invoice flow over Epicbox.
//!
//! The issuer is the receiver and the payer the sender, so the legacy participant ids keep
//! their meaning (sender 0, receiver 1) while the initiator is participant 1; the legacy
//! codecs handle that order.
//!
//! Over Epicbox, where upstream has nothing, invoice stages travel as V3 with the LEPIC marker,
//! because the payer sets a TTL on I2 and only the V3 shape carries one; S1 keeps the V2 shape
//! (`docs/compat/epicbox.md`). [`crate::epicbox_invoice`] parks received invoices and pays them.
//!
//! [`build_i1`], [`build_i2`] and [`build_i3`] are the constructions on their own.
//! [`crate::Wallet::issue_invoice`], [`crate::Wallet::pay_invoice`] and
//! [`crate::Wallet::finalize_invoice`] run them against the store, each in one store
//! transaction.

mod build;

use jiff::Timestamp;
use lepic_crypto::{Commitment, CryptoError};
use lepic_epicbox::TRANSPORT_ID as EPICBOX;
use lepic_epicbox::marker::v3::MarkedV3JsonCodec;
use lepic_keychain::{IdentifierError, Keychain, KeychainError, ProofError, SwitchCommitment};
use lepic_node::{NodeApi, NodeError, Propagation};
use lepic_primitives::amount::{Amount, ArithmeticError, Fee, Height};
use lepic_primitives::committed::KernelSumError;
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_primitives::validate::ValidationError;
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_slate::codec::{Codec, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, EncodeError, RegistryError, SlateError};
use lepic_slate::model::{Slate, SlateId};
use lepic_slate::origin::WireOrigin;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{
    AccountIndex, KeyId, OutputRecord, OutputStatus, ParticipantId, PendingInvoiceStatus,
    Repositories, SlateStage, StoreError, StoredSlate, TransactionEntry, TxDirection, TxId,
    TxState, WalletStore,
};
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::file::FILE;
use lepic_transport::policy::{Encoding, FormatPolicy, encode_with};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, Transport, TransportId};
use thiserror::Error;
use tracing::field::Empty;
use tracing::{Span, debug, info, instrument};
use uuid::Uuid;

pub use build::{
    BuiltI1, I1Plan, I1Randomness, I2Plan, I2Randomness, build_i1, build_i2, build_i3,
};

use crate::account::{AccountError, next_output_key};
use crate::codecs;
use crate::error::WalletError;
use crate::extension::ReplyKeys;
use crate::finalize::{Finalized, FinalizedSlate, PushFailure};
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::with_spend_confirmations;
use crate::selection::{self, SelectionError, SelectionRequest, SelectionStrategy};
use crate::send::{
    ChangeOutput, Delivery, SendRequest, block_header_version, record_counterparty, spendable_here,
};
use crate::state::{StateChange, apply_transition, state_name};
use crate::wallet::Wallet;
pub(crate) use build::check_signed_payment;
use build::{IssuerContext, final_transaction, verify_message};

/// The issuer's private context is stored under the participant id legacy slates give the
/// receiver, which the issuer is.
pub(crate) const ISSUER_CONTEXT: ParticipantId = ParticipantId(1);

/// A day of blocks: the TTL an invoice is meant to be payable for at most. The binding issues
/// invoices with it and gives its sends the same limit.
pub const INVOICE_TTL_BLOCKS: u64 = 1_440;

/// How far above the payer's tip an invoice's TTL cutoff may lie: [`INVOICE_TTL_BLOCKS`] for
/// the TTL itself and as many again for an issuer's node ahead of the payer's. A cutoff further
/// ahead was set on a longer chain, another network's, or from a wrong height; paying it would
/// lock the payer's inputs in a payment that cannot complete here.
pub const MAX_INVOICE_TTL_LEAD_BLOCKS: u64 = 2 * INVOICE_TTL_BLOCKS;

/// How far below the payer's tip an invoice's TTL cutoff may lie and still read as expired
/// here: a year of [`INVOICE_TTL_BLOCKS`]. Nobody pays a request that long after it expired,
/// while one made on a younger chain, such as floonet's read on mainnet, has its cutoff
/// millions of blocks below the tip; that one was not made for this chain.
pub const MAX_INVOICE_TTL_LAG_BLOCKS: u64 = 365 * INVOICE_TTL_BLOCKS;

/// Blocks before an invoice's TTL cutoff from which a payer no longer pays it and its issuer no
/// longer finalizes a payment of it, and blocks after the cutoff before the payer releases the
/// payment's inputs. Issuer and payer
/// read their tips from different nodes, which may stand a few blocks apart: without the
/// margin, a payment finalized and posted just below the cutoff by the issuer's node could be
/// released by a payer whose node reached the cutoff before the transaction reached its pool,
/// and the payer could spend the inputs again under the issuer's posted payment. As many
/// blocks as a peer's slate height may lead this wallet's tip.
pub const INVOICE_TTL_MARGIN_BLOCKS: u64 = crate::chain::SLATE_LEAD_BLOCKS;

/// A slate field the payer may not change between I1 and I2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvoiceField {
    Amount,
    Lock,
    Offset,
    Outputs,
    Issuer,
}

impl std::fmt::Display for InvoiceField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Amount => "amount",
            Self::Lock => "lock height",
            Self::Offset => "offset",
            Self::Outputs => "issuer outputs",
            Self::Issuer => "issuer data",
        })
    }
}

/// Why an invoice was not issued, paid or finalized.
// Amounts and fees stay out of the text of every variant because errors are logged above
// `debug` (docs/logging.md); callers read them from the fields.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InvoiceError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("node request failed")]
    Node(#[source] NodeError),
    #[error("transport {transport} is not registered")]
    UnknownTransport { transport: TransportId },
    #[error("transport {transport} cannot deliver slates")]
    CannotDeliver { transport: TransportId },
    #[error("transport {transport} cannot export slates")]
    CannotExport { transport: TransportId },
    #[error("slate could not be decoded")]
    Decode(#[source] DecodeError),
    #[error("slate at stage {stage} does not fit this step of the invoice flow")]
    WrongStage { stage: Stage },
    #[error("output selection failed")]
    Selection(#[from] SelectionError),
    /// The invoice asks for another amount than the one the payer approved.
    #[error("invoice amount differs from the approved amount")]
    AmountMismatch { invoiced: Amount, approved: Amount },
    #[error("invoice {slate_id} was already paid as transaction {tx_id}")]
    AlreadyPaid { slate_id: SlateId, tx_id: TxId },
    #[error("slate expired at height {cutoff}, the chain tip is at {tip}")]
    Expired { cutoff: Height, tip: Height },
    /// The invoice's kernel may not be mined before `lock_height`, which the chain has not
    /// reached. `epic-wallet` issues invoices without a lock height.
    #[error("invoice kernel is locked until height {lock_height}, the chain tip is at {tip}")]
    LockedUntil { lock_height: Height, tip: Height },
    /// The invoice's height is above any the chain can have reached by now.
    #[error("slate height {height} is above the highest plausible height {limit}")]
    AheadOfTip { height: Height, limit: Height },
    /// The invoice's TTL cutoff lies further above the chain tip than
    /// [`MAX_INVOICE_TTL_LEAD_BLOCKS`]: it was issued on another network or at a wrong height.
    #[error("slate ttl cutoff {cutoff} is above the highest plausible cutoff {limit}")]
    TtlTooFarAhead { cutoff: Height, limit: Height },
    /// The invoice's TTL cutoff lies further below the chain tip than
    /// [`MAX_INVOICE_TTL_LAG_BLOCKS`]: it was issued on another network or at a wrong height.
    #[error("slate ttl cutoff {cutoff} is below the lowest plausible cutoff {limit}")]
    TtlTooFarBehind { cutoff: Height, limit: Height },
    #[error("{role} message signature does not verify")]
    MessageSignature {
        role: Role,
        #[source]
        source: CryptoError,
    },
    /// The I2 differs from the I1 this wallet issued in a field only the issuer sets.
    #[error("payment changed the {field} of the invoice")]
    Mismatch { field: InvoiceField },
    #[error("stored output is not the commitment its key derives")]
    InputKeyMismatch,
    #[error("stored key identifier rejected")]
    KeyIdentifier(#[from] IdentifierError),
    #[error("output could not be built")]
    Output(#[source] ProofError),
    #[error("signature could not be created")]
    Signing(#[source] CryptoError),
    #[error("payer partial signature does not verify")]
    PayerSignature(#[source] CryptoError),
    #[error("fee is below the minimum for the transaction")]
    FeeBelowMinimum { fee: Fee, minimum: Fee },
    #[error("minimum fee could not be computed")]
    FeeOverflow,
    #[error("kernel excess could not be computed")]
    Excess(#[source] KernelSumError),
    #[error("final transaction is invalid")]
    InvalidTransaction(#[source] ValidationError),
    #[error("slate rejected")]
    Slate(#[source] SlateError),
    #[error("transaction height arithmetic failed")]
    Arithmetic(#[from] ArithmeticError),
    #[error("codec registration failed")]
    Codecs(#[source] RegistryError),
    /// The format the transport uses for this slate cannot carry all of it. Nothing was stored.
    #[error("transport cannot carry this slate")]
    Encode(#[source] FormatError),
    #[error("slate could not be stored")]
    Unrepresentable(#[source] EncodeError),
    #[error("stored slate is unreadable")]
    StoredSlate(#[source] DecodeError),
    #[error("slate {slate_id} answers no invoice this wallet issued")]
    UnknownSlate { slate_id: SlateId },
    /// The invoice was finalized with another I2 under the same slate id.
    #[error("invoice {slate_id} was already finalized as transaction {tx_id}")]
    AlreadyFinalized { slate_id: SlateId, tx_id: TxId },
    #[error("transaction {tx_id} is {} and cannot be finalized", state_name(*state))]
    NotFinalizable { tx_id: TxId, state: TxState },
    #[error("private context of slate {slate_id} is missing")]
    MissingContext { slate_id: SlateId },
    #[error("stored private context is malformed")]
    MalformedContext,
    /// The invoice and its I1 are stored; cancelling the transaction withdraws it.
    #[error("invoice {slate_id} of transaction {tx_id} is stored but was not delivered")]
    Undelivered {
        tx_id: TxId,
        slate_id: SlateId,
        #[source]
        source: TransportError,
    },
    /// The invoice is finalized and stored; finalizing the same I2 again posts it again.
    #[error("transaction {tx_id} is finalized but the node did not accept it")]
    NotPosted {
        tx_id: TxId,
        #[source]
        source: NodeError,
    },
    /// As [`crate::finalize::FinalizeError::InputsSpentElsewhere`].
    #[error("inputs of transaction {tx_id} were spent by another wallet")]
    InputsSpentElsewhere {
        tx_id: TxId,
        #[source]
        source: NodeError,
    },
    /// No invoice with the slate id waits on the invoice address to be paid or declined.
    #[error("invoice {slate_id} is not waiting to be paid")]
    NotParked { slate_id: SlateId },
    /// The payment is stored and its inputs locked; [`crate::Wallet::resend`] delivers the
    /// stored I2 again, and [`crate::Wallet::cancel`] gives up.
    #[error("payment {tx_id} of invoice {slate_id} is stored but was not delivered")]
    PaymentUndelivered {
        tx_id: TxId,
        slate_id: SlateId,
        #[source]
        source: TransportError,
    },
}

impl From<StoreError> for InvoiceError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

impl From<KeychainError> for InvoiceError {
    fn from(error: KeychainError) -> Self {
        Self::Wallet(WalletError::Keychain(error))
    }
}

/// What to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceRequest {
    /// The account the payment goes to.
    pub account: AccountIndex,
    /// What the issuer receives; the payer adds the fee on top.
    pub amount: Amount,
    /// Cut to [`lepic_slate::model::MAX_MESSAGE_LEN`] bytes, on a character boundary, before
    /// it is signed.
    pub message: Option<String>,
    /// Blocks past the chain tip from which a payer refuses the invoice and this wallet refuses
    /// to finalize its payment. The I1 carries the height as its TTL cutoff; this wallet
    /// refuses past it also when the payer's I2 drops or moves it. `None` issues the invoice
    /// without a TTL, as upstream does.
    pub ttl_blocks: Option<u64>,
}

/// How to pay an invoice. [`PayRequest::new`] fills in the defaults of `epic-wallet`'s
/// `InitTxArgs`, as [`SendRequest::new`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayRequest {
    pub account: AccountIndex,
    /// The amount the payer approved. An invoice for any other amount is refused, as
    /// `epic-wallet pay` refuses unless the user types the invoiced amount.
    pub amount: Amount,
    pub minimum_confirmations: u64,
    pub max_outputs: std::num::NonZeroUsize,
    pub change_outputs: std::num::NonZeroUsize,
    pub strategy: SelectionStrategy,
    /// Blocks past the chain tip after which the issuer must refuse the payment. An invoice
    /// with an earlier TTL cutoff of its own keeps that one.
    pub ttl_blocks: Option<u64>,
    /// Cut to [`lepic_slate::model::MAX_MESSAGE_LEN`] bytes, on a character boundary, before
    /// it is signed.
    pub message: Option<String>,
    /// Outputs selection must not take, whatever their state.
    pub exclude_outputs: Vec<Commitment>,
}

impl PayRequest {
    pub fn new(account: AccountIndex, amount: Amount) -> Self {
        let defaults = SendRequest::new(account, amount);
        Self {
            account,
            amount,
            minimum_confirmations: defaults.minimum_confirmations,
            max_outputs: defaults.max_outputs,
            change_outputs: defaults.change_outputs,
            strategy: defaults.strategy,
            ttl_blocks: None,
            message: None,
            exclude_outputs: Vec::new(),
        }
    }
}

/// An invoice that was stored and delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuedInvoice {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub amount: Amount,
}

/// A paid invoice: the stored transaction and the I2 reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidInvoice {
    pub tx_id: TxId,
    pub slate: Slate,
    /// I2 encoded by the transport's reply rule, the bytes that were stored.
    pub reply: WireSlate,
}

/// The codecs a legacy transport policy decodes and encodes with, at the network's base fee.
fn legacy_codecs(base_fee: Fee) -> Result<CodecRegistry, InvoiceError> {
    codecs_with(Box::new(V3JsonCodec::new(base_fee)), base_fee)
}

/// The codecs invoice stages go out with over `transport`: over Epicbox the V3 shape carries
/// the LEPIC marker, so a reply that keeps it proves the peer runs LEPIC. A file or paste I1
/// carries the marker with `reply_key`, so a LEPIC payer can answer sealed (RFC 0002 5).
fn invoice_codecs(
    transport: TransportId,
    base_fee: Fee,
    reply_key: Option<[u8; 32]>,
) -> Result<CodecRegistry, InvoiceError> {
    let v3 = V3JsonCodec::new(base_fee);
    match reply_key {
        _ if transport == EPICBOX => codecs_with(Box::new(MarkedV3JsonCodec::new(v3)), base_fee),
        Some(key) if transport == FILE => codecs_with(
            Box::new(MarkedV3JsonCodec::new(v3).with_reply_key(key)),
            base_fee,
        ),
        _ => codecs_with(Box::new(v3), base_fee),
    }
}

fn codecs_with(v3: Box<dyn Codec>, base_fee: Fee) -> Result<CodecRegistry, InvoiceError> {
    Ok(codecs::legacy_with(
        v3,
        Box::new(V2JsonCodec::new(base_fee)),
    ))
}

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn registered(
    transports: &TransportRegistry,
    transport: TransportId,
) -> Result<&dyn Transport, InvoiceError> {
    transports
        .get(transport)
        .ok_or(InvoiceError::UnknownTransport { transport })
}

/// The transport of `delivery`, if it can carry the slate the way `delivery` says.
fn delivering<'a>(
    transports: &'a TransportRegistry,
    delivery: &Delivery,
) -> Result<&'a dyn Transport, InvoiceError> {
    let id = delivery.transport();
    let transport = registered(transports, id)?;
    match delivery {
        Delivery::Deliver { .. } if transport.outbound().is_none() => {
            Err(InvoiceError::CannotDeliver { transport: id })
        }
        Delivery::Export { .. } if transport.exchange().is_none() => {
            Err(InvoiceError::CannotExport { transport: id })
        }
        Delivery::Deliver { .. } | Delivery::Export { .. } => Ok(transport),
    }
}

/// The encoding of a new I1 over `transport`. Over Epicbox it is V3, which upstream's
/// untagged parse reads first, instead of the V2 shape the Epicbox policy gives a new S1: the
/// payer's TTL on I2 has no field in V2, and I2 answers in the shape of I1.
fn new_invoice_encoding(
    transport: &dyn Transport,
    slate: &Slate,
    context: &EncodeContext,
) -> Encoding {
    if transport.id() == EPICBOX {
        Encoding {
            codec: LEGACY_V3_JSON,
            legacy_header: None,
        }
    } else {
        transport.policy().for_new_slate(slate, context)
    }
}

/// An I1 or I2 whose sender and receiver messages, if any, are signed by their authors.
pub(crate) fn check_messages(slate: &Slate) -> Result<(), InvoiceError> {
    for (role, participant) in slate.participants() {
        if let Some(message) = &participant.message {
            verify_message(message, &participant.public_blind_excess)
                .map_err(|source| InvoiceError::MessageSignature { role, source })?;
        }
    }
    Ok(())
}

/// Refuses once the node's current tip reaches `cutoff`.
fn check_cutoff(cutoff: Option<Height>, tip: Height) -> Result<(), InvoiceError> {
    match cutoff {
        Some(cutoff) if tip >= cutoff => Err(InvoiceError::Expired { cutoff, tip }),
        _ => Ok(()),
    }
}

/// Refuses an invoice whose TTL cutoff lies more than [`MAX_INVOICE_TTL_LAG_BLOCKS`] below the
/// node's tip, before [`check_margin_ttl`] would call it expired. An invoice without a TTL
/// passes.
fn check_ttl_lag(slate: &Slate, tip: Height) -> Result<(), InvoiceError> {
    let Some(cutoff) = slate.ttl_cutoff_height() else {
        return Ok(());
    };
    // A tip too low to have a limit below it has no cutoff that far behind.
    let Ok(limit) = tip.checked_sub_blocks(MAX_INVOICE_TTL_LAG_BLOCKS) else {
        return Ok(());
    };
    if cutoff < limit {
        return Err(InvoiceError::TtlTooFarBehind { cutoff, limit });
    }
    Ok(())
}

/// The height from which the payer refuses to pay an invoice whose TTL cutoff is `cutoff`, and
/// the issuer to finalize a payment of it: [`INVOICE_TTL_MARGIN_BLOCKS`] before it.
fn margin_cutoff(cutoff: Height) -> Height {
    cutoff
        .checked_sub_blocks(INVOICE_TTL_MARGIN_BLOCKS)
        .unwrap_or(Height::ZERO)
}

/// The height from which the payer releases an invoice payment whose TTL cutoff is `cutoff`:
/// [`INVOICE_TTL_MARGIN_BLOCKS`] after it, so an issuer whose node is behind the payer's has
/// posted by then whatever it finalized in time.
pub(crate) fn payer_release_height(cutoff: Height) -> Height {
    // A cutoff so high that the margin overflows is never reached either.
    cutoff
        .checked_add_blocks(INVOICE_TTL_MARGIN_BLOCKS)
        .unwrap_or(cutoff)
}

/// The earlier of two TTL cutoffs, either of which may be missing.
pub(crate) fn earliest_cutoff(first: Option<Height>, second: Option<Height>) -> Option<Height> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (first, second) => first.or(second),
    }
}

/// Refuses to pay an invoice or finalize a payment once the node's tip comes within
/// [`INVOICE_TTL_MARGIN_BLOCKS`] of `cutoff`, reporting that height as the cutoff reached.
fn check_margin_ttl(cutoff: Option<Height>, tip: Height) -> Result<(), InvoiceError> {
    match cutoff.map(margin_cutoff) {
        Some(cutoff) if tip >= cutoff => Err(InvoiceError::Expired { cutoff, tip }),
        _ => Ok(()),
    }
}

/// Refuses an invoice whose TTL cutoff lies more than [`MAX_INVOICE_TTL_LEAD_BLOCKS`] above the
/// node's tip. An invoice without a TTL, as upstream issues them, passes.
fn check_ttl_lead(slate: &Slate, tip: Height) -> Result<(), InvoiceError> {
    let Some(cutoff) = slate.ttl_cutoff_height() else {
        return Ok(());
    };
    // A limit that overflows is never exceeded.
    let Ok(limit) = tip.checked_add_blocks(MAX_INVOICE_TTL_LEAD_BLOCKS) else {
        return Ok(());
    };
    if cutoff > limit {
        return Err(InvoiceError::TtlTooFarAhead { cutoff, limit });
    }
    Ok(())
}

/// Refuses an invoice whose kernel could not be mined at the node's current tip, which would
/// keep the payer's inputs locked in a transaction the chain cannot take until then.
fn check_lock(slate: &Slate, tip: Height) -> Result<(), InvoiceError> {
    let lock_height = slate.lock().lock_height();
    if lock_height > tip {
        return Err(InvoiceError::LockedUntil { lock_height, tip });
    }
    Ok(())
}

/// Refuses an invoice created at a height the chain cannot have reached yet. One above the
/// node's tip is paid: the issuer's node may be ahead of this wallet's.
fn check_height(slate: &Slate, limit: Height) -> Result<(), InvoiceError> {
    let height = slate.height();
    if height > limit {
        return Err(InvoiceError::AheadOfTip { height, limit });
    }
    Ok(())
}

/// The header block version of a slate this wallet answers or stores: the one it arrived
/// with, or the one of a slate created at its height.
fn encode_context(network: Network, slate: &Slate) -> EncodeContext {
    let block_header_version = slate
        .origin()
        .and_then(WireOrigin::legacy_header)
        .map_or_else(
            || block_header_version(network, slate.height()),
            |header| header.block_header_version,
        );
    EncodeContext {
        block_header_version,
    }
}

/// What the store transactions of the invoice flow run with, so they need no `Ports`.
struct InvoiceEnvironment<'a> {
    keychain: &'a Keychain,
    network: Network,
    tip: Height,
    now: Timestamp,
    reply_keys: Option<&'a dyn ReplyKeys>,
}

impl InvoiceEnvironment<'_> {
    fn base_fee(&self) -> Fee {
        self.network.params().default_base_fee()
    }

    /// The slate as V3, which carries every field, for the store.
    fn stored(&self, slate: &Slate) -> Result<WireSlate, InvoiceError> {
        V3JsonCodec::new(self.base_fee())
            .encode(slate, &encode_context(self.network, slate))
            .map_err(InvoiceError::Unrepresentable)
    }

    /// A slate this wallet stored as V3; the stages it stores in another codec are not read.
    fn decode_stored(&self, stored: StoredSlate) -> Result<Slate, InvoiceError> {
        V3JsonCodec::new(self.base_fee())
            .decode(&WireSlate::binary(MediaType::JSON, stored.bytes))
            .map_err(InvoiceError::StoredSlate)
    }
}

/// Reserves the issuer's output key, builds, encodes and stores an I1 in the caller's store
/// transaction. Returns the transaction and the I1 as the transport sends a new slate.
fn issue_stored(
    repos: &mut dyn Repositories,
    env: &InvoiceEnvironment<'_>,
    transport: &dyn Transport,
    delivery: &Delivery,
    request: &InvoiceRequest,
    randomness: I1Randomness,
) -> Result<(TxId, Slate, WireSlate), InvoiceError> {
    if repos.account(request.account)?.is_none() {
        return Err(WalletError::from(AccountError::UnknownAccount(request.account)).into());
    }
    let key_id = next_output_key(repos, request.account)?;
    let ttl_cutoff_height = request
        .ttl_blocks
        .map(|blocks| env.tip.checked_add_blocks(blocks))
        .transpose()?;
    let built = build_i1(
        env.keychain,
        &I1Plan {
            account: request.account,
            amount: request.amount,
            height: env.tip,
            ttl_cutoff_height,
            key_id,
            message: request.message.clone(),
        },
        randomness,
    )?;
    let slate = built.slate;
    let context = encode_context(env.network, &slate);
    let reply_key = env.reply_keys.and_then(|keys| {
        keys.reply_public_key(
            env.keychain,
            env.network,
            request.account,
            *slate.id().as_bytes(),
        )
    });
    let wire = encode_with(
        &invoice_codecs(transport.id(), env.base_fee(), reply_key)?,
        new_invoice_encoding(transport, &slate, &context),
        &slate,
        &context,
    )
    .map_err(InvoiceError::Encode)?;
    let stored = env.stored(&slate)?;

    let slate_id = uuid(slate.id());
    let tx_id = repos.insert_transaction(&TransactionEntry {
        account: request.account,
        direction: TxDirection::Incoming,
        state: TxState::Received,
        slate_id: Some(slate_id),
        transport: Some(transport.id().as_str().to_owned()),
        amount_credited: request.amount,
        amount_debited: Amount::ZERO,
        fee: None,
        created_at: env.now,
        updated_at: env.now,
    })?;
    record_counterparty(repos, tx_id, delivery)?;
    let commitment =
        env.keychain
            .commit(request.amount.value(), &key_id, SwitchCommitment::Regular)?;
    repos.insert_output(&OutputRecord {
        id: OutputIdentifier::new(OutputFeatures::Plain, commitment),
        key_id: KeyId(key_id.to_bytes()),
        account: request.account,
        amount: request.amount,
        status: OutputStatus::Unconfirmed,
        height: env.tip,
        lock_height: Height::ZERO,
        mmr_index: None,
        tx: Some(tx_id),
    })?;
    repos.put_context(slate_id, ISSUER_CONTEXT, &built.context.to_private())?;
    repos.insert_slate(&StoredSlate {
        slate_id,
        stage: SlateStage::Invoice1,
        codec: LEGACY_V3_JSON.as_str().to_owned(),
        bytes: stored.as_bytes().to_vec(),
    })?;
    Ok((tx_id, slate, wire))
}

/// Selects the payer's inputs, builds I2, encodes it by the transport's reply rule and stores
/// the locked inputs, the change, the transaction and the I2 in the caller's store transaction.
fn pay_stored(
    repos: &mut dyn Repositories,
    env: &InvoiceEnvironment<'_>,
    transport: TransportId,
    policy: &dyn FormatPolicy,
    i1: &Slate,
    request: &PayRequest,
    randomness: &I2Randomness,
) -> Result<PaidInvoice, InvoiceError> {
    let slate_id = i1.id();
    if let Some(paid) = repos.transaction_by_slate(uuid(slate_id), TxDirection::Outgoing)? {
        return Err(InvoiceError::AlreadyPaid {
            slate_id,
            tx_id: paid.id,
        });
    }
    if repos.account(request.account)?.is_none() {
        return Err(WalletError::from(AccountError::UnknownAccount(request.account)).into());
    }
    let selection = selection::select(
        &spendable_here(
            env.keychain,
            repos.outputs(request.account, None)?,
            &request.exclude_outputs,
        ),
        &with_spend_confirmations(
            repos,
            SelectionRequest {
                account: request.account,
                amount: i1.amount(),
                tip: env.tip,
                minimum_confirmations: request.minimum_confirmations,
                max_outputs: request.max_outputs,
                change_outputs: request.change_outputs,
                strategy: request.strategy,
                base_fee: env.base_fee(),
            },
        )?,
    )?;
    let change = selection
        .change
        .iter()
        .map(|&amount| {
            Ok(ChangeOutput {
                key_id: next_output_key(repos, request.account)?,
                amount,
            })
        })
        .collect::<Result<Vec<_>, InvoiceError>>()?;
    // The issuer refuses the payment from its own cutoff whatever the I2 says, so a later one
    // would only keep this wallet's inputs locked past the point where the payment can complete.
    let ttl_cutoff_height = request
        .ttl_blocks
        .map(|blocks| env.tip.checked_add_blocks(blocks))
        .transpose()?
        .map(|cutoff| {
            i1.ttl_cutoff_height()
                .map_or(cutoff, |issuer| cutoff.min(issuer))
        });
    let plan = I2Plan {
        fee: selection.fee,
        height: env.tip,
        ttl_cutoff_height,
        inputs: selection.inputs,
        change,
        message: request.message.clone(),
    };
    let slate = build_i2(env.keychain, i1, &plan, randomness)?;
    let context = encode_context(env.network, &slate);
    let encoding = policy.for_reply(&slate, &context);
    let reply = encode_with(
        &invoice_codecs(transport, env.base_fee(), None)?,
        encoding,
        &slate,
        &context,
    )
    .map_err(InvoiceError::Encode)?;

    let tx_id = store_payment(
        repos,
        env,
        &StoredPayment {
            transport,
            account: request.account,
            slate_id: uuid(slate_id),
            plan: &plan,
            debited: selection.total,
            codec: encoding.codec.as_str(),
            reply: &reply,
        },
    )?;
    Ok(PaidInvoice {
        tx_id,
        slate,
        reply,
    })
}

/// What [`store_payment`] stores of an invoice payment.
struct StoredPayment<'a> {
    transport: TransportId,
    account: AccountIndex,
    slate_id: Uuid,
    plan: &'a I2Plan,
    /// The value of the inputs.
    debited: Amount,
    /// The codec the I2 is encoded with.
    codec: &'a str,
    reply: &'a WireSlate,
}

/// Stores a new invoice payment: its outgoing entry, its inputs locked to it, its change
/// unconfirmed and its I2. Returns the entry's id. Run it in the store transaction that pays.
fn store_payment(
    repos: &mut dyn Repositories,
    env: &InvoiceEnvironment<'_>,
    payment: &StoredPayment<'_>,
) -> Result<TxId, InvoiceError> {
    let &StoredPayment {
        transport,
        account,
        slate_id: slate_uuid,
        plan,
        debited,
        codec,
        reply,
    } = payment;
    let total_change = plan.change.iter().try_fold(Amount::ZERO, |total, change| {
        total.checked_add(change.amount)
    })?;
    let tx_id = repos.insert_transaction(&TransactionEntry {
        account,
        direction: TxDirection::Outgoing,
        state: TxState::Sent,
        slate_id: Some(slate_uuid),
        transport: Some(transport.as_str().to_owned()),
        amount_credited: total_change,
        amount_debited: debited,
        fee: Some(plan.fee),
        created_at: env.now,
        updated_at: env.now,
    })?;
    for input in &plan.inputs {
        repos.put_output(&OutputRecord {
            status: OutputStatus::Locked,
            tx: Some(tx_id),
            ..input.clone()
        })?;
    }
    for change in &plan.change {
        let commitment = env.keychain.commit(
            change.amount.value(),
            &change.key_id,
            SwitchCommitment::Regular,
        )?;
        repos.insert_output(&OutputRecord {
            id: OutputIdentifier::new(OutputFeatures::Plain, commitment),
            key_id: KeyId(change.key_id.to_bytes()),
            account,
            amount: change.amount,
            status: OutputStatus::Unconfirmed,
            height: env.tip,
            lock_height: Height::ZERO,
            mmr_index: None,
            tx: Some(tx_id),
        })?;
    }
    repos.insert_slate(&StoredSlate {
        slate_id: slate_uuid,
        stage: SlateStage::Invoice2,
        codec: codec.to_owned(),
        bytes: reply.as_bytes().to_vec(),
    })?;
    Ok(tx_id)
}

/// What a finalize stored, or found stored by an earlier one.
struct StoredI3 {
    tx_id: TxId,
    finalized: FinalizedSlate,
    change: Option<StateChange>,
    state: TxState,
}

/// Whether `i3` was finalized from `i2`: the two agree on everything but what finalizing adds.
fn finalized_from(i3: &Slate, i2: &Slate) -> bool {
    let mut finalized = i3.clone().with_origin(None).into_parts();
    finalized.stage = Stage::I2;
    finalized.kernel = None;
    if let Some(issuer) = &mut finalized.receiver {
        issuer.partial_signature = None;
    }
    finalized == i2.clone().with_origin(None).into_parts()
}

/// Finalizes `i2` against the stored I1 and issuer context in the caller's store transaction:
/// stores I3, drops the context and moves the transaction to `finalized`. A transaction
/// already finalized from the same I2 is returned as stored, unless it is still to be posted
/// and the tip has reached its TTL cutoff. That refusal comes at the cutoff, not
/// [`INVOICE_TTL_MARGIN_BLOCKS`] after it where the payer releases, so the margin still covers
/// an issuer's node behind the payer's.
fn finalize_stored(
    repos: &mut dyn Repositories,
    env: &InvoiceEnvironment<'_>,
    i2: &Slate,
) -> Result<StoredI3, InvoiceError> {
    let slate_id = i2.id();
    let slate_uuid = uuid(slate_id);
    let entry = repos
        .transaction_by_slate(slate_uuid, TxDirection::Incoming)?
        .ok_or(InvoiceError::UnknownSlate { slate_id })?;
    let tx_id = entry.id;
    let issued = repos
        .slate(slate_uuid, SlateStage::Invoice1)?
        .filter(|stored| stored.codec == LEGACY_V3_JSON.as_str())
        .ok_or(InvoiceError::UnknownSlate { slate_id })?;
    match entry.entry.state {
        TxState::Received => {}
        state @ (TxState::Finalized | TxState::Posted) => {
            let stored = repos
                .slate(slate_uuid, SlateStage::Invoice3)?
                .filter(|stored| stored.codec == LEGACY_V3_JSON.as_str())
                .map(|stored| env.decode_stored(stored))
                .transpose()?;
            return match stored {
                // Returned as the first finalize returned it: with the wire origin of the I2.
                Some(i3) if finalized_from(&i3, i2) => {
                    if state == TxState::Finalized {
                        let issued = env.decode_stored(issued)?;
                        check_cutoff(
                            earliest_cutoff(i3.ttl_cutoff_height(), issued.ttl_cutoff_height()),
                            env.tip,
                        )?;
                    }
                    Ok(StoredI3 {
                        tx_id,
                        finalized: FinalizedSlate {
                            transaction: final_transaction(&i3)?,
                            slate: i3.with_origin(i2.origin().copied()),
                        },
                        change: None,
                        state,
                    })
                }
                _ => Err(InvoiceError::AlreadyFinalized { slate_id, tx_id }),
            };
        }
        state @ (TxState::Sent | TxState::Confirmed | TxState::Cancelled | TxState::Expired) => {
            return Err(InvoiceError::NotFinalizable { tx_id, state });
        }
    }
    // The payer may drop or move the cutoff in its I2: a version 2 header loses it, and
    // upstream's payer replaces it with its own. The one this wallet issued still holds.
    let issued = env.decode_stored(issued)?.with_origin(None);
    check_margin_ttl(
        earliest_cutoff(i2.ttl_cutoff_height(), issued.ttl_cutoff_height()),
        env.tip,
    )?;
    let context = repos
        .context(slate_uuid, ISSUER_CONTEXT)?
        .ok_or(InvoiceError::MissingContext { slate_id })?;
    let i1 = BuiltI1 {
        slate: issued,
        context: IssuerContext::from_private(&context)?,
    };
    let finalized = build_i3(env.base_fee(), &i1, i2)?;

    let stored = env.stored(&finalized.slate)?;
    repos.insert_slate(&StoredSlate {
        slate_id: slate_uuid,
        stage: SlateStage::Invoice3,
        codec: LEGACY_V3_JSON.as_str().to_owned(),
        bytes: stored.as_bytes().to_vec(),
    })?;
    // Upstream drops the context once the slate is final; nothing signs with it again.
    repos.delete_context(slate_uuid, ISSUER_CONTEXT)?;
    let change = apply_transition(repos, tx_id, TxState::Finalized, env.now)?;
    Ok(StoredI3 {
        tx_id,
        finalized,
        change,
        state: TxState::Finalized,
    })
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Issues an invoice for `request.amount` to `request.account`: builds the I1 with this
    /// wallet's output, stores the output, the private context, the transaction (incoming,
    /// `received`) and the I1, then delivers it as `delivery` says, encoded with that
    /// transport's rule for a new slate. Over Epicbox the I1 goes out as V3 with the LEPIC
    /// marker, for the payer's invoice address.
    ///
    /// Asks the node for its tip. Fails, with nothing stored, with [`InvoiceError::Wallet`]
    /// carrying [`WalletError::Locked`], an unknown account or
    /// [`WalletError::RestoreScanRequired`], [`InvoiceError::Node`],
    /// [`InvoiceError::UnknownTransport`], [`InvoiceError::CannotDeliver`] or
    /// [`InvoiceError::CannotExport`]. Fails with [`InvoiceError::Undelivered`] when the
    /// invoice was stored but the transport failed; [`Wallet::cancel`] withdraws it.
    #[instrument(skip_all, fields(
        wallet = %self.config().name,
        transport = %delivery.transport(),
        stage = %Stage::I1,
        tx_id = Empty,
        slate_id = Empty,
    ))]
    pub async fn issue_invoice(
        &self,
        request: InvoiceRequest,
        delivery: Delivery,
    ) -> Result<IssuedInvoice, InvoiceError> {
        delivering(&self.ports().transports, &delivery)?;
        let (tx_id, slate, wire) = self.issue_unsent(request, delivery.clone()).await?;
        let span = Span::current();
        span.record("tx_id", tx_id.0);
        span.record("slate_id", tracing::field::display(slate.id()));
        info!("invoice issued");

        let transport = delivering(&self.ports().transports, &delivery)?;
        let outcome = match (&delivery, transport.outbound(), transport.exchange()) {
            (Delivery::Deliver { to, .. }, Some(outbound), _) => outbound.deliver(to, &wire).await,
            (Delivery::Export { to, .. }, _, Some(exchange)) => exchange.export(&wire, to).await,
            (Delivery::Deliver { .. }, None, _) => {
                return Err(InvoiceError::CannotDeliver {
                    transport: delivery.transport(),
                });
            }
            (Delivery::Export { .. }, _, None) => {
                return Err(InvoiceError::CannotExport {
                    transport: delivery.transport(),
                });
            }
        };
        outcome.map_err(|source| InvoiceError::Undelivered {
            tx_id,
            slate_id: slate.id(),
            source,
        })?;
        info!("slate sent");
        Ok(IssuedInvoice {
            tx_id,
            slate_id: slate.id(),
            amount: slate.amount(),
        })
    }

    /// Issues and stores an invoice as [`Wallet::issue_invoice`] does, encoded for the
    /// transport of `delivery` and recording its destination, without delivering it.
    pub async fn issue_unsent(
        &self,
        request: InvoiceRequest,
        delivery: Delivery,
    ) -> Result<(TxId, Slate, WireSlate), InvoiceError> {
        let session = self.session()?;
        registered(&self.ports().transports, delivery.transport())?;
        let tip = self
            .ports()
            .node
            .get_tip()
            .await
            .map_err(InvoiceError::Node)?
            .height;
        self.check_plausible_tip(&session, tip).await?;
        let reply_keys = self.reply_keys();
        self.blocking(move |ports, config| {
            let env = InvoiceEnvironment {
                keychain: &session.keychain,
                network: config.network,
                tip,
                now: ports.clock.now(),
                reply_keys: reply_keys.as_deref(),
            };
            let issued =
                registered(&ports.transports, delivery.transport()).and_then(|transport| {
                    let randomness = I1Randomness::draw(&mut **ports.rng.lock())
                        .map_err(InvoiceError::Signing)?;
                    session.store.write(|repos| {
                        issue_stored(repos, &env, transport, &delivery, &request, randomness)
                    })
                });
            Ok(issued)
        })
        .await?
    }

    /// Pays the issuer's I1, which arrived over `transport`: checks it, selects inputs from
    /// `request.account`, adds them with the change, the fee, this wallet's public data,
    /// message and partial signature, and stores the locked inputs, the change, the transaction
    /// (outgoing, `sent`) and the I2 reply in one store transaction. The caller sends the reply
    /// over the same transport.
    ///
    /// Asks the node for its tip, which becomes the slate height and the base of
    /// `request.ttl_blocks`. Fails with [`InvoiceError::AmountMismatch`] when the invoice asks
    /// for another amount than `request.amount`, [`InvoiceError::AlreadyPaid`] for an invoice
    /// this wallet paid before, [`InvoiceError::Expired`] once the tip comes within
    /// [`INVOICE_TTL_MARGIN_BLOCKS`] of the invoice's TTL cutoff, the height it reports as the
    /// cutoff, [`InvoiceError::TtlTooFarAhead`] when that cutoff lies more than
    /// [`MAX_INVOICE_TTL_LEAD_BLOCKS`] above the tip, [`InvoiceError::TtlTooFarBehind`] when it
    /// lies more than [`MAX_INVOICE_TTL_LAG_BLOCKS`] below it, [`InvoiceError::LockedUntil`]
    /// when its kernel lock height is above the tip, [`InvoiceError::AheadOfTip`] when its
    /// height is above any the chain can have reached by now, a [`InvoiceError::Selection`]
    /// error, and a typed rejection for any slate that is malformed, not an I1, or whose
    /// message does not verify. A payment with
    /// change fails with [`WalletError::RestoreScanRequired`] on a database rebuilt from the
    /// seed before a scan from genesis completed. Nothing is stored on failure.
    #[instrument(skip_all, fields(
        wallet = %self.config().name,
        transport = %transport,
        slate_id = Empty,
        stage = Empty,
        tx_id = Empty,
    ))]
    pub async fn pay_invoice(
        &self,
        transport: TransportId,
        wire: &WireSlate,
        request: PayRequest,
    ) -> Result<PaidInvoice, InvoiceError> {
        let network = self.config().network;
        let i1 = registered(&self.ports().transports, transport)?
            .policy()
            .decode(&legacy_codecs(network.params().default_base_fee())?, wire)
            .map_err(InvoiceError::Decode)?;
        let span = Span::current();
        span.record("slate_id", tracing::field::display(i1.id()));
        span.record("stage", i1.stage().as_str());
        let paid = self.pay_decoded(transport, i1, request, None).await?;
        span.record("tx_id", paid.tx_id.0);
        info!("invoice paid");
        Ok(paid)
    }

    /// Checks and pays a decoded I1, as [`Wallet::pay_invoice`] describes. With `parked`, the
    /// same store transaction marks that parked invoice paid and records where the I2 goes.
    pub async fn pay_decoded(
        &self,
        transport: TransportId,
        i1: Slate,
        request: PayRequest,
        parked: Option<Destination>,
    ) -> Result<PaidInvoice, InvoiceError> {
        let session = self.session()?;
        let network = self.config().network;
        if i1.stage() != Stage::I1 {
            return Err(InvoiceError::WrongStage { stage: i1.stage() });
        }
        if i1.amount() != request.amount {
            return Err(InvoiceError::AmountMismatch {
                invoiced: i1.amount(),
                approved: request.amount,
            });
        }
        check_messages(&i1)?;
        let tip = self
            .ports()
            .node
            .get_tip()
            .await
            .map_err(InvoiceError::Node)?
            .height;
        let limit = self.check_plausible_tip(&session, tip).await?;
        check_ttl_lag(&i1, tip)?;
        // The issuer would refuse to finalize a payment signed from here on, which would only
        // keep this wallet's inputs locked until the payment expires.
        check_margin_ttl(i1.ttl_cutoff_height(), tip)?;
        check_ttl_lead(&i1, tip)?;
        check_lock(&i1, tip)?;
        check_height(&i1, limit)?;
        debug!(height = tip.value(), "slate checked");

        let paid = self
            .blocking(move |ports, _| {
                let env = InvoiceEnvironment {
                    keychain: &session.keychain,
                    network,
                    tip,
                    now: ports.clock.now(),
                    reply_keys: None,
                };
                let paid = registered(&ports.transports, transport).and_then(|carrier| {
                    let randomness = I2Randomness::draw(&mut **ports.rng.lock())
                        .map_err(InvoiceError::Signing)?;
                    session.store.write(|repos| {
                        let paid = pay_stored(
                            repos,
                            &env,
                            transport,
                            carrier.policy(),
                            &i1,
                            &request,
                            &randomness,
                        )?;
                        if let Some(to) = &parked {
                            repos.set_pending_invoice_status(
                                uuid(i1.id()),
                                PendingInvoiceStatus::Paid,
                            )?;
                            repos.set_counterparty(paid.tx_id, to.as_str())?;
                        }
                        Ok(paid)
                    })
                });
                Ok(paid)
            })
            .await??;
        Ok(paid)
    }

    /// Finalizes the payer's I2, which arrived over `transport`, and posts the transaction:
    /// checks the payment against the I1 this wallet issued, verifies the payer's message and
    /// partial signature, builds and validates the final transaction, stores I3 and drops the
    /// private context in one store transaction, then pushes the transaction to the node with
    /// `propagation`.
    ///
    /// Asks the node for its tip, and refuses with [`InvoiceError::Expired`] once it comes
    /// within [`INVOICE_TTL_MARGIN_BLOCKS`] of the earlier of the TTL cutoff the I2 carries and
    /// the one this wallet issued the I1 with; the error reports that height as its cutoff.
    /// Finalizing an I2 a second time returns the stored result and posts only if the first
    /// post did not succeed, which is how a failed post is retried, and is refused with
    /// [`InvoiceError::Expired`] once the tip reaches that cutoff itself; another I2 under the
    /// same slate id fails with [`InvoiceError::AlreadyFinalized`]. Fails with
    /// [`InvoiceError::NotPosted`] when the invoice was finalized and stored but the node
    /// refused or could not be reached and does not hold its kernel. A node whose pool already
    /// holds the transaction, or whose chain holds its kernel, counts as having accepted it.
    /// Every other failure stores nothing.
    #[instrument(skip_all, fields(
        wallet = %self.config().name,
        transport = %transport,
        slate_id = Empty,
        stage = Empty,
        tx_id = Empty,
    ))]
    pub async fn finalize_invoice(
        &self,
        transport: TransportId,
        wire: &WireSlate,
        propagation: Propagation,
    ) -> Result<Finalized, InvoiceError> {
        let session = self.session()?;
        let network = self.config().network;
        let i2 = registered(&self.ports().transports, transport)?
            .policy()
            .decode(&legacy_codecs(network.params().default_base_fee())?, wire)
            .map_err(InvoiceError::Decode)?;
        let span = Span::current();
        span.record("slate_id", tracing::field::display(i2.id()));
        span.record("stage", i2.stage().as_str());
        if i2.stage() != Stage::I2 {
            return Err(InvoiceError::WrongStage { stage: i2.stage() });
        }
        let tip = self
            .ports()
            .node
            .get_tip()
            .await
            .map_err(InvoiceError::Node)?
            .height;
        self.check_plausible_tip(&session, tip).await?;
        let stored = self
            .blocking(move |ports, _| {
                let env = InvoiceEnvironment {
                    keychain: &session.keychain,
                    network,
                    tip,
                    now: ports.clock.now(),
                    reply_keys: None,
                };
                Ok(session
                    .store
                    .write(|repos| finalize_stored(repos, &env, &i2)))
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
        let pushed = stored.state != TxState::Posted;
        if pushed {
            self.push_invoice(stored.tx_id, &stored.finalized, propagation)
                .await?;
        }
        Ok(Finalized {
            tx_id: stored.tx_id,
            slate: stored.finalized.slate,
            transaction: stored.finalized.transaction,
            pushed,
        })
    }

    /// [`Wallet::push_final`], with its failures as [`InvoiceError`].
    async fn push_invoice(
        &self,
        tx_id: TxId,
        finalized: &FinalizedSlate,
        propagation: Propagation,
    ) -> Result<(), InvoiceError> {
        match self.push_final(finalized, tx_id, propagation).await {
            Ok(_) => Ok(()),
            Err(PushFailure::NotPosted(source)) => Err(InvoiceError::NotPosted { tx_id, source }),
            Err(PushFailure::InputsSpent(source)) => {
                self.end_spent_elsewhere(tx_id).await;
                Err(InvoiceError::InputsSpentElsewhere { tx_id, source })
            }
            Err(PushFailure::Wallet(error)) => Err(InvoiceError::Wallet(error)),
        }
    }
}
