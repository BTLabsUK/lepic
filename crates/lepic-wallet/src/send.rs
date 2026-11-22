// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/api_impl/owner.rs, libwallet/src/internal/tx.rs,
// libwallet/src/internal/selection.rs, libwallet/src/slate.rs, libwallet/src/types.rs
// (Apache-2.0); see NOTICE and upstream.toml.

//! Send, standard flow: build the S1 slate, lock its inputs, store it, deliver it.
//!
//! The slate is built as `epic-wallet` `v4.1.0` builds it (`owner::init_send_tx`): selection,
//! change outputs with their proofs, the kernel offset split off the sender's excess, the
//! sender's public excess and nonce, an optional signed message, TTL and payment proof
//! addresses. [`build_s1`] is that construction on its own, with the randomness passed in.
//!
//! [`crate::Wallet::send`] then stores everything in one store transaction (locked inputs, the
//! change outputs, the sealed private context, the transaction entry and the S1 slate) and only
//! afterwards delivers. A slate the chosen transport cannot carry is refused before anything is
//! stored. A failed delivery leaves the transaction waiting in state `sent`, from where
//! [`crate::Wallet::resend`] delivers the stored slate again and [`crate::Wallet::cancel`]
//! releases its inputs.

use std::num::NonZeroUsize;
use std::sync::Arc;

use blake2::Blake2b256;
use blake2::digest::{FixedOutput, Update};
use jiff::Timestamp;
use lepic_crypto::{Commitment, CryptoError, Message, PublicKey, SecretKey, aggsig};
use lepic_keychain::proof::create_output;
use lepic_keychain::{
    Identifier, IdentifierError, Keychain, KeychainError, ProofBuilder, ProofError,
    SwitchCommitment,
};
use lepic_legacy_slate::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_node::{NodeApi, NodeError};
use lepic_primitives::amount::{Amount, ArithmeticError, Fee, Height};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::input::Input;
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_primitives::tx::TransactionBody;
use lepic_slate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{
    DecodeError, EncodeError, ProofAddressError, SlateError, Unrepresentable,
};
use lepic_slate::model::{
    KernelLock, Participant, ParticipantMessage, PaymentProof, ProofAddress, Proposal, Slate,
    SlateId,
};
use lepic_slate::origin::WireOrigin;
use lepic_slate::stage::{Flow, Stage};
use lepic_store::{
    AccountIndex, KeyId, OutboxEntry, OutboxId, OutboxStatus, OutputRecord, OutputStatus,
    ParticipantId, PrivateContext, Record, Repositories, SlateStage, StoreError, StoredOutbox,
    StoredSlate, TransactionEntry, TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::method::{Method, Sending};
use lepic_transport::transport::{Destination, Location, PostedSize, TransportId};
use rand_core::CryptoRng;
use thiserror::Error;
use tracing::field::Empty;
use tracing::{Span, debug, info, instrument, warn};
use uuid::Uuid;

use crate::account::{self, AccountError, next_output_key};
use crate::checked_outputs::CheckedOutputs;
use crate::codecs;
use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::with_spend_confirmations;
use crate::relay_cancel::RelayTxIdError;
use crate::selection::{self, Selection, SelectionError, SelectionOptions, SelectionStrategy};
use crate::send_limit::record_local_cutoff;
use crate::wallet::Wallet;

/// The private context of the party that adds inputs, under the participant id `epic-wallet`
/// gives the sender.
pub(crate) const SENDER_CONTEXT: ParticipantId = ParticipantId(0);

/// `epic-wallet` derives the sender's payment proof address at this index only.
const PAYMENT_PROOF_ADDRESS_INDEX: u32 = 0;

/// Heights at which each network's block header version changes from 6 to 7, as in the node's
/// `consensus::header_version`.
const MAINNET_FIRST_HARD_FORK: u64 = 9_000_000;
const FLOONET_FIRST_HARD_FORK: u64 = 25_800;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SendError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("node request failed")]
    Node(#[source] NodeError),
    #[error("output selection failed")]
    Selection(#[from] SelectionError),
    #[error("transport {transport} is not registered")]
    UnknownTransport { transport: TransportId },
    #[error("transport {transport} cannot deliver slates")]
    CannotDeliver { transport: TransportId },
    #[error("transport {transport} cannot export slates")]
    CannotExport { transport: TransportId },
    /// The format the transport uses for this slate cannot carry all of it, for example a TTL
    /// or payment proof in the V2 shape. Nothing was stored.
    #[error("transport cannot carry this slate")]
    Unrepresentable(#[source] EncodeError),
    #[error("codec {codec} chosen by the transport is not registered")]
    CodecNotRegistered { codec: CodecId },
    #[error("stored output is not the commitment its key derives")]
    InputKeyMismatch,
    #[error("stored key identifier rejected")]
    KeyIdentifier(#[from] IdentifierError),
    #[error("change output proof failed")]
    Proof(#[from] ProofError),
    #[error("transaction key operation failed")]
    Crypto(#[from] CryptoError),
    #[error("payment proof address rejected")]
    ProofAddress(#[from] ProofAddressError),
    #[error("slate rejected")]
    Slate(#[from] SlateError),
    #[error("transaction height arithmetic failed")]
    Arithmetic(#[from] ArithmeticError),
    #[error("stored slate is unreadable")]
    StoredSlate(#[source] DecodeError),
    #[error("stored private context is malformed")]
    MalformedContext,
    /// Only an outgoing transaction in state `sent` with a stored S1 slate, or an invoice
    /// payment with its stored I2, is delivered again.
    #[error("transaction {tx_id} is not waiting for its slate to be delivered")]
    NotResendable { tx_id: TxId },
    /// The payment of a parked invoice goes only over Epicbox to the address the invoice's
    /// sender was allowed under.
    #[error("payment {tx_id} goes only to the allowed address of its invoice")]
    PayeeMismatch { tx_id: TxId },
    /// [`SendRequest::slate_id`] names a slate id this wallet already stores; nothing was
    /// stored. `sent` is this wallet's send under that id, when the id is one.
    #[error("slate id {slate_id} is already taken")]
    SlateIdTaken {
        slate_id: SlateId,
        sent: Option<TxId>,
    },
    /// The transaction and its slate are stored and the inputs locked;
    /// [`crate::Wallet::resend`] tries again and [`crate::Wallet::cancel`] gives up.
    #[error("slate {slate_id} of transaction {tx_id} is stored but was not delivered")]
    Undelivered {
        tx_id: TxId,
        slate_id: SlateId,
        #[source]
        source: TransportError,
    },
    /// The relay refused the slate because the other party cancelled the transaction there
    /// (Epicbox 3.1.0). The transaction stays as it is here, its inputs locked until it is
    /// cancelled or expires.
    #[error("transaction {tx_id} was cancelled on the relay")]
    CancelledOnRelay { tx_id: TxId, slate_id: SlateId },
    /// The send needs a fee above [`SendRequest::max_fee`]; nothing was stored.
    #[error("the send needs a fee of {fee}, above the maximum of {max_fee}")]
    FeeAboveMaximum { fee: Fee, max_fee: Fee },
    /// The relay would get `bytes` for this slate, more than the `limit` it takes, or a
    /// stock receiver's answer would be that long. `inputs` is how many outputs the slate
    /// spends; fewer, larger outputs make it shorter. Nothing was stored.
    #[error("the slate is {bytes} bytes on the relay, above its limit of {limit}")]
    SlateTooLarge {
        bytes: usize,
        limit: usize,
        inputs: usize,
    },
    /// What the caller stores with a send it carries itself ([`StoreCarried`]) could not be
    /// stored, for the caller's own reason. Nothing was stored.
    #[error("the records stored with the send failed")]
    Carried(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<StoreError> for SendError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

impl From<KeychainError> for SendError {
    fn from(error: KeychainError) -> Self {
        Self::Wallet(WalletError::Keychain(error))
    }
}

impl From<FormatError> for SendError {
    fn from(error: FormatError) -> Self {
        match error {
            FormatError::CodecNotRegistered { codec } => Self::CodecNotRegistered { codec },
            FormatError::Encode(error) => Self::Unrepresentable(error),
        }
    }
}

/// What to send. [`SendRequest::new`] fills in the defaults of `epic-wallet`'s `InitTxArgs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRequest {
    pub account: AccountIndex,
    /// What the receiver gets; the fee comes on top.
    pub amount: Amount,
    pub minimum_confirmations: u64,
    pub max_outputs: NonZeroUsize,
    pub change_outputs: NonZeroUsize,
    pub strategy: SelectionStrategy,
    /// [`KernelLock::NONE`] gives a `Plain` kernel, any other height a `HeightLocked` one.
    pub lock: KernelLock,
    /// Blocks past the chain tip after which the receiver must refuse the slate. A send whose
    /// format has no TTL field, the legacy V2 shape, keeps it as [`Self::local_ttl_blocks`]
    /// instead.
    pub ttl_blocks: Option<u64>,
    /// Blocks past the chain tip after which this wallet refuses to finalize or post the send,
    /// and expires it at a refresh if it is unanswered. Kept by this wallet only, not in the
    /// slate, so it works on every method. With [`Self::ttl_blocks`] as well, the earlier
    /// height applies.
    pub local_ttl_blocks: Option<u64>,
    /// Cut to [`lepic_slate::model::MAX_MESSAGE_LEN`] bytes, on a character boundary, before
    /// it is signed.
    pub message: Option<String>,
    /// The receiver's payment proof address. Asks the receiver to sign a payment proof. For
    /// a wallet reached at its onion this is the onion's public key, which a LEPIC receiver
    /// signs with its onion key and a stock one with its payment-proof key (ADR 0044).
    pub payment_proof_recipient: Option<ProofAddress>,
    /// Outputs selection must not take, whatever their state.
    pub exclude_outputs: Vec<Commitment>,
    /// The slate id, instead of one drawn at random. A caller that stores it before sending
    /// can repeat the send after a crash without paying twice: the repeat fails with
    /// [`SendError::SlateIdTaken`], which names the first send. It must be a random version-4
    /// id made for this send, since it travels in the slate.
    pub slate_id: Option<SlateId>,
    /// The highest fee the send may pay. A selection that needs more fails with
    /// [`SendError::FeeAboveMaximum`] before anything is stored, so a send shown to the user
    /// with a fee never pays more than that fee.
    pub max_fee: Option<Fee>,
}

impl SendRequest {
    pub fn new(account: AccountIndex, amount: Amount) -> Self {
        let options = SelectionOptions::new(account);
        Self {
            account,
            amount,
            minimum_confirmations: options.minimum_confirmations,
            max_outputs: options.max_outputs,
            change_outputs: options.change_outputs,
            strategy: options.strategy,
            lock: KernelLock::NONE,
            ttl_blocks: None,
            local_ttl_blocks: None,
            message: None,
            payment_proof_recipient: None,
            exclude_outputs: Vec::new(),
            slate_id: None,
            max_fee: None,
        }
    }

    /// The options [`crate::Wallet::estimate_fee`] takes to estimate this send.
    pub fn selection_options(&self) -> SelectionOptions {
        SelectionOptions {
            account: self.account,
            minimum_confirmations: self.minimum_confirmations,
            max_outputs: self.max_outputs,
            change_outputs: self.change_outputs,
            strategy: self.strategy,
            exclude_outputs: self.exclude_outputs.clone(),
        }
    }
}

/// How a slate went out over a method or to a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlateFormat {
    /// As the method's legacy JSON, V2 or V3; to a contact, sealed V3.
    #[default]
    Legacy,
    /// As a `lepic.v1` slate in a type `0A` envelope, armored `BEGINEPICTX.`, signed to a
    /// contact.
    Native,
}

impl SlateFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Native => "native",
        }
    }
}

/// How a slate leaves the wallet, through the method the call names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Through a method that delivers, such as Epicbox.
    Deliver { to: Destination },
    /// Through a method where the user carries the slate, such as a file.
    Export { to: Location },
}

/// A slate that was stored and delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentSlate {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub amount: Amount,
    pub fee: Fee,
    /// How the S1 went out: as legacy JSON, or as a native slate over Epicbox or to a contact.
    pub format: SlateFormat,
    /// The bytes the relay gets for the S1, or for the stock receiver's answer when that is
    /// longer, and the most the relay takes. `None` when the slate goes through no relay.
    pub slate_bytes: Option<usize>,
    pub slate_limit: Option<usize>,
}

/// How much longer a stock receiver's answer, its S2, is than the S1 it answers, as legacy
/// JSON: its own output with the range proof, its excess and its signatures. The send
/// measures the S1 plus this against the relay's limit, since the receiver posts its answer
/// through the same relay.
pub const CLASSIC_REPLY_GROWTH: usize = 1_822;

/// Measures what a caller posts for a send that leaves the wallet as an export: called with
/// the stored S1 as V3 JSON and the wallet's generator, it returns what the relay would get
/// for it. `None` when it goes through no relay.
pub type MeasurePost =
    Arc<dyn Fn(&[u8], &mut (dyn CryptoRng + Send)) -> Option<PostedSize> + Send + Sync>;

/// Stores what a caller keeps for a send it carries itself, in the send's own store
/// transaction once the S1 is stored and measured: called with that transaction, the send and
/// the wallet's generator. A failure rolls the whole send back, so the send and the caller's
/// records are stored together or not at all.
pub type StoreCarried = Arc<
    dyn Fn(
            &mut dyn Repositories,
            CarriedSend<'_>,
            &mut (dyn CryptoRng + Send),
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
        + Send
        + Sync,
>;

/// The send a [`StoreCarried`] stores its records with.
#[derive(Debug, Clone, Copy)]
pub struct CarriedSend<'a> {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The stored S1 as V3 JSON.
    pub v3: &'a [u8],
    /// The time the send is stored at.
    pub now: Timestamp,
}

/// A change output of a send: the key it is derived from and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeOutput {
    pub key_id: Identifier,
    pub amount: Amount,
}

/// Everything an S1 slate is built from once selection has chosen the inputs and the change
/// keys are reserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S1Plan {
    pub account: AccountIndex,
    pub amount: Amount,
    pub fee: Fee,
    /// The chain tip the slate is built at.
    pub height: Height,
    pub lock: KernelLock,
    pub ttl_cutoff_height: Option<Height>,
    pub inputs: Vec<OutputRecord>,
    pub change: Vec<ChangeOutput>,
    pub message: Option<String>,
    pub payment_proof_recipient: Option<ProofAddress>,
}

/// The random values of one S1. [`S1Randomness::draw`] takes them from the wallet's RNG; tests
/// pass the values upstream chose.
#[derive(Debug, Clone)]
pub struct S1Randomness {
    pub slate_id: SlateId,
    /// The kernel offset, split off the sender's excess.
    pub offset: SecretKey,
    /// The sender's signing nonce for the kernel.
    pub nonce: SecretKey,
    /// The nonce of the sender's message signature.
    pub message_nonce: SecretKey,
}

impl S1Randomness {
    pub fn draw(rng: &mut (impl CryptoRng + ?Sized)) -> Result<Self, CryptoError> {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Ok(Self {
            slate_id: SlateId::from_random_bytes(id),
            // Any valid scalar serves as an offset, which is what a nonce draw yields.
            offset: aggsig::create_secnonce(rng)?,
            nonce: aggsig::create_secnonce(rng)?,
            message_nonce: aggsig::create_secnonce(rng)?,
        })
    }
}

/// An S1 slate and the secrets the sender needs to finalize it.
#[derive(Debug)]
pub struct BuiltS1 {
    pub slate: Slate,
    pub(crate) context: SenderContext,
}

/// Builds the S1 slate of `plan`, as `epic-wallet` builds it for `init_send_tx`.
///
/// Fails with [`SendError::InputKeyMismatch`] when an input's stored commitment is not the one
/// its key and value derive, which would make the transaction invalid.
pub fn build_s1(
    keychain: &Keychain,
    plan: &S1Plan,
    randomness: S1Randomness,
) -> Result<BuiltS1, SendError> {
    let mut inputs = Vec::with_capacity(plan.inputs.len());
    let mut spent_keys = Vec::with_capacity(plan.inputs.len().saturating_add(1));
    for record in &plan.inputs {
        let key_id = Identifier::from_bytes(&record.key_id.0)?;
        let key = keychain.derive_key(record.amount.value(), &key_id, SwitchCommitment::Regular)?;
        let commitment = Commitment::commit(record.amount.value(), &key)?;
        if commitment != record.id.commitment {
            return Err(SendError::InputKeyMismatch);
        }
        inputs.push(Input::new(record.id.features, record.id.commitment));
        spent_keys.push(key);
    }

    let builder = ProofBuilder::new(keychain)?;
    let mut outputs = Vec::with_capacity(plan.change.len());
    let mut change_keys = Vec::with_capacity(plan.change.len());
    for change in &plan.change {
        let amount = change.amount.value();
        change_keys.push(keychain.derive_key(amount, &change.key_id, SwitchCommitment::Regular)?);
        outputs.push(create_output(
            keychain,
            &builder,
            amount,
            &change.key_id,
            SwitchCommitment::Regular,
        )?);
    }

    // The offset is split off the excess, so the sender signs with what remains.
    spent_keys.push(randomness.offset.clone());
    let secret_key = SecretKey::sum(&change_keys, &spent_keys)?;
    let public_blind_excess = PublicKey::from_secret_key(&secret_key)?;
    let public_nonce = PublicKey::from_secret_key(&randomness.nonce)?;
    let mut sender = Participant::new(public_blind_excess, public_nonce);
    sender.message = plan
        .message
        .as_deref()
        .map(|text| {
            sign_message(
                text,
                &secret_key,
                &public_blind_excess,
                &randomness.message_nonce,
            )
        })
        .transpose()?;

    let payment_proof = plan
        .payment_proof_recipient
        .map(|receiver_address| payment_proof(keychain, plan.account, receiver_address))
        .transpose()?;

    let (inputs, outputs, _) = TransactionBody::new(inputs, outputs, Vec::new()).into_parts();
    let proposal = Proposal {
        id: randomness.slate_id,
        amount: plan.amount,
        fee: plan.fee,
        height: plan.height,
        lock: plan.lock,
        ttl_cutoff_height: plan.ttl_cutoff_height,
        offset: BlindingFactor::from_secret_key(&randomness.offset),
        inputs,
        outputs,
        payment_proof,
    };
    let slate = Slate::propose(Flow::Standard, proposal, sender)?;
    Ok(BuiltS1 {
        slate,
        context: SenderContext {
            account: plan.account,
            secret_key,
            secret_nonce: randomness.nonce,
            payment_proof_index: plan
                .payment_proof_recipient
                .map(|_| PAYMENT_PROOF_ADDRESS_INDEX),
        },
    })
}

/// The party's message, cut to the length upstream keeps, signed under the party's excess with
/// the BLAKE2b-256 digest of its bytes as the message.
fn sign_message(
    text: &str,
    secret_key: &SecretKey,
    public_key: &PublicKey,
    nonce: &SecretKey,
) -> Result<ParticipantMessage, SendError> {
    let text = ParticipantMessage::truncate(text);
    let mut digest = Blake2b256::default();
    digest.update(text.as_bytes());
    let digest: [u8; 32] = digest.finalize_fixed().into();
    let signature =
        aggsig::sign_single(&Message::from(digest), secret_key, nonce, Some(public_key))?;
    Ok(ParticipantMessage::new(text.to_owned(), signature)?)
}

/// The proof the sender asks for. Its sender address is always the payment-proof key, never
/// the onion key, whatever the transport (ADR 0044).
fn payment_proof(
    keychain: &Keychain,
    account: AccountIndex,
    receiver_address: ProofAddress,
) -> Result<PaymentProof, SendError> {
    let key = keychain.payment_proof_key(
        &account::parent_key_id(account)?,
        PAYMENT_PROOF_ADDRESS_INDEX,
    )?;
    Ok(PaymentProof {
        sender_address: ProofAddress::from_bytes(key.public_key())?,
        receiver_address,
        receiver_signature: None,
    })
}

/// What the sender keeps secret between S1 and S3, sealed in the store under
/// [`SENDER_CONTEXT`].
pub(crate) struct SenderContext {
    pub(crate) account: AccountIndex,
    /// The sender's excess with the offset split off.
    pub(crate) secret_key: SecretKey,
    pub(crate) secret_nonce: SecretKey,
    /// The address index of the payment proof the sender asked for, if any.
    pub(crate) payment_proof_index: Option<u32>,
}

impl std::fmt::Debug for SenderContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SenderContext([redacted])")
    }
}

impl SenderContext {
    const FORMAT_V1: u8 = 1;
    const LEN_V1: usize = 1 + 4 + SecretKey::LEN + SecretKey::LEN + 1 + 4;

    /// Format 1: format byte, account index, secret key, secret nonce, a byte that is 1 when a
    /// payment proof index follows, the index. Integers are big-endian.
    pub(crate) fn to_private(&self) -> PrivateContext {
        let mut bytes = Vec::with_capacity(Self::LEN_V1);
        bytes.push(Self::FORMAT_V1);
        bytes.extend_from_slice(&self.account.0.to_be_bytes());
        bytes.extend_from_slice(self.secret_key.expose_bytes());
        bytes.extend_from_slice(self.secret_nonce.expose_bytes());
        bytes.push(u8::from(self.payment_proof_index.is_some()));
        bytes.extend_from_slice(&self.payment_proof_index.unwrap_or(0).to_be_bytes());
        PrivateContext::new(bytes)
    }

    pub(crate) fn from_private(context: &PrivateContext) -> Result<Self, SendError> {
        let bytes = context.expose();
        let Some((&Self::FORMAT_V1, rest)) = bytes.split_first() else {
            return Err(SendError::MalformedContext);
        };
        let (account, rest) = split_array::<4>(rest)?;
        let (secret_key, rest) = split_array::<{ SecretKey::LEN }>(rest)?;
        let (secret_nonce, rest) = split_array::<{ SecretKey::LEN }>(rest)?;
        let (&flag, rest) = split_array::<1>(rest)?;
        let (&index, rest) = split_array::<4>(rest)?;
        if !rest.is_empty() {
            return Err(SendError::MalformedContext);
        }
        let payment_proof_index = match flag {
            [0] => None,
            [1] => Some(u32::from_be_bytes(index)),
            _ => return Err(SendError::MalformedContext),
        };
        // Read from the borrowed context, so no copy of a key is left behind unwiped.
        let key = |bytes: &[u8; SecretKey::LEN]| {
            SecretKey::from_bytes(bytes).map_err(|_| SendError::MalformedContext)
        };
        Ok(Self {
            account: AccountIndex(u32::from_be_bytes(*account)),
            secret_key: key(secret_key)?,
            secret_nonce: key(secret_nonce)?,
            payment_proof_index,
        })
    }
}

fn split_array<const N: usize>(bytes: &[u8]) -> Result<(&[u8; N], &[u8]), SendError> {
    bytes
        .split_first_chunk::<N>()
        .ok_or(SendError::MalformedContext)
}

/// Block header version at `height` on `network`, which a legacy slate created at that height
/// carries in its header.
pub(crate) const fn block_header_version(network: Network, height: Height) -> u16 {
    let first_hard_fork = match network {
        Network::Mainnet => MAINNET_FIRST_HARD_FORK,
        Network::Floonet => FLOONET_FIRST_HARD_FORK,
    };
    if height.value() < first_hard_fork {
        6
    } else {
        7
    }
}

/// Fails unless `method` can carry `delivery`: deliver for [`Delivery::Deliver`], export for
/// [`Delivery::Export`].
fn check_delivery(method: &dyn Method, delivery: &Delivery) -> Result<(), SendError> {
    match delivery {
        Delivery::Deliver { .. } if method.outbound().is_none() => Err(SendError::CannotDeliver {
            transport: method.id(),
        }),
        Delivery::Export { .. } if method.exchange().is_none() => Err(SendError::CannotExport {
            transport: method.id(),
        }),
        Delivery::Deliver { .. } | Delivery::Export { .. } => Ok(()),
    }
}

/// The S1 as the method sends a new slate, as the method's legacy JSON.
fn encode_for_delivery(
    env: &SendEnvironment<'_>,
    slate: &Slate,
    context: &EncodeContext,
) -> Result<(WireSlate, SlateFormat), SendError> {
    let sending = Sending::new(env.network);
    Ok((
        env.method.encode_new(slate, context, &sending)?.wire,
        SlateFormat::Legacy,
    ))
}

/// What the store transaction of a send produced, for the delivery that follows it.
struct StoredS1 {
    tx_id: TxId,
    slate_id: SlateId,
    amount: Amount,
    fee: Fee,
    wire: WireSlate,
    format: SlateFormat,
    outbox: Option<OutboxId>,
    /// Where the slate must go whatever the caller named: the allowed address of a parked
    /// invoice's payment.
    bound_to: Option<Destination>,
    /// The S1 as stored.
    slate: Slate,
    /// What the relay gets for it, when it goes through one.
    size: Option<PostedSize>,
}

/// What the store transaction of a send or resend runs with, so it needs no `Ports`.
struct SendEnvironment<'a> {
    method: &'a dyn Method,
    network: Network,
    now: Timestamp,
    /// The caller's measure of what it posts, for a send it carries itself.
    measure: Option<(&'a MeasurePost, &'a crate::ports::SharedRng)>,
    /// What the caller stores with a send it carries itself.
    carried: Option<(&'a StoreCarried, &'a crate::ports::SharedRng)>,
    /// Builds the S1 and rolls its store transaction back: nothing is stored.
    dry_run: bool,
    /// The outputs the session found it can spend.
    checked: &'a CheckedOutputs,
}

impl SendEnvironment<'_> {
    fn base_fee(&self) -> Fee {
        self.network.params().default_base_fee()
    }
}

/// `outputs` without the ones the caller excludes and the unspent ones this wallet cannot
/// spend: those whose stored commitment is not the one their key and value derive with the
/// regular switch commitment, the only one a transaction here spends with. A restore stores
/// every output whose proof rewinds, so one created with another switch commitment still
/// counts in the balance; selecting it would only build a transaction that fails.
pub(crate) fn spendable_here(
    keychain: &Keychain,
    checked: &CheckedOutputs,
    outputs: Vec<OutputRecord>,
    exclude: &[Commitment],
) -> Vec<OutputRecord> {
    outputs
        .into_iter()
        .filter(|output| !exclude.contains(&output.id.commitment))
        .filter(|output| {
            if output.status != OutputStatus::Unspent {
                return true;
            }
            let spendable = checked.derives(keychain, output);
            if !spendable {
                debug!(height = %output.height, "output not derived for spending skipped");
            }
            spendable
        })
        .collect()
}

/// `randomness` under the caller's `slate_id`, when there is one and no stored transaction has
/// it, in either direction; else [`SendError::SlateIdTaken`]. The stage caches key by slate id
/// alone, so an id taken in either direction is refused. So is one whose send its receiver
/// declined: the wallet erased that send, but the id stays spent (`sent` is then `None`).
pub(crate) fn under_slate_id(
    repos: &dyn Repositories,
    randomness: S1Randomness,
    slate_id: Option<SlateId>,
) -> Result<S1Randomness, SendError> {
    let Some(slate_id) = slate_id else {
        return Ok(randomness);
    };
    let uuid = Uuid::from_bytes(*slate_id.as_bytes());
    let sent = repos.transaction_by_slate(uuid, TxDirection::Outgoing)?;
    if sent.is_some()
        || repos
            .transaction_by_slate(uuid, TxDirection::Incoming)?
            .is_some()
        || crate::notices::receiver_declined_report(repos, uuid)?.is_some()
    {
        return Err(SendError::SlateIdTaken {
            slate_id,
            sent: sent.map(|tx| tx.id),
        });
    }
    Ok(S1Randomness {
        slate_id,
        ..randomness
    })
}

/// Selects, builds, encodes and stores an S1 in the caller's store transaction. Every failure
/// aborts that transaction, so nothing is stored unless the transport can carry the slate.
fn create_s1(
    repos: &mut dyn Repositories,
    env: &SendEnvironment<'_>,
    keychain: &Keychain,
    tip: Height,
    request: &SendRequest,
    delivery: &Delivery,
    randomness: S1Randomness,
) -> Result<StoredS1, SendError> {
    if repos.account(request.account)?.is_none() {
        return Err(WalletError::from(AccountError::UnknownAccount(request.account)).into());
    }
    // Checked before selection, so a repeat names the first send even once the balance it
    // spent is gone.
    let randomness = under_slate_id(repos, randomness, request.slate_id)?;
    let base_fee = env.base_fee();
    let outputs = spendable_here(
        keychain,
        env.checked,
        repos.outputs(request.account, None)?,
        &request.exclude_outputs,
    );
    let selection = selection::select(
        &outputs,
        &with_spend_confirmations(
            repos,
            request
                .selection_options()
                .request(request.amount, tip, base_fee),
        )?,
    )?;
    if let Some(max_fee) = request.max_fee
        && selection.fee > max_fee
    {
        return Err(SendError::FeeAboveMaximum {
            fee: selection.fee,
            max_fee,
        });
    }
    let inputs = selection.inputs.len();
    let built = store_s1(
        repos,
        keychain,
        &S1Storage {
            network: env.network,
            now: env.now,
            tip,
            transport: env.method.id(),
        },
        request,
        selection,
        randomness,
    )?;
    let (wire, format) = encode_for_delivery(env, &built.slate, &built.encode_context)?;
    let size = post_size(&*repos, env, delivery, built.slate.id(), &wire, format)?;
    if let Some(size) = size
        && !size.fits()
    {
        return Err(SendError::SlateTooLarge {
            bytes: size.bytes,
            limit: size.limit,
            inputs,
        });
    }
    record_counterparty(repos, built.tx_id, delivery)?;
    let slate_uuid = Uuid::from_bytes(*built.slate.id().as_bytes());
    let outbox = enqueue_delivery(repos, env.method.id(), delivery, slate_uuid, env.now)?;
    if let Some((store, rng)) = env.carried {
        let stored =
            repos
                .slate(slate_uuid, SlateStage::Standard1)?
                .ok_or(StoreError::NotFound {
                    record: Record::Slate,
                })?;
        let send = CarriedSend {
            tx_id: built.tx_id,
            slate_id: built.slate.id(),
            v3: &stored.bytes,
            now: env.now,
        };
        store(repos, send, &mut **rng.lock()).map_err(SendError::Carried)?;
    }
    Ok(StoredS1 {
        tx_id: built.tx_id,
        slate_id: built.slate.id(),
        amount: built.plan_amount,
        fee: built.plan_fee,
        wire,
        format,
        outbox,
        bound_to: None,
        slate: built.slate,
        size,
    })
}

/// What the relay gets for the S1 of a send, or for the stock receiver's answer to it when
/// that is longer: the caller's measure for a send it carries itself, else the method's.
fn post_size(
    repos: &dyn Repositories,
    env: &SendEnvironment<'_>,
    delivery: &Delivery,
    slate_id: SlateId,
    wire: &WireSlate,
    format: SlateFormat,
) -> Result<Option<PostedSize>, SendError> {
    if let Some((measure, rng)) = env.measure {
        let uuid = Uuid::from_bytes(*slate_id.as_bytes());
        let Some(stored) = repos.slate(uuid, SlateStage::Standard1)? else {
            return Ok(None);
        };
        return Ok(measure(&stored.bytes, &mut **rng.lock()));
    }
    let to = match delivery {
        Delivery::Deliver { to } => Some(to),
        Delivery::Export { .. } => None,
    };
    Ok(wire_size(env.method, to, wire, format))
}

/// What the relay of `method` gets for `wire` posted to `to`, or for the stock receiver's
/// answer to a legacy slate when that is longer; with no `to`, the answer alone. `None` when
/// the method posts through no relay.
pub(crate) fn wire_size(
    method: &dyn Method,
    to: Option<&Destination>,
    wire: &WireSlate,
    format: SlateFormat,
) -> Option<PostedSize> {
    let outbound = method.outbound()?;
    let len = wire.as_text()?.len();
    let posted = to.and_then(|to| outbound.posted_size(to, len));
    let answer = match format {
        SlateFormat::Legacy => outbound.reply_size(len.saturating_add(CLASSIC_REPLY_GROWTH)),
        SlateFormat::Native => None,
    };
    match (posted, answer) {
        (Some(posted), Some(answer)) => Some(if answer.bytes > posted.bytes {
            answer
        } else {
            posted
        }),
        (posted, answer) => posted.or(answer),
    }
}

/// Creates the S1 of `request` in one store transaction, as [`create_s1`] does. When the
/// format the S1 goes out in cannot carry a TTL, the legacy V2 shape a stock Epicbox or HTTP
/// receiver gets, the transaction is rolled back and the S1 is built again without the slate
/// TTL: its cutoff becomes the send's local cutoff, the earlier one when the request has both,
/// which this wallet enforces as it enforces [`SendRequest::local_ttl_blocks`]. A format that
/// carries a TTL gets it in the slate as before.
fn write_s1<D: WalletStore>(
    store: &D,
    env: &SendEnvironment<'_>,
    keychain: &Keychain,
    tip: Height,
    request: &SendRequest,
    delivery: &Delivery,
    randomness: S1Randomness,
) -> Result<StoredS1, SendError> {
    let Some(ttl_blocks) = request.ttl_blocks else {
        return write_or_try(store, env.dry_run, |repos| {
            create_s1(repos, env, keychain, tip, request, delivery, randomness)
        });
    };
    let first = write_or_try(store, env.dry_run, |repos| {
        create_s1(
            repos,
            env,
            keychain,
            tip,
            request,
            delivery,
            randomness.clone(),
        )
    });
    match first {
        Err(SendError::Unrepresentable(EncodeError::Unrepresentable {
            codec,
            what: Unrepresentable::TimeToLive,
        })) => {
            let local = SendRequest {
                ttl_blocks: None,
                local_ttl_blocks: Some(
                    request
                        .local_ttl_blocks
                        .map_or(ttl_blocks, |local| local.min(ttl_blocks)),
                ),
                ..request.clone()
            };
            debug!(%codec, "ttl kept as a local cutoff");
            write_or_try(store, env.dry_run, |repos| {
                create_s1(repos, env, keychain, tip, &local, delivery, randomness)
            })
        }
        other => other,
    }
}

/// How a dry run's store transaction ended: rolled back either way.
enum Tried {
    Built(Box<StoredS1>),
    Failed(SendError),
}

impl From<StoreError> for Tried {
    fn from(error: StoreError) -> Self {
        Self::Failed(error.into())
    }
}

/// Runs `create` in one store transaction, or, for a dry run, rolls the transaction back and
/// returns what it built.
fn write_or_try<D: WalletStore>(
    store: &D,
    dry_run: bool,
    create: impl FnOnce(&mut dyn Repositories) -> Result<StoredS1, SendError>,
) -> Result<StoredS1, SendError> {
    if !dry_run {
        return store.write(create);
    }
    let tried = store.write::<std::convert::Infallible, Tried>(|repos| match create(repos) {
        Ok(stored) => Err(Tried::Built(Box::new(stored))),
        Err(error) => Err(Tried::Failed(error)),
    });
    match tried {
        Ok(never) => match never {},
        Err(Tried::Built(stored)) => Ok(*stored),
        Err(Tried::Failed(error)) => Err(error),
    }
}

/// What an S1 is stored with, apart from the request and its selection.
pub(crate) struct S1Storage {
    pub(crate) network: Network,
    pub(crate) now: Timestamp,
    /// The chain tip the slate is built at.
    pub(crate) tip: Height,
    /// Recorded on the transaction entry.
    pub(crate) transport: TransportId,
}

/// An S1 stored by [`store_s1`].
pub(crate) struct BuiltAndStored {
    pub(crate) tx_id: TxId,
    pub(crate) slate: Slate,
    pub(crate) encode_context: EncodeContext,
    plan_amount: Amount,
    plan_fee: Fee,
}

/// Builds the S1 of `request` with the inputs and change of `selection` and stores it in the
/// caller's store transaction: the outgoing entry, the inputs locked by it, the change as
/// unconfirmed outputs, the sender's private context, the slate itself and the request's local
/// cutoff.
pub(crate) fn store_s1(
    repos: &mut dyn Repositories,
    keychain: &Keychain,
    storage: &S1Storage,
    request: &SendRequest,
    selection: Selection,
    randomness: S1Randomness,
) -> Result<BuiltAndStored, SendError> {
    let tip = storage.tip;
    let base_fee = storage.network.params().default_base_fee();
    let change = selection
        .change
        .iter()
        .map(|&amount| {
            Ok(ChangeOutput {
                key_id: next_output_key(repos, request.account)?,
                amount,
            })
        })
        .collect::<Result<Vec<_>, SendError>>()?;
    let ttl_cutoff_height = request
        .ttl_blocks
        .map(|blocks| tip.checked_add_blocks(blocks))
        .transpose()?;
    let local_cutoff = request
        .local_ttl_blocks
        .map(|blocks| tip.checked_add_blocks(blocks))
        .transpose()?;
    let plan = S1Plan {
        account: request.account,
        amount: request.amount,
        fee: selection.fee,
        height: tip,
        lock: request.lock,
        ttl_cutoff_height,
        inputs: selection.inputs,
        change,
        message: request.message.clone(),
        payment_proof_recipient: request.payment_proof_recipient,
    };
    let built = build_s1(keychain, &plan, randomness)?;
    let encode_context = EncodeContext {
        block_header_version: block_header_version(storage.network, tip),
    };
    // Stored as V3, which carries every field, with the header of a slate created here; a
    // later delivery re-encodes it for its transport.
    let stored = V3JsonCodec::new(base_fee)
        .encode(&built.slate, &encode_context)
        .map_err(SendError::Unrepresentable)?;

    let slate_id = built.slate.id();
    let slate_uuid = Uuid::from_bytes(*slate_id.as_bytes());
    let total_change = plan.change.iter().try_fold(Amount::ZERO, |total, change| {
        total.checked_add(change.amount)
    })?;
    let tx_id = repos.insert_transaction(&TransactionEntry {
        account: request.account,
        direction: TxDirection::Outgoing,
        state: TxState::Sent,
        slate_id: Some(slate_uuid),
        transport: Some(storage.transport.as_str().to_owned()),
        amount_credited: total_change,
        amount_debited: selection.total,
        fee: Some(selection.fee),
        created_at: storage.now,
        updated_at: storage.now,
    })?;
    record_local_cutoff(repos, tx_id, local_cutoff)?;
    for input in &plan.inputs {
        repos.put_output(&OutputRecord {
            status: OutputStatus::Locked,
            tx: Some(tx_id),
            ..input.clone()
        })?;
    }
    for change in &plan.change {
        let commitment = keychain.commit(
            change.amount.value(),
            &change.key_id,
            SwitchCommitment::Regular,
        )?;
        repos.insert_output(&OutputRecord {
            id: OutputIdentifier::new(OutputFeatures::Plain, commitment),
            key_id: KeyId(change.key_id.to_bytes()),
            account: request.account,
            amount: change.amount,
            status: OutputStatus::Unconfirmed,
            height: tip,
            lock_height: Height::ZERO,
            mmr_index: None,
            tx: Some(tx_id),
        })?;
    }
    repos.put_context(slate_uuid, SENDER_CONTEXT, &built.context.to_private())?;
    repos.insert_slate(&StoredSlate {
        slate_id: slate_uuid,
        stage: SlateStage::Standard1,
        codec: LEGACY_V3_JSON.as_str().to_owned(),
        bytes: stored.as_bytes().to_vec(),
    })?;
    Ok(BuiltAndStored {
        tx_id,
        slate: built.slate,
        encode_context,
        plan_amount: plan.amount,
        plan_fee: plan.fee,
    })
}

/// Records where a delivered slate goes as the transaction's counterparty. An export has no
/// address to record.
pub(crate) fn record_counterparty(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    delivery: &Delivery,
) -> Result<(), StoreError> {
    match delivery {
        Delivery::Deliver { to } => repos.set_counterparty(tx_id, to.as_str()),
        Delivery::Export { .. } => Ok(()),
    }
}

/// Records a delivery over `transport` to a destination in the outbox, reusing a pending entry
/// for the same slate and destination. Exports have no destination to record.
fn enqueue_delivery(
    repos: &mut dyn Repositories,
    transport: TransportId,
    delivery: &Delivery,
    slate_id: Uuid,
    now: Timestamp,
) -> Result<Option<OutboxId>, SendError> {
    let Delivery::Deliver { to } = delivery else {
        return Ok(None);
    };
    let pending = repos
        .outbox(OutboxStatus::Pending)?
        .into_iter()
        .find(|stored| {
            stored.entry.slate_id == slate_id
                && stored.entry.stage == SlateStage::Standard1
                && stored.entry.transport == transport.as_str()
                && stored.entry.destination == to.as_str()
        });
    if let Some(pending) = pending {
        return Ok(Some(pending.id));
    }
    Ok(Some(repos.enqueue_outbox(&OutboxEntry {
        transport: transport.as_str().to_owned(),
        destination: to.as_str().to_owned(),
        slate_id,
        stage: SlateStage::Standard1,
        status: OutboxStatus::Pending,
        attempts: 0,
        created_at: now,
        updated_at: now,
    })?))
}

/// Counts a delivery attempt on the outbox entry. Once the slate is delivered, the entry is
/// marked delivered and other pending deliveries of the same slate are dropped.
fn record_attempt(
    repos: &mut dyn Repositories,
    outbox: OutboxId,
    delivered: bool,
    now: Timestamp,
) -> Result<(), SendError> {
    let pending = repos.outbox(OutboxStatus::Pending)?;
    let Some(mut attempted) = pending.iter().find(|stored| stored.id == outbox).cloned() else {
        return Ok(());
    };
    attempted.entry.attempts = attempted.entry.attempts.saturating_add(1);
    attempted.entry.updated_at = now;
    if delivered {
        attempted.entry.status = OutboxStatus::Delivered;
        for other in &pending {
            if other.id != outbox
                && other.entry.slate_id == attempted.entry.slate_id
                && other.entry.stage == attempted.entry.stage
            {
                repos.delete_outbox(other.id)?;
            }
        }
    }
    Ok(repos.update_outbox(outbox, &attempted.entry)?)
}

/// Puts the delivery of the S1 of `tx_id` over `transport` back to pending. Leaves the outbox
/// as it is when the transaction is no longer an outgoing send in state `sent`, or a delivery
/// of its S1 is pending already.
fn record_undelivered(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    transport: TransportId,
    now: Timestamp,
) -> Result<(), WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let (TxDirection::Outgoing, TxState::Sent, Some(slate_uuid)) =
        (entry.direction, entry.state, entry.slate_id)
    else {
        return Ok(());
    };
    let of_slate = |stored: &StoredOutbox| {
        stored.entry.slate_id == slate_uuid && stored.entry.stage == SlateStage::Standard1
    };
    if repos.outbox(OutboxStatus::Pending)?.iter().any(of_slate) {
        return Ok(());
    }
    let delivered = repos
        .outbox(OutboxStatus::Delivered)?
        .into_iter()
        .filter(|stored| of_slate(stored) && stored.entry.transport == transport.as_str())
        .max_by_key(|stored| stored.entry.updated_at);
    let Some(mut delivered) = delivered else {
        return Ok(());
    };
    delivered.entry.status = OutboxStatus::Pending;
    delivered.entry.updated_at = now;
    Ok(repos.update_outbox(delivered.id, &delivered.entry)?)
}

/// The slate id of `tx_id` while it is a send waiting for its answer.
fn waiting_send(repos: &dyn Repositories, tx_id: TxId) -> Result<Uuid, SendError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let (TxDirection::Outgoing, TxState::Sent, Some(slate_uuid)) =
        (entry.direction, entry.state, entry.slate_id)
    else {
        return Err(SendError::NotResendable { tx_id });
    };
    Ok(slate_uuid)
}

/// The stored S1 of `slate_uuid`, encoded again; `None` when the send stored no plain S1.
fn encode_stored_s1(
    repos: &dyn Repositories,
    env: &SendEnvironment<'_>,
    tx_id: TxId,
    slate_uuid: Uuid,
) -> Result<Option<(Slate, WireSlate, SlateFormat)>, SendError> {
    let Some(stored) = repos
        .slate(slate_uuid, SlateStage::Standard1)?
        .filter(|stored| stored.codec == LEGACY_V3_JSON.as_str())
    else {
        return Ok(None);
    };
    let base_fee = env.base_fee();
    let slate = V3JsonCodec::new(base_fee)
        .decode(&WireSlate::binary(MediaType::JSON, stored.bytes))
        .map_err(SendError::StoredSlate)?;
    if slate.stage() != Stage::S1 {
        return Err(SendError::NotResendable { tx_id });
    }
    let block_header_version = slate
        .origin()
        .and_then(WireOrigin::legacy_header)
        .map_or_else(
            || block_header_version(env.network, slate.height()),
            |header| header.block_header_version,
        );
    let slate = slate.with_origin(None);
    let (wire, format) = encode_for_delivery(
        env,
        &slate,
        &EncodeContext {
            block_header_version,
        },
    )?;
    Ok(Some((slate, wire, format)))
}

/// The stored S1 of a transaction waiting for delivery, encoded for `delivery`.
fn stored_s1_for_delivery(
    repos: &mut dyn Repositories,
    env: &SendEnvironment<'_>,
    tx_id: TxId,
    delivery: &Delivery,
) -> Result<StoredS1, SendError> {
    let slate_uuid = waiting_send(&*repos, tx_id)?;
    // A slate exchanged with a paired contact goes again only through its outbox, sealed.
    if matches!(delivery, Delivery::Deliver { .. })
        && crate::contact_link::slate_contact(repos, slate_uuid)?.is_some()
    {
        return Err(SendError::NotResendable { tx_id });
    }
    let Some((slate, wire, format)) = encode_stored_s1(&*repos, env, tx_id, slate_uuid)? else {
        return stored_i2_for_delivery(repos, env, tx_id, slate_uuid, delivery);
    };
    let outbox = enqueue_delivery(repos, env.method.id(), delivery, slate_uuid, env.now)?;
    record_counterparty(repos, tx_id, delivery)?;
    Ok(StoredS1 {
        tx_id,
        slate_id: slate.id(),
        amount: slate.amount(),
        fee: slate.fee(),
        wire,
        format,
        outbox,
        bound_to: None,
        slate,
        size: None,
    })
}

/// Whether `delivery` goes over `method` to the peer of the address `allowed`.
fn same_payee(
    method: &dyn Method,
    network: Network,
    delivery: &Delivery,
    allowed: Option<&str>,
) -> bool {
    let Delivery::Deliver { to } = delivery else {
        return false;
    };
    allowed.is_some_and(|allowed| method.same_payee(network, to, allowed))
}

/// The stored I2 of an invoice payment, as it was encoded for its first delivery. It was
/// encoded by the reply rule of the method the invoice came over, which gave it the shape of
/// the I1, so it goes out unchanged.
fn stored_i2_for_delivery(
    repos: &mut dyn Repositories,
    env: &SendEnvironment<'_>,
    tx_id: TxId,
    slate_uuid: Uuid,
    delivery: &Delivery,
) -> Result<StoredS1, SendError> {
    let stored = repos
        .slate(slate_uuid, SlateStage::Invoice2)?
        .ok_or(SendError::NotResendable { tx_id })?;
    let wire = WireSlate::binary(MediaType::JSON, stored.bytes);
    let slate = codecs::legacy(env.base_fee())
        .decode(&wire)
        .map_err(SendError::StoredSlate)?;
    if slate.stage() != Stage::I2 {
        return Err(SendError::NotResendable { tx_id });
    }
    let bound_to = if repos.pending_invoice(slate_uuid)?.is_some() {
        // A parked invoice is paid only to the address the user allowed, recorded when it was
        // paid; the recorded address also decides whose notices count for the payment. The
        // caller's address may name the same key under another domain, which the relay does
        // not authenticate, so the recorded one is used.
        let allowed = repos.counterparty(tx_id)?;
        if !same_payee(env.method, env.network, delivery, allowed.as_deref()) {
            return Err(SendError::PayeeMismatch { tx_id });
        }
        allowed.map(Destination::new)
    } else {
        record_counterparty(repos, tx_id, delivery)?;
        None
    };
    Ok(StoredS1 {
        tx_id,
        slate_id: slate.id(),
        amount: slate.amount(),
        fee: slate.fee(),
        wire,
        format: SlateFormat::Legacy,
        outbox: None,
        bound_to,
        slate,
        size: None,
    })
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Sends `request.amount` from `request.account`: builds the S1 slate, stores it with its
    /// inputs locked, then delivers it as `delivery` says, encoded with that transport's format
    /// policy. A `request.local_ttl_blocks` is stored as a height past the tip, after which
    /// [`Wallet::finalize`] and [`Wallet::post`] refuse the send and a refresh expires it if
    /// it is unanswered.
    ///
    /// Fails, with nothing stored, with [`SendError::Wallet`] carrying [`WalletError::Locked`]
    /// when the wallet is locked, [`SendError::Node`] when the chain tip is unavailable,
    /// [`SendError::CannotDeliver`] or [`SendError::CannotExport`], a
    /// [`SendError::Selection`] error, or [`SendError::Unrepresentable`] when the transport's
    /// format cannot carry the slate. A send with change fails with
    /// [`WalletError::RestoreScanRequired`] on a database rebuilt from the seed before a scan
    /// from genesis completed. Fails with [`SendError::Undelivered`] when the slate was
    /// stored but the transport failed; the transaction then waits for
    /// [`Wallet::resend`] or [`Wallet::cancel`]. Fails with [`SendError::SlateTooLarge`], with
    /// nothing stored, when the relay would get more than it takes for the S1 or for the
    /// stock receiver's answer to it.
    pub async fn send(
        &self,
        method: &Arc<dyn Method>,
        request: SendRequest,
        delivery: Delivery,
    ) -> Result<SentSlate, SendError> {
        self.send_carried(method, request, delivery, None, None)
            .await
    }

    /// Sends as [`Wallet::send`] does. With `measure`, the slate is one the caller posts itself
    /// after the send, measured by `measure` against the relay's limit instead of by `method`.
    pub async fn send_measured(
        &self,
        method: &Arc<dyn Method>,
        request: SendRequest,
        delivery: Delivery,
        measure: Option<MeasurePost>,
    ) -> Result<SentSlate, SendError> {
        self.send_carried(method, request, delivery, measure, None)
            .await
    }

    /// Sends as [`Wallet::send_measured`] does. With `carried`, what the caller keeps for the
    /// send is stored in the send's own store transaction, so a stop between the two leaves
    /// neither. Fails with [`SendError::Carried`], nothing stored, when `carried` fails.
    #[instrument(name = "send", skip_all, fields(
        wallet = %self.config().name,
        transport = %method.id(),
        stage = %Stage::S1,
        tx_id = Empty,
        slate_id = Empty,
    ))]
    pub async fn send_carried(
        &self,
        method: &Arc<dyn Method>,
        request: SendRequest,
        delivery: Delivery,
        measure: Option<MeasurePost>,
        carried: Option<StoreCarried>,
    ) -> Result<SentSlate, SendError> {
        let session = self.session()?;
        check_delivery(&**method, &delivery)?;
        let (tip, _) = self.stage_tip(&session, SendError::Node).await?;
        let target = delivery.clone();
        let carrier = Arc::clone(method);
        let stored = self
            .blocking(move |ports, config| {
                let env = SendEnvironment {
                    method: &*carrier,
                    network: config.network,
                    now: ports.clock.now(),
                    measure: measure.as_ref().map(|measure| (measure, &ports.rng)),
                    carried: carried.as_ref().map(|carried| (carried, &ports.rng)),
                    dry_run: false,
                    checked: &session.checked,
                };
                let randomness = S1Randomness::draw(&mut **ports.rng.lock());
                Ok(randomness.map_err(SendError::from).and_then(|randomness| {
                    write_s1(
                        &session.store,
                        &env,
                        &session.keychain,
                        tip,
                        &request,
                        &target,
                        randomness,
                    )
                }))
            })
            .await??;
        let span = Span::current();
        span.record("tx_id", stored.tx_id.0);
        span.record("slate_id", tracing::field::display(stored.slate_id));
        info!("slate created");
        self.deliver(&**method, &stored, &delivery).await?;
        Ok(SentSlate {
            tx_id: stored.tx_id,
            slate_id: stored.slate_id,
            amount: stored.amount,
            fee: stored.fee,
            format: stored.format,
            slate_bytes: stored.size.map(|size| size.bytes),
            slate_limit: stored.size.map(|size| size.limit),
        })
    }

    /// What the relay of `method` would get for a send of `request` to `to`, or for the stock
    /// receiver's answer to it when that is longer, and the relay's limit: the S1 is built as
    /// [`Wallet::send`] builds it, measured, and dropped, with nothing locked, derived or
    /// stored. With no `to`, only the answer is measured, sealed to this wallet's address.
    /// `None` when `method` posts through no relay or has no identity attached.
    ///
    /// Fails as [`Wallet::send`] fails before it stores anything, with
    /// [`SendError::SlateTooLarge`] when the slate or the answer is longer than the relay
    /// takes.
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = %method.id()))]
    pub async fn estimate_slate_size(
        &self,
        method: &Arc<dyn Method>,
        request: SendRequest,
        to: Option<Destination>,
    ) -> Result<Option<PostedSize>, SendError> {
        if method.outbound().is_none() {
            return Ok(None);
        }
        let session = self.session()?;
        let (tip, _) = self.stage_tip(&session, SendError::Node).await?;
        // A send that names no address is measured as an export: the S1 goes out as legacy
        // JSON and the answer comes back through the relay.
        let delivery = to.map_or_else(
            || Delivery::Export {
                to: Location::File(std::path::PathBuf::new()),
            },
            |to| Delivery::Deliver { to },
        );
        let carrier = Arc::clone(method);
        let stored = self
            .blocking(move |ports, config| {
                let env = SendEnvironment {
                    method: &*carrier,
                    network: config.network,
                    now: ports.clock.now(),
                    measure: None,
                    carried: None,
                    dry_run: true,
                    checked: &session.checked,
                };
                let randomness = S1Randomness::draw(&mut **ports.rng.lock());
                Ok(randomness.map_err(SendError::from).and_then(|randomness| {
                    write_s1(
                        &session.store,
                        &env,
                        &session.keychain,
                        tip,
                        &request,
                        &delivery,
                        randomness,
                    )
                }))
            })
            .await??;
        debug!(bytes = ?stored.size.map(|size| size.bytes), "slate size estimated");
        Ok(stored.size)
    }

    /// Builds and stores a send as [`Wallet::send`] does, encoded for `method` and recording
    /// the destination of `delivery`, without delivering it: the caller carries the S1, which
    /// is returned with what was stored.
    ///
    /// Fails as [`Wallet::send`] fails before it delivers.
    pub async fn send_unsent(
        &self,
        method: &Arc<dyn Method>,
        request: SendRequest,
        delivery: Delivery,
    ) -> Result<(SentSlate, Slate), SendError> {
        let session = self.session()?;
        check_delivery(&**method, &delivery)?;
        let (tip, _) = self.stage_tip(&session, SendError::Node).await?;
        let carrier = Arc::clone(method);
        let stored = self
            .blocking(move |ports, config| {
                let env = SendEnvironment {
                    method: &*carrier,
                    network: config.network,
                    now: ports.clock.now(),
                    measure: None,
                    carried: None,
                    dry_run: false,
                    checked: &session.checked,
                };
                let randomness = S1Randomness::draw(&mut **ports.rng.lock());
                Ok(randomness.map_err(SendError::from).and_then(|randomness| {
                    write_s1(
                        &session.store,
                        &env,
                        &session.keychain,
                        tip,
                        &request,
                        &delivery,
                        randomness,
                    )
                }))
            })
            .await??;
        info!(tx_id = %stored.tx_id, slate_id = %stored.slate_id, "slate created");
        Ok((
            SentSlate {
                tx_id: stored.tx_id,
                slate_id: stored.slate_id,
                amount: stored.amount,
                fee: stored.fee,
                format: stored.format,
                slate_bytes: stored.size.map(|size| size.bytes),
                slate_limit: stored.size.map(|size| size.limit),
            },
            stored.slate,
        ))
    }

    /// Delivers the stored S1 of a transaction whose delivery failed, through `delivery`, which
    /// may name another transport than the first attempt, and returns the format it went out
    /// in. For an invoice payment, delivers its stored I2 as it was first encoded; the payment
    /// of a parked invoice goes to the recorded allowed address, whatever domain `delivery`
    /// names for its key.
    ///
    /// Fails with [`SendError::Wallet`] carrying [`WalletError::UnknownTransaction`],
    /// [`SendError::NotResendable`] when the
    /// transaction is not an outgoing one in state `sent`, [`SendError::PayeeMismatch`] when the
    /// payment of a parked invoice would go anywhere but its sender's allowed address over
    /// Epicbox, the transport errors of [`Wallet::send`], or [`SendError::Undelivered`] when
    /// the transport fails again.
    #[instrument(skip_all, fields(
        wallet = %self.config().name,
        transport = %method.id(),
        stage = %Stage::S1,
        tx_id = %tx_id,
        slate_id = Empty,
    ))]
    pub async fn resend(
        &self,
        method: &Arc<dyn Method>,
        tx_id: TxId,
        delivery: Delivery,
    ) -> Result<SlateFormat, SendError> {
        let session = self.session()?;
        check_delivery(&**method, &delivery)?;
        let target = delivery.clone();
        let carrier = Arc::clone(method);
        let stored = self
            .blocking(move |ports, config| {
                let env = SendEnvironment {
                    method: &*carrier,
                    network: config.network,
                    now: ports.clock.now(),
                    measure: None,
                    carried: None,
                    dry_run: false,
                    checked: &session.checked,
                };
                Ok(session
                    .store
                    .write(|repos| stored_s1_for_delivery(repos, &env, tx_id, &target)))
            })
            .await??;
        Span::current().record("slate_id", tracing::field::display(stored.slate_id));
        let delivery = match &stored.bound_to {
            Some(to) => Delivery::Deliver { to: to.clone() },
            None => delivery,
        };
        self.deliver(&**method, &stored, &delivery).await?;
        Ok(stored.format)
    }

    /// The S1 of the send `tx_id` as [`Wallet::resend`] exports it over `method` while the send
    /// waits for its answer. Stores nothing.
    ///
    /// Fails with [`SendError::Wallet`] carrying [`WalletError::UnknownTransaction`], or
    /// [`SendError::NotResendable`] when the transaction is not an outgoing one in state `sent`
    /// or stored no plain S1.
    pub async fn sent_slate(
        &self,
        method: &Arc<dyn Method>,
        tx_id: TxId,
    ) -> Result<WireSlate, SendError> {
        let session = self.session()?;
        let method = Arc::clone(method);
        self.blocking(move |ports, config| {
            let env = SendEnvironment {
                method: &*method,
                network: config.network,
                now: ports.clock.now(),
                measure: None,
                carried: None,
                dry_run: false,
                checked: &session.checked,
            };
            Ok(session.store.read(|repos| {
                let slate_uuid = waiting_send(repos, tx_id)?;
                encode_stored_s1(repos, &env, tx_id, slate_uuid)?
                    .map(|(_, wire, _)| wire)
                    .ok_or(SendError::NotResendable { tx_id })
            }))
        })
        .await?
    }

    /// Records that the S1 of `tx_id`, which `transport` took as delivered, did not reach its
    /// peer: the send shows as waiting for delivery again, for [`Wallet::resend`] or
    /// [`Wallet::cancel`]. For a carrier that only hands the slate on, whose own delivery
    /// fails afterwards. Does nothing when the transaction is no longer an outgoing send in
    /// state `sent` or a delivery of its S1 is pending already.
    ///
    /// Fails with [`WalletError::Locked`] when the wallet is locked and
    /// [`WalletError::UnknownTransaction`].
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = %transport, tx_id = %tx_id))]
    pub async fn record_undelivered(
        &self,
        tx_id: TxId,
        transport: TransportId,
    ) -> Result<(), WalletError> {
        let session = self.session()?;
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session
                .store
                .write(|repos| record_undelivered(repos, tx_id, transport, now))
        })
        .await
    }

    /// Hands the wire slate to `method`, then records the attempt in the outbox. A store
    /// failure while recording is logged and not returned, because the slate already left.
    async fn deliver(
        &self,
        method: &dyn Method,
        stored: &StoredS1,
        delivery: &Delivery,
    ) -> Result<(), SendError> {
        let outcome = match (delivery, method.outbound(), method.exchange()) {
            (Delivery::Deliver { to }, Some(outbound), _) => {
                // An S1 is filed under a fresh relay transaction id; a slate delivered again
                // keeps the id it was filed under.
                let fresh = stored.slate.stage() == Stage::S1;
                match self.relay_txid_for(outbound, stored.slate_id, fresh).await {
                    Ok(txid) => outbound.deliver_tx(to, &stored.wire, txid.as_ref()).await,
                    Err(RelayTxIdError::Transport(source)) => Err(source),
                    Err(RelayTxIdError::Wallet(error)) => return Err(error.into()),
                }
            }
            (Delivery::Export { to }, _, Some(exchange)) => exchange.export(&stored.wire, to).await,
            (Delivery::Deliver { .. }, None, _) => {
                return Err(SendError::CannotDeliver {
                    transport: method.id(),
                });
            }
            (Delivery::Export { .. }, _, None) => {
                return Err(SendError::CannotExport {
                    transport: method.id(),
                });
            }
        };
        if let Some(outbox) = stored.outbox {
            let session = self.session()?;
            let delivered = outcome.is_ok();
            let recorded = self
                .blocking(move |ports, _| {
                    let now = ports.clock.now();
                    Ok(session
                        .store
                        .write(|repos| record_attempt(repos, outbox, delivered, now)))
                })
                .await
                .map_err(SendError::from)
                .and_then(|recorded| recorded);
            if let Err(error) = recorded {
                warn!(error = %error, "delivery attempt not recorded");
            }
        }
        match outcome {
            Ok(()) => {
                info!("slate sent");
                Ok(())
            }
            Err(source) if method.delivery_cancelled_on_relay(&source) => {
                info!("slate refused, the transaction was cancelled on the relay");
                self.cancelled_on_relay(stored.slate_id).await;
                Err(SendError::CancelledOnRelay {
                    tx_id: stored.tx_id,
                    slate_id: stored.slate_id,
                })
            }
            Err(source) => Err(SendError::Undelivered {
                tx_id: stored.tx_id,
                slate_id: stored.slate_id,
                source,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use lepic_legacy_slate::v2_json::V2JsonCodec;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    #[test]
    fn sender_context_round_trips_through_its_sealed_form() {
        for payment_proof_index in [None, Some(0), Some(u32::MAX)] {
            let context = SenderContext {
                account: AccountIndex(7),
                secret_key: key(3),
                secret_nonce: key(4),
                payment_proof_index,
            };
            let read = SenderContext::from_private(&context.to_private()).unwrap();
            assert_eq!(read.account, AccountIndex(7));
            assert_eq!(read.secret_key.expose_bytes(), &[3; 32]);
            assert_eq!(read.secret_nonce.expose_bytes(), &[4; 32]);
            assert_eq!(read.payment_proof_index, payment_proof_index);
        }
    }

    #[test]
    fn rejects_a_malformed_sender_context() {
        let good = SenderContext {
            account: AccountIndex(0),
            secret_key: key(3),
            secret_nonce: key(4),
            payment_proof_index: None,
        }
        .to_private();
        let mut unknown_format = good.expose().to_vec();
        unknown_format[0] = 2;
        let mut bad_flag = good.expose().to_vec();
        bad_flag[SenderContext::LEN_V1 - 5] = 2;
        let mut zero_key = good.expose().to_vec();
        zero_key[5..37].fill(0);
        let mut long = good.expose().to_vec();
        long.push(0);
        for bytes in [
            Vec::new(),
            good.expose()[..SenderContext::LEN_V1 - 1].to_vec(),
            unknown_format,
            bad_flag,
            zero_key,
            long,
        ] {
            assert!(matches!(
                SenderContext::from_private(&PrivateContext::new(bytes)),
                Err(SendError::MalformedContext)
            ));
        }
    }

    #[test]
    fn sender_context_debug_is_redacted() {
        let context = SenderContext {
            account: AccountIndex(0),
            secret_key: key(3),
            secret_nonce: key(4),
            payment_proof_index: None,
        };
        assert_eq!(format!("{context:?}"), "SenderContext([redacted])");
    }

    #[test]
    fn header_version_changes_at_each_networks_first_hard_fork() {
        for (network, fork) in [
            (Network::Mainnet, MAINNET_FIRST_HARD_FORK),
            (Network::Floonet, FLOONET_FIRST_HARD_FORK),
        ] {
            assert_eq!(block_header_version(network, Height::new(0)), 6);
            assert_eq!(block_header_version(network, Height::new(fork - 1)), 6);
            assert_eq!(block_header_version(network, Height::new(fork)), 7);
        }
    }

    #[test]
    fn drawn_randomness_gives_a_version_4_slate_id() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let drawn = S1Randomness::draw(&mut rng).unwrap();
        assert_eq!(drawn.slate_id.to_string().as_bytes()[14], b'4');
    }

    #[test]
    fn the_classic_reply_growth_is_what_the_stock_receiver_adds_in_the_vectors() {
        let json = |vector: &str| {
            let vector: serde_json::Value = serde_json::from_str(vector).unwrap();
            vector["expected"]["json"].as_str().unwrap().len()
        };
        let s1 = json(include_str!(
            "../../../testdata/vectors/slates/send_epicbox_plain_s1_v2.json"
        ));
        let s2 = json(include_str!(
            "../../../testdata/vectors/slates/send_epicbox_plain_s2_v2.json"
        ));
        assert_eq!(s2 - s1, CLASSIC_REPLY_GROWTH);
    }

    /// The S1 of the plain-send vector.
    fn vector_s1() -> Slate {
        let base_fee = Network::Floonet.params().default_base_fee();
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/vectors/slates/send_epicbox_plain_s1_v2.json"
        ))
        .unwrap();
        let json = vector["expected"]["json"].as_str().unwrap().to_owned();
        V2JsonCodec::new(base_fee)
            .decode(&WireSlate::text(lepic_slate::codec::MediaType::JSON, json))
            .unwrap()
    }

    fn floonet_epicbox() -> lepic_methods::epicbox::Epicbox {
        let relay = lepic_epicbox::mock_relay::MockRelay::new(lepic_epicbox::Network::Floonet);
        let endpoint = lepic_epicbox::RelayEndpoint::new(
            lepic_epicbox::Domain::parse("relay.test").unwrap(),
            None,
            lepic_epicbox::Security::Plain,
        );
        lepic_methods::epicbox::Epicbox::new(
            lepic_epicbox::testing::client_settings(endpoint),
            lepic_epicbox::Network::Floonet,
            relay.connector(),
        )
    }

    #[test]
    fn an_epicbox_or_file_s1_carries_no_lepic_key() {
        let slate = vector_s1();
        let context = EncodeContext {
            block_header_version: 6,
        };
        let sending = Sending::new(Network::Floonet);
        let encode =
            |method: &dyn Method| method.encode_new(&slate, &context, &sending).unwrap().wire;
        let epicbox = encode(&floonet_epicbox());
        assert!(!epicbox.as_text().unwrap().contains("lepic"));
        let file = encode(&lepic_transport::file::FileTransport::default());
        assert!(!file.as_text().unwrap().contains("lepic"));
    }
}
