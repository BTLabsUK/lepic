//! Send, standard flow: build the S1 slate, lock its inputs, store it, deliver it.
//!
//! The slate is built as `epic-wallet` `v4.0.2` builds it (`owner::init_send_tx`): selection,
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

use blake2::Blake2b256;
use blake2::digest::{FixedOutput, Update};
use jiff::Timestamp;
use lepic_crypto::{Commitment, CryptoError, Message, PublicKey, SecretKey, aggsig};
use lepic_epicbox::{EpicboxAddress, TRANSPORT_ID as EPICBOX};
use lepic_keychain::proof::create_output;
use lepic_keychain::{
    Identifier, IdentifierError, Keychain, KeychainError, ProofBuilder, ProofError,
    SwitchCommitment,
};
use lepic_node::{NodeApi, NodeError};
use lepic_primitives::amount::{Amount, ArithmeticError, Fee, Height};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::input::Input;
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_primitives::tx::TransactionBody;
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_slate::codec::marked_v2::MarkedV2JsonCodec;
use lepic_slate::codec::marked_v3::MarkedV3JsonCodec;
use lepic_slate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, EncodeError, ProofAddressError, SlateError};
use lepic_slate::model::{
    KernelLock, Participant, ParticipantMessage, PaymentProof, ProofAddress, Proposal, Slate,
    SlateId,
};
use lepic_slate::origin::WireOrigin;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::stage::{Flow, Stage};
use lepic_store::{
    AccountIndex, KeyId, OutboxEntry, OutboxId, OutboxStatus, OutputRecord, OutputStatus,
    ParticipantId, PrivateContext, Repositories, SlateStage, StoreError, StoredSlate,
    TransactionEntry, TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::file::FILE;
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, Location, Transport, TransportId};
use rand_core::CryptoRng;
use thiserror::Error;
use tracing::field::Empty;
use tracing::{Span, debug, info, instrument, warn};
use uuid::Uuid;

use crate::account::{self, AccountError, next_output_key};
use crate::epicbox_invoice::invoice_origin;
use crate::error::WalletError;
use crate::inbox::relay_network;
use crate::ports::{SecretVault, StoreOpener};
use crate::selection::{self, Selection, SelectionError, SelectionOptions, SelectionStrategy};
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
    /// The transaction and its slate are stored and the inputs locked;
    /// [`crate::Wallet::resend`] tries again and [`crate::Wallet::cancel`] gives up.
    #[error("slate {slate_id} of transaction {tx_id} is stored but was not delivered")]
    Undelivered {
        tx_id: TxId,
        slate_id: SlateId,
        #[source]
        source: TransportError,
    },
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
    /// Blocks past the chain tip after which the receiver must refuse the slate.
    pub ttl_blocks: Option<u64>,
    /// Cut to [`lepic_slate::model::MAX_MESSAGE_LEN`] bytes, on a character boundary, before
    /// it is signed.
    pub message: Option<String>,
    /// The receiver's payment proof address. Asks the receiver to sign a payment proof.
    pub payment_proof_recipient: Option<ProofAddress>,
}

impl SendRequest {
    pub const fn new(account: AccountIndex, amount: Amount) -> Self {
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
            message: None,
            payment_proof_recipient: None,
        }
    }

    /// The options [`crate::Wallet::estimate_fee`] takes to estimate this send.
    pub const fn selection_options(&self) -> SelectionOptions {
        SelectionOptions {
            account: self.account,
            minimum_confirmations: self.minimum_confirmations,
            max_outputs: self.max_outputs,
            change_outputs: self.change_outputs,
            strategy: self.strategy,
        }
    }
}

/// How a slate leaves the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Through a transport that delivers, such as Epicbox.
    Deliver {
        transport: TransportId,
        to: Destination,
    },
    /// Through a method where the user carries the slate, such as a file.
    Export {
        transport: TransportId,
        to: Location,
    },
}

impl Delivery {
    pub const fn transport(&self) -> TransportId {
        match self {
            Self::Deliver { transport, .. } | Self::Export { transport, .. } => *transport,
        }
    }
}

/// A slate that was stored and delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentSlate {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub amount: Amount,
    pub fee: Fee,
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
#[derive(Debug)]
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

/// The codecs of the legacy methods, in the detection order `receive` uses.
fn legacy_codecs(base_fee: Fee) -> CodecRegistry {
    codecs_with(Box::new(V2JsonCodec::new(base_fee)), base_fee)
}

/// The codecs a new S1 goes out with over `transport`: over Epicbox the V2 shape carries the
/// LEPIC marker, so a reply that keeps it proves the receiver runs LEPIC, and a stock receiver
/// drops it.
fn delivery_codecs(transport: TransportId, base_fee: Fee) -> CodecRegistry {
    let v2 = V2JsonCodec::new(base_fee);
    if transport == EPICBOX {
        codecs_with(Box::new(MarkedV2JsonCodec::new(v2)), base_fee)
    } else {
        codecs_with(Box::new(v2), base_fee)
    }
}

fn codecs_with(v2: Box<dyn Codec>, base_fee: Fee) -> CodecRegistry {
    let mut codecs = CodecRegistry::new();
    // Registration fails only for a duplicate id, and these ids differ; a missing codec would
    // surface as `CodecNotRegistered` anyway.
    let _ = codecs.register(Box::new(V3JsonCodec::new(base_fee)));
    let _ = codecs.register(v2);
    codecs
}

fn transport<'a>(
    transports: &'a TransportRegistry,
    delivery: &Delivery,
) -> Result<&'a dyn Transport, SendError> {
    let id = delivery.transport();
    let transport = transports
        .get(id)
        .ok_or(SendError::UnknownTransport { transport: id })?;
    match delivery {
        Delivery::Deliver { .. } if transport.outbound().is_none() => {
            Err(SendError::CannotDeliver { transport: id })
        }
        Delivery::Export { .. } if transport.exchange().is_none() => {
            Err(SendError::CannotExport { transport: id })
        }
        Delivery::Deliver { .. } | Delivery::Export { .. } => Ok(transport),
    }
}

/// The S1 as the transport sends a new slate.
fn encode_for_delivery(
    env: &SendEnvironment<'_>,
    delivery: &Delivery,
    slate: &Slate,
    account: AccountIndex,
    context: &EncodeContext,
) -> Result<WireSlate, SendError> {
    let base_fee = env.base_fee();
    let policy = transport(env.transports, delivery)?.policy();
    // A file or paste S1 carries the reply key in the LEPIC marker, so a LEPIC receiver can
    // answer sealed (RFC 0002 5); stock wallets ignore the extra key.
    let reply_key = (delivery.transport() == FILE)
        .then(|| {
            crate::contact::reply_public_key(
                env.keychain,
                env.network,
                account,
                *slate.id().as_bytes(),
            )
        })
        .flatten();
    let codecs = match reply_key {
        Some(key) => {
            let mut codecs = CodecRegistry::new();
            // Registration fails only for a duplicate id, and these ids differ.
            let _ = codecs.register(Box::new(
                MarkedV3JsonCodec::new(V3JsonCodec::new(base_fee)).with_reply_key(key),
            ));
            let _ = codecs.register(Box::new(V2JsonCodec::new(base_fee)));
            codecs
        }
        None => delivery_codecs(delivery.transport(), base_fee),
    };
    Ok(policy.encode_new_slate(&codecs, slate, context)?)
}

/// What the store transaction of a send produced, for the delivery that follows it.
struct StoredS1 {
    tx_id: TxId,
    slate_id: SlateId,
    amount: Amount,
    fee: Fee,
    wire: WireSlate,
    outbox: Option<OutboxId>,
    /// Where the slate must go whatever the caller named: the allowed address of a parked
    /// invoice's payment.
    bound_to: Option<Destination>,
    /// Where the slate goes as well: the address a parked invoice came from, when it names the
    /// allowed key under another relay.
    also_to: Option<Destination>,
}

/// What the store transaction of a send or resend runs with, so it needs no `Ports`.
struct SendEnvironment<'a> {
    transports: &'a TransportRegistry,
    keychain: &'a Keychain,
    network: Network,
    now: Timestamp,
}

impl SendEnvironment<'_> {
    fn base_fee(&self) -> Fee {
        self.network.params().default_base_fee()
    }
}

/// `outputs` without the unspent ones this wallet cannot spend: those whose stored commitment
/// is not the one their key and value derive with the regular switch commitment, the only one
/// a transaction here spends with. A restore stores every output whose proof rewinds, so one
/// created with another switch commitment still counts in the balance; selecting it would only
/// build a transaction that fails.
pub(crate) fn spendable_here(keychain: &Keychain, outputs: Vec<OutputRecord>) -> Vec<OutputRecord> {
    outputs
        .into_iter()
        .filter(|output| {
            if output.status != OutputStatus::Unspent {
                return true;
            }
            let derived = Identifier::from_bytes(&output.key_id.0)
                .ok()
                .and_then(|key_id| {
                    keychain
                        .commit(output.amount.value(), &key_id, SwitchCommitment::Regular)
                        .ok()
                });
            let spendable = derived == Some(output.id.commitment);
            if !spendable {
                debug!(height = %output.height, "output not derived for spending skipped");
            }
            spendable
        })
        .collect()
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
    let base_fee = env.base_fee();
    let outputs = spendable_here(keychain, repos.outputs(request.account, None)?);
    let selection = selection::select(
        &outputs,
        &request
            .selection_options()
            .request(request.amount, tip, base_fee),
    )?;
    let built = store_s1(
        repos,
        keychain,
        &S1Storage {
            network: env.network,
            now: env.now,
            tip,
            transport: delivery.transport(),
        },
        request,
        selection,
        randomness,
    )?;
    let wire = encode_for_delivery(
        env,
        delivery,
        &built.slate,
        request.account,
        &built.encode_context,
    )?;
    record_counterparty(repos, built.tx_id, delivery)?;
    let slate_uuid = Uuid::from_bytes(*built.slate.id().as_bytes());
    let outbox = enqueue_delivery(repos, delivery, slate_uuid, env.now)?;
    Ok(StoredS1 {
        tx_id: built.tx_id,
        slate_id: built.slate.id(),
        amount: built.plan_amount,
        fee: built.plan_fee,
        wire,
        outbox,
        bound_to: None,
        also_to: None,
    })
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
/// unconfirmed outputs, the sender's private context and the slate itself.
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
        repos.put_output(&OutputRecord {
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
        Delivery::Deliver { to, .. } => repos.set_counterparty(tx_id, to.as_str()),
        Delivery::Export { .. } => Ok(()),
    }
}

/// Records a delivery to a destination in the outbox, reusing a pending entry for the same
/// slate and destination. Exports have no destination to record.
fn enqueue_delivery(
    repos: &mut dyn Repositories,
    delivery: &Delivery,
    slate_id: Uuid,
    now: Timestamp,
) -> Result<Option<OutboxId>, SendError> {
    let Delivery::Deliver { transport, to } = delivery else {
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

/// The stored S1 of a transaction waiting for delivery, encoded for `delivery`.
fn stored_s1_for_delivery(
    repos: &mut dyn Repositories,
    env: &SendEnvironment<'_>,
    tx_id: TxId,
    delivery: &Delivery,
) -> Result<StoredS1, SendError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let not_resendable = SendError::NotResendable { tx_id };
    let (TxDirection::Outgoing, TxState::Sent, Some(slate_uuid)) =
        (entry.direction, entry.state, entry.slate_id)
    else {
        return Err(not_resendable);
    };
    // A slate exchanged with a paired contact goes again only through its outbox, sealed.
    if matches!(delivery, Delivery::Deliver { .. })
        && crate::contact::slate_contact(repos, slate_uuid)?.is_some()
    {
        return Err(not_resendable);
    }
    let Some(stored) = repos
        .slate(slate_uuid, SlateStage::Standard1)?
        .filter(|stored| stored.codec == LEGACY_V3_JSON.as_str())
    else {
        return stored_i2_for_delivery(repos, env, tx_id, slate_uuid, delivery);
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
    let wire = encode_for_delivery(
        env,
        delivery,
        &slate,
        entry.account,
        &EncodeContext {
            block_header_version,
        },
    )?;
    let outbox = enqueue_delivery(repos, delivery, slate_uuid, env.now)?;
    record_counterparty(repos, tx_id, delivery)?;
    Ok(StoredS1 {
        tx_id,
        slate_id: slate.id(),
        amount: slate.amount(),
        fee: slate.fee(),
        wire,
        outbox,
        bound_to: None,
        also_to: None,
    })
}

/// Whether `delivery` goes over Epicbox to the key of the address `allowed`.
fn same_epicbox_key(network: Network, delivery: &Delivery, allowed: Option<&str>) -> bool {
    let Delivery::Deliver { transport, to } = delivery else {
        return false;
    };
    let network = relay_network(network);
    let key = |address: &str| {
        EpicboxAddress::parse(address, network)
            .ok()
            .map(|address| *address.public_key())
    };
    *transport == EPICBOX
        && allowed
            .and_then(key)
            .is_some_and(|allowed| key(to.as_str()) == Some(allowed))
}

/// The stored I2 of an invoice payment, as it was encoded for its first delivery. It was
/// encoded by the reply rule of the transport the invoice came over, which gave it the shape of
/// the I1 and over Epicbox the LEPIC marker, so it goes out unchanged.
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
    let slate = legacy_codecs(env.base_fee())
        .decode(&wire)
        .map_err(SendError::StoredSlate)?;
    if slate.stage() != Stage::I2 {
        return Err(SendError::NotResendable { tx_id });
    }
    let (bound_to, also_to) = if repos.pending_invoice(slate_uuid)?.is_some() {
        // A parked invoice is paid only to the address the user allowed, recorded when it was
        // paid; the recorded address also decides whose notices count for the payment. The
        // caller's address may name the same key under another domain, which the relay does
        // not authenticate, so the recorded one is used.
        let allowed = repos.counterparty(tx_id)?;
        if !same_epicbox_key(env.network, delivery, allowed.as_deref()) {
            return Err(SendError::PayeeMismatch { tx_id });
        }
        let origin = invoice_origin(repos, slate_uuid)?.map(Destination::new);
        (allowed.map(Destination::new), origin)
    } else {
        record_counterparty(repos, tx_id, delivery)?;
        (None, None)
    };
    Ok(StoredS1 {
        tx_id,
        slate_id: slate.id(),
        amount: slate.amount(),
        fee: slate.fee(),
        wire,
        outbox: None,
        bound_to,
        also_to,
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
    /// policy.
    ///
    /// Fails, with nothing stored, with [`SendError::Wallet`] carrying [`WalletError::Locked`]
    /// when the wallet is locked, [`SendError::Node`] when the chain tip is unavailable, [`SendError::UnknownTransport`],
    /// [`SendError::CannotDeliver`] or [`SendError::CannotExport`], a
    /// [`SendError::Selection`] error, or [`SendError::Unrepresentable`] when the transport's
    /// format cannot carry the slate. A send with change fails with
    /// [`WalletError::RestoreScanRequired`] on a database rebuilt from the seed before a scan
    /// from genesis completed. Fails with [`SendError::Undelivered`] when the slate was
    /// stored but the transport failed; the transaction then waits for
    /// [`Wallet::resend`] or [`Wallet::cancel`].
    #[instrument(skip_all, fields(
        wallet = %self.config().name,
        transport = %delivery.transport(),
        stage = %Stage::S1,
        tx_id = Empty,
        slate_id = Empty,
    ))]
    pub async fn send(
        &self,
        request: SendRequest,
        delivery: Delivery,
    ) -> Result<SentSlate, SendError> {
        let session = self.session()?;
        transport(&self.ports().transports, &delivery)?;
        let tip = self
            .ports()
            .node
            .get_tip()
            .await
            .map_err(SendError::Node)?
            .height;
        self.check_plausible_tip(&session, tip).await?;
        let target = delivery.clone();
        let stored = self
            .blocking(move |ports, config| {
                let env = SendEnvironment {
                    transports: &ports.transports,
                    keychain: &session.keychain,
                    network: config.network,
                    now: ports.clock.now(),
                };
                let randomness = S1Randomness::draw(&mut **ports.rng.lock());
                Ok(randomness.map_err(SendError::from).and_then(|randomness| {
                    session.store.write(|repos| {
                        create_s1(
                            repos,
                            &env,
                            &session.keychain,
                            tip,
                            &request,
                            &target,
                            randomness,
                        )
                    })
                }))
            })
            .await??;
        let span = Span::current();
        span.record("tx_id", stored.tx_id.0);
        span.record("slate_id", tracing::field::display(stored.slate_id));
        info!("slate created");
        self.deliver(&stored, &delivery).await?;
        Ok(SentSlate {
            tx_id: stored.tx_id,
            slate_id: stored.slate_id,
            amount: stored.amount,
            fee: stored.fee,
        })
    }

    /// Delivers the stored S1 of a transaction whose delivery failed, through `delivery`, which
    /// may name another transport than the first attempt. For an invoice payment, delivers its
    /// stored I2 as it was first encoded; the payment of a parked invoice goes to the recorded
    /// allowed address, whatever domain `delivery` names for its key.
    ///
    /// Fails with [`SendError::Wallet`] carrying [`WalletError::UnknownTransaction`],
    /// [`SendError::NotResendable`] when the
    /// transaction is not an outgoing one in state `sent`, [`SendError::PayeeMismatch`] when the
    /// payment of a parked invoice would go anywhere but its sender's allowed address over
    /// Epicbox, the transport errors of [`Wallet::send`], or [`SendError::Undelivered`] when
    /// the transport fails again.
    #[instrument(skip_all, fields(
        wallet = %self.config().name,
        transport = %delivery.transport(),
        stage = %Stage::S1,
        tx_id = %tx_id,
        slate_id = Empty,
    ))]
    pub async fn resend(&self, tx_id: TxId, delivery: Delivery) -> Result<(), SendError> {
        let session = self.session()?;
        transport(&self.ports().transports, &delivery)?;
        let target = delivery.clone();
        let stored = self
            .blocking(move |ports, config| {
                let env = SendEnvironment {
                    transports: &ports.transports,
                    keychain: &session.keychain,
                    network: config.network,
                    now: ports.clock.now(),
                };
                Ok(session
                    .store
                    .write(|repos| stored_s1_for_delivery(repos, &env, tx_id, &target)))
            })
            .await??;
        Span::current().record("slate_id", tracing::field::display(stored.slate_id));
        let delivery = match &stored.bound_to {
            Some(to) => Delivery::Deliver {
                transport: delivery.transport(),
                to: to.clone(),
            },
            None => delivery,
        };
        let delivered = self.deliver(&stored, &delivery).await;
        match &stored.also_to {
            // The issuer listens where it sent the invoice from; either delivery is enough.
            Some(to) => {
                let also = Delivery::Deliver {
                    transport: delivery.transport(),
                    to: to.clone(),
                };
                let also = self.deliver(&stored, &also).await;
                delivered.or(also)
            }
            None => delivered,
        }
    }

    /// Hands the wire slate to the transport, then records the attempt in the outbox. A store
    /// failure while recording is logged and not returned, because the slate already left.
    async fn deliver(&self, stored: &StoredS1, delivery: &Delivery) -> Result<(), SendError> {
        let transport = transport(&self.ports().transports, delivery)?;
        let outcome = match (delivery, transport.outbound(), transport.exchange()) {
            (Delivery::Deliver { to, .. }, Some(outbound), _) => {
                outbound.deliver(to, &stored.wire).await
            }
            (Delivery::Export { to, .. }, _, Some(exchange)) => {
                exchange.export(&stored.wire, to).await
            }
            (Delivery::Deliver { .. }, None, _) => {
                return Err(SendError::CannotDeliver {
                    transport: delivery.transport(),
                });
            }
            (Delivery::Export { .. }, _, None) => {
                return Err(SendError::CannotExport {
                    transport: delivery.transport(),
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
}
