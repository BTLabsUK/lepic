// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/api_impl/foreign.rs,
// libwallet/src/internal/tx.rs, libwallet/src/internal/selection.rs, libwallet/src/slate.rs
// (Apache-2.0); see NOTICE and upstream.toml.

//! Receive: the receiver's step of the standard flow, from the sender's S1 to the S2 reply, as
//! `epic-wallet`'s `receive_tx` does it (`docs/compat/legacy-slates.md`, "Lifecycle").

use crate::namespace::{self, Listing};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use lepic_crypto::aggsig::{
    calculate_partial_sig, create_secnonce, sign_single, verify_completed_sig,
};
use lepic_crypto::{Commitment, CryptoError, Message, PublicKey, SecretKey, Signature};
use lepic_keychain::proof::create_output;
use lepic_keychain::{
    Identifier, Keychain, KeychainError, ProofBuilder, ProofError, SwitchCommitment,
};
use lepic_legacy_slate::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
use lepic_node::{NodeApi, NodeError};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::committed::{KernelSumError, sum_commitments};
use lepic_primitives::crypto_ser::BlindingFactor;
use lepic_primitives::fee::BodyCounts;
use lepic_primitives::hash::{Hashed, blake2b_256};
use lepic_primitives::output::Output;
use lepic_primitives::params::Network;
use lepic_primitives::tx::TransactionBody;
use lepic_slate::codec::WireSlate;
use lepic_slate::codec::{Codec as _, EncodeContext};
use lepic_slate::error::{DecodeError, RegistryError, SlateError};
use lepic_slate::model::{
    Participant, ParticipantMessage, ProofSignature, Receipt, Slate, SlateId, SlateParts,
};
use lepic_slate::origin::WireOrigin;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{
    AccountIndex, KeyId, OutputRecord, OutputStatus, Repositories, SlateStage, StoreError,
    StoredSlate, TransactionEntry, TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::error::FormatError;
use lepic_transport::method::{Encoded, Method, SenderFacts};
use lepic_transport::transport::{Destination, TransportId};
use rand_core::CryptoRng;
use thiserror::Error;
use tracing::{Span, debug, info, instrument};
use uuid::Uuid;

use crate::account::{self, DEFAULT_ACCOUNT_LABEL};
use crate::codecs;
use crate::error::WalletError;
use crate::event::{AnsweredSlate, Event, ReceivedTransaction};
use crate::lifecycle::Session;
use crate::native_epicbox::Claim;
use crate::ports::{Ports, SecretVault, StoreOpener};
use crate::wallet::Wallet;

pub(crate) mod redelivery;

/// `epic-wallet` signs payment proofs with the address key at index 0 of the account.
const PAYMENT_PROOF_KEY_INDEX: u32 = 0;

/// What the receiver chooses when it accepts a slate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiveRequest {
    /// Label of the account the funds go to; the default account when `None`.
    pub account: Option<String>,
    /// The receiver's message to the sender, cut to the first 256 bytes before it is signed.
    pub message: Option<String>,
    /// The key that signs a payment proof the slate asks for: the key of the address the
    /// slate came to.
    pub proof_key: ProofKey,
}

/// Which key signs a payment proof (ADR 0044). A proof whose receiver address is not that
/// key's public key is refused with [`ReceiveError::ForeignProofAddress`], so a slate sent to
/// one address of the wallet never learns that another address is the same wallet's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProofKey {
    /// The payment-proof key, index 0 of the receiving account, as `epic-wallet` signs: for
    /// Epicbox, HTTP, files, and the previous onion.
    #[default]
    Payments,
    /// The wallet's onion key ([`Wallet::onion_key`]): for slates that came to the onion.
    Onion,
    /// The epic1 proof key of the receiving account on the slate's network at the address
    /// index the slate came to ([`Wallet::epic1_proof_key`]): for slates that came to one of
    /// the account's epic1 addresses. The index is stored with the transaction.
    Epic1 { index: u32 },
}

/// A received slate: the stored transaction and the S2 reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub tx_id: TxId,
    pub slate: Slate,
    /// S2 encoded by the transport's reply rule, the bytes that were stored.
    pub reply: WireSlate,
    /// The slate was received before and `reply` is the S2 stored then. Nothing was stored and
    /// no key was reserved; the event was [`Event::AnsweredAgain`], not [`Event::Received`].
    pub repeated: bool,
}

/// Why a slate was not received. Nothing is stored for any of them.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReceiveError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("transport {transport} is not registered")]
    UnknownTransport { transport: TransportId },
    #[error("slate could not be decoded")]
    Decode(#[source] DecodeError),
    #[error("slate at stage {stage} is not a payment to receive")]
    WrongStage { stage: Stage },
    #[error("slate pays an amount of zero")]
    ZeroAmount,
    /// A different S1 reuses the id of a slate received as `tx_id`, or that transaction was
    /// cancelled or expired. The same S1 again is answered with the stored S2 instead.
    #[error("slate {slate_id} was already received as transaction {tx_id}")]
    AlreadyReceived { slate_id: SlateId, tx_id: TxId },
    #[error("slate expired at height {cutoff}, the chain tip is at {tip}")]
    Expired { cutoff: Height, tip: Height },
    /// The slate's height is above any height the chain can have reached by now.
    #[error("slate height {height} is above the highest plausible height {limit}")]
    AheadOfTip { height: Height, limit: Height },
    #[error("fee is below the minimum for the transaction")]
    FeeBelowMinimum { fee: Fee, minimum: Fee },
    #[error("minimum fee could not be computed")]
    FeeOverflow,
    #[error("{role} message signature does not verify")]
    MessageSignature {
        role: Role,
        #[source]
        source: CryptoError,
    },
    #[error("payment proof asks for a signature this wallet does not make")]
    ForeignProofAddress,
    #[error("node request failed")]
    Node(#[source] NodeError),
    #[error("receiver output could not be built")]
    Output(#[source] ProofError),
    #[error("receiver signature could not be created")]
    Signing(#[source] CryptoError),
    #[error("kernel excess could not be computed")]
    Excess(#[source] KernelSumError),
    #[error("receiver data does not fit the slate")]
    Slate(#[source] SlateError),
    #[error("codec registration failed")]
    Codecs(#[source] RegistryError),
    #[error("reply could not be encoded")]
    Encode(#[source] FormatError),
    /// Too many payments nobody asked for wait for their senders to finalize, and none could
    /// be cancelled to make room; it carries why the node could not be asked, when that was
    /// the reason. See [`Wallet::receive_unsolicited`].
    #[error("open receipts are at the cap")]
    OpenReceipts(#[source] Option<WalletError>),
    /// The wallet refuses payments nobody asked for
    /// ([`crate::config::WalletPolicy::refuse_unsolicited_payments`]); nothing was signed or
    /// stored (ADR 0045).
    #[error("this wallet refuses payments nobody asked for")]
    Refused,
}

impl From<StoreError> for ReceiveError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

impl From<KeychainError> for ReceiveError {
    fn from(error: KeychainError) -> Self {
        Self::Wallet(WalletError::Keychain(error))
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Receives the sender's S1, which arrived over `transport`: checks it, adds this wallet's
    /// output, public data, partial signature and, when asked for, payment proof signature, and
    /// stores the output, the transaction and the S2 reply in one store transaction. No private
    /// context is kept: the receiver's signing keys are dropped once S2 is signed. The caller
    /// sends the reply over the same transport.
    ///
    /// The same S1 received again, on any transport, returns the S2 stored the first time with
    /// [`Received::repeated`] set, without asking the node or storing anything, so a reply lost
    /// before it reached the sender can be sent again.
    ///
    /// Emits [`Event::Received`] once the transaction is stored, and for a repeat only
    /// [`Event::AnsweredAgain`].
    ///
    /// Asks the node for its tip. Fails with [`ReceiveError::Wallet`] carrying
    /// [`WalletError::Locked`] when the wallet is locked, with [`ReceiveError::AlreadyReceived`]
    /// for another S1 under a slate id this wallet has received before or for a slate whose
    /// transaction was cancelled or expired, with [`ReceiveError::Expired`] when the
    /// tip has reached the slate's TTL cutoff, with [`ReceiveError::AheadOfTip`] when its height
    /// is above any the chain can have reached by now, and with a typed
    /// rejection for any slate that is malformed, not an S1, pays nothing, or whose fee or
    /// messages do not check. Fails with
    /// [`WalletError::RestoreScanRequired`] inside [`ReceiveError::Wallet`] on a database rebuilt
    /// from the seed before a scan from genesis completed. Nothing is stored on failure.
    pub async fn receive(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
    ) -> Result<Received, ReceiveError> {
        self.receive_from(method, wire, request, None, None).await
    }

    /// [`Wallet::receive`] of a slate that came from `counterparty`, which is stored with the
    /// new transaction.
    #[instrument(
        name = "receive",
        skip_all,
        fields(wallet = %self.config().name, transport = %method.id(), slate_id, stage)
    )]
    pub(crate) async fn receive_from(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
        counterparty: Option<Destination>,
        listing: Option<Listing>,
    ) -> Result<Received, ReceiveError> {
        let slate = method
            .decode(self.config().network, wire)
            .map_err(ReceiveError::Decode)?;
        let from = method.sender_facts(wire);
        self.receive_slate(method, slate, from, request, counterparty, listing)
            .await
    }

    /// [`Wallet::receive`] of an S1 the caller decoded from a compact format such as
    /// `lepic.v1`, which carries no wire facts about its sender. The S2 is stored as `method`
    /// encodes it, and returned for the caller to carry back.
    #[instrument(
        name = "receive",
        skip_all,
        fields(wallet = %self.config().name, transport = %method.id(), slate_id, stage)
    )]
    pub async fn receive_decoded(
        &self,
        method: &Arc<dyn Method>,
        slate: Slate,
        request: ReceiveRequest,
    ) -> Result<Received, ReceiveError> {
        self.receive_slate(method, slate, SenderFacts::default(), request, None, None)
            .await
    }

    async fn receive_slate(
        &self,
        method: &Arc<dyn Method>,
        slate: Slate,
        from: SenderFacts,
        request: ReceiveRequest,
        counterparty: Option<Destination>,
        listing: Option<Listing>,
    ) -> Result<Received, ReceiveError> {
        let session = self.session()?;
        let network = self.config().network;
        let transport = method.id();
        let span = Span::current();
        span.record("slate_id", tracing::field::display(slate.id()));
        span.record("stage", slate.stage().as_str());
        check_proposal(&slate)?;
        if let Some(received) = self.received_before(&slate).await? {
            return Ok(self.answered_again(received, transport));
        }
        let (tip, limit) = self.stage_tip(&session, ReceiveError::Node).await?;
        check_ttl(&slate, tip)?;
        check_height(&slate, limit)?;
        let context = self.encode_context(&slate).await?;
        // An answer from a listing claims no native slates, so the listing's address is not
        // linked to the payments address's seal key.
        let claim = match listing {
            None => Claim::of(self.config(), &session.seed),
            Some(_) => Claim::plain(self.config().claimed_features()),
        };
        debug!(height = tip.value(), "slate checked");

        let method = Arc::clone(method);
        let answer = self
            .blocking(move |ports, _| {
                Ok(store_reply(
                    ports,
                    &session,
                    &*method,
                    &Proposal {
                        slate,
                        transport,
                        network,
                        context,
                        counterparty,
                        from,
                        claim,
                        listing,
                    },
                    &request,
                ))
            })
            .await??;
        let (received, account) = match answer {
            Answer::Stored { received, account } => (received, account),
            Answer::Repeated(received) => {
                return Ok(self.answered_again(received, transport));
            }
        };
        info!(tx_id = %received.tx_id, "slate received");
        self.emit(Event::Received(ReceivedTransaction {
            tx_id: received.tx_id,
            slate_id: received.slate.id(),
            account,
            amount: received.slate.amount(),
            transport,
        }));
        Ok(received)
    }

    fn answered_again(&self, received: Received, transport: TransportId) -> Received {
        info!(tx_id = %received.tx_id, "slate answered again");
        self.emit(Event::AnsweredAgain(AnsweredSlate {
            tx_id: received.tx_id,
            slate_id: received.slate.id(),
            transport,
        }));
        received
    }

    /// The S2 stored for `proposal` when this wallet received it before, read before the node
    /// is asked anything, so a repeat is answered while the node is unreachable or past the
    /// slate's TTL.
    async fn received_before(&self, proposal: &Slate) -> Result<Option<Received>, ReceiveError> {
        let session = self.session()?;
        let network = self.config().network;
        let proposal = proposal.clone();
        self.blocking(move |_, _| {
            Ok(session
                .store
                .read(|repos| redelivery::answer_again(repos, network, &proposal)))
        })
        .await?
    }

    /// The header facts for a reply: those the slate arrived with, or the node's when it
    /// carries none.
    async fn encode_context(&self, slate: &Slate) -> Result<EncodeContext, ReceiveError> {
        if let Some(header) = slate.origin().and_then(WireOrigin::legacy_header) {
            return Ok(EncodeContext {
                block_header_version: header.block_header_version,
            });
        }
        let version = self
            .ports()
            .node
            .get_version()
            .await
            .map_err(ReceiveError::Node)?;
        Ok(EncodeContext {
            block_header_version: version.block_header_version,
        })
    }
}

/// An S1 that passed the checks needing no keys, with what its reply depends on.
struct Proposal {
    slate: Slate,
    transport: TransportId,
    network: Network,
    context: EncodeContext,
    counterparty: Option<Destination>,
    /// What the S1 says about its sender, which the method's reply follows.
    from: SenderFacts,
    /// What this wallet's marker claims.
    claim: Claim,
    /// The listing the S1 came in on; `None` for the payments address.
    listing: Option<Listing>,
}

/// What storing a reply ended with: a new transaction and the account the funds go to, or the
/// S2 stored for the same S1 by a receive that finished first.
enum Answer {
    Stored {
        received: Received,
        account: AccountIndex,
    },
    Repeated(Received),
}

/// Builds S2, encodes it by the method's reply rule and stores everything in one store
/// transaction, so the output key it reserves is used exactly once. The check for a slate id
/// received before runs inside that transaction, so two receives of one S1 store it once.
fn store_reply<N, S: StoreOpener, V>(
    ports: &Ports<N, S, V>,
    session: &Session<S::Store>,
    method: &dyn Method,
    proposal: &Proposal,
    request: &ReceiveRequest,
) -> Result<Answer, ReceiveError> {
    let transport = proposal.transport;
    let sending = proposal.claim.sending(proposal.network, None);
    let now = ports.clock.now();
    session.store.write(|repos| {
        if let Some(received) =
            redelivery::answer_again(&*repos, proposal.network, &proposal.slate)?
        {
            return Ok(Answer::Repeated(received));
        }
        // Store first, generator second, as everywhere: the reverse order deadlocks with a
        // contact operation that draws inside its own store write.
        let response = respond(repos, session, proposal, request, &mut **ports.rng.lock())?;
        let Encoded { wire: reply, codec } = method
            .encode_reply(&response.slate, &proposal.context, &sending, &proposal.from)
            .map_err(ReceiveError::Encode)?;
        let tx_id = store_response(repos, &response, &reply, codec.as_str(), transport, now)?;
        if let Some(counterparty) = &proposal.counterparty {
            repos.set_counterparty(tx_id, counterparty.as_str())?;
        }
        if let Some(listing) = proposal.listing {
            repos.set_receive_listing(tx_id, &listing.to_stored())?;
        }
        if let ProofKey::Epic1 { index } = request.proof_key {
            crate::epic1_index::record_payment(repos, tx_id, response.account, index)?;
        }
        Ok(Answer::Stored {
            received: Received {
                tx_id,
                slate: response.slate,
                reply,
                repeated: false,
            },
            account: response.account,
        })
    })
}

/// Receives `s1`, a slate this wallet built, into `account` in the caller's store
/// transaction, as [`Wallet::receive`] stores a slate that came over `transport`, and returns
/// the new incoming entry and the S2. The reply is stored as V3 since no transport carries it.
#[allow(clippy::too_many_arguments)] // One store transaction's inputs; a struct would only rename them.
pub(crate) fn receive_own<D>(
    repos: &mut dyn Repositories,
    session: &Session<D>,
    network: Network,
    account: AccountIndex,
    s1: &Slate,
    transport: TransportId,
    context: EncodeContext,
    rng: &mut (impl CryptoRng + ?Sized),
    now: jiff::Timestamp,
) -> Result<(TxId, Slate), ReceiveError> {
    check_proposal(s1)?;
    let label = repos
        .account(account)?
        .ok_or(WalletError::from(account::AccountError::UnknownAccount(
            account,
        )))?
        .label;
    let proposal = Proposal {
        slate: s1.clone(),
        transport,
        network,
        context,
        counterparty: None,
        from: SenderFacts::default(),
        claim: Claim::plain(0),
        listing: None,
    };
    let request = ReceiveRequest {
        account: Some(label),
        message: None,
        proof_key: ProofKey::Payments,
    };
    let response = respond(repos, session, &proposal, &request, rng)?;
    let reply = V3JsonCodec::new(network.params().default_base_fee())
        .encode(&response.slate, &context)
        .map_err(|error| ReceiveError::Encode(FormatError::Encode(error)))?;
    let tx_id = store_response(
        repos,
        &response,
        &reply,
        LEGACY_V3_JSON.as_str(),
        transport,
        now,
    )?;
    Ok((tx_id, response.slate))
}

/// The codecs a legacy transport policy decodes and encodes with, at the network's base fee.
pub fn legacy_codecs(network: Network) -> Result<CodecRegistry, ReceiveError> {
    Ok(codecs::legacy(network.params().default_base_fee()))
}

/// An S1 whose sender message, if any, is signed by the sender.
pub(crate) fn check_proposal(slate: &Slate) -> Result<(), ReceiveError> {
    if slate.stage() != Stage::S1 {
        return Err(ReceiveError::WrongStage {
            stage: slate.stage(),
        });
    }
    if slate.amount() == Amount::ZERO {
        return Err(ReceiveError::ZeroAmount);
    }
    for (role, participant) in slate.participants() {
        if let Some(message) = &participant.message {
            verify_message(message, &participant.public_blind_excess)
                .map_err(|source| ReceiveError::MessageSignature { role, source })?;
        }
    }
    Ok(())
}

/// Refuses a slate once the node's current tip reaches the cutoff. Upstream compares the cutoff
/// with the last confirmed height stored at its last refresh instead, so the two disagree while
/// that height is behind the tip.
fn check_ttl(slate: &Slate, tip: Height) -> Result<(), ReceiveError> {
    match slate.ttl_cutoff_height() {
        Some(cutoff) if tip >= cutoff => Err(ReceiveError::Expired { cutoff, tip }),
        _ => Ok(()),
    }
}

/// Refuses a slate created at a height the chain cannot have reached yet. A slate a few blocks,
/// or more, above the node's tip is received: the sender's node may simply be ahead of this
/// wallet's, and kernel lookups start at or below the tip either way ([`crate::chain::kernel_floor`]).
fn check_height(slate: &Slate, limit: Height) -> Result<(), ReceiveError> {
    let height = slate.height();
    if height > limit {
        return Err(ReceiveError::AheadOfTip { height, limit });
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
    verify_signed_text(message.text(), message.signature(), signer)
}

/// Verifies a participant's message signature as `epic-wallet` signs it: over the BLAKE2b
/// hash of the text, under the participant's public excess.
pub(crate) fn verify_signed_text(
    text: &str,
    signature: &Signature,
    signer: &PublicKey,
) -> Result<(), CryptoError> {
    verify_completed_sig(signature, signer, Some(signer), &message_digest(text))
}

/// The receiver's S2 and what it stores alongside. The excess key and nonce of its partial
/// signature are dropped once S2 is signed: a receiver never signs this kernel again.
struct Response {
    slate: Slate,
    account: AccountIndex,
    key_id: Identifier,
    output: Output,
}

/// Reserves the account's next output key and builds S2 for a slate id not received before.
fn respond<D>(
    repos: &mut dyn Repositories,
    session: &Session<D>,
    proposal: &Proposal,
    request: &ReceiveRequest,
    rng: &mut (impl CryptoRng + ?Sized),
) -> Result<Response, ReceiveError> {
    let slate = &proposal.slate;
    // A payment to a listing never names the wallet's payments key: a proof it asks for would
    // be signed by that key, so it is refused and nothing is signed.
    if proposal.listing.is_some() && slate.payment_proof().is_some() {
        return Err(ReceiveError::ForeignProofAddress);
    }
    let label = request.account.as_deref().unwrap_or(DEFAULT_ACCOUNT_LABEL);
    let account = account::account_by_label(repos, label)?;
    let key_id = account::next_output_key(repos, account.index)?;
    let parent = account.parent_key_id()?;
    let keychain = &session.keychain;
    let proof_key = match request.proof_key {
        ProofKey::Payments => None,
        ProofKey::Onion => Some(SigningKey::from_bytes(&*namespace::onion_seed(
            &session.seed,
        )?)),
        ProofKey::Epic1 { index } => Some(namespace::epic1_proof_key(
            &session.seed,
            account.index.0,
            match proposal.network {
                Network::Mainnet => lepic_contact::Network::Mainnet,
                Network::Floonet => lepic_contact::Network::Floonet,
            },
            index,
        )?),
    };
    build_response(
        keychain,
        slate,
        &Contribution {
            key_id,
            parent,
            message: request.message.as_deref(),
            base_fee: proposal.network.params().default_base_fee(),
            proof_key: proof_key.as_ref(),
        },
        rng,
    )
    .map(|(slate, output)| Response {
        slate,
        account: account.index,
        key_id,
        output,
    })
}

/// S1 to S2 on its own, as a receive builds it once the proposal is checked
/// ([`ReceiveError::WrongStage`], a zero amount, a sender message that does not verify) and the
/// output key `key_id` of the account `parent` is reserved; no store, node or TTL check. The
/// entry point for fuzzing the receiver with adversarial S1s.
pub fn build_s2(
    keychain: &Keychain,
    s1: &Slate,
    key_id: Identifier,
    parent: Identifier,
    message: Option<&str>,
    base_fee: Fee,
    rng: &mut (impl CryptoRng + ?Sized),
) -> Result<(Slate, Output), ReceiveError> {
    check_proposal(s1)?;
    build_response(
        keychain,
        s1,
        &Contribution {
            key_id,
            parent,
            message,
            base_fee,
            proof_key: None,
        },
        rng,
    )
}

/// What the receiver puts into the slate, besides randomness.
struct Contribution<'a> {
    key_id: Identifier,
    parent: Identifier,
    message: Option<&'a str>,
    base_fee: Fee,
    /// Signs the payment proof instead of the payment-proof key of `parent`: the onion or
    /// epic1 proof key.
    proof_key: Option<&'a SigningKey>,
}

/// S1 to S2 as `add_output_to_slate` and `receive_tx` do it: the output for the slate amount at
/// the reserved key, the receiver's public excess and nonce, its signed message, its partial
/// signature over the kernel message, and the payment proof signature.
fn build_response(
    keychain: &Keychain,
    slate: &Slate,
    contribution: &Contribution<'_>,
    rng: &mut (impl CryptoRng + ?Sized),
) -> Result<(Slate, Output), ReceiveError> {
    let amount = slate.amount().value();
    let switch = SwitchCommitment::Regular;
    let builder = ProofBuilder::new(keychain).map_err(ReceiveError::Output)?;
    let output = create_output(keychain, &builder, amount, &contribution.key_id, switch)
        .map_err(ReceiveError::Output)?;
    let output_key = keychain.derive_key(amount, &contribution.key_id, switch)?;
    let (slate, blinding) = with_offset(slate, output_key, rng)?;
    check_fee(&slate, contribution.base_fee)?;

    let public_excess = PublicKey::from_secret_key(&blinding).map_err(ReceiveError::Signing)?;
    let nonce = create_secnonce(rng).map_err(ReceiveError::Signing)?;
    let public_nonce = PublicKey::from_secret_key(&nonce).map_err(ReceiveError::Signing)?;
    let message = contribution
        .message
        .map(|text| sign_message(text, &blinding, &public_excess, rng))
        .transpose()?;
    let sender = slate.participant(Role::Sender).ok_or(ReceiveError::Slate(
        SlateError::MissingParticipant {
            stage: slate.stage(),
            role: Role::Sender,
        },
    ))?;
    let nonce_sum =
        PublicKey::sum(&[sender.public_nonce, public_nonce]).map_err(ReceiveError::Signing)?;
    let excess_sum = PublicKey::sum(&[sender.public_blind_excess, public_excess])
        .map_err(ReceiveError::Signing)?;
    let partial_signature = calculate_partial_sig(
        &blinding,
        &nonce,
        &nonce_sum,
        Some(&excess_sum),
        &slate.kernel_features().signature_message(),
    )
    .map_err(ReceiveError::Signing)?;

    let proof_signature = match slate.payment_proof() {
        Some(proof) => {
            let payments;
            let key = match contribution.proof_key {
                Some(key) => key,
                None => {
                    payments = keychain
                        .payment_proof_key(&contribution.parent, PAYMENT_PROOF_KEY_INDEX)?;
                    payments.expose_signing_key()
                }
            };
            if &key.verifying_key().to_bytes() != proof.receiver_address.as_bytes() {
                return Err(ReceiveError::ForeignProofAddress);
            }
            // A native S1 carries no body; the excess the kernel will have is then the sum
            // of both parties' public excesses.
            let excess = if slate.inputs().is_empty() {
                Commitment::from_public_key(&excess_sum).map_err(ReceiveError::Signing)?
            } else {
                kernel_excess(&slate, &output)?
            };
            let mut signed = Vec::with_capacity(8 + Commitment::LEN + 32);
            signed.extend_from_slice(&amount.to_be_bytes());
            signed.extend_from_slice(excess.as_bytes());
            signed.extend_from_slice(proof.sender_address.as_bytes());
            let signature = key.sign(&signed);
            Some(ProofSignature::from_bytes(signature.to_bytes()))
        }
        None => None,
    };

    let receiver = Participant {
        public_blind_excess: public_excess,
        public_nonce,
        partial_signature: Some(partial_signature),
        message,
    };
    let received = slate
        .receive(Receipt {
            receiver,
            outputs: vec![output.clone()],
            proof_signature,
        })
        .map_err(ReceiveError::Slate)?;
    Ok((sorted_outputs(received)?, output))
}

/// The slate with an offset, and the receiver's excess key. Upstream lets whoever adds data
/// first draw the offset and subtract it from its own key; a sender always has, so this only
/// draws one for an S1 whose offset is zero.
fn with_offset(
    slate: &Slate,
    output_key: SecretKey,
    rng: &mut (impl CryptoRng + ?Sized),
) -> Result<(Slate, SecretKey), ReceiveError> {
    if !slate.offset().is_zero() {
        return Ok((slate.clone(), output_key));
    }
    let offset = create_secnonce(rng).map_err(ReceiveError::Signing)?;
    let blinding = SecretKey::sum(&[output_key], std::slice::from_ref(&offset))
        .map_err(ReceiveError::Signing)?;
    let mut parts: SlateParts = slate.clone().into_parts();
    parts.offset = BlindingFactor::from_secret_key(&offset);
    let slate = Slate::from_parts(parts).map_err(ReceiveError::Slate)?;
    Ok((slate, blinding))
}

/// Upstream checks the fee against the transaction as it will be once the receiver's output is
/// in. Its second check, that this fee does not exceed amount plus fee, follows from the first.
///
/// A native S1 carries no inputs, so the sender's are unknown and the weight is bounded from
/// below, at one base fee; the sender's finalize and the node enforce the real minimum.
fn check_fee(slate: &Slate, base_fee: Fee) -> Result<(), ReceiveError> {
    let inputs = match slate.inputs().len() {
        0 => u64::MAX,
        len => count(len),
    };
    let counts = BodyCounts::new(inputs, count(slate.outputs().len()).saturating_add(1), 1);
    let minimum = counts
        .tx_fee(base_fee)
        .map_err(|_| ReceiveError::FeeOverflow)?;
    if slate.fee() < minimum {
        return Err(ReceiveError::FeeBelowMinimum {
            fee: slate.fee(),
            minimum,
        });
    }
    Ok(())
}

fn sign_message(
    text: &str,
    blinding: &SecretKey,
    public_excess: &PublicKey,
    rng: &mut (impl CryptoRng + ?Sized),
) -> Result<ParticipantMessage, ReceiveError> {
    let text = ParticipantMessage::truncate(text);
    let nonce = create_secnonce(rng).map_err(ReceiveError::Signing)?;
    let signature = sign_single(&message_digest(text), blinding, &nonce, Some(public_excess))
        .map_err(ReceiveError::Signing)?;
    ParticipantMessage::new(text.to_owned(), signature).map_err(ReceiveError::Slate)
}

/// `calc_excess`: the outputs, including the receiver's, plus the fee, less the inputs and the
/// offset. The payment proof signs it, since it names the kernel the transaction will have.
fn kernel_excess(slate: &Slate, own_output: &Output) -> Result<Commitment, ReceiveError> {
    let mut outputs = slate.outputs().to_vec();
    outputs.push(own_output.clone());
    let body = TransactionBody::from_parts(slate.inputs().to_vec(), outputs, Vec::new());
    let total = sum_commitments(&body, slate.fee().value()).map_err(ReceiveError::Excess)?;
    if slate.offset().is_zero() {
        return Ok(total);
    }
    let offset = slate
        .offset()
        .to_secret_key()
        .map_err(|error| ReceiveError::Excess(KernelSumError::InvalidOffset(error)))?;
    let offset = Commitment::commit(0, &offset)
        .map_err(|error| ReceiveError::Excess(KernelSumError::Excesses(error)))?;
    Commitment::sum(&[total], &[offset])
        .map_err(|error| ReceiveError::Excess(KernelSumError::Excesses(error)))
}

/// Upstream inserts the output into the body in hash order, as the node requires.
fn sorted_outputs(slate: Slate) -> Result<Slate, ReceiveError> {
    let mut parts = slate.into_parts();
    parts.outputs.sort_by_cached_key(Hashed::hash);
    Slate::from_parts(parts).map_err(ReceiveError::Slate)
}

fn store_response(
    repos: &mut dyn Repositories,
    response: &Response,
    reply: &WireSlate,
    codec: &str,
    transport: TransportId,
    now: jiff::Timestamp,
) -> Result<TxId, ReceiveError> {
    let slate = &response.slate;
    let slate_id = Uuid::from_bytes(*slate.id().as_bytes());
    let tx_id = repos.insert_transaction(&TransactionEntry {
        account: response.account,
        direction: TxDirection::Incoming,
        state: TxState::Received,
        slate_id: Some(slate_id),
        transport: Some(transport.as_str().to_owned()),
        amount_credited: slate.amount(),
        amount_debited: lepic_primitives::amount::Amount::ZERO,
        fee: None,
        created_at: now,
        updated_at: now,
    })?;
    repos.insert_output(&OutputRecord {
        id: response.output.identifier(),
        key_id: KeyId(response.key_id.to_bytes()),
        account: response.account,
        amount: slate.amount(),
        status: OutputStatus::Unconfirmed,
        height: slate.height(),
        lock_height: Height::ZERO,
        mmr_index: None,
        tx: Some(tx_id),
    })?;
    repos.insert_slate(&StoredSlate {
        slate_id,
        stage: SlateStage::Standard2,
        codec: codec.to_owned(),
        bytes: reply.as_bytes().to_vec(),
    })?;
    Ok(tx_id)
}

/// Lengths of in-memory collections always fit `u64`.
fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}
