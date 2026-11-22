// SPDX-License-Identifier: Apache-2.0
//! Slates exchanged in person (RFC 0003 §9): a code shown on one screen and scanned by the
//! other wallet, answered sealed to the code's reply key.
//!
//! The payee shows an I1 as raw `lepic.v1` bytes. Its tail names the reply key (record 01),
//! derived from the slate id, and, when the wallet is online, a reply mailbox on the wallet's
//! own relay (record 02). The payer scans it, pays it, and seals the I2 to the reply key in an
//! anonymous type 0A envelope; the envelope is posted to the reply mailbox or shown back. A
//! sender shows an S1 the same way, and the receiver answers it with a sealed S2; the S1's
//! inputs stay locked until an answer is finalized or the TTL passes.
//!
//! Nothing here finalizes by itself. Each answer that checks is stored with its check code and
//! told with [`Event::InPersonAnswer`]; the user picks the answer to finalize. The check code
//! is four digits of the answering party's public excess, the payer's for an I2 and the
//! receiver's for an S2: both screens show the same digits for the same answer, and two
//! answers with the same digits are flagged.
//!
//! Raw `lepic.v1` is read only here, from a scan: file and paste paths keep refusing it.

use std::collections::HashSet;
use std::path::PathBuf;

use jiff::Timestamp;
use lepic_crypto::PublicKey;
use lepic_epic1::{MethodId, RouteEntry};
use lepic_epicbox::{
    EpicboxAddress, Identity, MailboxContent, MailboxMessage, RelayEndpoint, Security,
};
use lepic_keychain::Keychain;
use lepic_methods::epicbox::relay_network;
use lepic_native_slate::{
    DirectEntry, DirectMethod, DirectRoute, NativeError, NativeSlate, ReplyKey as TailReplyKey,
    ReplyMailbox, Tail,
};
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::amount::{Amount, Fee};
use lepic_primitives::error_chain::ErrorChain;
use lepic_primitives::params::Network;
use lepic_seal::{
    ArmorMarker, EncPublicKey, EncSecretKey, Hint, HintRule, KeyClass, SealedEnvelope, TxContent,
    TxKey, armor_tx, dearmor_marked, seal_tx,
};
use lepic_slate::model::{Slate, SlateId};
use lepic_slate::stage::Stage;
use lepic_slate::ur_slate::{UrBinary, UrContent, decode_ur_parts};
use lepic_store::{
    AccountIndex, MailClass, OutboxState, Repositories, SlateStage, StoreError, TxId, TxState,
    WalletStore, WatchRow,
};
use lepic_transport::host_rule::{self, HostReport};
use lepic_transport::transport::{BoxFuture, Location};
use lepic_wallet::account::{DEFAULT_ACCOUNT_LABEL, parent_key_id};
use lepic_wallet::event::{Event, InPersonAnswerEvent, InPersonAnswerRefusedEvent};
use lepic_wallet::finalize::{FinalizeError, Finalized};
use lepic_wallet::invoice::{INVOICE_TTL_MARGIN_BLOCKS, InvoiceError, InvoiceRequest, PayRequest};
use lepic_wallet::namespace::check_code;
use lepic_wallet::ports::{SecretVault, StoreOpener};
use lepic_wallet::receive::ReceiveRequest;
use lepic_wallet::selection::SelectionOptions;
use lepic_wallet::send::{Delivery, SendRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::address_proof::domain_signer;
use super::collect::{Job, passes};
use super::delivery::epicbox::{Envelope, PostError, Posted};
use super::delivery::outbox::{self, Owed, Sender};
use super::delivery::router::{Handler, Hold, Pushed, Stored};
use super::direct::InPersonDirect;
use super::keys::contact_network;
use super::relay::{check_online, mailbox_host, parse_host};
use super::{ContactError, ContactRelays, LockedRng, RelayMode};
use crate::{ContactBook, file_method, hex};

/// The TTL of an in-person code, in blocks past the chain tip, for a caller that passes no
/// `ttl_blocks` (the CLI, tests). The expiry is the app's choice: an app passes its own, and
/// LEPIC refuses one at or under [`INVOICE_TTL_MARGIN_BLOCKS`].
pub const IN_PERSON_TTL_BLOCKS: u64 = 30;

/// How many different answers a code keeps. Anyone who saw the code can seal an answer to its
/// reply key, so the answers past this many are dropped.
pub const MAX_ANSWERS_PER_CODE: usize = 16;

/// The state of a code this wallet showed, by slate id.
const CODE_PREFIX: &str = "inperson.code.";

/// The state of an answer this wallet made to a code it scanned, by slate id.
const REPLY_PREFIX: &str = lepic_wallet::IN_PERSON_REPLY_PREFIX;

/// Refuses a TTL the payer would refuse from the start: it stops paying `margin` blocks
/// before the cutoff.
fn check_ttl(ttl_blocks: u64) -> Result<u64, ContactError> {
    if ttl_blocks <= INVOICE_TTL_MARGIN_BLOCKS {
        return Err(refused(InPersonRefusal::TtlTooShort {
            margin: INVOICE_TTL_MARGIN_BLOCKS,
        }));
    }
    Ok(ttl_blocks)
}

/// Why an in-person call refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum InPersonRefusal {
    /// The code carries a payment proof: an in-person code never does.
    #[error("the code carries a payment proof")]
    Proof,
    /// The code names no reply key (record 01).
    #[error("the code names no reply key")]
    NoReplyKey,
    /// The code has no TTL.
    #[error("the code has no TTL")]
    NoTtl,
    /// The TTL is at or under the margin before the cutoff where the payer refuses, so the
    /// code could never be paid.
    #[error("the TTL must be more than {margin} blocks")]
    TtlTooShort {
        /// [`INVOICE_TTL_MARGIN_BLOCKS`].
        margin: u64,
    },
    /// The slate is at a stage this call does not take.
    #[error("the slate is at a stage this call does not take")]
    WrongStage,
    /// The answer is for another slate than the code its key opened.
    #[error("the answer is for another slate")]
    OtherSlate,
    /// The answer is signed: an answer to an in-person code is anonymous.
    #[error("the answer is signed")]
    Signed,
    /// The answer names a reply mailbox (tag 09): an answer names none.
    #[error("the answer names a reply mailbox")]
    ReplyMailboxTag,
    /// The code already holds [`MAX_ANSWERS_PER_CODE`] answers; one more is dropped.
    #[error("the code already holds all the answers it keeps")]
    TooManyAnswers,
    /// This wallet holds no in-person code or answer for the slate.
    #[error("no in-person code for this slate")]
    NoCode,
    /// No answer with that number was taken for the code.
    #[error("no such answer to this code")]
    NoAnswer,
    /// A stored answer could not be read.
    #[error("a stored answer could not be read")]
    StoredAnswer,
    /// The code's reply mailbox is a loopback or unspecified host.
    #[error("the reply mailbox is a loopback or unspecified host")]
    Loopback,
    /// The code named no reply mailbox: show the answer instead.
    #[error("the code names no reply mailbox")]
    NoMailbox,
    /// The scanned parts do not make a whole envelope yet.
    #[error("the scanned parts are not complete")]
    UrIncomplete,
    /// The answer's transaction was cancelled or has ended: it is not posted.
    #[error("the transaction was cancelled or has ended")]
    Ended,
    /// The slate is the answer to an in-person code this wallet showed: it is finalized only
    /// with its check code, through [`ContactBook::in_person_take`] and
    /// [`ContactBook::in_person_finalize`].
    #[error("an answer to an in-person code is finalized with its check code")]
    AnswerToCode,
    /// A direct route entry is not an `http` or `tor` address a code can carry, or there are
    /// more entries than a code carries.
    #[error("the direct route is not one a code can carry")]
    DirectRoute,
    /// The slate id names a code issued before for another account, amount or message: a
    /// repeat issues nothing new and returns the stored code only for the same request.
    #[error("this slate id was issued before with another account, amount or message")]
    RepeatDiffers,
}

/// An in-person invoice to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonInvoiceRequest {
    pub account: AccountIndex,
    pub amount: Amount,
    pub message: Option<String>,
    /// Blocks past the chain tip, more than [`INVOICE_TTL_MARGIN_BLOCKS`];
    /// [`IN_PERSON_TTL_BLOCKS`] when `None`.
    pub ttl_blocks: Option<u64>,
    /// The slate id to issue under; a new one when `None`. Issuing an id again while its code
    /// is stored returns the stored code and issues nothing.
    pub slate_id: Option<SlateId>,
    /// Where the payer may also post the answer directly (tail record 0x81): `http` and `tor`
    /// entries, at most [`lepic_native_slate::MAX_DIRECT_ENTRIES`], in the payee's order.
    pub direct: Vec<RouteEntry>,
    /// Signs the code with the wallet's domain key for this domain (tail record 0xF0).
    pub claim: Option<ClaimSigner>,
    /// The answers come to the account's one shared reply slot rather than a slot for this
    /// code only: a service showing many codes watches one mailbox.
    pub shared_slot: bool,
}

/// The domain a code is signed for. The key is the wallet's own domain key
/// ([`ContactBook::own_domain_key`]); the domain's file must list it for a payer to see the
/// domain as checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSigner {
    pub domain: String,
}

/// A code this wallet made, to show as a QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonCode {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The raw `lepic.v1` bytes to show.
    pub bytes: Vec<u8>,
    /// The height from which the code is refused.
    pub ttl_cutoff: u64,
    /// The reply mailbox's relay, `domain[:port]`, when the code names one.
    pub mailbox: Option<String>,
}

/// What a scanned code asks, as the host shows it before the user pays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonRead {
    pub slate_id: SlateId,
    pub stage: Stage,
    pub amount: Amount,
    /// The fee this wallet would pay for an I1, when it can tell now.
    pub fee: Option<Fee>,
    /// The message of the party that made the code.
    pub message: Option<String>,
    pub ttl_cutoff: u64,
    /// The relay of the code's reply mailbox, when it names one.
    pub mailbox: Option<HostReport>,
    /// The domain the code is signed for, as the code claims it: check it with
    /// [`crate::verify_request`] against the domain's file before showing it as proven.
    pub claim: Option<crate::Claim>,
    /// The direct routes the code names, in the payee's order.
    pub direct: Vec<RouteEntry>,
}

/// Whether the well-known file `file`, fetched from the domain the request claim of the scanned
/// code `code` names, proves the claim on the chain `network`: [`crate::verify_request`] for a
/// wallet's network. Needs no wallet; nothing is fetched or stored.
pub fn in_person_request_verify(
    code: &[u8],
    file: &[u8],
    network: Network,
) -> crate::RequestVerdict {
    crate::verify_request(code, file, contact_network(network))
}

/// How a post of an answer to one route went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InPersonPostOutcome {
    /// The mailbox stored it, or the payee's listener took the answer.
    Accepted,
    /// The payee's listener refused the answer, with its reason when it gave one
    /// (`already_finalized`, `expired`, `inputs_spent`, `bad_answer`).
    Refused { reason: Option<String> },
    /// The route could not be reached or was not tried (`tor_expected`: an `http` route in
    /// Tor-only mode).
    Failed { reason: String },
}

/// The post of an answer to one route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonRoutePost {
    /// The reply mailbox as an `epicbox` route, or a direct `http` or `tor` route.
    pub route: RouteEntry,
    pub outcome: InPersonPostOutcome,
}

/// What [`ContactBook::in_person_post`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonPosted {
    /// The answer's check code, to show now that it is posted.
    pub check_code: String,
    /// One per route, the reply mailbox first.
    pub routes: Vec<InPersonRoutePost>,
}

impl InPersonPosted {
    /// Whether any route took the answer.
    pub fn accepted(&self) -> bool {
        self.routes
            .iter()
            .any(|post| post.outcome == InPersonPostOutcome::Accepted)
    }
}

/// An answer this wallet made to a scanned code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonPaid {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The sealed answer, to show when it is not posted.
    pub envelope: Vec<u8>,
    /// The check code the other screen shows for this answer. Show it only once the answer is
    /// posted, as [`ContactBook::in_person_post`] returns it.
    pub check_code: String,
    pub mailbox: Option<HostReport>,
}

/// An answer to a code this wallet showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonAnswerView {
    /// From 1, in the order the answers were taken.
    pub number: u32,
    pub check_code: String,
    /// An earlier answer had the same check code.
    pub same_code: bool,
    pub received_at: Timestamp,
}

/// A code this wallet showed, with its answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonCodeView {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The stage of the code: I1 or S1.
    pub stage: Stage,
    pub ttl_cutoff: u64,
    pub mailbox: Option<String>,
    /// An answer that checks arrived: the code is no longer shown. Answers still arriving
    /// before its TTL are recorded.
    pub closed: bool,
    /// The answer that was finalized.
    pub finalized: Option<u32>,
    pub answers: Vec<InPersonAnswerView>,
}

/// An answer taken for a code this wallet showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonTaken {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub stage: Stage,
    pub answer: u32,
    pub check_code: String,
    pub same_code: bool,
    /// The same answer was taken before; nothing changed.
    pub duplicate: bool,
}

/// What kind of code a state belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CodeKind {
    Invoice,
    Send,
}

impl CodeKind {
    const fn proposal(self) -> Stage {
        match self {
            Self::Invoice => Stage::I1,
            Self::Send => Stage::S1,
        }
    }

    const fn answer(self) -> Stage {
        match self {
            Self::Invoice => Stage::I2,
            Self::Send => Stage::S2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodeState {
    tx_id: u32,
    account: u32,
    kind: CodeKind,
    ttl_cutoff: u64,
    mailbox: Option<String>,
    closed: bool,
    finalized: Option<u32>,
    answers: Vec<StoredAnswer>,
    /// The answers come to the account's shared reply slot. Codes stored before it are false.
    #[serde(default)]
    shared_slot: bool,
    /// The code's `lepic.v1` bytes, hex, so issuing its slate id again returns it. Codes
    /// stored before it have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bytes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAnswer {
    number: u32,
    check_code: String,
    /// The answer's `lepic.v1` bytes, hex.
    body: String,
    same_code: bool,
    /// Unix seconds.
    received_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplyState {
    tx_id: u32,
    account: u32,
    kind: CodeKind,
    /// The sealed answer, hex.
    envelope: String,
    /// The reply mailbox's key, hex, and relay, when the code names one.
    mailbox_key: Option<String>,
    mailbox: Option<String>,
    check_code: String,
    /// Set by a wallet made before the outbox once it posted the answer; read by the fill.
    posted: bool,
    /// The direct routes the code named, as `(method, value)`. Answers stored before them
    /// have none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    direct: Vec<(String, String)>,
}

fn code_key(slate_id: SlateId) -> String {
    format!("{CODE_PREFIX}{slate_id}")
}

/// Whether this wallet showed an in-person code for `slate_id`.
pub(crate) fn has_code(repos: &dyn Repositories, slate_id: SlateId) -> Result<bool, StoreError> {
    Ok(repos.setting(&code_key(slate_id))?.is_some())
}

/// The watch row of the reply mailbox of each code that waits for answers: its transaction
/// open, no answer finalized and a mailbox named, on the mailbox's relay, until one of those
/// ends.
pub(crate) fn in_person_rows(
    repos: &dyn Repositories,
) -> Result<Vec<(WatchRow, Job)>, ContactError> {
    let mut rows = Vec::new();
    for (key, text) in repos.settings_with_prefix(CODE_PREFIX)? {
        let parsed = key
            .strip_prefix(CODE_PREFIX)
            .and_then(|id| SlateId::parse(id).ok())
            .zip(from_text::<CodeState>(&text, "in-person code").ok());
        let Some((slate_id, state)) = parsed else {
            continue;
        };
        let open = repos
            .transaction(TxId(state.tx_id))?
            .is_some_and(|tx| matches!(tx.state, TxState::Received | TxState::Sent));
        let (true, None, Some(relay)) = (open, state.finalized, state.mailbox) else {
            continue;
        };
        let (key_ref, job) = if state.shared_slot {
            let account = AccountIndex(state.account);
            (slot_ref(account), Job::Slot(account))
        } else {
            (
                format!("inperson:{slate_id}"),
                Job::Code(slate_id, AccountIndex(state.account)),
            )
        };
        // The codes sharing a slot share its one row, kept while any of them waits.
        if rows
            .iter()
            .any(|(row, _): &(WatchRow, Job)| row.key_ref == key_ref && row.relay == relay)
        {
            continue;
        }
        rows.push((
            WatchRow {
                key_ref,
                relay,
                class: MailClass::InPerson,
                expires_at: None,
            },
            job,
        ));
    }
    Ok(rows)
}

/// The watch-row key of the shared reply slot of `account`.
fn slot_ref(account: AccountIndex) -> String {
    format!("inperson-slot:{}", account.0)
}

fn reply_key(slate_id: SlateId) -> String {
    format!("{REPLY_PREFIX}{slate_id}")
}

fn refused(refusal: InPersonRefusal) -> ContactError {
    ContactError::InPerson(refusal)
}

fn native_error(error: NativeError) -> ContactError {
    match error {
        NativeError::ProofInInvoice => refused(InPersonRefusal::Proof),
        error => ContactError::Native(error),
    }
}

pub(crate) fn corrupt(field: &'static str) -> StoreError {
    StoreError::Corrupt {
        record: lepic_store::Record::Setting,
        field,
    }
}

pub(crate) fn to_text<T: Serialize>(value: &T, field: &'static str) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| corrupt(field))
}

pub(crate) fn from_text<T: for<'de> Deserialize<'de>>(
    text: &str,
    field: &'static str,
) -> Result<T, StoreError> {
    serde_json::from_str(text).map_err(|_| corrupt(field))
}

fn load_code(repos: &dyn Repositories, slate_id: SlateId) -> Result<CodeState, ContactError> {
    let text = repos
        .setting(&code_key(slate_id))?
        .ok_or(refused(InPersonRefusal::NoCode))?;
    Ok(from_text(&text, "in-person code")?)
}

fn load_reply(repos: &dyn Repositories, slate_id: SlateId) -> Result<ReplyState, ContactError> {
    let text = repos
        .setting(&reply_key(slate_id))?
        .ok_or(refused(InPersonRefusal::NoCode))?;
    Ok(from_text(&text, "in-person answer")?)
}

/// The code among `codes`, stored settings, finalized or not, whose reply key the hint `hint` of an
/// envelope with the ephemeral key `enc` names, with its state and reply key.
fn code_for_hint(
    codes: Vec<(String, String)>,
    keychain: &Keychain,
    network: Network,
    hint: Hint,
    enc: &[u8; 32],
) -> Result<Option<(SlateId, CodeState, EncSecretKey)>, ContactError> {
    for (key, text) in codes {
        let Some(slate_id) = key
            .strip_prefix(CODE_PREFIX)
            .and_then(|id| SlateId::parse(id).ok())
        else {
            continue;
        };
        let Ok(state) = from_text::<CodeState>(&text, "in-person code") else {
            continue;
        };
        let secret = reply_secret(keychain, network, AccountIndex(state.account), slate_id)?;
        if Hint::reply(&secret.public_key(), enc) == hint {
            return Ok(Some((slate_id, state, secret)));
        }
    }
    Ok(None)
}

/// Records the answer `body`, hex, with the check code `code` for the code of `slate_id`, and
/// closes the code. Returns the answer's number, whether an earlier answer had the same check
/// code, and whether this answer was recorded before, when nothing changes. Fails with
/// [`InPersonRefusal::TooManyAnswers`] for a new answer when the code holds
/// [`MAX_ANSWERS_PER_CODE`].
fn record_answer(
    repos: &mut dyn Repositories,
    slate_id: SlateId,
    body: String,
    code: String,
    now: Timestamp,
) -> Result<(u32, bool, bool), ContactError> {
    let mut state = load_code(repos, slate_id)?;
    if let Some(earlier) = state.answers.iter().find(|answer| answer.body == body) {
        return Ok((earlier.number, earlier.same_code, true));
    }
    if state.answers.len() >= MAX_ANSWERS_PER_CODE {
        return Err(refused(InPersonRefusal::TooManyAnswers));
    }
    let same_code = state.answers.iter().any(|answer| answer.check_code == code);
    let number = u32::try_from(state.answers.len())
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    state.answers.push(StoredAnswer {
        number,
        check_code: code,
        body,
        same_code,
        received_at: now.as_second(),
    });
    state.closed = true;
    repos.put_setting(&code_key(slate_id), &to_text(&state, "in-person code")?)?;
    Ok((number, same_code, false))
}

/// Why an answer to a code was refused for good, as [`Event::InPersonAnswerRefused`] and a
/// direct route's listener say it: `already_finalized`, `cancelled`, `expired`, `inputs_spent`
/// or `bad_answer`. `None` for a failure that passes, such as the node not answering: the
/// answer is taken again later.
pub(crate) fn refusal_reason(error: &ContactError) -> Option<&'static str> {
    if passes(error) {
        return None;
    }
    Some(match error {
        ContactError::Invoice(InvoiceError::AlreadyFinalized { .. })
        | ContactError::Finalize(FinalizeError::AlreadyFinalized { .. }) => "already_finalized",
        ContactError::Invoice(InvoiceError::NotFinalizable {
            state: TxState::Cancelled,
            ..
        })
        | ContactError::Finalize(FinalizeError::NotFinalizable {
            state: TxState::Cancelled,
            ..
        }) => "cancelled",
        ContactError::Invoice(
            InvoiceError::Expired { .. } | InvoiceError::NotFinalizable { .. },
        )
        | ContactError::Finalize(
            FinalizeError::Expired { .. } | FinalizeError::NotFinalizable { .. },
        ) => "expired",
        ContactError::Invoice(InvoiceError::AnswerInputsSpent { .. })
        | ContactError::Finalize(FinalizeError::PeerInputsSpent { .. }) => "inputs_spent",
        _ => "bad_answer",
    })
}

/// The reply key of the slate `slate_id` of `account`: answers to its code are sealed to it.
pub(crate) fn reply_secret(
    keychain: &Keychain,
    network: Network,
    account: AccountIndex,
    slate_id: SlateId,
) -> Result<EncSecretKey, ContactError> {
    let root = crate::key_schedule::contact_root(keychain, &parent_key_id(account)?, network)
        .map_err(ContactError::Keys)?;
    let reply = root
        .reply_key(*slate_id.as_bytes())
        .map_err(ContactError::Keys)?;
    Ok(EncSecretKey::from_bytes(*reply.expose_x25519_secret()))
}

/// The answering party's public excess: the payer's for an I2, the receiver's for an S2. The
/// check code is made from it.
fn answering_excess(slate: &Slate) -> Result<PublicKey, ContactError> {
    slate
        .participant(slate.flow().responder())
        .map(|participant| participant.public_blind_excess)
        .ok_or(refused(InPersonRefusal::WrongStage))
}

/// An identity on `relay` with the key `secret`.
pub(crate) fn identity(
    secret: lepic_crypto::SecretKey,
    network: Network,
    relay: &RelayEndpoint,
) -> Result<Identity, ContactError> {
    let public = PublicKey::from_secret_key(&secret).map_err(|_| ContactError::RelayAddress)?;
    let address = EpicboxAddress::new(
        public,
        relay_network(network),
        relay.domain().clone(),
        Some(relay.port()),
    );
    Identity::new(secret, address).map_err(|_| ContactError::RelayAddress)
}

/// The endpoint of the reply mailbox relay `host`, `domain[:port]`, and what the user is
/// shown about it. A mailbox of the wallet's list is reached as the
/// wallet reaches it; any other over TLS. A loopback or unspecified host is refused, a known
/// one too; an address on a local network is allowed and reported as such.
pub(crate) fn mailbox_endpoint(
    host: &str,
    relays: &ContactRelays,
) -> Result<(RelayEndpoint, HostReport), ContactError> {
    let (domain, port) = parse_host(host)?;
    let class = host_rule::classify_name(domain.as_str())
        .map_err(|_| refused(InPersonRefusal::Loopback))?;
    if port == Some(0) {
        return Err(ContactError::RelayAddress);
    }
    let known = known_endpoint(relays, &domain, port);
    let in_relay_list = known.is_some();
    let endpoint = known.unwrap_or_else(|| RelayEndpoint::new(domain, port, Security::Tls));
    let report = HostReport {
        host: endpoint.domain().to_string(),
        port: endpoint.port(),
        in_relay_list,
        class,
    };
    Ok((endpoint, report))
}

/// Stores in the outbox, in the caller's write, each in-person answer posted before the
/// outbox as a posted row, so how far it got reads from the outbox. An answer that has outbox
/// rows, or whose transaction ended, is left as it is. Returns the rows stored.
pub(crate) fn fill_outbox(
    repos: &mut dyn Repositories,
    network: Network,
    relays: &ContactRelays,
    now: Timestamp,
) -> Result<usize, ContactError> {
    let mut stored = 0usize;
    for (key, text) in repos.settings_with_prefix(REPLY_PREFIX)? {
        let parsed = key
            .strip_prefix(REPLY_PREFIX)
            .and_then(|id| SlateId::parse(id).ok())
            .zip(from_text::<ReplyState>(&text, "in-person answer").ok());
        let Some((slate_id, state)) = parsed.filter(|(_, state)| state.posted) else {
            continue;
        };
        let payment_id = Uuid::from_bytes(*slate_id.as_bytes());
        let open = repos
            .transaction(TxId(state.tx_id))?
            .is_some_and(|tx| !ended(tx.state));
        if !open || !repos.native_outbox_of(payment_id)?.is_empty() {
            continue;
        }
        let Some(owed) = state.owed(network, relays, slate_id) else {
            continue;
        };
        outbox::enqueue_as(repos, &owed, OutboxState::Posted, now)?;
        stored = stored.saturating_add(1);
    }
    Ok(stored)
}

impl ReplyState {
    /// The answer's post to the reply mailbox its code named, when it named one and the
    /// record reads.
    fn owed(&self, network: Network, relays: &ContactRelays, slate_id: SlateId) -> Option<Owed> {
        let (Some(key), Some(host)) = (&self.mailbox_key, &self.mailbox) else {
            return None;
        };
        let route = reply_route(network, relays, key, host, "in-person answer").ok()?;
        let envelope = hex::unhex(&self.envelope)?;
        Some(Owed {
            payment_id: Uuid::from_bytes(*slate_id.as_bytes()),
            sender: Sender::Payee(AccountIndex(self.account)),
            route,
            envelope: armor_tx(&envelope),
            cutoff: None,
            stage: Some(match self.kind {
                CodeKind::Invoice => SlateStage::Invoice2,
                CodeKind::Send => SlateStage::Standard2,
            }),
            notice: false,
        })
    }
}

/// The reason of a direct route not tried in Tor-only mode.
const TOR_EXPECTED: &str = "tor_expected";

impl ReplyState {
    /// The direct routes the code named, those of a method this wallet posts by.
    fn direct_routes(&self) -> Vec<RouteEntry> {
        self.direct
            .iter()
            .filter_map(|(method, value)| {
                let method = method.parse::<MethodId>().ok()?;
                matches!(method, MethodId::Http | MethodId::Tor).then(|| RouteEntry {
                    method,
                    value: value.clone(),
                })
            })
            .collect()
    }
}

/// What a post to a direct route did: taken, refused by the payee's listener with its reason,
/// or not delivered.
fn direct_outcome(posted: Result<Posted, PostError>) -> InPersonPostOutcome {
    match posted {
        Ok(_) => InPersonPostOutcome::Accepted,
        Err(PostError::Refused {
            reason,
            retryable: false,
            ..
        }) => InPersonPostOutcome::Refused { reason },
        Err(error) => InPersonPostOutcome::Failed {
            reason: ErrorChain(&error).to_string(),
        },
    }
}

impl InPersonPostOutcome {
    /// The outcome's name, for logs.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Refused { .. } => "refused",
            Self::Failed { .. } => "failed",
        }
    }
}

/// The route of a post to the reply mailbox of key `mailbox_key`, hex, on the relay `host`:
/// its Epicbox address. `what` names the record the key was read from.
pub(crate) fn reply_route(
    network: Network,
    relays: &ContactRelays,
    mailbox_key: &str,
    host: &str,
    what: &'static str,
) -> Result<RouteEntry, ContactError> {
    let (endpoint, _) = mailbox_endpoint(host, relays)?;
    let key = hex::unhex(mailbox_key)
        .and_then(|key| PublicKey::from_bytes(&key).ok())
        .ok_or(corrupt(what))?;
    let to = EpicboxAddress::new(
        key,
        relay_network(network),
        endpoint.domain().clone(),
        Some(endpoint.port()),
    );
    let route = RouteEntry {
        method: MethodId::Epicbox,
        value: to.to_string(),
    };
    Ok(route)
}

pub(crate) fn known_endpoint(
    relays: &ContactRelays,
    domain: &lepic_epicbox::Domain,
    port: Option<u16>,
) -> Option<RelayEndpoint> {
    relays
        .list()
        .into_iter()
        .find(|known| known.domain() == domain && port.is_none_or(|port| port == known.port()))
}

/// The code in `bytes` for `network`, refused unless it is a proposal, an I1 or an S1 or only
/// the one of `kind`, with a reply key and a TTL and without a payment proof.
fn read_code(
    network: Network,
    bytes: &[u8],
    kind: Option<CodeKind>,
) -> Result<NativeSlate, ContactError> {
    let native = NativeSlate::decode(network, bytes).map_err(native_error)?;
    let slate = native.slate();
    if slate.payment_proof().is_some() {
        return Err(refused(InPersonRefusal::Proof));
    }
    let proposal = match kind {
        Some(kind) => slate.stage() == kind.proposal(),
        None => matches!(slate.stage(), Stage::I1 | Stage::S1),
    };
    if !proposal {
        return Err(refused(InPersonRefusal::WrongStage));
    }
    if native.tail().reply_key().is_none() {
        return Err(refused(InPersonRefusal::NoReplyKey));
    }
    if slate.ttl_cutoff_height().is_none() {
        return Err(refused(InPersonRefusal::NoTtl));
    }
    Ok(native)
}

/// A reply mailbox an answer is posted to: the mailbox key in hex, the relay and the report
/// on it.
type AnswerMailbox = (String, String, HostReport);

/// What a code carries besides its slate and reply key.
struct CodeMade {
    kind: CodeKind,
    direct: Option<DirectRoute>,
    claim: Option<ClaimSigner>,
    shared_slot: bool,
}

/// The tail record of the direct routes `entries`; none for none. Refuses an `epicbox` entry,
/// an address that is not canonical for its method, a duplicate and too many entries.
fn direct_route(entries: &[RouteEntry]) -> Result<Option<DirectRoute>, ContactError> {
    if entries.is_empty() {
        return Ok(None);
    }
    let entries = entries
        .iter()
        .map(|entry| {
            let method = match entry.method {
                MethodId::Http => DirectMethod::Http,
                MethodId::Tor => DirectMethod::Tor,
                MethodId::Epicbox => return Err(refused(InPersonRefusal::DirectRoute)),
            };
            DirectEntry::new(method, entry.value.clone())
                .map_err(|_| refused(InPersonRefusal::DirectRoute))
        })
        .collect::<Result<Vec<_>, _>>()?;
    DirectRoute::new(entries)
        .map(Some)
        .map_err(|_| refused(InPersonRefusal::DirectRoute))
}

/// The direct routes of the code `native`, as routes.
fn direct_entries(native: &NativeSlate) -> Vec<RouteEntry> {
    native
        .tail()
        .direct_route()
        .map(|route| {
            route
                .entries()
                .iter()
                .map(|entry| RouteEntry {
                    method: match entry.method() {
                        DirectMethod::Http => MethodId::Http,
                        DirectMethod::Tor => MethodId::Tor,
                    },
                    value: entry.address().to_owned(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Where an answer to `native` goes: the reply mailbox it names and the reply key the answer
/// is sealed to.
fn answer_route(
    native: &NativeSlate,
    relays: &ContactRelays,
) -> Result<(Option<AnswerMailbox>, EncPublicKey), ContactError> {
    let mailbox = match native.tail().reply_mailbox() {
        Some(mailbox) => {
            let (_, report) = mailbox_endpoint(mailbox.address(), relays)?;
            Some((
                hex::encode(&mailbox.key().to_bytes()),
                mailbox.address().to_owned(),
                report,
            ))
        }
        None => None,
    };
    let reply_to = native
        .tail()
        .reply_key()
        .map(|key| EncPublicKey::from_bytes(*key.as_bytes()))
        .and_then(Result::ok)
        .ok_or(refused(InPersonRefusal::NoReplyKey))?;
    Ok((mailbox, reply_to))
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Makes an in-person invoice: an I1 to show as raw `lepic.v1`, without a payment proof,
    /// with a TTL ([`IN_PERSON_TTL_BLOCKS`] by default) and the reply key of its slate. When
    /// `relays` are online it also names a reply mailbox on the wallet's own relay, which
    /// collecting then watches until the TTL. The invoice and the code are stored.
    ///
    /// Fails with [`ContactError::InPerson`] when the TTL is at or under
    /// [`INVOICE_TTL_MARGIN_BLOCKS`], and with [`ContactError::Invoice`] as
    /// [`lepic_wallet::Wallet::issue_invoice`] does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn in_person_invoice(
        &self,
        relays: &ContactRelays,
        request: InPersonInvoiceRequest,
    ) -> Result<InPersonCode, ContactError> {
        self.check_contact_network(relays)?;
        let ttl_blocks = check_ttl(request.ttl_blocks.unwrap_or(IN_PERSON_TTL_BLOCKS))?;
        let direct = direct_route(&request.direct)?;
        if let Some(code) = self.stored_code(&request).await? {
            return Ok(code);
        }
        let account = request.account;
        let (tx_id, slate, _) = self
            .wallet
            .issue_unsent_as(
                &file_method(),
                InvoiceRequest {
                    account,
                    amount: request.amount,
                    message: request.message,
                    ttl_blocks: Some(ttl_blocks),
                },
                // Never exported: issue_unsent only records where the slate would go, and a
                // file records no counterparty.
                Delivery::Export {
                    to: Location::File(PathBuf::new()),
                },
                request.slate_id,
            )
            .await
            .map_err(ContactError::Invoice)?;
        let made = CodeMade {
            kind: CodeKind::Invoice,
            direct,
            claim: request.claim,
            shared_slot: request.shared_slot,
        };
        match self.store_code(relays, tx_id, account, slate, made).await {
            Ok(code) => Ok(code),
            Err(error) => Err(self.give_up_send(tx_id, error).await),
        }
    }

    /// Makes an in-person send: an S1 to show as raw `lepic.v1`, as
    /// [`ContactBook::in_person_invoice`] makes an invoice. The send is stored and its inputs
    /// stay locked until an answer is finalized, the TTL passes or it is cancelled.
    ///
    /// Fails with [`ContactError::InPerson`] when `request` asks for a payment proof or a TTL
    /// at or under [`INVOICE_TTL_MARGIN_BLOCKS`], and with
    /// [`ContactError::Send`] as [`lepic_wallet::Wallet::send`] fails before it delivers.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn in_person_send(
        &self,
        relays: &ContactRelays,
        request: SendRequest,
    ) -> Result<InPersonCode, ContactError> {
        if request.payment_proof_recipient.is_some() {
            return Err(refused(InPersonRefusal::Proof));
        }
        self.check_contact_network(relays)?;
        let ttl_blocks = check_ttl(request.ttl_blocks.unwrap_or(IN_PERSON_TTL_BLOCKS))?;
        let account = request.account;
        let request = SendRequest {
            ttl_blocks: Some(ttl_blocks),
            ..request
        };
        let (sent, slate) = self
            .wallet
            .send_unsent(
                &file_method(),
                request,
                // Never exported, as for an in-person invoice.
                Delivery::Export {
                    to: Location::File(PathBuf::new()),
                },
            )
            .await
            .map_err(ContactError::Send)?;
        let made = CodeMade {
            kind: CodeKind::Send,
            direct: None,
            claim: None,
            shared_slot: false,
        };
        match self
            .store_code(relays, sent.tx_id, account, slate, made)
            .await
        {
            Ok(code) => Ok(code),
            Err(error) => Err(self.give_up_send(sent.tx_id, error).await),
        }
    }

    /// The code stored for the slate id `request` names, when it names one whose code holds
    /// its bytes. Fails with [`InPersonRefusal::RepeatDiffers`] when that code is an invoice for
    /// another account, amount or message than `request` asks for.
    async fn stored_code(
        &self,
        request: &InPersonInvoiceRequest,
    ) -> Result<Option<InPersonCode>, ContactError> {
        let Some(slate_id) = request.slate_id else {
            return Ok(None);
        };
        let session = self.wallet.session()?;
        let state = self
            .contact_work(move |_, _| {
                session
                    .store
                    .read(|repos| match repos.setting(&code_key(slate_id))? {
                        Some(text) => Ok::<_, ContactError>(Some(from_text::<CodeState>(
                            &text,
                            "in-person code",
                        )?)),
                        None => Ok(None),
                    })
            })
            .await?;
        let Some(state) = state else {
            return Ok(None);
        };
        let bytes = state
            .bytes
            .as_deref()
            .and_then(hex::unhex)
            .ok_or(corrupt("in-person code"))?;
        let stored = NativeSlate::decode(self.wallet.config().network, &bytes)
            .map_err(|_| corrupt("in-person code"))?
            .into_parts()
            .0;
        let message = stored
            .participant(stored.flow().initiator())
            .and_then(|participant| participant.message.as_ref())
            .map(lepic_slate::model::ParticipantMessage::text);
        if !matches!(state.kind, CodeKind::Invoice)
            || state.account != request.account.0
            || stored.amount() != request.amount
            || message != request.message.as_deref()
        {
            return Err(refused(InPersonRefusal::RepeatDiffers));
        }
        debug!(tx_id = state.tx_id, "in-person code issued before");
        Ok(Some(InPersonCode {
            tx_id: TxId(state.tx_id),
            slate_id,
            bytes,
            ttl_cutoff: state.ttl_cutoff,
            mailbox: state.mailbox,
        }))
    }

    async fn store_code(
        &self,
        relays: &ContactRelays,
        tx_id: TxId,
        account: AccountIndex,
        slate: Slate,
        made: CodeMade,
    ) -> Result<InPersonCode, ContactError> {
        let CodeMade {
            kind,
            direct,
            claim,
            shared_slot,
        } = made;
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let slate_id = slate.id();
        let ttl_cutoff = slate
            .ttl_cutoff_height()
            .ok_or(refused(InPersonRefusal::NoTtl))?
            .value();
        let own = &relays.home();
        let mailbox = match relays.mode {
            // A relay on this device cannot be reached from the other one: the code names
            // none, and the answer is shown back.
            RelayMode::Online if host_rule::classify_name(own.domain().as_str()).is_ok() => {
                let secret = if shared_slot {
                    self.wallet.shared_reply_mailbox_key(account, net)?
                } else {
                    self.wallet
                        .reply_mailbox_key(account, net, slate_id.as_bytes())?
                };
                let public =
                    PublicKey::from_secret_key(&secret).map_err(|_| ContactError::RelayAddress)?;
                Some(
                    ReplyMailbox::new(public, mailbox_host(own))
                        .map_err(|error| native_error(error.into()))?,
                )
            }
            _ => None,
        };
        let host = mailbox.as_ref().map(|mailbox| mailbox.address().to_owned());
        let session = self.wallet.session()?;
        let issued_at = self.wallet.ports().clock.now().as_second();
        let mut state = CodeState {
            tx_id: tx_id.0,
            account: account.0,
            kind,
            ttl_cutoff,
            mailbox: host.clone(),
            closed: false,
            finalized: None,
            answers: Vec::new(),
            shared_slot: shared_slot && host.is_some(),
            bytes: None,
        };
        let bytes = self
            .contact_work(move |_, _| {
                let reply = reply_secret(&session.keychain, network, account, slate_id)?;
                let mut tail = Tail::new(
                    Some(TailReplyKey::from_bytes(*reply.public_key().as_bytes())),
                    mailbox,
                    Vec::new(),
                )
                .map_err(|error| native_error(error.into()))?;
                if let Some(direct) = direct {
                    tail = tail.with_direct_route(direct);
                }
                let mut bytes = NativeSlate::new(slate, tail)
                    .map_err(native_error)?
                    .encode(network);
                // The claim is signed last, over the whole code before it.
                if let Some(claim) = claim {
                    let signer = domain_signer(&session.keychain, network, Some(&claim.domain))?
                        .ok_or(ContactError::Domain(lepic_contact::DomainError::Name))?;
                    // Only an I1 is signed, and only invoices carry a claim.
                    bytes = signer
                        .sign_request(&bytes, net, u64::try_from(issued_at).unwrap_or(0))
                        .map_err(|_| refused(InPersonRefusal::WrongStage))?;
                }
                state.bytes = Some(hex::encode(&bytes));
                let text = to_text(&state, "in-person code")?;
                session.store.write(|repos| {
                    repos.put_setting(&code_key(slate_id), &text)?;
                    Ok::<_, ContactError>(())
                })?;
                Ok(bytes)
            })
            .await?;
        info!(tx_id = %tx_id, online = host.is_some(), shared_slot, "in-person code made");
        Ok(InPersonCode {
            tx_id,
            slate_id,
            bytes,
            ttl_cutoff,
            mailbox: host,
        })
    }

    /// Whether the well-known file `file`, fetched from the domain the request claim of the
    /// scanned code `code` names, proves the claim on this wallet's network: as
    /// [`crate::verify_request`]. Nothing is fetched or stored.
    pub fn in_person_request_verify(&self, code: &[u8], file: &[u8]) -> crate::RequestVerdict {
        in_person_request_verify(code, file, self.wallet.config().network)
    }

    /// Reads a scanned code: raw `lepic.v1`, which only a scan gives. A code with a payment
    /// proof, without a reply key or without a TTL is refused, as is one whose reply mailbox
    /// is a loopback or unspecified host. Nothing is stored. The fee of an I1 is estimated
    /// with `options`, the selection the payment would use.
    ///
    /// Fails with [`ContactError::Native`] for bytes that are not a `lepic.v1` slate of this
    /// network, and [`ContactError::InPerson`] for a code refused.
    pub async fn in_person_read(
        &self,
        relays: &ContactRelays,
        options: SelectionOptions,
        bytes: &[u8],
    ) -> Result<InPersonRead, ContactError> {
        let network = self.wallet.config().network;
        let native = read_code(network, bytes, None)?;
        let mailbox = native
            .tail()
            .reply_mailbox()
            .map(|mailbox| mailbox_endpoint(mailbox.address(), relays).map(|(_, report)| report))
            .transpose()?;
        let slate = native.slate();
        let fee = match slate.stage() {
            Stage::I1 => match self.wallet.estimate_fee(slate.amount(), options).await {
                Ok(selection) => Some(selection.fee),
                Err(error) => {
                    debug!(error = %ErrorChain(&error), "no fee estimate for an in-person code");
                    None
                }
            },
            _ => Some(slate.fee()),
        };
        Ok(InPersonRead {
            slate_id: slate.id(),
            stage: slate.stage(),
            amount: slate.amount(),
            fee,
            message: slate
                .participant(slate.flow().initiator())
                .and_then(|participant| participant.message.as_ref())
                .map(|message| message.text().to_owned()),
            ttl_cutoff: slate
                .ttl_cutoff_height()
                .map_or(0, lepic_primitives::amount::Height::value),
            mailbox,
            claim: crate::request_claim(bytes),
            direct: direct_entries(&native),
        })
    }

    /// Pays a scanned in-person invoice as [`lepic_wallet::Wallet::pay_invoice`] pays one, and
    /// seals the I2 to the code's reply key in an anonymous, padded envelope. The payment and
    /// the envelope are stored; the inputs stay locked until the TTL passes or the payment is
    /// cancelled. Post the envelope with [`ContactBook::in_person_post`] or show it.
    ///
    /// Fails as [`ContactBook::in_person_read`] does, and with [`ContactError::Invoice`] as
    /// paying fails.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn in_person_pay(
        &self,
        relays: &ContactRelays,
        bytes: &[u8],
        request: PayRequest,
    ) -> Result<InPersonPaid, ContactError> {
        let network = self.wallet.config().network;
        let native = read_code(network, bytes, Some(CodeKind::Invoice))?;
        let (mailbox, reply_to) = answer_route(&native, relays)?;
        let direct = direct_entries(&native);
        let (i1, _) = native.into_parts();
        let account = request.account;
        let paid = self
            .wallet
            .pay_decoded(&file_method(), i1, request, None)
            .await
            .map_err(ContactError::Invoice)?;
        let tx_id = paid.tx_id;
        match self
            .store_answer(
                paid.slate,
                tx_id,
                account,
                &reply_to,
                mailbox,
                direct,
                CodeKind::Invoice,
            )
            .await
        {
            Ok(paid) => Ok(paid),
            Err(error) => Err(self.give_up_send(tx_id, error).await),
        }
    }

    /// Receives a scanned in-person send as [`lepic_wallet::Wallet::receive`] receives an S1,
    /// and seals the S2 to the code's reply key in an anonymous, padded envelope. The
    /// transaction and the envelope are stored. Post the envelope with
    /// [`ContactBook::in_person_post`] or show it; the sender finalizes the answer it picks by
    /// the check code returned.
    ///
    /// Fails as [`ContactBook::in_person_read`] does, and with [`ContactError::Receive`] as
    /// receiving fails.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn in_person_receive(
        &self,
        relays: &ContactRelays,
        bytes: &[u8],
        request: ReceiveRequest,
    ) -> Result<InPersonPaid, ContactError> {
        let network = self.wallet.config().network;
        let native = read_code(network, bytes, Some(CodeKind::Send))?;
        let (mailbox, reply_to) = answer_route(&native, relays)?;
        let (s1, _) = native.into_parts();
        let account = self
            .wallet
            .account(request.account.as_deref().unwrap_or(DEFAULT_ACCOUNT_LABEL))?
            .index;
        let received = self
            .wallet
            .receive_decoded(&file_method(), s1, request)
            .await
            .map_err(ContactError::Receive)?;
        let tx_id = received.tx_id;
        match self
            .store_answer(
                received.slate,
                tx_id,
                account,
                &reply_to,
                mailbox,
                Vec::new(),
                CodeKind::Send,
            )
            .await
        {
            Ok(paid) => Ok(paid),
            Err(error) => Err(self.give_up_send(tx_id, error).await),
        }
    }

    #[allow(clippy::too_many_arguments)] // Each is one fact of the answer as stored.
    async fn store_answer(
        &self,
        answer: Slate,
        tx_id: TxId,
        account: AccountIndex,
        reply_to: &EncPublicKey,
        mailbox: Option<AnswerMailbox>,
        direct: Vec<RouteEntry>,
        kind: CodeKind,
    ) -> Result<InPersonPaid, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let slate_id = answer.id();
        let check = check_code(&answering_excess(&answer)?);
        let body = NativeSlate::new(answer, Tail::empty())
            .map_err(native_error)?
            .encode(network);
        let envelope = {
            let mut rng = LockedRng(&mut **self.wallet.ports().rng.lock());
            seal_tx(
                net,
                reply_to,
                TxKey::Seal(HintRule::ReplyKey),
                &TxContent::new(body),
                None,
                &mut rng,
            )
            .map_err(ContactError::Encode)?
        };
        let (mailbox_key, host, report) = match mailbox {
            Some((key, host, report)) => (Some(key), Some(host), Some(report)),
            None => (None, None, None),
        };
        let state = ReplyState {
            tx_id: tx_id.0,
            account: account.0,
            kind,
            envelope: hex::encode(&envelope),
            mailbox_key,
            mailbox: host,
            check_code: check.clone(),
            posted: false,
            direct: direct
                .into_iter()
                .map(|route| (route.method.as_str().to_owned(), route.value))
                .collect(),
        };
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            let text = to_text(&state, "in-person answer")?;
            session.store.write(|repos| {
                repos.put_setting(&reply_key(slate_id), &text)?;
                Ok::<_, ContactError>(())
            })
        })
        .await?;
        info!(tx_id = %tx_id, "in-person answer sealed");
        Ok(InPersonPaid {
            tx_id,
            slate_id,
            envelope,
            check_code: check,
            mailbox: report,
        })
    }

    /// Posts the stored answer to the slate `slate_id` to the reply mailbox its code named,
    /// from a key used for this slate only, through the outbox, and to each direct route the
    /// code named, at once. The outbox stores the mailbox post before it is made, and one
    /// that is sent and not answered is posted again later. The hosts are checked again when
    /// connecting: a name or, connecting directly, any address it resolves to that is loopback
    /// or unspecified is refused, and the connection goes to the addresses checked. Through
    /// Tor the exit resolves the name, so only the name is checked. In Tor-only mode an `http`
    /// direct route is not tried.
    ///
    /// Only an answer whose transaction is still sent or received is posted: once it is
    /// cancelled, the answer no longer moves money. A direct route that refuses the answer
    /// cancels nothing: the caller reads its reason.
    ///
    /// Fails with [`ContactError::InPerson`] when no answer is stored, the code named no
    /// mailbox and no direct route, or the transaction was cancelled or ended
    /// ([`InPersonRefusal::Ended`]), [`ContactError::Offline`], and, for a code that named a
    /// mailbox and no direct route, [`ContactError::Relay`] when the post failed; posting
    /// again is safe.
    ///
    /// Returns the answer's check code, to show once a route took it, and what each route did.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn in_person_post(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
    ) -> Result<InPersonPosted, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let (state, tx_state) = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    let state = load_reply(repos, slate_id)?;
                    let tx_state = repos.transaction(TxId(state.tx_id))?.map(|tx| tx.state);
                    Ok::<_, ContactError>((state, tx_state))
                })
            })
            .await?;
        if !matches!(tx_state, Some(TxState::Sent | TxState::Received)) {
            return Err(refused(InPersonRefusal::Ended));
        }
        let direct = state.direct_routes();
        let mailbox = match (&state.mailbox_key, &state.mailbox) {
            (Some(key), Some(host)) => Some((key, host)),
            _ => None,
        };
        if mailbox.is_none() && direct.is_empty() {
            return Err(refused(InPersonRefusal::NoMailbox));
        }
        let mut routes = Vec::with_capacity(direct.len().saturating_add(1));
        if let Some((key, host)) = mailbox {
            // The route is checked first, so a host refused has its own error.
            let posted = match reply_route(network, relays, key, host, "in-person answer") {
                Ok(route) => {
                    let owed = state
                        .owed(network, relays, slate_id)
                        .ok_or(corrupt("in-person answer"))?;
                    let _turn = self.wallet.contact_turn().await;
                    self.outbox_post_now(relays, owed).await.map(|()| route)
                }
                Err(error) => Err(error),
            };
            match posted {
                Ok(route) => routes.push(InPersonRoutePost {
                    route,
                    outcome: InPersonPostOutcome::Accepted,
                }),
                Err(error) if direct.is_empty() => return Err(error),
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "in-person answer not posted to the mailbox");
                    routes.push(InPersonRoutePost {
                        route: RouteEntry {
                            method: MethodId::Epicbox,
                            value: host.clone(),
                        },
                        outcome: InPersonPostOutcome::Failed {
                            reason: ErrorChain(&error).to_string(),
                        },
                    });
                }
            }
        }
        if !direct.is_empty() {
            let envelope = hex::unhex(&state.envelope).ok_or(corrupt("in-person answer"))?;
            let envelope = Envelope::Sealed(envelope);
            let carrier = outbox::link_carrier(relays);
            for route in direct {
                let outcome = if relays.tor_expected && route.method == MethodId::Http {
                    InPersonPostOutcome::Failed {
                        reason: TOR_EXPECTED.to_owned(),
                    }
                } else {
                    direct_outcome(carrier.post_to_peer(&envelope, &route).await)
                };
                info!(slate_id = %slate_id, method = %route.method, outcome = outcome.label(),
                    "in-person answer posted to a direct route");
                routes.push(InPersonRoutePost { route, outcome });
            }
        }
        info!(slate_id = %slate_id, "in-person answer posted");
        Ok(InPersonPosted {
            check_code: state.check_code,
            routes,
        })
    }

    /// Takes an answer to a code this wallet showed, given offline: the envelope's bytes, or
    /// its `BEGINEPICTX.` armour. It is checked and stored as a collected answer is, and
    /// nothing is finalized.
    ///
    /// Fails with [`ContactError::Decode`] for input that is not such an envelope of this
    /// network, [`ContactError::NotForThisInstall`] when it answers no open code,
    /// [`ContactError::InPerson`] for an answer refused, and [`ContactError::Invoice`] when the
    /// answer does not check.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn in_person_take(&self, input: &[u8]) -> Result<InPersonTaken, ContactError> {
        let envelope = if input.starts_with(&lepic_seal::MAGIC) {
            input.to_vec()
        } else {
            let text = std::str::from_utf8(input)
                .map_err(|_| ContactError::Decode(lepic_seal::DecodeError::Damaged))?;
            match dearmor_marked(text.trim()).map_err(ContactError::Decode)? {
                (bytes, ArmorMarker::Tx) => bytes,
                (_, ArmorMarker::Sealed) => {
                    return Err(ContactError::Decode(lepic_seal::DecodeError::Damaged));
                }
            }
        };
        self.take_envelope(&envelope).await
    }

    /// As [`ContactBook::in_person_take`], for the parts of an animated QR code scanned.
    ///
    /// Fails with [`ContactError::InPerson`] while the parts are incomplete or hold a slate
    /// rather than an envelope.
    pub async fn in_person_take_ur<T: AsRef<str>>(
        &self,
        parts: &[T],
    ) -> Result<InPersonTaken, ContactError> {
        let progress = decode_ur_parts(parts)
            .map_err(|_| ContactError::Decode(lepic_seal::DecodeError::Damaged))?;
        match progress.content {
            Some(UrContent::Binary(UrBinary::Envelope(bytes))) => self.take_envelope(&bytes).await,
            Some(_) => Err(refused(InPersonRefusal::WrongStage)),
            None => Err(refused(InPersonRefusal::UrIncomplete)),
        }
    }

    /// Takes a sealed answer to an open code, found by the envelope's hint, as
    /// [`ContactBook::in_person_take`] does. An answer refused for good, such as one to a code
    /// already finalized, is told with [`Event::InPersonAnswerRefused`]; one whose check failed
    /// for a passing reason, such as the node not answering, is not.
    pub(crate) async fn take_envelope(
        &self,
        envelope: &[u8],
    ) -> Result<InPersonTaken, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let sealed = SealedEnvelope::decode(envelope, net).map_err(ContactError::Decode)?;
        let hint = sealed.hint();
        let enc = *sealed.enc();
        let session = self.wallet.session()?;
        let (slate_id, state, secret) = self
            .contact_work(move |_, _| {
                let codes = session
                    .store
                    .read(|repos| repos.settings_with_prefix(CODE_PREFIX))?;
                code_for_hint(codes, &session.keychain, network, hint, &enc)
            })
            .await?
            .ok_or(ContactError::NotForThisInstall)?;
        let tx_id = TxId(state.tx_id);
        let taken = self
            .take_answer(network, slate_id, state, &secret, &sealed)
            .await;
        if let Err(error) = &taken
            && let Some(reason) = refusal_reason(error)
        {
            info!(
                tx_id = %tx_id,
                slate_id = %slate_id,
                reason,
                error = %ErrorChain(error),
                "in-person answer refused"
            );
            self.wallet
                .emit(Event::InPersonAnswerRefused(InPersonAnswerRefusedEvent {
                    tx_id,
                    slate_id,
                    reason,
                }));
        }
        taken
    }

    /// Takes a pushed or posted answer straight to a code this wallet showed, for a listener of
    /// direct routes: the envelope `envelope` sealed to the reply key of an open code. Runs
    /// [`ContactBook::in_person_take`]'s checks and says how the listener answers.
    pub async fn in_person_take_direct(&self, envelope: &[u8]) -> InPersonDirect {
        match self.take_envelope(envelope).await {
            Ok(_) => InPersonDirect::Accepted,
            Err(ContactError::NotForThisInstall | ContactError::Decode(_)) => {
                InPersonDirect::NotOurs
            }
            Err(error) => match refusal_reason(&error) {
                Some(reason) => InPersonDirect::Refused(reason),
                None => {
                    warn!(error = %ErrorChain(&error), "direct in-person answer not taken for now");
                    InPersonDirect::Transient
                }
            },
        }
    }

    /// Opens, checks and records an answer to the code of `slate_id`, found by its hint.
    #[allow(clippy::too_many_lines)] // One answer from checks to stored, in order.
    async fn take_answer(
        &self,
        network: Network,
        slate_id: SlateId,
        state: CodeState,
        secret: &EncSecretKey,
        sealed: &SealedEnvelope<'_>,
    ) -> Result<InPersonTaken, ContactError> {
        let opened = sealed
            .open_tx(secret, KeyClass::Seal)
            .map_err(|_| ContactError::CannotOpen)?;
        if opened.sender.is_some() {
            return Err(refused(InPersonRefusal::Signed));
        }
        if opened.content.reply_route.is_some() {
            return Err(refused(InPersonRefusal::ReplyMailboxTag));
        }
        let body = opened.content.body;
        let answer = NativeSlate::decode(network, &body)
            .map_err(native_error)?
            .into_parts()
            .0;
        if answer.stage() != state.kind.answer() {
            return Err(refused(InPersonRefusal::WrongStage));
        }
        if answer.id() != slate_id {
            return Err(refused(InPersonRefusal::OtherSlate));
        }
        let tx_id = TxId(state.tx_id);
        let stage = state.kind.answer();
        let body = hex::encode(&body);
        if state.finalized.is_some() {
            // The answer finalized, or another taken before it, comes again: nothing changes.
            if let Some(earlier) = state.answers.iter().find(|stored| stored.body == body) {
                debug!(tx_id = %tx_id, answer = earlier.number, "in-person answer taken before");
                return Ok(InPersonTaken {
                    tx_id,
                    slate_id,
                    stage,
                    answer: earlier.number,
                    check_code: earlier.check_code.clone(),
                    same_code: earlier.same_code,
                    duplicate: true,
                });
            }
            return Err(match state.kind {
                CodeKind::Invoice => {
                    ContactError::Invoice(InvoiceError::AlreadyFinalized { slate_id, tx_id })
                }
                CodeKind::Send => {
                    ContactError::Finalize(FinalizeError::AlreadyFinalized { slate_id, tx_id })
                }
            });
        }
        let check = check_code(&answering_excess(&answer)?);
        match state.kind {
            CodeKind::Invoice => self
                .wallet
                .check_invoice_answer(answer)
                .await
                .map_err(ContactError::Invoice)?,
            CodeKind::Send => self
                .wallet
                .check_send_answer(answer)
                .await
                .map_err(ContactError::Finalize)?,
        }
        let now = self.wallet.ports().clock.now();
        let session = self.wallet.session()?;
        let code = check.clone();
        let recorded = self
            .contact_work(move |_, _| {
                session
                    .store
                    .write(|repos| record_answer(repos, slate_id, body, code, now))
            })
            .await;
        if matches!(
            recorded,
            Err(ContactError::InPerson(InPersonRefusal::TooManyAnswers))
        ) {
            info!(
                tx_id = state.tx_id,
                count = MAX_ANSWERS_PER_CODE,
                reason = "answer cap reached",
                "in-person answer dropped"
            );
        }
        let (number, same_code, duplicate) = recorded?;
        if duplicate {
            debug!(tx_id = %tx_id, answer = number, "in-person answer taken before");
        } else {
            info!(tx_id = %tx_id, answer = number, same_code, "in-person answer taken");
            self.wallet.emit(Event::InPersonAnswer(InPersonAnswerEvent {
                tx_id,
                slate_id,
                stage,
                answer: number,
                check_code: check.clone(),
                same_code,
            }));
        }
        Ok(InPersonTaken {
            tx_id,
            slate_id,
            stage,
            answer: number,
            check_code: check,
            same_code,
            duplicate,
        })
    }

    /// The code this wallet showed for the slate `slate_id`, with the answers taken for it.
    ///
    /// Fails with [`ContactError::InPerson`] when the wallet holds no such code.
    pub async fn in_person_answers(
        &self,
        slate_id: SlateId,
    ) -> Result<InPersonCodeView, ContactError> {
        let session = self.wallet.session()?;
        let state = self
            .contact_work(move |_, _| session.store.read(|repos| load_code(repos, slate_id)))
            .await?;
        Ok(InPersonCodeView {
            tx_id: TxId(state.tx_id),
            slate_id,
            stage: state.kind.proposal(),
            ttl_cutoff: state.ttl_cutoff,
            mailbox: state.mailbox,
            closed: state.closed,
            finalized: state.finalized,
            answers: state
                .answers
                .into_iter()
                .map(|answer| InPersonAnswerView {
                    number: answer.number,
                    check_code: answer.check_code,
                    same_code: answer.same_code,
                    received_at: Timestamp::from_second(answer.received_at)
                        .unwrap_or(Timestamp::UNIX_EPOCH),
                })
                .collect(),
        })
    }

    /// Finalizes the answer `answer` to the code for the slate `slate_id` and posts it with
    /// `propagation`, as finalizing the invoice does; the user picked it by its check code.
    ///
    /// Fails with [`ContactError::InPerson`] when there is no such code or answer, and
    /// [`ContactError::Invoice`] as finalizing fails. After a `NotPosted` failure the code
    /// names `answer` as finalized: the transaction was stored finalized with it.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn in_person_finalize(
        &self,
        slate_id: SlateId,
        answer: u32,
        propagation: Propagation,
    ) -> Result<Finalized, ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let state = self
            .contact_work(move |_, _| session.store.read(|repos| load_code(repos, slate_id)))
            .await?;
        let stored = state
            .answers
            .iter()
            .find(|stored| stored.number == answer)
            .ok_or(refused(InPersonRefusal::NoAnswer))?;
        let body = hex::unhex(&stored.body).ok_or(refused(InPersonRefusal::StoredAnswer))?;
        let slate = NativeSlate::decode(network, &body)
            .map_err(|_| refused(InPersonRefusal::StoredAnswer))?
            .into_parts()
            .0;
        let finalized = match state.kind {
            CodeKind::Invoice => self
                .wallet
                .finalize_invoice_decoded(slate, propagation)
                .await
                .map_err(ContactError::Invoice),
            CodeKind::Send => self
                .wallet
                .finalize_decoded(slate, propagation)
                .await
                .map_err(ContactError::Finalize),
        };
        // A push the node did not take still stored the transaction finalized with this
        // answer: note it, so the code names the answer its retries post.
        if !matches!(
            finalized,
            Ok(_)
                | Err(ContactError::Invoice(InvoiceError::NotPosted { .. })
                    | ContactError::Finalize(FinalizeError::NotPosted { .. }))
        ) {
            return finalized;
        }
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                let mut state = load_code(repos, slate_id)?;
                state.finalized = Some(answer);
                state.closed = true;
                repos.put_setting(&code_key(slate_id), &to_text(&state, "in-person code")?)?;
                Ok::<_, ContactError>(())
            })
        })
        .await?;
        info!(slate_id = %slate_id, answer, "in-person answer finalized");
        finalized
    }

    /// Forgets the codes and the answers whose transaction ended. Runs before the watch set is
    /// made equal to the records, so their reply mailboxes leave it. The code of a cancelled
    /// transaction stays until the confirmed tip reaches its TTL cutoff, so an answer posted to
    /// a direct route after the cancel is still found and refused as `cancelled`; its mailbox
    /// is not watched (see [`in_person_rows`]).
    pub(crate) async fn tend_in_person(&self) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let tip = self.wallet.confirmed_tip()?.map(|tip| tip.height.value());
        self.contact_work(move |_, _| {
            // Read first: a cycle with nothing to forget writes nothing.
            let ended_keys = session.store.read(|repos| {
                let mut keys = Vec::new();
                for (key, text) in repos.settings_with_prefix(CODE_PREFIX)? {
                    let Ok(state) = from_text::<CodeState>(&text, "in-person code") else {
                        continue;
                    };
                    let forget = repos.transaction(TxId(state.tx_id))?.is_none_or(|tx| {
                        ended(tx.state)
                            && (tx.state != TxState::Cancelled
                                || tip.is_some_and(|tip| tip >= state.ttl_cutoff))
                    });
                    if forget {
                        keys.push(key);
                    }
                }
                for (key, text) in repos.settings_with_prefix(REPLY_PREFIX)? {
                    let Ok(state) = from_text::<ReplyState>(&text, "in-person answer") else {
                        continue;
                    };
                    if repos
                        .transaction(TxId(state.tx_id))?
                        .is_none_or(|tx| ended(tx.state))
                    {
                        keys.push(key);
                    }
                }
                Ok::<_, ContactError>(keys)
            })?;
            if ended_keys.is_empty() {
                return Ok(());
            }
            session.store.write(|repos| {
                for key in &ended_keys {
                    repos.delete_setting(key)?;
                }
                Ok::<_, ContactError>(())
            })
        })
        .await
    }
}

/// Whether a transaction in `state` has ended.
fn ended(state: TxState) -> bool {
    matches!(
        state,
        TxState::Confirmed | TxState::Cancelled | TxState::Expired
    )
}

/// Takes the answers pushed to the reply mailboxes of in-person codes. An answer refused is
/// stored and dropped with its reason; one whose check failed for a passing reason is held.
pub(crate) struct Answers<'a, N, S: StoreOpener, V> {
    book: &'a ContactBook<'a, N, S, V>,
    /// Answers taken.
    pub(crate) taken: usize,
    /// The mailboxes, by key reference and relay, a message was held in.
    pub(crate) kept: HashSet<(String, String)>,
}

impl<'a, N, S: StoreOpener, V> Answers<'a, N, S, V> {
    pub(crate) fn new(book: &'a ContactBook<'a, N, S, V>) -> Self {
        Self {
            book,
            taken: 0,
            kept: HashSet::new(),
        }
    }
}

impl<N, S, V> Handler for Answers<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn handle(&mut self, mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
        Box::pin(async move {
            let handled = self.take(mail.mail).await;
            if handled.is_err() {
                self.kept.insert((mail.key_ref, mail.relay));
            }
            handled
        })
    }
}

impl<N, S, V> Answers<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes one message of the reply mailbox of an in-person code. The envelope names its
    /// slate.
    async fn take(&mut self, message: MailboxMessage) -> Result<Stored, Hold> {
        let MailboxContent::Opened(received) = message.into_content() else {
            return Ok(Stored);
        };
        let Ok((envelope, ArmorMarker::Tx)) = dearmor_marked(received.plaintext.expose_str())
        else {
            info!(
                reason = "not a slate envelope",
                "in-person mailbox message dropped"
            );
            return Ok(Stored);
        };
        match self.book.take_envelope(&envelope).await {
            Ok(taken) => {
                if !taken.duplicate {
                    self.taken = self.taken.saturating_add(1);
                }
                Ok(Stored)
            }
            Err(error) if passes(&error) => {
                warn!(error = %ErrorChain(&error), "in-person answer kept until the failure passes");
                Err(Hold)
            }
            Err(error) => {
                info!(reason = %ErrorChain(&error), "in-person mailbox message dropped");
                Ok(Stored)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lepic_transport::host_rule::HostClass;

    #[test]
    fn a_reply_mailbox_on_this_device_is_refused() {
        let relays_free = |host: &str| -> Result<HostClass, RefusedOrAddress> {
            let (domain, _) = parse_host(host).map_err(|_| RefusedOrAddress)?;
            host_rule::classify_name(domain.as_str()).map_err(|_| RefusedOrAddress)
        };
        assert!(relays_free("127.0.0.1").is_err());
        assert!(relays_free("localhost:7000").is_err());
        assert!(relays_free("0.0.0.0").is_err());
        assert_eq!(relays_free("192.168.1.10"), Ok(HostClass::LocalNetwork));
        assert_eq!(relays_free("relay.example:443"), Ok(HostClass::Public));
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RefusedOrAddress;

    #[test]
    fn a_code_keeps_a_bounded_number_of_answers() {
        use lepic_store::StoreKeys;
        use lepic_store::{MemoryStore, WalletStore};

        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let slate_id = SlateId::from_bytes([7; 16]);
        let state = CodeState {
            tx_id: 1,
            account: 0,
            kind: CodeKind::Invoice,
            ttl_cutoff: 100,
            mailbox: None,
            closed: false,
            finalized: None,
            answers: Vec::new(),
            shared_slot: false,
            bytes: None,
        };
        store
            .write(|repos| {
                repos.put_setting(&code_key(slate_id), &to_text(&state, "in-person code")?)
            })
            .unwrap();
        let now = Timestamp::from_second(1).unwrap();
        let record = |body: &str| -> Result<(u32, bool, bool), ContactError> {
            store.write(|repos| record_answer(repos, slate_id, body.to_owned(), "1234".into(), now))
        };

        for number in 1..=MAX_ANSWERS_PER_CODE {
            let (taken, _, duplicate) = record(&format!("{number:02x}")).unwrap();
            assert_eq!(taken as usize, number);
            assert!(!duplicate);
        }
        // A new answer past the cap is dropped and the stored ones stay as they were.
        assert!(matches!(
            record("ff"),
            Err(ContactError::InPerson(InPersonRefusal::TooManyAnswers))
        ));
        let kept = store
            .read(|repos| load_code(repos, slate_id))
            .unwrap()
            .answers;
        assert_eq!(kept.len(), MAX_ANSWERS_PER_CODE);
        assert!(kept.iter().all(|answer| answer.body != "ff"));
        // An answer already taken is still known past the cap.
        assert_eq!(record("01").unwrap(), (1, false, true));
    }

    /// Codes and answers stored before shared slots, stored code bytes and direct routes
    /// still read: a per-code slot, no bytes and no routes.
    #[test]
    fn codes_and_answers_stored_before_shared_slots_still_read() {
        let code: CodeState = from_text(
            r#"{"tx_id":3,"account":0,"kind":"invoice","ttl_cutoff":130,"mailbox":"relay.test:80","closed":false,"finalized":null,"answers":[]}"#,
            "in-person code",
        )
        .unwrap();
        assert!(!code.shared_slot);
        assert_eq!(code.bytes, None);
        assert_eq!(code.mailbox.as_deref(), Some("relay.test:80"));

        let reply: ReplyState = from_text(
            r#"{"tx_id":4,"account":0,"kind":"invoice","envelope":"00","mailbox_key":null,"mailbox":null,"check_code":"1234","posted":true}"#,
            "in-person answer",
        )
        .unwrap();
        assert!(reply.direct.is_empty());
        assert!(reply.direct_routes().is_empty());
        assert!(reply.posted);
    }
}
