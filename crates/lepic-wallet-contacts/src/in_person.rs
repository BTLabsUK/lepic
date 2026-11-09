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

use std::path::PathBuf;
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::PublicKey;
use lepic_epicbox::{
    EpicboxAddress, Handled, Identity, MailboxClient, MailboxContent, MailboxHandler,
    MailboxMessage, RelayEndpoint, Security, UntrustedHosts,
};
use lepic_keychain::Keychain;
use lepic_methods::epicbox::relay_network;
use lepic_native_slate::{NativeError, NativeSlate, ReplyKey as TailReplyKey, ReplyMailbox, Tail};
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
use lepic_store::{AccountIndex, Repositories, StoreError, TxId, TxState, WalletStore};
use lepic_transport::host_rule::{self, HostReport};
use lepic_transport::method::SenderFacts;
use lepic_transport::transport::{BoxFuture, Location};
use lepic_wallet::account::{DEFAULT_ACCOUNT_LABEL, parent_key_id};
use lepic_wallet::event::{Event, InPersonAnswerEvent};
use lepic_wallet::finalize::Finalized;
use lepic_wallet::invoice::{INVOICE_TTL_MARGIN_BLOCKS, InvoiceRequest, PayRequest};
use lepic_wallet::namespace::{PostRole, check_code};
use lepic_wallet::ports::{SecretVault, StoreOpener};
use lepic_wallet::receive::ReceiveRequest;
use lepic_wallet::selection::SelectionOptions;
use lepic_wallet::send::{Delivery, SendRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use super::collect::passes;
use super::keys::contact_network;
use super::relay::{check_online, mailbox_client, meeting_host, parse_host};
use super::{ContactError, ContactRelays, LockedRng, RelayMode};
use crate::{ContactBook, file_method, hex};

/// The TTL of an in-person code, in blocks past the chain tip, for a caller that passes no
/// `ttl_blocks` (the CLI, tests). The expiry is the app's choice: an app passes its own, and
/// LEPIC refuses one at or under [`INVOICE_TTL_MARGIN_BLOCKS`].
pub const IN_PERSON_TTL_BLOCKS: u64 = 30;

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
    /// The user did not confirm the relay the answer is posted to.
    #[error("the relay was not confirmed")]
    RelayNotConfirmed,
    /// The code named no reply mailbox: show the answer instead.
    #[error("the code names no reply mailbox")]
    NoMailbox,
    /// The scanned parts do not make a whole envelope yet.
    #[error("the scanned parts are not complete")]
    UrIncomplete,
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
}

/// An answer this wallet made to a scanned code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonPaid {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The sealed answer, to show when it is not posted.
    pub envelope: Vec<u8>,
    /// The check code the other screen shows for this answer.
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
    posted: bool,
}

fn code_key(slate_id: SlateId) -> String {
    format!("{CODE_PREFIX}{slate_id}")
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

/// The open code among `codes`, stored settings, whose reply key the hint `hint` of an
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
        if state.finalized.is_some() {
            continue;
        }
        let secret = reply_secret(keychain, network, AccountIndex(state.account), slate_id)?;
        if Hint::reply(&secret.public_key(), enc) == hint {
            return Ok(Some((slate_id, state, secret)));
        }
    }
    Ok(None)
}

/// Records the answer `body`, hex, with the check code `code` for the code of `slate_id`, and
/// closes the code. Returns the answer's number, whether an earlier answer had the same check
/// code, and whether this answer was recorded before, when nothing changes.
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
/// shown about it. A relay the wallet knows, its own or a meeting relay, is reached as the
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

pub(crate) fn known_endpoint(
    relays: &ContactRelays,
    domain: &lepic_epicbox::Domain,
    port: Option<u16>,
) -> Option<RelayEndpoint> {
    std::iter::once(&relays.epicbox.settings().endpoint)
        .chain(relays.meeting.iter())
        .find(|known| known.domain() == domain && port.is_none_or(|port| port == known.port()))
        .cloned()
}

/// A client on `endpoint`: the wallet's own client for a relay it knows, one that checks the
/// host before connecting for any other.
pub(crate) fn client_for(
    relays: &ContactRelays,
    endpoint: RelayEndpoint,
    known: bool,
) -> MailboxClient {
    if known {
        return mailbox_client(relays, endpoint, None);
    }
    let mut settings = relays.epicbox.settings().clone();
    settings.endpoint = endpoint;
    MailboxClient::new(
        settings,
        Arc::new(UntrustedHosts(relays.epicbox.connector())),
    )
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
        let account = request.account;
        let (tx_id, slate, _) = self
            .wallet
            .issue_unsent(
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
            )
            .await
            .map_err(ContactError::Invoice)?;
        match self
            .store_code(relays, tx_id, account, slate, CodeKind::Invoice)
            .await
        {
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
        match self
            .store_code(relays, sent.tx_id, account, slate, CodeKind::Send)
            .await
        {
            Ok(code) => Ok(code),
            Err(error) => Err(self.give_up_send(sent.tx_id, error).await),
        }
    }

    async fn store_code(
        &self,
        relays: &ContactRelays,
        tx_id: TxId,
        account: AccountIndex,
        slate: Slate,
        kind: CodeKind,
    ) -> Result<InPersonCode, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let slate_id = slate.id();
        let ttl_cutoff = slate
            .ttl_cutoff_height()
            .ok_or(refused(InPersonRefusal::NoTtl))?
            .value();
        let own = &relays.epicbox.settings().endpoint;
        let mailbox = match relays.mode {
            // A relay on this device cannot be reached from the other one: the code names
            // none, and the answer is shown back.
            RelayMode::Online if host_rule::classify_name(own.domain().as_str()).is_ok() => {
                let secret = self
                    .wallet
                    .reply_mailbox_key(account, net, slate_id.as_bytes())?;
                let public =
                    PublicKey::from_secret_key(&secret).map_err(|_| ContactError::RelayAddress)?;
                Some(
                    ReplyMailbox::new(public, meeting_host(own))
                        .map_err(|error| native_error(error.into()))?,
                )
            }
            _ => None,
        };
        let host = mailbox.as_ref().map(|mailbox| mailbox.address().to_owned());
        let session = self.wallet.session()?;
        let state = CodeState {
            tx_id: tx_id.0,
            account: account.0,
            kind,
            ttl_cutoff,
            mailbox: host.clone(),
            closed: false,
            finalized: None,
            answers: Vec::new(),
        };
        let bytes = self
            .contact_work(move |_, _| {
                let reply = reply_secret(&session.keychain, network, account, slate_id)?;
                let tail = Tail::new(
                    Some(TailReplyKey::from_bytes(*reply.public_key().as_bytes())),
                    mailbox,
                    Vec::new(),
                )
                .map_err(|error| native_error(error.into()))?;
                let bytes = NativeSlate::new(slate, tail)
                    .map_err(native_error)?
                    .encode(network);
                let text = to_text(&state, "in-person code")?;
                session.store.write(|repos| {
                    repos.put_setting(&code_key(slate_id), &text)?;
                    Ok::<_, ContactError>(())
                })?;
                Ok(bytes)
            })
            .await?;
        info!(tx_id = %tx_id, online = host.is_some(), "in-person code made");
        Ok(InPersonCode {
            tx_id,
            slate_id,
            bytes,
            ttl_cutoff,
            mailbox: host,
        })
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
        let (i1, _) = native.into_parts();
        let account = request.account;
        let paid = self
            .wallet
            .pay_decoded(&file_method(), i1, SenderFacts::default(), request, None)
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
                CodeKind::Send,
            )
            .await
        {
            Ok(paid) => Ok(paid),
            Err(error) => Err(self.give_up_send(tx_id, error).await),
        }
    }

    async fn store_answer(
        &self,
        answer: Slate,
        tx_id: TxId,
        account: AccountIndex,
        reply_to: &EncPublicKey,
        mailbox: Option<AnswerMailbox>,
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
    /// from a key used for this slate only, through the wallet's connector (over Tor when it
    /// is configured). `relay_ok` says the user confirmed the relay
    /// [`ContactBook::in_person_read`] reported. The host is checked again when connecting: a
    /// name or, connecting directly, any address it resolves to that is loopback or
    /// unspecified is refused, and the connection goes to the addresses checked. Through Tor
    /// the exit resolves the name, so only the name is checked.
    ///
    /// Fails with [`ContactError::InPerson`] when `relay_ok` is false, no answer is stored or
    /// the code named no mailbox, [`ContactError::Offline`] or [`ContactError::EpicboxOff`],
    /// and [`ContactError::Relay`] when the post failed; posting again is safe.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn in_person_post(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
        relay_ok: bool,
    ) -> Result<(), ContactError> {
        if !relay_ok {
            return Err(refused(InPersonRefusal::RelayNotConfirmed));
        }
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let state = self
            .contact_work(move |_, _| session.store.read(|repos| load_reply(repos, slate_id)))
            .await?;
        let (Some(key), Some(host)) = (&state.mailbox_key, &state.mailbox) else {
            return Err(refused(InPersonRefusal::NoMailbox));
        };
        let (endpoint, report) = mailbox_endpoint(host, relays)?;
        let key = hex::unhex(key)
            .and_then(|key| PublicKey::from_bytes(&key).ok())
            .ok_or(corrupt("in-person answer"))?;
        let envelope = hex::unhex(&state.envelope).ok_or(corrupt("in-person answer"))?;
        let to = EpicboxAddress::new(
            key,
            relay_network(network),
            endpoint.domain().clone(),
            Some(endpoint.port()),
        );
        let secret = self.wallet.post_key(
            AccountIndex(state.account),
            net,
            slate_id.as_bytes(),
            PostRole::Responder,
        )?;
        let from = identity(secret, network, &endpoint)?;
        client_for(relays, endpoint, report.in_relay_list)
            .post(&from, &to, &armor_tx(&envelope))
            .await
            .map_err(ContactError::Relay)?;
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                let mut state = load_reply(repos, slate_id)?;
                state.posted = true;
                repos.put_setting(&reply_key(slate_id), &to_text(&state, "in-person answer")?)?;
                Ok::<_, ContactError>(())
            })
        })
        .await?;
        info!(slate_id = %slate_id, "in-person answer posted");
        Ok(())
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
        let opened = sealed
            .open_tx(&secret, KeyClass::Seal)
            .map_err(|_| ContactError::CannotOpen)?;
        if opened.sender.is_some() {
            return Err(refused(InPersonRefusal::Signed));
        }
        if opened.content.reply_mailbox.is_some() {
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
        let body = hex::encode(&body);
        let code = check.clone();
        let (number, same_code, duplicate) = self
            .contact_work(move |_, _| {
                session
                    .store
                    .write(|repos| record_answer(repos, slate_id, body, code, now))
            })
            .await?;
        let tx_id = TxId(state.tx_id);
        let stage = state.kind.answer();
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
    /// [`ContactError::Invoice`] as finalizing fails.
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
                .map_err(ContactError::Invoice)?,
            CodeKind::Send => self
                .wallet
                .finalize_decoded(slate, propagation)
                .await
                .map_err(ContactError::Finalize)?,
        };
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
        Ok(finalized)
    }

    /// Drains the reply mailboxes of the codes still waiting for answers, and takes what
    /// they hold. Codes whose transaction ended are forgotten. Returns how many answers were
    /// taken.
    pub(crate) async fn collect_in_person(
        &self,
        relays: &ContactRelays,
    ) -> Result<usize, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let watched = self
            .contact_work(move |_, _| {
                session.store.write(|repos| {
                    let mut watched = Vec::new();
                    for (key, text) in repos.settings_with_prefix(CODE_PREFIX)? {
                        let parsed = key
                            .strip_prefix(CODE_PREFIX)
                            .and_then(|id| SlateId::parse(id).ok())
                            .zip(from_text::<CodeState>(&text, "in-person code").ok());
                        let Some((slate_id, state)) = parsed else {
                            continue;
                        };
                        let tx = repos.transaction(TxId(state.tx_id))?;
                        match tx.map(|tx| tx.state) {
                            None
                            | Some(TxState::Confirmed | TxState::Cancelled | TxState::Expired) => {
                                repos.delete_setting(&key)?;
                            }
                            Some(TxState::Received | TxState::Sent)
                                if state.finalized.is_none() =>
                            {
                                if let Some(host) = state.mailbox {
                                    watched.push((slate_id, AccountIndex(state.account), host));
                                }
                            }
                            Some(_) => {}
                        }
                    }
                    for (key, text) in repos.settings_with_prefix(REPLY_PREFIX)? {
                        let Ok(state) = from_text::<ReplyState>(&text, "in-person answer") else {
                            continue;
                        };
                        let tx = repos.transaction(TxId(state.tx_id))?;
                        if tx.is_none_or(|tx| {
                            matches!(
                                tx.state,
                                TxState::Confirmed | TxState::Cancelled | TxState::Expired
                            )
                        }) {
                            repos.delete_setting(&key)?;
                        }
                    }
                    Ok::<_, ContactError>(watched)
                })
            })
            .await?;
        let mut by_relay: std::collections::BTreeMap<String, Vec<(SlateId, AccountIndex)>> =
            std::collections::BTreeMap::new();
        for (slate_id, account, host) in watched {
            by_relay.entry(host).or_default().push((slate_id, account));
        }
        let mut taken = 0usize;
        for (host, codes) in by_relay {
            let (endpoint, known) = match parse_host(&host) {
                Ok((domain, port)) => match known_endpoint(relays, &domain, port) {
                    Some(endpoint) => (endpoint, true),
                    None => match mailbox_endpoint(&host, relays) {
                        Ok((endpoint, _)) => (endpoint, false),
                        Err(error) => {
                            warn!(error = %ErrorChain(&error), "in-person reply mailbox not watched");
                            continue;
                        }
                    },
                },
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "in-person reply mailbox not watched");
                    continue;
                }
            };
            let mut identities = Vec::with_capacity(codes.len());
            for (slate_id, account) in codes {
                let secret = self
                    .wallet
                    .reply_mailbox_key(account, net, slate_id.as_bytes())?;
                identities.push(identity(secret, network, &endpoint)?);
            }
            let mut handler = Answers {
                book: self,
                taken: 0,
            };
            let drained = client_for(relays, endpoint, known)
                .drain_once(&identities, &mut handler)
                .await;
            taken = taken.saturating_add(handler.taken);
            if let Err(error) = drained {
                warn!(relay = %host, error = %ErrorChain(&error), "in-person reply mailboxes not drained");
            }
        }
        Ok(taken)
    }
}

/// Takes the answers drained from reply mailboxes. An answer refused is acknowledged and
/// dropped with its reason; one whose check failed for a passing reason is kept.
struct Answers<'a, N, S: StoreOpener, V> {
    book: &'a ContactBook<'a, N, S, V>,
    taken: usize,
}

impl<N, S, V> MailboxHandler for Answers<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            let MailboxContent::Opened(received) = message.into_content() else {
                return Handled::Stored;
            };
            let Ok((envelope, ArmorMarker::Tx)) = dearmor_marked(received.plaintext.expose_str())
            else {
                info!(
                    reason = "not a slate envelope",
                    "in-person mailbox message dropped"
                );
                return Handled::Stored;
            };
            match self.book.take_envelope(&envelope).await {
                Ok(taken) => {
                    if !taken.duplicate {
                        self.taken = self.taken.saturating_add(1);
                    }
                    Handled::Stored
                }
                Err(error) if passes(&error) => {
                    warn!(error = %ErrorChain(&error), "in-person answer kept until the failure passes");
                    Handled::Later
                }
                Err(error) => {
                    info!(reason = %ErrorChain(&error), "in-person mailbox message dropped");
                    Handled::Stored
                }
            }
        })
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
}
