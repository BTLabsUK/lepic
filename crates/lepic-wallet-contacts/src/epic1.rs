// SPDX-License-Identifier: Apache-2.0
//! Payments to an epic1 address (RFC 0003 §5.14, §5.15): the address, the links that name a
//! mailbox to pay it at, and the slates exchanged through those mailboxes.
//!
//! The payee hands out links. Each names one link mailbox of the account: an on-screen link takes
//! the next of 50 mailboxes in a ring, a printed link the first of 32 that is free until it is
//! retired. A payer seals an S1 to the address's seal key in an anonymous type `0A` envelope with
//! a zero hint, names the slate's reply key (tag 03) and a reply mailbox on its own relay (tag
//! 09), and posts it to the link's mailbox. The payee receives it with the epic1 proof key and
//! seals the S2 to the reply key; the host posts it to the reply mailbox once the user agrees to
//! the relay. The payer finalizes an S2 that checks as soon as it collects it.
//!
//! Collecting drains every on-screen link mailbox used in the last seven days and every printed
//! one not retired. There is no live mode: they are drained on each collect.

use std::collections::BTreeMap;
use std::path::PathBuf;

use jiff::Timestamp;
use lepic_crypto::PublicKey;
use lepic_epic1::{Delivery as LinkDelivery, Epic1Address, Epic1Link, EpicboxTransport};
use lepic_epicbox::{
    EpicboxAddress, Handled, MAX_MAILBOXES_PER_DRAIN, MailboxContent, MailboxError, MailboxHandler,
    MailboxMessage, RelayEndpoint,
};
use lepic_methods::epicbox::relay_network;
use lepic_native_slate::{NativeSlate, Tail};
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::amount::Amount;
use lepic_primitives::error_chain::ErrorChain;
use lepic_primitives::params::Network;
use lepic_seal::{
    ArmorMarker, Content, EncPublicKey, Hint, HintRule, KeyClass, MessageType, SealedEnvelope,
    TxContent, TxKey, armor, armor_tx, dearmor_marked, seal, seal_tx,
};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::{ProofAddress, SlateId};
use lepic_slate::stage::Stage;
use lepic_store::{AccountIndex, Repositories, SlateStage, TxId, TxState, WalletStore};
use lepic_transport::host_rule::{self, HostReport};
use lepic_transport::transport::{BoxFuture, Location};
use lepic_wallet::epic1_index::{self, IssueError, trial_open};
use lepic_wallet::namespace::{LinkMailbox, PostRole};
use lepic_wallet::notice::{Notice, NoticeKind, Payload, classify_text};
use lepic_wallet::ports::{SecretVault, StoreOpener};
use lepic_wallet::receive::{ProofKey, ReceiveRequest};
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::collect::passes;
use super::in_person::{
    client_for, corrupt, from_text, identity, known_endpoint, mailbox_endpoint, reply_secret,
    to_text,
};
use super::keys::contact_network;
use super::native::{decode_native, native_body, v3_of_native};
use super::relay::{check_online, mailbox_client, meeting_host, parse_host};
use super::{ContactError, ContactRelays, LockedRng};
use crate::{ContactBook, file_method, hex};

/// The TTL of a payment to an epic1 link, in blocks past the chain tip, when the caller gives
/// none.
pub const EPIC1_TTL_BLOCKS: u64 = 1440;

/// How long an on-screen link mailbox is drained after it was issued or last used.
pub const ON_SCREEN_LIVE_FOR: jiff::SignedDuration = jiff::SignedDuration::from_hours(7 * 24);

/// The state of a link this wallet issued: `epic1.link.<account>.<screen|printed>.<n>`.
const LINK_PREFIX: &str = "epic1.link.";

/// The next on-screen link mailbox of an account: `epic1.ring.<account>`.
const RING_PREFIX: &str = "epic1.ring.";

/// The S2 this wallet made for an S1 taken at a link mailbox, by slate id.
const ANSWER_PREFIX: &str = "epic1.answer.";

/// A payment this wallet made to an epic1 link, by slate id.
const PAY_PREFIX: &str = "epic1.pay.";

/// The refusal this wallet sealed for an S1 taken at a link mailbox and not received, by slate
/// id.
const REFUSAL_PREFIX: &str = "epic1.refusal.";

/// How long a refusal is kept after it was sealed. A payment refused again within it, as when
/// the relay delivers the S1 a second time, is not refused again.
const REFUSAL_KEPT_FOR: jiff::SignedDuration = jiff::SignedDuration::from_hours(7 * 24);

/// The most refusals kept at once; a payment refused beyond it is dropped without one, and its
/// payer frees its inputs when its TTL passes.
const MAX_REFUSALS: usize = 64;

/// Why an epic1 call refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Epic1Refusal {
    /// The link names no transport this wallet can use.
    #[error("cannot pay this code")]
    CannotPay,
    /// The link or the slate is for another network than the wallet.
    #[error("the epic1 is for another network")]
    WrongNetwork,
    /// The envelope at a link mailbox is signed: a payment to an epic1 is anonymous.
    #[error("the payment is signed")]
    Signed,
    /// The envelope's hint is not zero.
    #[error("the envelope's hint is not zero")]
    HintNotZero,
    /// The payment names no reply key (tag 03).
    #[error("the payment names no reply key")]
    NoReplyKey,
    /// The payment names no reply mailbox (tag 09).
    #[error("the payment names no reply mailbox")]
    NoReplyMailbox,
    /// The slate is at a stage this call does not take: only an S1 comes to a link mailbox,
    /// and only an S2 answers one.
    #[error("the slate is at a stage this call does not take")]
    WrongStage,
    /// The answer is for another slate than the payment.
    #[error("the answer is for another slate")]
    OtherSlate,
    /// All 32 printed links are in use: retire one first.
    #[error("all printed links are in use")]
    PrintedFull,
    /// No printed link with that number is in use.
    #[error("no printed link with that number is in use")]
    NotIssued,
    /// This wallet holds no answer or payment for the slate.
    #[error("no epic1 payment for this slate")]
    NoPayment,
    /// The user did not confirm the relays the slate is posted to.
    #[error("the relay was not confirmed")]
    RelayNotConfirmed,
    /// Every transport of the link was tried.
    #[error("no transport of the link is left to try")]
    NoMoreEntries,
    /// The wallet's own relay is a loopback or unspecified host: no other device reaches it.
    #[error("the wallet's relay is on this device")]
    OwnRelayLocal,
    /// A relay named for a link is not a domain with an optional port, or is on this device.
    #[error("a link relay is not usable")]
    LinkRelay,
    /// More relays than a link names.
    #[error("a link names at most three relays")]
    TooManyRelays,
    /// The message is longer than a link carries or holds control characters.
    #[error("the message does not fit in a link")]
    Message,
    /// The address's proof key is not a payment proof address.
    #[error("the address's proof key is not usable")]
    ProofKey,
    /// The payment was finalized already.
    #[error("the payment was finalized already")]
    Finalized,
    /// The amount of a payment is not the one its link asks.
    #[error("the amount is not the one the link asks")]
    AmountMismatch,
    /// The account did not issue the epic1 address at that index.
    #[error("the account did not issue that address")]
    AddressNotIssued,
    /// The account issued its last address index.
    #[error("the account has no address index left")]
    NoAddressLeft,
    /// The wallet was restored from its recovery phrase and the host has not made this install
    /// the one that issues new addresses ([`ContactBook::epic1_issue_here`]).
    #[error("this install does not issue new epic1 addresses")]
    NotIssuingInstall,
    /// A payment to the link is waiting for its answer: finalize or cancel it first, or post
    /// it to the link's next relay.
    #[error("a payment to this link is waiting for its answer")]
    PaymentPending,
}

/// The kind of a link mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Epic1LinkKind {
    /// A link shown on a screen: a ring of 50 mailboxes.
    OnScreen,
    /// A link printed or kept: one of 32 mailboxes, held until retired.
    Printed,
}

impl Epic1LinkKind {
    const fn key(self) -> &'static str {
        match self {
            Self::OnScreen => "screen",
            Self::Printed => "printed",
        }
    }

    fn from_key(text: &str) -> Option<Self> {
        match text {
            "screen" => Some(Self::OnScreen),
            "printed" => Some(Self::Printed),
            _ => None,
        }
    }

    const fn count(self) -> u32 {
        match self {
            Self::OnScreen => LinkMailbox::ON_SCREEN,
            Self::Printed => LinkMailbox::PRINTED,
        }
    }

    fn mailbox(self, n: u32) -> Option<LinkMailbox> {
        match self {
            Self::OnScreen => LinkMailbox::on_screen(n),
            Self::Printed => LinkMailbox::printed(n),
        }
    }
}

/// A link to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1LinkRequest {
    pub account: AccountIndex,
    /// The index of the account's epic1 address the link pays; 0 for its first address.
    pub index: u32,
    pub amount: Option<Amount>,
    pub message: Option<String>,
    pub kind: Epic1LinkKind,
    /// The relays the link mailbox is named on, `domain[:port]`, at most three; the wallet's
    /// own relay when empty.
    pub relays: Vec<String>,
}

/// A link this wallet issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1LinkIssued {
    /// The link text, `epic:epic1…?epicbox=…`.
    pub link: String,
    /// The epic1 address the link pays.
    pub address: String,
    /// The index of that address in its account.
    pub index: u32,
    pub kind: Epic1LinkKind,
    pub n: u32,
}

/// A link mailbox in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1LinkView {
    pub account: AccountIndex,
    /// The index of the epic1 address the link pays; `None` when the wallet does not know it,
    /// as for a link mailbox a restore found in use.
    pub index: Option<u32>,
    pub kind: Epic1LinkKind,
    pub n: u32,
    pub issued_at: Timestamp,
    pub used_at: Option<Timestamp>,
    pub relays: Vec<String>,
}

/// What an epic1 link asks, as the host shows it before the user pays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1Read {
    /// The payee: the epic1, never a mailbox.
    pub address: String,
    pub amount: Option<Amount>,
    pub message: Option<String>,
    pub label: Option<String>,
    /// The relays of the usable transports, in the order they are tried.
    pub hosts: Vec<HostReport>,
}

/// A payment to make to an epic1 link.
#[derive(Debug, Clone)]
pub struct Epic1PayRequest {
    /// The link text.
    pub link: String,
    /// The send. Its TTL is [`EPIC1_TTL_BLOCKS`] when it sets none; a payment proof it asks
    /// for is replaced by the epic1 proof key.
    pub send: SendRequest,
    /// Ask the payee for a payment proof signed with the epic1 proof key.
    pub proof: bool,
    /// A path in the wallet's directory the S1 is written to on the way; the caller removes it.
    pub slate_file: PathBuf,
}

/// A post of a payment to one transport of a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1Attempt {
    pub host: String,
    /// Why the post failed; `None` when it went through.
    pub error: Option<String>,
    /// The post failed after the payment was sent: the relay may hold it, and the payee may
    /// still take it from there.
    pub uncertain: bool,
}

/// A payment this wallet made to an epic1 link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1Paid {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub address: String,
    /// The posts made, in order; the last went through when [`Epic1Paid::posted`] is set.
    pub attempts: Vec<Epic1Attempt>,
    /// The transport, from 0, the payment was posted to.
    pub posted: Option<usize>,
    /// The first transport, from 0, whose relay may hold the payment though its post failed
    /// ([`Epic1Attempt::uncertain`]). The payment may arrive from there; it is the same
    /// payment, so posting it to the next relay never pays twice.
    pub uncertain: Option<usize>,
}

/// An S2 this wallet made for a payment taken at a link mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1AnswerView {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The relay of the payer's reply mailbox, as written.
    pub mailbox: String,
    /// What the user is shown about that relay; `None` when it cannot be posted to.
    pub report: Option<HostReport>,
    pub posted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinkState {
    /// Unix seconds.
    issued_at: i64,
    used_at: Option<i64>,
    /// `domain[:port]` of each relay the link names.
    relays: Vec<String>,
    /// The amount the link asks, in atoms; `None` when it asks none, and for a link issued
    /// before the amount was kept.
    #[serde(default)]
    amount: Option<u64>,
    /// The index of the epic1 address the link pays; `None` when the wallet does not know it.
    /// A payment at the link mailbox is opened with that address's seal key first.
    #[serde(default)]
    index: Option<u32>,
}

/// An epic1 address an account issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1AddressView {
    pub index: u32,
    /// The address text, `epic1…`.
    pub address: String,
}

/// A page of the epic1 addresses an account issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1Addresses {
    pub account: AccountIndex,
    /// The highest index issued or paid; every index up to it is issued.
    pub highest: u32,
    /// The addresses of the page, from the lowest index.
    pub addresses: Vec<Epic1AddressView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnswerState {
    tx_id: u32,
    account: u32,
    /// The sealed S2, hex.
    envelope: String,
    /// The payer's reply mailbox key, hex, and relay.
    mailbox_key: String,
    mailbox: String,
    posted: bool,
}

/// The refusal of a payment: the notice sealed to the payer's reply key, to post to its reply
/// mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefusalState {
    /// The account whose link mailbox the payment came to.
    account: u32,
    /// The sealed notice, hex.
    envelope: String,
    /// The payer's reply mailbox key, hex, and relay.
    mailbox_key: String,
    mailbox: String,
    posted: bool,
    /// Unix seconds when it was sealed.
    at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    /// The link mailbox key, hex.
    mailbox: String,
    /// `domain[:port]`.
    host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PayState {
    tx_id: u32,
    account: u32,
    /// The sealed S1, hex.
    envelope: String,
    /// The epic1 the payment is to.
    address: String,
    /// The usable transports of the link, in the order they are tried.
    entries: Vec<StoredEntry>,
    /// The next transport to try.
    next: usize,
    posted: Option<usize>,
    finalized: bool,
    /// The first transport whose relay may hold the payment though its post failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uncertain: Option<usize>,
    /// The relay of the reply mailbox the payment names, as written in it. `None` for a
    /// payment stored before it was kept: its reply mailbox is on the wallet's own relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply_relay: Option<String>,
}

/// Whether the relays of a payment are confirmed: the user said so, or every one is in the
/// relay list of the settings.
fn hosts_confirmed(hosts_ok: bool, usable: &[(EpicboxTransport, HostReport)]) -> bool {
    hosts_ok || usable.iter().all(|(_, report)| report.in_relay_list)
}

fn refused(refusal: Epic1Refusal) -> ContactError {
    ContactError::Epic1(refusal)
}

/// Takes the link mailbox a new link of `kind` names: the next of the on-screen ring, which
/// wraps, or the first printed one not in use.
fn take_link_mailbox(
    repos: &mut dyn Repositories,
    account: AccountIndex,
    kind: Epic1LinkKind,
) -> Result<u32, ContactError> {
    match kind {
        Epic1LinkKind::OnScreen => {
            let n = repos
                .setting(&ring_key(account))?
                .and_then(|text| text.parse::<u32>().ok())
                .filter(|n| *n < LinkMailbox::ON_SCREEN)
                .unwrap_or(0);
            let next = n
                .saturating_add(1)
                .checked_rem(LinkMailbox::ON_SCREEN)
                .unwrap_or(0);
            repos.put_setting(&ring_key(account), &next.to_string())?;
            Ok(n)
        }
        Epic1LinkKind::Printed => (0..LinkMailbox::PRINTED)
            .find(|n| {
                repos
                    .setting(&link_key(account, kind, *n))
                    .is_ok_and(|state| state.is_none())
            })
            .ok_or(refused(Epic1Refusal::PrintedFull)),
    }
}

fn link_key(account: AccountIndex, kind: Epic1LinkKind, n: u32) -> String {
    format!("{LINK_PREFIX}{}.{}.{n}", account.0, kind.key())
}

fn parse_link_key(key: &str) -> Option<(AccountIndex, Epic1LinkKind, u32)> {
    let mut parts = key.strip_prefix(LINK_PREFIX)?.split('.');
    let account = parts.next()?.parse().ok()?;
    let kind = Epic1LinkKind::from_key(parts.next()?)?;
    let n = parts.next()?.parse().ok()?;
    if parts.next().is_some() || kind.mailbox(n).is_none() {
        return None;
    }
    Some((AccountIndex(account), kind, n))
}

fn ring_key(account: AccountIndex) -> String {
    format!("{RING_PREFIX}{}", account.0)
}

fn answer_key(slate_id: SlateId) -> String {
    format!("{ANSWER_PREFIX}{slate_id}")
}

fn refusal_key(slate_id: SlateId) -> String {
    format!("{REFUSAL_PREFIX}{slate_id}")
}

/// The reason of a refusal for an amount other than the one the link asks.
const REASON_AMOUNT: &str = "amount";

/// What a refusal says: the `declined` notice of ADR 0016 for `slate_id`, with the reason
/// beside it. A reader that does not know the reason ignores it.
#[derive(Serialize)]
struct RefusalBody {
    lepic: u64,
    #[serde(rename = "type")]
    kind: &'static str,
    slate_id: String,
    reason: &'static str,
}

fn refusal_body(slate_id: SlateId, reason: &'static str) -> Vec<u8> {
    let body = RefusalBody {
        lepic: lepic_wallet::notice::NOTICE_VERSION,
        kind: "declined",
        slate_id: slate_id.to_string(),
        reason,
    };
    // A struct of strings and a number always serializes.
    serde_json::to_vec(&body).unwrap_or_default()
}

fn pay_key(slate_id: SlateId) -> String {
    format!("{PAY_PREFIX}{slate_id}")
}

fn load<T: for<'de> Deserialize<'de>>(
    repos: &dyn Repositories,
    key: &str,
    field: &'static str,
) -> Result<T, ContactError> {
    let text = repos
        .setting(key)?
        .ok_or(refused(Epic1Refusal::NoPayment))?;
    Ok(from_text(&text, field)?)
}

fn ended(state: TxState) -> bool {
    matches!(
        state,
        TxState::Confirmed | TxState::Cancelled | TxState::Expired
    )
}

fn seconds(at: i64) -> Timestamp {
    Timestamp::from_second(at).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// `domain[:port]` of a transport.
fn transport_host(transport: &EpicboxTransport) -> String {
    match transport.port() {
        Some(port) => format!("{}:{port}", transport.relay()),
        None => transport.relay().to_string(),
    }
}

/// The endpoint of `host` and whether the wallet knows the relay, as collecting reaches it.
fn watched_endpoint(
    relays: &ContactRelays,
    host: &str,
) -> Result<(RelayEndpoint, bool), ContactError> {
    let (domain, port) = parse_host(host)?;
    if let Some(endpoint) = known_endpoint(relays, &domain, port) {
        return Ok((endpoint, true));
    }
    let (endpoint, _) = mailbox_endpoint(host, relays)?;
    Ok((endpoint, false))
}

/// The wallet's own relay, refused when no other device reaches it.
fn own_relay(relays: &ContactRelays) -> Result<&RelayEndpoint, ContactError> {
    let own = &relays.epicbox.settings().endpoint;
    host_rule::classify_name(own.domain().as_str())
        .map_err(|_| refused(Epic1Refusal::OwnRelayLocal))?;
    Ok(own)
}

/// The link in `text` for `network`, its usable transports and what the user is shown about
/// each. An entry on this device is left out.
fn read_link(
    text: &str,
    network: Network,
    relays: &ContactRelays,
) -> Result<(Epic1Link, Vec<(EpicboxTransport, HostReport)>), ContactError> {
    let link = Epic1Link::parse(text.trim()).map_err(ContactError::Epic1Link)?;
    if link.address.network() != relay_network(network) {
        return Err(refused(Epic1Refusal::WrongNetwork));
    }
    let LinkDelivery::Usable(transports) = link.delivery() else {
        return Err(refused(Epic1Refusal::CannotPay));
    };
    let mut usable = Vec::with_capacity(transports.len());
    for transport in transports {
        match mailbox_endpoint(&transport_host(transport), relays) {
            Ok((_, report)) => usable.push((transport.clone(), report)),
            Err(error) => {
                debug!(error = %ErrorChain(&error), "epic1 transport left out");
            }
        }
    }
    if usable.is_empty() {
        return Err(refused(Epic1Refusal::CannotPay));
    }
    Ok((link, usable))
}

/// The S1 in an envelope that came to a link mailbox, opened with the first of the epic1 seal
/// keys `keys`, `(index, key)`, that opens it: the index of the address it was sealed to, the
/// slate's V3 JSON, the reply key and the reply mailbox.
fn open_payment(
    network: Network,
    envelope: &[u8],
    keys: &[(u32, lepic_seal::EncSecretKey)],
) -> Result<(u32, OpenedPayment), ContactError> {
    let net = contact_network(network);
    let sealed = SealedEnvelope::decode(envelope, net).map_err(ContactError::Decode)?;
    if sealed.hint() != Hint::from_bytes([0; 8]) {
        return Err(refused(Epic1Refusal::HintNotZero));
    }
    let (index, opened) = trial_open(keys, |key| sealed.open_tx(key, KeyClass::Epic1).ok())
        .ok_or(ContactError::CannotOpen)?;
    if opened.sender.is_some() {
        return Err(refused(Epic1Refusal::Signed));
    }
    let content = opened.content;
    let reply_key = content.reply_key.ok_or(refused(Epic1Refusal::NoReplyKey))?;
    let reply_mailbox = content
        .reply_mailbox
        .ok_or(refused(Epic1Refusal::NoReplyMailbox))?;
    let slate = decode_native(network, &content.body).ok_or(ContactError::NotASlate)?;
    if slate.stage() != Stage::S1 {
        return Err(refused(Epic1Refusal::WrongStage));
    }
    let slate_id = slate.id();
    let amount = slate.amount();
    let v3 = v3_of_native(network, slate, None).ok_or(ContactError::NotASlate)?;
    Ok((
        index,
        OpenedPayment {
            slate_id,
            v3,
            amount,
            reply_key,
            reply_mailbox,
        },
    ))
}

/// What an envelope at a link mailbox holds.
struct OpenedPayment {
    slate_id: SlateId,
    v3: Vec<u8>,
    /// What the S1 pays.
    amount: Amount,
    reply_key: EncPublicKey,
    reply_mailbox: lepic_seal::ReplyMailbox,
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The first epic1 address of `account`, index 0: its seal key and its epic1 proof key on
    /// the wallet's network.
    ///
    /// Fails with [`ContactError::Wallet`] when the wallet is locked.
    pub fn epic1_address(&self, account: AccountIndex) -> Result<Epic1Address, ContactError> {
        self.address_at(account, 0)
    }

    /// The epic1 address `index` of `account`, issued or not.
    fn address_at(&self, account: AccountIndex, index: u32) -> Result<Epic1Address, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let seal = self
            .wallet
            .epic1_seal_key(account, net, index)?
            .public_key();
        let proof = self
            .wallet
            .epic1_proof_key(account, net, index)?
            .verifying_key();
        Ok(Epic1Address::new(relay_network(network), proof, seal))
    }

    /// The epic1 address `index` of `account`. The index is one the account issued, or one a
    /// restored wallet tries.
    ///
    /// Fails with [`ContactError::Epic1`] for an index the account did not issue, and
    /// [`ContactError::Wallet`] when the wallet is locked.
    pub async fn epic1_address_at(
        &self,
        account: AccountIndex,
        index: u32,
    ) -> Result<Epic1Address, ContactError> {
        let session = self.wallet.session()?;
        let top = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| epic1_index::highest_tried(repos, account))?)
            })
            .await?;
        if index > top {
            return Err(refused(Epic1Refusal::AddressNotIssued));
        }
        self.address_at(account, index)
    }

    /// Issues the next epic1 address of `account` and returns its index and the address. The
    /// wallet tries its seal key on what it receives from then on. There is no limit; an app
    /// that wants one sets it.
    ///
    /// Fails with [`ContactError::Epic1`] when the account issued its last index, or the
    /// wallet was restored from its recovery phrase and this install was not made the one that
    /// issues ([`Self::epic1_issue_here`]), and [`ContactError::Wallet`] when the wallet is
    /// locked.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_new_address(
        &self,
        account: AccountIndex,
    ) -> Result<(u32, Epic1Address), ContactError> {
        // Fails on a locked wallet before anything is stored.
        self.address_at(account, 0)?;
        let session = self.wallet.session()?;
        let index = self
            .contact_work(move |_, _| {
                session
                    .store
                    .write(|repos| epic1_index::issue_next(repos, account))
                    .map_err(|error| match error {
                        IssueError::NotIssuingInstall => refused(Epic1Refusal::NotIssuingInstall),
                        IssueError::Store(error) => error.into(),
                    })
            })
            .await?
            .ok_or(refused(Epic1Refusal::NoAddressLeft))?;
        info!(account = account.0, index, "epic1 address issued");
        Ok((index, self.address_at(account, index)?))
    }

    /// Whether this install issues new epic1 addresses. A wallet created fresh does; one
    /// restored from its recovery phrase does once [`Self::epic1_issue_here`] made it the
    /// issuer. Index 0 is there either way.
    ///
    /// Fails with [`ContactError::Wallet`] when the wallet is locked.
    pub async fn epic1_issuing(&self) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| Ok(session.store.read(epic1_index::issuing)?))
            .await
    }

    /// Makes this install the one that issues new epic1 addresses. Call it on a restored wallet
    /// once no other install on the same recovery phrase issues them: two installs that both
    /// issue hand the same address to two payers. The first address each account issues after
    /// it comes after the restore gap. Calling it again changes nothing.
    ///
    /// Fails with [`ContactError::Wallet`] when the wallet is locked.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_issue_here(&self) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .write(|repos| epic1_index::issue_here(repos))?)
        })
        .await?;
        info!("this install issues epic1 addresses");
        Ok(())
    }

    /// The epic1 addresses `account` issued, at most `limit` from the index `from`.
    ///
    /// Fails with [`ContactError::Wallet`] when the wallet is locked.
    pub async fn epic1_addresses(
        &self,
        account: AccountIndex,
        from: u32,
        limit: u32,
    ) -> Result<Epic1Addresses, ContactError> {
        let session = self.wallet.session()?;
        let highest = self
            .contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    Ok::<_, lepic_store::StoreError>(
                        epic1_index::highest_issued(repos, account)?
                            .max(epic1_index::highest_seen(repos, account)?.unwrap_or(0)),
                    )
                })?)
            })
            .await?;
        let mut addresses = Vec::new();
        if from <= highest {
            let end = from.saturating_add(limit.saturating_sub(1)).min(highest);
            if limit > 0 {
                for index in from..=end {
                    addresses.push(Epic1AddressView {
                        index,
                        address: self.address_at(account, index)?.encode(),
                    });
                }
            }
        }
        Ok(Epic1Addresses {
            account,
            highest,
            addresses,
        })
    }

    /// Issues a link to the epic1 address of the request's account. An on-screen link takes
    /// the next mailbox of the ring of 50, which wraps; a printed one the first of 32 not in
    /// use. The link names the mailbox on each relay of the request, or on the wallet's own
    /// relay; it has no expiry. The link mailbox is stored with when it was issued.
    ///
    /// Fails with [`ContactError::Epic1`] when all printed links are in use, a relay is not
    /// usable, or the message does not fit.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_link(
        &self,
        relays: &ContactRelays,
        request: Epic1LinkRequest,
    ) -> Result<Epic1LinkIssued, ContactError> {
        self.check_contact_network(relays)?;
        let network = self.wallet.config().network;
        let net = contact_network(network);
        if request.relays.len() > lepic_epic1::MAX_TRANSPORTS {
            return Err(refused(Epic1Refusal::TooManyRelays));
        }
        if let Some(message) = &request.message
            && (message.len() > lepic_epic1::MAX_VALUE_LEN || message.chars().any(char::is_control))
        {
            return Err(refused(Epic1Refusal::Message));
        }
        let hosts = if request.relays.is_empty() {
            vec![meeting_host(own_relay(relays)?)]
        } else {
            request.relays.clone()
        };
        let mut places = Vec::with_capacity(hosts.len());
        for host in &hosts {
            let (relay, port) =
                lepic_epic1::parse_host_port(host).map_err(|_| refused(Epic1Refusal::LinkRelay))?;
            host_rule::classify_name(relay.as_str())
                .map_err(|_| refused(Epic1Refusal::LinkRelay))?;
            places.push((relay, port));
        }
        let index = request.index;
        let address = self.address_at(request.account, index)?;
        let account = request.account;
        let kind = request.kind;
        let now = self.wallet.ports().clock.now().as_second();
        let session = self.wallet.session()?;
        let stored_hosts = hosts.clone();
        let stored_amount = request.amount.map(Amount::value);
        let n = self
            .contact_work(move |_, _| {
                session.store.write(|repos| {
                    if index > epic1_index::highest_tried(repos, account)? {
                        return Err(refused(Epic1Refusal::AddressNotIssued));
                    }
                    let n = take_link_mailbox(repos, account, kind)?;
                    let state = LinkState {
                        issued_at: now,
                        used_at: None,
                        relays: stored_hosts,
                        amount: stored_amount,
                        index: Some(index),
                    };
                    repos.put_setting(
                        &link_key(account, kind, n),
                        &to_text(&state, "epic1 link")?,
                    )?;
                    Ok::<_, ContactError>(n)
                })
            })
            .await?;
        let mailbox = kind.mailbox(n).ok_or(refused(Epic1Refusal::NotIssued))?;
        let secret = self.wallet.link_mailbox_key(account, net, mailbox)?;
        let public = PublicKey::from_secret_key(&secret).map_err(|_| ContactError::RelayAddress)?;
        let mut link = Epic1Link::new(address);
        link.transports = places
            .into_iter()
            .map(|(relay, port)| EpicboxTransport::new(public, relay, port))
            .collect();
        link.amount = request.amount;
        link.message = request.message;
        info!(
            account = account.0,
            index,
            kind = kind.key(),
            n,
            "epic1 link issued"
        );
        Ok(Epic1LinkIssued {
            link: link.to_uri(),
            address: link.address.encode(),
            index,
            kind,
            n,
        })
    }

    /// Frees the printed link `n` of `account`: its mailbox is no longer drained and the next
    /// printed link may take it.
    ///
    /// Fails with [`ContactError::Epic1`] when no printed link `n` is in use.
    pub async fn epic1_retire(&self, account: AccountIndex, n: u32) -> Result<(), ContactError> {
        let key = link_key(account, Epic1LinkKind::Printed, n);
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                if repos.setting(&key)?.is_none() {
                    return Err(refused(Epic1Refusal::NotIssued));
                }
                repos.delete_setting(&key)?;
                Ok(())
            })
        })
        .await?;
        info!(account = account.0, n, "printed epic1 link retired");
        Ok(())
    }

    /// The link mailboxes in use, by account, kind and number.
    pub async fn epic1_links(&self) -> Result<Vec<Epic1LinkView>, ContactError> {
        let session = self.wallet.session()?;
        let stored = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.settings_with_prefix(LINK_PREFIX))?)
            })
            .await?;
        let mut links: Vec<Epic1LinkView> = stored
            .into_iter()
            .filter_map(|(key, text)| {
                let (account, kind, n) = parse_link_key(&key)?;
                let state = from_text::<LinkState>(&text, "epic1 link").ok()?;
                Some(Epic1LinkView {
                    account,
                    index: state.index,
                    kind,
                    n,
                    issued_at: seconds(state.issued_at),
                    used_at: state.used_at.map(seconds),
                    relays: state.relays,
                })
            })
            .collect();
        links.sort_by_key(|link| (link.account.0, link.kind, link.n));
        Ok(links)
    }

    /// The S2s this wallet made for payments taken at its link mailboxes.
    pub async fn epic1_answers(
        &self,
        relays: &ContactRelays,
    ) -> Result<Vec<Epic1AnswerView>, ContactError> {
        let session = self.wallet.session()?;
        let stored = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.settings_with_prefix(ANSWER_PREFIX))?)
            })
            .await?;
        Ok(stored
            .into_iter()
            .filter_map(|(key, text)| {
                let slate_id = SlateId::parse(key.strip_prefix(ANSWER_PREFIX)?).ok()?;
                let state = from_text::<AnswerState>(&text, "epic1 answer").ok()?;
                let report = mailbox_endpoint(&state.mailbox, relays)
                    .ok()
                    .map(|(_, report)| report);
                Some(Epic1AnswerView {
                    tx_id: TxId(state.tx_id),
                    slate_id,
                    mailbox: state.mailbox,
                    report,
                    posted: state.posted,
                })
            })
            .collect())
    }

    /// Posts the S2 for the payment `slate_id` to the reply mailbox the payer named, from a
    /// key used for this slate only, through the wallet's connector. Collecting posts it by
    /// itself when the relay is in the relay list; for any other relay `relay_ok` says the
    /// user confirmed the relay [`ContactBook::epic1_answers`] reported. The host is checked again
    /// when connecting, as [`ContactBook::in_person_post`] checks it. Posting again is safe.
    ///
    /// Fails with [`ContactError::Epic1`] when `relay_ok` is false or no S2 is stored,
    /// [`ContactError::InPerson`] for a reply mailbox on this device,
    /// [`ContactError::Offline`] or [`ContactError::EpicboxOff`], and [`ContactError::Relay`]
    /// when the post failed.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_post_answer(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
        relay_ok: bool,
    ) -> Result<(), ContactError> {
        if !relay_ok {
            return Err(refused(Epic1Refusal::RelayNotConfirmed));
        }
        self.check_contact_network(relays)?;
        check_online(relays)?;
        self.post_stored_answer(relays, slate_id).await
    }

    /// Posts the stored answer of `slate_id` to the payer's reply mailbox.
    async fn post_stored_answer(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let state: AnswerState = self
            .contact_work(move |_, _| {
                session
                    .store
                    .read(|repos| load(repos, &answer_key(slate_id), "epic1 answer"))
            })
            .await?;
        let (endpoint, report) = mailbox_endpoint(&state.mailbox, relays)?;
        let key = hex::unhex(&state.mailbox_key)
            .and_then(|key| PublicKey::from_bytes(&key).ok())
            .ok_or(corrupt("epic1 answer"))?;
        let envelope = hex::unhex(&state.envelope).ok_or(corrupt("epic1 answer"))?;
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
                let mut state: AnswerState = load(repos, &answer_key(slate_id), "epic1 answer")?;
                state.posted = true;
                repos.put_setting(&answer_key(slate_id), &to_text(&state, "epic1 answer")?)?;
                Ok::<_, ContactError>(())
            })
        })
        .await?;
        info!(slate_id = %slate_id, "epic1 answer posted");
        Ok(())
    }

    /// Seals the refusal of the payment `slate_id` to its reply key and stores it to post. One
    /// already stored for the slate is kept, as is the store when [`MAX_REFUSALS`] are kept.
    async fn store_refusal(
        &self,
        account: AccountIndex,
        slate_id: SlateId,
        reply_key: &EncPublicKey,
        reply_mailbox: &lepic_seal::ReplyMailbox,
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let body = refusal_body(slate_id, REASON_AMOUNT);
        let envelope = {
            let mut rng = LockedRng(&mut **self.wallet.ports().rng.lock());
            seal(
                net,
                reply_key,
                HintRule::ReplyKey,
                &Content::new(MessageType::Notice, body),
                None,
                &mut rng,
            )
            .map_err(ContactError::Encode)?
        };
        let state = RefusalState {
            account: account.0,
            envelope: hex::encode(&envelope),
            mailbox_key: hex::encode(reply_mailbox.key()),
            mailbox: reply_mailbox.relay().to_owned(),
            posted: false,
            at: self.wallet.ports().clock.now().as_second(),
        };
        let text = to_text(&state, "epic1 refusal")?;
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                let key = refusal_key(slate_id);
                if repos.setting(&key)?.is_some()
                    || repos.settings_with_prefix(REFUSAL_PREFIX)?.len() >= MAX_REFUSALS
                {
                    return Ok::<_, ContactError>(());
                }
                repos.put_setting(&key, &text)?;
                Ok(())
            })
        })
        .await?;
        info!(slate_id = %slate_id, "epic1 refusal stored");
        Ok(())
    }

    /// Posts the stored refusal of `slate_id` to the payer's reply mailbox, from the key the
    /// answer to the slate would be posted from.
    async fn post_stored_refusal(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let state: RefusalState = self
            .contact_work(move |_, _| {
                session
                    .store
                    .read(|repos| load(repos, &refusal_key(slate_id), "epic1 refusal"))
            })
            .await?;
        let (endpoint, report) = mailbox_endpoint(&state.mailbox, relays)?;
        let key = hex::unhex(&state.mailbox_key)
            .and_then(|key| PublicKey::from_bytes(&key).ok())
            .ok_or(corrupt("epic1 refusal"))?;
        let envelope = hex::unhex(&state.envelope).ok_or(corrupt("epic1 refusal"))?;
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
            .post(&from, &to, &armor(&envelope))
            .await
            .map_err(ContactError::Relay)?;
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                let mut state: RefusalState = load(repos, &refusal_key(slate_id), "epic1 refusal")?;
                state.posted = true;
                repos.put_setting(&refusal_key(slate_id), &to_text(&state, "epic1 refusal")?)?;
                Ok::<_, ContactError>(())
            })
        })
        .await?;
        info!(slate_id = %slate_id, "epic1 refusal posted");
        Ok(())
    }

    /// Posts the refusals not posted yet whose reply mailbox is on a relay in the relay list.
    /// A refusal for any other relay is not posted: the user confirms a relay for an answer,
    /// and a refusal only spares the payer a wait. One that fails is tried again at the next
    /// cycle.
    async fn post_trusted_refusals(&self, relays: &ContactRelays) {
        let session = match self.wallet.session() {
            Ok(session) => session,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "epic1 refusals not listed");
                return;
            }
        };
        let stored = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.settings_with_prefix(REFUSAL_PREFIX))?)
            })
            .await;
        let stored = match stored {
            Ok(stored) => stored,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "epic1 refusals not listed");
                return;
            }
        };
        for (key, text) in stored {
            let Some(slate_id) = key
                .strip_prefix(REFUSAL_PREFIX)
                .and_then(|id| SlateId::parse(id).ok())
            else {
                continue;
            };
            let Ok(state) = from_text::<RefusalState>(&text, "epic1 refusal") else {
                continue;
            };
            let trusted = mailbox_endpoint(&state.mailbox, relays)
                .is_ok_and(|(_, report)| report.in_relay_list);
            if state.posted || !trusted {
                continue;
            }
            if let Err(error) = self.post_stored_refusal(relays, slate_id).await {
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "epic1 refusal not posted");
            }
        }
    }

    /// Opens a payment that came to a link mailbox of `account`. The seal key of the address
    /// the link was issued for is tried first; when it does not open, or the wallet does not
    /// know it, the seal keys of every address the account issued are tried, in
    /// [`epic1_index::trial_order`]. Returns the address index it opened at.
    async fn open_link_payment(
        &self,
        account: AccountIndex,
        link: Option<(Epic1LinkKind, u32)>,
        envelope: &[u8],
    ) -> Result<(u32, OpenedPayment), ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let link_index = match link {
            Some((kind, n)) => {
                let session = self.wallet.session()?;
                self.contact_work(move |_, _| {
                    Ok(session.store.read(|repos| {
                        Ok::<_, lepic_store::StoreError>(
                            repos
                                .setting(&link_key(account, kind, n))?
                                .and_then(|text| from_text::<LinkState>(&text, "epic1 link").ok())
                                .and_then(|state| state.index),
                        )
                    })?)
                })
                .await?
            }
            None => None,
        };
        let direct = match link_index {
            Some(index) => {
                let key = self.wallet.epic1_seal_key(account, net, index)?;
                match open_payment(network, envelope, &[(index, key)]) {
                    Err(ContactError::CannotOpen) => None,
                    opened => Some(opened?),
                }
            }
            None => None,
        };
        match direct {
            Some(opened) => Ok(opened),
            None => {
                // Every issued address may be tried: off the async workers.
                let keys = self.wallet.epic1_trial_keys(account, net).await?;
                let envelope = envelope.to_vec();
                self.contact_work(move |_, _| Ok(open_payment(network, &envelope, &keys)))
                    .await?
            }
        }
    }

    /// What the wallet knows for a payment of `slate_id` to a link mailbox of `account`:
    /// whether it was taken before, the account's label, and the amount the link asks.
    async fn payment_context(
        &self,
        account: AccountIndex,
        link: Option<(Epic1LinkKind, u32)>,
        slate_id: SlateId,
    ) -> Result<(bool, Option<String>, Option<u64>), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.read(|repos| {
                let taken = repos.setting(&answer_key(slate_id))?.is_some();
                let asked = match link {
                    Some((kind, n)) => repos
                        .setting(&link_key(account, kind, n))?
                        .and_then(|text| from_text::<LinkState>(&text, "epic1 link").ok())
                        .and_then(|state| state.amount),
                    None => None,
                };
                let label = repos
                    .accounts()?
                    .into_iter()
                    .find(|record| record.index == account)
                    .map(|record| record.label);
                Ok::<_, ContactError>((taken, label, asked))
            })
        })
        .await
    }

    /// Takes a payment that came to the link mailbox of `account`: an S1 sealed to the seal key
    /// of one of its epic1 addresses, received with that address's proof key, its S2 sealed to
    /// the slate's reply key and stored to post ([`Self::open_link_payment`] says which keys
    /// are tried). Returns whether it was new; one taken before changes nothing. A payment
    /// whose amount is not the one the link asks is refused with
    /// [`Epic1Refusal::AmountMismatch`] before anything is received, and a notice that says so
    /// is sealed to its reply key and stored to post to its reply mailbox. A new payment is
    /// taken only within the open receipt cap
    /// ([`lepic_wallet::Wallet::receive_at_link`]); one refused leaves the link as it was.
    async fn take_payment(
        &self,
        account: AccountIndex,
        link: Option<(Epic1LinkKind, u32)>,
        envelope: &[u8],
    ) -> Result<bool, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let (
            index,
            OpenedPayment {
                slate_id,
                v3,
                amount,
                reply_key,
                reply_mailbox,
            },
        ) = self.open_link_payment(account, link, envelope).await?;
        let (taken, label, asked) = self.payment_context(account, link, slate_id).await?;
        if taken {
            debug!(slate_id = %slate_id, "epic1 payment taken before");
            return Ok(false);
        }
        if asked.is_some_and(|asked| asked != amount.value()) {
            if let Err(error) = self
                .store_refusal(account, slate_id, &reply_key, &reply_mailbox)
                .await
            {
                if passes(&error) {
                    return Err(error);
                }
                warn!(slate_id = %slate_id, error = %ErrorChain(&error), "epic1 refusal not stored");
            }
            return Err(refused(Epic1Refusal::AmountMismatch));
        }
        let received = self
            .wallet
            .receive_at_link(
                &file_method(),
                &WireSlate::binary(MediaType::JSON, v3),
                ReceiveRequest {
                    account: label,
                    message: None,
                    proof_key: ProofKey::Epic1 { index },
                },
            )
            .await
            .map_err(ContactError::Receive)?;
        let body = NativeSlate::new(received.slate, Tail::empty())
            .map_err(ContactError::Native)?
            .encode(network);
        let envelope = {
            let mut rng = LockedRng(&mut **self.wallet.ports().rng.lock());
            seal_tx(
                net,
                &reply_key,
                TxKey::Seal(HintRule::ReplyKey),
                &TxContent::new(body),
                None,
                &mut rng,
            )
            .map_err(ContactError::Encode)?
        };
        let state = AnswerState {
            tx_id: received.tx_id.0,
            account: account.0,
            envelope: hex::encode(&envelope),
            mailbox_key: hex::encode(reply_mailbox.key()),
            mailbox: reply_mailbox.relay().to_owned(),
            posted: false,
        };
        let now = self.wallet.ports().clock.now().as_second();
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            let text = to_text(&state, "epic1 answer")?;
            session.store.write(|repos| {
                repos.put_setting(&answer_key(slate_id), &text)?;
                if let Some((kind, n)) = link {
                    mark_used(repos, account, kind, n, now)?;
                }
                Ok::<_, ContactError>(())
            })
        })
        .await?;
        info!(tx_id = %received.tx_id, index, "epic1 payment taken");
        Ok(true)
    }

    /// Reads an epic1 link: the address it pays, what it asks, and the relays of the transports
    /// a payment would be posted to. Nothing is stored.
    ///
    /// Fails with [`ContactError::Epic1Link`] for text that is not an epic1 link, and
    /// [`ContactError::Epic1`] for one of another network or with no usable transport.
    pub fn epic1_read(
        &self,
        relays: &ContactRelays,
        text: &str,
    ) -> Result<Epic1Read, ContactError> {
        let network = self.wallet.config().network;
        let (link, usable) = read_link(text, network, relays)?;
        Ok(Epic1Read {
            address: link.address.encode(),
            amount: link.amount,
            message: link.message,
            label: link.label,
            hosts: usable.into_iter().map(|(_, report)| report).collect(),
        })
    }

    /// Pays an epic1 link: sends the request's S1 with a TTL ([`EPIC1_TTL_BLOCKS`] by default),
    /// asking for a payment proof signed with the epic1 proof key when the request says so,
    /// and seals it to the address in an anonymous, padded envelope with a zero hint. The
    /// envelope names the slate's reply key and a reply mailbox on the wallet's own relay. The
    /// payment is stored, then posted to the link's first transport, and to the next when a
    /// post fails, at most three. `hosts_ok` says the user confirmed every relay
    /// [`ContactBook::epic1_read`] reported; it is not needed when each is in the relay list. Collecting watches the reply mailbox until the TTL
    /// and finalizes the S2 that answers.
    ///
    /// Fails as [`ContactBook::epic1_read`] does, with [`ContactError::Epic1`] when a relay is
    /// not in the relay list and `hosts_ok` is false, the wallet's relay is on this device, the
    /// amount sent is not the one the link asks ([`Epic1Refusal::AmountMismatch`]), a payment to
    /// the link waits for its answer ([`Epic1Refusal::PaymentPending`]),
    /// [`ContactError::Send`] as sending fails, and [`ContactError::Encode`] with [`lepic_seal::EncodeError::BodyTooLarge`] for
    /// a slate too large to seal; a send that could not be sealed or stored is cancelled.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_pay(
        &self,
        relays: &ContactRelays,
        request: Epic1PayRequest,
        hosts_ok: bool,
    ) -> Result<Epic1Paid, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let network = self.wallet.config().network;
        let (link, usable) = read_link(&request.link, network, relays)?;
        if !hosts_confirmed(hosts_ok, &usable) {
            return Err(refused(Epic1Refusal::RelayNotConfirmed));
        }
        if link
            .amount
            .is_some_and(|asked| asked != request.send.amount)
        {
            return Err(refused(Epic1Refusal::AmountMismatch));
        }
        let own = own_relay(relays)?.clone();
        let mailboxes: Vec<String> = usable
            .iter()
            .map(|(transport, _)| hex::encode(&transport.mailbox().to_bytes()))
            .collect();
        self.refuse_while_pending(link.address.encode(), mailboxes)
            .await?;
        let mut send = request.send;
        let account = send.account;
        send.ttl_blocks = Some(send.ttl_blocks.unwrap_or(EPIC1_TTL_BLOCKS));
        send.payment_proof_recipient = if request.proof {
            Some(
                ProofAddress::from_bytes(link.address.proof_key().to_bytes())
                    .map_err(|_| refused(Epic1Refusal::ProofKey))?,
            )
        } else {
            None
        };
        let delivery = Delivery::Export {
            to: Location::File(request.slate_file),
        };
        let sent = match self.wallet.send(&file_method(), send, delivery).await {
            Ok(sent) => sent,
            Err(error @ SendError::Undelivered { tx_id, .. }) => {
                return Err(self.give_up_send(tx_id, ContactError::Send(error)).await);
            }
            Err(error) => return Err(ContactError::Send(error)),
        };
        let entries: Vec<StoredEntry> = usable
            .iter()
            .map(|(transport, _)| StoredEntry {
                mailbox: hex::encode(&transport.mailbox().to_bytes()),
                host: transport_host(transport),
            })
            .collect();
        let envelope = match self
            .store_payment(
                &link.address,
                &own,
                sent.tx_id,
                sent.slate_id,
                account,
                entries,
            )
            .await
        {
            Ok(envelope) => envelope,
            Err(error) => return Err(self.give_up_send(sent.tx_id, error).await),
        };
        let (attempts, posted, uncertain) = self
            .post_payment(relays, sent.slate_id, account, &envelope, &usable, 0)
            .await?;
        Ok(Epic1Paid {
            tx_id: sent.tx_id,
            slate_id: sent.slate_id,
            address: link.address.encode(),
            attempts,
            posted,
            uncertain,
        })
    }

    /// Refuses with [`Epic1Refusal::PaymentPending`] while a payment this wallet made to
    /// `address` at one of the link mailboxes `mailboxes` (hex) waits for its answer: sent,
    /// not finalized and not cancelled. A second payment then would pay twice once the first
    /// arrives.
    async fn refuse_while_pending(
        &self,
        address: String,
        mailboxes: Vec<String>,
    ) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let pending = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    for (_, text) in repos.settings_with_prefix(PAY_PREFIX)? {
                        let Ok(state) = from_text::<PayState>(&text, "epic1 payment") else {
                            continue;
                        };
                        let same_link = state.address == address
                            && state
                                .entries
                                .iter()
                                .any(|entry| mailboxes.contains(&entry.mailbox));
                        if !same_link || state.finalized {
                            continue;
                        }
                        let tx = repos.transaction(TxId(state.tx_id))?;
                        if tx.is_some_and(|tx| tx.state == TxState::Sent) {
                            return Ok::<_, ContactError>(true);
                        }
                    }
                    Ok(false)
                })
            })
            .await?;
        if pending {
            return Err(refused(Epic1Refusal::PaymentPending));
        }
        Ok(())
    }

    /// Seals the stored S1 of `slate_id` to `address` and stores the payment. Returns the
    /// envelope.
    #[allow(clippy::too_many_arguments)] // Each is a separate part of the stored payment.
    async fn store_payment(
        &self,
        address: &Epic1Address,
        own: &RelayEndpoint,
        tx_id: TxId,
        slate_id: SlateId,
        account: AccountIndex,
        entries: Vec<StoredEntry>,
    ) -> Result<Vec<u8>, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let mailbox_secret = self
            .wallet
            .reply_mailbox_key(account, net, slate_id.as_bytes())?;
        let mailbox_key = PublicKey::from_secret_key(&mailbox_secret)
            .map_err(|_| ContactError::RelayAddress)?
            .to_bytes();
        let reply_relay = meeting_host(own);
        let reply_mailbox = lepic_seal::ReplyMailbox::new(mailbox_key, &reply_relay)
            .map_err(|_| refused(Epic1Refusal::OwnRelayLocal))?;
        let session = self.wallet.session()?;
        let uuid = Uuid::from_bytes(*slate_id.as_bytes());
        let (v3, reply) = self
            .contact_work(move |_, _| {
                let stored = session
                    .store
                    .read(|repos| repos.slate(uuid, SlateStage::Standard1))?
                    .ok_or(ContactError::UnknownTransaction)?;
                let reply = reply_secret(&session.keychain, network, account, slate_id)?;
                Ok((stored.bytes, reply.public_key()))
            })
            .await?;
        let mut content = TxContent::new(native_body(network, &v3)?);
        content.reply_key = Some(reply);
        content.reply_mailbox = Some(reply_mailbox);
        let envelope = {
            let mut rng = LockedRng(&mut **self.wallet.ports().rng.lock());
            seal_tx(
                net,
                address.seal_key(),
                TxKey::Epic1,
                &content,
                None,
                &mut rng,
            )
            .map_err(ContactError::Encode)?
        };
        let state = PayState {
            tx_id: tx_id.0,
            account: account.0,
            envelope: hex::encode(&envelope),
            address: address.encode(),
            entries,
            next: 0,
            posted: None,
            finalized: false,
            uncertain: None,
            reply_relay: Some(reply_relay),
        };
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            let text = to_text(&state, "epic1 payment")?;
            session.store.write(|repos| {
                repos.put_setting(&pay_key(slate_id), &text)?;
                Ok::<_, ContactError>(())
            })
        })
        .await?;
        info!(tx_id = %tx_id, "epic1 payment sealed");
        Ok(envelope)
    }

    /// Posts `envelope` to the transports of `usable` from `start` until one takes it, and
    /// stores how far it got. A post that failed after the payment was sent is recorded as
    /// uncertain and the next transport is tried: the payee takes a payment once, wherever it
    /// arrives from. Returns the attempts, the transport posted to and the first uncertain
    /// one, with any stored before.
    async fn post_payment(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
        account: AccountIndex,
        envelope: &[u8],
        usable: &[(EpicboxTransport, HostReport)],
        start: usize,
    ) -> Result<(Vec<Epic1Attempt>, Option<usize>, Option<usize>), ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let armored = armor_tx(envelope);
        let mut attempts = Vec::new();
        let mut posted = None;
        let mut uncertain = None;
        for (index, (transport, report)) in usable.iter().enumerate().skip(start) {
            let host = transport_host(transport);
            let result = async {
                let (endpoint, _) = mailbox_endpoint(&host, relays)?;
                let to = EpicboxAddress::new(
                    *transport.mailbox(),
                    relay_network(network),
                    endpoint.domain().clone(),
                    Some(endpoint.port()),
                );
                let secret =
                    self.wallet
                        .post_key(account, net, slate_id.as_bytes(), PostRole::Initiator)?;
                let from = identity(secret, network, &endpoint)?;
                client_for(relays, endpoint, report.in_relay_list)
                    .post(&from, &to, &armored)
                    .await
                    .map_err(ContactError::Relay)
            }
            .await;
            match result {
                Ok(()) => {
                    attempts.push(Epic1Attempt {
                        host,
                        error: None,
                        uncertain: false,
                    });
                    posted = Some(index);
                    break;
                }
                Err(error) => {
                    let sent = matches!(error, ContactError::Relay(MailboxError::Unanswered(_)));
                    warn!(relay = %host, sent, error = %ErrorChain(&error), "epic1 payment not posted");
                    if sent {
                        uncertain = uncertain.or(Some(index));
                    }
                    attempts.push(Epic1Attempt {
                        host,
                        error: Some(ErrorChain(&error).to_string()),
                        uncertain: sent,
                    });
                }
            }
        }
        let next = posted.map_or(usable.len(), |index: usize| index.saturating_add(1));
        let session = self.wallet.session()?;
        let uncertain = self
            .contact_work(move |_, _| {
                session.store.write(|repos| {
                    let mut state: PayState = load(repos, &pay_key(slate_id), "epic1 payment")?;
                    state.next = next;
                    if posted.is_some() {
                        state.posted = posted;
                    }
                    state.uncertain = state.uncertain.or(uncertain);
                    repos.put_setting(&pay_key(slate_id), &to_text(&state, "epic1 payment")?)?;
                    Ok::<_, ContactError>(state.uncertain)
                })
            })
            .await?;
        if let Some(index) = posted {
            info!(slate_id = %slate_id, transport = index, "epic1 payment posted");
        }
        Ok((attempts, posted, uncertain))
    }

    /// Posts the stored payment `slate_id` again, the same bytes, to the transports of its link
    /// after the one it was last posted to. `hosts_ok` says the user confirmed their relays; it
    /// is not needed when each is in the relay list.
    ///
    /// Fails with [`ContactError::Epic1`] when a relay is not in the relay list and `hosts_ok`
    /// is false, no payment is stored, it was finalized, or every transport was tried.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_post_next(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
        hosts_ok: bool,
    ) -> Result<Epic1Paid, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let session = self.wallet.session()?;
        let state: PayState = self
            .contact_work(move |_, _| {
                session
                    .store
                    .read(|repos| load(repos, &pay_key(slate_id), "epic1 payment"))
            })
            .await?;
        if state.finalized {
            return Err(refused(Epic1Refusal::Finalized));
        }
        if state.next >= state.entries.len() {
            return Err(refused(Epic1Refusal::NoMoreEntries));
        }
        let usable = stored_entries(relays, &state.entries)?;
        if !hosts_confirmed(hosts_ok, &usable) {
            return Err(refused(Epic1Refusal::RelayNotConfirmed));
        }
        let envelope = hex::unhex(&state.envelope).ok_or(corrupt("epic1 payment"))?;
        let (attempts, posted, uncertain) = self
            .post_payment(
                relays,
                slate_id,
                AccountIndex(state.account),
                &envelope,
                &usable,
                state.next,
            )
            .await?;
        Ok(Epic1Paid {
            tx_id: TxId(state.tx_id),
            slate_id,
            address: state.address,
            attempts,
            posted,
            uncertain,
        })
    }

    /// The payment this wallet made to an epic1 link under `slate_id`, when it holds one: its
    /// transaction, address and the transport it was last posted to. It lists no attempts, as
    /// nothing is posted.
    pub async fn epic1_payment(
        &self,
        slate_id: SlateId,
    ) -> Result<Option<Epic1Paid>, ContactError> {
        let session = self.wallet.session()?;
        let state = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    repos
                        .setting(&pay_key(slate_id))?
                        .map(|text| from_text::<PayState>(&text, "epic1 payment"))
                        .transpose()
                        .map_err(ContactError::from)
                })
            })
            .await?;
        Ok(state.map(|state| Epic1Paid {
            tx_id: TxId(state.tx_id),
            slate_id,
            address: state.address,
            attempts: Vec::new(),
            posted: state.posted,
            uncertain: state.uncertain,
        }))
    }

    /// The secret of the reply mailbox of `slate_id`, and the payment this wallet made to an
    /// epic1 link under it, when it holds one.
    async fn reply_state(
        &self,
        slate_id: SlateId,
        account: AccountIndex,
    ) -> Result<(lepic_seal::EncSecretKey, Option<PayState>), ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            let secret = reply_secret(&session.keychain, network, account, slate_id)?;
            let state = session.store.read(|repos| {
                Ok::<_, ContactError>(
                    repos
                        .setting(&pay_key(slate_id))?
                        .and_then(|text| from_text::<PayState>(&text, "epic1 payment").ok()),
                )
            })?;
            Ok((secret, state))
        })
        .await
    }

    /// Takes the refusal of the payment `slate_id` that came to its reply mailbox: a sealed
    /// `declined` notice for the slate, anonymous, sealed to the reply key the S1 gave the payee
    /// and opened with its secret. The relay of the reply mailbox could forge one, which only
    /// frees this wallet's inputs (ADR 0045). The wallet cancels the payment, which frees its
    /// inputs, as it does for a send declined unanswered. A refusal for a payment that is
    /// finalized, was answered or ended changes nothing. Returns whether the payment was
    /// cancelled by it.
    async fn take_epic1_refusal(
        &self,
        slate_id: SlateId,
        account: AccountIndex,
        envelope: &[u8],
    ) -> Result<bool, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let sealed = SealedEnvelope::decode(envelope, net).map_err(ContactError::Decode)?;
        let (secret, state) = self.reply_state(slate_id, account).await?;
        let Some(state) = state else {
            return Ok(false);
        };
        if state.finalized {
            return Ok(false);
        }
        let opened = sealed.open(&secret).map_err(|_| ContactError::CannotOpen)?;
        if opened.sender.is_some() {
            return Err(refused(Epic1Refusal::Signed));
        }
        if opened.content.kind != MessageType::Notice {
            return Err(refused(Epic1Refusal::WrongStage));
        }
        let text = std::str::from_utf8(&opened.content.body)
            .map_err(|_| refused(Epic1Refusal::WrongStage))?;
        match classify_text(text) {
            Payload::Notice(Notice {
                slate_id: named,
                kind: NoticeKind::Declined,
            }) if named == slate_id => {}
            Payload::Notice(Notice {
                slate_id: named, ..
            }) if named != slate_id => {
                return Err(refused(Epic1Refusal::OtherSlate));
            }
            _ => return Err(refused(Epic1Refusal::WrongStage)),
        }
        let cancelled = self
            .wallet
            .send_refused_by_receiver(slate_id)
            .await
            .map_err(ContactError::Wallet)?;
        if cancelled {
            info!(slate_id = %slate_id, "epic1 payment refused by its payee");
        }
        Ok(cancelled)
    }

    /// Finalizes an S2 that came to the reply mailbox of the payment `slate_id` and posts it.
    /// An envelope at the reply mailbox of a slate that is not an epic1 payment is taken as
    /// the answer to an in-person code. Returns
    /// whether something new was taken.
    async fn take_epic1_answer(
        &self,
        slate_id: SlateId,
        account: AccountIndex,
        envelope: &[u8],
    ) -> Result<bool, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let sealed = SealedEnvelope::decode(envelope, net).map_err(ContactError::Decode)?;
        let (secret, state) = self.reply_state(slate_id, account).await?;
        let Some(state) = state else {
            return Ok(!self.take_envelope(envelope).await?.duplicate);
        };
        if state.finalized {
            return Ok(false);
        }
        let opened = sealed
            .open_tx(&secret, KeyClass::Seal)
            .map_err(|_| ContactError::CannotOpen)?;
        if opened.sender.is_some() {
            return Err(refused(Epic1Refusal::Signed));
        }
        let body = opened.content.body;
        let slate = decode_native(network, &body).ok_or(ContactError::NotASlate)?;
        if slate.stage() != Stage::S2 {
            return Err(refused(Epic1Refusal::WrongStage));
        }
        if slate.id() != slate_id {
            return Err(refused(Epic1Refusal::OtherSlate));
        }
        let v3 = self
            .v3_of_native(&body)
            .await?
            .ok_or(ContactError::NotASlate)?;
        let finalized = self
            .wallet
            .finalize(
                &file_method(),
                &WireSlate::binary(MediaType::JSON, v3),
                Propagation::Stem,
            )
            .await
            .map_err(ContactError::Finalize)?;
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                if let Some(text) = repos.setting(&pay_key(slate_id))? {
                    let mut state: PayState = from_text(&text, "epic1 payment")?;
                    state.finalized = true;
                    repos.put_setting(&pay_key(slate_id), &to_text(&state, "epic1 payment")?)?;
                }
                Ok::<_, ContactError>(())
            })
        })
        .await?;
        info!(tx_id = %finalized.tx_id, "epic1 payment finalized");
        Ok(true)
    }

    /// Drains the live link mailboxes and the reply mailboxes of payments waiting for an S2,
    /// and takes what they hold: a payment, an S2, or a refusal of a payment of this wallet.
    /// Posts the answers and refusals sealed here whose reply relay is in the relay list.
    /// Answers and payments whose transaction ended are forgotten, as are refusals kept for
    /// [`REFUSAL_KEPT_FOR`] and on-screen links not used for [`ON_SCREEN_LIVE_FOR`]. Returns
    /// how many payments were taken and S2s finalized.
    pub(crate) async fn collect_epic1(
        &self,
        relays: &ContactRelays,
    ) -> Result<usize, ContactError> {
        let now = self.wallet.ports().clock.now();
        let live_from = now
            .checked_sub(ON_SCREEN_LIVE_FOR)
            .unwrap_or(Timestamp::UNIX_EPOCH)
            .as_second();
        let refusals_from = now
            .checked_sub(REFUSAL_KEPT_FOR)
            .unwrap_or(Timestamp::UNIX_EPOCH)
            .as_second();
        let session = self.wallet.session()?;
        let (links, replies) = self
            .contact_work(move |_, _| {
                session.store.write(|repos| {
                    let mut links = Vec::new();
                    for (key, text) in repos.settings_with_prefix(LINK_PREFIX)? {
                        let Some((account, kind, n)) = parse_link_key(&key) else {
                            continue;
                        };
                        let Ok(state) = from_text::<LinkState>(&text, "epic1 link") else {
                            continue;
                        };
                        let last = state
                            .used_at
                            .unwrap_or(state.issued_at)
                            .max(state.issued_at);
                        if kind == Epic1LinkKind::OnScreen && last < live_from {
                            continue;
                        }
                        for host in state.relays {
                            links.push((host, account, kind, n));
                        }
                    }
                    let mut replies = Vec::new();
                    for (key, text) in repos.settings_with_prefix(PAY_PREFIX)? {
                        let parsed = key
                            .strip_prefix(PAY_PREFIX)
                            .and_then(|id| SlateId::parse(id).ok())
                            .zip(from_text::<PayState>(&text, "epic1 payment").ok());
                        let Some((slate_id, state)) = parsed else {
                            continue;
                        };
                        match repos.transaction(TxId(state.tx_id))?.map(|tx| tx.state) {
                            None => repos.delete_setting(&key)?,
                            Some(state_now) if ended(state_now) => repos.delete_setting(&key)?,
                            Some(TxState::Sent) if !state.finalized => {
                                replies.push((
                                    slate_id,
                                    AccountIndex(state.account),
                                    state.reply_relay,
                                ));
                            }
                            Some(_) => {}
                        }
                    }
                    for (key, text) in repos.settings_with_prefix(ANSWER_PREFIX)? {
                        let Ok(state) = from_text::<AnswerState>(&text, "epic1 answer") else {
                            continue;
                        };
                        let tx = repos.transaction(TxId(state.tx_id))?;
                        if tx.is_none_or(|tx| ended(tx.state)) {
                            repos.delete_setting(&key)?;
                        }
                    }
                    for (key, text) in repos.settings_with_prefix(REFUSAL_PREFIX)? {
                        let kept = from_text::<RefusalState>(&text, "epic1 refusal")
                            .is_ok_and(|state| state.at >= refusals_from);
                        if !kept {
                            repos.delete_setting(&key)?;
                        }
                    }
                    Ok::<_, ContactError>((links, replies))
                })
            })
            .await?;
        let mut taken = self.drain_links(relays, links).await?;
        if !replies.is_empty() {
            taken = taken.saturating_add(self.drain_replies(relays, replies).await?);
        }
        self.post_trusted_answers(relays).await;
        self.post_trusted_refusals(relays).await;
        Ok(taken)
    }

    /// Posts the answers not posted yet whose reply mailbox is on a relay in the relay list.
    /// An answer for any other relay waits for [`ContactBook::epic1_post_answer`]. One that
    /// fails is tried again at the next cycle.
    async fn post_trusted_answers(&self, relays: &ContactRelays) {
        let answers = match self.epic1_answers(relays).await {
            Ok(answers) => answers,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "epic1 answers not listed");
                return;
            }
        };
        for answer in answers {
            if answer.posted || !answer.report.is_some_and(|report| report.in_relay_list) {
                continue;
            }
            if let Err(error) = self.post_stored_answer(relays, answer.slate_id).await {
                warn!(slate_id = %answer.slate_id, error = %ErrorChain(&error), "epic1 answer not posted");
            }
        }
    }

    /// Drains the link mailboxes `links`, `(relay, account, kind, n)`, by relay.
    async fn drain_links(
        &self,
        relays: &ContactRelays,
        links: Vec<(String, AccountIndex, Epic1LinkKind, u32)>,
    ) -> Result<usize, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let mut by_relay: BTreeMap<String, Vec<(AccountIndex, Epic1LinkKind, u32)>> =
            BTreeMap::new();
        for (host, account, kind, n) in links {
            by_relay.entry(host).or_default().push((account, kind, n));
        }
        let mut taken = 0usize;
        for (host, mailboxes) in by_relay {
            let (endpoint, known) = match watched_endpoint(relays, &host) {
                Ok(found) => found,
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "epic1 link mailbox not watched");
                    continue;
                }
            };
            let client = client_for(relays, endpoint.clone(), known);
            for chunk in mailboxes.chunks(MAX_MAILBOXES_PER_DRAIN) {
                let mut identities = Vec::with_capacity(chunk.len());
                for (account, kind, n) in chunk {
                    let mailbox = kind.mailbox(*n).ok_or(refused(Epic1Refusal::NotIssued))?;
                    let secret = self.wallet.link_mailbox_key(*account, net, mailbox)?;
                    identities.push(identity(secret, network, &endpoint)?);
                }
                let mut handler = Payments {
                    book: self,
                    relays,
                    mailboxes: chunk.to_vec(),
                    taken: 0,
                    restore: false,
                };
                let drained = client.drain_once(&identities, &mut handler).await;
                taken = taken.saturating_add(handler.taken);
                if let Err(error) = drained {
                    warn!(relay = %host, error = %ErrorChain(&error), "epic1 link mailboxes not drained");
                }
            }
        }
        Ok(taken)
    }

    /// Drains the reply mailboxes of the slates `replies`, `(slate, account, relay)`, by
    /// relay: the one the payment named, or the wallet's own relay when none is stored. A
    /// payment keeps the relay it named when the wallet's relay setting changes.
    async fn drain_replies(
        &self,
        relays: &ContactRelays,
        replies: Vec<(SlateId, AccountIndex, Option<String>)>,
    ) -> Result<usize, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let own = relays.epicbox.settings().endpoint.clone();
        let own_host = meeting_host(&own);
        let mut by_relay: BTreeMap<String, Vec<(SlateId, AccountIndex)>> = BTreeMap::new();
        for (slate_id, account, host) in replies {
            let host = host.unwrap_or_else(|| own_host.clone());
            by_relay.entry(host).or_default().push((slate_id, account));
        }
        let mut taken = 0usize;
        for (host, slates) in by_relay {
            let (endpoint, client) = if host == own_host {
                (own.clone(), mailbox_client(relays, own.clone(), None))
            } else {
                match watched_endpoint(relays, &host) {
                    Ok((endpoint, known)) => {
                        let client = client_for(relays, endpoint.clone(), known);
                        (endpoint, client)
                    }
                    Err(error) => {
                        warn!(error = %ErrorChain(&error), "epic1 reply mailbox not watched");
                        continue;
                    }
                }
            };
            for chunk in slates.chunks(MAX_MAILBOXES_PER_DRAIN) {
                let mut identities = Vec::with_capacity(chunk.len());
                for (slate_id, account) in chunk {
                    let secret =
                        self.wallet
                            .reply_mailbox_key(*account, net, slate_id.as_bytes())?;
                    identities.push(identity(secret, network, &endpoint)?);
                }
                let mut handler = Replies {
                    book: self,
                    slates: chunk.to_vec(),
                    taken: 0,
                };
                let drained = client.drain_once(&identities, &mut handler).await;
                taken = taken.saturating_add(handler.taken);
                if let Err(error) = drained {
                    warn!(relay = %host, error = %ErrorChain(&error), "epic1 reply mailboxes not drained");
                }
            }
        }
        Ok(taken)
    }

    /// After a restore from the phrase: drains, once, all 50 on-screen and all 32 printed link
    /// mailboxes of every account on the wallet's own relay, and the reply mailboxes of the
    /// pending payments and in-person codes of the wallet's transactions. A link mailbox that
    /// held a payment is marked in use. Links named on other relays are not found. Returns how
    /// many payments were taken and S2s finalized.
    ///
    /// Fails with [`ContactError::Offline`] or [`ContactError::EpicboxOff`], and
    /// [`ContactError::Relay`] when a drain failed.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_restore(&self, relays: &ContactRelays) -> Result<usize, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let own = relays.epicbox.settings().endpoint.clone();
        let session = self.wallet.session()?;
        let (accounts, pending) = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    let accounts: Vec<AccountIndex> = repos
                        .accounts()?
                        .into_iter()
                        .map(|record| record.index)
                        .collect();
                    let mut pending = Vec::new();
                    for account in &accounts {
                        for tx in repos.transactions(*account)? {
                            let entry = &tx.entry;
                            if matches!(entry.state, TxState::Sent | TxState::Received)
                                && let Some(uuid) = entry.slate_id
                            {
                                pending.push((
                                    SlateId::from_bytes(*uuid.as_bytes()),
                                    *account,
                                    None,
                                ));
                            }
                        }
                    }
                    Ok::<_, ContactError>((accounts, pending))
                })
            })
            .await?;
        let mut mailboxes = Vec::new();
        for account in accounts {
            for kind in [Epic1LinkKind::OnScreen, Epic1LinkKind::Printed] {
                for n in 0..kind.count() {
                    mailboxes.push((account, kind, n));
                }
            }
        }
        let client = mailbox_client(relays, own.clone(), None);
        let mut taken = 0usize;
        for chunk in mailboxes.chunks(MAX_MAILBOXES_PER_DRAIN) {
            let mut identities = Vec::with_capacity(chunk.len());
            for (account, kind, n) in chunk {
                let mailbox = kind.mailbox(*n).ok_or(refused(Epic1Refusal::NotIssued))?;
                let secret = self.wallet.link_mailbox_key(*account, net, mailbox)?;
                identities.push(identity(secret, network, &own)?);
            }
            let mut handler = Payments {
                book: self,
                relays,
                mailboxes: chunk.to_vec(),
                taken: 0,
                restore: true,
            };
            let drained = client.drain_once(&identities, &mut handler).await;
            taken = taken.saturating_add(handler.taken);
            drained.map_err(ContactError::Relay)?;
        }
        if !pending.is_empty() {
            taken = taken.saturating_add(self.drain_replies(relays, pending).await?);
        }
        info!(taken, "epic1 mailboxes drained after a restore");
        Ok(taken)
    }

    /// Marks the link mailbox `n` of `kind` of `account` in use after a restore found a payment
    /// in it, and moves the ring past an on-screen one.
    async fn mark_found(
        &self,
        relays: &ContactRelays,
        account: AccountIndex,
        kind: Epic1LinkKind,
        n: u32,
    ) -> Result<(), ContactError> {
        let now = self.wallet.ports().clock.now().as_second();
        let host = meeting_host(&relays.epicbox.settings().endpoint);
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                let key = link_key(account, kind, n);
                if repos.setting(&key)?.is_none() {
                    let state = LinkState {
                        issued_at: now,
                        used_at: Some(now),
                        relays: vec![host],
                        amount: None,
                        index: None,
                    };
                    repos.put_setting(&key, &to_text(&state, "epic1 link")?)?;
                }
                if kind == Epic1LinkKind::OnScreen {
                    let ring = repos
                        .setting(&ring_key(account))?
                        .and_then(|text| text.parse::<u32>().ok())
                        .unwrap_or(0);
                    let next = n
                        .saturating_add(1)
                        .checked_rem(LinkMailbox::ON_SCREEN)
                        .unwrap_or(0);
                    if n >= ring {
                        repos.put_setting(&ring_key(account), &next.to_string())?;
                    }
                }
                Ok::<_, ContactError>(())
            })
        })
        .await
    }
}

/// Records that the link mailbox `n` of `kind` of `account` took a payment at `now`.
fn mark_used(
    repos: &mut dyn Repositories,
    account: AccountIndex,
    kind: Epic1LinkKind,
    n: u32,
    now: i64,
) -> Result<(), ContactError> {
    let key = link_key(account, kind, n);
    if let Some(text) = repos.setting(&key)? {
        let mut state: LinkState = from_text(&text, "epic1 link")?;
        state.used_at = Some(now);
        repos.put_setting(&key, &to_text(&state, "epic1 link")?)?;
    }
    Ok(())
}

/// The transports stored for a payment, with what the user is shown about each relay.
fn stored_entries(
    relays: &ContactRelays,
    entries: &[StoredEntry],
) -> Result<Vec<(EpicboxTransport, HostReport)>, ContactError> {
    let mut usable = Vec::with_capacity(entries.len());
    for entry in entries {
        let mailbox = hex::unhex(&entry.mailbox)
            .and_then(|key| PublicKey::from_bytes(&key).ok())
            .ok_or(corrupt("epic1 payment"))?;
        let (relay, port) =
            lepic_epic1::parse_host_port(&entry.host).map_err(|_| corrupt("epic1 payment"))?;
        let (_, report) = mailbox_endpoint(&entry.host, relays)?;
        usable.push((EpicboxTransport::new(mailbox, relay, port), report));
    }
    Ok(usable)
}

/// Takes the payments drained from link mailboxes. Anything but a sealed slate envelope is
/// acknowledged and dropped, as is a payment refused; one whose take failed for a passing
/// reason is kept.
struct Payments<'a, N, S: StoreOpener, V> {
    book: &'a ContactBook<'a, N, S, V>,
    relays: &'a ContactRelays,
    /// The link mailbox of each identity drained.
    mailboxes: Vec<(AccountIndex, Epic1LinkKind, u32)>,
    taken: usize,
    /// Mark a link mailbox that held a payment in use.
    restore: bool,
}

impl<N, S, V> MailboxHandler for Payments<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            let Some(&(account, kind, n)) = self.mailboxes.get(message.mailbox()) else {
                return Handled::Later;
            };
            let MailboxContent::Opened(received) = message.into_content() else {
                return Handled::Stored;
            };
            let Ok((envelope, ArmorMarker::Tx)) = dearmor_marked(received.plaintext.expose_str())
            else {
                info!(
                    reason = "not a slate envelope",
                    "epic1 link mailbox message dropped"
                );
                return Handled::Stored;
            };
            let taken = self
                .book
                .take_payment(account, Some((kind, n)), &envelope)
                .await;
            if self.restore
                && taken.is_ok()
                && let Err(error) = self.book.mark_found(self.relays, account, kind, n).await
            {
                warn!(error = %ErrorChain(&error), "epic1 link not marked in use");
                return Handled::Later;
            }
            match taken {
                Ok(new) => {
                    if new {
                        self.taken = self.taken.saturating_add(1);
                    }
                    Handled::Stored
                }
                Err(error) if passes(&error) => {
                    warn!(error = %ErrorChain(&error), "epic1 payment kept until the failure passes");
                    Handled::Later
                }
                Err(error) => {
                    info!(reason = %ErrorChain(&error), "epic1 link mailbox message dropped");
                    Handled::Stored
                }
            }
        })
    }
}

/// Takes the answers drained from the reply mailboxes of payments and in-person codes.
struct Replies<'a, N, S: StoreOpener, V> {
    book: &'a ContactBook<'a, N, S, V>,
    /// The slate of each identity drained.
    slates: Vec<(SlateId, AccountIndex)>,
    taken: usize,
}

impl<N, S, V> MailboxHandler for Replies<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            let Some(&(slate_id, account)) = self.slates.get(message.mailbox()) else {
                return Handled::Later;
            };
            let MailboxContent::Opened(received) = message.into_content() else {
                return Handled::Stored;
            };
            let Ok((envelope, marker)) = dearmor_marked(received.plaintext.expose_str()) else {
                info!(reason = "not an envelope", "reply mailbox message dropped");
                return Handled::Stored;
            };
            let taken = match marker {
                ArmorMarker::Tx => {
                    self.book
                        .take_epic1_answer(slate_id, account, &envelope)
                        .await
                }
                ArmorMarker::Sealed => {
                    self.book
                        .take_epic1_refusal(slate_id, account, &envelope)
                        .await
                }
            };
            match taken {
                Ok(new) => {
                    if new {
                        self.taken = self.taken.saturating_add(1);
                    }
                    Handled::Stored
                }
                Err(error) if passes(&error) => {
                    warn!(error = %ErrorChain(&error), "answer kept until the failure passes");
                    Handled::Later
                }
                Err(error) => {
                    info!(reason = %ErrorChain(&error), "reply mailbox message dropped");
                    Handled::Stored
                }
            }
        })
    }
}
