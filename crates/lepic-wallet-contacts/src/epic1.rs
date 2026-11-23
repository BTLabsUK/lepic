// SPDX-License-Identifier: Apache-2.0
//! Payments to an epic1 address (RFC 0003 §5.13, §5.14, §5.19): the address, the links that
//! ask a payment to it, and the slates exchanged through its delivery mailbox.
//!
//! Each account has one epic1 address, index 0. A link is that address with an amount, a
//! message and route entries; the wallet stores nothing for it, and a payment to it is taken
//! whatever amount it pays. A payer seals an S1 to the address's seal
//! key in an anonymous type `0A` envelope with a zero hint, names the slate's reply key (tag 03)
//! and a reply route (tag 09) holding the key of a one-time reply mailbox, and posts it to the
//! address's delivery mailbox, the delivery key on any relay. The payee receives it, refusing
//! one that asks for a payment proof, and seals the S2 to the reply key; the wallet posts it
//! once, to the reply mailbox on the relay the payment was read from and on the 2 healthiest
//! other relays of the list (`delivery::epicbox::post_mailboxes`). A copy read on another relay
//! is answered with the same bytes or not at all.
//!
//! The watch set holds the delivery mailbox of every account's address on every usable relay
//! of the relay list, and the reply mailbox of each payment waiting for its S2; the contacts' sessions
//! read them by push with the contact mailboxes.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};

use jiff::Timestamp;
use lepic_crypto::PublicKey;
use lepic_epic1::{Epic1Address, Epic1Link, MethodId, RouteEntry, Skipped};
use lepic_epicbox::{
    Domain, EpicboxAddress, MailboxContent, MailboxMessage, RELAY_MAX_STR_BYTES, RelayEndpoint,
    sealed_str_len,
};
use lepic_methods::epicbox::relay_network;
use lepic_native_slate::{NativeSlate, Tail};
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::amount::Amount;
use lepic_primitives::amount::Height;
use lepic_primitives::error_chain::ErrorChain;
use lepic_primitives::params::Network;
use lepic_seal::{
    ArmorMarker, EncPublicKey, EncSecretKey, Hint, HintRule, KeyClass, MessageType, ReplyRoute,
    SealedEnvelope, TxContent, TxKey, TxKind, TxOpened, armor_tx, dearmor_marked, seal_tx,
};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::SlateId;
use lepic_slate::stage::Stage;
use lepic_store::{
    AccountIndex, MailClass, NativeOutboxId, OutboxState, Repositories, SlateStage, StoreError,
    StoredNativeOutbox, TxDirection, TxId, TxState, WalletStore, WatchRow,
};
use lepic_transport::host_rule;
use lepic_transport::transport::{BoxFuture, Location, PostedSize};
use lepic_wallet::epic1_index;
use lepic_wallet::finalize::Finalized;
use lepic_wallet::notice::{Notice, Payload, Reason, classify_text};
use lepic_wallet::ports::{SecretVault, StoreOpener};
use lepic_wallet::receive::{ProofKey, ReceiveError, ReceiveRequest, Received};
use lepic_wallet::send::{
    CarriedSend, Delivery, MeasurePost, SendError, SendRequest, StoreCarried,
};
use lepic_wallet::{NoticeFrom, Taken};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::collect::{CollectReport, CollectTrigger, Job, Told, all_watched, passes};
use super::delivery::epicbox::usable_relays;
use super::delivery::outbox::{self, NextRouteError, Owed, Sender, Tried, link_carrier};
use super::delivery::reconcile::Mailboxes;
use super::delivery::router::{Handler, Hold, Pushed, Stored};
use super::delivery::transport::Reach;
use super::delivery::watch::WatchError;
use super::epic1_receipt::{self, ReceiptFault, receipt_key};
use super::in_person::{corrupt, from_text, known_endpoint, reply_secret, to_text};
use super::keys::contact_network;
use super::mailboxes::{MailboxList, check_public};
use super::native::{decode_native, native_body, v3_of_native};
use super::notice_out::{NoticeTo, send_notice};
use super::outbox::MailboxRefusal;
use super::relay::{check_online, endpoint_for, host_text, mailbox_host};
use super::{ContactError, ContactRelays, LockedRng};
use crate::{ContactBook, file_method, hex};

/// The TTL of a payment to an epic1 link, in blocks past the chain tip, when the caller gives
/// none.
pub const EPIC1_TTL_BLOCKS: u64 = lepic_wallet::DEFAULT_TTL_BLOCKS;

/// The S2 this wallet made for an S1 taken at a delivery mailbox, by slate id.
const ANSWER_PREFIX: &str = "epic1.answer.";

/// A payment this wallet made to an epic1 link, by slate id.
const PAY_PREFIX: &str = "epic1.pay.";

/// The refusal this wallet sealed for an S1 taken at a delivery mailbox and not received, by
/// slate id.
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
    /// The envelope at a delivery mailbox is signed: a payment to an epic1 is anonymous.
    #[error("the payment is signed")]
    Signed,
    /// The envelope's hint is not zero.
    #[error("the envelope's hint is not zero")]
    HintNotZero,
    /// The payment names no reply key (tag 03).
    #[error("the payment names no reply key")]
    NoReplyKey,
    /// The payment's reply route (tag 09) names no mailbox the payee can answer on.
    #[error("the payment names no reply route")]
    NoReplyRoute,
    /// The slate is at a stage this call does not take: only an S1 comes to a delivery
    /// mailbox, and only an S2 answers one.
    #[error("the slate is at a stage this call does not take")]
    WrongStage,
    /// The answer is for another slate than the payment.
    #[error("the answer is for another slate")]
    OtherSlate,
    /// This wallet holds no answer or payment for the slate.
    #[error("no epic1 payment for this slate")]
    NoPayment,
    /// Every transport of the link was tried.
    #[error("no transport of the link is left to try")]
    NoMoreEntries,
    /// Making a link: an entry given for it is not an `http` host or onion with an optional
    /// port, or its host is on this device.
    #[error("a link entry is not usable")]
    LinkRelay,
    /// Making a link: more entries were given than a link carries.
    #[error("a link carries at most three entries")]
    TooManyRelays,
    /// The message is longer than a link carries or holds control characters.
    #[error("the message does not fit in a link")]
    Message,
    /// The payment was finalized already.
    #[error("the payment was finalized already")]
    Finalized,
    /// Tor is expected and the link's entry is `http`, which would connect directly. Paying
    /// it needs Tor turned off, or an entry that does not go direct.
    #[error("Tor is expected and this link's http entry would connect directly")]
    TorExpected,
    /// The payment requires a receipt and the payee's answer carries none: it is not
    /// finalized, and the payment is cancelled.
    #[error("the payee's answer brings no payment proof")]
    NoReceipt,
    /// The payment requires a receipt and the one the payee's answer carries does not hold for
    /// the payment: it is not finalized, and the payment is cancelled.
    #[error("the payee's payment proof does not verify")]
    BadReceipt,
}

/// A link to make: the account's address, with what the link asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1LinkRequest {
    pub account: AccountIndex,
    pub amount: Option<Amount>,
    pub message: Option<String>,
    /// The `http` and `tor` entries the link carries, at most three, in link order. A link
    /// without entries is paid through the address's delivery mailbox.
    pub entries: Vec<RouteEntry>,
}

/// A link this wallet issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1LinkIssued {
    /// The link text, `epic:epic1…`.
    pub link: String,
    /// The epic1 address the link pays.
    pub address: String,
}

/// What a restore read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Epic1Restored {
    /// Payments taken and S2s finalized.
    pub taken: usize,
    /// The mailboxes of the list that were not read, each with why.
    pub not_read: Vec<Epic1NotRead>,
}

/// A mailbox a restore did not read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Epic1NotRead {
    /// The mailbox, `domain:port`.
    pub host: String,
    /// Why it was not read.
    pub reason: NotReadReason,
}

/// Why a restore did not read a mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NotReadReason {
    /// The mailbox does not offer mux/1.
    #[error("it does not offer mux/1")]
    NoPush,
    /// No session to the mailbox could be had, or none of its sessions answered.
    #[error("it did not answer")]
    NotAnswering,
    /// Some of the slots to read could not be watched on it.
    #[error("some slots could not be watched on it")]
    SlotsLeftOut,
}

impl NotReadReason {
    /// The reason a watch error gives, if it means the mailbox was not reached.
    fn of_watch(error: &WatchError) -> Option<Self> {
        match error {
            WatchError::NoPush => Some(Self::NoPush),
            WatchError::Session(_) => Some(Self::NotAnswering),
            WatchError::LeftOut { .. } => None,
        }
    }
}

/// What an epic1 link asks, as the host shows it before the user pays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1Read {
    /// The payee: the epic1, never a mailbox.
    pub address: String,
    pub amount: Option<Amount>,
    pub message: Option<String>,
    pub label: Option<String>,
    /// The host of the link's first usable `http` or `tor` entry, which a payment is posted to
    /// first; `None` when the payment goes to the address's delivery mailbox on the relays of
    /// the list.
    pub http_host: Option<String>,
    /// How many `mailbox=` entries the link holds. They are read past: no link names a mailbox,
    /// and none is connected to.
    pub ignored_mailboxes: usize,
}

/// A payment to make to an epic1 link.
#[derive(Debug, Clone)]
pub struct Epic1PayRequest {
    /// The link text.
    pub link: String,
    /// The send. Its TTL is [`EPIC1_TTL_BLOCKS`] when it sets none; it asks for no payment
    /// proof.
    pub send: SendRequest,
    /// A path in the wallet's directory the S1 is written to on the way; the caller removes it.
    pub slate_file: PathBuf,
    /// The mailboxes this one payment goes through, in place of the wallet's list, each a
    /// public name: the payee's, or the wallet's own when payer and payee share a private one.
    /// Empty to pay through the list.
    pub mailboxes: Vec<RelayEndpoint>,
    /// Finalize only on an answer that carries a receipt that holds
    /// (`docs/protocols/epic1-receipt.md`): an S2 with none, or with one that does not hold, is
    /// refused and the payment cancelled. Off, such an answer is finalized with no receipt kept.
    pub require_receipt: bool,
}

/// A post of a payment to one transport of a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1Attempt {
    /// The relay that took the post, `domain:port`; for a post no relay took, the route's
    /// value: the host of an `http` or `tor` entry, the mailbox key of a delivery mailbox.
    pub host: String,
    /// Why the post failed; `None` when it went through.
    pub error: Option<String>,
    /// The post failed after the payment was sent: the relay may hold it, and the payee may
    /// still take it from there.
    pub uncertain: bool,
    /// The mailbox refused the post: its words, the wait it asked for and whether the post
    /// goes again. `None` when no mailbox refused it.
    pub refusal: Option<MailboxRefusal>,
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

/// An S2 this wallet made for a payment taken at a delivery mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epic1AnswerView {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The relay of the payer's reply mailbox, the one the payment was read from.
    pub mailbox: String,
    pub posted: bool,
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
}

impl AnswerState {
    /// The answer's post to the payer's reply mailbox.
    fn owed(
        &self,
        network: Network,
        relays: &ContactRelays,
        slate_id: SlateId,
    ) -> Result<Owed, ContactError> {
        let route = answer_route(
            network,
            relays,
            &self.mailbox_key,
            &self.mailbox,
            "epic1 answer",
        )?;
        let envelope = hex::unhex(&self.envelope).ok_or(corrupt("epic1 answer"))?;
        let owed = Owed {
            payment_id: Uuid::from_bytes(*slate_id.as_bytes()),
            sender: Sender::Payee(AccountIndex(self.account)),
            route,
            envelope: armor_tx(&envelope),
            cutoff: None,
            stage: Some(SlateStage::Standard2),
            notice: false,
        };
        Ok(owed)
    }
}

/// The newest outbox row of the answer to `slate_id` from `account`.
fn answer_row(
    repos: &dyn Repositories,
    slate_id: SlateId,
    account: u32,
) -> Result<Option<StoredNativeOutbox>, StoreError> {
    let from_ref = Sender::Payee(AccountIndex(account)).from_ref();
    Ok(repos
        .native_outbox_of(Uuid::from_bytes(*slate_id.as_bytes()))?
        .into_iter()
        .filter(|row| {
            row.entry.from_ref == from_ref && row.entry.stage == Some(SlateStage::Standard2)
        })
        .max_by_key(|row| row.id))
}

/// The refusal of a payment, kept so a copy of it read again is refused once. Its notice goes
/// out as a notice row (ADR 0067); a state an earlier build wrote with the sealed notice in it
/// still reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefusalState {
    /// The account of the address the payment came to.
    account: u32,
    /// The payer's reply mailbox key, hex, and relay.
    mailbox_key: String,
    mailbox: String,
    /// Unix seconds when it was sealed.
    at: i64,
}

/// A route of a payment, as the link wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredRoute {
    method: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PayState {
    tx_id: u32,
    account: u32,
    /// The sealed S1, hex.
    envelope: String,
    /// The epic1 the payment is to.
    address: String,
    /// The usable routes of the link, in the order they are tried: its `http` and `tor`
    /// entries, or the address's delivery mailbox by its key alone, posted to every relay of
    /// the list. A payment stored by an earlier release may hold `<key>@<relay>` routes. The
    /// outbox holds how far the payment got. A record of an earlier release with fields no
    /// longer kept still reads: they are ignored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    routes: Vec<StoredRoute>,
    /// For a payment to the delivery mailbox, the relays of the list at the time of paying, as
    /// [`address_relays`] gives them: each one not known to lack mux/1, named as the watch rows
    /// name it. Empty for a payment on `http` or `tor` entries. The payer reads its answer on
    /// these relays and on the relays of the list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    relays: Vec<String>,
    /// The payment goes through `relays`, which the pay call gave, in place of the list.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    given: bool,
    /// The payer finalizes only on an answer with a receipt that holds
    /// ([`Epic1PayRequest::require_receipt`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    require_receipt: bool,
    finalized: bool,
}

/// Where the outbox row of an epic1 payment is left by the write that stores it with its send.
type PaymentRow = Arc<std::sync::Mutex<Option<NativeOutboxId>>>;

/// An epic1 payment ready to be stored with its send: all but the send's own parts.
struct CarriedPayment {
    network: Network,
    seal_key: EncPublicKey,
    reply: EncPublicKey,
    mailbox_key: [u8; 33],
    /// The payer key the S1 asks a receipt for (tag 84).
    receipt_ask: [u8; 33],
    first: RouteEntry,
    /// The record, its transaction and envelope still to be filled in.
    state: PayState,
}

impl CarriedPayment {
    /// Seals the stored S1 of `send` and stores the payment with its post, in `repos`.
    /// Returns the post's outbox row.
    fn store(
        &self,
        repos: &mut dyn Repositories,
        send: CarriedSend<'_>,
        rng: &mut (dyn rand_core::CryptoRng + Send),
    ) -> Result<NativeOutboxId, ContactError> {
        let body = native_body(self.network, send.v3)?;
        let ttl_cutoff = decode_native(self.network, &body)
            .and_then(|slate| slate.ttl_cutoff_height())
            .map(|height| Height::new(height.value()));
        let mut content = TxContent::new(body);
        content.reply_key = Some(self.reply);
        content.reply_route = Some(ReplyRoute::epicbox(self.mailbox_key));
        content.receipt_ask = Some(self.receipt_ask);
        let envelope = seal_tx(
            contact_network(self.network),
            &self.seal_key,
            TxKey::Epic1,
            &content,
            None,
            &mut LockedRng(rng),
        )
        .map_err(ContactError::Encode)?;
        let state = PayState {
            tx_id: send.tx_id.0,
            envelope: hex::encode(&envelope),
            ..self.state.clone()
        };
        let text = to_text(&state, "epic1 payment")?;
        // The wallet's own limit counts when it comes before the TTL.
        let cutoff = pay_cutoff(repos, ttl_cutoff, send.tx_id)?;
        repos.put_setting(&pay_key(send.slate_id), &text)?;
        let id = outbox::enqueue(
            repos,
            &Owed {
                payment_id: Uuid::from_bytes(*send.slate_id.as_bytes()),
                sender: Sender::Payer(AccountIndex(self.state.account)),
                route: self.first.clone(),
                envelope: armor_tx(&envelope),
                cutoff,
                stage: Some(SlateStage::Standard1),
                notice: false,
            },
            send.now,
        )?;
        info!(tx_id = %send.tx_id, "epic1 payment sealed");
        Ok(id)
    }
}

impl PayState {
    /// The routes of the payment, in the order they are tried.
    fn route_entries(&self) -> Result<Vec<RouteEntry>, ContactError> {
        stored_entries(&self.routes, "epic1 payment")
    }
}

/// Refuses the host of an `http` or `tor` route that a payment may not be posted to: an `http`
/// host that is not a host name or address on another device, or one on the local network
/// that is not a relay of the relay list. An onion is public. An `epicbox` route has no host to
/// check here and is refused.
fn check_entry_host(route: &RouteEntry, relays: &ContactRelays) -> Result<(), ContactError> {
    let (host, _) = route.host_port().ok_or(ContactError::RelayAddress)?;
    if route.method != MethodId::Http {
        return Ok(());
    }
    let class = host_rule::classify_name(&host).map_err(|_| ContactError::RelayAddress)?;
    // A host the wallet lists is one it reaches as its own, on any port.
    let in_relay_list = Domain::parse(&host)
        .ok()
        .and_then(|domain| known_endpoint(relays, &domain, None))
        .is_some();
    if class == host_rule::HostClass::LocalNetwork && !in_relay_list {
        return Err(ContactError::RelayAddress);
    }
    Ok(())
}

/// Marks the stored payment `slate_id` finalized in the caller's write. Its `posted` goes when
/// it is first posted ([`ContactBook::send_payer_notice`]).
fn mark_finalized(repos: &mut dyn Repositories, slate_id: SlateId) -> Result<(), ContactError> {
    let Some(text) = repos.setting(&pay_key(slate_id))? else {
        return Ok(());
    };
    let mut state: PayState = from_text(&text, "epic1 payment")?;
    if state.finalized {
        return Ok(());
    }
    state.finalized = true;
    repos.put_setting(&pay_key(slate_id), &to_text(&state, "epic1 payment")?)?;
    Ok(())
}

/// Queues the payer's `notice` of the payment in `state`, in the caller's write: sealed to the
/// seal key of the address it paid, as a notice row (ADR 0067) on the delivery mailbox an S1
/// of the payment was posted to or may have reached, which the carrier posts to every usable
/// relay of the list with no transaction id (RFC 0003 5.9). A payment that went only by an
/// `http` or `tor` entry, or never went out, gets none.
fn queue_payer_notice(
    repos: &mut dyn Repositories,
    (network, rng): (Network, &mut LockedRng<'_>),
    state: &PayState,
    notice: &Notice,
    now: Timestamp,
) -> Result<(), ContactError> {
    let account = AccountIndex(state.account);
    let from_ref = Sender::Payer(account).from_ref();
    let Some(slate_id) = notice.slate_id() else {
        return Ok(());
    };
    let payment_id = Uuid::from_bytes(*slate_id.as_bytes());
    let Some(mailbox) = repos.native_outbox_of(payment_id)?.into_iter().find(|row| {
        row.entry.from_ref == from_ref
            && row.entry.stage == Some(SlateStage::Standard1)
            && matches!(
                row.entry.state,
                OutboxState::Posted | OutboxState::Uncertain
            )
            && row.entry.route_method == MethodId::Epicbox.as_str()
            && !row.entry.route_value.contains('@')
    }) else {
        return Ok(());
    };
    let Ok(address) = Epic1Address::decode(&state.address, relay_network(network)) else {
        warn!(
            tx_id = state.tx_id,
            "epic1 payment names no address it can seal a notice to"
        );
        return Ok(());
    };
    let to = NoticeTo::Address {
        account,
        seal_key: address.seal_key(),
        mailbox: mailbox.entry.route_value,
    };
    send_notice(repos, (network, rng), notice, to, now)?;
    Ok(())
}

/// Refuses an entry the payer may not post on: one [`check_entry_host`] refuses, and an `http`
/// entry while Tor is expected, as it would connect directly.
fn check_payer_entry(route: &RouteEntry, relays: &ContactRelays) -> Result<(), ContactError> {
    if relays.tor_expected && route.method == MethodId::Http {
        return Err(refused(Epic1Refusal::TorExpected));
    }
    check_entry_host(route, relays)
}

fn refused(refusal: Epic1Refusal) -> ContactError {
    ContactError::Epic1(refusal)
}

/// Refuses a route entry a link may not carry: an `epicbox` entry, an `http` host that is not a
/// host on another device, or on the local network and not a relay of the relay list.
fn check_link_entry(entry: &RouteEntry, relays: &ContactRelays) -> Result<(), ContactError> {
    check_entry_host(entry, relays).map_err(|_| refused(Epic1Refusal::LinkRelay))
}

/// The route entries of a stored record, in order.
fn stored_entries(
    stored: &[StoredRoute],
    what: &'static str,
) -> Result<Vec<RouteEntry>, ContactError> {
    stored
        .iter()
        .map(|route| {
            Ok(RouteEntry {
                method: route.method.parse().map_err(|_| corrupt(what))?,
                value: route.value.clone(),
            })
        })
        .collect()
}

/// What the wallet knows for a payment to an address before it takes it.
struct PaymentContext {
    /// Whether the payment's slate was answered before.
    taken: bool,
    /// The label of the address's account.
    label: Option<String>,
}

/// The longest text a relay gets for the payment of the S1 `v3` to `seal_key`, over the
/// Epicbox mailboxes `mailboxes` it may be posted to: sealed as [`ContactBook::epic1_pay`]
/// stores it, armored, then sealed for the relay. The reply keys are placeholders of their
/// length; the padding hides the rest. `None` when no mailbox is given or the slate does not
/// seal, which storing the payment reports.
fn sealed_s1_size(
    network: Network,
    seal_key: &EncPublicKey,
    mailboxes: &[EpicboxAddress],
    v3: &[u8],
    rng: &mut (dyn rand_core::CryptoRng + Send),
) -> Option<PostedSize> {
    let mut content = TxContent::new(native_body(network, v3).ok()?);
    content.reply_key = Some(EncSecretKey::from_bytes([1; 32]).public_key());
    content.reply_route = Some(ReplyRoute::epicbox([2; 33]));
    content.receipt_ask = Some([2; 33]);
    let envelope = seal_tx(
        contact_network(network),
        seal_key,
        TxKey::Epic1,
        &content,
        None,
        &mut LockedRng(rng),
    )
    .ok()?;
    let armored = armor_tx(&envelope).len();
    let bytes = mailboxes
        .iter()
        .map(|to| sealed_str_len(armored, to).unwrap_or(armored))
        .max()?;
    Some(PostedSize {
        bytes,
        limit: RELAY_MAX_STR_BYTES,
    })
}

/// The relays the delivery mailboxes are watched on: each of [`usable_relays`], as the watch
/// rows name it.
pub(crate) fn address_relays(relays: &ContactRelays) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for endpoint in usable_relays(relays) {
        let host = mailbox_host(&endpoint);
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

/// The mailboxes a restore reads, each as the watch rows name it and as the report names it:
/// every mailbox of the list.
fn restore_relays(relays: &ContactRelays) -> Vec<(String, String)> {
    let mut read: Vec<(String, String)> = Vec::new();
    for endpoint in relays.list() {
        let name = mailbox_host(&endpoint);
        if !read.iter().any(|(known, _)| *known == name) {
            read.push((name, host_text(&endpoint)));
        }
    }
    read
}

/// The watch rows of a restore round: each mailbox of `mailboxes`, `(key_ref, class, job)`, on
/// each relay of `read_on`.
fn restore_rows(
    mailboxes: &[(String, MailClass, Job)],
    read_on: &[(String, String)],
) -> Vec<(WatchRow, Job)> {
    let mut rows = Vec::with_capacity(mailboxes.len().saturating_mul(read_on.len()));
    for (key_ref, class, job) in mailboxes {
        for (relay, _) in read_on {
            rows.push((
                WatchRow {
                    key_ref: key_ref.clone(),
                    relay: relay.clone(),
                    class: *class,
                    expires_at: None,
                },
                *job,
            ));
        }
    }
    rows
}

/// The watch rows of the delivery mailbox of each account's address, on each of
/// `address_relays`, and of the reply mailboxes of the payments waiting for their answer. The
/// payee answers a payment on the
/// relay it read it from: a payment to the delivery mailbox has a reply row on each relay it
/// went to when it was paid and on each of `address_relays`, where the outbox posts it again;
/// one stored by an earlier release has one on the relay of each `<key>@<relay>` route, and
/// one on each of `address_relays` when it holds no route. A payment
/// posted by `http` or `tor` only is answered in the post's reply and has none. A payment's rows
/// stay from its send until its transaction is confirmed, cancelled or expired.
pub(crate) fn epic1_rows(
    repos: &dyn Repositories,
    address_relays: &[String],
) -> Result<Vec<(WatchRow, Job)>, ContactError> {
    let mut rows = Vec::new();
    for account in repos.accounts()? {
        let account = account.index;
        for relay in address_relays {
            rows.push((
                WatchRow {
                    key_ref: address_ref(account),
                    relay: relay.clone(),
                    class: MailClass::Address,
                    expires_at: None,
                },
                Job::Address(account),
            ));
        }
    }
    for (key, text) in repos.settings_with_prefix(PAY_PREFIX)? {
        let parsed = key
            .strip_prefix(PAY_PREFIX)
            .and_then(|id| SlateId::parse(id).ok())
            .zip(from_text::<PayState>(&text, "epic1 payment").ok());
        let Some((slate_id, state)) = parsed else {
            continue;
        };
        // Read past the finalize until the transaction ends, so an answer offered again after
        // its acknowledgement was lost is taken as handled and leaves the relay.
        let open = repos.transaction(TxId(state.tx_id))?.is_some_and(|tx| {
            matches!(
                tx.state,
                TxState::Sent | TxState::Finalized | TxState::Posted
            )
        });
        if open {
            let mut relays: Vec<&str> = Vec::new();
            for route in &state.routes {
                if route.method != MethodId::Epicbox.as_str() {
                    continue;
                }
                let hosts: Vec<&str> = match route.value.split_once('@') {
                    Some((_, host)) => vec![host],
                    None => state
                        .relays
                        .iter()
                        .chain(address_relays)
                        .map(String::as_str)
                        .collect(),
                };
                for host in hosts {
                    if !relays.contains(&host) {
                        relays.push(host);
                    }
                }
            }
            if state.routes.is_empty() {
                for host in address_relays {
                    if !relays.contains(&host.as_str()) {
                        relays.push(host);
                    }
                }
            }
            for relay in relays {
                rows.push((
                    WatchRow {
                        key_ref: format!("reply:{slate_id}"),
                        relay: relay.to_owned(),
                        class: MailClass::Reply,
                        expires_at: None,
                    },
                    Job::Payment(slate_id, AccountIndex(state.account)),
                ));
            }
        }
    }
    Ok(rows)
}

/// The watch key of the delivery mailbox of the address of `account`.
fn address_ref(account: AccountIndex) -> String {
    format!("address:{}.0", account.0)
}

fn answer_key(slate_id: SlateId) -> String {
    format!("{ANSWER_PREFIX}{slate_id}")
}

fn refusal_key(slate_id: SlateId) -> String {
    format!("{REFUSAL_PREFIX}{slate_id}")
}

/// The route of a payee's answer or refusal to the payer's reply slot `mailbox_key`, hex: the
/// key alone, which the carrier posts to `read_on`, the mailbox the payment was read on
/// ([`read_on_host`]), and to the 2 healthiest other mailboxes of the list: never the whole
/// list ([`crate::delivery::epicbox::post_mailboxes`]). Fails when `read_on` is a mailbox the
/// wallet may not reach or the key does not read.
fn answer_route(
    network: Network,
    relays: &ContactRelays,
    mailbox_key: &str,
    read_on: &str,
    what: &'static str,
) -> Result<RouteEntry, ContactError> {
    endpoint_for(read_on, relays)?;
    let key = hex::unhex(mailbox_key)
        .and_then(|key| PublicKey::from_bytes(&key).ok())
        .ok_or(corrupt(what))?;
    Ok(RouteEntry {
        method: MethodId::Epicbox,
        value: EpicboxAddress::key_text_of(&key, relay_network(network)),
    })
}

/// The mailboxes, as the watch rows name them, that the payment `slate_id` was given for
/// itself; `None` when it goes through the list.
pub(crate) fn given_hosts(
    repos: &dyn Repositories,
    slate_id: SlateId,
) -> Result<Option<Vec<String>>, StoreError> {
    let Some(text) = repos.setting(&pay_key(slate_id))? else {
        return Ok(None);
    };
    Ok(from_text::<PayState>(&text, "epic1 payment")
        .ok()
        .filter(|state| state.given)
        .map(|state| state.relays))
}

/// The mailbox, `domain:port`, the payment `slate_id` was read on, as its stored answer or
/// refusal names it: the hint of the post of either.
pub(crate) fn read_on_host(
    repos: &dyn Repositories,
    slate_id: SlateId,
) -> Result<Option<String>, StoreError> {
    if let Some(text) = repos.setting(&answer_key(slate_id))? {
        let state: AnswerState = from_text(&text, "epic1 answer")?;
        return Ok(Some(state.mailbox));
    }
    if let Some(text) = repos.setting(&refusal_key(slate_id))? {
        let state: RefusalState = from_text(&text, "epic1 refusal")?;
        return Ok(Some(state.mailbox));
    }
    Ok(None)
}

/// The route of `what` for the payment `slate_id`, or none, logged at warn: then it is stored
/// without its post, and goes when the payment is read again.
fn route_or_warn<T>(slate_id: SlateId, what: &str, route: Result<T, ContactError>) -> Option<T> {
    match route {
        Ok(route) => Some(route),
        Err(error) => {
            warn!(slate_id = %slate_id, error = %ErrorChain(&error), "{what} has no route");
            None
        }
    }
}

fn pay_key(slate_id: SlateId) -> String {
    format!("{PAY_PREFIX}{slate_id}")
}

/// Whether a row of `sender` at `stage` of the payment `payment_id`, whose outgoing
/// transaction is `state`, is a payer's S1 of a cancelled payment this wallet still keeps:
/// its `cancelled` notice may still be owed (see [`ContactBook::tend_epic1`]), and the row
/// says where to. The row is left as it is and never posted again.
pub(crate) fn held_for_notice(
    repos: &dyn Repositories,
    (sender, stage): (Option<Sender>, Option<SlateStage>),
    payment_id: uuid::Uuid,
    state: TxState,
) -> Result<bool, StoreError> {
    if state != TxState::Cancelled
        || !matches!(sender, Some(Sender::Payer(_)))
        || stage != Some(SlateStage::Standard1)
    {
        return Ok(false);
    }
    let slate_id = SlateId::from_bytes(*payment_id.as_bytes());
    Ok(repos.setting(&pay_key(slate_id))?.is_some())
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

/// The routes of the payment `payment_id` this wallet made, in link order, when one is
/// stored and its record reads.
pub(crate) fn pay_routes(
    repos: &dyn Repositories,
    payment_id: Uuid,
) -> Result<Option<Vec<RouteEntry>>, StoreError> {
    let key = pay_key(SlateId::from_bytes(*payment_id.as_bytes()));
    let Some(text) = repos.setting(&key)? else {
        return Ok(None);
    };
    let routes = from_text::<PayState>(&text, "epic1 payment")
        .ok()
        .and_then(|state| state.route_entries().ok());
    Ok(routes)
}

/// The height a payment is posted before: the TTL of its slate or the wallet's own limit for
/// the transaction, whichever comes first.
fn pay_cutoff(
    repos: &dyn Repositories,
    ttl: Option<Height>,
    tx_id: TxId,
) -> Result<Option<Height>, StoreError> {
    let local = repos.tx_marks(tx_id)?.local_cutoff;
    Ok(match (ttl, local) {
        (Some(ttl), Some(local)) => Some(ttl.min(local)),
        (ttl, local) => ttl.or(local),
    })
}

/// The link in `text` for `network` and the routes a payment to it is posted through
/// ([`payer_routes`]). Refused when no route is left.
fn read_link(
    text: &str,
    network: Network,
    relays: &ContactRelays,
) -> Result<(Epic1Link, Vec<RouteEntry>), ContactError> {
    let link = Epic1Link::parse(text.trim()).map_err(ContactError::Epic1Link)?;
    if link.address.network() != relay_network(network) {
        return Err(refused(Epic1Refusal::WrongNetwork));
    }
    let routes = payer_routes(&link, network, relays);
    if routes.is_empty() {
        let direct_only = relays.tor_expected
            && link
                .routes
                .iter()
                .any(|route| route.method == MethodId::Http);
        return Err(refused(if direct_only {
            Epic1Refusal::TorExpected
        } else {
            Epic1Refusal::CannotPay
        }));
    }
    Ok((link, routes))
}

/// The routes a payment to `link` is posted through, in the order they are tried. A link with
/// entries is paid through its usable entries only, in link order, and never through the
/// delivery mailbox; an entry whose host is on this device is left out, and an `http` entry
/// while Tor is expected. A bare address or a
/// link without entries is paid through one route, the address's delivery mailbox by its key
/// alone, which the carrier posts to each usable relay of [`ContactRelays::list`]; none when
/// no relay of the list is usable. Posts nothing; empty when no route is left.
pub(crate) fn payer_routes(
    link: &Epic1Link,
    network: Network,
    relays: &ContactRelays,
) -> Vec<RouteEntry> {
    if link.routes.is_empty() {
        if usable_relays(relays).is_empty() {
            return Vec::new();
        }
        return vec![RouteEntry {
            method: MethodId::Epicbox,
            value: EpicboxAddress::key_text_of(link.address.delivery_key(), relay_network(network)),
        }];
    }
    link.routes
        .iter()
        .filter(|route| match check_payer_entry(route, relays) {
            Ok(()) => true,
            Err(error) => {
                debug!(method = %route.method, error = %ErrorChain(&error), "epic1 route left out");
                false
            }
        })
        .cloned()
        .collect()
}

/// An envelope that came to a delivery mailbox, opened with the epic1 seal key `key`: what it
/// holds, a slate or a notice. Its hint must be zero and it must be unsigned.
fn open_at_address(
    network: Network,
    envelope: &[u8],
    key: &lepic_seal::EncSecretKey,
) -> Result<TxOpened, ContactError> {
    let net = contact_network(network);
    let sealed = SealedEnvelope::decode(envelope, net).map_err(ContactError::Decode)?;
    if sealed.hint() != Hint::from_bytes([0; 8]) {
        return Err(refused(Epic1Refusal::HintNotZero));
    }
    let opened = sealed
        .open_epic1(key)
        .map_err(|_| ContactError::CannotOpen)?;
    if opened.sender.is_some() {
        return Err(refused(Epic1Refusal::Signed));
    }
    Ok(opened)
}

/// The S1 in an envelope that came to a delivery mailbox, opened as [`open_at_address`] opens
/// it: the slate's V3 JSON, the reply key and the key of the reply mailbox, the first `epicbox`
/// entry of the reply route.
fn open_payment(
    network: Network,
    envelope: &[u8],
    key: &lepic_seal::EncSecretKey,
) -> Result<OpenedPayment, ContactError> {
    let opened = open_at_address(network, envelope, key)?;
    if opened.kind != TxKind::Slate {
        return Err(ContactError::NotASlate);
    }
    let content = opened.content;
    let reply_key = content.reply_key.ok_or(refused(Epic1Refusal::NoReplyKey))?;
    let reply_mailbox = content
        .reply_route
        .and_then(|route| route.epicbox_key())
        .ok_or(refused(Epic1Refusal::NoReplyRoute))?;
    let slate = decode_native(network, &content.body).ok_or(ContactError::NotASlate)?;
    if slate.stage() != Stage::S1 {
        return Err(refused(Epic1Refusal::WrongStage));
    }
    let slate_id = slate.id();
    let v3 = v3_of_native(network, slate, None).ok_or(ContactError::NotASlate)?;
    Ok(OpenedPayment {
        slate_id,
        v3,
        reply_key,
        reply_mailbox,
        receipt_ask: content.receipt_ask,
    })
}

/// What an envelope at a delivery mailbox holds.
struct OpenedPayment {
    slate_id: SlateId,
    v3: Vec<u8>,
    reply_key: EncPublicKey,
    /// The key of the reply mailbox; the answer goes to it on the relay the S1 was read from.
    reply_mailbox: [u8; 33],
    /// The payer key the payment asks a receipt for (tag 84), when it asks one.
    receipt_ask: Option<[u8; 33]>,
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The epic1 address of `account`, index 0: its seal key and its delivery key on the
    /// wallet's network.
    ///
    /// Fails with [`ContactError::Wallet`] when the wallet is locked.
    pub fn epic1_address(&self, account: AccountIndex) -> Result<Epic1Address, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let seal = self.wallet.epic1_seal_key(account, net)?.public_key();
        let delivery = PublicKey::from_secret_key(&self.wallet.epic1_delivery_key(account, net)?)
            .map_err(|_| ContactError::RelayAddress)?;
        Ok(Epic1Address::new(relay_network(network), seal, delivery))
    }

    /// A link on the address of the request's account, with the amount, message and route
    /// entries of the request. Nothing is stored: the same request gives the same text, and a
    /// payment to the link is taken as any payment to the address, whatever it pays.
    ///
    /// Fails with [`ContactError::Epic1`] when an entry is not an `http` host or onion this
    /// wallet may name, there are more than three, or the message does not fit, and
    /// [`ContactError::Wallet`] when the wallet is locked.
    pub fn epic1_link(
        &self,
        relays: &ContactRelays,
        request: Epic1LinkRequest,
    ) -> Result<Epic1LinkIssued, ContactError> {
        self.check_contact_network(relays)?;
        if request.entries.len() > lepic_epic1::MAX_TRANSPORTS {
            return Err(refused(Epic1Refusal::TooManyRelays));
        }
        for entry in &request.entries {
            check_link_entry(entry, relays)?;
        }
        if let Some(message) = &request.message
            && (message.len() > lepic_epic1::MAX_VALUE_LEN || message.chars().any(char::is_control))
        {
            return Err(refused(Epic1Refusal::Message));
        }
        let mut link = Epic1Link::new(self.epic1_address(request.account)?);
        link.routes = request.entries;
        link.amount = request.amount;
        link.message = request.message;
        Ok(Epic1LinkIssued {
            link: link.to_uri(),
            address: link.address.encode(),
        })
    }

    /// The receipt the payee's answer carried for the epic1 payment `tx_id`; `None` when the
    /// payment has none: not an epic1 payment, not answered yet, or answered without one. Fails
    /// with [`WalletError::UnknownTransaction`] for a transaction the wallet does not have.
    ///
    /// [`WalletError::UnknownTransaction`]: lepic_wallet::WalletError::UnknownTransaction
    pub async fn epic1_receipt(
        &self,
        tx_id: TxId,
    ) -> Result<Option<epic1_receipt::Epic1Receipt>, ContactError> {
        let session = self.wallet.session()?;
        let stored = self
            .contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    let Some(entry) = repos.transaction(tx_id)? else {
                        return Ok(None);
                    };
                    // A payment to this wallet's own address keeps the proof under the same
                    // slate id: only the sending side has it.
                    let text = match entry.slate_id {
                        Some(slate_id) if entry.direction == TxDirection::Outgoing => repos
                            .setting(&receipt_key(SlateId::from_bytes(*slate_id.as_bytes())))?,
                        _ => None,
                    };
                    Ok::<_, StoreError>(Some(text))
                })?)
            })
            .await?;
        let text = stored.ok_or(lepic_wallet::WalletError::UnknownTransaction(tx_id))?;
        Ok(text.and_then(|text| epic1_receipt::Epic1Receipt::parse(&text)))
    }

    /// The S2s this wallet made for payments taken at its delivery mailboxes.
    pub async fn epic1_answers(&self) -> Result<Vec<Epic1AnswerView>, ContactError> {
        let session = self.wallet.session()?;
        let stored = self
            .contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    let mut stored = Vec::new();
                    for (key, text) in repos.settings_with_prefix(ANSWER_PREFIX)? {
                        let Some(slate_id) = key
                            .strip_prefix(ANSWER_PREFIX)
                            .and_then(|id| SlateId::parse(id).ok())
                        else {
                            continue;
                        };
                        let Ok(state) = from_text::<AnswerState>(&text, "epic1 answer") else {
                            continue;
                        };
                        let posted = answer_row(repos, slate_id, state.account)?
                            .is_some_and(|row| row.entry.state == OutboxState::Posted);
                        stored.push((slate_id, state, posted));
                    }
                    Ok::<_, StoreError>(stored)
                })?)
            })
            .await?;
        Ok(stored
            .into_iter()
            .map(|(slate_id, state, posted)| Epic1AnswerView {
                tx_id: TxId(state.tx_id),
                slate_id,
                mailbox: state.mailbox,
                posted,
            })
            .collect())
    }

    /// [`Self::store_refusal`], with a failure to store logged and let pass unless the store
    /// [`passes`] it on.
    async fn refuse(
        &self,
        relays: &ContactRelays,
        account: AccountIndex,
        slate_id: SlateId,
        reply_key: &EncPublicKey,
        reply_to: (&[u8; 33], &str),
    ) -> Result<(), ContactError> {
        let stored = self
            .store_refusal(relays, account, slate_id, reply_key, reply_to)
            .await;
        match stored {
            Err(error) if passes(&error) => Err(error),
            Err(error) => {
                warn!(
                    slate_id = %slate_id,
                    error = %ErrorChain(&error),
                    "epic1 refusal not stored"
                );
                Ok(())
            }
            Ok(()) => Ok(()),
        }
    }

    /// Seals the refusal of the payment `slate_id`, a `declined` with the reason `declined`, to
    /// its reply key and
    /// stores it to post to the reply mailbox `reply_mailbox` on `relay`, the relay the payment
    /// was read from. One already stored for the slate is kept, as is the store when
    /// [`MAX_REFUSALS`] are kept: a copy of the payment read on another relay is refused once.
    async fn store_refusal(
        &self,
        relays: &ContactRelays,
        account: AccountIndex,
        slate_id: SlateId,
        reply_key: &EncPublicKey,
        (reply_mailbox, relay): (&[u8; 33], &str),
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let notice = Notice::Declined {
            slate_id,
            reason: Some(Reason::Declined),
        };
        let state = RefusalState {
            account: account.0,
            mailbox_key: hex::encode(reply_mailbox),
            mailbox: relay.to_owned(),
            at: self.wallet.ports().clock.now().as_second(),
        };
        let text = to_text(&state, "epic1 refusal")?;
        let route = answer_route(
            network,
            relays,
            &state.mailbox_key,
            &state.mailbox,
            "epic1 refusal",
        );
        let route = route_or_warn(slate_id, "epic1 refusal", route);
        let reply_key = *reply_key;
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                // The store before the RNG, the order every other path takes them in.
                let mut rng = LockedRng(&mut **ports.rng.lock());
                let key = refusal_key(slate_id);
                if repos.setting(&key)?.is_some()
                    || repos.settings_with_prefix(REFUSAL_PREFIX)?.len() >= MAX_REFUSALS
                {
                    return Ok::<_, ContactError>(());
                }
                repos.put_setting(&key, &text)?;
                if let Some(route) = route {
                    let to = NoticeTo::ReplyKey {
                        account,
                        reply_key: &reply_key,
                        route,
                    };
                    send_notice(repos, (network, &mut rng), &notice, to, now)?;
                }
                Ok(())
            })
        })
        .await?;
        info!(slate_id = %slate_id, reason = "declined", "epic1 refusal stored");
        Ok(())
    }

    /// The receipt the payee signs into the S2 `slate` of a payment to the address of `account`
    /// that asked one for the payer key `ask` (`docs/protocols/epic1-receipt.md`). `None` when the
    /// payment asks none, its ask is not a key, or the keys to sign cannot be had (a locked
    /// wallet): the answer then goes with no receipt, as the payment is taken either way.
    pub(crate) fn receipt_for(
        &self,
        account: AccountIndex,
        slate: &lepic_slate::model::Slate,
        ask: Option<[u8; 33]>,
    ) -> Option<[u8; 64]> {
        let ask = ask?;
        let net = contact_network(self.wallet.config().network);
        let signed = self
            .wallet
            .epic1_delivery_key(account, net)
            .map_err(ContactError::from)
            .and_then(|delivery| Ok((delivery, self.epic1_address(account)?)))
            .map(|(delivery, address)| {
                epic1_receipt::sign_receipt(&address, &delivery, slate, &ask)
            });
        match signed {
            Ok(Some(receipt)) => Some(receipt),
            Ok(None) => {
                debug!(slate_id = %slate.id(), "epic1 receipt ask not answered");
                None
            }
            Err(error) => {
                warn!(slate_id = %slate.id(), error = %ErrorChain(&error), "epic1 answer sent with no receipt");
                None
            }
        }
    }

    /// Opens a payment that came to the delivery mailbox of the address of `account`, with
    /// that address's seal key only.
    fn open_address_payment(
        &self,
        account: AccountIndex,
        envelope: &[u8],
    ) -> Result<OpenedPayment, ContactError> {
        let network = self.wallet.config().network;
        let key = self
            .wallet
            .epic1_seal_key(account, contact_network(network))?;
        open_payment(network, envelope, &key)
    }

    /// What the wallet knows for a payment of `slate_id` to the address of `account`: whether
    /// it was taken before, and the account's label.
    async fn payment_context(
        &self,
        account: AccountIndex,
        slate_id: SlateId,
    ) -> Result<PaymentContext, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.read(|repos| {
                let taken = repos.setting(&answer_key(slate_id))?.is_some();
                let label = repos
                    .accounts()?
                    .into_iter()
                    .find(|record| record.index == account)
                    .map(|record| record.label);
                Ok::<_, ContactError>(PaymentContext { taken, label })
            })
        })
        .await
    }

    /// Queues the stored answer to the payment `slate_id` once more when its last post was
    /// made or ended: the same bytes under the same payment, to the relay the payment was
    /// first read from. An answer still waiting is left as it is.
    async fn answer_again(&self, slate_id: SlateId) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                let Some(text) = repos.setting(&answer_key(slate_id))? else {
                    return Ok::<_, ContactError>(());
                };
                let state: AnswerState = from_text(&text, "epic1 answer")?;
                if let Some(row) = answer_row(repos, slate_id, state.account)?
                    && matches!(row.entry.state, OutboxState::Posted | OutboxState::Failed)
                {
                    outbox::requeue(repos, &row, now)?;
                }
                Ok(())
            })
        })
        .await
    }

    /// Takes a payment read on `relay` from the delivery mailbox of the address of `account`:
    /// an S1 sealed to the address's seal key, received into its account, its S2
    /// sealed to the slate's reply key and stored to post once, to the reply mailbox on
    /// `relay` and on the 2 healthiest other relays of the list. Returns whether it was new.
    /// A payment taken before, as a copy read on another relay is, is not taken again: its
    /// stored answer is queued once more, the same bytes to the first relay, and nothing goes
    /// to the second. A payment received before with no answer stored gets its stored S2
    /// sealed and stored as the answer.
    ///
    /// A payment is taken whatever amount it pays. While the wallet refuses unsolicited
    /// payments it is declined with the reason `declined` and fails with
    /// [`ReceiveError::Refused`]; one that asks for a payment proof, which an epic1 address has
    /// no key to sign, is declined with the reason `declined` and fails with
    /// [`ReceiveError::ForeignProofAddress`]. The notice is sealed to the reply key and stored to
    /// post to the reply mailbox, and nothing is received. A new payment is taken only within
    /// the open receipt cap ([`lepic_wallet::Wallet::receive_at_link`]).
    async fn take_payment(
        &self,
        relays: &ContactRelays,
        account: AccountIndex,
        relay: &str,
        envelope: &[u8],
    ) -> Result<bool, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let payment = self.open_address_payment(account, envelope)?;
        let slate_id = payment.slate_id;
        let context = self.payment_context(account, slate_id).await?;
        if context.taken {
            self.answer_again(slate_id).await?;
            debug!(slate_id = %slate_id, "epic1 payment taken before");
            return Ok(false);
        }
        let received = self
            .receive_unless_declined(relays, account, relay, &payment, context)
            .await?;
        // Received before with no answer stored, as a stop between the two left it: the stored
        // S2 is the answer, sealed and stored now.
        let repeated = received.repeated;
        let receipt = self.receipt_for(account, &received.slate, payment.receipt_ask);
        let body = NativeSlate::new(received.slate, Tail::empty())
            .map_err(ContactError::Native)?
            .encode(network);
        let mut content = TxContent::new(body);
        content.receipt = receipt;
        let envelope = {
            let mut rng = LockedRng(&mut **self.wallet.ports().rng.lock());
            seal_tx(
                net,
                &payment.reply_key,
                TxKey::Seal(HintRule::ReplyKey),
                &content,
                None,
                &mut rng,
            )
            .map_err(ContactError::Encode)?
        };
        let state = AnswerState {
            tx_id: received.tx_id.0,
            account: account.0,
            envelope: hex::encode(&envelope),
            mailbox_key: hex::encode(&payment.reply_mailbox),
            mailbox: relay.to_owned(),
        };
        let owed = state.owed(network, relays, slate_id);
        let owed = route_or_warn(slate_id, "epic1 answer", owed);
        let session = self.wallet.session()?;
        let tx_id = received.tx_id;
        let new = self
            .contact_work(move |ports, _| {
                let at = ports.clock.now();
                let text = to_text(&state, "epic1 answer")?;
                session.store.write(|repos| {
                    let key = answer_key(slate_id);
                    // One answer per payment, whichever read stores it first.
                    if repos.setting(&key)?.is_some() {
                        return Ok::<_, ContactError>(false);
                    }
                    repos.put_setting(&key, &text)?;
                    if let Some(owed) = &owed {
                        outbox::enqueue(repos, owed, at)?;
                    }
                    Ok(true)
                })
            })
            .await?;
        if !new {
            // Another read stored the answer first.
            self.answer_again(slate_id).await?;
        } else if repeated {
            info!(tx_id = %tx_id, "epic1 answer stored for a payment received before");
        } else {
            info!(tx_id = %tx_id, "epic1 payment taken");
        }
        Ok(new && !repeated)
    }

    /// Receives `payment` at the address of `account`, unless it is declined: any payment while
    /// the wallet refuses unsolicited payments, one that asks for a payment proof, which an
    /// epic1 address has no key to sign, or one that comes while the open receipts are at a
    /// cap of [`lepic_wallet::config::WalletPolicy`]. A declined payment's notice is sealed to
    /// its reply key and stored to post to its reply mailbox on `relay`, nothing is received,
    /// and it fails as `take_payment` says.
    async fn receive_unless_declined(
        &self,
        relays: &ContactRelays,
        account: AccountIndex,
        relay: &str,
        payment: &OpenedPayment,
        context: PaymentContext,
    ) -> Result<Received, ContactError> {
        let reply_to = (&payment.reply_mailbox, relay);
        if self.wallet.config().policy.refuse_unsolicited_payments {
            self.refuse(
                relays,
                account,
                payment.slate_id,
                &payment.reply_key,
                reply_to,
            )
            .await?;
            return Err(ContactError::Receive(ReceiveError::Refused));
        }
        let received = self
            .wallet
            .receive_at_link(
                &file_method(),
                &WireSlate::binary(MediaType::JSON, payment.v3.clone()),
                ReceiveRequest {
                    account: context.label,
                    message: None,
                    proof_key: ProofKey::Epic1 { index: 0 },
                },
            )
            .await;
        match received {
            Ok(received) => Ok(received),
            Err(error @ (ReceiveError::ForeignProofAddress | ReceiveError::OpenReceipts(_))) => {
                self.refuse(
                    relays,
                    account,
                    payment.slate_id,
                    &payment.reply_key,
                    reply_to,
                )
                .await?;
                Err(ContactError::Receive(error))
            }
            Err(error) => Err(ContactError::Receive(error)),
        }
    }

    /// Takes a notice read from the delivery mailbox of the address of `account` (RFC 0003
    /// 5.9): sealed to the address's seal key, about a payment the address took, handed to
    /// [`lepic_wallet::Wallet::take_notice`] from the address key. A notice about a payment
    /// this address did not take changes nothing, and nothing is kept for it. Returns whether
    /// it raised an event.
    ///
    /// Fails with [`Epic1Refusal::WrongStage`] for a slate, a notice not readable or of a kind
    /// an address key may not send, sealed as a notice.
    async fn take_address_notice(
        &self,
        account: AccountIndex,
        envelope: &[u8],
    ) -> Result<bool, ContactError> {
        let network = self.wallet.config().network;
        let key = self
            .wallet
            .epic1_seal_key(account, contact_network(network))?;
        let opened = open_at_address(network, envelope, &key)?;
        if opened.kind != TxKind::Notice {
            return Err(refused(Epic1Refusal::WrongStage));
        }
        let Ok(Payload::Notice(notice)) =
            std::str::from_utf8(&opened.content.body).map(classify_text)
        else {
            return Err(refused(Epic1Refusal::WrongStage));
        };
        let Some(slate_id) = notice.slate_id() else {
            return Err(refused(Epic1Refusal::WrongStage));
        };
        let payment_id = Uuid::from_bytes(*slate_id.as_bytes());
        let session = self.wallet.session()?;
        let tx_id = self
            .contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    let Some(tx) = repos.transaction_by_slate(payment_id, TxDirection::Incoming)?
                    else {
                        return Ok::<_, StoreError>(None);
                    };
                    let taken = tx.entry.account == account
                        && epic1_index::index_of(repos, tx.id)? == Some(0);
                    Ok(taken.then_some(tx.id))
                })?)
            })
            .await?;
        let Some(tx_id) = tx_id else {
            debug!(
                slate_id = %slate_id,
                "epic1 notice about no payment the address took"
            );
            return Ok(false);
        };
        match self
            .wallet
            .take_notice(notice, NoticeFrom::AddressKey(tx_id))
            .await?
        {
            Taken::Refused => Err(refused(Epic1Refusal::WrongStage)),
            taken => Ok(taken == Taken::Raised),
        }
    }

    /// Reads an epic1 link: the address it pays, what it asks, and the host of the `http` or
    /// `tor` entry a payment would be posted to first, if it goes by one. Nothing is stored.
    ///
    /// Fails with [`ContactError::Epic1Link`] for text that is not an epic1 link, and
    /// [`ContactError::Epic1`] for one of another network or with no usable transport.
    pub fn epic1_read(
        &self,
        relays: &ContactRelays,
        text: &str,
    ) -> Result<Epic1Read, ContactError> {
        let network = self.wallet.config().network;
        let (link, routes) = read_link(text, network, relays)?;
        let http_host = routes
            .first()
            .and_then(RouteEntry::host_port)
            .map(|(host, _)| host);
        let ignored_mailboxes = link
            .ignored
            .iter()
            .filter(|skipped| matches!(skipped, Skipped::Mailbox))
            .count();
        Ok(Epic1Read {
            address: link.address.encode(),
            amount: link.amount,
            message: link.message,
            label: link.label,
            http_host,
            ignored_mailboxes,
        })
    }

    /// Pays an epic1 link: sends the request's S1 with a TTL ([`EPIC1_TTL_BLOCKS`] by default),
    /// asking for no payment proof, and seals it to the address in an anonymous, padded
    /// envelope with a zero hint. The envelope names the slate's reply key and the key of a reply
    /// mailbox, which the payee answers on the relay it read the payment from. The payment is
    /// stored with its post to the link's first route, then posted, and posted to the next
    /// route while a post reaches nothing. A link without `http` or `tor` entries has one route,
    /// the address's delivery mailbox, posted to every usable relay of the list at once. A post
    /// sent and not answered is posted again on the same route later; only
    /// [`ContactBook::epic1_post_next`] moves on from it. Collecting watches the reply mailbox
    /// on each relay of the list until the TTL and finalizes the S2 that answers; an `http` or
    /// `tor` route answers with the S2 at once. A second payment to the same address is taken
    /// while the first waits: each is its own transaction. The send's amount and message are
    /// paid whatever the link asks.
    ///
    /// A payment to the delivery mailbox goes through `request.mailboxes` when the request
    /// gives some, and through the list otherwise.
    ///
    /// Fails as [`ContactBook::epic1_read`] does; with [`ContactError::NoSharedMailbox`] before
    /// anything is sent or stored when the payment goes to the delivery mailbox, the request
    /// gives no mailbox and the list holds no shipped one; with [`ContactError::Mailboxes`] when
    /// a given mailbox is not a public name or none is left; [`ContactError::Send`] as sending
    /// fails, and
    /// [`ContactError::Encode`] with
    /// [`lepic_seal::EncodeError::BodyTooLarge`] for a slate too large to seal. The payment is
    /// stored with its send in one write: a send that could not be sealed or stored leaves
    /// nothing, and one whose slate file could not be written is cancelled.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    #[allow(clippy::too_many_lines)] // One payment from link to sealed post, in order.
    pub async fn epic1_pay(
        &self,
        relays: &ContactRelays,
        request: Epic1PayRequest,
    ) -> Result<Epic1Paid, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let network = self.wallet.config().network;
        let (link, routes) = read_link(&request.link, network, relays)?;
        let to_mailbox = routes.iter().any(|route| route.method == MethodId::Epicbox);
        let given = !request.mailboxes.is_empty();
        let paying = if given {
            for endpoint in &request.mailboxes {
                check_public(endpoint).map_err(ContactError::Mailboxes)?;
            }
            let list = MailboxList::new(Vec::new(), request.mailboxes, Vec::new())
                .map_err(ContactError::Mailboxes)?;
            relays.clone().with_mailboxes(list)
        } else {
            if to_mailbox && !relays.mailboxes.holds_shipped() {
                return Err(ContactError::NoSharedMailbox {
                    shipped: relays
                        .mailboxes
                        .shipped()
                        .iter()
                        .map(mailbox_host)
                        .collect(),
                });
            }
            relays.clone()
        };
        let relays = &paying;
        let mut send = request.send;
        let account = send.account;
        send.ttl_blocks = Some(send.ttl_blocks.unwrap_or(EPIC1_TTL_BLOCKS));
        send.payment_proof_recipient = None;
        let delivery = Delivery::Export {
            to: Location::File(request.slate_file),
        };
        let paid_relays = if to_mailbox {
            address_relays(relays)
        } else {
            Vec::new()
        };
        let mailboxes: Vec<EpicboxAddress> = usable_relays(relays)
            .into_iter()
            .filter(|_| to_mailbox)
            .map(|endpoint| {
                EpicboxAddress::new(
                    *link.address.delivery_key(),
                    relays.epicbox.network(),
                    endpoint.domain().clone(),
                    Some(endpoint.port()),
                )
            })
            .collect();
        let seal_key = *link.address.seal_key();
        let measure: MeasurePost =
            Arc::new(move |v3, rng| sealed_s1_size(network, &seal_key, &mailboxes, v3, rng));
        let slate_id = match send.slate_id {
            Some(slate_id) => slate_id,
            None => {
                SlateId::from_random_bytes(crate::new_id(&mut **self.wallet.ports().rng.lock()))
            }
        };
        send.slate_id = Some(slate_id);
        let (carried, stored) = self
            .carried_payment(
                &link.address,
                (slate_id, account),
                &routes,
                (paid_relays, given && to_mailbox, request.require_receipt),
            )
            .await?;
        let sent = match self
            .wallet
            .send_carried(&file_method(), send, delivery, Some(measure), Some(carried))
            .await
        {
            Ok(sent) => sent,
            Err(error @ SendError::Undelivered { tx_id, .. }) => {
                return Err(self.give_up_send(tx_id, ContactError::Send(error)).await);
            }
            Err(SendError::Carried(error)) => {
                return Err(match error.downcast::<ContactError>() {
                    Ok(error) => *error,
                    Err(error) => ContactError::Send(SendError::Carried(error)),
                });
            }
            Err(error) => return Err(ContactError::Send(error)),
        };
        let id = stored
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or(ContactError::UnknownTransaction)?;
        let tried = {
            let _turn = self.wallet.contact_turn().await;
            let carrier = link_carrier(relays);
            // Stored in this call, from the tip the send stage just checked.
            match self.outbox_deliver(&carrier, id, true).await {
                Ok((tried, _)) => tried,
                Err(error) => {
                    // Stored as owed: the next collecting pass posts it.
                    warn!(error = %ErrorChain(&error), "epic1 payment stored and not posted");
                    Vec::new()
                }
            }
        };
        let (posted, uncertain) = self.posts_of(sent.slate_id, account, &routes).await?;
        info!(slate_id = %sent.slate_id, posted = ?posted, "epic1 payment stored");
        Ok(Epic1Paid {
            tx_id: sent.tx_id,
            slate_id: sent.slate_id,
            address: link.address.encode(),
            attempts: attempts_of(&tried),
            posted,
            uncertain,
        })
    }

    /// What [`ContactBook::epic1_pay`] stores with its send, in the send's own write: the S1
    /// sealed to `address`, the payment and its post to the first of `routes`. The post's
    /// outbox row is left in the slot returned with it once the send is stored.
    async fn carried_payment(
        &self,
        address: &Epic1Address,
        (slate_id, account): (SlateId, AccountIndex),
        routes: &[RouteEntry],
        (relays, given, require_receipt): (Vec<String>, bool, bool),
    ) -> Result<(StoreCarried, PaymentRow), ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let first = routes
            .first()
            .cloned()
            .ok_or(refused(Epic1Refusal::CannotPay))?;
        let mailbox_secret = self
            .wallet
            .reply_mailbox_key(account, net, slate_id.as_bytes())?;
        let mailbox_key = PublicKey::from_secret_key(&mailbox_secret)
            .map_err(|_| ContactError::RelayAddress)?
            .to_bytes();
        let payer_secret = self
            .wallet
            .receipt_payer_key(account, net, slate_id.as_bytes())?;
        let receipt_ask = PublicKey::from_secret_key(&payer_secret)
            .map_err(|_| ContactError::RelayAddress)?
            .to_bytes();
        let session = self.wallet.session()?;
        let reply = self
            .contact_work(move |_, _| {
                Ok(reply_secret(&session.keychain, network, account, slate_id)?.public_key())
            })
            .await?;
        let payment = CarriedPayment {
            network,
            seal_key: *address.seal_key(),
            reply,
            mailbox_key,
            receipt_ask,
            first,
            state: PayState {
                tx_id: 0,
                account: account.0,
                envelope: String::new(),
                address: address.encode(),
                routes: routes
                    .iter()
                    .map(|route| StoredRoute {
                        method: route.method.as_str().to_owned(),
                        value: route.value.clone(),
                    })
                    .collect(),
                relays,
                given,
                require_receipt,
                finalized: false,
            },
        };
        let row = PaymentRow::default();
        let slot = Arc::clone(&row);
        let carried: StoreCarried = Arc::new(move |repos, send, rng| {
            let id = payment
                .store(repos, send, rng)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(id);
            Ok(())
        });
        Ok((carried, row))
    }

    /// The route, from 0, of `routes` the payment `slate_id` was posted to, and the first
    /// whose post is uncertain, as its outbox rows say.
    async fn posts_of(
        &self,
        slate_id: SlateId,
        account: AccountIndex,
        routes: &[RouteEntry],
    ) -> Result<(Option<usize>, Option<usize>), ContactError> {
        let session = self.wallet.session()?;
        let payment_id = Uuid::from_bytes(*slate_id.as_bytes());
        let rows = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.native_outbox_of(payment_id))?)
            })
            .await?;
        let from_ref = Sender::Payer(account).from_ref();
        let index = |row: &StoredNativeOutbox| {
            routes.iter().position(|route| {
                route.method.as_str() == row.entry.route_method
                    && route.value == row.entry.route_value
            })
        };
        let mine = || {
            rows.iter()
                .filter(|row| row.entry.from_ref == from_ref && row.entry.stage.is_some())
        };
        let posted = mine()
            .filter(|row| row.entry.state == OutboxState::Posted)
            .max_by_key(|row| row.id)
            .and_then(index);
        let uncertain = mine()
            .filter(|row| row.entry.state == OutboxState::Uncertain)
            .filter_map(index)
            .min();
        Ok((posted, uncertain))
    }

    /// Posts the stored payment `slate_id` again, the same bytes, to the route of its link that
    /// follows the routes it was posted to.
    ///
    /// Fails with [`ContactError::Epic1`] when no payment is stored or it does not wait for a
    /// post
    /// ([`Epic1Refusal::NoPayment`]), it was finalized, or every route was tried or the chain
    /// reached the payment's cutoff ([`Epic1Refusal::NoMoreEntries`]).
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_post_next(
        &self,
        relays: &ContactRelays,
        slate_id: SlateId,
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
        let routes = state.route_entries()?;
        let account = AccountIndex(state.account);
        let payment_id = Uuid::from_bytes(*slate_id.as_bytes());
        self.outbox_fill(relays).await?;
        let next = {
            let _turn = self.wallet.contact_turn().await;
            let carrier = link_carrier(relays);
            self.outbox_next_route(&carrier, payment_id).await
        };
        let tried = match next {
            Ok(tried) => tried,
            Err(NextRouteError::Contact(error)) => return Err(error),
            Err(NextRouteError::PastCutoff | NextRouteError::NoMoreRoutes) => {
                return Err(refused(Epic1Refusal::NoMoreEntries));
            }
            Err(NextRouteError::NotOpen) => {
                let session = self.wallet.session()?;
                let tx_id = TxId(state.tx_id);
                let finalized = self
                    .contact_work(move |_, _| {
                        Ok(session.store.read(|repos| repos.transaction(tx_id))?)
                    })
                    .await?
                    .is_some_and(|tx| {
                        matches!(
                            tx.state,
                            TxState::Finalized | TxState::Posted | TxState::Confirmed
                        )
                    });
                return Err(refused(if finalized {
                    Epic1Refusal::Finalized
                } else {
                    Epic1Refusal::NoPayment
                }));
            }
        };
        let (posted, uncertain) = self.posts_of(slate_id, account, &routes).await?;
        Ok(Epic1Paid {
            tx_id: TxId(state.tx_id),
            slate_id,
            address: state.address,
            attempts: attempts_of(&tried),
            posted,
            uncertain,
        })
    }

    /// The payment this wallet made to an epic1 link under `slate_id`, when it holds one: its
    /// transaction, address, the route it was posted to and the first uncertain one. It lists
    /// no attempts, as nothing is posted.
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
        let Some(state) = state else {
            return Ok(None);
        };
        let routes = state.route_entries()?;
        let (posted, uncertain) = self
            .posts_of(slate_id, AccountIndex(state.account), &routes)
            .await?;
        Ok(Some(Epic1Paid {
            tx_id: TxId(state.tx_id),
            slate_id,
            address: state.address,
            attempts: Vec::new(),
            posted,
            uncertain,
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
    /// and opened with its secret, handed to [`lepic_wallet::Wallet::take_notice`] from the
    /// reply key. A payment that waits unanswered never happened: the wallet erases it, unlocks
    /// its inputs and keeps only when it was declined ([`lepic_wallet::Wallet::send_declined_at`]),
    /// and this record goes at the next tending. A refusal for a payment that is finalized, was
    /// answered or ended changes nothing. Returns whether it raised an event.
    pub(crate) async fn take_epic1_refusal(
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
        let notice = match classify_text(text) {
            Payload::Notice(notice) if notice.slate_id() == Some(slate_id) => notice,
            Payload::Notice(notice) if notice.slate_id().is_some() => {
                return Err(refused(Epic1Refusal::OtherSlate));
            }
            _ => return Err(refused(Epic1Refusal::WrongStage)),
        };
        match self
            .wallet
            .take_notice(notice, NoticeFrom::ReplyKey(slate_id))
            .await?
        {
            Taken::Refused => Err(refused(Epic1Refusal::WrongStage)),
            Taken::Raised => {
                info!(slate_id = %slate_id, "epic1 payment refused by its payee");
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Finalizes an S2 that came to the reply mailbox of the payment `slate_id` and posts it.
    /// An envelope at the reply mailbox of a slate that is not an epic1 payment is taken as
    /// the answer to an in-person code. Returns
    /// whether something new was taken.
    pub(crate) async fn take_epic1_answer(
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
        // A payment its payee declined was erased: a late answer finds nothing to finish.
        if !self.payment_held(TxId(state.tx_id)).await? {
            debug!(slate_id = %slate_id, "answer to an erased epic1 payment dropped");
            return Ok(false);
        }
        let opened = sealed
            .open_tx(&secret, KeyClass::Seal)
            .map_err(|_| ContactError::CannotOpen)?;
        if opened.sender.is_some() {
            return Err(refused(Epic1Refusal::Signed));
        }
        let carried_receipt = opened.content.receipt;
        let body = opened.content.body;
        let slate = decode_native(network, &body).ok_or(ContactError::NotASlate)?;
        if slate.stage() != Stage::S2 {
            return Err(refused(Epic1Refusal::WrongStage));
        }
        if slate.id() != slate_id {
            return Err(refused(Epic1Refusal::OtherSlate));
        }
        // A payment finalized before its record said so, by a pass that stopped between the
        // two writes, is only marked: finalizing it again would post it twice.
        if self.mark_if_finalized(slate_id, TxId(state.tx_id)).await? {
            return Ok(false);
        }
        self.finish_epic1_answer(
            &state,
            &slate,
            &body,
            carried_receipt.as_ref(),
            Propagation::Stem,
        )
        .await?;
        Ok(true)
    }

    /// Finalizes the native S2 `body` from sealed text when it answers an epic1 payment this
    /// wallet made and still holds unfinalized, with its proof checked and kept as
    /// [`Self::take_epic1_answer`] does: a payment that requires a proof is refused without
    /// one that holds. `receipt` is the proof the envelope carried and `signed` whether a
    /// contact signed it. Returns `None` for any other S2, for the caller to finalize as a
    /// file's.
    pub(crate) async fn finalize_epic1_text(
        &self,
        body: &[u8],
        receipt: Option<&[u8; 64]>,
        signed: bool,
        propagation: Propagation,
    ) -> Result<Option<Finalized>, ContactError> {
        let network = self.wallet.config().network;
        let Some(slate) = decode_native(network, body) else {
            return Ok(None);
        };
        if slate.stage() != Stage::S2 {
            return Ok(None);
        }
        let slate_id = slate.id();
        let Some(state) = self.pay_state(slate_id).await? else {
            return Ok(None);
        };
        if state.finalized || !self.payment_held(TxId(state.tx_id)).await? {
            return Ok(None);
        }
        if signed {
            return Err(refused(Epic1Refusal::Signed));
        }
        if self.mark_if_finalized(slate_id, TxId(state.tx_id)).await? {
            return Ok(None);
        }
        self.finish_epic1_answer(&state, &slate, body, receipt, propagation)
            .await
            .map(Some)
    }

    /// The stored epic1 payment `slate_id`, when this wallet made one.
    async fn pay_state(&self, slate_id: SlateId) -> Result<Option<PayState>, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.read(|repos| {
                Ok::<_, ContactError>(
                    repos
                        .setting(&pay_key(slate_id))?
                        .and_then(|text| from_text::<PayState>(&text, "epic1 payment").ok()),
                )
            })
        })
        .await
    }

    /// Checks the proof `carried` of the S2 `slate` (native `body`) answering the payment in
    /// `state`, finalizes and posts it, and keeps the proof and marks the payment finalized.
    /// A payment that requires a proof and has none that holds is refused and cancelled, once
    /// the S2 is otherwise one that finalizes: the payee's partial signature, the fields of the
    /// stored S1 and the sender's check. An S2 that fails them fails as [`Wallet::finalize`]
    /// fails and leaves the payment waiting for its answer, as without a required proof.
    ///
    /// [`Wallet::finalize`]: lepic_wallet::Wallet::finalize
    async fn finish_epic1_answer(
        &self,
        state: &PayState,
        slate: &lepic_slate::model::Slate,
        body: &[u8],
        carried: Option<&[u8; 64]>,
        propagation: Propagation,
    ) -> Result<Finalized, ContactError> {
        let slate_id = slate.id();
        let receipt = match self.answer_receipt(state, slate, carried)? {
            Ok(receipt) => Some(receipt),
            Err(fault) if state.require_receipt => {
                // Only the payee's genuine S2 cancels the payment: anyone who knows the reply
                // key could send one with no receipt.
                self.wallet
                    .check_send_answer(slate.clone())
                    .await
                    .map_err(ContactError::Finalize)?;
                return Err(self.refuse_answer(state, slate_id, fault).await);
            }
            Err(fault) => {
                warn!(slate_id = %slate_id, fault = ?fault, "epic1 answer finalized with no receipt");
                None
            }
        };
        let v3 = self
            .v3_of_native(body)
            .await?
            .ok_or(ContactError::NotASlate)?;
        let finalized = self
            .wallet
            .finalize(
                &file_method(),
                &WireSlate::binary(MediaType::JSON, v3),
                propagation,
            )
            .await
            .map_err(ContactError::Finalize)?;
        let session = self.wallet.session()?;
        let receipt = receipt.map(|receipt| receipt.to_text());
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                if let Some(receipt) = &receipt {
                    repos.put_setting(&receipt_key(slate_id), receipt)?;
                }
                mark_finalized(repos, slate_id)
            })
        })
        .await?;
        info!(tx_id = %finalized.tx_id, "epic1 payment finalized");
        Ok(finalized)
    }

    /// The receipt the S2 `slate` of the payment in `state` carries, `signature`, checked
    /// against the address paid, the S2's amount, kernel excess and slate id, and the payer key
    /// this wallet asked with. The inner result is the receipt or why it does not hold; the
    /// outer one fails with [`ContactError::Wallet`] when the payer key cannot be derived (a
    /// locked wallet), which says nothing about the receipt.
    fn answer_receipt(
        &self,
        state: &PayState,
        slate: &lepic_slate::model::Slate,
        signature: Option<&[u8; 64]>,
    ) -> Result<Result<epic1_receipt::Epic1Receipt, ReceiptFault>, ContactError> {
        let network = self.wallet.config().network;
        let Ok(address) = Epic1Address::decode(&state.address, relay_network(network)) else {
            return Ok(Err(ReceiptFault::Invalid));
        };
        let secret = self.wallet.receipt_payer_key(
            AccountIndex(state.account),
            contact_network(network),
            slate.id().as_bytes(),
        )?;
        let Ok(payer_key) = PublicKey::from_secret_key(&secret) else {
            return Ok(Err(ReceiptFault::Invalid));
        };
        Ok(epic1_receipt::check_answer(
            &address, slate, payer_key, signature,
        ))
    }

    /// Refuses the answer to the payment in `state`, which requires a receipt, for `fault`: the
    /// payment is not finalized and is cancelled, which unlocks its inputs and tells the payee.
    /// A cancel that fails leaves the payment to its TTL. Returns the error the answer fails with.
    async fn refuse_answer(
        &self,
        state: &PayState,
        slate_id: SlateId,
        fault: ReceiptFault,
    ) -> ContactError {
        let refusal = match fault {
            ReceiptFault::Missing => Epic1Refusal::NoReceipt,
            ReceiptFault::Invalid => Epic1Refusal::BadReceipt,
        };
        warn!(slate_id = %slate_id, reason = %refusal, "epic1 answer refused");
        if let Err(error) = self.wallet.cancel(TxId(state.tx_id)).await {
            warn!(error = %ErrorChain(&error), "epic1 payment not cancelled after its answer was refused");
        }
        refused(refusal)
    }

    /// Whether the transaction `tx_id` of an epic1 payment is still stored.
    async fn payment_held(&self, tx_id: TxId) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session
                .store
                .read(|repos| Ok::<_, ContactError>(repos.transaction(tx_id)?.is_some()))
        })
        .await
    }

    /// Marks the payment `slate_id` finalized when its transaction `tx_id` is past finalizing,
    /// as [`mark_finalized`] does. Returns whether it was.
    async fn mark_if_finalized(
        &self,
        slate_id: SlateId,
        tx_id: TxId,
    ) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                let past = repos.transaction(tx_id)?.is_some_and(|tx| {
                    matches!(
                        tx.state,
                        TxState::Finalized | TxState::Posted | TxState::Confirmed
                    )
                });
                if !past {
                    return Ok::<_, ContactError>(false);
                }
                mark_finalized(repos, slate_id)?;
                Ok(true)
            })
        })
        .await
    }

    /// Queues the payer's `notice` of the epic1 payment its slate names, in a write of its own
    /// (see [`queue_payer_notice`]). Nothing for a slate that is no epic1 payment.
    pub(crate) async fn send_payer_notice(&self, notice: Notice) -> Result<(), ContactError> {
        let Some(slate_id) = notice.slate_id() else {
            return Ok(());
        };
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                // The store before the RNG, the order every other path takes them in.
                let mut rng = LockedRng(&mut **ports.rng.lock());
                let Some(text) = repos.setting(&pay_key(slate_id))? else {
                    return Ok(());
                };
                let state: PayState = from_text(&text, "epic1 payment")?;
                queue_payer_notice(repos, (network, &mut rng), &state, &notice, now)
            })
        })
        .await
    }

    /// Forgets the payments and answers whose transaction ended and the refusals kept for
    /// [`REFUSAL_KEPT_FOR`]. Runs before the watch set is made equal to the records, so their
    /// mailboxes leave it.
    pub(crate) async fn tend_epic1(&self) -> Result<(), ContactError> {
        let now = self.wallet.ports().clock.now();
        let refusals_from = now
            .checked_sub(REFUSAL_KEPT_FOR)
            .unwrap_or(Timestamp::UNIX_EPOCH)
            .as_second();
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            // Read first: a cycle with nothing to forget writes nothing.
            let (ended_keys, cancelled) = session.store.read(|repos| {
                let mut keys = Vec::new();
                let mut cancelled = Vec::new();
                for (key, text) in repos.settings_with_prefix(PAY_PREFIX)? {
                    let Ok(state) = from_text::<PayState>(&text, "epic1 payment") else {
                        continue;
                    };
                    let tx = repos.transaction(TxId(state.tx_id))?;
                    if tx.as_ref().is_none_or(|tx| ended(tx.state)) {
                        keys.push(key);
                    }
                    if let Some(tx) = tx
                        && tx.state == TxState::Cancelled
                        && let Some(slate_id) = tx.slate_id
                    {
                        cancelled.push((SlateId::from_bytes(*slate_id.as_bytes()), state));
                    }
                }
                for (key, text) in repos.settings_with_prefix(ANSWER_PREFIX)? {
                    let Ok(state) = from_text::<AnswerState>(&text, "epic1 answer") else {
                        continue;
                    };
                    if repos
                        .transaction(TxId(state.tx_id))?
                        .is_none_or(|tx| ended(tx.state))
                    {
                        keys.push(key);
                    }
                }
                for (key, text) in repos.settings_with_prefix(REFUSAL_PREFIX)? {
                    let kept = from_text::<RefusalState>(&text, "epic1 refusal")
                        .is_ok_and(|state| state.at >= refusals_from);
                    if !kept {
                        keys.push(key);
                    }
                }
                Ok::<_, ContactError>((keys, cancelled))
            })?;
            if ended_keys.is_empty() {
                return Ok(());
            }
            session.store.write(|repos| {
                // The store before the RNG, the order every other path takes them in.
                let mut rng = LockedRng(&mut **ports.rng.lock());
                // A cancelled payment's state goes in the write that queues its notice, so the
                // notice is queued once.
                for (slate_id, state) in &cancelled {
                    if repos.setting(&pay_key(*slate_id))?.is_none() {
                        continue;
                    }
                    if let Some(notice) = lepic_wallet::epic1_cancelled_notice(repos, *slate_id)? {
                        queue_payer_notice(repos, (network, &mut rng), state, &notice, now)?;
                    }
                }
                for key in &ended_keys {
                    repos.delete_setting(key)?;
                }
                Ok::<_, ContactError>(())
            })
        })
        .await
    }

    /// After a restore from the phrase: reads, once, on every mailbox of the list, the delivery
    /// slot of each account's address and the reply slots of the pending payments and in-person
    /// codes of the wallet's transactions, with the watch set, until the mailboxes say nothing
    /// waits; then the watch set alone is watched again. Mailboxes another socket of the wallet
    /// took over are taken back first.
    /// Returns how many payments were taken and S2s finalized, and the mailboxes not read.
    ///
    /// A mailbox that does not answer, does not offer mux/1, or on which some slot was not
    /// watched is named with its reason in [`Epic1Restored::not_read`]; the others are read.
    /// Fails with [`ContactError::Offline`], and with [`ContactError::RelayNotRead`] naming the
    /// first mailbox when no mailbox of the list was read.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn epic1_restore(
        &self,
        relays: &ContactRelays,
    ) -> Result<Epic1Restored, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let read_on = restore_relays(relays);
        let mut mailboxes = self.restore_reply_rows().await?;
        let session = self.wallet.session()?;
        let accounts = self
            .contact_work(move |_, _| Ok(session.store.read(|repos| repos.accounts())?))
            .await?;
        mailboxes.extend(accounts.into_iter().map(|record| {
            (
                address_ref(record.index),
                MailClass::Address,
                Job::Address(record.index),
            )
        }));
        let mut report = CollectReport::default();
        let mut told = Told::default();
        let _turn = self.wallet.contact_turn().await;
        let mut not_read = self.restore_start(relays, &read_on).await?;
        let rows = restore_rows(&mailboxes, &read_on);
        let read = self
            .read_mailboxes(
                relays,
                CollectTrigger::Foreground,
                rows.clone(),
                &mut told,
                &mut report,
            )
            .await;
        // The restore's rows leave the sessions; the watch set stays.
        let watched = self.watch_mailboxes(relays, Vec::new(), Reach::Claim).await;
        let watch = read?;
        watched?;
        for (_, host) in &read_on {
            if not_read.iter().any(|known| known.host == *host) {
                continue;
            }
            // A mailbox where some slot was not asked was not read.
            let reason = if report.unreachable.contains(host) {
                NotReadReason::NotAnswering
            } else if !all_watched(&watch, &rows, host) {
                NotReadReason::SlotsLeftOut
            } else {
                continue;
            };
            not_read.push(Epic1NotRead {
                host: host.clone(),
                reason,
            });
        }
        if not_read.len() == read_on.len()
            && let Some(first) = not_read.first()
        {
            return Err(ContactError::RelayNotRead(first.host.clone()));
        }
        let taken = report.epic1;
        info!(
            taken,
            not_read = not_read.len(),
            "epic1 mailboxes read after a restore"
        );
        Ok(Epic1Restored { taken, not_read })
    }

    /// The reply mailboxes a restore reads, as `(key_ref, class, job)`: one per transaction of
    /// the wallet still `Sent` or `Received` that has a slate id.
    async fn restore_reply_rows(&self) -> Result<Vec<(String, MailClass, Job)>, ContactError> {
        let session = self.wallet.session()?;
        let pending = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    let mut pending = Vec::new();
                    for record in repos.accounts()? {
                        for tx in repos.transactions(record.index)? {
                            let entry = &tx.entry;
                            if matches!(entry.state, TxState::Sent | TxState::Received)
                                && let Some(uuid) = entry.slate_id
                            {
                                pending.push((SlateId::from_bytes(*uuid.as_bytes()), record.index));
                            }
                        }
                    }
                    Ok::<_, ContactError>(pending)
                })
            })
            .await?;
        Ok(pending
            .into_iter()
            .map(|(slate_id, account)| {
                (
                    format!("reply:{slate_id}"),
                    MailClass::Reply,
                    Job::Payment(slate_id, account),
                )
            })
            .collect())
    }

    /// Starts a restore as an open does, once: the watch set is claimed, every mailbox another
    /// socket of the wallet took over is taken back, and every session waiting to reconnect
    /// tries now.
    /// Returns the mailboxes of `read_on` whose session could not be had, with why. The caller
    /// holds the contact turn.
    async fn restore_start(
        &self,
        relays: &ContactRelays,
        read_on: &[(String, String)],
    ) -> Result<Vec<Epic1NotRead>, ContactError> {
        let (_, _, watch) = self
            .watch_mailboxes(relays, Vec::new(), Reach::TakeBack)
            .await?;
        Ok(read_on
            .iter()
            .filter_map(|(_, host)| {
                let reason = watch
                    .relays
                    .iter()
                    .filter(|relay| relay.relay == *host)
                    .find_map(|relay| relay.error.as_ref().and_then(NotReadReason::of_watch))?;
                Some(Epic1NotRead {
                    host: host.clone(),
                    reason,
                })
            })
            .collect())
    }
}

/// The posts the outbox made, as a payment's attempts: one per relay that took a post to a
/// delivery mailbox, else one per post, named by its route's value.
fn attempts_of(tried: &[Tried]) -> Vec<Epic1Attempt> {
    let mut attempts = Vec::with_capacity(tried.len());
    for tried in tried {
        if tried.relays.is_empty() {
            attempts.push(Epic1Attempt {
                host: tried.route.value.clone(),
                error: tried.reason.clone(),
                uncertain: tried.state == OutboxState::Uncertain,
                refusal: tried.refusal.clone(),
            });
            continue;
        }
        attempts.extend(tried.relays.iter().map(|relay| Epic1Attempt {
            host: relay.clone(),
            error: None,
            uncertain: false,
            refusal: None,
        }));
    }
    attempts
}

/// Takes the payments and notices pushed to delivery mailboxes. Anything but a sealed slate or
/// notice envelope is stored and dropped, as is a payment refused; one whose take failed for a
/// passing reason is held.
pub(crate) struct Payments<'a, N, S: StoreOpener, V> {
    book: &'a ContactBook<'a, N, S, V>,
    relays: &'a ContactRelays,
    mailboxes: &'a Mailboxes,
    /// Payments taken.
    pub(crate) taken: usize,
    /// The mailboxes, by key reference and relay, a message was held in.
    pub(crate) kept: HashSet<(String, String)>,
}

impl<'a, N, S: StoreOpener, V> Payments<'a, N, S, V> {
    pub(crate) fn new(
        book: &'a ContactBook<'a, N, S, V>,
        relays: &'a ContactRelays,
        mailboxes: &'a Mailboxes,
    ) -> Self {
        Self {
            book,
            relays,
            mailboxes,
            taken: 0,
            kept: HashSet::new(),
        }
    }
}

impl<N, S, V> Handler for Payments<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn handle(&mut self, mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
        Box::pin(async move {
            let handled = match self.mailboxes.job(&mail.key_ref, &mail.relay) {
                Some(Job::Address(account)) => self.take(account, &mail.relay, mail.mail).await,
                _ => Err(Hold),
            };
            if handled.is_err() {
                self.kept.insert((mail.key_ref, mail.relay));
            }
            handled
        })
    }
}

impl<N, S, V> Payments<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes one message of the delivery mailbox of the address of `account`, read on `relay`.
    async fn take(
        &mut self,
        account: AccountIndex,
        relay: &str,
        message: MailboxMessage,
    ) -> Result<Stored, Hold> {
        let MailboxContent::Opened(received) = message.into_content() else {
            return Ok(Stored);
        };
        let Ok((envelope, marker)) = dearmor_marked(received.plaintext.expose_str()) else {
            info!(
                reason = "not an envelope",
                "epic1 delivery mailbox message dropped"
            );
            return Ok(Stored);
        };
        let taken = match marker {
            ArmorMarker::Tx => {
                self.book
                    .take_payment(self.relays, account, relay, &envelope)
                    .await
            }
            // A notice is no payment taken: it adds nothing to the count.
            ArmorMarker::Sealed => self
                .book
                .take_address_notice(account, &envelope)
                .await
                .map(|_| false),
        };
        match taken {
            Ok(new) => {
                if new {
                    self.taken = self.taken.saturating_add(1);
                }
                Ok(Stored)
            }
            Err(error) if passes(&error) => {
                warn!(error = %ErrorChain(&error), "epic1 payment kept until the failure passes");
                Err(Hold)
            }
            Err(error) => {
                info!(reason = %ErrorChain(&error), "epic1 delivery mailbox message dropped");
                Ok(Stored)
            }
        }
    }
}

/// Takes the answers pushed to the reply mailboxes of payments: an S2 or a refusal.
pub(crate) struct Replies<'a, N, S: StoreOpener, V> {
    book: &'a ContactBook<'a, N, S, V>,
    mailboxes: &'a Mailboxes,
    /// Answers and refusals taken.
    pub(crate) taken: usize,
    /// The mailboxes, by key reference and relay, a message was held in.
    pub(crate) kept: HashSet<(String, String)>,
    /// The payments whose answer or refusal was taken, each with the relay it was read on: the
    /// copies of their post on the other relays are owed a cancel.
    pub(crate) cancels: Vec<(SlateId, AccountIndex, String)>,
}

impl<'a, N, S: StoreOpener, V> Replies<'a, N, S, V> {
    pub(crate) fn new(book: &'a ContactBook<'a, N, S, V>, mailboxes: &'a Mailboxes) -> Self {
        Self {
            book,
            mailboxes,
            taken: 0,
            kept: HashSet::new(),
            cancels: Vec::new(),
        }
    }
}

impl<N, S, V> Handler for Replies<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn handle(&mut self, mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
        Box::pin(async move {
            let handled = match self.mailboxes.job(&mail.key_ref, &mail.relay) {
                Some(Job::Payment(slate_id, account)) => {
                    let before = self.taken;
                    let handled = self.take(slate_id, account, mail.mail).await;
                    if self.taken != before {
                        self.cancels.push((slate_id, account, mail.relay.clone()));
                    }
                    handled
                }
                Some(Job::Code(slate_id, account)) => self.take(slate_id, account, mail.mail).await,
                _ => Err(Hold),
            };
            if handled.is_err() {
                self.kept.insert((mail.key_ref, mail.relay));
            }
            handled
        })
    }
}

impl<N, S, V> Replies<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes one message of the reply mailbox of the payment `slate_id` of `account`.
    async fn take(
        &mut self,
        slate_id: SlateId,
        account: AccountIndex,
        message: MailboxMessage,
    ) -> Result<Stored, Hold> {
        let MailboxContent::Opened(received) = message.into_content() else {
            return Ok(Stored);
        };
        let Ok((envelope, marker)) = dearmor_marked(received.plaintext.expose_str()) else {
            info!(reason = "not an envelope", "reply mailbox message dropped");
            return Ok(Stored);
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
                Ok(Stored)
            }
            Err(error) if passes(&error) => {
                warn!(error = %ErrorChain(&error), "answer kept until the failure passes");
                Err(Hold)
            }
            Err(error) => {
                info!(reason = %ErrorChain(&error), "reply mailbox message dropped");
                Ok(Stored)
            }
        }
    }
}
