// SPDX-License-Identifier: Apache-2.0
//! What the engine tells the host while it runs. Events go to every subscriber of
//! [`crate::Wallet::subscribe`]; a subscriber that falls more than [`EVENT_CAPACITY`] events
//! behind misses the oldest ones and is told how many it missed.

use lepic_crypto::Commitment;
use lepic_primitives::amount::{Amount, Height};
pub use lepic_slate::model::SlateId;
use lepic_slate::stage::Stage;
use lepic_store::{AccountIndex, RecoveryState, TxId, TxState};
use lepic_transport::transport::TransportId;

use crate::state::StateChange;

pub const EVENT_CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    Session(SessionState),
    Balance(Balance),
    Transaction(TransactionState),
    /// A received slate created a transaction. Its later state changes arrive as
    /// [`Event::Transaction`]. A send to the wallet itself raises [`Event::SelfSent`]
    /// instead: nothing was received from anyone.
    Received(ReceivedTransaction),
    /// A send to the wallet itself was stored and finalized: two entries over transport
    /// `self`, the outgoing one `finalized` and the incoming one `received`. Its posting and
    /// confirmation arrive as [`Event::Transaction`] for each entry.
    SelfSent(SelfSentTransaction),
    /// A slate received before arrived again and was answered with the reply stored the first
    /// time. Nothing changed; no [`Event::Received`] follows for it.
    AnsweredAgain(AnsweredSlate),
    /// A payment received over Epicbox was stored, but its S2 reply could not be delivered: the
    /// relay refused it, or delivering it kept failing. The transaction stays received and its
    /// message is settled; a sender that sends the same S1 again is answered with the stored S2.
    ReplyUndelivered(UndeliveredReply),
    Sync(SyncProgress),
    Transport(TransportStatus),
    /// A transport's connection dropped: why, and how long it waits before it tries again.
    /// Follows the [`Event::Transport`] that reports `Disconnected`.
    TransportDisconnected(TransportDisconnect),
    /// An invoice this wallet issued was paid and finalized. Its posting shows as
    /// [`Event::Transaction`].
    InvoiceFinalized(FinalizedInvoice),
    /// An invoice expired unpaid: a parked one was deleted, or one this wallet issued was
    /// cancelled.
    InvoiceExpired(ExpiredInvoice),
    /// The issuer of an invoice this wallet paid reports that it pushed the transaction, with
    /// the kernel excess the payment expects, or a refresh found that kernel in the node's
    /// pool (once per payment while the wallet is open). Advisory: the transaction's state
    /// changes only when a refresh finds the kernel on chain.
    InvoicePosted(PostedInvoice),
    /// The payer declined an invoice this wallet issued. Nothing changed; the host may cancel
    /// the invoice. A cancellation the relay reports raises nothing
    /// ([`crate::Wallet::apply_relay_cancellation`]).
    InvoiceDeclined(DeclinedInvoice),
    /// The issuer withdrew an invoice. A parked one was deleted. For one this wallet already
    /// paid, `tx_id` names the payment, which the host may offer the user to cancel; nothing
    /// was cancelled. A cancellation the relay reports raises nothing
    /// ([`crate::Wallet::apply_relay_cancellation`]).
    InvoiceWithdrawn(WithdrawnInvoice),
    /// An S2 arrived over Epicbox for a slate this wallet's store does not know.
    /// Another install of the same wallet, on the same recovery phrase and so the same
    /// payments address, may have sent the payment it answers. The
    /// message is left on the relay for that install, and requeued for it, for up to
    /// [`crate::inbox::TWIN_REQUEUE_WINDOW`]; the host should say that the other install must
    /// be opened to finish the payment. Raised once per answer, when it is first seen, and
    /// also when it is refused at once because [`crate::inbox::MAX_TWIN_ANSWERS`] others are
    /// cycling. Nothing changed here. Nothing verifies the slate id or the
    /// sender: anyone who knows the payments address can raise this with any id, so the host
    /// must only inform the user, never act on it or treat the sender as trusted.
    UnknownSlate(UnknownSlate),
    /// A received payment that waited for its sender can never be mined: the inputs of the
    /// sender's slate were spent by another transaction, and neither its kernel nor its output
    /// is on chain. Another install of the same wallet, on the same recovery phrase, most
    /// likely answered the same payment and the sender finalized that answer; the funds then
    /// reached this wallet's seed through the other install. The payment was ended as a
    /// cancel ends it, which its [`Event::Transaction`] to `cancelled` reports just before;
    /// the host should say that another install took this payment and offer a rescan to see
    /// it. Should the kernel still appear, a later refresh confirms the payment.
    ReceiveSuperseded(SupersededReceive),
    /// The sender of a payment this wallet received over Epicbox reports that it pushed the
    /// transaction, with the kernel excess this wallet's own S2 implies. Raised once per
    /// payment, while it waits for its sender. Advisory: nothing changed, and the payment
    /// confirms only when a refresh finds the kernel, so the host should refresh now.
    PaymentPosted(PostedPayment),
    /// The sender of a payment this wallet received and answered reports that it cancelled
    /// the payment. Raised once per payment, while it waits for its sender. Advisory: nothing
    /// changed and nothing was released; the host decides whether to cancel the payment here,
    /// which [`crate::Wallet::cancel`] does by its usual rules. A cancellation the relay
    /// reports raises nothing ([`crate::Wallet::apply_relay_cancellation`]).
    PaymentCancelled(CancelledPayment),
    /// The receiver of a send this wallet made refused it unanswered, as a wallet set to refuse
    /// payments nobody asked for does (ADR 0045), and said so authenticated: a paired contact,
    /// or the payee of an epic1 payment to the send's reply key. The send never happened: it
    /// was erased with its change and its inputs unlocked, so `tx_id` no longer names a stored
    /// transaction, and no one was told. Raised once per send.
    /// [`crate::Wallet::send_declined_at`] keeps when, for the slate id. A cancellation the
    /// relay reports raises nothing ([`crate::Wallet::apply_relay_cancellation`]).
    PaymentDeclined(DeclinedPayment),
    /// A new payment nobody asked for was refused at an open receipt cap: the sender's
    /// [`crate::config::WalletPolicy::max_open_receipts_per_sender`] or
    /// [`crate::config::WalletPolicy::max_open_receipts`] in all. Nothing was signed or stored
    /// and no receipt was cancelled. Raised once for each refused delivery, on every transport,
    /// so a relay that offers the same S1 again raises it again; over stock Epicbox the sender
    /// is not told and its send waits unanswered. Advisory: the count drops as open receipts
    /// confirm or end, and the owner may raise the caps.
    PaymentRefused(RefusedPayment),
    /// A reply to one of this wallet's invites paired a contact; its SAS waits for the user's
    /// check (RFC 0002 7.3).
    PairingReplied(ContactEvent),
    /// A pairing this wallet answered, or one in person, completed; its SAS waits for the
    /// user's check.
    PairingConfirmed(ContactEvent),
    /// A pairing in progress ended without a record. The id names the record that was removed.
    PairingFailed(FailedPairing),
    /// Something about a pairing changed that the contact caused, one event per change in the
    /// order they happened: a newer card (same keys), the contact heard from for the first
    /// time, its match verdict accepted, or the pairing ended by the contact or by never being
    /// finished. Never raised for this side's own words check.
    ContactUpdated(ContactUpdate),
    /// A contact update named a mailbox on another relay. The newer card was stored, with an
    /// [`Event::ContactUpdated`] for it, and the mailbox in use stays: the host decides whether
    /// to follow, and applies the move with the contact book's `apply_relay_move`. Raised once
    /// per card.
    ContactRelayMoveRequested(RelayMoveRequest),
    /// A home relay did not answer; collecting from it backs off (RFC 0002 8.4).
    HomeRelayUnreachable(UnreachableRelay),
    /// A key check proved the contact still holds the old keys: the old pairing keeps its keys
    /// and trust, and the new pairing was folded into it ("Anna's keys are back").
    ContactKeysRestored(ContactEvent),
    /// A key check found no old keys, or went unanswered for a day: the new pairing shows
    /// keys-changed and the old one is untouched, until the user decides.
    ContactKeysChanged(ContactEvent),
    /// The contact removed its pairing with this wallet and said so in a signed notice: nothing
    /// sent through the pairing arrives any more. The record stays, ended as unpaired, until
    /// the user removes it too. Raised once per pairing, with no [`Event::ContactUpdated`].
    ContactUnpaired(ContactEvent),
    /// A verified contact that may send invoices sent one; it is parked for the user to pay or
    /// decline. Nothing was paid.
    InvoiceFromContact(ContactInvoiceEvent),
    /// A contact sent a withdrawal (an S1 with purpose withdrawal); it was received and the
    /// answer queued for the contact's mailbox.
    WithdrawalFromContact(ContactSlateEvent),
    /// A contact's sealed slate (an S1 that is not a withdrawal) arrived in its mailbox; it was
    /// received and the answer queued for the contact's mailbox.
    SealedReceived(ContactSlateEvent),
    /// Envelopes in the contact's mailbox did not open with this install's keys and were
    /// dropped; raised at most once per contact in a collecting cycle. The contact may write to
    /// keys of another install or from before a restore (RFC 0002 C-12); pairing again runs the
    /// key check. Advisory: whoever knows the mailbox can cause it, so the host only informs the
    /// user and never acts on it. An envelope signed by another key raises nothing.
    SealedUnopenable(ContactEvent),
    /// An outbox entry reached the contact's home relay.
    OutboxDelivered(OutboxNews),
    /// An outbox entry could not be delivered for a day and stopped retrying; the host offers
    /// "Send again". Funds unlock as for any unfinished payment.
    OutboxStuck(OutboxNews),
    /// A payment's post changed to uncertain (it went unanswered and is posted again on the
    /// same route), to failed (no route took it, or its time or cutoff ran out), or from
    /// uncertain to posted (the same route took it later). Raised once for each change. The
    /// host may move an uncertain or failed payment on with its next route.
    DeliveryChanged(DeliveryNews),
    /// The contact's answer (S2) to a payment this wallet sent through its mailbox arrived and
    /// the payment was finalized. Its posting shows as [`Event::Transaction`].
    ContactPaymentFinalized(ContactSlateEvent),
    /// A contact sent a payload; it is kept for [`crate::Wallet::contact_payloads`] until the
    /// host acknowledges it.
    ContactPayload(ContactEvent),
    /// Payloads from the pairing were left on the relay because its cap of kept payloads is
    /// reached; raised at most once per pairing in a collecting cycle. They arrive once the host
    /// acknowledges payloads with [`crate::Wallet::contact_payloads_ack`].
    ContactPayloadsParked(ContactEvent),
    /// The node refused a finalized transaction or could not be reached when it was pushed.
    /// The transaction stays finalized and stored with its inputs locked, and a refresh pushes
    /// it again while it may still be mined. The host may push it sooner with
    /// [`crate::Wallet::post`], or cancel it. Raised for the first failed push of a
    /// transaction, from a finalize, a repost, a refresh, an Epicbox answer or an invoice
    /// payment, and again only when the next failure differs in kind or in the node's text;
    /// a push the node refused because inputs were spent ends the transaction instead and
    /// raises no such event.
    NotPosted(NotPosted),
    /// An answer to a code this wallet showed in person (RFC 0003 §9) arrived in the code's
    /// reply mailbox and checks: an I2 to an in-person invoice, or an S2 to an in-person send.
    /// Nothing was finalized: the host shows the answer with its check code and the user picks
    /// the one to finalize. Raised once per answer that checks.
    InPersonAnswer(InPersonAnswerEvent),
    /// An answer to an in-person code was refused for good: it reached the code's slot or a
    /// direct route, but the checks turned it down. Nothing was stored for it. Not raised when
    /// the answer is held to be tried again (the node did not answer).
    InPersonAnswerRefused(InPersonAnswerRefusedEvent),
    /// The recovery of a payment ([`crate::Wallet::recover`]) moved to another state: stored,
    /// taken by the node, mined, back to waiting after a reorg, done or failed. Raised once per
    /// change; the payment's own changes arrive as [`Event::Transaction`].
    RecoveryChanged(RecoveryNews),
}

/// An answer to an in-person code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonAnswerEvent {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub stage: Stage,
    /// The answer's number among the answers to this code, from 1.
    pub answer: u32,
    /// The four digits the answering party's wallet shows for the same answer.
    pub check_code: String,
    /// An earlier answer to this code had the same check code: the user cannot tell the two
    /// apart by it.
    pub same_code: bool,
}

/// An answer to an in-person code that was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPersonAnswerRefusedEvent {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// Why, in snake case: `already_finalized`, `expired`, `inputs_spent`, `bad_answer` or `cancelled`.
    pub reason: &'static str,
}

/// An invoice a contact sent, with what the contact says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactInvoiceEvent {
    pub contact_id: lepic_store::ContactId,
    pub slate_id: SlateId,
    pub amount: Amount,
    pub purpose: Option<lepic_contact::Purpose>,
    pub reference: Option<String>,
    /// Unix seconds; advisory.
    pub expires: Option<u64>,
    /// The issuer's message, only when its signature verifies, made safe to display.
    pub message: Option<String>,
}

/// A slate exchanged with a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactSlateEvent {
    pub contact_id: lepic_store::ContactId,
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub amount: Amount,
}

/// An outbox entry an event is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxNews {
    pub contact_id: lepic_store::ContactId,
    pub slate_id: SlateId,
}

/// A payment's post whose delivery state changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryNews {
    pub slate_id: SlateId,
    /// [`lepic_store::OutboxState::Uncertain`], [`lepic_store::OutboxState::Failed`], or
    /// [`lepic_store::OutboxState::Posted`] after uncertain.
    pub state: lepic_store::OutboxState,
    /// The route the post went to as the link or the contact names it: an Epicbox address,
    /// or the endpoint of an `http` or `tor` entry.
    pub route: String,
}

/// A contact an event is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactEvent {
    pub contact_id: lepic_store::ContactId,
}

/// A contact that asked to move to another relay, and that relay as `domain:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMoveRequest {
    pub contact_id: lepic_store::ContactId,
    pub host: String,
}

/// What changed about a pairing in an [`Event::ContactUpdated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactChange {
    /// A newer card with the same keys.
    Card,
    /// The proven payments address was set or changed.
    Address,
    /// The contact was heard from in this pairing for the first time.
    Heard,
    /// The contact's match verdict for this pairing's words was accepted.
    PeerVerified,
    /// The pairing ended; the update says why.
    Ended,
}

/// A change to a pairing, and for [`ContactChange::Ended`] why it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactUpdate {
    pub contact_id: lepic_store::ContactId,
    pub change: ContactChange,
    pub ended_reason: Option<lepic_store::PairingEndReason>,
}

impl ContactUpdate {
    pub const fn of(contact_id: lepic_store::ContactId, change: ContactChange) -> Self {
        Self {
            contact_id,
            change,
            ended_reason: None,
        }
    }
}

/// A pairing that ended without a record, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailedPairing {
    pub contact_id: lepic_store::ContactId,
    pub reason: PairingFailure,
}

/// Why a pairing ended without a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingFailure {
    /// The confirm does not match the invite's commitment or enc key: something changed the
    /// invite on the way. Nothing was stored.
    ChangedOnTheWay,
    /// The confirm's card names another contact kind than the invite did. Nothing was stored.
    KindDiffers,
    /// The invite expired before a reply arrived.
    Expired,
    /// This wallet answered an invite and no confirm came in time, or, as the inviter, could
    /// not deliver its confirm in time: the other side cannot have finished, so nothing of the
    /// pairing is kept.
    NotConfirmed,
    /// The inviter refused the reply: the invite was used, expired or cancelled. Advisory.
    Refused(lepic_contact::Refusal),
    /// The answer proved another payments address than the one the pairing expected.
    OtherAddress,
    /// The pairing expected an address proof and the answer carried none.
    AddressProofMissing,
    /// Another pairing with the same wallet was in progress, and this one lost to it.
    Crossed,
}

/// A home relay that did not answer, as `domain:port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreachableRelay {
    pub relay: String,
}

/// Whether the root key is in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Unlocked,
    Locked,
    /// The wallet handle was closed; no further events follow.
    Closed,
}

/// The balance of one account, in the categories `epic-wallet info` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    pub account: AccountIndex,
    /// The tip height the balance was computed at.
    pub height: Height,
    /// The confirmations the spendable / awaiting-confirmation split was made with: the
    /// wallet's setting at that time.
    pub minimum_confirmations: u64,
    pub total: Amount,
    pub spendable: Amount,
    pub awaiting_confirmation: Amount,
    pub awaiting_finalization: Amount,
    pub immature: Amount,
    pub locked: Amount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionState {
    pub tx_id: TxId,
    pub from: TxState,
    pub to: TxState,
}

/// The transaction a received slate created, stored in state `received`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedTransaction {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub account: AccountIndex,
    pub amount: Amount,
    pub transport: TransportId,
}

/// The two entries a send to the wallet itself stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfSentTransaction {
    /// The outgoing entry: it spent the inputs and holds the change.
    pub tx_id: TxId,
    /// The incoming entry: it holds the output of `amount`.
    pub received_tx_id: TxId,
    pub account: AccountIndex,
    pub amount: Amount,
}

/// A received transaction whose S2 reply was not delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UndeliveredReply {
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

/// The transaction a repeated slate was received as before, and the transport it came over
/// this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnsweredSlate {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub transport: TransportId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedInvoice {
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredInvoice {
    pub slate_id: SlateId,
    /// The issuer's cancelled transaction; `None` for a parked invoice, which has none.
    pub tx_id: Option<TxId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostedInvoice {
    /// The payment of the invoice.
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub excess: Commitment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclinedInvoice {
    /// The issued invoice.
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawnInvoice {
    pub slate_id: SlateId,
    /// The payment still waiting for the issuer; `None` when the invoice was not paid.
    pub tx_id: Option<TxId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSlate {
    pub slate_id: SlateId,
    /// [`Stage::S2`], the answer to a send.
    pub stage: Stage,
    /// The address the message came from, as the relay reported it.
    pub sender: String,
}

/// A new payment refused at an open receipt cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedPayment {
    pub slate_id: SlateId,
    /// The transport it came over. A payment to an epic1 address reports the method that
    /// took it, `file`.
    pub transport: TransportId,
    /// The sender's key as the transport names it, when it names one.
    pub sender: Option<String>,
    /// The cap that refused it.
    pub cap: ReceiptCap,
}

/// An open receipt cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptCap {
    /// [`crate::config::WalletPolicy::max_open_receipts_per_sender`].
    PerSender,
    /// [`crate::config::WalletPolicy::max_open_receipts`].
    Total,
}

impl ReceiptCap {
    /// The name the logs and the serve API use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerSender => "per_sender",
            Self::Total => "total",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupersededReceive {
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

/// A recovery that changed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryNews {
    /// The payment recovered.
    pub tx_id: TxId,
    pub state: RecoveryState,
}

/// A finalized transaction the node did not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotPosted {
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// Why, as the node's error reads, for the host to log or show.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclinedPayment {
    /// The send, erased by the decline.
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelledPayment {
    /// The received payment.
    pub tx_id: TxId,
    pub slate_id: SlateId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostedPayment {
    /// The received payment.
    pub tx_id: TxId,
    pub slate_id: SlateId,
    pub excess: Commitment,
}

impl From<StateChange> for Event {
    fn from(change: StateChange) -> Self {
        Self::Transaction(TransactionState {
            tx_id: change.tx_id,
            from: change.from,
            to: change.to,
        })
    }
}

/// Progress of a scan or refresh over a height range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncProgress {
    pub height: Height,
    pub target: Height,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportDisconnect {
    pub transport: TransportId,
    pub connection: Connection,
    /// What ended the connection, as the transport reports it. No secrets.
    pub reason: String,
    /// The wait before the next attempt; `None` when the transport does not retry.
    pub retry_in: Option<std::time::Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportStatus {
    pub transport: TransportId,
    pub connection: Connection,
    pub state: TransportState,
}

/// Which of a transport's connections an event is about. A drain opens its own short-lived
/// connection beside a running listener, so a host that shows the listener's health must read
/// only the listener's events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connection {
    /// The connection held while the wallet listens on its payments address.
    Listener,
    /// A one-time drain of the payments address.
    PaymentsDrain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportState {
    Connecting,
    Connected,
    /// Disconnected; the transport retries on its own unless it was stopped.
    Disconnected,
    Stopped,
}
