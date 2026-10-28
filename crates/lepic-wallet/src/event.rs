// SPDX-License-Identifier: Apache-2.0
//! What the engine tells the host while it runs. Events go to every subscriber of
//! [`crate::Wallet::subscribe`]; a subscriber that falls more than [`EVENT_CAPACITY`] events
//! behind misses the oldest ones and is told how many it missed.

use lepic_crypto::Commitment;
use lepic_epicbox::EpicboxAddress;
use lepic_primitives::amount::{Amount, Height};
pub use lepic_slate::model::SlateId;
use lepic_slate::stage::Stage;
use lepic_store::{AccountIndex, TxId, TxState};
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
    /// An invoice was parked, waiting for the user to pay or decline it. Nothing was paid.
    InvoiceParked(ParkedInvoice),
    /// An invoice this wallet issued was paid and finalized. Its posting shows as
    /// [`Event::Transaction`].
    InvoiceFinalized(FinalizedInvoice),
    /// An invoice expired unpaid: a parked one was deleted, or one this wallet issued was
    /// cancelled.
    InvoiceExpired(ExpiredInvoice),
    /// The issuer of an invoice this wallet paid reports that it pushed the transaction, with
    /// the kernel excess the payment expects. Advisory: the transaction's state changes only
    /// when a refresh finds the kernel.
    InvoicePosted(PostedInvoice),
    /// The payer declined an invoice this wallet issued. Nothing changed; the host may cancel
    /// the invoice.
    InvoiceDeclined(DeclinedInvoice),
    /// The issuer withdrew an invoice. A parked one was deleted. For one this wallet already
    /// paid, `tx_id` names the payment, which the host may offer the user to cancel; nothing
    /// was cancelled.
    InvoiceWithdrawn(WithdrawnInvoice),
    /// A payer sent an invoice this wallet issued back unchanged, as a wallet that does not
    /// pay invoices does. The peer is recorded as not paying invoices; the invoice stays
    /// issued until the host cancels it or it expires. A bounce redelivered before its relay
    /// message was settled raises this again for the same `tx_id`; treat it as the same bounce.
    InvoiceBounced(BouncedInvoice),
    /// An S2 or an I2 arrived over Epicbox for a slate this wallet's store does not know.
    /// Another install of the same wallet, on the same recovery phrase and so the same
    /// payments address, may have sent the payment or issued the invoice it answers. The
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
    /// A reply to one of this wallet's invites paired a contact; its SAS waits for the user's
    /// check (RFC 0002 7.3).
    PairingReplied(ContactEvent),
    /// A pairing this wallet answered, or one in person, completed; its SAS waits for the
    /// user's check.
    PairingConfirmed(ContactEvent),
    /// A pairing in progress ended without a record. The id names the record that was removed.
    PairingFailed(FailedPairing),
    /// A contact sent a newer card: its addresses changed, its keys did not.
    ContactUpdated(ContactEvent),
    /// A home relay did not answer; collecting from it backs off (RFC 0002 8.4).
    HomeRelayUnreachable(UnreachableRelay),
    /// A key check proved the contact still holds the old keys: the old pairing keeps its keys
    /// and trust, and the new pairing was folded into it ("Anna's keys are back").
    ContactKeysRestored(ContactEvent),
    /// A key check found no old keys, or went unanswered for a day: the new pairing shows
    /// keys-changed and the old one is untouched, until the user decides.
    ContactKeysChanged(ContactEvent),
    /// The contact removed its pairing with this wallet and said so in a signed notice: its
    /// mailbox is no longer read, so nothing sent through the pairing arrives. The record stays,
    /// marked removed by the peer (`lepic_wallet_contacts::ContactView::removed_by_peer`), until the user removes it too.
    /// Raised once per pairing.
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
    /// The contact's answer (S2) to a payment this wallet sent through its mailbox arrived and
    /// the payment was finalized. Its posting shows as [`Event::Transaction`].
    ContactPaymentFinalized(ContactSlateEvent),
    /// A contact sent a payload; it is kept for [`crate::Wallet::contact_payloads`] until the
    /// host acknowledges it.
    ContactPayload(ContactEvent),
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

/// A contact an event is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactEvent {
    pub contact_id: lepic_store::ContactId,
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
    /// The invite expired before a reply arrived.
    Expired,
    /// This wallet answered an invite and no confirm came in time, or, as the inviter, could
    /// not deliver its confirm in time: the other side cannot have finished, so nothing of the
    /// pairing is kept.
    NotConfirmed,
    /// The inviter refused the reply: the invite was used, expired or cancelled. Advisory.
    Refused(lepic_contact::Refusal),
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
pub struct ParkedInvoice {
    pub slate_id: SlateId,
    pub amount: Amount,
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
    /// [`Stage::S2`], the answer to a send, or [`Stage::I2`], the payment of an invoice.
    pub stage: Stage,
    /// The address the message came from, as the relay reported it.
    pub sender: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupersededReceive {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BouncedInvoice {
    /// The issued invoice.
    pub tx_id: TxId,
    pub slate_id: SlateId,
    /// The address the invoice was issued to.
    pub peer: EpicboxAddress,
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
