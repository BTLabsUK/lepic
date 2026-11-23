//! Payments to epic1 links (EPICTX), from anyone, with no pairing.
//!
//! The payee shows its epic1 address, [`EpicWallet::epic1_address`], or a request link from
//! [`EpicWallet::epic1_link_make`]: `epic:epic1…`, the account's address with what it asks.
//! The address carries its own delivery mailbox, which a payer posts to on the relays of its
//! relay list. The wallet stores nothing for a link.
//!
//! The relay list is the mailbox list of [`EpicWallet::mailbox_set`]. Delivery mailboxes are
//! posted to and read on each mailbox of the list not known to lack mux/1;
//! [`EpicWallet::mailbox_list`] shows what is known.
//!
//! The payer reads the link with [`EpicWallet::epic1_link_read`] to show the address, what it
//! asks and its entries, then pays it with [`EpicWallet::epic1_pay`] once the user confirmed
//! them. The payment is sealed anonymously to the address and posted on the link's `http` and
//! `tor` entries, or, for a bare address or a link without entries, to the address's delivery
//! mailbox on every usable relay of the list.
//!
//! The delivery loop ([`EpicWallet::set_delivery`]) does the rest on both sides: the payee
//! takes payments from the delivery mailbox of its address and answers each on the
//! relay it read the payment from, and the payer takes the answer from its reply mailbox and
//! finalizes it. [`EpicWallet::epic1_answers`] lists the answers. After a restore from the
//! phrase, [`EpicWallet::epic1_restore`] reads the delivery mailbox of each account's address
//! once.
//!
//! A listener tries the key of the wallet's epic1 address on payments sent to it only where
//! [`EpicWallet::set_epic1_at_listener`] switched it on for that socket.
//!
//! Links and payments belong to the default account. Making and reading a link connect
//! nowhere. Calls that take a [`ContactRelayMode`]
//! reach relays as the contact calls do and fail with `ContactsOffline` before connecting when
//! the mode does not allow it, and with `Unsupported` when the configuration
//! names no Epicbox relay. Every call fails with `Locked` on a locked wallet.

use flutter_rust_bridge::frb;

use crate::api::error::WalletError;
use crate::api::types::{
    ContactRelayMode, Epic1AnswerView, Epic1Link, Epic1LinkRead, Epic1Paid, Epic1Restored,
    EpictxView, PaymentProofCheck, SendOptions,
};
use crate::api::wallet::EpicWallet;

/// A listener socket of the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerSocket {
    /// The HTTP listener.
    Web,
    /// The listener behind the wallet's onion.
    Onion,
}

impl EpicWallet {
    /// The epic1 address of the default account: its seal key and its delivery key on the
    /// wallet's network, with the bare link to share and the text of its QR code.
    pub async fn epic1_address(&self) -> Result<Epic1Link, WalletError> {
        self.run(
            "epic1_address",
            |session| async move { session.epic1_address() },
        )
        .await
    }

    /// Makes a request link: the default account's epic1 address, asking `amount` atomic units
    /// or, with `None`, any amount the payer chooses. The wallet stores nothing for it, and the
    /// same fields give the same link. A payment to it comes to the address's delivery mailbox,
    /// which the delivery loop reads on every relay the wallet uses; the payer may pay another
    /// amount, and the payment is taken.
    ///
    /// Fails with `InvalidArgument` for a zero amount or a relay list off the wallet's
    /// network, as `lepic epic1 link` checks it, `Epic1MessageInvalid` for a message longer
    /// than a link carries or with control characters, and `Unsupported` when the
    /// configuration names no Epicbox relay. Connects to no relay.
    pub async fn epic1_link_make(
        &self,
        amount: Option<u64>,
        message: Option<String>,
    ) -> Result<Epic1Link, WalletError> {
        self.run("epic1_link_make", |session| async move {
            session.epic1_link_make(amount, message)
        })
        .await
    }

    /// Reads an epic1 link: the address it pays, what it asks, and the host of its first
    /// `http` or `tor` entry, or none for a payment that goes to the payee's mailbox, to show
    /// before the user pays, and how many `mailbox=` entries it holds, which a payment never
    /// uses. Nothing is stored and no relay is reached.
    ///
    /// Fails with `NotAnEpic1Link` for text that is not one, `Epic1WrongNetwork` for a link of
    /// the other network, and `Epic1CannotPay` when it names no relay this wallet can use.
    pub async fn epic1_link_read(&self, link: String) -> Result<Epic1LinkRead, WalletError> {
        self.run("epic1_link_read", |session| async move {
            session.epic1_link_read(&link)
        })
        .await
    }

    /// Pays an epic1 link `amount` atomic units with `message`, or with `None` the amount and the
    /// message the link asks; an empty `message`, or one of spaces only, pays without one. The
    /// payment is stored, then posted to the link's first `http` or `tor` entry. A post that was
    /// not sent, or was refused, goes to the next entry at once; one sent and not answered stays on
    /// its entry and is posted again later. A link without such entries is posted to the payee's
    /// delivery mailbox on each mailbox of the list not known to lack mux/1, or on those of
    /// `mailboxes` alone when it names any: the payee's own, given by the user. The payee answers
    /// on the relay it read the payment from, or in the reply to an `http` or `tor` post. The
    /// delivery loop reads the answer on the relays the payment went to and on those of the list,
    /// and finalizes it. A second payment to a link is made while the first waits.
    ///
    /// A LEPIC payee signs a payment proof into its answer; one that holds is kept with the
    /// payment ([`EpicWallet::epic1_proof`]). With `require_proof`, an answer without a proof
    /// that holds is refused: the payment is cancelled unfinalized, its inputs are unlocked,
    /// and the payee is told it was declined. A payee that signs none cannot be paid then.
    ///
    /// Fails as [`EpicWallet::epic1_link_read`] does, with `InvalidArgument` for a zero amount
    /// or none when the link asks none, `MailboxInvalid` or `MailboxNotPublic` for a host of
    /// `mailboxes`, `NoSharedMailbox` before anything is stored when a payment to the
    /// payee's mailbox would go through a list that keeps none of the shipped mailboxes and
    /// `mailboxes` names none (the message names the shipped ones; ask the user for the
    /// payee's mailbox), and as `send` fails.
    #[allow(clippy::too_many_arguments)] // The app's send form, one value per field.
    pub async fn epic1_pay(
        &self,
        link: String,
        amount: Option<u64>,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        mailboxes: Vec<String>,
        relay_mode: ContactRelayMode,
        require_proof: bool,
    ) -> Result<Epic1Paid, WalletError> {
        self.run("epic1_pay", |session| async move {
            session
                .epic1_pay(
                    link,
                    amount,
                    minimum_confirmations,
                    message,
                    options,
                    mailboxes,
                    relay_mode,
                    require_proof,
                )
                .await
        })
        .await
    }

    /// The payment proof of the payment `tx_id` to an epic1 address, as the JSON text of a
    /// proof file (media type `application/vnd.lepic.receipt+json`,
    /// `docs/protocols/epic1-receipt.md`), to save or share. `None` when the payment has none:
    /// not a payment to an epic1 address, not answered yet, or answered without one.
    ///
    /// Fails with `InvalidArgument` for a `tx_id` the wallet does not have.
    pub async fn epic1_proof(&self, tx_id: u32) -> Result<Option<String>, WalletError> {
        self.run("epic1_proof", |session| async move {
            session.epic1_proof(tx_id).await
        })
        .await
    }

    /// Checks the payment proof `proof`, the text of a proof file, for the wallet's network,
    /// and with `on_chain` asks the wallet's node whether the payment's kernel is on chain. The
    /// verdict says whether it holds; the facts are what the proof states, to show beside it.
    /// Nothing is stored.
    ///
    /// Fails with `InvalidArgument` for text that is not a payment proof, and as the node
    /// fails when `on_chain` asks it.
    pub async fn epic1_proof_verify(
        &self,
        proof: String,
        on_chain: bool,
    ) -> Result<PaymentProofCheck, WalletError> {
        self.run("epic1_proof_verify", |session| async move {
            session.epic1_proof_verify(&proof, on_chain).await
        })
        .await
    }

    /// The answers this wallet made for payments taken at its delivery mailboxes, each posted
    /// on the relay its payment was read from, and whether it was posted.
    pub async fn epic1_answers(&self) -> Result<Vec<Epic1AnswerView>, WalletError> {
        self.run("epic1_answers", |session| async move {
            session.epic1_answers().await
        })
        .await
    }

    /// After a restore from the phrase: reads, once, on each mailbox of the list, the delivery
    /// mailbox of each account's address and the reply mailboxes of the pending payments.
    /// Payments on mailboxes outside the list are not found, so call
    /// [`EpicWallet::mailbox_set`] first. Returns how many payments were taken and answers
    /// finalized, and the mailboxes that were not read, each with why; a mailbox not read is
    /// no failure.
    ///
    /// Fails with `ContactsOffline` in `Offline` mode and `TransportFailed` when no mailbox
    /// of the list could be read.
    pub async fn epic1_restore(
        &self,
        relay_mode: ContactRelayMode,
    ) -> Result<Epic1Restored, WalletError> {
        self.run("epic1_restore", |session| async move {
            session.epic1_restore(relay_mode).await
        })
        .await
    }

    /// Turns on or off, for the listener `socket`, taking payments sealed to the wallet's epic1
    /// address at its native endpoint. It is off for both sockets until this turns it on:
    /// the listener then answers such a payment as one sealed to a key it does not hold, so
    /// whoever has the wallet's epic1 address cannot tell that the listener is the same
    /// wallet. The setting is kept in the wallet's directory and takes effect when the listener
    /// next starts. Deleting the wallet removes it.
    ///
    /// Fails with `Io` when the setting cannot be written.
    #[frb(sync)]
    pub fn set_epic1_at_listener(
        &self,
        socket: ListenerSocket,
        enabled: bool,
    ) -> Result<(), WalletError> {
        self.boundary().guard("set_epic1_at_listener", || {
            self.session.set_epic1_at_listener(socket, enabled)
        })
    }

    /// Whether the listener `socket` takes payments sealed to the wallet's epic1 address from
    /// its next start, as [`EpicWallet::set_epic1_at_listener`] last saved it.
    #[frb(sync)]
    pub fn epic1_at_listener(&self, socket: ListenerSocket) -> bool {
        self.boundary().guard_or("epic1_at_listener", false, || {
            self.session.epic1_at_listener(socket)
        })
    }

    /// Opens sealed text, `BEGINEPICTX.` or `BEGINEPICSEALED.`, with this wallet's keys and
    /// shows its slate as it arrived, as JSON. Nothing is stored and no contact is refreshed.
    ///
    /// Fails as [`EpicWallet::sealed_open`] does, with `SavedTransaction` for a record another
    /// Epic wallet keeps in its `saved_txs` directory.
    pub async fn epictx_open(&self, text: String) -> Result<EpictxView, WalletError> {
        self.run("epictx_open", |session| async move {
            session.epictx_open(&text).await
        })
        .await
    }
}
