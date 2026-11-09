//! Payments to epic1 links (EPICTX), from anyone, with no pairing.
//!
//! The payee shows its epic1 address, [`EpicWallet::epic1_address`], or a link to it from
//! [`EpicWallet::epic1_link_make`]: `epic:epic1…?epicbox=…`, which names a mailbox of this
//! wallet on one to three relays. An on-screen link takes the next of 50 mailboxes; a printed
//! one keeps one of 32 until [`EpicWallet::epic1_link_retire`] frees it.
//!
//! The payer reads the link with [`EpicWallet::epic1_link_read`] to show the address, what it
//! asks and its relays, then pays it with [`EpicWallet::epic1_pay`] once the user confirmed
//! them. The payment is sealed anonymously to the address and posted to the link's first
//! relay, and to the next when a post fails; [`EpicWallet::epic1_post_next`] tries the rest.
//!
//! [`EpicWallet::contacts_collect`] does the rest on both sides and counts it in `epic1`: the
//! payee takes payments from its link mailboxes and answers each, and the payer takes the
//! answer from its reply mailbox and finalizes it. A payee that cannot post an answer lists it
//! with [`EpicWallet::epic1_answers`] and posts it with [`EpicWallet::epic1_post_answer`]
//! once the user confirmed the payer's relay. After a restore from the phrase,
//! [`EpicWallet::epic1_restore`] drains every link mailbox once.
//!
//! Links and payments belong to the default account. Calls that take a [`ContactRelayMode`]
//! reach relays as the contact calls do and fail with `ContactsOffline` or `EpicboxOff` before
//! connecting when the mode does not allow it, and with `Unsupported` when the configuration
//! names no Epicbox relay. Every call fails with `Locked` on a locked wallet.

use crate::api::error::WalletError;
use crate::api::types::{
    ContactRelayMode, Epic1AnswerView, Epic1Link, Epic1LinkKind, Epic1LinkRead, Epic1LinkView,
    Epic1Paid, EpictxView, SendOptions, SlateWire,
};
use crate::api::wallet::EpicWallet;

impl EpicWallet {
    /// The epic1 address of the default account: its seal key and its epic1 proof key on the
    /// wallet's network.
    pub async fn epic1_address(&self) -> Result<String, WalletError> {
        self.run(
            "epic1_address",
            |session| async move { session.epic1_address() },
        )
        .await
    }

    /// Issues a link to the wallet's epic1 address, asking `amount` atomic units or, with
    /// `None`, any amount the payer chooses. The link names its mailbox on each of `relays`,
    /// `domain[:port]`, at most three, or on the wallet's own relay when `relays` is empty. It
    /// has no expiry. Collecting drains an on-screen link's mailbox for seven days after it was
    /// issued or last used, and a printed link's until it is retired.
    ///
    /// Fails with `InvalidArgument` for a zero amount, `PrintedLinksFull` when all 32 printed
    /// links are in use, `Epic1RelayInvalid` for more than three relays or one that is not a
    /// domain with an optional port or is on this device, `OwnRelayLocal` when the wallet's own
    /// relay is on this device, and `Epic1MessageInvalid` for a message longer than a link
    /// carries or with control characters.
    pub async fn epic1_link_make(
        &self,
        amount: Option<u64>,
        message: Option<String>,
        kind: Epic1LinkKind,
        relays: Vec<String>,
        relay_mode: ContactRelayMode,
    ) -> Result<Epic1Link, WalletError> {
        self.run("epic1_link_make", |session| async move {
            session
                .epic1_link_make(amount, message, kind, relays, relay_mode)
                .await
        })
        .await
    }

    /// The link mailboxes of the default account in use, by kind and number.
    pub async fn epic1_links(&self) -> Result<Vec<Epic1LinkView>, WalletError> {
        self.run("epic1_links", |session| async move {
            session.epic1_links().await
        })
        .await
    }

    /// Frees the printed link `n`: its mailbox is no longer drained and the next printed link
    /// may take it. Fails with `Epic1NotFound` when no printed link `n` is in use.
    pub async fn epic1_link_retire(&self, n: u32) -> Result<(), WalletError> {
        self.run("epic1_link_retire", |session| async move {
            session.epic1_link_retire(n).await
        })
        .await
    }

    /// Reads an epic1 link: the address it pays, what it asks, and the relays a payment would
    /// be posted to, to show before the user pays. Nothing is stored.
    ///
    /// Fails with `NotAnEpic1Link` for text that is not one, `Epic1WrongNetwork` for a link of
    /// the other network, and `Epic1CannotPay` when it names no relay this wallet can use.
    pub async fn epic1_link_read(
        &self,
        link: String,
        relay_mode: ContactRelayMode,
    ) -> Result<Epic1LinkRead, WalletError> {
        self.run("epic1_link_read", |session| async move {
            session.epic1_link_read(&link, relay_mode)
        })
        .await
    }

    /// Pays an epic1 link `amount` atomic units, or with `None` the amount the link asks. With
    /// `proof` the payee is asked for a payment proof signed with the address's epic1 proof
    /// key. The payment names a reply mailbox on the wallet's own relay, is stored, then posted
    /// to the link's first relay, and to the next when a post fails, at most three.
    /// `hosts_ok` says the user confirmed every relay [`EpicWallet::epic1_link_read`] showed.
    /// Collecting takes the answer and finalizes it.
    ///
    /// Fails as [`EpicWallet::epic1_link_read`] does, with `InvalidArgument` for a zero amount
    /// or none when the link asks none, `RelayNotConfirmed` when `hosts_ok` is false,
    /// `OwnRelayLocal` when the wallet's own relay is on this device, and as `send` fails.
    #[allow(clippy::too_many_arguments)] // The app's send form, one value per field.
    pub async fn epic1_pay(
        &self,
        link: String,
        amount: Option<u64>,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        proof: bool,
        hosts_ok: bool,
        relay_mode: ContactRelayMode,
    ) -> Result<Epic1Paid, WalletError> {
        self.run("epic1_pay", |session| async move {
            session
                .epic1_pay(
                    link,
                    amount,
                    minimum_confirmations,
                    message,
                    options,
                    proof,
                    hosts_ok,
                    relay_mode,
                )
                .await
        })
        .await
    }

    /// Posts the stored payment `slate_id` again, the same bytes, to the relays of its link
    /// after the one it was last posted to. `hosts_ok` says the user confirmed them.
    ///
    /// Fails with `RelayNotConfirmed` when `hosts_ok` is false, `Epic1NotFound` when no
    /// payment is stored, `Epic1Finalized` once it was finalized, and `Epic1NoMoreRelays` when
    /// every relay was tried.
    pub async fn epic1_post_next(
        &self,
        slate_id: String,
        hosts_ok: bool,
        relay_mode: ContactRelayMode,
    ) -> Result<Epic1Paid, WalletError> {
        self.run("epic1_post_next", |session| async move {
            session
                .epic1_post_next(&slate_id, hosts_ok, relay_mode)
                .await
        })
        .await
    }

    /// The answers this wallet made for payments taken at its link mailboxes, with the relay
    /// each goes to and whether it was posted.
    pub async fn epic1_answers(
        &self,
        relay_mode: ContactRelayMode,
    ) -> Result<Vec<Epic1AnswerView>, WalletError> {
        self.run("epic1_answers", |session| async move {
            session.epic1_answers(relay_mode).await
        })
        .await
    }

    /// Posts the answer for the payment `slate_id` to the reply mailbox the payer named.
    /// `relay_ok` says the user confirmed the relay [`EpicWallet::epic1_answers`] showed.
    /// Posting again is safe.
    ///
    /// Fails with `RelayNotConfirmed` when `relay_ok` is false, `Epic1NotFound` when no answer
    /// is stored, and `TransportFailed` when the post failed.
    ///
    /// Returns the format the answer went out in, always `Native`.
    pub async fn epic1_post_answer(
        &self,
        slate_id: String,
        relay_ok: bool,
        relay_mode: ContactRelayMode,
    ) -> Result<SlateWire, WalletError> {
        self.run("epic1_post_answer", |session| async move {
            session
                .epic1_post_answer(&slate_id, relay_ok, relay_mode)
                .await
        })
        .await
    }

    /// After a restore from the phrase: drains, once, all 50 on-screen and all 32 printed link
    /// mailboxes on the wallet's own relay, and the reply mailboxes of the pending payments.
    /// A link mailbox that held a payment is marked in use; links named on other relays are not
    /// found. Returns how many payments were taken and answers finalized.
    ///
    /// Fails with `TransportFailed` when a drain failed.
    pub async fn epic1_restore(&self, relay_mode: ContactRelayMode) -> Result<u32, WalletError> {
        self.run("epic1_restore", |session| async move {
            session.epic1_restore(relay_mode).await
        })
        .await
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
