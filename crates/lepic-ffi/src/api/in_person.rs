//! In-person invoices and sends (EPICTX), between two phones side by side, with no pairing.
//!
//! One side shows a code: [`EpicWallet::in_person_invoice`] for an invoice to be paid,
//! [`EpicWallet::in_person_send`] for coins to be received. Its `bytes` are a raw `lepic.v1`
//! slate, shown as one byte-mode QR code or as the parts [`in_person_qr_parts`] gives. The other
//! side scans it, reads it with [`EpicWallet::in_person_read`] to show the amount, the fee, the
//! message and the reply mailbox, and answers with [`EpicWallet::in_person_pay`] or
//! [`EpicWallet::in_person_receive`]. The answer is sealed to the code's reply key; it is posted
//! with [`EpicWallet::in_person_post`] to the reply mailbox the code names, or shown back as a
//! QR code or as its `BEGINEPICTX.` text. The answering side shows its check code only after
//! posting: `in_person_post` returns it.
//!
//! The showing side takes answers from its reply mailbox with [`EpicWallet::contacts_collect`],
//! which raises `InPersonAnswer` for each, or from a scan with [`EpicWallet::in_person_take`]
//! and [`EpicWallet::in_person_take_qr`]; [`EpicWallet::in_person_answers`] lists them. Each
//! answer has a four-digit check code that both screens show. Nothing is finalized when an
//! answer arrives: the user picks the answer whose check code the other screen shows, and the
//! app calls [`EpicWallet::in_person_finalize`] with its number.
//!
//! Codes and answers belong to the default account. Calls that take a [`ContactRelayMode`]
//! reach relays as the contact calls do: the wallet's Epicbox relay names the reply mailbox,
//! and with `Offline` or `EpicboxOff` a code names none and posting fails before connecting.
//! They fail with `Unsupported` when the configuration names no Epicbox relay. Every call fails
//! with `Locked` on a locked wallet, `InvalidSlate` for a code or answer that is not one of this
//! network or is over 128 KiB, and `InvalidArgument` for a slate id that is not one.

use flutter_rust_bridge::frb;

use crate::api::error::WalletError;
use crate::api::types::{
    ContactRelayMode, FinalizedTx, InPersonCode, InPersonCodeView, InPersonPosted,
    InPersonQrProgress, InPersonRead, InPersonReply, InPersonTaken, SendOptions,
};
use crate::api::wallet::EpicWallet;
use crate::boundary::guard;
use crate::ur_slate;

/// The parts of an animated QR code for the `bytes` of an in-person code or the `envelope` of
/// an answer, to show in a loop, in order. A payload (the bytes and up to 7 bytes of framing)
/// of at most `single_code_max_len` bytes, 0 to 1024, is one single-part code; a
/// longer one is split into parts that each carry at most `max_fragment_len` bytes, 16 to 1024.
/// Without `single_code_max_len` the limit is 360. Which to pass is the caller's display
/// choice: smaller values give smaller codes and more of them. Fails with `InvalidSlate` for
/// bytes that are neither, `InvalidArgument` for a length outside its limits, and
/// `UrCodeTooLarge` for more than 67,648 bytes or 256 fragments.
#[frb(sync)]
pub fn in_person_qr_parts(
    bytes: Vec<u8>,
    max_fragment_len: u32,
    single_code_max_len: Option<u32>,
) -> Result<Vec<String>, WalletError> {
    guard("in_person_qr_parts", || {
        ur_slate::encode_binary(&bytes, max_fragment_len, single_code_max_len)
    })
}

/// Reads the distinct QR texts of an in-person code or answer scanned so far, in any order and
/// case; pass all of them on each call. Holds no state. Once `complete`, `bytes` go to
/// [`EpicWallet::in_person_read`] or [`EpicWallet::in_person_take`]. Fails as
/// `decode_ur_slate` does, and with `InvalidSlate` for parts of a slate text code or bytes
/// that are neither a code nor an answer.
#[frb(sync)]
pub fn in_person_qr_read(parts: Vec<String>) -> Result<InPersonQrProgress, WalletError> {
    guard("in_person_qr_read", move || ur_slate::decode_binary(&parts))
}

impl EpicWallet {
    /// Makes an in-person invoice for `amount` atomic units, with no payment proof, good for
    /// `ttl_blocks` blocks past the chain tip. The app chooses the TTL: LEPIC uses 30 when
    /// `None` and refuses one of 10 or fewer with `InvalidArgument`, as the payer stops paying
    /// 10 blocks before the cutoff. With `Online` the code names a reply mailbox on the wallet's relay, which [`EpicWallet::contacts_collect`] then
    /// watches until the code expires. The invoice and the code are stored.
    ///
    /// Fails with `InvalidArgument` for a zero amount or a TTL of 10 blocks or fewer, and as
    /// `issue_invoice` fails.
    pub async fn in_person_invoice(
        &self,
        amount: u64,
        message: Option<String>,
        ttl_blocks: Option<u64>,
        relay_mode: ContactRelayMode,
    ) -> Result<InPersonCode, WalletError> {
        self.run("in_person_invoice", |session| async move {
            session
                .in_person_invoice(amount, message, ttl_blocks, relay_mode)
                .await
        })
        .await
    }

    /// Makes an in-person send of `amount` atomic units, as [`EpicWallet::in_person_invoice`]
    /// makes an invoice, selecting outputs as `send` does. The send is stored and its inputs
    /// stay locked until an answer is finalized, the code expires or the send is cancelled.
    /// `ttl_blocks` is as for `in_person_invoice`: the app chooses it, LEPIC uses 30 when `None`
    /// and refuses one of 10 or fewer.
    ///
    /// Fails with `InvalidArgument` for a zero amount or a TTL of 10 blocks or fewer, and as
    /// `send` fails before it delivers.
    pub async fn in_person_send(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        ttl_blocks: Option<u64>,
        relay_mode: ContactRelayMode,
    ) -> Result<InPersonCode, WalletError> {
        self.run("in_person_send", |session| async move {
            session
                .in_person_send(
                    amount,
                    minimum_confirmations,
                    message,
                    options,
                    ttl_blocks,
                    relay_mode,
                )
                .await
        })
        .await
    }

    /// Reads a scanned code: raw `lepic.v1` bytes, from a byte-mode QR code or from
    /// [`in_person_qr_read`]. Nothing is stored. The fee of an invoice is estimated with the
    /// selection paying it would use. A code with a payment proof, without a reply key or a
    /// TTL, or whose reply mailbox is a loopback or unspecified host, is refused.
    ///
    /// Fails with `InvalidSlate` for a code that is not one or is refused.
    pub async fn in_person_read(
        &self,
        code: Vec<u8>,
        minimum_confirmations: u64,
        options: Option<SendOptions>,
        relay_mode: ContactRelayMode,
    ) -> Result<InPersonRead, WalletError> {
        self.run("in_person_read", |session| async move {
            session
                .in_person_read(code, minimum_confirmations, options, relay_mode)
                .await
        })
        .await
    }

    /// Pays a scanned in-person invoice of `amount`, the amount [`EpicWallet::in_person_read`]
    /// showed, as `pay_invoice` pays one, and seals the answer to the code. The payment and
    /// the answer are stored; the inputs stay locked until the code expires or the payment is
    /// cancelled. Post the answer with [`EpicWallet::in_person_post`], which returns the check
    /// code to show, or show the answer back.
    ///
    /// Fails as [`EpicWallet::in_person_read`] does, with `InvalidArgument` for a zero amount,
    /// and as `pay_invoice` fails.
    #[allow(clippy::too_many_arguments)] // The app's pay form, one value per field.
    pub async fn in_person_pay(
        &self,
        code: Vec<u8>,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
        relay_mode: ContactRelayMode,
    ) -> Result<InPersonReply, WalletError> {
        self.run("in_person_pay", |session| async move {
            session
                .in_person_pay(
                    code,
                    amount,
                    minimum_confirmations,
                    message,
                    options,
                    relay_mode,
                )
                .await
        })
        .await
    }

    /// Receives a scanned in-person send as `receive` receives a slate, and seals the answer to
    /// the code. The transaction and the answer are stored. Post the answer with
    /// [`EpicWallet::in_person_post`], which returns the check code to show, or show the answer
    /// back.
    ///
    /// Fails as [`EpicWallet::in_person_read`] does, and as `receive` fails.
    pub async fn in_person_receive(
        &self,
        code: Vec<u8>,
        message: Option<String>,
        relay_mode: ContactRelayMode,
    ) -> Result<InPersonReply, WalletError> {
        self.run("in_person_receive", |session| async move {
            session.in_person_receive(code, message, relay_mode).await
        })
        .await
    }

    /// Posts the stored answer for the slate `slate_id` to the reply mailbox its code named,
    /// from a key used for this slate only, through the wallet's connection to relays (over
    /// Tor when Epicbox over Tor is on). `relay_ok` says the user confirmed the mailbox
    /// [`EpicWallet::in_person_read`] reported. Posting again is safe.
    ///
    /// Fails with `RelayNotConfirmed` when `relay_ok` is false, `InPersonNotFound` when no
    /// answer is stored for the slate, `InPersonNoMailbox` when its code named no mailbox,
    /// `ContactsOffline` or `EpicboxOff` before connecting, and `TransportFailed` when the
    /// post failed.
    ///
    /// Returns the answer's check code, to show the user now and not before, and the format
    /// the answer went out in, always `Native`.
    pub async fn in_person_post(
        &self,
        slate_id: String,
        relay_ok: bool,
        relay_mode: ContactRelayMode,
    ) -> Result<InPersonPosted, WalletError> {
        self.run("in_person_post", |session| async move {
            session
                .in_person_post(&slate_id, relay_ok, relay_mode)
                .await
        })
        .await
    }

    /// Takes an answer to a code this wallet showed, scanned or pasted: the envelope's bytes,
    /// or its `BEGINEPICTX.` text as UTF-8. It is checked and stored as a collected answer is,
    /// and nothing is finalized.
    ///
    /// Fails with `InvalidSlate` for input that is not such an answer, `SealedForAnotherWallet`
    /// when it answers no open code of this wallet, and as the answer fails to check.
    pub async fn in_person_take(&self, answer: Vec<u8>) -> Result<InPersonTaken, WalletError> {
        self.run("in_person_take", |session| async move {
            session.in_person_take(answer).await
        })
        .await
    }

    /// As [`EpicWallet::in_person_take`], for the parts of an animated QR code scanned so far.
    ///
    /// Fails as [`in_person_qr_read`] does, with `UrCodeIncomplete` while parts are missing,
    /// and with `InvalidSlate` when the parts hold a code rather than an answer.
    pub async fn in_person_take_qr(
        &self,
        parts: Vec<String>,
    ) -> Result<InPersonTaken, WalletError> {
        self.run("in_person_take_qr", |session| async move {
            session.in_person_take_qr(parts).await
        })
        .await
    }

    /// The code this wallet showed for the slate `slate_id`, with the answers taken for it and
    /// their check codes. Reads only the store.
    ///
    /// Fails with `InPersonNotFound` when the wallet holds no such code.
    pub async fn in_person_answers(
        &self,
        slate_id: String,
    ) -> Result<InPersonCodeView, WalletError> {
        self.run("in_person_answers", |session| async move {
            session.in_person_answers(&slate_id).await
        })
        .await
    }

    /// Finalizes the answer numbered `answer` to the code for the slate `slate_id`, the one the
    /// user picked by its check code, and posts it to the node, as finalizing an invoice does.
    /// The code then takes no more answers.
    ///
    /// Fails with `InPersonNotFound` when there is no such code or answer, and as finalizing
    /// fails.
    pub async fn in_person_finalize(
        &self,
        slate_id: String,
        answer: u32,
    ) -> Result<FinalizedTx, WalletError> {
        self.run("in_person_finalize", |session| async move {
            session.in_person_finalize(&slate_id, answer).await
        })
        .await
    }
}
