//! Direct transactions over Tor on desktop (ADR 0018): the wallet's own tor publishes its
//! onion, the payment-proof address in onion form, and sends reach other wallets' onions.
//! Both speak the foreign API that `send_http` and the HTTP listener speak.
//!
//! Tor is off until [`EpicWallet::start_tor`]. While it runs, the wallet listens on
//! `127.0.0.1` on a port of its own, separate from [`EpicWallet::start_http_listener`], and
//! tor forwards the onion's port 80 there. Locking or dropping the wallet stops tor, then
//! that listener. Android and iOS cannot run the bundled tor binary.

use std::sync::Arc;

use flutter_rust_bridge::frb;

use crate::api::error::WalletError;
use crate::api::http::{HttpRefusal, HttpResentTx, HttpSentTx};
use crate::api::wallet::EpicWallet;
use crate::boundary::{end_stream, guard_or};
use crate::frb_generated::StreamSink;

/// Why the wallet's tor is not working. None of them carries a key or the control cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorFailureKind {
    /// No tor binary at the path given to `start_tor`.
    Missing,
    /// Tor did not start, or its control port did not answer as expected.
    Start,
    /// Tor made no bootstrap progress for a while, or did not finish in time: no network, or
    /// the network blocks Tor.
    Network,
    /// Tor reported the computer's clock as wrong.
    Clock,
    /// The wallet's listener did not start or does not answer, so the onion would lead
    /// nowhere.
    Listener,
    /// Tor exited after it had bootstrapped.
    Stopped,
    /// The onion was added, but its descriptor was not uploaded in time.
    Publish,
    /// Tor refused the onion key or published another onion than the wallet's.
    Keys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorEventKind {
    /// Tor is starting and connecting to the Tor network, `progress` percent done.
    Starting,
    /// Connected to the Tor network: sends to onions work from now on.
    Bootstrapped,
    /// The onion is being published.
    Publishing,
    /// Other wallets can reach this one at `onion`.
    Ready,
    /// Tor failed for the reason in `failure`. After `Listener` or `Keys` tor keeps running for
    /// sends, and the status stays `Bootstrapped`; after any other reason `Stopped` follows.
    Failed,
    /// A send or resend over Tor started to reach the other wallet. Reaching an onion that is
    /// not online takes up to about 150 seconds before the send fails.
    Sending,
    /// Signed a payment that came in over Tor and answered it, as the HTTP listener's
    /// `Received`: `tx_id`, `amount`, `repeated`.
    Received,
    /// Refused a payment that came in over Tor for the reason in `refusal`.
    Refused,
    /// Tor and its listener stopped; no more events follow.
    Stopped,
}

/// What the wallet's tor did. Nothing about a sender, the slate or a key is reported.
#[derive(Debug, Clone)]
pub struct TorEvent {
    pub kind: TorEventKind,
    /// For `Starting`, 0 to 100.
    pub progress: Option<u8>,
    /// For `Ready`: `<56 characters>.onion`.
    pub onion: Option<String>,
    /// For `Failed`.
    pub failure: Option<TorFailureKind>,
    /// For `Received`.
    pub tx_id: Option<u32>,
    /// For `Received`.
    pub amount: Option<u64>,
    /// For `Received`.
    pub repeated: bool,
    /// For `Refused`.
    pub refusal: Option<HttpRefusal>,
}

impl TorEvent {
    pub(crate) const fn of(kind: TorEventKind) -> Self {
        Self {
            kind,
            progress: None,
            onion: None,
            failure: None,
            tx_id: None,
            amount: None,
            repeated: false,
            refusal: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorStatusKind {
    /// Not started, stopped, or ended after a failure.
    Off,
    Starting,
    /// Sends work; the onion is not published, or could not be (see `failure`).
    Bootstrapped,
    Publishing,
    /// Sends work and other wallets can reach this one at `onion`.
    Ready,
}

/// The wallet's tor now.
#[derive(Debug, Clone)]
pub struct TorStatus {
    pub kind: TorStatusKind,
    /// For `Starting`, 0 to 100.
    pub progress: Option<u8>,
    /// For `Ready`.
    pub onion: Option<String>,
    /// Why the onion was not published while tor runs for sends: `Listener` or `Keys`.
    pub failure: Option<TorFailureKind>,
}

/// Whether `address` is an onion v3 address: 56 characters, with or without `.onion`, an
/// `http://` prefix, a port or a path, whose version and checksum hold.
#[frb(sync)]
pub fn validate_onion_address(address: String) -> bool {
    guard_or("validate_onion_address", false, || {
        lepic_tor::parse_onion(&address).is_ok()
    })
}

impl EpicWallet {
    /// The wallet's onion address, `<56 characters>.onion`: its payment-proof address in onion
    /// form, which `epic-wallet address` prints too. It is known without tor running and stays
    /// the same after a restore from the phrase.
    ///
    /// Fails with `Locked` while the wallet is locked.
    pub async fn onion_address(&self) -> Result<String, WalletError> {
        self.run(
            "onion_address",
            |session| async move { session.onion_address() },
        )
        .await
    }

    /// Starts the wallet's tor from the binary at `tor_binary`, with `lib_dir` on the library
    /// path for the libraries the Tor Expert Bundle ships on Linux, and streams what it does
    /// until [`EpicWallet::stop_tor`], [`EpicWallet::lock`] or the wallet is dropped. Tor keeps
    /// its files in `tor` inside the wallet's data directory.
    ///
    /// The first event is `Starting`, or `Failed` with `Listener` when the wallet's listener
    /// could not start; the last one is always `Stopped`. A wallet runs one tor: a call while one
    /// runs or starts gets a stream that ends at once. On a locked wallet the stream ends with
    /// `Locked` as its error and no event.
    pub async fn start_tor(
        &self,
        tor_binary: String,
        lib_dir: Option<String>,
        events: StreamSink<TorEvent>,
    ) {
        let sink = events.clone();
        let started = self
            .run("start_tor", |session| async move {
                // A closed stream only means the app stopped listening.
                let report = Arc::new(move |event| drop(sink.add(event)));
                session.start_tor(tor_binary, lib_dir, report).await
            })
            .await;
        end_stream(&events, started);
    }

    /// Stops the wallet's tor, then its listener. The stream of `start_tor` ends with
    /// `Stopped` once both are down. Sends over Tor in progress fail.
    #[frb(sync)]
    pub fn stop_tor(&self) {
        self.boundary()
            .guard_or("stop_tor", (), || self.session.stop_tor());
    }

    #[frb(sync)]
    pub fn tor_status(&self) -> TorStatus {
        self.boundary().guard_or(
            "tor_status",
            TorStatus {
                kind: TorStatusKind::Off,
                progress: None,
                onion: None,
                failure: None,
            },
            || self.session.tor_status(),
        )
    }

    /// Sends `amount` to the wallet at `onion` over the wallet's tor, then finalizes its
    /// answer and posts the transaction, as [`EpicWallet::send_http`] does. `onion` is read as
    /// [`validate_onion_address`] reads it; the other wallet is always reached at port 80.
    /// Emits `Sending` on the tor stream; an onion that is not online takes up to about 150
    /// seconds to fail.
    ///
    /// Fails, storing nothing, with `OnionAddressInvalid` for the address, `TorNotRunning`
    /// when tor has not bootstrapped, and the errors of [`EpicWallet::estimate_fee`]. Fails
    /// with `OnionUnreachable` when the other wallet is not online or could not be reached in
    /// time, and with `TransportFailed` when it refused or the exchange broke: the send is then
    /// stored as sent with its inputs locked, so deliver it again with
    /// [`EpicWallet::resend_tor`] or [`EpicWallet::resend_http`], or cancel it. A tor that
    /// stops during the send fails it the same way with `TorNotRunning`. Fails as
    /// [`EpicWallet::send_http`] does when the answer could not be finalized.
    pub async fn send_tor(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        onion: String,
        message: Option<String>,
    ) -> Result<HttpSentTx, WalletError> {
        self.run("send_tor", |session| async move {
            session
                .send_tor(amount, minimum_confirmations, &onion, message)
                .await
        })
        .await
    }

    /// Delivers the slate of send `tx_id` again, to the wallet at `onion`, which may be
    /// another address or method than the first attempt, then finalizes and posts as
    /// [`EpicWallet::send_tor`] does.
    ///
    /// Fails with `OnionAddressInvalid` or `TorNotRunning` before anything is sent,
    /// `InvalidArgument` when `tx_id` is not a send waiting for its answer, and otherwise as
    /// [`EpicWallet::send_tor`].
    pub async fn resend_tor(&self, tx_id: u32, onion: String) -> Result<HttpResentTx, WalletError> {
        self.run("resend_tor", |session| async move {
            session.resend_tor(tx_id, &onion).await
        })
        .await
    }
}
