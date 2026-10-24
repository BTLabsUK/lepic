//! Direct transactions over Tor on desktop (ADR 0018): the wallet's own tor publishes its
//! onion, the payment-proof address in onion form, and sends reach other wallets' onions.
//! Both speak the foreign API that `send_http` and the HTTP listener speak.
//!
//! Tor is off until [`EpicWallet::start_tor`]. While it runs, the wallet listens on
//! `127.0.0.1` on a port of its own, separate from [`EpicWallet::start_http_listener`], and
//! tor forwards the onion's port 80 there. Locking or dropping the wallet stops tor, then
//! that listener. On Android the app passes the tor it ships as a native library
//! (`<nativeLibraryDir>/libtor.so`) and calls [`EpicWallet::refresh_tor`] when it comes back
//! to the foreground or the network changes. iOS cannot run a tor binary: there `start_tor`
//! starts nothing and reports `Failed` with [`TorFailureKind::Missing`], then `Stopped`.

use std::sync::Arc;

use flutter_rust_bridge::frb;

use crate::api::error::WalletError;
use crate::api::http::{HttpRefusal, HttpResentTx, HttpSentTx};
use crate::api::types::SendOptions;
use crate::api::wallet::EpicWallet;
use crate::boundary::{end_stream, guard_or};
use crate::frb_generated::StreamSink;

/// A host that is also an onion service presenting the host's TLS certificate: connections to
/// `host:port` through tor dial `onion:onion_port` instead, with TLS for `host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionRoute {
    pub host: String,
    pub port: u16,
    /// `<56 characters>.onion`, as [`validate_onion_address`] reads it.
    pub onion: String,
    pub onion_port: u16,
}

/// Why the wallet's tor is not working. None of them carries a key or the control cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorFailureKind {
    /// No tor binary at the path given to `start_tor`, or none can run: iOS.
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
    /// A send or resend over Tor started to reach the other wallet, after the checks made
    /// before anything is stored passed: for a send, that the wallet can pay the amount and
    /// its fee. Reaching an onion that is not online takes up to about 150 seconds before the
    /// send fails.
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
    /// For `Bootstrapped`, `Publishing` and `Ready`: the port of tor's SOCKS proxy on
    /// `127.0.0.1`, as [`TorStatus::socks_port`].
    pub socks_port: Option<u16>,
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
            socks_port: None,
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
    /// Once tor has bootstrapped: the port of its SOCKS5 proxy, on `127.0.0.1` only. The app
    /// may send its own HTTP through it; see the binding README. It changes when tor restarts.
    pub socks_port: Option<u16>,
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
    /// `Locked` as its error and no event. A call right after a stop or lock waits for the tor
    /// stopped last to be down, as both use the same files; when that takes over 30 seconds,
    /// the stream gets `Failed` with `Start`, then `Stopped`. A tor that an earlier run of the
    /// app left running on the wallet's files, as after the app was killed, is halted first.
    /// The onion is the same on every start. On iOS nothing is started: the stream gets
    /// `Failed` with `Missing`, then `Stopped`.
    pub async fn start_tor(
        &self,
        tor_binary: String,
        lib_dir: Option<String>,
        events: StreamSink<TorEvent>,
    ) {
        let sink = events.clone();
        let started = self
            .run_until_stopped("start_tor", |session| async move {
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

    /// Tells the wallet's tor that the app is back: call it when the app returns to the
    /// foreground and, with `network_changed`, when the device's network changed (Wi-Fi to
    /// mobile data, or back online). Tor leaves its dormant state, and after a network change
    /// it drops every connection, whose routes may be gone, builds new ones and forgets the
    /// onion services that failed while the network was gone: sends over Tor in progress then
    /// fail, and the onion stays this wallet's and is republished by tor
    /// itself, so `Ready` is not reported again. A bootstrap in progress gets its full time
    /// again. Returns once tor has taken the commands, in at most about 15 seconds.
    ///
    /// Fails with `Locked` while the wallet is locked and with `TorNotRunning` when no tor
    /// runs: start it with [`EpicWallet::start_tor`]. A tor that does not answer is ended:
    /// the call fails with `TorNotRunning` and the stream of `start_tor` gets `Failed` with
    /// `Stopped` (or `Start` before the bootstrap), then `Stopped`. While tor is still being
    /// started there is nothing to refresh and the call succeeds.
    pub async fn refresh_tor(&self, network_changed: bool) -> Result<(), WalletError> {
        self.run("refresh_tor", |session| async move {
            session.refresh_tor(network_changed).await
        })
        .await
    }

    /// Tells the wallet's tor that the device has no network: call it when the device's
    /// network goes (airplane mode, no signal). Tor turns its network off at once and makes no
    /// connection attempt until the next [`EpicWallet::refresh_tor`], which turns it on again
    /// whatever its `network_changed`; attempts made without a network would mark the relays
    /// tor enters the Tor network through as unreachable, and slow its return for minutes.
    /// Sends over Tor in progress fail. Does nothing when no tor runs, while the wallet is
    /// locked, or while tor is still being started (a network turned off would stall it).
    ///
    /// A tor that does not answer is ended, as by [`EpicWallet::refresh_tor`]: the call fails
    /// with `TorNotRunning`.
    pub async fn tor_network_lost(&self) -> Result<(), WalletError> {
        self.run("tor_network_lost", |session| async move {
            session.tor_network_lost().await
        })
        .await
    }

    /// Turns Epicbox over Tor on or off (ADR 0021); it is on when the wallet opens. While it is
    /// on and the wallet's tor runs, the connection to the wallet's Epicbox relay goes through
    /// tor: to the relay's onion when one is known, else to its domain through the Tor network.
    /// It then never goes directly: it waits for tor to connect while it starts, and for the
    /// app to start it again when it ended on its own. With tor stopped by
    /// [`EpicWallet::stop_tor`] or `lock`, or the setting off, the relay is reached directly.
    /// Addresses do not change. A listener
    /// connection that would now go another way is replaced as soon as the messages in flight
    /// on it are acknowledged, within 30 seconds; messages not acknowledged by then stay with
    /// the relay and come again. A send in progress finishes on its own connection.
    #[frb(sync)]
    pub fn set_epicbox_over_tor(&self, enabled: bool) {
        self.boundary().guard_or("set_epicbox_over_tor", (), || {
            self.session.set_epicbox_over_tor(enabled);
        });
    }

    /// Says that [`EpicWallet::start_tor`] follows, so that a relay connection made before it,
    /// such as the listener's when the wallet opens, waits for tor instead of going directly.
    /// Call it before [`EpicWallet::start_listener`] when tor is about to start and Epicbox over
    /// Tor is on. Until `start_tor`, relay connections wait. To restart tor, call it before
    /// [`EpicWallet::stop_tor`]: that stop keeps the relay connection waiting for the
    /// `start_tor` that follows. A further `stop_tor`, or `lock`, ends the wait. Nothing on iOS.
    ///
    /// Fails with `Locked` while the wallet is locked.
    /// Turns the node client over Tor on or off; it is on when the wallet opens. While it is
    /// on and the wallet's tor runs or is expected (see [`EpicWallet::expect_tor`]), every
    /// request to the node goes through tor: to the node's onion when one is known, else to
    /// its domain, which tor resolves, through the Tor network. The system resolver is not
    /// used and nothing goes directly; while tor starts, requests wait for it, within their
    /// timeouts, and fail with `NodeUnreachable` if it does not connect. The node's TLS
    /// certificate is checked for its domain either way. With tor stopped by
    /// [`EpicWallet::stop_tor`] or `lock`, or the setting off, the node is reached directly.
    /// A request in progress finishes on its own connection.
    #[frb(sync)]
    pub fn set_node_over_tor(&self, enabled: bool) {
        self.boundary().guard_or("set_node_over_tor", (), || {
            self.session.set_node_over_tor(enabled);
        });
    }

    /// Whether the node client over Tor is on, as [`EpicWallet::set_node_over_tor`] set it.
    #[frb(sync)]
    pub fn node_over_tor(&self) -> bool {
        self.boundary()
            .guard_or("node_over_tor", true, || self.session.node_over_tor())
    }

    #[frb(sync)]
    pub fn expect_tor(&self) -> Result<(), WalletError> {
        self.boundary()
            .guard("expect_tor", || self.session.expect_tor())
    }

    /// Replaces the onion routes the wallet uses through tor, for example with the signed list
    /// the app fetched; until then a built-in table holds `flooepicbox.btlabs.uk:443` and
    /// `node.btlabs.uk:443`, for the relay and for the node client. Only TLS
    /// hosts belong here: the connection still checks `host`'s certificate. Applies from the
    /// next connection. An empty list leaves no route, so every host goes through a Tor exit.
    ///
    /// Fails with `InvalidArgument`, changing nothing, when a host is not a host name, an onion
    /// is not an onion v3 address, a port is 0, or there are more than 256 routes.
    #[frb(sync)]
    pub fn set_onion_routes(&self, routes: Vec<OnionRoute>) -> Result<(), WalletError> {
        self.boundary()
            .guard("set_onion_routes", || self.session.set_onion_routes(routes))
    }

    /// Whether Epicbox over Tor is on, as [`EpicWallet::set_epicbox_over_tor`] set it.
    #[frb(sync)]
    pub fn epicbox_over_tor(&self) -> bool {
        self.boundary()
            .guard_or("epicbox_over_tor", true, || self.session.epicbox_over_tor())
    }

    #[frb(sync)]
    pub fn tor_status(&self) -> TorStatus {
        self.boundary().guard_or(
            "tor_status",
            TorStatus {
                kind: TorStatusKind::Off,
                progress: None,
                onion: None,
                socks_port: None,
                failure: None,
            },
            || self.session.tor_status(),
        )
    }

    /// Sends `amount` to the wallet at `onion` over the wallet's tor, then finalizes its
    /// answer and posts the transaction, as [`EpicWallet::send_http`] does. `onion` is read as
    /// [`validate_onion_address`] reads it; the other wallet is always reached at port 80.
    /// Emits `Sending` on the tor stream once the wallet has checked it can pay; an onion that
    /// is not online takes up to about 150 seconds to fail.
    ///
    /// Fails, storing nothing, with `OnionAddressInvalid` for the address, `TorNotRunning`
    /// when tor has not bootstrapped, and the errors of [`EpicWallet::estimate_fee`]. Fails
    /// with `OnionUnreachable` when the other wallet is not online or could not be reached in
    /// time, and with `TransportFailed` when it refused or the exchange broke: the send is then
    /// stored as sent with its inputs locked, so deliver it again with
    /// [`EpicWallet::resend_tor`] or [`EpicWallet::resend_http`], or cancel it. A tor that
    /// stops during the send fails it the same way with `TorNotRunning`. Fails as
    /// [`EpicWallet::send_http`] does when the answer could not be finalized.
    ///
    /// `options` chooses the inputs and change, `Smallest` with one change output when `None`;
    /// change outputs outside 1..=10 fail with `InvalidArgument`.
    pub async fn send_tor(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        onion: String,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<HttpSentTx, WalletError> {
        self.run("send_tor", |session| async move {
            session
                .send_tor(amount, minimum_confirmations, &onion, message, options)
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
