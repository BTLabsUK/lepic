//! Direct transactions over HTTP (ADR 0017): a send to a wallet listening at an
//! `http(s)://` address gets its answer in the same exchange and is finalized and posted at
//! once, and the wallet's own listener answers payments sent to it the same way. Both speak
//! the foreign API of `epic-wallet` `send -m http` and `listen -m http`.
//!
//! The listener answers payments only; invoices are not served over HTTP. It never starts by
//! itself, and it stops when the wallet is locked or dropped.

use std::sync::Arc;

use flutter_rust_bridge::frb;

use crate::api::error::WalletError;
use crate::api::types::SendOptions;
use crate::api::wallet::EpicWallet;
use crate::boundary::end_stream;
use crate::frb_generated::StreamSink;

/// Who can reach the HTTP listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpExposure {
    /// This device only, on `127.0.0.1`.
    LocalOnly,
    /// Every network interface, on `0.0.0.0`, for a port the user forwards from the internet.
    /// Anyone who can reach the port can send this wallet payments.
    Internet,
}

/// A running HTTP listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpListenerInfo {
    /// The port it listens on; the one the system picked when it was started with port 0.
    pub port: u16,
    pub exposure: HttpExposure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpListenerEventKind {
    /// Listening on `port` with `exposure`.
    Started,
    /// Another program holds `port`. The listener did not start; no more events follow.
    PortInUse,
    /// `port` could not be listened on, for example a port below 1024 without the right to
    /// it. The listener did not start; no more events follow.
    BindFailed,
    /// Signed a payment and answered it: `tx_id`, `amount`, and `repeated` when the same
    /// payment came again and was answered with the reply stored the first time, which is not
    /// a second payment.
    Received,
    /// Refused a payment for the reason in `refusal`. Nothing was stored.
    Refused,
    /// The listener stopped and its port is free; no more events follow.
    Stopped,
}

/// Why the listener refused a payment. The sender's wallet is told only this much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRefusal {
    /// The slate was checked and refused for good.
    Rejected,
    /// The wallet could not take it now, for example while it is locked, its node cannot be
    /// reached, or a restore scan has not completed. The sender may try again later.
    Unavailable,
}

/// What the HTTP listener did. Nothing about the sender, its address or the slate is reported.
#[derive(Debug, Clone)]
pub struct HttpListenerEvent {
    pub kind: HttpListenerEventKind,
    /// For `Started`, `PortInUse` and `BindFailed`.
    pub port: Option<u16>,
    /// For `Started`.
    pub exposure: Option<HttpExposure>,
    /// For `Received`.
    pub tx_id: Option<u32>,
    /// For `Received`.
    pub amount: Option<u64>,
    /// For `Received`.
    pub repeated: bool,
    /// For `Refused`.
    pub refusal: Option<HttpRefusal>,
}

impl HttpListenerEvent {
    pub(crate) const fn of(kind: HttpListenerEventKind) -> Self {
        Self {
            kind,
            port: None,
            exposure: None,
            tx_id: None,
            amount: None,
            repeated: false,
            refusal: None,
        }
    }
}

/// A send over HTTP that the other wallet answered and this wallet finalized.
#[derive(Debug, Clone)]
pub struct HttpSentTx {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: u64,
    pub fee: u64,
    /// The node accepted the transaction. When false it is finalized and stored but the node
    /// refused it: post it again with `repost_transaction`.
    pub posted: bool,
}

/// A send delivered again over HTTP, answered and finalized.
#[derive(Debug, Clone)]
pub struct HttpResentTx {
    pub tx_id: u32,
    pub slate_id: String,
    /// As in [`HttpSentTx::posted`].
    pub posted: bool,
}

impl EpicWallet {
    /// Sends `amount` to the wallet listening at `url`, `http(s)://host[:port][/path]`, then
    /// finalizes its answer and posts the transaction. A missing port is 3415 for `http` and
    /// 443 for `https`. `message` is sent as [`EpicWallet::create_send_slate`] sends it.
    ///
    /// Plain `http` to any host but this device needs `allow_plain_http`, set only after the
    /// user agreed that the slate travels unencrypted.
    ///
    /// While the wallet's tor runs or is expected (`WalletConfig::tor_wanted`,
    /// [`EpicWallet::expect_tor`]), the connection goes through tor, which resolves the host,
    /// and waits for a tor that is still starting within the request timeout; a host on this
    /// device stays direct. A tor that fails fails the send: it never goes directly instead.
    /// Otherwise the wallet is reached directly.
    ///
    /// Fails, storing nothing, with `HttpUrlInvalid` or `PlainHttpNotAllowed` for the URL and
    /// the errors of [`EpicWallet::estimate_fee`]. Fails with `TransportFailed` when the other
    /// wallet could not be reached, refused, or answered with something else than a slate: the
    /// send is then stored as sent with its inputs locked, so deliver it again with
    /// [`EpicWallet::resend_http`] or cancel it with [`EpicWallet::cancel_transaction`]. Fails
    /// with the errors of [`EpicWallet::finalize_and_post`] except `NotPosted` when the answer
    /// could not be finalized; the send then stays sent, and a resend gets the same answer
    /// again.
    pub async fn send_http(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        url: String,
        allow_plain_http: bool,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<HttpSentTx, WalletError> {
        self.run("send_http", |session| async move {
            session
                .send_http_with(
                    amount,
                    minimum_confirmations,
                    &url,
                    allow_plain_http,
                    message,
                    options,
                )
                .await
        })
        .await
    }

    /// Delivers the slate of send `tx_id` again, to the wallet listening at `url`, which may
    /// be another address or method than the first attempt, then finalizes and posts as
    /// [`EpicWallet::send_http`] does. Use it after a delivery failed. A wallet that answered
    /// the slate before answers it again the same way.
    ///
    /// Fails with `HttpUrlInvalid` or `PlainHttpNotAllowed` for the URL, `InvalidArgument`
    /// when `tx_id` is not a send waiting for its answer, and otherwise as
    /// [`EpicWallet::send_http`].
    pub async fn resend_http(
        &self,
        tx_id: u32,
        url: String,
        allow_plain_http: bool,
    ) -> Result<HttpResentTx, WalletError> {
        self.run("resend_http", |session| async move {
            session.resend_http(tx_id, &url, allow_plain_http).await
        })
        .await
    }

    /// Starts the HTTP listener on `port` and streams what it does until
    /// [`EpicWallet::stop_http_listener`], [`EpicWallet::lock`] or the wallet is dropped. Port
    /// 0 lets the system pick one, which the `Started` event and
    /// [`EpicWallet::http_listener_status`] report; `epic-wallet` listens on 3415.
    ///
    /// The first event is `Started`, `PortInUse` or `BindFailed`; after a start the last one
    /// is `Stopped`. A wallet runs one HTTP listener: a call while one runs or starts gets a
    /// stream that ends at once. On a locked wallet the stream ends with `Locked` as its error
    /// and no event.
    pub async fn start_http_listener(
        &self,
        exposure: HttpExposure,
        port: u16,
        events: StreamSink<HttpListenerEvent>,
    ) {
        let sink = events.clone();
        let started = self
            .run_until_stopped("start_http_listener", |session| async move {
                // A closed stream only means the app stopped listening.
                let report = Arc::new(move |event| drop(sink.add(event)));
                session.start_http_listener(exposure, port, report).await
            })
            .await;
        end_stream(&events, started);
    }

    /// Stops the HTTP listener. Requests in progress finish; its stream ends with `Stopped`
    /// once the port is free.
    #[frb(sync)]
    pub fn stop_http_listener(&self) {
        self.boundary().guard_or("stop_http_listener", (), || {
            self.session.stop_http_listener();
        });
    }

    /// The running HTTP listener, or `None`.
    #[frb(sync)]
    pub fn http_listener_status(&self) -> Option<HttpListenerInfo> {
        self.boundary().guard_or("http_listener_status", None, || {
            self.session.http_listener_status()
        })
    }
}
