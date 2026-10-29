// SPDX-License-Identifier: Apache-2.0
//! Direct transactions over HTTP (ADR 0017): sends answered in the same exchange, and the
//! listener that answers payments sent to this wallet.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use lepic_foreign::{
    Exposure, ForeignClient, ForeignUrl, HttpTransport, ListenError, ListenSettings,
    ListenerHandle, PlainHttp, ReceiveHandler, Refusal, TRANSPORT_ID, UrlError, webpki_tls_config,
};
use lepic_node::Propagation;
use lepic_store::TxId;
use lepic_transport::transport::{BoxFuture, Destination, TransportId};
use lepic_wallet::send::Delivery;
use lepic_wallet::slate::WireSlate;
use lepic_wallet::{ReceiveError, ReceiveRequest};
use tracing::{debug, warn};

use super::{DEFAULT_ACCOUNT, Session, invalid, lock};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::http::{
    HttpExposure, HttpListenerEvent, HttpListenerEventKind, HttpListenerInfo, HttpRefusal,
    HttpResentTx, HttpSentTx,
};
use crate::api::types::SendOptions;
use crate::tuning::Tuning;

/// Where the HTTP listener's events go.
pub(crate) type HttpReport = Arc<dyn Fn(HttpListenerEvent) + Send + Sync>;

/// The HTTP listener of a session.
#[derive(Default)]
pub(super) enum HttpListener {
    #[default]
    Idle,
    /// Binding; the number tells this start from a later one.
    Starting(u64),
    Running {
        handle: ListenerHandle,
        report: HttpReport,
    },
}

pub(super) fn http_transport(tuning: &Tuning) -> Result<HttpTransport, WalletError> {
    let tls = webpki_tls_config()
        .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
    Ok(HttpTransport::new(ForeignClient::new(tuning.send, tls)))
}

fn foreign_url(url: &str, allow_plain_http: bool) -> Result<ForeignUrl, WalletError> {
    let plain = if allow_plain_http {
        PlainHttp::Allowed
    } else {
        PlainHttp::LoopbackOnly
    };
    ForeignUrl::parse(url, plain).map_err(|error| {
        let kind = match error {
            UrlError::PlainHttpNotAllowed => WalletErrorKind::PlainHttpNotAllowed,
            _ => WalletErrorKind::HttpUrlInvalid,
        };
        WalletError::new(kind, error.to_string())
    })
}

fn delivery(url: &ForeignUrl) -> Delivery {
    Delivery::Deliver {
        transport: TRANSPORT_ID,
        to: Destination::new(url.as_uri()),
    }
}

const fn exposure(exposure: HttpExposure) -> Exposure {
    match exposure {
        HttpExposure::LocalOnly => Exposure::LocalOnly,
        HttpExposure::Internet => Exposure::Internet,
    }
}

const fn http_exposure(exposure: Exposure) -> HttpExposure {
    match exposure {
        Exposure::LocalOnly => HttpExposure::LocalOnly,
        Exposure::Internet => HttpExposure::Internet,
    }
}

/// Whether the sender may try again: the wallet could not take the payment now, but nothing
/// about the slate was wrong.
const fn refusal(kind: WalletErrorKind) -> Refusal {
    match kind {
        WalletErrorKind::Locked
        | WalletErrorKind::NodeUnreachable
        | WalletErrorKind::RestoreScanRequired
        | WalletErrorKind::WalletBusy
        | WalletErrorKind::Io
        | WalletErrorKind::DamagedDatabase
        | WalletErrorKind::Panic
        | WalletErrorKind::Cancelled => Refusal::Unavailable,
        _ => Refusal::Rejected,
    }
}

const fn http_refusal(refusal: Refusal) -> HttpRefusal {
    match refusal {
        Refusal::Unavailable => HttpRefusal::Unavailable,
        _ => HttpRefusal::Rejected,
    }
}

fn stopped(report: &HttpReport) {
    report(HttpListenerEvent::of(HttpListenerEventKind::Stopped));
}

impl Session {
    #[cfg(test)]
    pub(crate) async fn send_http(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        url: &str,
        allow_plain_http: bool,
        message: Option<String>,
    ) -> Result<HttpSentTx, WalletError> {
        self.send_http_with(
            amount,
            minimum_confirmations,
            url,
            allow_plain_http,
            message,
            None,
        )
        .await
    }

    pub(crate) async fn send_http_with(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        url: &str,
        allow_plain_http: bool,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<HttpSentTx, WalletError> {
        let request = Self::send_request_with(amount, minimum_confirmations, message, options)?;
        let url = foreign_url(url, allow_plain_http)?;
        let sent = self.engine.send(request, delivery(&url)).await?;
        let slate_id = sent.slate_id.to_string();
        let posted = self.finalize_http_reply(&slate_id).await?;
        Ok(HttpSentTx {
            tx_id: sent.tx_id.0,
            slate_id,
            amount: sent.amount.value(),
            fee: sent.fee.value(),
            posted,
        })
    }

    pub(crate) async fn resend_http(
        &self,
        tx_id: u32,
        url: &str,
        allow_plain_http: bool,
    ) -> Result<HttpResentTx, WalletError> {
        let url = foreign_url(url, allow_plain_http)?;
        let details = self.engine.transaction_details(TxId(tx_id)).await?;
        let entry = &details.transaction.entry;
        let slate_id = match entry.slate_id {
            Some(slate_id) if entry.account == DEFAULT_ACCOUNT => slate_id.to_string(),
            _ => {
                return Err(invalid(
                    "the transaction is not a send waiting for its answer",
                ));
            }
        };
        self.engine.resend(TxId(tx_id), delivery(&url)).await?;
        let posted = self.finalize_http_reply(&slate_id).await?;
        Ok(HttpResentTx {
            tx_id,
            slate_id,
            posted,
        })
    }

    /// Finalizes the answer the HTTP transport kept for `slate_id` and posts it. Returns
    /// whether the node accepted the transaction.
    async fn finalize_http_reply(&self, slate_id: &str) -> Result<bool, WalletError> {
        self.finalize_direct_reply(TRANSPORT_ID, self.http.take_reply(slate_id))
            .await
    }

    /// Finalizes `reply`, the answer a direct send over `transport` kept, and posts it.
    /// Returns whether the node accepted the transaction.
    pub(super) async fn finalize_direct_reply(
        &self,
        transport: TransportId,
        reply: Option<WireSlate>,
    ) -> Result<bool, WalletError> {
        let reply = reply.ok_or_else(|| {
            WalletError::new(
                WalletErrorKind::TransportFailed,
                "the other wallet's answer was not kept; send it again",
            )
        })?;
        match self
            .engine
            .finalize(transport, &reply, Propagation::Fluff)
            .await
        {
            Ok(_) => Ok(true),
            Err(error) => {
                let error = WalletError::from(error);
                if error.kind == WalletErrorKind::NotPosted {
                    warn!(error = %error, "transaction not posted");
                    Ok(false)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Starts the HTTP listener unless one runs or starts, and reports its start or why it
    /// could not to `report`.
    pub(crate) async fn start_http_listener(
        self: &Arc<Self>,
        exposure: HttpExposure,
        port: u16,
        report: HttpReport,
    ) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let generation = self.http_starts.fetch_add(1, Ordering::Relaxed);
        {
            let mut slot = lock(&self.http_listener);
            // Checked again under the slot lock: a lock that ran since stops only a listener
            // it finds in the slot.
            self.ensure_unlocked()?;
            let busy = match &*slot {
                HttpListener::Idle => false,
                HttpListener::Starting(_) => true,
                HttpListener::Running { handle, .. } => handle.is_running(),
            };
            if busy {
                return Ok(());
            }
            *slot = HttpListener::Starting(generation);
        }
        let receiver = self.http_receiver(Arc::clone(&report), TRANSPORT_ID);
        let settings = ListenSettings::new(self::exposure(exposure), port, self.tuning.listen);
        let listening = lepic_foreign::listen(settings, receiver).await;
        let handle = match listening {
            Ok(handle) => handle,
            Err(error) => {
                let mut slot = lock(&self.http_listener);
                if matches!(&*slot, HttpListener::Starting(started) if *started == generation) {
                    *slot = HttpListener::Idle;
                }
                drop(slot);
                let kind = match error {
                    ListenError::PortInUse { .. } => HttpListenerEventKind::PortInUse,
                    _ => HttpListenerEventKind::BindFailed,
                };
                debug!(error = %error, "http listener not started");
                report(HttpListenerEvent {
                    port: Some(port),
                    ..HttpListenerEvent::of(kind)
                });
                return Ok(());
            }
        };
        let unclaimed = {
            let mut slot = lock(&self.http_listener);
            if matches!(&*slot, HttpListener::Starting(started) if *started == generation) {
                // Reported under the lock, so a stop that follows cannot report `Stopped`
                // first.
                report(HttpListenerEvent {
                    port: Some(handle.local_addr().port()),
                    exposure: Some(exposure),
                    ..HttpListenerEvent::of(HttpListenerEventKind::Started)
                });
                *slot = HttpListener::Running {
                    handle,
                    report: Arc::clone(&report),
                };
                None
            } else {
                Some(handle)
            }
        };
        // Stopped or locked while it was binding.
        if let Some(handle) = unclaimed {
            handle.shutdown().await;
            stopped(&report);
        }
        Ok(())
    }

    /// What the HTTP listener hands each payment to.
    /// The wallet behind a listener of the foreign API, recording receipts as `transport`'s:
    /// HTTP's, or Tor's for the listener behind the onion. Each has its own open receipts.
    pub(crate) fn http_receiver(
        self: &Arc<Self>,
        report: HttpReport,
        transport: TransportId,
    ) -> Arc<dyn ReceiveHandler> {
        Arc::new(HttpReceiver {
            session: Arc::downgrade(self),
            report,
            transport,
        })
    }

    /// Stops the HTTP listener. `Stopped` is reported once its port is free.
    pub(crate) fn stop_http_listener(&self) {
        let previous = std::mem::take(&mut *lock(&self.http_listener));
        if let HttpListener::Running { handle, report } = previous {
            handle.stop();
            // A runtime that is shutting down drops the task, and with it the report: the
            // stream then ends without `Stopped`, and the socket closes with the runtime.
            drop(self.runtime().boundary.handle.spawn(async move {
                handle.shutdown().await;
                stopped(&report);
            }));
        }
    }

    pub(crate) fn http_listener_status(&self) -> Option<HttpListenerInfo> {
        match &*lock(&self.http_listener) {
            HttpListener::Running { handle, .. } if handle.is_running() => Some(HttpListenerInfo {
                port: handle.local_addr().port(),
                exposure: http_exposure(handle.exposure()),
            }),
            _ => None,
        }
    }
}

/// The wallet behind the HTTP listener. It holds the session weakly, so a running listener
/// never keeps a dropped wallet open.
struct HttpReceiver {
    session: Weak<Session>,
    report: HttpReport,
    transport: TransportId,
}

impl ReceiveHandler for HttpReceiver {
    fn receive(&self, slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async move {
            let Some(session) = self.session.upgrade() else {
                return Err(Refusal::Unavailable);
            };
            let boundary = session.runtime().boundary.clone();
            let transport = self.transport;
            let received = boundary
                .run("http_receive", async move {
                    match session
                        .engine
                        .receive_unsolicited(transport, &slate, ReceiveRequest::default())
                        .await
                    {
                        Err(ReceiveError::OpenReceipts(cause)) => Ok(Err(cause)),
                        received => Ok(Ok(received?)),
                    }
                })
                .await;
            match received {
                Ok(Err(cause)) => {
                    debug!(
                        transport = %self.transport,
                        error = cause.as_ref().map(tracing::field::display),
                        "payment refused at the open receipt cap"
                    );
                    self.refused(Refusal::Unavailable);
                    Err(Refusal::Unavailable)
                }
                Ok(Ok(received)) => {
                    (self.report)(HttpListenerEvent {
                        tx_id: Some(received.tx_id.0),
                        amount: Some(received.slate.amount().value()),
                        repeated: received.repeated,
                        ..HttpListenerEvent::of(HttpListenerEventKind::Received)
                    });
                    Ok(received.reply)
                }
                Err(error) => {
                    let refusal = refusal(error.kind);
                    debug!(transport = %self.transport, error = %error, "payment refused");
                    self.refused(refusal);
                    Err(refusal)
                }
            }
        })
    }

    fn refused(&self, refusal: Refusal) {
        (self.report)(HttpListenerEvent {
            refusal: Some(http_refusal(refusal)),
            ..HttpListenerEvent::of(HttpListenerEventKind::Refused)
        });
    }
}
