//! Push sessions of the Epicbox relay (mux/1): one socket that carries the mail of many
//! mailboxes. The delivery loop ([`EpicWallet::set_delivery`]) reads the contact mailboxes
//! through them, and so does a listener started with [`EpicWallet::start_listener_via`]. While
//! tor is off the loop joins the listener's group, so both read from one session a relay.
//!
//! A listener started without a session reads the relay on a socket of its own, and so does one
//! whose relay does not offer mux/1. A relay switch moves the sessions to the new relay; sessions
//! on the old one end. Locking the wallet ends all sessions.

use flutter_rust_bridge::frb;

use crate::api::types::{EpicboxSessionEvent, EpicboxSessionView, ListenVia, ListenerEvent};
use crate::api::wallet::EpicWallet;
use crate::boundary::{end_stream, spawn_listener};
use crate::frb_generated::StreamSink;
use std::sync::Arc;
use tokio::sync::Notify;

impl EpicWallet {
    /// Like [`EpicWallet::start_listener`], reading the relay through a push session. While tor
    /// is off the delivery loop reads the contact mailboxes through the same session. Fails with
    /// `InvalidArgument` for an empty or too long group or an interval of 0 or over a day.
    pub async fn start_listener_via(&self, via: ListenVia, events: StreamSink<ListenerEvent>) {
        let boundary = self.boundary();
        let handle = match boundary.guard("start_listener_via", || {
            self.session.claim_listener_via(via)
        }) {
            Ok(Some(handle)) => handle,
            Ok(None) => return,
            Err(error) => return end_stream(&events, Err(error)),
        };
        spawn_listener(&boundary, Arc::clone(&self.session), handle, events);
    }

    /// The push sessions of the relay in use, by relay and group; none without a relay.
    #[frb(sync)]
    pub fn epicbox_sessions(&self) -> Vec<EpicboxSessionView> {
        self.boundary()
            .guard_or("epicbox_sessions", Vec::new(), || {
                self.session.epicbox_sessions()
            })
    }

    /// Streams what the push sessions do: each one's state when it appears and at every change,
    /// and a note when mail was queued. The stream follows a relay switch, starting over with
    /// the sessions of the new relay, and ends when the wallet is dropped. Counters are in
    /// [`EpicWallet::epicbox_sessions`]. Ends with `Unsupported` when no relay is configured, at
    /// the start or after a relay switch.
    pub fn watch_epicbox_sessions(&self, events: StreamSink<EpicboxSessionEvent>) {
        let boundary = self.boundary();
        let session = Arc::clone(&self.session);
        let failed = events.clone();
        let ended = events.clone();
        let sink = events;
        let started = boundary.guard("watch_epicbox_sessions", || {
            session.epicbox()?;
            let gone = Arc::new(Notify::new());
            let closed = Arc::clone(&gone);
            boundary.handle.spawn(async move {
                let watching = session.watch_epicbox_sessions(move |event| {
                    // A closed stream means the app stopped watching.
                    if sink.add(event).is_err() {
                        closed.notify_one();
                    }
                });
                tokio::select! {
                    // A relay switch to a wallet without a relay ends the stream with why.
                    result = watching => end_stream(&ended, result),
                    () = gone.notified() => {}
                }
            });
            Ok(())
        });
        end_stream(&failed, started);
    }
}
