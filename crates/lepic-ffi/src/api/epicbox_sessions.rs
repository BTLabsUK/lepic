//! Push sessions of the Epicbox relay (mux/1): one socket that carries the mail of many
//! mailboxes. The contacts collect and the payments listener can read from the same session
//! when they name the same group.
//!
//! Without these calls the wallet reads the relay on sockets of its own. The relay must offer
//! mux/1; when it does not, the listener falls back to its own socket and the contacts collect
//! keeps its sockets. A relay switch moves the contacts setting to the new relay; sessions on
//! the old one end. Locking the wallet ends all sessions and forgets the contacts setting: call
//! [`EpicWallet::contacts_push_start`] again after unlocking.

use flutter_rust_bridge::frb;

use crate::api::error::WalletError;
use crate::api::types::{EpicboxSessionEvent, EpicboxSessionView, ListenVia, ListenerEvent};
use crate::api::wallet::EpicWallet;
use crate::boundary::{end_stream, spawn_listener};
use crate::frb_generated::StreamSink;
use std::sync::Arc;
use tokio::sync::Notify;

impl EpicWallet {
    /// Like [`EpicWallet::start_listener`], reading the relay through a push session. The
    /// session is shared with a contacts collect that uses the same `via.group`. Fails with
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

    /// Makes the contacts collect read the mailboxes of contacts on relays that offer mux/1
    /// through push sessions of `via.group`, from the next collect on. Other relays keep their
    /// sockets. Fails with `InvalidArgument` as [`EpicWallet::start_listener_via`] does and
    /// with `Unsupported` when the configuration names no relay.
    pub async fn contacts_push_start(&self, via: ListenVia) -> Result<(), WalletError> {
        self.run("contacts_push_start", |session| async move {
            session.contacts_push_start(via)
        })
        .await
    }

    /// Makes the contacts collect use sockets again and lets go of its sessions. A session the
    /// listener also uses stays for the listener.
    pub async fn contacts_push_stop(&self) -> Result<(), WalletError> {
        self.run("contacts_push_stop", |session| async move {
            session.contacts_push_stop().await
        })
        .await
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
