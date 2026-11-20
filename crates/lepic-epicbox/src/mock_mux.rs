// SPDX-License-Identifier: Apache-2.0
//! An in-process relay that speaks mux/1 (`docs/protocols/epicbox-mux.md`), for tests of
//! [`crate::MuxSession`].
//!
//! It offers the extension when asked, sends a 22-character challenge, verifies each `Attach`
//! signature against it, issues single-use resume tokens that a restart forgets, pushes stored
//! mail up to the in-flight limit and answers `Ack`, `Hold`, `Detach` and `Waiting`. Switches
//! make it refuse the extension, answer the greeting with an `Error` or not at all, send a
//! challenge of the wrong shape, stop pushing, push past the in-flight limit, drop sockets,
//! send `Detached`, answer attaches with `rate_limited`, or answer attach entries `internal`
//! while attaching the mailbox all the same. It records every frame it
//! receives. Tests wait on its state with [`MuxMockRelay::wait_until`].
//!
//! It also offers `txcancel/1` to clients that ask for it, unless switched off with
//! [`MuxMockRelay::offer_cancel`]. On a socket without it `CancelTx` and `CancelAck` get
//! `unknown_type` and the `epicboxtxid` of mail is left out. With it, a cancel is pushed as
//! `Cancelled` to the other participant's attached mailbox, once per socket, and again on every
//! `Attach` or `Resume` until a `CancelAck` for a mailbox attached on that socket acknowledges
//! it.
//!
//! A `PostSlate` with a `ref` on a mux/1 socket is checked against the `from` key, stored for
//! the `to` mailbox and answered `Ok` with the `ref`. On a socket with `txcancel/1` its
//! transaction id is checked and kept, so either participant may cancel it, and a post with the
//! id of a cancelled transaction gets `post_refused`. A `PostSlate` on a socket without mux/1
//! is stored and answered the same way, as a relay without the extension takes a post.
//! Switches make it answer every post with an `Error` or not at all.

use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use futures_util::{SinkExt, StreamExt};
use lepic_transport::transport::BoxFuture;
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::address::{EpicboxAddress, Network, decode_key};
use crate::crypto::{SignedMessage, verify_text};
use crate::frame::{
    CANCEL_FORM_EXTENSION, CANCEL_SIGNATURE_PREFIX, ClientFrame, EpicboxTxId, MAX_FRAME_LEN,
};
use crate::mock_relay::CancelForm;
use crate::mux_frame::{
    ATTACH_HOST_EXTENSION, AttachEntry, MAX_MAILBOXES_PER_SOCKET, MuxClientFrame,
    TXCANCEL_EXTENSION, attach_text,
};
use crate::session::{Connector, RelayEndpoint, RelayStream};

const PIPE_CAPACITY: usize = 64 * 1024;

/// The in-flight limit the relay announces.
pub(crate) const INFLIGHT_LIMIT: usize = 32;

/// A challenge of the wrong shape, for [`MuxMockRelay::set_bad_challenge`].
const BAD_CHALLENGE: &str = "too-short";

/// A relay shared by every connection made through its [`MuxMockRelay::connector`].
#[derive(Clone)]
pub struct MuxMockRelay {
    inner: Arc<Inner>,
}

struct Inner {
    network: Network,
    state: Mutex<State>,
    changed: Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Held(u64),
    Pending,
    InFlight(u64),
    Done,
}

/// How the relay treats the `ClientDetails` greeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Greeting {
    Answer,
    Error,
    Silent,
}

struct StoredMail {
    id: String,
    key: String,
    from: String,
    text: String,
    signature: String,
    phase: Phase,
    txid: Option<String>,
}

/// A cancel kept for a mailbox until its `CancelAck`.
struct Tombstone {
    key: String,
    txid: String,
    acked: bool,
}

struct Socket {
    outgoing: mpsc::UnboundedSender<Outgoing>,
    challenge: String,
    mux: bool,
    /// Whether `txcancel/1` was negotiated on this socket.
    cancel: bool,
    /// Whether `epicbox-cancel/1` was negotiated on this socket.
    cancel_form: bool,
    /// Whether `epicbox-attach/1` was negotiated on this socket.
    attach_host: bool,
    attached: HashSet<String>,
}

enum Outgoing {
    Text(String),
    Close,
}

struct State {
    next_socket: u64,
    next_message: u64,
    next_token: u64,
    sockets: HashMap<u64, Socket>,
    /// Issued tokens, each with the mailboxes of its session.
    tokens: HashMap<String, HashSet<String>>,
    messages: Vec<StoredMail>,
    offering: bool,
    bad_challenge: bool,
    greeting: Greeting,
    ignoring_limit: bool,
    stalling_pushes: bool,
    rate_limited: Option<(u32, u64)>,
    /// Attach entries still to be answered `internal`, the mailbox attached all the same.
    internal_attaches: u32,
    received: Vec<Value>,
    sockets_made: u64,
    pings: u64,
    signatures_checked: u64,
    resumes_accepted: u64,
    acked: Vec<String>,
    held: Vec<(String, u64)>,
    offering_cancel: bool,
    /// Whether the relay offers `epicbox-cancel/1` to clients that ask for it.
    offering_cancel_form: bool,
    /// The form of every cancel it accepted.
    cancel_forms: Vec<CancelForm>,
    /// The names the relay answers to when it offers `epicbox-attach/1`; `None` when it does
    /// not offer it.
    attach_host_names: Option<Vec<String>>,
    /// Whether an attach entry without a host (the bare challenge) is accepted.
    accepting_bare_attach: bool,
    /// The host each accepted attach entry named, `None` for the bare form, in order.
    attach_forms: Vec<Option<String>>,
    /// The two keys of each transaction, by txid.
    transactions: HashMap<String, (String, String)>,
    tombstones: Vec<Tombstone>,
    /// Cancels pushed, per socket, mailbox and txid, since the mailbox was last attached.
    cancel_sent: HashSet<(u64, String, String)>,
    /// How many `Cancelled` frames were pushed, per txid.
    cancel_pushes: HashMap<String, usize>,
    /// The `code` of the `Error` every `CancelTx` is answered with, when set.
    cancel_error: Option<String>,
    /// The `code`, `retry_after` and `description` of the `Error` every `PostSlate` is
    /// answered with, when set; the description is the code when none is given.
    post_error: Option<(String, Option<u64>, Option<String>)>,
    /// Whether a `PostSlate` is taken without an answer and without being stored.
    ignoring_posts: bool,
    /// The `mailboxes_per_socket` limit it names and keeps to.
    mailboxes_per_socket: usize,
}

impl MuxMockRelay {
    /// A relay for addresses on `network` that offers mux/1.
    pub fn new(network: Network) -> Self {
        Self {
            inner: Arc::new(Inner {
                network,
                state: Mutex::new(State {
                    next_socket: 0,
                    next_message: 0,
                    next_token: 0,
                    sockets: HashMap::new(),
                    tokens: HashMap::new(),
                    messages: Vec::new(),
                    offering: true,
                    bad_challenge: false,
                    greeting: Greeting::Answer,
                    ignoring_limit: false,
                    stalling_pushes: false,
                    rate_limited: None,
                    internal_attaches: 0,
                    received: Vec::new(),
                    sockets_made: 0,
                    pings: 0,
                    signatures_checked: 0,
                    resumes_accepted: 0,
                    acked: Vec::new(),
                    held: Vec::new(),
                    offering_cancel: true,
                    offering_cancel_form: false,
                    cancel_forms: Vec::new(),
                    attach_host_names: None,
                    accepting_bare_attach: true,
                    attach_forms: Vec::new(),
                    transactions: HashMap::new(),
                    tombstones: Vec::new(),
                    cancel_sent: HashSet::new(),
                    cancel_pushes: HashMap::new(),
                    cancel_error: None,
                    post_error: None,
                    ignoring_posts: false,
                    mailboxes_per_socket: MAX_MAILBOXES_PER_SOCKET,
                }),
                changed: Notify::new(),
            }),
        }
    }

    /// Connects in memory, whatever the endpoint says.
    pub fn connector(&self) -> Arc<dyn Connector> {
        Arc::new(MockConnector {
            relay: self.clone(),
        })
    }

    /// Offers mux/1 to clients that ask, or answers a plain `Ok` as a relay without it.
    pub fn offer_mux(&self, offering: bool) {
        self.update(|state| state.offering = offering);
    }

    /// Offers `txcancel/1` to clients that ask for it, or leaves it out of the `Ok`, as a relay
    /// without cancel does.
    pub fn offer_cancel(&self, offering: bool) {
        self.update(|state| state.offering_cancel = offering);
    }

    /// Offers `epicbox-cancel/1` (the separated cancel signature) to clients that ask for it, or
    /// leaves it out of the `Ok`, as a relay without it does.
    pub fn offer_cancel_form(&self, offering: bool) {
        self.update(|state| state.offering_cancel_form = offering);
    }

    /// The form of each cancel the relay accepted, in order.
    pub fn cancel_forms(&self) -> Vec<CancelForm> {
        self.lock().cancel_forms.clone()
    }

    /// Offers `epicbox-attach/1` (attach signatures bound to the relay's name) to clients that
    /// ask for it, answering to `names`; or, with `None`, leaves it out of the `Ok` as a relay
    /// without it does.
    pub fn offer_attach_host(&self, names: Option<Vec<String>>) {
        self.update(|state| state.attach_host_names = names);
    }

    /// Accepts attach entries signed over the bare challenge, or refuses them with
    /// `bad_signature` on sockets that negotiated `epicbox-attach/1`.
    pub fn accept_bare_attach(&self, accepting: bool) {
        self.update(|state| state.accepting_bare_attach = accepting);
    }

    /// The host each accepted attach entry was bound to, `None` for the bare form, in order.
    pub fn attach_forms(&self) -> Vec<Option<String>> {
        self.lock().attach_forms.clone()
    }

    /// Answers every `CancelTx` with an `Error` of this `code`, or normally again with `None`.
    pub fn set_cancel_error(&self, code: Option<&str>) {
        self.update(|state| state.cancel_error = code.map(str::to_owned));
    }

    /// Answers every `PostSlate` on a mux/1 socket with an `Error` of this `code` and
    /// `retry_after`, or normally again with `None`.
    pub fn set_post_error(&self, code: Option<&str>, retry_after_secs: Option<u64>) {
        self.update(|state| {
            state.post_error = code.map(|code| (code.to_owned(), retry_after_secs, None));
        });
    }

    /// [`Self::set_post_error`] with the `description` the `Error` gives.
    pub fn set_post_refusal(&self, code: &str, retry_after_secs: Option<u64>, description: &str) {
        self.update(|state| {
            state.post_error = Some((
                code.to_owned(),
                retry_after_secs,
                Some(description.to_owned()),
            ));
        });
    }

    /// Takes every `PostSlate` on a mux/1 socket without storing or answering it.
    pub fn ignore_posts(&self, ignoring: bool) {
        self.update(|state| state.ignoring_posts = ignoring);
    }

    /// Names `limit` as `mailboxes_per_socket` to the sockets negotiated from now on, and refuses
    /// a mailbox with `too_many_mailboxes` when its socket already holds that many, as the relay
    /// does.
    pub fn set_mailboxes_per_socket(&self, limit: usize) {
        self.update(|state| state.mailboxes_per_socket = limit);
    }

    /// Sends a negotiation challenge of the wrong shape from now on.
    pub fn set_bad_challenge(&self, bad: bool) {
        self.update(|state| state.bad_challenge = bad);
    }

    /// Answers the greeting with an `Error` frame, as a relay that does not know the extension
    /// field may.
    pub fn answer_greeting_with_error(&self, erroring: bool) {
        self.update(|state| {
            state.greeting = if erroring {
                Greeting::Error
            } else {
                Greeting::Answer
            };
        });
    }

    /// Does not answer the greeting at all.
    pub fn ignore_greeting(&self, ignoring: bool) {
        self.update(|state| {
            state.greeting = if ignoring {
                Greeting::Silent
            } else {
                Greeting::Answer
            };
        });
    }

    /// Pushes mail without counting what is in flight, as a relay with a bug would.
    pub fn ignore_inflight_limit(&self, ignoring: bool) {
        self.update(|state| state.ignoring_limit = ignoring);
    }

    /// Stops pushing mail, as a relay whose push path is broken does. `Waiting` still reports
    /// it. Pushing resumes, and sends what is stored, when switched off.
    pub fn stall_pushes(&self, stalling: bool) {
        self.update(|state| {
            state.stalling_pushes = stalling;
            if !stalling {
                state.push_all();
            }
        });
    }

    /// Answers the next `attempts` `Attach` or `Resume` frames with `rate_limited`.
    pub fn rate_limit_attaches(&self, attempts: u32, retry_after_secs: u64) {
        self.update(|state| state.rate_limited = Some((attempts, retry_after_secs)));
    }

    /// Answers the next `entries` `Attach` entries that verify with `ok: false` and code
    /// `internal`, and attaches each mailbox all the same, as Epicmail does when its store
    /// fails after it took the mailbox.
    pub fn fail_attach_entries(&self, entries: u32) {
        self.update(|state| state.internal_attaches = entries);
    }

    /// Closes every open socket, keeping tokens and mail.
    pub fn drop_sockets(&self) {
        self.update(|state| {
            for socket in state.sockets.values() {
                let _ = socket.outgoing.send(Outgoing::Close);
            }
        });
    }

    /// Closes every open socket and forgets every token, as a relay restart does.
    pub fn restart(&self) {
        self.update(|state| {
            state.tokens.clear();
            for socket in state.sockets.values() {
                let _ = socket.outgoing.send(Outgoing::Close);
            }
        });
    }

    /// Tells the socket holding `address` that it lost the mailbox, for `reason` (`replaced`,
    /// `limit` or `shutdown`), and detaches it there.
    pub fn send_detached(&self, address: &EpicboxAddress, reason: &str) {
        let key = address.key_text();
        self.update(|state| {
            let holders: Vec<u64> = state
                .sockets
                .iter()
                .filter(|(_, socket)| socket.attached.contains(&key))
                .map(|(id, _)| *id)
                .collect();
            for id in holders {
                state.detach(id, &key, reason);
            }
        });
    }

    /// Stores a message as if another wallet had posted it, pushes it when its mailbox is
    /// attached, and returns its id.
    pub fn store(
        &self,
        from: &EpicboxAddress,
        to: &EpicboxAddress,
        message: &SignedMessage,
    ) -> String {
        self.update(|state| {
            state.next_message = state.next_message.wrapping_add(1);
            let id = format!("mock-mux-message-{}", state.next_message);
            state.messages.push(StoredMail {
                id: id.clone(),
                key: to.key_text(),
                from: from.to_string(),
                text: message.str.clone(),
                signature: message.signature.to_der_hex(),
                phase: Phase::Pending,
                txid: None,
            });
            state.push_all();
            id
        })
    }

    /// Stores a message as [`Self::store`] does, posted with transaction id `txid`. Its two
    /// participants may cancel the transaction.
    pub fn store_with_txid(
        &self,
        from: &EpicboxAddress,
        to: &EpicboxAddress,
        message: &SignedMessage,
        txid: &str,
    ) -> String {
        self.update(|state| {
            state.next_message = state.next_message.wrapping_add(1);
            let id = format!("mock-mux-message-{}", state.next_message);
            state
                .transactions
                .insert(txid.to_owned(), (from.key_text(), to.key_text()));
            state.messages.push(StoredMail {
                id: id.clone(),
                key: to.key_text(),
                from: from.to_string(),
                text: message.str.clone(),
                signature: message.signature.to_der_hex(),
                phase: Phase::Pending,
                txid: Some(txid.to_owned()),
            });
            state.push_all();
            id
        })
    }

    /// Cancels transaction `txid` as its participant `canceller` would, and pushes it to the
    /// other participant. Returns whether `canceller` takes part in the transaction.
    pub fn cancel_as(&self, canceller: &EpicboxAddress, txid: &str) -> bool {
        self.update(|state| state.record_cancel(txid, &canceller.key_text()))
    }

    /// Cancels kept for `address` that no `CancelAck` acknowledged.
    pub fn unacked_cancels(&self, address: &EpicboxAddress) -> usize {
        let key = address.key_text();
        self.lock()
            .tombstones
            .iter()
            .filter(|t| t.key == key && !t.acked)
            .count()
    }

    /// How many `Cancelled` frames were pushed for `txid`, to any socket.
    pub fn cancel_pushes(&self, txid: &str) -> usize {
        self.lock().cancel_pushes.get(txid).copied().unwrap_or(0)
    }

    /// Whether `txcancel/1` is negotiated on any open socket.
    pub fn cancel_negotiated(&self) -> bool {
        self.lock().sockets.values().any(|socket| socket.cancel)
    }

    /// Frames of `type_name` the relay received, in order, as JSON.
    pub fn frames(&self, type_name: &str) -> Vec<Value> {
        self.lock()
            .received
            .iter()
            .filter(|frame| frame.get("type").and_then(Value::as_str) == Some(type_name))
            .cloned()
            .collect()
    }

    /// How many frames of `type_name` the relay received.
    pub fn received(&self, type_name: &str) -> usize {
        self.frames(type_name).len()
    }

    /// Sockets opened to the relay, ever.
    pub fn sockets_made(&self) -> u64 {
        self.lock().sockets_made
    }

    /// WebSocket pings the relay received, ever.
    pub fn pings_received(&self) -> u64 {
        self.lock().pings
    }

    /// Sockets open now.
    pub fn sockets_open(&self) -> usize {
        self.lock().sockets.len()
    }

    /// Attach signatures the relay checked and accepted.
    pub fn signatures_checked(&self) -> u64 {
        self.lock().signatures_checked
    }

    /// Resumes the relay accepted.
    pub fn resumes_accepted(&self) -> u64 {
        self.lock().resumes_accepted
    }

    /// Whether the message `id` was acknowledged.
    pub fn is_acked(&self, id: &str) -> bool {
        self.lock().acked.iter().any(|acked| acked == id)
    }

    /// The `seconds` of each `Hold` for message `id`.
    pub fn holds(&self, id: &str) -> Vec<u64> {
        self.lock()
            .held
            .iter()
            .filter(|(held, _)| held == id)
            .map(|(_, seconds)| *seconds)
            .collect()
    }

    /// The mailboxes attached on open sockets, as keys.
    pub fn attached(&self) -> HashSet<String> {
        self.lock()
            .sockets
            .values()
            .flat_map(|socket| socket.attached.iter().cloned())
            .collect()
    }

    /// Waits until `condition` holds. The condition is checked again after every change.
    pub async fn wait_until(&self, condition: impl Fn(&Self) -> bool) {
        loop {
            let mut changed = pin!(self.inner.changed.notified());
            changed.as_mut().enable();
            if condition(self) {
                return;
            }
            changed.await;
        }
    }

    // Every update leaves the state consistent before it can panic.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn update<T>(&self, change: impl FnOnce(&mut State) -> T) -> T {
        let result = change(&mut self.lock());
        self.inner.changed.notify_waiters();
        result
    }

    async fn run_socket<S>(self, stream: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME_LEN))
            .max_frame_size(Some(MAX_FRAME_LEN));
        let Ok(mut ws) = tokio_tungstenite::accept_async_with_config(stream, Some(config)).await
        else {
            return;
        };
        let (outgoing, mut queued) = mpsc::unbounded_channel();
        let id = self.update(|state| state.open_socket(outgoing));
        loop {
            tokio::select! {
                next = queued.recv() => match next {
                    Some(Outgoing::Text(text)) => {
                        if ws.send(Message::text(text)).await.is_err() {
                            break;
                        }
                    }
                    Some(Outgoing::Close) => {
                        let frame = CloseFrame { code: CloseCode::Away, reason: "".into() };
                        let _ = ws.send(Message::Close(Some(frame))).await;
                        break;
                    }
                    None => break,
                },
                incoming = ws.next() => match incoming {
                    Some(Ok(Message::Text(text))) => {
                        self.update(|state| state.handle(id, self.inner.network, text.as_str()));
                    }
                    Some(Ok(Message::Ping(_))) => {
                        self.update(|state| state.pings = state.pings.saturating_add(1));
                    }
                    Some(Ok(Message::Pong(_) | Message::Binary(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                },
            }
        }
        self.update(|state| state.drop_socket(id));
    }
}

impl std::fmt::Debug for MuxMockRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxMockRelay")
            .field("network", &self.inner.network)
            .finish_non_exhaustive()
    }
}

struct MockConnector {
    relay: MuxMockRelay,
}

impl Connector for MockConnector {
    fn connect<'a>(
        &'a self,
        _endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        Box::pin(async move {
            let (client, server) = tokio::io::duplex(PIPE_CAPACITY);
            let relay = self.relay.clone();
            let runtime = Handle::try_current().map_err(io::Error::other)?;
            runtime.spawn(async move { relay.run_socket(server).await });
            Ok(Box::new(client) as Box<dyn RelayStream>)
        })
    }
}

pub(crate) fn error(
    kind: &str,
    code: &str,
    reference: Option<&str>,
    retry_after: Option<u64>,
) -> String {
    let mut frame = json!({
        "type": "Error", "kind": kind, "code": code, "description": code,
    });
    if let Some(reference) = reference {
        set(&mut frame, "ref", json!(reference));
    }
    if let Some(retry_after) = retry_after {
        set(&mut frame, "retry_after", json!(retry_after));
    }
    frame.to_string()
}

/// Sets one field of a JSON object.
fn set(frame: &mut Value, key: &str, value: Value) {
    if let Some(object) = frame.as_object_mut() {
        object.insert(key.to_owned(), value);
    }
}

pub(crate) fn with_ref(mut frame: Value, reference: Option<&str>) -> String {
    if let Some(reference) = reference {
        set(&mut frame, "ref", json!(reference));
    }
    frame.to_string()
}

impl State {
    fn open_socket(&mut self, outgoing: mpsc::UnboundedSender<Outgoing>) -> u64 {
        let id = self.next_socket;
        self.next_socket = self.next_socket.wrapping_add(1);
        self.sockets_made = self.sockets_made.saturating_add(1);
        let challenge = format!("mockmux{id:015}");
        self.sockets.insert(
            id,
            Socket {
                outgoing,
                challenge,
                mux: false,
                cancel: false,
                cancel_form: false,
                attach_host: false,
                attached: HashSet::new(),
            },
        );
        self.send(
            id,
            json!({"type": "Challenge", "str": "mock-classic-challenge"}).to_string(),
        );
        id
    }

    fn send(&self, id: u64, text: String) {
        if let Some(socket) = self.sockets.get(&id) {
            let _ = socket.outgoing.send(Outgoing::Text(text));
        }
    }

    fn drop_socket(&mut self, id: u64) {
        self.sockets.remove(&id);
        for message in &mut self.messages {
            if message.phase == Phase::InFlight(id) {
                message.phase = Phase::Pending;
            }
        }
    }

    fn handle(&mut self, id: u64, network: Network, text: &str) {
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            self.received.push(value);
        }
        match MuxClientFrame::from_json(text) {
            Ok(Some(frame)) => self.handle_mux(id, network, frame),
            Ok(None) => match ClientFrame::from_json(text) {
                Ok(ClientFrame::ClientDetails { ext, .. }) => self.negotiate(id, ext.as_ref()),
                Ok(ClientFrame::PostSlate { .. }) => {
                    match serde_json::from_str::<MuxClientFrame>(text) {
                        Ok(frame) if self.is_mux(id) => self.handle_mux(id, network, frame),
                        Ok(frame) => self.post_frame(id, network, frame),
                        Err(_) => self.send(id, error("InvalidRequest", "bad_frame", None, None)),
                    }
                }
                _ => {}
            },
            Err(_) => self.send(id, error("InvalidRequest", "bad_frame", None, None)),
        }
    }

    fn negotiate(&mut self, id: u64, ext: Option<&Vec<String>>) {
        match self.greeting {
            Greeting::Answer => {}
            Greeting::Error => {
                self.send(id, error("InvalidRequest", "bad_frame", None, None));
                return;
            }
            Greeting::Silent => return,
        }
        let asked = ext.is_some_and(|ext| ext.iter().any(|name| name == "mux/1"));
        if !(asked && self.offering) {
            self.send(id, json!({"type": "Ok"}).to_string());
            return;
        }
        let cancel = self.offering_cancel
            && ext.is_some_and(|ext| ext.iter().any(|name| name == TXCANCEL_EXTENSION));
        let form = cancel
            && self.offering_cancel_form
            && ext.is_some_and(|ext| ext.iter().any(|name| name == CANCEL_FORM_EXTENSION));
        let attach_host = self.attach_host_names.is_some()
            && ext.is_some_and(|ext| ext.iter().any(|name| name == ATTACH_HOST_EXTENSION));
        let bad = self.bad_challenge;
        let Some(socket) = self.sockets.get_mut(&id) else {
            return;
        };
        socket.mux = true;
        socket.cancel = cancel;
        socket.cancel_form = form;
        socket.attach_host = attach_host;
        let mut offered: Vec<&str> = vec!["mux/1"];
        if cancel {
            offered.push(TXCANCEL_EXTENSION);
        }
        if form {
            offered.push(CANCEL_FORM_EXTENSION);
        }
        if attach_host {
            offered.push(ATTACH_HOST_EXTENSION);
        }
        let challenge = if bad {
            BAD_CHALLENGE.to_owned()
        } else {
            socket.challenge.clone()
        };
        self.send(
            id,
            json!({
                "type": "Ok",
                "ext": offered,
                "challenge": challenge,
                "limits": {
                    "attach_per_frame": 64,
                    "mailboxes_per_socket": self.mailboxes_per_socket,
                    "inflight_per_socket": INFLIGHT_LIMIT,
                    "hold_max_s": 3600,
                },
            })
            .to_string(),
        );
    }

    fn is_mux(&self, id: u64) -> bool {
        self.sockets.get(&id).is_some_and(|socket| socket.mux)
    }

    fn handle_mux(&mut self, id: u64, network: Network, frame: MuxClientFrame) {
        if !self.is_mux(id) {
            self.send(id, error("InvalidRequest", "not_mux", None, None));
            return;
        }
        match frame {
            MuxClientFrame::Attach {
                reference,
                mailboxes,
            } => {
                if self.refuse_rate(id, reference.as_deref()) {
                    return;
                }
                self.attach(id, network, reference.as_deref(), &mailboxes);
            }
            MuxClientFrame::Resume { reference, token } => {
                if self.refuse_rate(id, reference.as_deref()) {
                    return;
                }
                self.resume(id, reference.as_deref(), token.expose());
            }
            MuxClientFrame::Detach {
                reference,
                mailboxes,
            } => {
                if let Some(socket) = self.sockets.get_mut(&id) {
                    for key in &mailboxes {
                        socket.attached.remove(key);
                    }
                }
                self.send(id, with_ref(json!({"type": "Ok"}), reference.as_deref()));
            }
            MuxClientFrame::Ack { reference, ids } => {
                for acked in &ids {
                    for message in &mut self.messages {
                        if message.id == acked.as_str() && message.phase != Phase::Done {
                            message.phase = Phase::Done;
                            self.acked.push(message.id.clone());
                        }
                    }
                }
                self.send(id, with_ref(json!({"type": "Ok"}), reference.as_deref()));
                self.push_all();
            }
            MuxClientFrame::Hold {
                reference,
                id: message_id,
                seconds,
            } => {
                let seconds = u64::from(seconds).clamp(1, 3600);
                for message in &mut self.messages {
                    if message.id == message_id.as_str() {
                        message.phase = Phase::Held(seconds);
                        self.held.push((message.id.clone(), seconds));
                    }
                }
                self.send(id, with_ref(json!({"type": "Ok"}), reference.as_deref()));
            }
            MuxClientFrame::Waiting { reference } => self.waiting(id, reference.as_deref()),
            MuxClientFrame::CancelTx {
                reference,
                address,
                epicboxtxid,
                signature,
            } => {
                if !self.has_cancel(id) {
                    self.send(
                        id,
                        error("InvalidRequest", "unknown_type", reference.as_deref(), None),
                    );
                    return;
                }
                self.cancel_tx(
                    id,
                    network,
                    reference.as_deref(),
                    &address,
                    epicboxtxid.as_str(),
                    &signature,
                );
            }
            MuxClientFrame::CancelAck {
                reference,
                mailbox,
                epicboxtxid,
            } => self.cancel_ack(id, reference.as_deref(), &mailbox, epicboxtxid.as_str()),
            frame @ MuxClientFrame::PostSlate { .. } => self.post_frame(id, network, frame),
        }
    }

    /// A `PostSlate` frame on the mux socket `id`: posts it and sends the answer, if any. A
    /// socket without txcancel/1 ignores the transaction id, as the relay does.
    fn post_frame(&mut self, id: u64, network: Network, frame: MuxClientFrame) {
        let MuxClientFrame::PostSlate {
            reference,
            from,
            to,
            str,
            signature,
            epicboxtxid,
            epicboxtxidsig,
        } = frame
        else {
            return;
        };
        let txid = match (epicboxtxid, epicboxtxidsig) {
            (Some(txid), Some(sig)) if self.has_cancel(id) => Some((txid, sig)),
            _ => None,
        };
        let answer = self.post_slate(
            network,
            reference.as_deref(),
            (from, &to),
            (str, signature),
            txid,
        );
        if let Some(answer) = answer {
            self.send(id, answer);
        }
    }

    /// A `PostSlate`: stores the message for the mailbox of `to`, pushes it if that is attached,
    /// and gives the answer, or none while posts are ignored. A post with the id of a cancelled
    /// transaction is refused with `post_refused`.
    fn post_slate(
        &mut self,
        network: Network,
        reference: Option<&str>,
        (from, to): (String, &str),
        (text, signature): (String, String),
        txid: Option<(EpicboxTxId, String)>,
    ) -> Option<String> {
        if self.ignoring_posts {
            return None;
        }
        if let Some((code, retry_after, description)) = &self.post_error {
            let mut frame = error("InvalidRequest", code, reference, *retry_after);
            if let Some(description) = description
                && let Ok(mut value) = serde_json::from_str::<Value>(&frame)
            {
                set(&mut value, "description", json!(description));
                frame = value.to_string();
            }
            return Some(frame);
        }
        let from_key = bare_key(&from);
        if !signed_by(&from_key, network, &text, &signature) {
            return Some(error("InvalidSignature", "bad_signature", reference, None));
        }
        let txid = match txid {
            Some((txid, txid_signature)) => {
                let txid = txid.as_str().to_owned();
                if !signed_by(&from_key, network, &txid, &txid_signature) {
                    return Some(error("InvalidSignature", "bad_signature", reference, None));
                }
                if self.tombstones.iter().any(|t| t.txid == txid) {
                    return Some(error("InvalidRequest", "post_refused", reference, None));
                }
                self.transactions
                    .entry(txid.clone())
                    .or_insert_with(|| (from_key, bare_key(to)));
                Some(txid)
            }
            None => None,
        };
        self.next_message = self.next_message.wrapping_add(1);
        self.messages.push(StoredMail {
            id: format!("mock-mux-message-{}", self.next_message),
            key: bare_key(to),
            from,
            text,
            signature,
            phase: Phase::Pending,
            txid,
        });
        self.push_all();
        Some(with_ref(json!({"type": "Ok"}), reference))
    }

    /// A `CancelAck`: marks the cancellation acknowledged for a mailbox attached on this socket.
    fn cancel_ack(&mut self, id: u64, reference: Option<&str>, mailbox: &str, txid: &str) {
        if !self.has_cancel(id) {
            self.send(id, error("InvalidRequest", "unknown_type", reference, None));
            return;
        }
        let key = bare_key(mailbox);
        let attached_here = self
            .sockets
            .get(&id)
            .is_some_and(|socket| socket.attached.contains(&key));
        if attached_here {
            for tombstone in &mut self.tombstones {
                if tombstone.key == key && tombstone.txid == txid {
                    tombstone.acked = true;
                }
            }
        }
        self.send(id, with_ref(json!({"type": "Ok"}), reference));
    }

    fn has_cancel(&self, id: u64) -> bool {
        self.sockets.get(&id).is_some_and(|socket| socket.cancel)
    }

    fn cancel_tx(
        &mut self,
        id: u64,
        network: Network,
        reference: Option<&str>,
        address: &str,
        txid: &str,
        signature: &str,
    ) {
        if let Some(code) = self.cancel_error.clone() {
            self.send(id, error("InvalidRequest", &code, reference, None));
            return;
        }
        let key = bare_key(address);
        let separated = self
            .sockets
            .get(&id)
            .is_some_and(|socket| socket.cancel_form)
            && signed_by(
                &key,
                network,
                &format!("{CANCEL_SIGNATURE_PREFIX}{txid}"),
                signature,
            );
        let form = if separated {
            Some(CancelForm::Separated)
        } else if signed_by(&key, network, txid, signature) {
            Some(CancelForm::Bare)
        } else {
            None
        };
        let Some(form) = form else {
            self.send(
                id,
                error("InvalidSignature", "bad_signature", reference, None),
            );
            return;
        };
        self.cancel_forms.push(form);
        if self.record_cancel(txid, &key) {
            self.send(
                id,
                with_ref(
                    json!({"type": "TransactionCancelled", "epicboxtxid": txid}),
                    reference,
                ),
            );
        } else {
            self.send(id, with_ref(json!({"type": "Ok"}), reference));
        }
    }

    /// Keeps the cancel of `txid` by `canceller` for the other participant and pushes it.
    /// Returns whether `canceller` takes part in the transaction.
    fn record_cancel(&mut self, txid: &str, canceller: &str) -> bool {
        let Some((from, to)) = self.transactions.get(txid).cloned() else {
            return false;
        };
        let other = if from == canceller {
            to
        } else if to == canceller {
            from
        } else {
            return false;
        };
        if !self
            .tombstones
            .iter()
            .any(|t| t.key == other && t.txid == txid)
        {
            self.tombstones.push(Tombstone {
                key: other,
                txid: txid.to_owned(),
                acked: false,
            });
        }
        self.push_all();
        true
    }

    fn refuse_rate(&mut self, id: u64, reference: Option<&str>) -> bool {
        let Some((attempts, retry_after)) = self.rate_limited else {
            return false;
        };
        self.rate_limited = (attempts > 1).then_some((attempts.saturating_sub(1), retry_after));
        self.send(
            id,
            error(
                "InvalidRequest",
                "rate_limited",
                reference,
                Some(retry_after),
            ),
        );
        true
    }

    fn attach(
        &mut self,
        id: u64,
        network: Network,
        reference: Option<&str>,
        mailboxes: &[AttachEntry],
    ) {
        let (challenge, bound) = self
            .sockets
            .get(&id)
            .map(|socket| (socket.challenge.clone(), socket.attach_host))
            .unwrap_or_default();
        let mut entries = Vec::new();
        let mut accepted = Vec::new();
        for entry in mailboxes {
            let key = bare_key(&entry.address);
            // A relay without `epicbox-attach/1` does not read the `host` field.
            let host = entry.host.as_deref().filter(|_| bound);
            let named = |names: &Option<Vec<String>>, host: &str| {
                names
                    .as_ref()
                    .is_some_and(|names| names.iter().any(|name| name == host))
            };
            if self.socket_full(id, &key, &accepted) {
                entries.push(json!({"mailbox": key, "ok": false, "code": "too_many_mailboxes"}));
            } else if host.is_some_and(|host| !named(&self.attach_host_names, host)) {
                entries.push(json!({"mailbox": key, "ok": false, "code": "wrong_host"}));
            } else if (host.is_some() || !bound || self.accepting_bare_attach)
                && signed_by(
                    &key,
                    network,
                    &attach_text(host, &challenge),
                    &entry.signature,
                )
            {
                self.signatures_checked = self.signatures_checked.saturating_add(1);
                self.attach_forms.push(host.map(str::to_owned));
                accepted.push(key.clone());
                if self.internal_attaches > 0 {
                    self.internal_attaches = self.internal_attaches.saturating_sub(1);
                    entries.push(json!({"mailbox": key, "ok": false, "code": "internal"}));
                } else {
                    entries
                        .push(json!({"mailbox": key, "ok": true, "waiting": self.pending(&key)}));
                }
            } else {
                entries.push(json!({"mailbox": key, "ok": false, "code": "bad_signature"}));
            }
        }
        for key in &accepted {
            self.take_over(id, key);
        }
        self.reply_attached(id, reference, &entries, &accepted);
    }

    fn resume(&mut self, id: u64, reference: Option<&str>, token: &str) {
        let Some(keys) = self.tokens.remove(token) else {
            self.send(
                id,
                error("InvalidChallenge", "token_unknown", reference, None),
            );
            return;
        };
        self.resumes_accepted = self.resumes_accepted.saturating_add(1);
        let mut accepted: Vec<String> = keys.into_iter().collect();
        accepted.sort();
        let mut entries = Vec::new();
        for key in &accepted {
            self.take_over(id, key);
            entries.push(json!({"mailbox": key, "ok": true, "waiting": self.pending(key)}));
        }
        self.reply_attached(id, reference, &entries, &accepted);
    }

    /// Whether socket `id`, with `accepted` about to join it, has no room for `key`.
    fn socket_full(&self, id: u64, key: &str, accepted: &[String]) -> bool {
        let Some(socket) = self.sockets.get(&id) else {
            return false;
        };
        if socket.attached.contains(key) || accepted.iter().any(|taken| taken == key) {
            return false;
        }
        let fresh = accepted
            .iter()
            .filter(|taken| !socket.attached.contains(*taken))
            .count();
        socket.attached.len().saturating_add(fresh) >= self.mailboxes_per_socket
    }

    /// Attaches `key` to socket `id`, detaching it from any other socket with `replaced`.
    fn take_over(&mut self, id: u64, key: &str) {
        let others: Vec<u64> = self
            .sockets
            .iter()
            .filter(|(other, socket)| **other != id && socket.attached.contains(key))
            .map(|(other, _)| *other)
            .collect();
        for other in others {
            self.detach(other, key, "replaced");
        }
        if let Some(socket) = self.sockets.get_mut(&id) {
            socket.attached.insert(key.to_owned());
        }
        // An attach asks for everything kept for the mailbox again.
        self.cancel_sent
            .retain(|(socket, mailbox, _)| !(*socket == id && mailbox == key));
    }

    fn reply_attached(
        &mut self,
        id: u64,
        reference: Option<&str>,
        entries: &[Value],
        accepted: &[String],
    ) {
        let mut frame = json!({"type": "Attached", "mailboxes": entries});
        if !accepted.is_empty() {
            self.next_token = self.next_token.wrapping_add(1);
            let token = format!("mocktoken{:020}", self.next_token);
            let session = self
                .sockets
                .get(&id)
                .map(|socket| socket.attached.clone())
                .unwrap_or_default();
            self.tokens.insert(token.clone(), session);
            set(&mut frame, "token", json!(token));
            set(&mut frame, "token_expires", json!(86_400));
        }
        self.send(id, with_ref(frame, reference));
        self.push_all();
    }

    fn detach(&mut self, id: u64, key: &str, reason: &str) {
        if let Some(socket) = self.sockets.get_mut(&id) {
            socket.attached.remove(key);
        }
        for message in &mut self.messages {
            if message.key == key && matches!(message.phase, Phase::InFlight(owner) if owner == id)
            {
                message.phase = Phase::Pending;
            }
        }
        // Sessions that hold the mailbox no longer resume it.
        for keys in self.tokens.values_mut() {
            keys.remove(key);
        }
        self.send(
            id,
            json!({"type": "Detached", "mailbox": key, "reason": reason}).to_string(),
        );
    }

    fn pending(&self, key: &str) -> usize {
        self.messages
            .iter()
            .filter(|message| message.key == key && message.phase == Phase::Pending)
            .count()
    }

    fn waiting(&mut self, id: u64, reference: Option<&str>) {
        let Some(socket) = self.sockets.get(&id) else {
            return;
        };
        let mut waiting = serde_json::Map::new();
        for key in &socket.attached {
            let count = self.pending(key);
            if count > 0 {
                waiting.insert(key.clone(), json!(count));
            }
        }
        let inflight = self
            .messages
            .iter()
            .filter(|message| message.phase == Phase::InFlight(id))
            .count();
        let held = self
            .messages
            .iter()
            .filter(|message| matches!(message.phase, Phase::Held(_)))
            .count();
        let frame = json!({
            "type": "Ok", "waiting": waiting, "inflight": inflight, "held": held,
        });
        self.send(id, with_ref(frame, reference));
    }

    /// Sends pending mail to attached mailboxes, up to the in-flight limit of each socket.
    fn push_all(&mut self) {
        if self.stalling_pushes {
            return;
        }
        let ids: Vec<u64> = self.sockets.keys().copied().collect();
        for id in ids {
            self.push(id);
        }
    }

    fn push(&mut self, id: u64) {
        let Some(socket) = self.sockets.get(&id) else {
            return;
        };
        if !socket.mux {
            return;
        }
        let attached = socket.attached.clone();
        let cancel = socket.cancel;
        if cancel {
            self.push_cancels(id, &attached);
        }
        let mut inflight = self
            .messages
            .iter()
            .filter(|message| message.phase == Phase::InFlight(id))
            .count();
        let mut frames = Vec::new();
        for message in &mut self.messages {
            if inflight >= INFLIGHT_LIMIT && !self.ignoring_limit {
                break;
            }
            if message.phase == Phase::Pending && attached.contains(&message.key) {
                message.phase = Phase::InFlight(id);
                inflight = inflight.saturating_add(1);
                let mut mail = json!({
                    "type": "Mail", "mailbox": message.key, "id": message.id,
                    "from": message.from, "str": message.text,
                    "signature": message.signature, "created": 0,
                });
                if cancel && let Some(txid) = &message.txid {
                    set(&mut mail, "epicboxtxid", json!(txid));
                }
                frames.push(mail.to_string());
            }
        }
        for frame in frames {
            self.send(id, frame);
        }
    }
}

impl State {
    /// Pushes each unacknowledged cancel for an attached mailbox of socket `id`, once per
    /// attach.
    fn push_cancels(&mut self, id: u64, attached: &HashSet<String>) {
        let mut frames = Vec::new();
        for tombstone in &self.tombstones {
            let sent = (id, tombstone.key.clone(), tombstone.txid.clone());
            if tombstone.acked
                || !attached.contains(&tombstone.key)
                || self.cancel_sent.contains(&sent)
            {
                continue;
            }
            frames.push(sent);
        }
        for (socket, key, txid) in frames {
            self.cancel_sent.insert((socket, key.clone(), txid.clone()));
            let count = self.cancel_pushes.entry(txid.clone()).or_default();
            *count = count.saturating_add(1);
            self.send(
                id,
                json!({"type": "Cancelled", "mailbox": key, "epicboxtxid": txid}).to_string(),
            );
        }
    }
}

/// The bare key of an address a client attaches by: the part before `@`.
pub(crate) fn bare_key(address: &str) -> String {
    address.split('@').next().unwrap_or(address).to_owned()
}

fn signed_by(key_text: &str, network: Network, text: &str, signature_hex: &str) -> bool {
    let Ok(key) = decode_key(key_text, network) else {
        return false;
    };
    let Ok(signature) = lepic_crypto::EcdsaSignature::from_der_hex(signature_hex) else {
        return false;
    };
    verify_text(text, &signature, &key).is_ok()
}
