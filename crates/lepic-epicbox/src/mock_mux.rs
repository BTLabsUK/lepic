// SPDX-License-Identifier: Apache-2.0
//! An in-process relay that speaks mux/1 (the relay's `docs/mux-1.md`), for tests of
//! [`crate::MuxSession`].
//!
//! It offers the extension when asked, sends a 22-character challenge, verifies each `Attach`
//! signature against it, issues single-use resume tokens that a restart forgets, pushes stored
//! mail up to the in-flight limit and answers `Ack`, `Hold`, `Detach` and `Waiting`. Switches
//! make it refuse the extension, send a challenge of the wrong shape, stop pushing, drop
//! sockets, send `Detached`, or answer attaches with `rate_limited`. It records every frame it
//! receives. Tests wait on its state with [`MuxMockRelay::wait_until`].

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
use crate::frame::{ClientFrame, MAX_FRAME_LEN};
use crate::mux_frame::{AttachEntry, MuxClientFrame};
use crate::session::{Connector, RelayEndpoint, RelayStream};

const PIPE_CAPACITY: usize = 64 * 1024;

/// The in-flight limit the relay announces.
const INFLIGHT_LIMIT: usize = 32;

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

struct StoredMail {
    id: String,
    key: String,
    from: String,
    text: String,
    signature: String,
    phase: Phase,
}

struct Socket {
    outgoing: mpsc::UnboundedSender<Outgoing>,
    challenge: String,
    mux: bool,
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
    stalling_pushes: bool,
    first_challenge: bool,
    rate_limited: Option<(u32, u64)>,
    received: Vec<Value>,
    sockets_made: u64,
    signatures_checked: u64,
    resumes_accepted: u64,
    acked: Vec<String>,
    held: Vec<(String, u64)>,
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
                    stalling_pushes: false,
                    first_challenge: true,
                    rate_limited: None,
                    received: Vec::new(),
                    sockets_made: 0,
                    signatures_checked: 0,
                    resumes_accepted: 0,
                    acked: Vec::new(),
                    held: Vec::new(),
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

    /// Sends a negotiation challenge of the wrong shape from now on.
    pub fn set_bad_challenge(&self, bad: bool) {
        self.update(|state| state.bad_challenge = bad);
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

    /// Whether a socket gets the 3.0.0 `Challenge` on connect, as the public relay sends it.
    pub fn send_first_challenge(&self, send: bool) {
        self.update(|state| state.first_challenge = send);
    }

    /// Answers the next `attempts` `Attach` or `Resume` frames with `rate_limited`.
    pub fn rate_limit_attaches(&self, attempts: u32, retry_after_secs: u64) {
        self.update(|state| state.rate_limited = Some((attempts, retry_after_secs)));
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
            });
            state.push_all();
            id
        })
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
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_))) => {}
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

fn error(kind: &str, code: &str, reference: Option<&str>, retry_after: Option<u64>) -> String {
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

fn with_ref(mut frame: Value, reference: Option<&str>) -> String {
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
                attached: HashSet::new(),
            },
        );
        if self.first_challenge {
            self.send(
                id,
                json!({"type": "Challenge", "str": "mock-classic-challenge"}).to_string(),
            );
        }
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
            Ok(None) => {
                if let Ok(ClientFrame::ClientDetails { ext, .. }) = ClientFrame::from_json(text) {
                    self.negotiate(id, ext.as_ref());
                }
            }
            Err(_) => self.send(id, error("InvalidRequest", "bad_frame", None, None)),
        }
    }

    fn negotiate(&mut self, id: u64, ext: Option<&Vec<String>>) {
        let asked = ext.is_some_and(|ext| ext.iter().any(|name| name == "mux/1"));
        if !(asked && self.offering) {
            self.send(id, json!({"type": "Ok"}).to_string());
            return;
        }
        let bad = self.bad_challenge;
        let Some(socket) = self.sockets.get_mut(&id) else {
            return;
        };
        socket.mux = true;
        let challenge = if bad {
            BAD_CHALLENGE.to_owned()
        } else {
            socket.challenge.clone()
        };
        self.send(
            id,
            json!({
                "type": "Ok",
                "ext": ["mux/1"],
                "challenge": challenge,
                "limits": {
                    "attach_per_frame": 64,
                    "mailboxes_per_socket": 256,
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
        }
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
        let challenge = self
            .sockets
            .get(&id)
            .map(|socket| socket.challenge.clone())
            .unwrap_or_default();
        let mut entries = Vec::new();
        let mut accepted = Vec::new();
        for entry in mailboxes {
            let key = bare_key(&entry.address);
            if signed_by(&key, network, &challenge, &entry.signature) {
                self.signatures_checked = self.signatures_checked.saturating_add(1);
                accepted.push(key.clone());
                entries.push(json!({"mailbox": key, "ok": true, "waiting": self.pending(&key)}));
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
        let mut inflight = self
            .messages
            .iter()
            .filter(|message| message.phase == Phase::InFlight(id))
            .count();
        let mut frames = Vec::new();
        for message in &mut self.messages {
            if inflight >= INFLIGHT_LIMIT {
                break;
            }
            if message.phase == Phase::Pending && attached.contains(&message.key) {
                message.phase = Phase::InFlight(id);
                inflight = inflight.saturating_add(1);
                frames.push(
                    json!({
                        "type": "Mail", "mailbox": message.key, "id": message.id,
                        "from": message.from, "str": message.text,
                        "signature": message.signature, "created": 0,
                    })
                    .to_string(),
                );
            }
        }
        for frame in frames {
            self.send(id, frame);
        }
    }
}

/// The bare key of an address a client attaches by: the part before `@`.
fn bare_key(address: &str) -> String {
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
