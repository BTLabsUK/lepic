// SPDX-License-Identifier: Apache-2.0
//! An in-process relay with the semantics of the public relay (`docs/compat/epicbox.md`), for
//! deterministic tests of the client, the engine and the bindings.
//!
//! It sends a challenge on connect, verifies `Subscribe`, `PostSlate` and `Made` signatures,
//! stores messages until `Made`, delivers the oldest pending message one at a time per socket,
//! redelivers an unacknowledged message to a new socket and, after three more subscribes, to the
//! same socket, discards an address's unacknowledged messages after three such rounds, keeps one
//! live listener per address, passes each newly posted message through to an idle listener,
//! answers the JSON `ping` with bare `pong` text, and closes sockets that send text that is not
//! JSON. A `Subscribe` for another address switches the socket to it, and `Made` is checked
//! against the address the socket last subscribed with, as on the public relay. Unlike the
//! public relay it stores every message itself instead of forwarding to other domains, and its
//! messages do not expire. All domains share one queue per key, unless
//! [`MockRelay::set_relays_apart`] makes each domain a relay of its own. Switches make it refuse
//! or stall connections, leave chosen frames unanswered, or stop reading a connection. Tests
//! wait on its state with [`MockRelay::wait_until`] instead of polling.

use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use futures_util::{SinkExt, StreamExt};
use lepic_transport::transport::BoxFuture;
use serde_json::{Value, json};
use tokio::io::DuplexStream;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::address::{EpicboxAddress, Network, decode_key};
use crate::crypto::{EncryptedMessage, SignedMessage, verify_text};
use crate::frame::{MAX_FRAME_LEN, PROTOCOL_VERSION};
use crate::session::{Connector, RelayEndpoint, RelayStream};

/// Buffer of each in-memory connection; writes beyond it wait for the reader.
const PIPE_CAPACITY: usize = 64 * 1024;

/// Close code the public relay uses for text that is not JSON.
const CLOSE_NOT_JSON: u16 = 3000;

/// Subscribes while a message is unacknowledged after which the relay sends it again on the same
/// socket, and redelivery rounds after which it discards the address's unacknowledged messages.
const RESEND_AFTER: u32 = 3;

/// The largest payload a websocket control frame carries.
const MAX_CONTROL_PAYLOAD: usize = 125;

/// Pings that fill a connection which is not read: their pongs exceed [`PIPE_CAPACITY`].
const FILL_PINGS: usize = 1024;

/// A frame the relay can be told to leave unanswered with [`MockRelay::set_unanswered`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unanswered {
    /// The challenge sent on connect and after each accepted `Made`.
    Challenge,
    ClientDetails,
    Subscribe,
    PostSlate,
    Made,
}

/// A relay shared by every connection made through its [`MockRelay::connector`].
#[derive(Clone)]
pub struct MockRelay {
    inner: Arc<Inner>,
}

struct Inner {
    network: Network,
    state: Mutex<RelayState>,
    /// Woken after every change that the relay's queries can report.
    changed: Notify,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stored {
    id: String,
    queue: String,
    from: String,
    str: String,
    signature: String,
    made: bool,
}

struct Socket {
    outgoing: mpsc::UnboundedSender<Outgoing>,
    challenge: String,
    listener_mode: bool,
    address: Option<String>,
    /// The relay domain the connection was made to; `None` for one served over TCP.
    domain: Option<String>,
    /// The queue the socket last subscribed to: its address, with the domain when relays are
    /// apart.
    queue: Option<String>,
    versioned: bool,
    /// The message this socket was sent and has not acknowledged.
    in_flight: Option<String>,
    /// Subscribes answered `Ok` while a message was in flight.
    resend_attempts: u32,
    /// Redeliveries made after `RESEND_AFTER` such subscribes.
    resend_rounds: u32,
    /// Frames still read before the socket stops reading, when that switch is set.
    reads_left: Option<usize>,
}

enum Outgoing {
    Text(String),
    Ping,
    StopReading,
    Close(u16),
}

struct RelayState {
    next_socket: u64,
    next_message: u64,
    next_challenge: u64,
    sockets: HashMap<u64, Socket>,
    listeners: HashMap<String, u64>,
    messages: Vec<Stored>,
    refusing: bool,
    /// Keys of addresses whose posts are never answered.
    unroutable: HashSet<String>,
    /// Keys of addresses whose posts are answered `InvalidRequest`.
    post_refused: HashSet<String>,
    /// Relay domains whose posts are answered `InvalidRequest`, whatever the key.
    domains_refused: HashSet<String>,
    /// Each domain keeps its own queues, as separate relays do.
    apart: bool,
    stalling: bool,
    stalled: Vec<DuplexStream>,
    unanswered: HashSet<Unanswered>,
    stop_reading_after: Option<usize>,
    version: Option<String>,
    received: HashMap<String, usize>,
    deliveries: HashMap<String, usize>,
    pings: usize,
}

impl MockRelay {
    /// A relay for addresses on `network` that reports protocol 3.0.0.
    pub fn new(network: Network) -> Self {
        Self {
            inner: Arc::new(Inner {
                network,
                state: Mutex::new(RelayState {
                    next_socket: 0,
                    next_message: 0,
                    next_challenge: 0,
                    sockets: HashMap::new(),
                    listeners: HashMap::new(),
                    messages: Vec::new(),
                    refusing: false,
                    unroutable: HashSet::new(),
                    domains_refused: HashSet::new(),
                    apart: false,
                    post_refused: HashSet::new(),
                    stalling: false,
                    stalled: Vec::new(),
                    unanswered: HashSet::new(),
                    stop_reading_after: None,
                    version: Some(PROTOCOL_VERSION.to_owned()),
                    received: HashMap::new(),
                    deliveries: HashMap::new(),
                    pings: 0,
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

    /// Serves websocket connections from `listener` until the task is aborted.
    pub fn serve(&self, listener: TcpListener) -> io::Result<JoinHandle<()>> {
        let runtime = Handle::try_current().map_err(io::Error::other)?;
        let relay = self.clone();
        Ok(runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                relay.accept(stream, None);
            }
        }))
    }

    /// Refuses new connections, as an unreachable relay does.
    pub fn set_refusing(&self, refusing: bool) {
        self.update(|state| state.refusing = refusing);
    }

    /// Leaves posts to `address` unanswered, as the relay does when it forwards a message to
    /// another domain that does not take it.
    pub fn set_unroutable(&self, address: &EpicboxAddress) {
        self.update(|state| {
            state.unroutable.insert(address.key_text());
        });
    }

    /// Answers posts to any address under relay `domain` with `InvalidRequest`, as the relay
    /// does when forwarding to a domain that does not answer.
    pub fn set_domain_refused(&self, domain: &str) {
        self.update(|state| {
            state.domains_refused.insert(domain.to_owned());
        });
    }

    /// Answers posts to `address` with `InvalidRequest`, as the relay does when forwarding a
    /// message to another domain fails.
    pub fn set_post_refused(&self, address: &EpicboxAddress) {
        self.update(|state| {
            state.post_refused.insert(address.key_text());
        });
    }

    /// Answers posts to `address` again, after [`Self::set_post_refused`].
    pub fn set_post_accepted(&self, address: &EpicboxAddress) {
        self.update(|state| {
            state.post_refused.remove(&address.key_text());
        });
    }

    /// Keeps one queue per relay domain from now on, as separate relays do: a message posted to
    /// `key@domain` reaches only connections made to `domain`. Off, every domain shares one
    /// queue per key. Messages stored before the switch stay in the queue they were stored in.
    pub fn set_relays_apart(&self, apart: bool) {
        self.update(|state| state.apart = apart);
    }

    /// Accepts new connections but never answers on them, as a relay stuck mid-handshake does.
    pub fn set_stalling(&self, stalling: bool) {
        self.update(|state| state.stalling = stalling);
    }

    /// Leaves `frame` unanswered from now on, or answers it again. A withheld challenge is
    /// never sent; a withheld request is counted by [`Self::received`] and otherwise ignored.
    pub fn set_unanswered(&self, frame: Unanswered, unanswered: bool) {
        self.update(|state| {
            if unanswered {
                state.unanswered.insert(frame);
            } else {
                state.unanswered.remove(&frame);
            }
        });
    }

    /// Stops reading every subscribed connection, as a relay whose process hangs does. Frames
    /// queued for it still go out, and the client's writes wait once the buffer is full.
    pub fn stop_reading_subscribed(&self) {
        self.send_to_subscribed(|| Outgoing::StopReading);
    }

    /// Sends `count` websocket pings with the largest payload to every subscribed connection.
    /// The client answers each with a pong, so this fills a connection that is not read.
    pub fn ping_subscribed(&self, count: usize) {
        for _ in 0..count {
            self.send_to_subscribed(|| Outgoing::Ping);
        }
    }

    /// Makes each connection opened from now on read `frames` protocol frames, then stop reading
    /// and fill itself with pings before it answers the last frame read, as a relay that hangs
    /// mid-conversation does. With `Some(0)` it stops before the first challenge; `None` restores
    /// normal reading.
    pub fn set_stop_reading_after(&self, frames: Option<usize>) {
        self.update(|state| state.stop_reading_after = frames);
    }

    // Not through `update`: nothing a query reports changes, so no `wait_until` needs waking.
    fn send_to_subscribed(&self, outgoing: impl Fn() -> Outgoing) {
        for socket in self.lock().sockets.values() {
            if socket.address.is_some() {
                let _ = socket.outgoing.send(outgoing());
            }
        }
    }

    /// The version `GetVersion` reports; `None` leaves `GetVersion` unanswered.
    pub fn set_version(&self, version: Option<&str>) {
        self.update(|state| state.version = version.map(str::to_owned));
    }

    /// Stores a message as if another wallet had posted it, and returns its message id.
    pub fn store(
        &self,
        from: &EpicboxAddress,
        to: &EpicboxAddress,
        message: &SignedMessage,
    ) -> String {
        self.update(|state| {
            let queue = state.queue_name(&to.key_text(), Some(to.domain().as_str()));
            let id = state.store(
                queue.clone(),
                from.to_string(),
                message.str.clone(),
                message.signature.to_der_hex(),
            );
            state.pass_through(&queue, &id);
            id
        })
    }

    /// How often the message with this id was sent to any socket.
    pub fn deliveries(&self, msg_id: &str) -> usize {
        self.lock().deliveries.get(msg_id).copied().unwrap_or(0)
    }

    /// Messages for `address` not yet acknowledged with `Made`.
    pub fn pending(&self, address: &EpicboxAddress) -> usize {
        let state = self.lock();
        let queue = state.queue_name(&address.key_text(), Some(address.domain().as_str()));
        state
            .messages
            .iter()
            .filter(|m| m.queue == queue && !m.made)
            .count()
    }

    /// Messages for `address` sent to a socket but not yet acknowledged with `Made`: in the
    /// hands of a client.
    pub fn in_hand(&self, address: &EpicboxAddress) -> usize {
        let state = self.lock();
        let queue = state.queue_name(&address.key_text(), Some(address.domain().as_str()));
        state
            .messages
            .iter()
            .filter(|m| m.queue == queue && !m.made && state.deliveries.contains_key(&m.id))
            .count()
    }

    /// Open websocket connections.
    pub fn connections(&self) -> usize {
        self.lock().sockets.len()
    }

    /// Frames received from clients with this `type`, compared without case as the relay does.
    pub fn received(&self, type_name: &str) -> usize {
        self.lock()
            .received
            .get(&type_name.to_ascii_lowercase())
            .copied()
            .unwrap_or(0)
    }

    /// Websocket ping frames received from clients.
    pub fn pings(&self) -> usize {
        self.lock().pings
    }

    /// Sends `text` as is to every open connection.
    pub fn broadcast(&self, text: &str) {
        for socket in self.lock().sockets.values() {
            let _ = socket.outgoing.send(Outgoing::Text(text.to_owned()));
        }
    }

    /// Sends a fresh challenge to every subscribed connection, as the relay's interval does.
    pub fn send_challenges(&self) {
        self.update(|state| {
            let ids: Vec<u64> = state
                .sockets
                .iter()
                .filter(|(_, socket)| socket.address.is_some())
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                state.challenge(id);
            }
        });
    }

    /// Drops every message not yet acknowledged and returns how many, as the relay does with
    /// messages it has kept for 7 days.
    pub fn expire_all(&self) -> usize {
        self.update(|state| {
            let before = state.messages.len();
            state.messages.retain(|m| m.made);
            before.saturating_sub(state.messages.len())
        })
    }

    /// Closes every connection and keeps every stored message, as a relay restart does.
    pub fn disconnect_all(&self) {
        self.update(|state| {
            for socket in state.sockets.values() {
                let _ = socket.outgoing.send(Outgoing::Close(1001));
            }
            state.sockets.clear();
            state.listeners.clear();
            state.stalled.clear();
        });
    }

    /// Resolves once `condition` holds. It is checked now and again after every change the
    /// relay's queries can report, so a test waits on what the relay saw rather than on time.
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

    // Every update leaves the state consistent before it can panic, so a poisoned lock is still
    // safe to use.
    fn lock(&self) -> MutexGuard<'_, RelayState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Applies `change` and wakes every [`Self::wait_until`].
    fn update<T>(&self, change: impl FnOnce(&mut RelayState) -> T) -> T {
        let result = change(&mut self.lock());
        self.inner.changed.notify_waiters();
        result
    }

    fn accept<S>(&self, stream: S, domain: Option<String>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let relay = self.clone();
        let Ok(runtime) = Handle::try_current() else {
            return;
        };
        runtime.spawn(async move { relay.run_socket(stream, domain).await });
    }

    async fn run_socket<S>(self, stream: S, domain: Option<String>)
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
        let id = self.update(|state| {
            let id = state.next_socket;
            state.next_socket = state.next_socket.wrapping_add(1);
            state.sockets.insert(
                id,
                Socket {
                    outgoing,
                    challenge: String::new(),
                    listener_mode: false,
                    address: None,
                    domain,
                    queue: None,
                    versioned: false,
                    in_flight: None,
                    resend_attempts: 0,
                    resend_rounds: 0,
                    reads_left: state.stop_reading_after,
                },
            );
            state.count_read(id, 0);
            state.challenge(id);
            id
        });
        let mut reading = true;
        loop {
            tokio::select! {
                next = queued.recv() => match next {
                    Some(Outgoing::Text(text)) => {
                        if ws.send(Message::text(text)).await.is_err() {
                            break;
                        }
                    }
                    Some(Outgoing::Ping) => {
                        let payload = vec![0_u8; MAX_CONTROL_PAYLOAD];
                        if ws.send(Message::Ping(payload.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(Outgoing::StopReading) => reading = false,
                    Some(Outgoing::Close(code)) => {
                        let frame = CloseFrame { code: CloseCode::from(code), reason: "".into() };
                        let _ = ws.send(Message::Close(Some(frame))).await;
                        break;
                    }
                    None => break,
                },
                incoming = ws.next(), if reading => match incoming {
                    Some(Ok(Message::Text(text))) => {
                        self.update(|state| {
                            state.count_read(id, 1);
                            state.handle(id, self.inner.network, text.as_str());
                        });
                    }
                    Some(Ok(Message::Ping(_))) => {
                        self.update(|state| state.pings = state.pings.saturating_add(1));
                    }
                    Some(Ok(Message::Binary(_) | Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                },
            }
        }
        self.update(|state| state.drop_socket(id));
    }
}

impl std::fmt::Debug for MockRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockRelay")
            .field("network", &self.inner.network)
            .finish_non_exhaustive()
    }
}

struct MockConnector {
    relay: MockRelay,
}

impl Connector for MockConnector {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        Box::pin(async move {
            let (client, server) = tokio::io::duplex(PIPE_CAPACITY);
            {
                let mut state = self.relay.lock();
                if state.refusing {
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                if state.stalling {
                    state.stalled.push(server);
                    return Ok(Box::new(client) as Box<dyn RelayStream>);
                }
            }
            self.relay
                .accept(server, Some(endpoint.domain().as_str().to_owned()));
            Ok(Box::new(client) as Box<dyn RelayStream>)
        })
    }
}

fn text_field<'a>(message: &'a Value, name: &str) -> &'a str {
    message.get(name).and_then(Value::as_str).unwrap_or("")
}

fn ok() -> String {
    json!({"type": "Ok"}).to_string()
}

fn error(kind: &str, description: &str) -> String {
    json!({"type": "Error", "kind": kind, "description": description}).to_string()
}

impl RelayState {
    fn send(&self, id: u64, text: String) {
        if let Some(socket) = self.sockets.get(&id) {
            let _ = socket.outgoing.send(Outgoing::Text(text));
        }
    }

    /// Counts `frames` read from socket `id`. Once its reads are used up it stops reading and
    /// queues pings ahead of anything it answers next, so the client's next write waits.
    fn count_read(&mut self, id: u64, frames: usize) {
        let Some(socket) = self.sockets.get_mut(&id) else {
            return;
        };
        let Some(left) = socket.reads_left else {
            return;
        };
        let left = left.saturating_sub(frames);
        if left > 0 {
            socket.reads_left = Some(left);
            return;
        }
        socket.reads_left = None;
        let _ = socket.outgoing.send(Outgoing::StopReading);
        for _ in 0..FILL_PINGS {
            let _ = socket.outgoing.send(Outgoing::Ping);
        }
    }

    fn challenge(&mut self, id: u64) {
        self.next_challenge = self.next_challenge.wrapping_add(1);
        let challenge = format!("mock-challenge-{}", self.next_challenge);
        if let Some(socket) = self.sockets.get_mut(&id) {
            socket.challenge.clone_from(&challenge);
        }
        if self.unanswered.contains(&Unanswered::Challenge) {
            return;
        }
        self.send(
            id,
            json!({"type": "Challenge", "str": challenge}).to_string(),
        );
    }

    fn drop_socket(&mut self, id: u64) {
        if let Some(socket) = self.sockets.remove(&id)
            && let Some(queue) = socket.queue
            && self.listeners.get(&queue) == Some(&id)
        {
            self.listeners.remove(&queue);
        }
    }

    /// The queue of messages for `key` posted to `domain`: one per key, or one per key and
    /// domain when relays are apart.
    fn queue_name(&self, key: &str, domain: Option<&str>) -> String {
        match domain {
            Some(domain) if self.apart => format!("{key}@{domain}"),
            _ => key.to_owned(),
        }
    }

    fn handle(&mut self, id: u64, network: Network, text: &str) {
        let Ok(message) = serde_json::from_str::<Value>(text) else {
            if let Some(socket) = self.sockets.get(&id) {
                let _ = socket.outgoing.send(Outgoing::Close(CLOSE_NOT_JSON));
            }
            return;
        };
        let Some(type_name) = message.get("type").and_then(Value::as_str) else {
            if let Some(socket) = self.sockets.get(&id) {
                let _ = socket.outgoing.send(Outgoing::Close(CLOSE_NOT_JSON));
            }
            return;
        };
        let type_name = type_name.to_ascii_lowercase();
        let count = self.received.entry(type_name.clone()).or_default();
        *count = count.saturating_add(1);
        let withheld = match type_name.as_str() {
            "clientdetails" => Some(Unanswered::ClientDetails),
            "subscribe" => Some(Unanswered::Subscribe),
            "postslate" => Some(Unanswered::PostSlate),
            "made" => Some(Unanswered::Made),
            _ => None,
        };
        if withheld.is_some_and(|frame| self.unanswered.contains(&frame)) {
            return;
        }
        match type_name.as_str() {
            "ping" => self.send(id, "pong".to_owned()),
            "clientdetails" => {
                if let Some(socket) = self.sockets.get_mut(&id) {
                    socket.listener_mode = text_field(&message, "wallet_mode") == "listener";
                }
                self.send(id, ok());
            }
            "getversion" => {
                if let Some(version) = self.version.clone() {
                    self.send(
                        id,
                        json!({"type": "GetVersion", "str": version}).to_string(),
                    );
                }
            }
            "subscribe" => self.subscribe(id, network, &message),
            "postslate" => self.post_slate(id, network, &message),
            "made" => self.made(id, network, &message),
            "unsubscribe" => {
                if let Some(socket) = self.sockets.get(&id) {
                    let _ = socket.outgoing.send(Outgoing::Close(1000));
                }
            }
            _ => {}
        }
    }

    fn subscribe(&mut self, id: u64, network: Network, message: &Value) {
        let address = text_field(message, "address").to_owned();
        let domain = self
            .sockets
            .get(&id)
            .and_then(|socket| socket.domain.clone());
        let queue = self.queue_name(&address, domain.as_deref());
        let Some(socket) = self.sockets.get_mut(&id) else {
            return;
        };
        if message.get("ver").is_some() {
            socket.versioned = true;
        }
        if !signed_by(
            &address,
            network,
            &socket.challenge,
            text_field(message, "signature"),
        ) {
            if socket.queue.as_deref() == Some(queue.as_str())
                && self.listeners.get(&queue) == Some(&id)
            {
                self.listeners.remove(&queue);
            }
            socket.address = None;
            socket.queue = None;
            self.send(id, error("InvalidSignature", "Invalid signature."));
            return;
        }
        socket.address = Some(address);
        socket.queue = Some(queue.clone());
        // The public relay retries an unacknowledged message on the same socket after a few
        // subscribes, and gives up on the address's unacknowledged messages after a few rounds.
        if socket.resend_attempts >= RESEND_AFTER && socket.resend_rounds <= RESEND_AFTER {
            socket.resend_attempts = 0;
            socket.resend_rounds = socket.resend_rounds.saturating_add(1);
            socket.in_flight = None;
        }
        let discard = socket.resend_rounds >= RESEND_AFTER;
        if discard {
            socket.resend_attempts = 0;
            socket.resend_rounds = 0;
            socket.in_flight = None;
        }
        let listener_mode = socket.listener_mode;
        let in_flight = socket.in_flight.is_some();
        if in_flight {
            socket.resend_attempts = socket.resend_attempts.saturating_add(1);
        }
        if listener_mode {
            self.listeners.entry(queue.clone()).or_insert(id);
        }
        if discard {
            self.messages.retain(|m| m.queue != queue || m.made);
        }
        if in_flight {
            self.send(id, ok());
            return;
        }
        let oldest = self
            .messages
            .iter()
            .find(|m| m.queue == queue && !m.made)
            .cloned();
        match oldest {
            Some(stored) => self.deliver(id, &stored),
            None => self.send(id, ok()),
        }
    }

    fn deliver(&mut self, id: u64, stored: &Stored) {
        let Some(socket) = self.sockets.get_mut(&id) else {
            return;
        };
        socket.in_flight = Some(stored.id.clone());
        let count = self.deliveries.entry(stored.id.clone()).or_default();
        *count = count.saturating_add(1);
        let mut slate = json!({
            "type": "Slate",
            "from": stored.from,
            "str": stored.str,
            "signature": stored.signature,
            "challenge": "",
        });
        if socket.versioned
            && let Some(fields) = slate.as_object_mut()
        {
            fields.insert("epicboxmsgid".to_owned(), Value::from(stored.id.clone()));
            fields.insert("ver".to_owned(), Value::from(PROTOCOL_VERSION));
        }
        self.send(id, slate.to_string());
    }

    fn store(&mut self, queue: String, from: String, str: String, signature: String) -> String {
        self.next_message = self.next_message.wrapping_add(1);
        let id = format!("mockmsg{}", self.next_message);
        self.messages.push(Stored {
            id: id.clone(),
            queue,
            from,
            str,
            signature,
            made: false,
        });
        id
    }

    /// Hands the message just stored to the address's live listener, if it is idle, as the
    /// public relay does.
    fn pass_through(&mut self, queue: &str, msg_id: &str) {
        let Some(&listener) = self.listeners.get(queue) else {
            return;
        };
        let idle = self
            .sockets
            .get(&listener)
            .is_some_and(|socket| socket.in_flight.is_none());
        if !idle {
            return;
        }
        if let Some(stored) = self.messages.iter().find(|m| m.id == msg_id).cloned() {
            self.deliver(listener, &stored);
        }
    }

    fn post_slate(&mut self, id: u64, network: Network, message: &Value) {
        let from = text_field(message, "from");
        let to = text_field(message, "to");
        let (Ok(sender), Ok(recipient)) = (
            EpicboxAddress::parse(from, network),
            EpicboxAddress::parse(to, network),
        ) else {
            self.send(id, error("InvalidRequest", "Wrong address format."));
            return;
        };
        if self.unroutable.contains(&recipient.key_text()) {
            return;
        }
        if self.post_refused.contains(&recipient.key_text())
            || self.domains_refused.contains(recipient.domain().as_str())
        {
            self.send(
                id,
                error("InvalidRequest", "Error forward slate to foreign epicbox."),
            );
            return;
        }
        let str = text_field(message, "str");
        let signature = text_field(message, "signature");
        if !signed_by(&sender.key_text(), network, str, signature) {
            self.send(id, error("InvalidRequest", "Error postslate signature."));
            return;
        }
        let Ok(encrypted) = EncryptedMessage::from_json(str) else {
            self.send(id, error("InvalidRequest", "Error parsing message string."));
            return;
        };
        let queue = self.queue_name(
            encrypted.destination().public_key(),
            Some(recipient.domain().as_str()),
        );
        let msg_id = self.store(
            queue.clone(),
            from.to_owned(),
            str.to_owned(),
            signature.to_owned(),
        );
        self.send(id, ok());
        self.pass_through(&queue, &msg_id);
    }

    fn made(&mut self, id: u64, network: Network, message: &Value) {
        let Some((address, queue)) = self
            .sockets
            .get(&id)
            .and_then(|s| s.address.clone().zip(s.queue.clone()))
        else {
            return;
        };
        let msg_id = text_field(message, "epicboxmsgid");
        if message.get("epicboxmsgid").is_none() || text_field(message, "ver") != PROTOCOL_VERSION {
            return;
        }
        if !signed_by(&address, network, msg_id, text_field(message, "signature")) {
            self.send(id, error("InvalidSignature", "Invalid signature."));
            return;
        }
        for stored in &mut self.messages {
            if stored.queue == queue && stored.id == msg_id {
                stored.made = true;
            }
        }
        if let Some(socket) = self.sockets.get_mut(&id) {
            socket.in_flight = None;
            socket.resend_attempts = 0;
        }
        self.send(id, ok());
        self.challenge(id);
    }
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
