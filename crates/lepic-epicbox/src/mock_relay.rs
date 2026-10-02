//! An in-process relay with the semantics of the public relay (`docs/compat/epicbox.md`), for
//! deterministic tests of the client, the engine and the bindings.
//!
//! It sends a challenge on connect, verifies `Subscribe`, `PostSlate` and `Made` signatures,
//! stores messages until `Made`, delivers the oldest pending message one at a time per socket,
//! redelivers to a socket that subscribes while a message is unacknowledged, keeps one live
//! listener per address, passes new messages through to that listener, answers the JSON `ping`
//! with bare `pong` text, and closes sockets that send text that is not JSON. Unlike the public
//! relay it stores every message itself instead of forwarding to other domains.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use futures_util::{SinkExt, StreamExt};
use lepic_transport::transport::BoxFuture;
use serde_json::{Value, json};
use tokio::io::DuplexStream;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
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

/// A relay shared by every connection made through its [`MockRelay::connector`].
#[derive(Clone)]
pub struct MockRelay {
    inner: Arc<Inner>,
}

struct Inner {
    network: Network,
    state: Mutex<RelayState>,
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
    versioned: bool,
    /// The message this socket was sent and has not acknowledged.
    in_flight: Option<String>,
}

enum Outgoing {
    Text(String),
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
    stalling: bool,
    stalled: Vec<DuplexStream>,
    version: Option<String>,
    received: HashMap<String, usize>,
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
                    stalling: false,
                    stalled: Vec::new(),
                    version: Some(PROTOCOL_VERSION.to_owned()),
                    received: HashMap::new(),
                    pings: 0,
                }),
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
                relay.accept(stream);
            }
        }))
    }

    /// Refuses new connections, as an unreachable relay does.
    pub fn set_refusing(&self, refusing: bool) {
        self.lock().refusing = refusing;
    }

    /// Accepts new connections but never answers on them, as a relay stuck mid-handshake does.
    pub fn set_stalling(&self, stalling: bool) {
        self.lock().stalling = stalling;
    }

    /// The version `GetVersion` reports; `None` leaves `GetVersion` unanswered.
    pub fn set_version(&self, version: Option<&str>) {
        self.lock().version = version.map(str::to_owned);
    }

    /// Stores a message as if another wallet had posted it, and returns its message id.
    pub fn store(
        &self,
        from: &EpicboxAddress,
        to: &EpicboxAddress,
        message: &SignedMessage,
    ) -> String {
        let mut state = self.lock();
        let id = state.store(
            to.key_text(),
            from.to_string(),
            message.str.clone(),
            message.signature.to_der_hex(),
        );
        state.pass_through(&to.key_text());
        id
    }

    /// Messages for `address` not yet acknowledged with `Made`.
    pub fn pending(&self, address: &EpicboxAddress) -> usize {
        let queue = address.key_text();
        self.lock()
            .messages
            .iter()
            .filter(|m| m.queue == queue && !m.made)
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
        let mut state = self.lock();
        let ids: Vec<u64> = state
            .sockets
            .iter()
            .filter(|(_, socket)| socket.address.is_some())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            state.challenge(id);
        }
    }

    /// Closes every connection and keeps every stored message, as a relay restart does.
    pub fn disconnect_all(&self) {
        let mut state = self.lock();
        for socket in state.sockets.values() {
            let _ = socket.outgoing.send(Outgoing::Close(1001));
        }
        state.sockets.clear();
        state.listeners.clear();
        state.stalled.clear();
    }

    // Every update leaves the state consistent before it can panic, so a poisoned lock is still
    // safe to use.
    fn lock(&self) -> MutexGuard<'_, RelayState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn accept<S>(&self, stream: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let relay = self.clone();
        let Ok(runtime) = Handle::try_current() else {
            return;
        };
        runtime.spawn(async move { relay.run_socket(stream).await });
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
        let id = {
            let mut state = self.lock();
            let id = state.next_socket;
            state.next_socket = state.next_socket.wrapping_add(1);
            state.sockets.insert(
                id,
                Socket {
                    outgoing,
                    challenge: String::new(),
                    listener_mode: false,
                    address: None,
                    versioned: false,
                    in_flight: None,
                },
            );
            state.challenge(id);
            id
        };
        loop {
            tokio::select! {
                next = queued.recv() => match next {
                    Some(Outgoing::Text(text)) => {
                        if ws.send(Message::text(text)).await.is_err() {
                            break;
                        }
                    }
                    Some(Outgoing::Close(code)) => {
                        let frame = CloseFrame { code: CloseCode::from(code), reason: "".into() };
                        let _ = ws.send(Message::Close(Some(frame))).await;
                        break;
                    }
                    None => break,
                },
                incoming = ws.next() => match incoming {
                    Some(Ok(Message::Text(text))) => self.lock().handle(id, self.inner.network, text.as_str()),
                    Some(Ok(Message::Ping(_))) => {
                        let mut state = self.lock();
                        state.pings = state.pings.saturating_add(1);
                    }
                    Some(Ok(Message::Binary(_) | Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                },
            }
        }
        self.lock().drop_socket(id);
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
        _endpoint: &'a RelayEndpoint,
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
            self.relay.accept(server);
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

    fn challenge(&mut self, id: u64) {
        self.next_challenge = self.next_challenge.wrapping_add(1);
        let challenge = format!("mock-challenge-{}", self.next_challenge);
        if let Some(socket) = self.sockets.get_mut(&id) {
            socket.challenge.clone_from(&challenge);
        }
        self.send(
            id,
            json!({"type": "Challenge", "str": challenge}).to_string(),
        );
    }

    fn drop_socket(&mut self, id: u64) {
        if let Some(socket) = self.sockets.remove(&id)
            && let Some(address) = socket.address
            && self.listeners.get(&address) == Some(&id)
        {
            self.listeners.remove(&address);
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
            if socket.address.as_deref() == Some(address.as_str())
                && self.listeners.get(&address) == Some(&id)
            {
                self.listeners.remove(&address);
            }
            socket.address = None;
            self.send(id, error("InvalidSignature", "Invalid signature."));
            return;
        }
        socket.address = Some(address.clone());
        let listener_mode = socket.listener_mode;
        let in_flight = socket.in_flight.is_some();
        if listener_mode {
            self.listeners.entry(address.clone()).or_insert(id);
        }
        if in_flight {
            self.send(id, ok());
            return;
        }
        let oldest = self
            .messages
            .iter()
            .find(|m| m.queue == address && !m.made)
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

    /// Hands the oldest pending message to the address's live listener, if it is idle.
    fn pass_through(&mut self, queue: &str) {
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
        if let Some(stored) = self
            .messages
            .iter()
            .find(|m| m.queue == queue && !m.made)
            .cloned()
        {
            self.deliver(listener, &stored);
        }
    }

    fn post_slate(&mut self, id: u64, network: Network, message: &Value) {
        let from = text_field(message, "from");
        let to = text_field(message, "to");
        let (Ok(sender), Ok(_)) = (
            EpicboxAddress::parse(from, network),
            EpicboxAddress::parse(to, network),
        ) else {
            self.send(id, error("InvalidRequest", "Wrong address format."));
            return;
        };
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
        let queue = encrypted.destination().public_key().to_owned();
        self.store(
            queue.clone(),
            from.to_owned(),
            str.to_owned(),
            signature.to_owned(),
        );
        self.send(id, ok());
        self.pass_through(&queue);
    }

    fn made(&mut self, id: u64, network: Network, message: &Value) {
        let Some(address) = self.sockets.get(&id).and_then(|s| s.address.clone()) else {
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
            if stored.queue == address && stored.id == msg_id {
                stored.made = true;
            }
        }
        if let Some(socket) = self.sockets.get_mut(&id) {
            socket.in_flight = None;
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
