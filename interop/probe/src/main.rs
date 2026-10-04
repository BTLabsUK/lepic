//! A small Epicbox client for checking what the public relay and a stock `epic-wallet` listener
//! do with the messages LEPIC plans to send. It speaks raw relay frames through the frame and
//! message types of `lepic-epicbox`, so each step is visible and nothing is retried or hidden.
//!
//!   lepic-interop-probe key <key-file> <relay-url>
//!       creates the key file if missing and prints the probe's address
//!   lepic-interop-probe post <key-file> <relay-url> <to-address> <payload-file>
//!       encrypts the payload to the address, posts it and prints the relay's answer
//!   lepic-interop-probe drain <key-file> <relay-url> <out-dir> <want> <seconds>
//!       subscribes, acknowledges and saves every message until `want` arrived or the time is up
//!   lepic-interop-probe sessions <relay-url>
//!       how the relay treats two addresses on one socket and on two sockets
//!   lepic-interop-probe decode <slate-file>
//!       what the Epicbox format policy decodes the file as
//!
//! Output is one JSON document on stdout.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::transport::EpicboxPolicy;
use lepic_epicbox::{
    ClientFrame, Domain, EpicboxAddress, Network, Nonce, ReceivedMessage, RelayFrame,
    RelayMessageId, SignedMessage, SlateFrame, WalletMode,
};
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::origin::WireOrigin;
use lepic_slate::registry::CodecRegistry;
use lepic_transport::policy::FormatPolicy;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

const ANSWER_WAIT: Duration = Duration::from_secs(10);
/// The stack runs on usernet, where `epic-wallet` derives mainnet addresses.
const NETWORK: Network = Network::Mainnet;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = match words.as_slice() {
        ["key", key_file, relay] => {
            let relay = Relay::parse(relay)?;
            let identity = Identity::load_or_create(Path::new(key_file), &relay)?;
            json!({ "address": identity.address.to_string() })
        }
        ["post", key_file, relay, to, payload] => {
            let relay = Relay::parse(relay)?;
            let identity = Identity::load(Path::new(key_file), &relay)?;
            let to = EpicboxAddress::parse(to, NETWORK).context("destination address")?;
            let payload = std::fs::read_to_string(payload).context("payload file")?;
            post(&relay, &identity, &to, &payload).await?
        }
        ["drain", key_file, relay, out_dir, want, seconds] => {
            let relay = Relay::parse(relay)?;
            let identity = Identity::load(Path::new(key_file), &relay)?;
            let want: usize = want.parse().context("message count")?;
            let seconds: u64 = seconds.parse().context("seconds")?;
            drain(&relay, &identity, Path::new(out_dir), want, seconds).await?
        }
        ["sessions", relay] => sessions(&Relay::parse(relay)?).await?,
        ["decode", file] => decode(Path::new(file))?,
        _ => bail!("usage: see the comment at the top of interop/probe/src/main.rs"),
    };
    println!("{output}");
    Ok(())
}

/// A plain `ws://` relay on a loopback host, as the interop stack publishes it.
struct Relay {
    host: String,
    port: u16,
}

impl Relay {
    fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("ws://")
            .context("relay url must start with ws://")?;
        let (host, port) = rest.split_once(':').context("relay url needs a port")?;
        Ok(Self {
            host: host.to_owned(),
            port: port.trim_end_matches('/').parse().context("relay port")?,
        })
    }

    fn url(&self) -> String {
        format!("ws://{}:{}", self.host, self.port)
    }
}

struct Identity {
    secret: SecretKey,
    address: EpicboxAddress,
}

impl Identity {
    fn random(relay: &Relay) -> Result<Self> {
        loop {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).context("randomness")?;
            if let Ok(secret) = SecretKey::from_array(bytes) {
                return Self::from_secret(secret, relay);
            }
        }
    }

    fn from_secret(secret: SecretKey, relay: &Relay) -> Result<Self> {
        let public = PublicKey::from_secret_key(&secret).context("public key")?;
        let domain = Domain::parse(&relay.host).context("relay host")?;
        let address = EpicboxAddress::new(public, NETWORK, domain, Some(relay.port));
        Ok(Self { secret, address })
    }

    fn load(path: &Path, relay: &Relay) -> Result<Self> {
        let hex = std::fs::read_to_string(path).with_context(|| format!("key file {path:?}"))?;
        let secret = SecretKey::from_hex(hex.trim()).context("key file content")?;
        Self::from_secret(secret, relay)
    }

    fn load_or_create(path: &Path, relay: &Relay) -> Result<Self> {
        if path.exists() {
            return Self::load(path, relay);
        }
        let identity = Self::random(relay)?;
        let hex: String = identity
            .secret
            .expose_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        write_private(path, &hex)?;
        Ok(identity)
    }
}

#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {path:?}"))?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("create {path:?}"))
}

/// One websocket to the relay, with every frame it sent kept in order for the report.
struct Session {
    ws: WebSocketStream<TcpStream>,
    challenge: String,
    transcript: Vec<Value>,
}

impl Session {
    async fn open(relay: &Relay, mode: WalletMode) -> Result<Self> {
        let stream = TcpStream::connect((relay.host.as_str(), relay.port))
            .await
            .context("connect to the relay")?;
        let (ws, _) = tokio_tungstenite::client_async(relay.url(), stream)
            .await
            .context("websocket handshake")?;
        let mut session = Self {
            ws,
            challenge: String::new(),
            transcript: Vec::new(),
        };
        session.next_challenge().await?;
        session
            .send(&ClientFrame::client_details("probe", mode))
            .await?;
        session.expect_ok().await?;
        Ok(session)
    }

    async fn send(&mut self, frame: &ClientFrame) -> Result<()> {
        self.ws
            .send(Message::text(frame.to_json()?))
            .await
            .context("send a frame")
    }

    /// The next protocol frame before `deadline`, or `None` when the time ran out.
    async fn receive_until(&mut self, deadline: Instant) -> Result<Option<RelayFrame>> {
        loop {
            let message = match timeout_at(deadline, self.ws.next()).await {
                Err(_) => return Ok(None),
                Ok(None) => bail!("the relay closed the connection"),
                Ok(Some(message)) => message.context("read a frame")?,
            };
            let Message::Text(text) = message else {
                continue;
            };
            let frame = RelayFrame::from_json(text.as_str())?;
            if matches!(frame, RelayFrame::Keepalive) {
                continue;
            }
            self.transcript.push(describe(&frame));
            if let RelayFrame::Challenge { str } = &frame {
                self.challenge.clone_from(str);
            }
            return Ok(Some(frame));
        }
    }

    async fn receive(&mut self) -> Result<RelayFrame> {
        self.receive_until(Instant::now() + ANSWER_WAIT)
            .await?
            .context("no answer from the relay")
    }

    async fn next_challenge(&mut self) -> Result<()> {
        loop {
            if let RelayFrame::Challenge { .. } = self.receive().await? {
                return Ok(());
            }
        }
    }

    async fn expect_ok(&mut self) -> Result<()> {
        match self.receive().await? {
            RelayFrame::Ok => Ok(()),
            other => bail!("expected Ok, got {}", describe(&other)),
        }
    }

    async fn subscribe(&mut self, identity: &Identity) -> Result<()> {
        let frame = ClientFrame::subscribe(&identity.address, &self.challenge, &identity.secret)?;
        self.send(&frame).await
    }

    /// The answer to a subscribe: the pending message, or `None` when the relay said `Ok`.
    async fn subscribe_answer(&mut self) -> Result<Option<SlateFrame>> {
        loop {
            match self.receive().await? {
                RelayFrame::Slate(slate) => return Ok(Some(slate)),
                RelayFrame::Ok => return Ok(None),
                RelayFrame::Error { kind, description } => {
                    bail!("subscribe refused: {kind:?}: {description}")
                }
                _ => {}
            }
        }
    }

    /// Sends `Made` signed by `signer` and returns the relay's answer, `Ok` or an error kind.
    async fn made(&mut self, signer: &Identity, id: &RelayMessageId) -> Result<String> {
        self.send(&ClientFrame::made(&signer.address, id, &signer.secret)?)
            .await?;
        loop {
            match self.receive().await? {
                RelayFrame::Ok => return Ok("Ok".to_owned()),
                RelayFrame::Error { kind, .. } => return Ok(format!("{kind:?}")),
                _ => {}
            }
        }
    }
}

fn describe(frame: &RelayFrame) -> Value {
    match frame {
        RelayFrame::Challenge { .. } => json!({ "type": "Challenge" }),
        RelayFrame::Ok => json!({ "type": "Ok" }),
        RelayFrame::Error { kind, description } => {
            json!({ "type": "Error", "kind": format!("{kind:?}"), "description": description })
        }
        RelayFrame::Slate(slate) => json!({
            "type": "Slate",
            "from": slate.from,
            "epicboxmsgid": slate.epicboxmsgid.as_ref().map(RelayMessageId::as_str),
        }),
        RelayFrame::GetVersion { str } => json!({ "type": "GetVersion", "str": str }),
        RelayFrame::Unknown { type_name } => json!({ "type": type_name }),
        RelayFrame::Keepalive => json!({ "type": "keepalive" }),
    }
}

fn seal(from: &Identity, to: &EpicboxAddress, payload: &str) -> Result<ClientFrame> {
    let mut salt = [0u8; 8];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).context("randomness")?;
    getrandom::fill(&mut nonce).context("randomness")?;
    let message = SignedMessage::seal(payload, to, &from.secret, salt.into(), Nonce::from(nonce))?;
    Ok(ClientFrame::post_slate(&from.address, to, &message))
}

async fn post_on(
    session: &mut Session,
    from: &Identity,
    to: &EpicboxAddress,
    payload: &str,
) -> Result<String> {
    session.send(&seal(from, to, payload)?).await?;
    loop {
        match session.receive().await? {
            RelayFrame::Ok => return Ok("Ok".to_owned()),
            RelayFrame::Error { kind, .. } => return Ok(format!("{kind:?}")),
            _ => {}
        }
    }
}

async fn post(relay: &Relay, from: &Identity, to: &EpicboxAddress, payload: &str) -> Result<Value> {
    let mut session = Session::open(relay, WalletMode::Send).await?;
    let answer = post_on(&mut session, from, to, payload).await?;
    Ok(json!({ "from": from.address.to_string(), "to": to.to_string(), "answer": answer }))
}

fn open_message(identity: &Identity, slate: &SlateFrame) -> Result<String> {
    let message = ReceivedMessage::open(
        &slate.from,
        &slate.str,
        &slate.signature,
        &identity.address,
        &identity.secret,
    )?;
    Ok(message.plaintext.expose_str().to_owned())
}

async fn drain(
    relay: &Relay,
    identity: &Identity,
    out_dir: &Path,
    want: usize,
    seconds: u64,
) -> Result<Value> {
    std::fs::create_dir_all(out_dir)?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut session = Session::open(relay, WalletMode::Listener).await?;
    let mut messages = Vec::new();
    session.subscribe(identity).await?;
    while messages.len() < want {
        // A pending message answers the subscribe; a later one arrives on its own because the
        // session is a listener; the relay also sends a fresh challenge every minute.
        let Some(frame) = session.receive_until(deadline).await? else {
            break;
        };
        let slate = match frame {
            RelayFrame::Slate(slate) => slate,
            RelayFrame::Challenge { .. } => {
                session.subscribe(identity).await?;
                continue;
            }
            _ => continue,
        };
        let plaintext = open_message(identity, &slate)?;
        let file = out_dir.join(format!("{}.json", messages.len() + 1));
        std::fs::write(&file, &plaintext)?;
        let made = match &slate.epicboxmsgid {
            Some(id) => session.made(identity, id).await?,
            None => "no message id".to_owned(),
        };
        messages.push(json!({
            "from": slate.from,
            "epicboxmsgid": slate.epicboxmsgid.as_ref().map(RelayMessageId::as_str),
            "file": file.display().to_string(),
            "made": made,
        }));
    }
    Ok(json!({ "address": identity.address.to_string(), "messages": messages }))
}

/// Fact 4: what one socket does with a second address, and whether two sockets serve two
/// addresses at once. Every frame the relay sent is in the report, so an answer such as
/// `TooManySubscriptions` would show up there.
async fn sessions(relay: &Relay) -> Result<Value> {
    let first = Identity::random(relay)?;
    let second = Identity::random(relay)?;
    let sender = Identity::random(relay)?;
    let mut outbox = Session::open(relay, WalletMode::Send).await?;
    let mut posts = Vec::new();
    for to in [&first, &second] {
        posts.push(post_on(&mut outbox, &sender, &to.address, "{\"probe\":1}").await?);
    }

    // One socket: subscribe the first address, acknowledge its message, then subscribe the
    // second address on the same socket.
    let mut shared = Session::open(relay, WalletMode::Listener).await?;
    shared.subscribe(&first).await?;
    let first_message = shared.subscribe_answer().await?.context("first message")?;
    let first_id = first_message.epicboxmsgid.clone().context("message id")?;
    let first_made = shared.made(&first, &first_id).await?;
    shared.next_challenge().await?;
    shared.subscribe(&second).await?;
    let second_message = shared.subscribe_answer().await?;
    let second_made = match second_message
        .as_ref()
        .and_then(|slate| slate.epicboxmsgid.clone())
    {
        Some(id) => Some(shared.made(&second, &id).await?),
        None => None,
    };

    // A new message for the first address while the socket is subscribed as the second: does it
    // reach the socket, and can the first address still acknowledge it there?
    let late_post = post_on(&mut outbox, &sender, &first.address, "{\"probe\":2}").await?;
    let late = loop {
        match shared
            .receive_until(Instant::now() + Duration::from_secs(5))
            .await?
        {
            Some(RelayFrame::Slate(slate)) => break Some(slate),
            Some(_) => {}
            None => break None,
        }
    };
    let late_made_by_first = match late.as_ref().and_then(|slate| slate.epicboxmsgid.clone()) {
        Some(id) => Some(shared.made(&first, &id).await?),
        None => None,
    };

    // Two sockets, one address each, both subscribed before anything is posted.
    let third = Identity::random(relay)?;
    let fourth = Identity::random(relay)?;
    let mut socket_a = Session::open(relay, WalletMode::Listener).await?;
    let mut socket_b = Session::open(relay, WalletMode::Listener).await?;
    socket_a.subscribe(&third).await?;
    let empty_a = socket_a.subscribe_answer().await?.is_none();
    socket_b.subscribe(&fourth).await?;
    let empty_b = socket_b.subscribe_answer().await?.is_none();
    let two_socket_posts = vec![
        post_on(&mut outbox, &sender, &third.address, "{\"probe\":3}").await?,
        post_on(&mut outbox, &sender, &fourth.address, "{\"probe\":4}").await?,
    ];
    let mut two_socket_made = Vec::new();
    for (socket, identity) in [(&mut socket_a, &third), (&mut socket_b, &fourth)] {
        let deadline = Instant::now() + ANSWER_WAIT;
        let slate = loop {
            match socket.receive_until(deadline).await? {
                Some(RelayFrame::Slate(slate)) => break slate,
                Some(_) => {}
                None => bail!("no live message on the socket of {}", identity.address),
            }
        };
        open_message(identity, &slate)?;
        let id = slate.epicboxmsgid.clone().context("message id")?;
        two_socket_made.push(socket.made(identity, &id).await?);
    }

    let all_frames: Vec<&Value> = [&outbox, &shared, &socket_a, &socket_b]
        .iter()
        .flat_map(|session| session.transcript.iter())
        .collect();
    let error_kinds: Vec<&Value> = all_frames
        .iter()
        .filter_map(|frame| frame.get("kind"))
        .collect();
    Ok(json!({
        "posts": posts,
        "one_socket": {
            "first_message_delivered": open_message(&first, &first_message).is_ok(),
            "first_made": first_made,
            "second_subscribe_answer": second_message.as_ref().map_or("Ok", |_| "Slate"),
            "second_message_opened": second_message.as_ref().is_some_and(|slate| open_message(&second, slate).is_ok()),
            "second_made": second_made,
            "late_post_for_first": late_post,
            "late_message_for_first_reached_socket": late.is_some(),
            "late_made_signed_by_first": late_made_by_first,
            "transcript": shared.transcript,
        },
        "two_sockets": {
            "both_queues_empty_at_subscribe": empty_a && empty_b,
            "posts": two_socket_posts,
            "made": two_socket_made,
            "transcript_a": socket_a.transcript,
            "transcript_b": socket_b.transcript,
        },
        "error_kinds_seen": error_kinds,
        "addresses": {
            "first": first.address.to_string(),
            "second": second.address.to_string(),
            "late_message_queue": first.address.key_text(),
        },
    }))
}

/// Fact 5: the codec, stage and TTL the Epicbox policy reads from a slate file.
fn decode(file: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(file).context("slate file")?;
    let base_fee = lepic_primitives::params::Network::Mainnet
        .params()
        .default_base_fee();
    let mut codecs = CodecRegistry::new();
    codecs.register(Box::new(V2JsonCodec::new(base_fee)))?;
    codecs.register(Box::new(V3JsonCodec::new(base_fee)))?;
    let slate = EpicboxPolicy.decode(&codecs, &WireSlate::text(MediaType::JSON, text))?;
    let header = slate.origin().and_then(WireOrigin::legacy_header);
    Ok(json!({
        "codec": slate.origin().map(|origin| origin.codec().as_str()),
        "header": header.map(|h| format!("{}/{}/{}", h.version, h.orig_version, h.block_header_version)),
        "stage": slate.stage().to_string(),
        "slate_id": slate.id().to_string(),
        "ttl_cutoff_height": slate.ttl_cutoff_height().map(|height| height.to_string()),
    }))
}
