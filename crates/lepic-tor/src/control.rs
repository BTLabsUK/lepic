// SPDX-License-Identifier: Apache-2.0
//! A minimal client for tor's control port: `SAFECOOKIE` authentication, ownership, the SOCKS
//! address, bootstrap progress, the onion service and shutdown.
//!
//! Replies are `250 OK`, multi-line `250-key=value` … `250 OK`, data blocks `250+key=` … `.`,
//! and asynchronous `650` events that may arrive between any two replies. Commands are answered
//! in order, so one command runs at a time. Tor is a local process the wallet started, but its
//! replies are still bounded: line length, lines per reply and data block size.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::onion::ONION_NAME_LEN;

/// Longest reply line accepted, in bytes.
pub const MAX_LINE_LEN: usize = 8 * 1024;
/// Most lines in one reply, data block lines included.
pub const MAX_REPLY_LINES: usize = 512;
const MAX_DATA_LEN: usize = 256 * 1024;
const EVENT_QUEUE: usize = 256;
const DROPPED_UPLOADS: usize = 8;
const COOKIE_LEN: usize = 32;
/// Padded base64 of the 64-byte expanded key.
const ENCODED_KEY_LEN: usize = 88;
const NONCE_LEN: usize = 32;
/// Streams at once on one rendezvous circuit to the onion; tor closes a circuit that opens
/// more. The listener behind the onion sees every sender as `127.0.0.1`, so this is the
/// per-sender limit there.
pub const MAX_STREAMS_PER_CIRCUIT: usize = 4;
const HASH_LEN: usize = 32;
const SAFECOOKIE_SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const SAFECOOKIE_CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";
const ASYNC_CODE: u16 = 650;
/// Rendezvous requests tor takes from its proof-of-work queue per second, and at once: a
/// phone answers a handful of payments a minute, not tor's defaults for large services
/// (250 and 2500). Under a flood the senders that solved the hardest puzzles go first.
pub const POW_QUEUE_RATE: u32 = 2;
pub const POW_QUEUE_BURST: u32 = 10;

/// Why a control-port exchange failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ControlError {
    #[error("could not reach tor's control port")]
    Connect(#[source] std::io::Error),
    #[error("the control connection failed")]
    Io(#[source] std::io::Error),
    #[error("the control connection is closed")]
    Closed,
    #[error("tor did not answer in time")]
    Timeout,
    #[error("a control reply line is longer than {MAX_LINE_LEN} bytes")]
    LineTooLong,
    #[error("a control reply is longer than allowed")]
    ReplyTooLong,
    #[error("a control reply is malformed")]
    Malformed,
    #[error("tor refused the command with status {code}")]
    Rejected { code: u16 },
    #[error("the command or its argument is invalid")]
    InvalidArgument,
    #[error("the control cookie is not 32 bytes")]
    Cookie,
    #[error("the control port did not prove it knows the cookie")]
    ServerProof,
    #[error("the system random generator failed")]
    Randomness,
}

/// One complete reply: its status code and its lines without the status prefix. A data block
/// is one line: its key line and its data joined with `\n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub const fn is_event(&self) -> bool {
        self.code == ASYNC_CODE
    }

    pub const fn is_success(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    /// The value of the first `key=value` line with this key.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|line| {
            line.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
        })
    }
}

/// Builds replies from lines, one line at a time.
#[derive(Debug, Default)]
pub struct ReplyAssembler {
    code: Option<u16>,
    lines: Vec<String>,
    data: Option<String>,
}

impl ReplyAssembler {
    /// Takes one line without its line ending; a complete reply comes back on its last line.
    pub fn push_line(&mut self, line: &str) -> Result<Option<Reply>, ControlError> {
        if let Some(data) = &mut self.data {
            if line == "." {
                let block = std::mem::take(data);
                self.data = None;
                self.lines.push(block);
                return Ok(None);
            }
            let line = line
                .strip_prefix('.')
                .filter(|l| l.starts_with('.'))
                .unwrap_or(line);
            if data.len().saturating_add(line.len()) >= MAX_DATA_LEN {
                return Err(ControlError::ReplyTooLong);
            }
            data.push('\n');
            data.push_str(line);
            return Ok(None);
        }
        let (code, kind, text) = split_status(line).ok_or(ControlError::Malformed)?;
        match self.code {
            Some(current) if current != code => return Err(ControlError::Malformed),
            _ => self.code = Some(code),
        }
        if self.lines.len() >= MAX_REPLY_LINES {
            return Err(ControlError::ReplyTooLong);
        }
        match kind {
            b'-' => self.lines.push(text.to_owned()),
            b'+' => self.data = Some(text.to_owned()),
            _ => {
                self.lines.push(text.to_owned());
                self.code = None;
                return Ok(Some(Reply {
                    code,
                    lines: std::mem::take(&mut self.lines),
                }));
            }
        }
        Ok(None)
    }
}

fn split_status(line: &str) -> Option<(u16, u8, &str)> {
    let digits = line.get(..3)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let kind = *line.as_bytes().get(3)?;
    if !matches!(kind, b' ' | b'-' | b'+') {
        return None;
    }
    Some((digits.parse().ok()?, kind, line.get(4..)?))
}

/// `KEY=value` pairs of an event or reply line, in order; values may be quoted with `\`
/// escapes. Words without `=` are skipped.
pub fn parse_keywords(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let word_end = rest.find([' ', '=']).unwrap_or(rest.len());
        let (key, after) = rest.split_at(word_end);
        let Some(after) = after.strip_prefix('=') else {
            rest = after.trim_start();
            continue;
        };
        let (value, remaining) = if let Some(quoted) = after.strip_prefix('"') {
            read_quoted(quoted)
        } else {
            let end = after.find(' ').unwrap_or(after.len());
            let (value, remaining) = after.split_at(end);
            (value.to_owned(), remaining)
        };
        if !key.is_empty() {
            out.push((key.to_owned(), value));
        }
        rest = remaining.trim_start();
    }
    out
}

fn read_quoted(text: &str) -> (String, &str) {
    let mut value = String::new();
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return (value, text.get(at.saturating_add(1)..).unwrap_or_default()),
            '\\' => {
                if let Some((_, escaped)) = chars.next() {
                    value.push(escaped);
                }
            }
            other => value.push(other),
        }
    }
    (value, "")
}

fn keyword<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Bootstrap progress as tor reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    /// 0 to 100.
    pub progress: u8,
    /// Tor's phase tag, for example `conn_done` or `done`.
    pub tag: String,
    /// Set when tor reported the phase as a warning.
    pub warning: Option<String>,
}

/// What an `HS_DESC` event says happened to a descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HsDescAction {
    Upload,
    Uploaded,
    Failed,
    Other,
}

/// The asynchronous events the wallet follows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    Bootstrap(Bootstrap),
    ClockSkew {
        skew_seconds: i64,
    },
    HsDesc {
        action: HsDescAction,
        service_id: String,
    },
    Other,
}

const MAX_TAG_LEN: usize = 64;
const MAX_WARNING_LEN: usize = 200;

/// Reads an event from the first line of a `650` reply.
pub fn parse_event(line: &str) -> Event {
    let mut words = line.splitn(4, ' ');
    let (kind, severity, action) = (words.next(), words.next(), words.next());
    let rest = words.next().unwrap_or_default();
    match (kind, action) {
        (Some("STATUS_CLIENT"), Some("BOOTSTRAP")) => {
            parse_bootstrap(severity.unwrap_or_default(), rest)
                .map_or(Event::Other, Event::Bootstrap)
        }
        (Some("STATUS_GENERAL" | "STATUS_CLIENT"), Some("CLOCK_SKEW")) => {
            let pairs = parse_keywords(rest);
            keyword(&pairs, "SKEW")
                .and_then(|skew| skew.parse().ok())
                .map_or(Event::Other, |skew_seconds| Event::ClockSkew {
                    skew_seconds,
                })
        }
        (Some("HS_DESC"), _) => {
            let mut words = line.split(' ').skip(1);
            let action = match words.next() {
                Some("UPLOAD") => HsDescAction::Upload,
                Some("UPLOADED") => HsDescAction::Uploaded,
                Some("FAILED") => HsDescAction::Failed,
                _ => HsDescAction::Other,
            };
            match words.next() {
                Some(id) if is_service_id(id) => Event::HsDesc {
                    action,
                    service_id: id.to_owned(),
                },
                _ => Event::Other,
            }
        }
        _ => Event::Other,
    }
}

fn parse_bootstrap(severity: &str, keywords: &str) -> Option<Bootstrap> {
    let pairs = parse_keywords(keywords);
    let progress = keyword(&pairs, "PROGRESS")?.parse::<u8>().ok()?.min(100);
    let tag = keyword(&pairs, "TAG").unwrap_or_default();
    let warning = (severity == "WARN").then(|| {
        let text = keyword(&pairs, "WARNING")
            .or_else(|| keyword(&pairs, "REASON"))
            .unwrap_or("warning");
        truncate(text, MAX_WARNING_LEN)
    });
    Some(Bootstrap {
        progress,
        tag: truncate(tag, MAX_TAG_LEN),
        warning,
    })
}

/// Reads `GETINFO status/bootstrap-phase`: `NOTICE BOOTSTRAP PROGRESS=… TAG=…`.
pub fn parse_bootstrap_phase(value: &str) -> Option<Bootstrap> {
    let mut words = value.splitn(3, ' ');
    let severity = words.next()?;
    if words.next()? != "BOOTSTRAP" {
        return None;
    }
    parse_bootstrap(severity, words.next().unwrap_or_default())
}

/// Reads the `ControlPortWriteToFile` file: `PORT=127.0.0.1:<port>`. Only loopback is accepted.
pub fn parse_control_file(text: &str) -> Option<SocketAddr> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("PORT="))
        .find_map(loopback_address)
}

/// Reads `GETINFO net/listeners/socks`: space-separated, quoted addresses. Takes the first
/// loopback one.
pub fn parse_socks_listeners(value: &str) -> Option<SocketAddr> {
    value
        .split(' ')
        .map(|item| item.trim_matches('"'))
        .find_map(loopback_address)
}

fn loopback_address(text: &str) -> Option<SocketAddr> {
    let address: SocketAddr = text.parse().ok()?;
    (address.ip().is_loopback() && address.port() != 0).then_some(address)
}

fn is_service_id(text: &str) -> bool {
    text.len() == ONION_NAME_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Where a reply or event came in among everything tor sent on one connection. An event
/// before a command's reply happened before tor carried out the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position(pub(crate) u64);

/// An onion service tor added: its ServiceID and the position of the `ADD_ONION` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedOnion {
    pub service_id: String,
    pub added_at: Position,
}

/// An authenticated or not yet authenticated control connection. Dropping it closes the
/// connection, which ends tor once ownership was taken.
#[derive(Debug)]
pub struct ControlConnection {
    commander: Mutex<Commander>,
    closed: Arc<AtomicBool>,
    dropped_uploads: DroppedUploads,
    reader: JoinHandle<()>,
    timeout: Duration,
}

// The services and positions of the last `HS_DESC UPLOADED` events dropped from a full queue.
type DroppedUploads = Arc<std::sync::Mutex<VecDeque<(String, Position)>>>;

#[derive(Debug)]
struct Commander {
    writer: OwnedWriteHalf,
    replies: mpsc::Receiver<Result<(Position, Reply), ControlError>>,
}

impl Drop for ControlConnection {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl ControlConnection {
    /// Connects to tor's control port. Events arrive on the returned receiver, which closes
    /// when the connection does. Each command waits at most `timeout` for its reply.
    pub async fn connect(
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<(Self, mpsc::Receiver<(Position, Event)>), ControlError> {
        if !address.ip().is_loopback() {
            return Err(ControlError::InvalidArgument);
        }
        let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
            .await
            .map_err(|_| ControlError::Timeout)?
            .map_err(ControlError::Connect)?;
        let (read, writer) = stream.into_split();
        let (reply_tx, replies) = mpsc::channel(4);
        let (event_tx, events) = mpsc::channel(EVENT_QUEUE);
        let closed = Arc::new(AtomicBool::new(false));
        let dropped_uploads = DroppedUploads::default();
        let reader = tokio::spawn(read_replies(
            BufReader::new(read),
            reply_tx,
            event_tx,
            closed.clone(),
            dropped_uploads.clone(),
        ));
        Ok((
            Self {
                commander: Mutex::new(Commander { writer, replies }),
                closed,
                dropped_uploads,
                reader,
                timeout,
            },
            events,
        ))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Whether an `HS_DESC UPLOADED` for `service_id` after `since` was dropped because the
    /// event receiver was full, so the upload happened although no event for it arrived.
    pub fn upload_was_dropped(&self, service_id: &str, since: Position) -> bool {
        self.dropped_uploads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|(id, at)| id == service_id && *at > since)
    }

    /// Sends one command line and returns its reply; a reply other than 2xx is
    /// [`ControlError::Rejected`]. The line may hold a secret, so it is never logged.
    async fn command(&self, line: &str) -> Result<Reply, ControlError> {
        self.positioned_command(line).await.map(|(_, reply)| reply)
    }

    async fn positioned_command(&self, line: &str) -> Result<(Position, Reply), ControlError> {
        if line.contains(['\r', '\n']) {
            return Err(ControlError::InvalidArgument);
        }
        if self.is_closed() {
            return Err(ControlError::Closed);
        }
        let mut commander = self.commander.lock().await;
        let exchange = async {
            let mut framed = Zeroizing::new(String::with_capacity(line.len().saturating_add(2)));
            framed.push_str(line);
            framed.push_str("\r\n");
            commander
                .writer
                .write_all(framed.as_bytes())
                .await
                .map_err(ControlError::Io)?;
            commander.replies.recv().await.ok_or(ControlError::Closed)?
        };
        let reply = match tokio::time::timeout(self.timeout, exchange).await {
            Ok(reply) => reply,
            Err(_) => {
                // A late reply would be matched to the next command.
                self.close();
                return Err(ControlError::Timeout);
            }
        }?;
        if reply.1.is_success() {
            Ok(reply)
        } else {
            Err(ControlError::Rejected { code: reply.1.code })
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.reader.abort();
    }

    /// `SAFECOOKIE` authentication with the 32-byte cookie tor wrote to `CookieAuthFile`:
    /// `AUTHCHALLENGE` with a fresh nonce, a check that the server's hash proves it knows the
    /// cookie, then `AUTHENTICATE` with the client's hash. The cookie itself never crosses the
    /// connection, so whatever listens on the port learns nothing it could replay.
    pub async fn authenticate(&self, cookie: &[u8]) -> Result<(), ControlError> {
        if cookie.len() != COOKIE_LEN {
            return Err(ControlError::InvalidArgument);
        }
        let mut client_nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut client_nonce).map_err(|_| ControlError::Randomness)?;
        let mut challenge = String::with_capacity(25 + 2 * NONCE_LEN);
        challenge.push_str("AUTHCHALLENGE SAFECOOKIE ");
        push_hex(&mut challenge, &client_nonce);
        let reply = self.command(&challenge).await?;
        let pairs = reply
            .lines
            .first()
            .and_then(|line| line.strip_prefix("AUTHCHALLENGE "))
            .map(parse_keywords)
            .ok_or(ControlError::Malformed)?;
        let server_hash = keyword(&pairs, "SERVERHASH")
            .and_then(decode_hex::<HASH_LEN>)
            .ok_or(ControlError::Malformed)?;
        let server_nonce = keyword(&pairs, "SERVERNONCE")
            .and_then(decode_hex::<NONCE_LEN>)
            .ok_or(ControlError::Malformed)?;
        safecookie_mac(SAFECOOKIE_SERVER_KEY, cookie, &client_nonce, &server_nonce)?
            .verify_slice(&server_hash)
            .map_err(|_| ControlError::ServerProof)?;
        let mut client_hash =
            safecookie_mac(SAFECOOKIE_CLIENT_KEY, cookie, &client_nonce, &server_nonce)?
                .finalize()
                .into_bytes();
        let mut line = Zeroizing::new(String::with_capacity(13 + 2 * HASH_LEN));
        line.push_str("AUTHENTICATE ");
        push_hex(&mut line, &client_hash);
        client_hash.as_mut_slice().zeroize();
        self.command(&line).await.map(drop)
    }

    /// `TAKEOWNERSHIP`, then drops `__OwningControllerProcess`: from now on tor exits when this
    /// connection closes.
    pub async fn take_ownership(&self) -> Result<(), ControlError> {
        self.command("TAKEOWNERSHIP").await?;
        self.command("RESETCONF __OwningControllerProcess")
            .await
            .map(drop)
    }

    /// `GETINFO <key>`, the value of its `key=value` line.
    pub async fn get_info(&self, key: &str) -> Result<String, ControlError> {
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        {
            return Err(ControlError::InvalidArgument);
        }
        let reply = self.command(&format!("GETINFO {key}")).await?;
        reply
            .value(key)
            .map(str::to_owned)
            .ok_or(ControlError::Malformed)
    }

    /// The SOCKS address tor picked for `SocksPort auto`.
    pub async fn socks_address(&self) -> Result<SocketAddr, ControlError> {
        parse_socks_listeners(&self.get_info("net/listeners/socks").await?)
            .ok_or(ControlError::Malformed)
    }

    /// The bootstrap phase tor is in now; events only report changes.
    pub async fn bootstrap_phase(&self) -> Result<Bootstrap, ControlError> {
        parse_bootstrap_phase(&self.get_info("status/bootstrap-phase").await?)
            .ok_or(ControlError::Malformed)
    }

    /// `SETEVENTS STATUS_CLIENT STATUS_GENERAL HS_DESC`.
    pub async fn follow_events(&self) -> Result<(), ControlError> {
        self.command("SETEVENTS STATUS_CLIENT STATUS_GENERAL HS_DESC")
            .await
            .map(drop)
    }

    /// `ADD_ONION` with the 64-byte expanded key, port 80 to `127.0.0.1:<target_port>`.
    /// `DiscardPK` keeps tor from echoing the key; `MaxStreams` with `MaxStreamsCloseCircuit`
    /// closes a circuit that opens more than [`MAX_STREAMS_PER_CIRCUIT`] streams at once; the
    /// proof-of-work defence makes each new sender circuit cost a puzzle once the service is
    /// flooded ([`POW_QUEUE_RATE`]). A tor built without the defence ignores it.
    pub async fn add_onion(
        &self,
        expanded_key: &[u8; 64],
        target_port: u16,
    ) -> Result<AddedOnion, ControlError> {
        if target_port == 0 {
            return Err(ControlError::InvalidArgument);
        }
        // Straight into a buffer that is wiped: `encode_string` goes through a stack buffer
        // that is not.
        let mut encoded = Zeroizing::new([0u8; ENCODED_KEY_LEN]);
        let written = STANDARD
            .encode_slice(expanded_key, &mut *encoded)
            .map_err(|_| ControlError::InvalidArgument)?;
        let encoded = encoded
            .get(..written)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .ok_or(ControlError::InvalidArgument)?;
        let mut line = Zeroizing::new(String::with_capacity(160));
        line.push_str("ADD_ONION ED25519-V3:");
        line.push_str(encoded);
        line.push_str(" Flags=DiscardPK,MaxStreamsCloseCircuit MaxStreams=");
        line.push_str(&MAX_STREAMS_PER_CIRCUIT.to_string());
        line.push_str(" PoWDefensesEnabled=1 PoWQueueRate=");
        line.push_str(&POW_QUEUE_RATE.to_string());
        line.push_str(" PoWQueueBurst=");
        line.push_str(&POW_QUEUE_BURST.to_string());
        line.push_str(" Port=80,127.0.0.1:");
        line.push_str(&target_port.to_string());
        let (added_at, reply) = self.positioned_command(&line).await?;
        reply
            .value("ServiceID")
            .filter(|id| is_service_id(id))
            .map(|id| AddedOnion {
                service_id: id.to_owned(),
                added_at,
            })
            .ok_or(ControlError::Malformed)
    }

    pub async fn del_onion(&self, service_id: &str) -> Result<(), ControlError> {
        if !is_service_id(service_id) {
            return Err(ControlError::InvalidArgument);
        }
        self.command(&format!("DEL_ONION {service_id}"))
            .await
            .map(drop)
    }

    /// `SIGNAL SHUTDOWN`: tor closes its listeners and exits.
    pub async fn signal_shutdown(&self) -> Result<(), ControlError> {
        self.command("SIGNAL SHUTDOWN").await.map(drop)
    }

    /// `SIGNAL HALT`: tor exits at once.
    pub async fn signal_halt(&self) -> Result<(), ControlError> {
        self.command("SIGNAL HALT").await.map(drop)
    }

    /// `SIGNAL ACTIVE`: tor leaves its dormant state, if it was in it, and builds circuits
    /// again.
    pub async fn signal_active(&self) -> Result<(), ControlError> {
        self.command("SIGNAL ACTIVE").await.map(drop)
    }

    /// `SIGNAL NEWNYM`: new streams get new circuits, and tor forgets what it learned of
    /// onion services: their descriptors, intro points that failed and the directories it
    /// asked lately. Tor delays a second one within 10 s, and answers at once.
    pub async fn signal_newnym(&self) -> Result<(), ControlError> {
        self.command("SIGNAL NEWNYM").await.map(drop)
    }

    /// `SETCONF DisableNetwork`. Disabling closes every connection but the control ones, the
    /// SOCKS listener included; enabling opens a new SOCKS listener, on another port when it
    /// is `auto`.
    pub async fn set_network_enabled(&self, enabled: bool) -> Result<(), ControlError> {
        let line = if enabled {
            "SETCONF DisableNetwork=0"
        } else {
            "SETCONF DisableNetwork=1"
        };
        self.command(line).await.map(drop)
    }
}

/// HMAC-SHA256 of `cookie | client_nonce | server_nonce` under one of the two fixed keys of
/// tor's control-spec.
fn safecookie_mac(
    key: &[u8],
    cookie: &[u8],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> Result<Hmac<Sha256>, ControlError> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| ControlError::InvalidArgument)?;
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    Ok(mac)
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
}

/// Exactly `N` bytes of hex, either case.
fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N.checked_mul(2)? || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (byte, pair) in out.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Reads tor's 32-byte control cookie, refusing a file of any other size before reading it.
pub async fn read_cookie(path: &Path) -> Result<Zeroizing<[u8; COOKIE_LEN]>, ControlError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(ControlError::Io)?;
    let length = file.metadata().await.map_err(ControlError::Io)?.len();
    if length != COOKIE_LEN as u64 {
        return Err(ControlError::Cookie);
    }
    // One byte more than a cookie, so a file that grew since is still caught.
    let mut buffer = Zeroizing::new([0u8; COOKIE_LEN + 1]);
    let mut filled = 0;
    while let Some(free) = buffer.get_mut(filled..).filter(|free| !free.is_empty()) {
        match file.read(free).await.map_err(ControlError::Io)? {
            0 => break,
            read => filled = filled.saturating_add(read),
        }
    }
    if filled != COOKIE_LEN {
        return Err(ControlError::Cookie);
    }
    let mut cookie = Zeroizing::new([0u8; COOKIE_LEN]);
    cookie.copy_from_slice(buffer.get(..COOKIE_LEN).ok_or(ControlError::Cookie)?);
    Ok(cookie)
}

fn hex_digit(nibble: u8) -> char {
    char::from(
        b"0123456789abcdef"
            .get(usize::from(nibble & 0x0f))
            .copied()
            .unwrap_or(b'0'),
    )
}

async fn read_replies(
    mut reader: BufReader<OwnedReadHalf>,
    replies: mpsc::Sender<Result<(Position, Reply), ControlError>>,
    events: mpsc::Sender<(Position, Event)>,
    closed: Arc<AtomicBool>,
    dropped_uploads: DroppedUploads,
) {
    let mut assembler = ReplyAssembler::default();
    let mut line = Vec::new();
    let mut dropping = false;
    let mut position = Position(0);
    let failure = loop {
        let text = match read_line(&mut reader, &mut line).await {
            Ok(Some(text)) => text,
            Ok(None) => break ControlError::Closed,
            Err(error) => break error,
        };
        let reply = match assembler.push_line(&text) {
            Ok(Some(reply)) => reply,
            Ok(None) => continue,
            Err(error) => break error,
        };
        position = Position(position.0.saturating_add(1));
        if reply.is_event() {
            let event = parse_event(reply.lines.first().map(String::as_str).unwrap_or_default());
            match events.try_send((position, event)) {
                Ok(()) => dropping = false,
                Err(mpsc::error::TrySendError::Full((_, event))) => {
                    // Once per run of drops: the queue fills only when its reader stalls.
                    if !dropping {
                        warn!("tor events dropped, the event queue is full");
                        dropping = true;
                    }
                    if let Event::HsDesc {
                        action: HsDescAction::Uploaded,
                        service_id,
                    } = event
                    {
                        let mut dropped = dropped_uploads
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if dropped.len() >= DROPPED_UPLOADS {
                            dropped.pop_front();
                        }
                        dropped.push_back((service_id, position));
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        } else if replies.send(Ok((position, reply))).await.is_err() {
            break ControlError::Closed;
        }
    };
    closed.store(true, Ordering::Release);
    debug!(error = %failure, "tor control connection ended");
    let _ = replies.try_send(Err(failure));
}

/// One line without its `\r\n`, at most [`MAX_LINE_LEN`] bytes; `None` at the end of the stream.
async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> Result<Option<String>, ControlError> {
    line.clear();
    loop {
        let available = reader.fill_buf().await.map_err(ControlError::Io)?;
        if available.is_empty() {
            return Ok(None);
        }
        let (chunk, found) = match available.iter().position(|&b| b == b'\n') {
            Some(at) => (available.get(..at).unwrap_or_default(), true),
            None => (available, false),
        };
        if line.len().saturating_add(chunk.len()) > MAX_LINE_LEN {
            return Err(ControlError::LineTooLong);
        }
        line.extend_from_slice(chunk);
        let used = chunk.len().saturating_add(usize::from(found));
        reader.consume(used);
        if found {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(String::from_utf8_lossy(line).into_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "mk7ca5rxicc6ps765gdj3irikfzer6ffd2jpysipnnpttl7jynzaluyd";

    fn feed(assembler: &mut ReplyAssembler, lines: &[&str]) -> Vec<Reply> {
        lines
            .iter()
            .filter_map(|line| assembler.push_line(line).unwrap())
            .collect()
    }

    #[test]
    fn assembles_single_multi_line_and_data_replies() {
        let mut assembler = ReplyAssembler::default();
        assert_eq!(
            feed(&mut assembler, &["250 OK"]),
            [Reply {
                code: 250,
                lines: vec!["OK".into()]
            }]
        );
        let replies = feed(
            &mut assembler,
            &[&format!("250-ServiceID={SERVICE}"), "250 OK"],
        );
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].value("ServiceID"), Some(SERVICE));
        let replies = feed(
            &mut assembler,
            &["250+config-text=", "SocksPort auto", "..dot", ".", "250 OK"],
        );
        assert_eq!(
            replies[0].lines,
            ["config-text=\nSocksPort auto\n.dot", "OK"]
        );
        let replies = feed(&mut assembler, &["650-HS_DESC_CONTENT x", "650 OK"]);
        assert!(replies[0].is_event());
        let replies = feed(&mut assembler, &["552 Unrecognized key"]);
        assert!(!replies[0].is_success());
    }

    #[test]
    fn rejects_malformed_and_oversized_replies() {
        for line in ["garbage", "25 OK", "250", "250_OK", "abc OK"] {
            assert!(
                matches!(
                    ReplyAssembler::default().push_line(line),
                    Err(ControlError::Malformed)
                ),
                "{line}"
            );
        }
        let mut assembler = ReplyAssembler::default();
        assembler.push_line("250-a=1").unwrap();
        assert!(matches!(
            assembler.push_line("650 x"),
            Err(ControlError::Malformed)
        ));

        let mut assembler = ReplyAssembler::default();
        let mut result = Ok(None);
        for _ in 0..=MAX_REPLY_LINES {
            result = assembler.push_line("250-a=1");
            if result.is_err() {
                break;
            }
        }
        assert!(matches!(result, Err(ControlError::ReplyTooLong)));

        let mut assembler = ReplyAssembler::default();
        assembler.push_line("250+data=").unwrap();
        let long = "x".repeat(MAX_LINE_LEN);
        let mut result = Ok(None);
        for _ in 0..=MAX_DATA_LEN / MAX_LINE_LEN {
            result = assembler.push_line(&long);
            if result.is_err() {
                break;
            }
        }
        assert!(matches!(result, Err(ControlError::ReplyTooLong)));
    }

    #[test]
    fn reads_keywords_with_quotes_and_escapes() {
        let pairs = parse_keywords(r#"PROGRESS=100 TAG=done SUMMARY="Done \"really\"" WORD X="#);
        assert_eq!(keyword(&pairs, "PROGRESS"), Some("100"));
        assert_eq!(keyword(&pairs, "SUMMARY"), Some(r#"Done "really""#));
        assert_eq!(keyword(&pairs, "X"), Some(""));
        assert_eq!(keyword(&pairs, "WORD"), None);
        assert_eq!(
            parse_keywords(r#"A="unterminated"#),
            [("A".into(), "unterminated".into())]
        );
    }

    #[test]
    fn reads_the_events_it_follows() {
        assert_eq!(
            parse_event(
                r#"STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY="Loading""#
            ),
            Event::Bootstrap(Bootstrap {
                progress: 45,
                tag: "loading_descriptors".into(),
                warning: None
            })
        );
        let Event::Bootstrap(warned) = parse_event(
            r#"STATUS_CLIENT WARN BOOTSTRAP PROGRESS=5 TAG=conn WARNING="Connection refused" REASON=CONNECTREFUSED"#,
        ) else {
            panic!("not a bootstrap event");
        };
        assert_eq!(warned.warning.as_deref(), Some("Connection refused"));
        assert_eq!(
            parse_event("STATUS_GENERAL WARN CLOCK_SKEW SKEW=-7200 SOURCE=OR:1.2.3.4:443"),
            Event::ClockSkew {
                skew_seconds: -7200
            }
        );
        assert_eq!(
            parse_event(&format!("HS_DESC UPLOADED {SERVICE} UNKNOWN $ABCDEF~relay")),
            Event::HsDesc {
                action: HsDescAction::Uploaded,
                service_id: SERVICE.into()
            }
        );
        assert_eq!(
            parse_event(&format!(
                "HS_DESC FAILED {SERVICE} NO_AUTH $A REASON=UPLOAD_REJECTED"
            )),
            Event::HsDesc {
                action: HsDescAction::Failed,
                service_id: SERVICE.into()
            }
        );
        assert_eq!(
            parse_event("HS_DESC UPLOADED notanid UNKNOWN $A"),
            Event::Other
        );
        assert_eq!(
            parse_event("STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=abc"),
            Event::Other
        );
        assert_eq!(parse_event("CIRC 1 BUILT"), Event::Other);
        assert_eq!(parse_event(""), Event::Other);
    }

    #[test]
    fn reads_the_bootstrap_phase_getinfo() {
        let phase =
            parse_bootstrap_phase(r#"NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done""#)
                .unwrap();
        assert_eq!(phase.progress, 100);
        assert_eq!(phase.tag, "done");
        assert_eq!(
            parse_bootstrap_phase("NOTICE BOOTSTRAP PROGRESS=250 TAG=x")
                .unwrap()
                .progress,
            100
        );
        assert_eq!(parse_bootstrap_phase("NOTICE OTHER PROGRESS=1"), None);
    }

    #[test]
    fn reads_only_loopback_addresses() {
        assert_eq!(
            parse_control_file("PORT=127.0.0.1:41235\n"),
            Some("127.0.0.1:41235".parse().unwrap())
        );
        assert_eq!(
            parse_control_file("PORT=[::1]:9051"),
            Some("[::1]:9051".parse().unwrap())
        );
        assert_eq!(parse_control_file("PORT=10.0.0.1:1"), None);
        assert_eq!(parse_control_file("PORT=127.0.0.1:0"), None);
        assert_eq!(parse_control_file(""), None);
        assert_eq!(
            parse_socks_listeners(r#""10.0.0.2:9050" "127.0.0.1:39111""#),
            Some("127.0.0.1:39111".parse().unwrap())
        );
        assert_eq!(parse_socks_listeners(""), None);
    }

    #[test]
    fn hex_digits() {
        let text: String = (0..16).map(hex_digit).collect();
        assert_eq!(text, "0123456789abcdef");
    }

    #[test]
    fn decodes_hex_of_one_length_only() {
        assert_eq!(decode_hex::<2>("0aFf"), Some([0x0a, 0xff]));
        assert_eq!(decode_hex::<2>("0aF"), None);
        assert_eq!(decode_hex::<2>("0aFf00"), None);
        assert_eq!(decode_hex::<2>("0g00"), None);
        assert_eq!(decode_hex::<1>("+1"), None);
    }

    #[tokio::test]
    async fn reads_only_a_cookie_of_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookie");
        std::fs::write(&path, [7; 32]).unwrap();
        assert_eq!(*read_cookie(&path).await.unwrap(), [7; 32]);
        for length in [0, 31, 33, 4096] {
            std::fs::write(&path, vec![7; length]).unwrap();
            assert!(
                matches!(read_cookie(&path).await, Err(ControlError::Cookie)),
                "{length}"
            );
        }
        assert!(matches!(
            read_cookie(&dir.path().join("missing")).await,
            Err(ControlError::Io(_))
        ));
    }

    /// A control port that answers `AUTHCHALLENGE` with `server_hash` and records every line.
    async fn challenging_port(
        server_hash: String,
    ) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = seen.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                recorded.lock().unwrap().push(line.clone());
                let answer = if line.starts_with("AUTHCHALLENGE ") {
                    format!(
                        "250 AUTHCHALLENGE SERVERHASH={server_hash} SERVERNONCE={}\r\n",
                        "03".repeat(NONCE_LEN)
                    )
                } else {
                    "250 OK\r\n".to_owned()
                };
                write.write_all(answer.as_bytes()).await.unwrap();
            }
        });
        (address, seen)
    }

    #[tokio::test]
    async fn a_port_that_does_not_know_the_cookie_gets_no_answer() {
        let (address, seen) = challenging_port("00".repeat(HASH_LEN)).await;
        let (control, _events) = ControlConnection::connect(address, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(matches!(
            control.authenticate(&[7; COOKIE_LEN]).await,
            Err(ControlError::ServerProof)
        ));
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let nonce = seen[0].strip_prefix("AUTHCHALLENGE SAFECOOKIE ").unwrap();
        assert!(decode_hex::<NONCE_LEN>(nonce).is_some());
        assert!(!seen[0].contains(&"07".repeat(COOKIE_LEN)));

        let (address, _) = challenging_port("zz".to_owned()).await;
        let (control, _events) = ControlConnection::connect(address, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(matches!(
            control.authenticate(&[7; COOKIE_LEN]).await,
            Err(ControlError::Malformed)
        ));
        assert!(matches!(
            control.authenticate(&[7; 31]).await,
            Err(ControlError::InvalidArgument)
        ));
    }

    #[tokio::test]
    async fn remembers_an_upload_dropped_from_a_full_queue() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let mut flood = "650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED\r\n".repeat(EVENT_QUEUE);
            flood.push_str(&format!("650 HS_DESC UPLOADED {SERVICE} UNKNOWN $A\r\n"));
            write.write_all(flood.as_bytes()).await.unwrap();
            while let Ok(Some(_)) = lines.next_line().await {
                write.write_all(b"250 OK\r\n").await.unwrap();
            }
        });
        let (control, events) = ControlConnection::connect(address, Duration::from_secs(5))
            .await
            .unwrap();
        // Replies come after the events sent before them, so all were handled by now.
        control.signal_shutdown().await.unwrap();
        assert_eq!(events.len(), EVENT_QUEUE);
        let uploaded_at = Position(u64::try_from(EVENT_QUEUE).unwrap() + 1);
        assert!(control.upload_was_dropped(SERVICE, Position(0)));
        assert!(!control.upload_was_dropped(SERVICE, uploaded_at));
        assert!(!control.upload_was_dropped(&SERVICE.replace('m', "n"), Position(0)));
    }

    #[tokio::test]
    async fn bounded_line_reader_refuses_a_line_without_end() {
        let data = vec![b'x'; MAX_LINE_LEN + 1];
        let mut reader = BufReader::new(&data[..]);
        assert!(matches!(
            read_line(&mut reader, &mut Vec::new()).await,
            Err(ControlError::LineTooLong)
        ));
        let mut reader = BufReader::new(&b"250 OK\r\n650 x\n"[..]);
        let mut line = Vec::new();
        assert_eq!(
            read_line(&mut reader, &mut line).await.unwrap().as_deref(),
            Some("250 OK")
        );
        assert_eq!(
            read_line(&mut reader, &mut line).await.unwrap().as_deref(),
            Some("650 x")
        );
        assert_eq!(read_line(&mut reader, &mut line).await.unwrap(), None);
    }
}
