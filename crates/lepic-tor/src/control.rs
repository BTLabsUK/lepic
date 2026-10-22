//! A minimal client for tor's control port: cookie authentication, ownership, the SOCKS
//! address, bootstrap progress, the onion service and shutdown.
//!
//! Replies are `250 OK`, multi-line `250-key=value` … `250 OK`, data blocks `250+key=` … `.`,
//! and asynchronous `650` events that may arrive between any two replies. Commands are answered
//! in order, so one command runs at a time. Tor is a local process the wallet started, but its
//! replies are still bounded: line length, lines per reply and data block size.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::debug;
use zeroize::Zeroizing;

use crate::onion::ONION_NAME_LEN;

/// Longest reply line accepted, in bytes.
pub const MAX_LINE_LEN: usize = 8 * 1024;
/// Most lines in one reply, data block lines included.
pub const MAX_REPLY_LINES: usize = 512;
const MAX_DATA_LEN: usize = 256 * 1024;
const EVENT_QUEUE: usize = 256;
const COOKIE_LEN: usize = 32;
const ASYNC_CODE: u16 = 650;

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

/// An authenticated or not yet authenticated control connection. Dropping it closes the
/// connection, which ends tor once ownership was taken.
#[derive(Debug)]
pub struct ControlConnection {
    commander: Mutex<Commander>,
    closed: Arc<AtomicBool>,
    reader: JoinHandle<()>,
    timeout: Duration,
}

#[derive(Debug)]
struct Commander {
    writer: OwnedWriteHalf,
    replies: mpsc::Receiver<Result<Reply, ControlError>>,
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
    ) -> Result<(Self, mpsc::Receiver<Event>), ControlError> {
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
        let reader = tokio::spawn(read_replies(
            BufReader::new(read),
            reply_tx,
            event_tx,
            closed.clone(),
        ));
        Ok((
            Self {
                commander: Mutex::new(Commander { writer, replies }),
                closed,
                reader,
                timeout,
            },
            events,
        ))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Sends one command line and returns its reply; a reply other than 2xx is
    /// [`ControlError::Rejected`]. The line may hold a secret, so it is never logged.
    async fn command(&self, line: &str) -> Result<Reply, ControlError> {
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
        if reply.is_success() {
            Ok(reply)
        } else {
            Err(ControlError::Rejected { code: reply.code })
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.reader.abort();
    }

    /// `AUTHENTICATE` with the 32-byte cookie tor wrote to `CookieAuthFile`.
    pub async fn authenticate(&self, cookie: &[u8]) -> Result<(), ControlError> {
        if cookie.len() != COOKIE_LEN {
            return Err(ControlError::InvalidArgument);
        }
        let mut line = Zeroizing::new(String::with_capacity(13 + 2 * COOKIE_LEN));
        line.push_str("AUTHENTICATE ");
        for byte in cookie {
            line.push(hex_digit(byte >> 4));
            line.push(hex_digit(byte & 0x0f));
        }
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
    /// `DiscardPK` keeps tor from echoing the key. Returns tor's ServiceID.
    pub async fn add_onion(
        &self,
        expanded_key: &[u8; 64],
        target_port: u16,
    ) -> Result<String, ControlError> {
        if target_port == 0 {
            return Err(ControlError::InvalidArgument);
        }
        let mut encoded = Zeroizing::new(String::with_capacity(88));
        STANDARD.encode_string(expanded_key, &mut encoded);
        let mut line = Zeroizing::new(String::with_capacity(160));
        line.push_str("ADD_ONION ED25519-V3:");
        line.push_str(&encoded);
        line.push_str(" Flags=DiscardPK Port=80,127.0.0.1:");
        line.push_str(&target_port.to_string());
        let reply = self.command(&line).await?;
        reply
            .value("ServiceID")
            .filter(|id| is_service_id(id))
            .map(str::to_owned)
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
    replies: mpsc::Sender<Result<Reply, ControlError>>,
    events: mpsc::Sender<Event>,
    closed: Arc<AtomicBool>,
) {
    let mut assembler = ReplyAssembler::default();
    let mut line = Vec::new();
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
        if reply.is_event() {
            let event = parse_event(reply.lines.first().map(String::as_str).unwrap_or_default());
            if events.try_send(event).is_err() {
                debug!("tor event dropped");
            }
        } else if replies.send(Ok(reply)).await.is_err() {
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
