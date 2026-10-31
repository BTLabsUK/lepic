// SPDX-License-Identifier: Apache-2.0
//! Logs kept on the device for support: a size-bounded ring of redacted records in a directory
//! the app owns. The host packages the ring's files into a report itself, so the ring's redaction
//! is the last one before a report leaves the device.
//!
//! Records are redacted before they reach the disk, so the ring never holds a value the
//! redaction drops. A field's value is kept only for the fields in [`KEPT_FIELDS`]; every other
//! field, including amounts, addresses and the `relay`, `peer_relay` and `node` hosts, is written
//! as `[redacted]`. Messages, LEPIC's own and a host app's (`dart` target), the kept values and
//! the `error` text all go through the same text redaction, [`redact_text`]:
//!
//! - A slate (JSON with a slate key) becomes `[slate]` from its first `{` on, an armoured
//!   slatepack `[slatepack]`, and 8 or more recovery-phrase words in a row, in any case and with
//!   anything but letters between them, `[words]`, one other word per 8 allowed as a typo.
//! - The value after a key-like name becomes `[redacted]`: `password`, `pin`, `seed`,
//!   `mnemonic`, `phrase`, `token`, `secret`, `key`, `nonce`, `mask`, `blind`, `commit`,
//!   `excess`, `signature`, `slate`, `cookie`, `authorization` and the like, also as part of a
//!   longer name (`wallet_password`, `apiKey`) unless it ends in `id`, `len`, `count` or similar.
//!   So do `Bearer` and `Basic` credentials, `--password` arguments and a 4 to 8 digit number
//!   after `pin`.
//! - Amounts become `[amount]`: a number before `EPIC`, an amount bucket such as `[<10 EPIC]`,
//!   and a number after `amount`, `fee`, `balance`, `spendable` and the like. A number after
//!   `port` becomes `[redacted]`.
//! - Text quoted with `"` or `` ` `` becomes `[redacted]`: decoder errors quote the input they
//!   rejected.
//! - A URL keeps only its scheme, `https://[host]`, losing its user, port, path and query; on
//!   an onion address it keeps that address's fingerprint, on a loopback host that host and
//!   port. An email address becomes `[email]`.
//! - IP addresses and host names become `[ip]` and `[host]`, with the port after them. Loopback
//!   addresses and `localhost`, path segments and file names such as `wallet.db` are kept.
//! - Home folders (`/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, `/root`) become `~`,
//!   and the host of a UNC path `[host]`.
//! - Addresses keep a fingerprint, their first and last 4 characters, so two can be told apart:
//!   an Epicbox address `esWW…K3oa@[host]`, an onion address `abcd…wxyz.onion`, a slatepack
//!   address `epic1qpzr…4khc` (its prefix kept), and any other base58 key of 40 or more
//!   characters. A fingerprint the app wrote with 6 leading characters is cut to 4. A UUID, a
//!   slate id, keeps its first 8 characters: `0436430c…`.
//! - 32 or more hex digits become `[hex]`; base64 of 40 or more characters, and any other run of
//!   64 or more token characters that is not a URL, `[redacted]`.
//!
//! Targets, span names and field names are kept, which is why messages must never interpolate
//! values.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use jiff::Timestamp;
use thiserror::Error;

use crate::{LogRecord, LogSink};

/// Fields from the log vocabulary whose values say nothing about keys, amounts, addresses or
/// hosts. Their values still go through [`redact_text`].
const KEPT_FIELDS: [&str; 15] = [
    "wallet",
    "account",
    "tx_id",
    "slate_id",
    "stage",
    "codec",
    "transport",
    "msg_id",
    "height",
    "attempt",
    "elapsed_ms",
    "retry_in_ms",
    "code",
    "error",
    "tag",
];

const REDACTED: &str = "[redacted]";
const AMOUNT: &str = "[amount]";
const HOST: &str = "[host]";
const IP: &str = "[ip]";
const EMAIL: &str = "[email]";
const HEX: &str = "[hex]";
const WORDS: &str = "[words]";
const SLATE: &str = "[slate]";
const SLATEPACK: &str = "[slatepack]";
/// The first word of every marker above and of the app's own (`[slate 0f3b2a1c… S2]`), whose
/// text a key-like name before it does not make a secret.
const MARKERS: [&str; 9] = [
    "redacted",
    "amount",
    "host",
    "ip",
    "email",
    "hex",
    "words",
    "slate",
    "slatepack",
];

/// The ring rotates through this many segment files, so at most one segment of the newest
/// records is lost when the oldest segment is dropped.
const SEGMENTS: u64 = 4;
const MIN_LIMIT_BYTES: u64 = 4 * 1024;
const MAX_LINE_BYTES: u64 = 4 * 1024;
/// How many times a line's length of one message or value the redaction reads, so a huge
/// message costs no more than a few lines' worth of work.
const REDACTED_INPUT_LINES: usize = 4;
/// What is dropped from the end of an input cut short, after its redaction: a rule reads the
/// words around what it takes out, so the text just before the cut may be a piece of a phrase,
/// key or address that the rule would have caught whole.
const CUT_MARGIN: usize = 512;

/// The most bytes the ring keeps on disk, across all its files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogRingLimit {
    segment_bytes: u64,
}

impl LogRingLimit {
    /// One MiB.
    pub const DEFAULT: Self = Self {
        segment_bytes: 256 * 1024,
    };

    /// # Errors
    ///
    /// [`LogRingError::LimitTooSmall`] below 4 KiB.
    pub fn new(max_bytes: u64) -> Result<Self, LogRingError> {
        if max_bytes < MIN_LIMIT_BYTES {
            return Err(LogRingError::LimitTooSmall {
                max_bytes,
                min_bytes: MIN_LIMIT_BYTES,
            });
        }
        Ok(Self {
            segment_bytes: max_bytes / SEGMENTS,
        })
    }

    /// The limit actually enforced, which may round [`LogRingLimit::new`]'s argument down.
    #[must_use]
    pub fn max_bytes(self) -> u64 {
        self.segment_bytes.saturating_mul(SEGMENTS)
    }

    fn max_line_bytes(self) -> usize {
        usize::try_from(self.segment_bytes.min(MAX_LINE_BYTES)).unwrap_or(usize::MAX)
    }
}

impl Default for LogRingLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LogRingError {
    #[error("log ring limit of {max_bytes} bytes is below the minimum of {min_bytes} bytes")]
    LimitTooSmall { max_bytes: u64, min_bytes: u64 },
    #[error("log ring directory {directory} could not be prepared")]
    Directory {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// A [`LogSink`] that appends each record, redacted, to a ring of files in one directory and
/// never lets them grow past their [`LogRingLimit`]. When the newest file is full the oldest is
/// deleted. A record longer than 4 KiB, or than a quarter of the limit, is cut short.
///
/// The directory should hold nothing else: files named like ring segments are deleted when they
/// do not fit the limit.
pub struct LogRing {
    dir: PathBuf,
    limit: LogRingLimit,
    clock: fn() -> Timestamp,
    active: Mutex<Active>,
}

/// The newest segment, open for appending, and its length.
#[derive(Default)]
struct Active {
    file: Option<File>,
    len: u64,
}

impl LogRing {
    /// Opens the ring in `dir`, creating the directory when needed, and keeps appending to the
    /// records already there.
    ///
    /// # Errors
    ///
    /// [`LogRingError::Directory`] when the directory or its files cannot be created, read or
    /// trimmed to the limit.
    pub fn open(dir: impl Into<PathBuf>, limit: LogRingLimit) -> Result<Self, LogRingError> {
        Self::open_with_clock(dir.into(), limit, Timestamp::now)
    }

    fn open_with_clock(
        dir: PathBuf,
        limit: LogRingLimit,
        clock: fn() -> Timestamp,
    ) -> Result<Self, LogRingError> {
        let prepared = fs::create_dir_all(&dir)
            .and_then(|()| remove_segments_outside(&dir, limit))
            .and_then(|()| Active::open(&dir));
        match prepared {
            Ok(active) => Ok(Self {
                dir,
                limit,
                clock,
                active: Mutex::new(active),
            }),
            Err(source) => Err(LogRingError::Directory {
                directory: dir,
                source,
            }),
        }
    }

    #[must_use]
    pub fn limit(&self) -> LogRingLimit {
        self.limit
    }

    fn append(&self, active: &mut Active, line: &[u8]) -> io::Result<()> {
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if active.file.is_none() {
            *active = Active::open(&self.dir)?;
        }
        if active.len.saturating_add(len) > self.limit.segment_bytes {
            *active = Active::default();
            self.rotate()?;
            *active = Active::open(&self.dir)?;
        }
        // Holds even when a rotation went wrong half way and left a full segment in place.
        if active.len.saturating_add(len) > self.limit.segment_bytes {
            return Ok(());
        }
        let Some(file) = active.file.as_mut() else {
            return Ok(());
        };
        if let Err(error) = file.write_all(line) {
            // The length on disk is unknown now; reopening reads it back.
            *active = Active::default();
            return Err(error);
        }
        active.len = active.len.saturating_add(len);
        Ok(())
    }

    fn rotate(&self) -> io::Result<()> {
        remove_if_present(&segment_path(&self.dir, SEGMENTS.saturating_sub(1)))?;
        let moves: Vec<(u64, u64)> = (0..SEGMENTS).zip(1..SEGMENTS).collect();
        for (from, to) in moves.into_iter().rev() {
            match fs::rename(segment_path(&self.dir, from), segment_path(&self.dir, to)) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        Ok(())
    }
}

impl LogSink for LogRing {
    fn record(&self, record: LogRecord) {
        let line = ring_line(&record, (self.clock)(), self.limit.max_line_bytes());
        let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        // A record that cannot be stored is dropped; logging the failure would come back here.
        let _ = self.append(&mut active, line.as_bytes());
    }
}

impl Active {
    fn open(dir: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(segment_path(dir, 0))?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: Some(file),
            len,
        })
    }
}

fn segment_path(dir: &Path, index: u64) -> PathBuf {
    dir.join(format!("lepic.{index}.log"))
}

fn segment_index(file_name: &str) -> Option<u64> {
    file_name
        .strip_prefix("lepic.")?
        .strip_suffix(".log")?
        .parse()
        .ok()
}

/// Deletes segments a larger or differently split limit left behind.
fn remove_segments_outside(dir: &Path, limit: LogRingLimit) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Some(index) = entry.file_name().to_str().and_then(segment_index) else {
            continue;
        };
        if index >= SEGMENTS || entry.metadata()?.len() > limit.segment_bytes {
            remove_if_present(&entry.path())?;
        }
    }
    Ok(())
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// One record as one line of at most `max_bytes`, with every field outside [`KEPT_FIELDS`]
/// redacted, the message and the kept values passed through [`redact_text`], and control
/// characters escaped.
fn ring_line(record: &LogRecord, at: Timestamp, max_bytes: usize) -> String {
    let mut line = String::new();
    // Writing to a String cannot fail.
    let _ = write!(line, "{at:.3} {} ", record.level);
    push_escaped(&mut line, &record.target);
    for span in &record.spans {
        line.push(':');
        push_escaped(&mut line, span);
    }
    line.push_str(": ");
    push_escaped(&mut line, &redact_bounded(&record.message, max_bytes));
    for (name, value) in &record.fields {
        line.push(' ');
        push_escaped(&mut line, name);
        line.push('=');
        if KEPT_FIELDS.contains(name) {
            push_escaped(&mut line, &redact_bounded(value, max_bytes));
        } else {
            line.push_str(REDACTED);
        }
    }
    let body_bytes = max_bytes.saturating_sub(1);
    if line.len() > body_bytes {
        line.truncate(line.floor_char_boundary(body_bytes));
    }
    line.push('\n');
    line
}

/// `text` through [`redact_text`], of which only the first [`REDACTED_INPUT_LINES`] times
/// `max_bytes` are read; a text cut there loses another [`CUT_MARGIN`] bytes at its end once
/// redacted, so no piece of a value cut in two is written.
fn redact_bounded(text: &str, max_bytes: usize) -> String {
    let bound = max_bytes.saturating_mul(REDACTED_INPUT_LINES);
    if text.len() <= bound {
        return redact_text(text);
    }
    let cut = text
        .get(..text.floor_char_boundary(bound))
        .unwrap_or_default();
    let mut redacted = redact_text(cut);
    let kept = redacted.len().saturating_sub(CUT_MARGIN);
    redacted.truncate(redacted.floor_char_boundary(kept));
    redacted
}

/// `text` with everything the module documentation lists taken out. Whole slates, slatepacks
/// and phrases go first, so no later rule leaves a piece of one; keyed values before quoted
/// text, so a quoted key still finds its value; URLs, email addresses and home folders before
/// host names; and the rules for single words and long runs last.
fn redact_text(text: &str) -> String {
    let text = redact_slate(text);
    let text = redact_slatepacks(&text);
    let text = redact_phrases(&text);
    let text = redact_keyed(&text);
    let text = redact_quoted(&text);
    let text = redact_urls(&text);
    let text = redact_mailboxes(&text);
    let text = redact_home_folders(&text);
    let text = rewrite_runs(&text, is_host_char, redact_host);
    let text = rewrite_runs(&text, is_token_char, redact_token);
    rewrite_runs(&text, is_long_run_char, redact_long_run)
}

/// Replaces every span quoted with `"` or `` ` `` by `[redacted]`. LEPIC's own errors carry no
/// values, but the decoder errors they keep as sources quote the input they rejected, and that
/// input may be an address or an amount. An unclosed quote redacts the rest of the text.
fn redact_quoted(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        redacted.push(c);
        if c != '"' && c != '`' {
            continue;
        }
        redacted.push_str(REDACTED);
        let mut escaped = false;
        for inner in chars.by_ref() {
            if inner == c && !escaped {
                redacted.push(c);
                break;
            }
            escaped = c == '"' && inner == '\\' && !escaped;
        }
    }
    redacted
}

/// JSON object keys of a slate, in any slate version.
const SLATE_KEYS: [&str; 11] = [
    "participant_data",
    "num_participants",
    "part_sig",
    "public_blind_excess",
    "blinding_factor",
    "sta",
    "tx",
    "offset",
    "kernels",
    "sigs",
    "coms",
];

/// Text holding a slate, cut to `[slate]` from its first `{` on.
fn redact_slate(text: &str) -> Cow<'_, str> {
    match text.split_once('{') {
        Some((before, json)) if SLATE_KEYS.iter().any(|key| has_json_key(json, key)) => {
            Cow::Owned(format!("{before}{SLATE}"))
        }
        _ => Cow::Borrowed(text),
    }
}

/// Whether `json` names `key` as an object key, `"key":`, also with the escaped quotes of JSON
/// carried in a JSON string, `\"key\":`.
fn has_json_key(json: &str, key: &str) -> bool {
    json.match_indices(key).any(|(at, _)| {
        let opened = json.get(..at).is_some_and(|before| before.ends_with('"'));
        let after = json
            .get(at..)
            .and_then(|rest| rest.strip_prefix(key))
            .unwrap_or_default();
        let after = after.strip_prefix('\\').unwrap_or(after);
        opened
            && after
                .strip_prefix('"')
                .is_some_and(|rest| rest.trim_start().starts_with(':'))
    })
}

const SLATEPACK_BEGIN: &str = "BEGINSLATEPACK.";
const SLATEPACK_END: &str = "ENDSLATEPACK.";

/// Every armoured slatepack, up to its end or, when it is cut short, to the end of the text, as
/// `[slatepack]`.
fn redact_slatepacks(text: &str) -> Cow<'_, str> {
    if !text.contains(SLATEPACK_BEGIN) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, slatepack)) = rest.split_once(SLATEPACK_BEGIN) {
        out.push_str(before);
        out.push_str(SLATEPACK);
        rest = slatepack
            .split_once(SLATEPACK_END)
            .map_or("", |(_, after)| after);
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// Recovery-phrase words in a row that [`redact_phrases`] takes out.
const PHRASE_RUN: usize = 8;
/// The most characters other than spaces between two words of one phrase: list numbers, commas,
/// the quotes of a JSON array.
const MAX_PHRASE_GAP: usize = 12;
/// The longest other word a phrase may hold as a typo.
const MAX_PHRASE_TYPO: usize = 16;

/// Every run of [`PHRASE_RUN`] or more BIP-39 words as `[words]`. The words may be in any case
/// and separated by anything without letters, as in a numbered list or a JSON array, and a run
/// may hold one other word (a typo) per [`PHRASE_RUN`] words, never two in a row.
fn redact_phrases(text: &str) -> Cow<'_, str> {
    let split: Vec<(bool, &str)> = pieces(text, |c| c.is_ascii_alphabetic()).collect();
    let mut scan = PhraseScan::default();
    // The text between the previous word and this one.
    let mut gap: Option<&str> = None;
    for (index, &(is_word, piece)) in split.iter().enumerate() {
        if is_word {
            scan.word(index, piece, gap.is_some_and(joins_phrase));
            gap = None;
        } else if index > 0 {
            gap = Some(piece);
        }
    }
    scan.close();
    if scan.spans.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut spans = scan.spans.into_iter().peekable();
    let mut inside: Option<usize> = None;
    for (index, &(_, piece)) in split.iter().enumerate() {
        if inside.is_some_and(|end| index <= end) {
            continue;
        }
        if let Some((_, end)) = spans.next_if(|&(start, _)| start == index) {
            out.push_str(WORDS);
            inside = Some(end);
        } else {
            out.push_str(piece);
        }
    }
    Cow::Owned(out)
}

fn joins_phrase(gap: &str) -> bool {
    gap.chars().filter(|c| !c.is_whitespace()).count() <= MAX_PHRASE_GAP
}

fn is_phrase_word(word: &str) -> bool {
    (3..=8).contains(&word.len())
        && bip39::Language::English
            .find_word(&word.to_ascii_lowercase())
            .is_some()
}

/// The runs of phrase words [`redact_phrases`] has found, by the index of their first and last
/// word among the text's pieces.
#[derive(Default)]
struct PhraseScan {
    /// The first and last phrase word of the open run, and its words with typos counted.
    run: Option<(usize, usize, usize)>,
    /// Whether the open run's last word was a typo not yet followed by a phrase word.
    typo_pending: bool,
    typos: usize,
    spans: Vec<(usize, usize)>,
}

impl PhraseScan {
    /// Takes the word at `index`; `joined` says only a short gap separates it from the word
    /// before.
    fn word(&mut self, index: usize, word: &str, joined: bool) {
        if !joined {
            self.close();
        }
        if is_phrase_word(word) {
            let counted = if self.typo_pending { 2 } else { 1 };
            self.run = Some(match self.run {
                Some((start, _, words)) => (start, index, words.saturating_add(counted)),
                None => (index, index, 1),
            });
            self.typo_pending = false;
        } else if self.run.is_some_and(|(_, _, words)| {
            !self.typo_pending
                && self.typos.saturating_mul(PHRASE_RUN) <= words
                && word.len() <= MAX_PHRASE_TYPO
        }) {
            self.typo_pending = true;
            self.typos = self.typos.saturating_add(1);
        } else {
            self.close();
        }
    }

    fn close(&mut self) {
        if let Some((start, end, _)) = self.run.take().filter(|&(_, _, words)| words >= PHRASE_RUN)
        {
            self.spans.push((start, end));
        }
        self.typo_pending = false;
        self.typos = 0;
    }
}

/// What the value after a key-like name is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Secret,
    /// A secret that may also follow as a bare 4 to 8 digit number.
    Pin,
    /// `Bearer` or `Basic`, followed by a credential.
    Scheme,
    Amount,
    Port,
}

/// Parts of a name, split at `_` and at camel-case humps, that make the value after it a secret.
const SECRET_PARTS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "passphrase",
    "pin",
    "mnemonic",
    "phrase",
    "seed",
    "mask",
    "token",
    "secret",
    "key",
    "apikey",
    "privkey",
    "authorization",
    "auth",
    "cookie",
    "credential",
    "credentials",
    "nonce",
    "blind",
    "blinding",
    "excess",
    "commit",
    "commitment",
    "signature",
    "sig",
    "slate",
    "slatepack",
    "proof",
];
/// Parts of a name that make the number after it an amount.
const AMOUNT_PARTS: &[&str] = &[
    "amount",
    "amt",
    "fee",
    "fees",
    "balance",
    "spendable",
    "credited",
    "debited",
    "awaiting",
    "immature",
    "locked",
];
const PORT_PARTS: &[&str] = &["port"];
/// Last parts of a name whose value describes a secret or an amount instead of being one:
/// `slate_id`, `password_set`, `key_count`.
const META_PARTS: &[&str] = &[
    "id", "ids", "len", "length", "count", "set", "type", "kind", "file", "path", "dir", "name",
    "status",
];
/// Values after a key-like name that are no secret.
const NOT_SECRETS: &[&str] = &["true", "false", "null", "none", "set", "unset"];
const AUTH_SCHEMES: &[&str] = &["bearer", "basic"];
/// The longest word taken for a key-like name.
const MAX_KEY_LEN: usize = 40;
/// The shortest credential after `Bearer` or `Basic`, so `basic check` stays.
const MIN_CREDENTIAL_LEN: usize = 6;

/// Every value after a key-like name as `[redacted]` or `[amount]`, and every amount in `EPIC`
/// as `[amount]`.
fn redact_keyed(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(is_word_char) {
        let (before, from) = rest.split_at_checked(start).unwrap_or((rest, ""));
        let len = from.find(|c: char| !is_word_char(c)).unwrap_or(from.len());
        let (word, after) = from.split_at_checked(len).unwrap_or((from, ""));
        out.push_str(before);
        rest = after;
        let amount = if word.eq_ignore_ascii_case("epic") {
            cut_epic_amount(&mut out, after)
        } else {
            None
        };
        if let Some(closed) = amount {
            rest = after.get(closed..).unwrap_or_default();
            continue;
        }
        out.push_str(word);
        let flag = before.ends_with("--");
        if let Some((value_start, value_end, marker)) =
            key_kind(word).and_then(|key| keyed_value(key, flag, after))
        {
            out.push_str(after.get(..value_start).unwrap_or_default());
            out.push_str(marker);
            rest = after.get(value_end..).unwrap_or_default();
        }
    }
    out.push_str(rest);
    out
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn in_set(set: &[&str], word: &str) -> bool {
    set.iter().any(|item| word.eq_ignore_ascii_case(item))
}

/// What the value after `word` is, when `word` is a key-like name.
fn key_kind(word: &str) -> Option<Key> {
    if word.len() > MAX_KEY_LEN {
        return None;
    }
    if in_set(AUTH_SCHEMES, word) {
        return Some(Key::Scheme);
    }
    let parts = word_parts(word);
    let last = *parts.last()?;
    if in_set(META_PARTS, last) {
        return None;
    }
    let has = |set: &[&str]| parts.iter().any(|part| in_set(set, part));
    if last.eq_ignore_ascii_case("pin") {
        Some(Key::Pin)
    } else if has(SECRET_PARTS) {
        Some(Key::Secret)
    } else if has(AMOUNT_PARTS) {
        Some(Key::Amount)
    } else if has(PORT_PARTS) {
        Some(Key::Port)
    } else {
        None
    }
}

/// `word` split at `_` and before an upper-case letter that follows a lower-case one or a digit:
/// `wallet_password` and `walletPassword` both give `wallet`, `password`.
fn word_parts(word: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut previous: Option<char> = None;
    for (index, c) in word.char_indices() {
        if c == '_' {
            parts.extend(word.get(start..index).filter(|part| !part.is_empty()));
            start = index.saturating_add(1);
        } else if c.is_ascii_uppercase()
            && previous.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
        {
            parts.extend(word.get(start..index).filter(|part| !part.is_empty()));
            start = index;
        }
        previous = Some(c);
    }
    parts.extend(word.get(start..).filter(|part| !part.is_empty()));
    parts
}

/// Where the value after a key-like name of kind `key` starts and ends in `after`, the text that
/// follows the name, and its marker. The value follows a `:` or `=`, or only spaces when it is
/// quoted, a `--` argument's (`flag`), a pin's digits, an amount, a port or a credential.
fn keyed_value(key: Key, flag: bool, after: &str) -> Option<(usize, usize, &'static str)> {
    let spaced = after.trim_start_matches([' ', '\t']);
    let lead = spaced.trim_start_matches(['"', '\'', ' ', '\t']);
    let (value, separated) = match lead.strip_prefix([':', '=']) {
        Some(value) => (value.trim_start_matches([' ', '\t']), true),
        None if spaced.len() < after.len() => (spaced, false),
        None => return None,
    };
    let quote = value.chars().next().filter(|c| matches!(c, '"' | '\''));
    let value = quote
        .and_then(|quote| value.strip_prefix(quote))
        .unwrap_or(value);
    let (len, marker) = match key {
        Key::Scheme if !separated && quote.is_none() => (credential_len(value)?, REDACTED),
        Key::Amount => (number_len(value, false)?, AMOUNT),
        Key::Port => (number_len(value, true)?, REDACTED),
        Key::Pin if !separated && quote.is_none() => (pin_len(value)?, REDACTED),
        Key::Secret | Key::Pin if separated || flag || quote.is_some() => {
            (secret_len(value, quote)?, REDACTED)
        }
        Key::Secret | Key::Pin | Key::Scheme => return None,
    };
    let start = after.len().saturating_sub(value.len());
    Some((start, start.saturating_add(len), marker))
}

fn credential_len(value: &str) -> Option<usize> {
    let len = value
        .find(|c: char| {
            !(c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '.' | '_' | '~' | '-'))
        })
        .unwrap_or(value.len());
    (len >= MIN_CREDENTIAL_LEN).then_some(len)
}

/// The length of the number `value` starts with, digits with `.` and `,`, when it is a whole
/// word; for a port, of 1 to 5 digits.
fn number_len(value: &str, port: bool) -> Option<usize> {
    let len = value
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == ','))
        .unwrap_or(value.len());
    let number = value.get(..len)?.trim_end_matches(['.', ',']);
    let rest = value.get(number.len()..)?;
    let valid = number.starts_with(|c: char| c.is_ascii_digit())
        && !rest.starts_with(|c: char| c.is_ascii_alphanumeric())
        && (!port || (number.len() <= 5 && number.bytes().all(|b| b.is_ascii_digit())));
    valid.then_some(number.len())
}

fn pin_len(value: &str) -> Option<usize> {
    let len = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let bounded = !value
        .get(len..)?
        .starts_with(|c: char| c.is_ascii_alphanumeric());
    ((4..=8).contains(&len) && bounded).then_some(len)
}

/// The length of the secret `value` starts with: up to `quote` when it was quoted, a whole
/// `[…]`, `{…}` or `(…)`, or else up to a space or a delimiter. `None` when the value is no
/// secret: empty, a marker, `***`, `none` or the like, or a credential scheme that comes next.
fn secret_len(value: &str, quote: Option<char>) -> Option<usize> {
    let len = match (quote, value.chars().next()) {
        (Some(quote), _) => quoted_len(value, quote),
        (None, Some(open @ ('[' | '{' | '('))) => {
            let close = match open {
                '[' => ']',
                '{' => '}',
                _ => ')',
            };
            value
                .find(close)
                .map_or(value.len(), |at| at.saturating_add(1))
        }
        (None, _) => value.find(ends_value).unwrap_or(value.len()),
    };
    let secret = value.get(..len)?;
    let kept = secret.is_empty()
        || is_marker(value)
        || secret.bytes().all(|b| b == b'*')
        || in_set(NOT_SECRETS, secret)
        || (quote.is_none() && in_set(AUTH_SCHEMES, secret));
    (!kept).then_some(len)
}

/// Where the text quoted with `quote` that `value` starts inside ends.
fn quoted_len(value: &str, quote: char) -> usize {
    let mut escaped = false;
    for (index, c) in value.char_indices() {
        if c == quote && !escaped {
            return index;
        }
        escaped = c == '\\' && !escaped;
    }
    value.len()
}

fn ends_value(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '}' | ')' | ']' | '&' | '<')
}

/// Whether `value` starts with a marker, this redaction's or the app's.
fn is_marker(value: &str) -> bool {
    value
        .strip_prefix('[')
        .and_then(|inner| inner.split_once(']'))
        .is_some_and(|(inner, _)| MARKERS.contains(&inner.split(' ').next().unwrap_or(inner)))
}

/// Replaces the number before an `EPIC` that follows `out`, and the brackets of an amount
/// bucket such as `[<10 EPIC]`, by `[amount]`. Returns how much of `after`, the text after the
/// `EPIC`, the bucket's `]` takes, or `None` when no number comes before the `EPIC`.
fn cut_epic_amount(out: &mut String, after: &str) -> Option<usize> {
    let text = out.as_str();
    let spaced = text.strip_suffix(' ').unwrap_or(text);
    let unit = spaced.strip_suffix(['k', 'K']).unwrap_or(spaced);
    let head = unit.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ',');
    let number = unit.strip_prefix(head)?;
    if !number.starts_with(|c: char| c.is_ascii_digit())
        || head.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let bucket = head
        .strip_suffix(['<', '>', '≤', '≥'])
        .unwrap_or(head)
        .strip_suffix('[')
        .filter(|_| after.starts_with(']'));
    let (keep, closed) = bucket.map_or((head.len(), 0), |open| (open.len(), 1));
    out.truncate(keep);
    out.push_str(AMOUNT);
    Some(closed)
}

/// Every URL as its scheme and `[host]`, without its user, port, path, query or fragment. A URL
/// on a loopback host keeps that host and port, and one on an onion address the address's
/// fingerprint.
fn redact_urls(text: &str) -> Cow<'_, str> {
    if !text.contains("://") {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    // A `://` inside the URL text the last one found runs to the same end, so that end, kept as
    // the length of the text after it, is not looked for again: a long run of `://` stays
    // linear.
    let mut url_left: Option<usize> = None;
    while let Some((before, after)) = rest.split_once("://") {
        out.push_str(before);
        out.push_str("://");
        rest = after;
        let scheme = before
            .strip_prefix(before.trim_end_matches(is_scheme_char))
            .unwrap_or_default();
        if !(2..=16).contains(&scheme.len())
            || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        {
            continue;
        }
        let url_len = match url_left {
            Some(left) if after.len() >= left => after.len().saturating_sub(left),
            _ => {
                let len = after.find(ends_url).unwrap_or(after.len());
                let url = after
                    .get(..len)
                    .unwrap_or_default()
                    .trim_end_matches(['.', ',', ':', ';', '!', '?']);
                url_left = Some(after.len().saturating_sub(url.len()));
                url.len()
            }
        };
        let url = after.get(..url_len).unwrap_or_default();
        if let Some(host) = url_host(url) {
            out.push_str(&host);
            rest = after.get(url.len()..).unwrap_or_default();
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')
}

fn ends_url(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '{' | '}' | '|' | ',' | '\\'
        )
}

/// What is kept of the URL `url`, the text after its `://`; `None` when it names no host.
fn url_host(url: &str) -> Option<String> {
    let authority = url.split(['/', '?', '#']).next().unwrap_or(url);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_port.strip_prefix('[') {
        Some(bracketed) => bracketed
            .split_once(']')
            .map_or(bracketed, |(host, _)| host),
        None => host_port.split(':').next().unwrap_or(host_port),
    };
    if host.is_empty() {
        None
    } else if is_loopback(host) {
        Some(host_port.to_owned())
    } else if let Some(key) = onion_key(host) {
        Some(format!("{}.onion", fingerprint(key)))
    } else {
        Some(HOST.to_owned())
    }
}

/// Every `name@domain`, with an optional port after it: an Epicbox address keeps its key's
/// fingerprint and loses its relay, `esWW…K3oa@[host]`, and anything else becomes `[email]`.
fn redact_mailboxes(text: &str) -> Cow<'_, str> {
    if !text.contains('@') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once('@') {
        let head = before.trim_end_matches(is_mailbox_char);
        let name = before.strip_prefix(head).unwrap_or_default();
        let domain_len = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
            .unwrap_or(after.len());
        let domain = after
            .get(..domain_len)
            .unwrap_or_default()
            .trim_end_matches(['.', '-']);
        let tail = after.get(domain.len()..).unwrap_or_default();
        let tail = tail
            .strip_prefix(':')
            .and_then(|port| {
                let len = port
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(port.len());
                port.get(len..).filter(|_| (1..=5).contains(&len))
            })
            .unwrap_or(tail);
        if name.is_empty() || !domain.bytes().any(|b| b.is_ascii_alphabetic()) {
            out.push_str(before);
            out.push('@');
            rest = after;
            continue;
        }
        out.push_str(head);
        if name.contains('…') {
            // A fingerprint the app already cut the key to.
            out.push_str(name);
            out.push('@');
            out.push_str(HOST);
        } else if is_base58_key(name) {
            out.push_str(&fingerprint(name));
            out.push('@');
            out.push_str(HOST);
        } else {
            out.push_str(EMAIL);
        }
        rest = tail;
    }
    out.push_str(rest);
    Cow::Owned(out)
}

fn is_mailbox_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '…')
}

/// Folders whose next path segment is a user name.
const HOME_FOLDERS: [&str; 5] = [
    "/home/",
    "/var/home/",
    "/Users/",
    "\\Users\\",
    "\\Documents and Settings\\",
];
/// The longest Windows user name looked for, which may hold spaces.
const MAX_USER_NAME: usize = 64;

/// Every home folder with its user name, and a drive letter before it, as `~`, and the host
/// of every UNC path as `[host]`.
fn redact_home_folders(text: &str) -> String {
    let mut text = text.to_owned();
    for folder in HOME_FOLDERS {
        if let Some(replaced) = replace_home(&text, folder) {
            text = replaced;
        }
    }
    if let Some(replaced) = replace_root_home(&text) {
        text = replaced;
    }
    replace_unc_hosts(&text).unwrap_or(text)
}

/// `text` with each `folder` and the user name after it cut to `~`; `None` without one.
fn replace_home(text: &str, folder: &str) -> Option<String> {
    if !text.contains(folder) {
        return None;
    }
    let windows = folder.starts_with('\\');
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once(folder) {
        let user = user_name_len(after, windows);
        if user == 0 || !(windows || starts_path(before)) {
            out.push_str(before);
            out.push_str(folder);
            rest = after;
            continue;
        }
        out.push_str(without_drive(before));
        out.push('~');
        rest = after.get(user..).unwrap_or_default();
    }
    out.push_str(rest);
    Some(out)
}

/// `text` with the root user's home, `/root`, cut to `~`; `None` without it.
fn replace_root_home(text: &str) -> Option<String> {
    let root = "/root";
    if !text.contains(root) {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once(root) {
        out.push_str(before);
        rest = after;
        let ends = !after.starts_with(|c: char| is_word_char(c) || c == '.' || c == '-');
        out.push_str(if ends && starts_path(before) {
            "~"
        } else {
            root
        });
    }
    out.push_str(rest);
    Some(out)
}

/// Whether a path that follows `before` starts there, rather than inside a longer one.
fn starts_path(before: &str) -> bool {
    !before.ends_with(|c: char| is_word_char(c) || matches!(c, '.' | '~' | '-'))
}

/// The length of the user name at the start of `after`. A Windows one may hold spaces, so it
/// runs to the next separator when one follows soon.
fn user_name_len(after: &str, windows: bool) -> usize {
    let plain = after
        .find(|c: char| c.is_whitespace() || ends_user_name(c))
        .unwrap_or(after.len());
    if !windows {
        return plain;
    }
    let spaced = after
        .find(|c: char| matches!(c, '\r' | '\n') || ends_user_name(c))
        .unwrap_or(after.len());
    let separated = after
        .get(spaced..)
        .is_some_and(|rest| rest.starts_with(['\\', '/']));
    if separated && spaced <= MAX_USER_NAME {
        spaced
    } else {
        plain
    }
}

fn ends_user_name(c: char) -> bool {
    matches!(
        c,
        '/' | '\\' | '"' | '\'' | '<' | '>' | '|' | '*' | '?' | ':' | ',' | ';' | ')' | ']'
    )
}

/// `before` without the drive letter, `C:`, it ends with.
fn without_drive(before: &str) -> &str {
    before
        .strip_suffix(':')
        .and_then(|head| head.strip_suffix(|c: char| c.is_ascii_alphabetic()))
        .filter(|head| !head.ends_with(is_word_char))
        .unwrap_or(before)
}

/// `text` with the host of each UNC path, `\\host\share`, as `[host]`; `None` without one.
fn replace_unc_hosts(text: &str) -> Option<String> {
    if !text.contains("\\\\") {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once("\\\\") {
        out.push_str(before);
        out.push_str("\\\\");
        rest = after;
        let len = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '$' | '-')))
            .unwrap_or(after.len());
        let host = (1..=63).contains(&len)
            && after.starts_with(|c: char| c.is_ascii_alphanumeric())
            && after
                .get(len..)
                .is_some_and(|share| share.starts_with('\\'))
            && !before.ends_with(|c: char| c.is_ascii_alphanumeric() || matches!(c, ':' | '\\'));
        if host {
            out.push_str(HOST);
            rest = after.get(len..).unwrap_or_default();
        }
    }
    out.push_str(rest);
    Some(out)
}

fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_' | '%' | '[' | ']')
}

/// A run of host characters with its IP address or host name, and the port after it, as `[ip]`
/// or `[host]`. A run that follows `/`, `\` (a path segment) or `…` (a fingerprint's tail) is
/// kept, and so is an onion address without a port, which [`redact_token`] fingerprints.
fn redact_host(run: &str, before: Option<char>) -> Option<String> {
    if before.is_some_and(|c| matches!(c, '/' | '\\' | '…')) {
        return None;
    }
    let inner = run.trim_start_matches(['.', '-', '_']);
    let core = inner.trim_end_matches(['.', '-', '_']);
    let core = if is_ipv6(core) {
        core
    } else {
        core.trim_end_matches(':')
    };
    let marker = host_marker(core)?;
    let lead = run.strip_suffix(inner).unwrap_or_default();
    let trail = inner.strip_prefix(core).unwrap_or_default();
    Some(format!("{lead}{marker}{trail}"))
}

fn host_marker(core: &str) -> Option<&'static str> {
    if let Some(bracketed) = core.strip_prefix('[') {
        let (address, tail) = bracketed.split_once(']')?;
        let port = tail.is_empty() || tail.strip_prefix(':').is_some_and(is_port);
        let ip = is_ipv6(address) || (is_ipv4(address) && !is_loopback(address));
        return (port && ip).then_some(IP);
    }
    if is_ipv6(core.split('%').next().unwrap_or(core)) {
        return Some(IP);
    }
    let (host, port) = match core.rsplit_once(':') {
        Some((host, port)) if is_port(port) && !host.contains(':') => (host, Some(port)),
        _ => (core, None),
    };
    if is_ipv4(host) {
        return (!is_loopback(host)).then_some(IP);
    }
    let onion_address = port.is_none() && onion_key(host).is_some();
    (is_host_name(host) && !onion_address).then_some(HOST)
}

fn is_port(text: &str) -> bool {
    (1..=5).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit())
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || matches!(host, "::1" | "0.0.0.0")
        || (host.starts_with("127.") && is_ipv4(host))
}

fn is_ipv4(text: &str) -> bool {
    let mut parts = 0_usize;
    let octets = text.split('.').all(|part| {
        parts = parts.saturating_add(1);
        (1..=3).contains(&part.len())
            && part.bytes().all(|b| b.is_ascii_digit())
            && part.parse::<u8>().is_ok()
    });
    octets && parts == 4
}

/// Whether `text` is an IPv6 address, also one ending in IPv4 form, other than `::1` and `::`.
/// Without a `::` it needs 5 or more colons and a hex letter, so times such as `12:34:56` stay.
fn is_ipv6(text: &str) -> bool {
    let (groups, ipv4_tail) = match text.rsplit_once(':') {
        Some((head, tail)) if tail.contains('.') => (head, Some(tail)),
        _ => (text, None),
    };
    if ipv4_tail.is_some_and(|tail| !is_ipv4(tail))
        || !groups.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
        || groups.split(':').any(|group| group.len() > 4)
    {
        return false;
    }
    let colons = groups
        .bytes()
        .filter(|&b| b == b':')
        .count()
        .saturating_add(usize::from(ipv4_tail.is_some()));
    if !(2..=7).contains(&colons) {
        return false;
    }
    if text.contains("::") {
        text != "::1" && groups.bytes().any(|b| b.is_ascii_hexdigit())
    } else {
        colons >= 5
            && (ipv4_tail.is_some()
                || groups
                    .bytes()
                    .any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F')))
    }
}

/// File name extensions that are no top-level domain, so a name such as `wallet.db` is not taken
/// for a host.
const FILE_EXTENSIONS: &[&str] = &[
    "log", "db", "json", "toml", "txt", "dart", "lock", "yaml", "yml", "sqlite", "tmp", "bak",
    "wal", "shm",
];

/// Whether `host` is a dotted host name: labels of letters, digits and `-`, the last of 2 to
/// 24 letters and no file name extension, none in camel case like a type's member.
fn is_host_name(host: &str) -> bool {
    let Some((_, top)) = host.rsplit_once('.') else {
        return false;
    };
    (2..=24).contains(&top.len())
        && top.bytes().all(|b| b.is_ascii_alphabetic())
        && !in_set(FILE_EXTENSIONS, top)
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !is_camel_case(label)
        })
}

fn is_camel_case(label: &str) -> bool {
    label
        .as_bytes()
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.is_ascii_lowercase() && b.is_ascii_uppercase()))
}

/// Characters an address keeps at each end, so two can be told apart.
const FINGERPRINT_LEN: usize = 4;
/// Characters a UUID keeps.
const UUID_KEPT: usize = 8;
const MIN_HEX_LEN: usize = 32;
/// The shortest base58 or bech32 word taken for an address or a key.
const MIN_ADDRESS_LEN: usize = 40;
const MIN_BECH32_DATA: usize = 32;
const ONION_KEY_LEN: usize = 56;
const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The key of the onion address `host`, `<key>.onion`.
fn onion_key(host: &str) -> Option<&str> {
    let (key, top) = host.rsplit_once('.')?;
    (top.eq_ignore_ascii_case("onion") && is_onion_key(key)).then_some(key)
}

fn is_onion_key(word: &str) -> bool {
    let base32_digit = |b: u8| (b'2'..=b'7').contains(&b);
    word.len() == ONION_KEY_LEN
        && word
            .bytes()
            .all(|b| b.is_ascii_alphabetic() || base32_digit(b))
        && word.bytes().any(base32_digit)
}

fn is_base58_key(word: &str) -> bool {
    word.len() >= MIN_ADDRESS_LEN
        && word.bytes().all(is_base58)
        && word.bytes().any(|b| b.is_ascii_digit())
        && word.bytes().any(|b| b.is_ascii_alphabetic())
}

fn is_base58(b: u8) -> bool {
    b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l')
}

/// The prefix and data of a bech32 word, such as a slatepack address `epic1…`.
fn bech32_parts(word: &str) -> Option<(&str, &str)> {
    let (prefix, data) = word.rsplit_once('1')?;
    let one_case = !word.bytes().any(|b| b.is_ascii_uppercase())
        || !word.bytes().any(|b| b.is_ascii_lowercase());
    let valid = word.len() >= MIN_ADDRESS_LEN
        && one_case
        && !prefix.is_empty()
        && prefix.bytes().all(|b| b.is_ascii_alphabetic())
        && data.len() >= MIN_BECH32_DATA
        && data
            .chars()
            .all(|c| BECH32_CHARSET.contains(c.to_ascii_lowercase()));
    valid.then_some((prefix, data))
}

/// The first and last [`FINGERPRINT_LEN`] characters of an ASCII address.
fn fingerprint(address: &str) -> String {
    let head = address.get(..FINGERPRINT_LEN).unwrap_or(address);
    let tail = address
        .get(address.len().saturating_sub(FINGERPRINT_LEN)..)
        .unwrap_or_default();
    format!("{head}…{tail}")
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '…'
}

/// A run of letters, digits, `-` and `…`: a UUID keeps its first [`UUID_KEPT`] characters, a
/// fingerprint the app wrote with 6 leading characters keeps [`FINGERPRINT_LEN`], and each word
/// in it goes through [`redact_word`].
fn redact_token(run: &str, _before: Option<char>) -> Option<String> {
    if is_uuid(run) {
        return Some(format!("{}…", run.get(..UUID_KEPT).unwrap_or_default()));
    }
    if let Some((head, tail)) = run.split_once('…') {
        let app_fingerprint = (5..=12).contains(&head.len())
            && tail.len() == FINGERPRINT_LEN
            && head
                .bytes()
                .chain(tail.bytes())
                .all(|b| b.is_ascii_alphanumeric());
        if app_fingerprint {
            let kept = head.get(..FINGERPRINT_LEN).unwrap_or(head);
            return Some(format!("{kept}…{tail}"));
        }
    }
    let rewritten = rewrite_runs(
        run,
        |c| c.is_ascii_alphanumeric(),
        |word, _| redact_word(word),
    );
    (rewritten != run).then_some(rewritten)
}

fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, b)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

/// A word of letters and digits: [`MIN_HEX_LEN`] or more hex digits become `[hex]`, and an
/// onion, bech32 or base58 address or key keeps its fingerprint.
fn redact_word(word: &str) -> Option<String> {
    if word.len() >= MIN_HEX_LEN && word.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(HEX.to_owned());
    }
    if is_onion_key(word) {
        return Some(fingerprint(word));
    }
    if let Some((prefix, data)) = bech32_parts(word) {
        return Some(format!("{prefix}1{}", fingerprint(data)));
    }
    is_base58_key(word).then(|| fingerprint(word))
}

/// Runs of token characters this long that are no URL are redacted whole.
const LONG_RUN: usize = 64;
/// The shortest base64-like piece redacted.
const MIN_BLOB_LEN: usize = 40;

fn is_long_run_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=' | ':' | '.' | '~')
}

/// A run of [`LONG_RUN`] or more token characters that is no URL, or a piece of one between
/// `:`, `.` and `~` of [`MIN_BLOB_LEN`] or more with letters and digits, as `[redacted]`:
/// tokens, keys and signatures in forms the rules before do not know.
fn redact_long_run(run: &str, _before: Option<char>) -> Option<String> {
    if run.len() >= LONG_RUN && !run.contains("//") {
        return Some(REDACTED.to_owned());
    }
    let rewritten = rewrite_runs(
        run,
        |c| !matches!(c, ':' | '.' | '~'),
        |piece, _| is_blob(piece).then(|| REDACTED.to_owned()),
    );
    (rewritten != run).then_some(rewritten)
}

fn is_blob(piece: &str) -> bool {
    let body = piece.trim_end_matches('=');
    body.len() >= MIN_BLOB_LEN
        && body.bytes().any(|b| b.is_ascii_digit())
        && body.bytes().any(|b| b.is_ascii_alphabetic())
}

/// `text` with each maximal run of characters that `in_run` accepts replaced by what `rewrite`
/// returns for it, given the character before the run; `None` keeps the run.
fn rewrite_runs(
    text: &str,
    in_run: impl Fn(char) -> bool,
    mut rewrite: impl FnMut(&str, Option<char>) -> Option<String>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut before = None;
    for (is_run, piece) in pieces(text, in_run) {
        let replacement = if is_run { rewrite(piece, before) } else { None };
        out.push_str(replacement.as_deref().unwrap_or(piece));
        before = piece.chars().next_back();
    }
    out
}

/// Splits `text` into the maximal runs of characters that `in_run` accepts and the text between
/// them, in order, each with whether it is a run.
fn pieces<F: Fn(char) -> bool>(text: &str, in_run: F) -> Pieces<'_, F> {
    Pieces { rest: text, in_run }
}

struct Pieces<'a, F> {
    rest: &'a str,
    in_run: F,
}

impl<'a, F: Fn(char) -> bool> Iterator for Pieces<'a, F> {
    type Item = (bool, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.rest;
        let is_run = (self.in_run)(rest.chars().next()?);
        let end = rest
            .find(|c: char| (self.in_run)(c) != is_run)
            .unwrap_or(rest.len());
        let (piece, tail) = rest.split_at_checked(end)?;
        self.rest = tail;
        Some((is_run, piece))
    }
}

fn push_escaped(line: &mut String, text: &str) {
    for c in text.chars() {
        if c.is_control() {
            line.extend(c.escape_default());
        } else {
            line.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tracing::dispatcher;

    use super::*;
    use crate::{LogFilter, LogLevel, assert_no_secrets, host_dispatch};

    const MNEMONIC: &str = "abandon ability able about above absent absorb abstract absurd";
    const PASSWORD: &str = "correct horse battery staple";
    const ADDRESS: &str = "esWWbPq4mFMqGXZ2nN1P9P2uGFZnTtM4axHwHrrcmVdTbixBK3oa@epicbox.example";
    const SEED: [u8; 8] = [0x8c, 0x01, 0xfe, 0x42, 0x17, 0x99, 0x00, 0xab];
    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";
    const SLATEPACK_ADDRESS: &str =
        "epic1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khc";
    const SLATE_ID: &str = "0f3b2a1c-6f1e-4c3a-9b2d-5e8f7a6b4c3d";

    fn fixed_clock() -> Timestamp {
        Timestamp::UNIX_EPOCH
    }

    fn open(dir: &Path, max_bytes: u64) -> LogRing {
        let limit = LogRingLimit::new(max_bytes).unwrap();
        LogRing::open_with_clock(dir.to_owned(), limit, fixed_clock).unwrap()
    }

    fn segment_sizes(dir: &Path) -> Vec<u64> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .collect()
    }

    fn record(message: &str, fields: Vec<(&'static str, String)>) -> LogRecord {
        LogRecord {
            level: LogLevel::Info,
            target: "lepic_wallet::send".to_owned(),
            message: message.to_owned(),
            spans: vec!["send"],
            fields,
        }
    }

    /// Every record in the ring at `dir`, oldest first: the highest segment index holds the
    /// oldest records.
    fn stored(dir: &Path) -> String {
        (0..SEGMENTS)
            .rev()
            .filter_map(|index| fs::read_to_string(segment_path(dir, index)).ok())
            .collect()
    }

    #[test]
    fn ring_never_exceeds_its_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let ring = open(dir.path(), 8 * 1024);
        let max = ring.limit().max_bytes();

        for index in 0_usize..3_000 {
            let message = match index % 7 {
                0 => "é".repeat(index),
                1 => "x".repeat(100_000),
                _ => format!("record {index}"),
            };
            ring.record(record(&message, vec![("height", index.to_string())]));

            let sizes = segment_sizes(dir.path());
            assert!(sizes.len() <= 4, "{} segments", sizes.len());
            assert!(sizes.iter().all(|&size| size <= max / 4));
            assert!(sizes.iter().sum::<u64>() <= max, "record {index}");
        }

        let bundle = stored(dir.path());
        assert!(bundle.ends_with("height=2999\n"));
    }

    #[test]
    fn reopening_with_a_smaller_limit_trims_the_ring() {
        let dir = tempfile::tempdir().unwrap();
        let large = open(dir.path(), 64 * 1024);
        for index in 0..2_000 {
            large.record(record(&format!("record {index}"), vec![]));
        }
        drop(large);
        fs::write(dir.path().join("lepic.9.log"), "stale").unwrap();

        let small = open(dir.path(), 4 * 1024);
        assert!(segment_sizes(dir.path()).iter().sum::<u64>() <= 4 * 1024);
        small.record(record("record after reopen", vec![]));
        assert!(segment_sizes(dir.path()).iter().sum::<u64>() <= 4 * 1024);
    }

    #[test]
    fn stored_records_keep_no_redacted_value() {
        let dir = tempfile::tempdir().unwrap();
        let ring = open(dir.path(), 4 * 1024);
        for index in 0..60 {
            ring.record(record(
                &format!("record {index:02}"),
                vec![("amount", "1000000".to_owned())],
            ));
        }

        let text = stored(dir.path());
        assert!(text.ends_with(": record 59 amount=[redacted]\n"));
        assert!(!text.contains("1000000"));
    }

    #[test]
    fn rejects_limit_below_minimum() {
        assert!(matches!(
            LogRingLimit::new(4 * 1024 - 1),
            Err(LogRingError::LimitTooSmall { .. })
        ));
    }

    #[test]
    fn segments_hold_records_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let ring = open(dir.path(), 4 * 1024);
        for index in 0..60 {
            ring.record(record(&format!("record {index:02}"), vec![]));
        }

        let body = stored(dir.path());
        let numbers: Vec<u32> = body
            .lines()
            .map(|line| line.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        assert!(numbers.len() > 4);
        assert!(numbers.windows(2).all(|pair| pair[0] + 1 == pair[1]));
        assert_eq!(numbers.last(), Some(&59));
    }

    #[test]
    fn stored_record_is_one_line_with_unknown_fields_redacted() {
        let line = ring_line(
            &record(
                "slate\nreceived",
                vec![
                    ("slate_id", "0436430c".to_owned()),
                    ("amount", "1000000".to_owned()),
                ],
            ),
            fixed_clock(),
            4096,
        );
        assert_eq!(
            line,
            "1970-01-01T00:00:00.000Z info lepic_wallet::send:send: slate\\nreceived \
             slate_id=0436430c amount=[redacted]\n"
        );
    }

    /// Hands every record to the ring and keeps a copy of what the live stream would get.
    struct Tee {
        ring: Arc<LogRing>,
        live: Mutex<Vec<LogRecord>>,
    }

    impl LogSink for Tee {
        fn record(&self, record: LogRecord) {
            self.live.lock().unwrap().push(record.clone());
            self.ring.record(record);
        }
    }

    #[test]
    fn ring_of_a_session_passes_assert_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let ring = Arc::new(open(dir.path(), 64 * 1024));
        let tee = Arc::new(Tee {
            ring: Arc::clone(&ring),
            live: Mutex::default(),
        });
        let dispatch = host_dispatch(tee.clone(), LogFilter::parse("trace").unwrap());

        dispatcher::with_default(&dispatch, || {
            let span = tracing::info_span!("send", wallet = "w1", seed = ?SEED);
            let _entered = span.enter();
            tracing::debug!(mnemonic = MNEMONIC, password = PASSWORD, "wallet opened");
            tracing::debug!(address = ADDRESS, amount = 1_000_000_u64, "slate created");
            tracing::trace!(key = %hex(&SEED), raw = &SEED[..], "key derived");
            tracing::info!(slate_id = "0436430c", stage = "S1", "slate sent");
        });

        let secrets: [&[u8]; 4] = [
            MNEMONIC.as_bytes(),
            PASSWORD.as_bytes(),
            ADDRESS.as_bytes(),
            &SEED,
        ];
        let live = tee.live.lock().unwrap().clone();
        assert!(
            assert_no_secrets(&live, &secrets).is_err(),
            "the session must log secrets for this test to show anything"
        );

        let bundle = stored(dir.path());
        assert!(
            bundle.contains(": slate sent wallet=w1 seed=[redacted] slate_id=0436430c stage=S1\n")
        );
        assert!(bundle.contains("wallet=w1"));
        let exported = LogRecord {
            level: LogLevel::Info,
            target: String::new(),
            message: bundle,
            spans: Vec::new(),
            fields: Vec::new(),
        };
        assert_eq!(assert_no_secrets(&[exported], &secrets), Ok(()));
    }

    #[test]
    fn oversized_record_is_cut_to_one_line_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let ring = open(dir.path(), 64 * 1024);
        ring.record(record(&"x ".repeat(50_000), vec![]));
        ring.record(record("record after", vec![]));

        let body = stored(dir.path());
        let lines: Vec<&str> = body.split_inclusive('\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("x x x x"));
        assert!(lines[0].len() <= 4 * 1024, "{} bytes", lines[0].len());
        assert!(lines[0].ends_with('\n'));
        assert!(lines[1].ends_with(": record after\n"));
    }

    #[test]
    fn huge_inputs_are_cut_before_redaction_without_leaving_a_piece() {
        let bound = 4096_usize.saturating_mul(REDACTED_INPUT_LINES);
        let hex_word = format!("{} ", "ab".repeat(32));
        let mut message = hex_word.repeat(250);
        message.push_str(&" ".repeat(bound.saturating_sub(20).saturating_sub(message.len())));
        // The cut falls after the phrase's third word, too few for a phrase alone.
        message.push_str(MNEMONIC);
        message.push_str(&" tail".repeat(10_000));

        let redacted = redact_bounded(&message, 4096);
        assert!(redacted.starts_with("[hex] [hex] "), "{redacted}");
        assert!(!redacted.contains("abandon"), "{redacted}");
        assert!(!redacted.contains("tail"));
        assert_eq!(redact_bounded("short pin 1234", 4096), "short pin [redacted]");
    }

    #[test]
    fn a_run_of_hostless_urls_is_read_once() {
        let run = "ab:///".repeat(100_000);
        assert_eq!(redact_urls(&run), run);
        let line = ring_line(&record(&run, vec![]), fixed_clock(), 4096);
        assert!(line.len() <= 4096);
        assert_eq!(
            redact_urls("x ab:///ab://node.example/v2 y"),
            "x ab:///ab://[host] y"
        );
    }

    #[derive(Debug, Error)]
    #[error("relay frame could not be decoded")]
    struct FrameError(#[source] serde_json::Error);

    #[test]
    fn quoted_input_in_error_text_is_redacted() {
        let invalid_type = serde_json::from_str::<u64>(&format!("\"{ADDRESS}\"")).unwrap_err();
        let out_of_range = serde_json::from_str::<u8>("300431").unwrap_err();
        let escaped = serde_json::from_str::<u64>(r#""say \"hi\" esWWbPq4""#).unwrap_err();
        for source in [&invalid_type, &escaped] {
            assert!(
                source.to_string().contains("esWWbPq4"),
                "serde_json must quote its input for this test to show anything: {source}"
            );
        }

        assert!(out_of_range.to_string().contains("`300431`"));

        let dir = tempfile::tempdir().unwrap();
        let ring = Arc::new(open(dir.path(), 64 * 1024));
        let dispatch = host_dispatch(ring.clone(), LogFilter::parse("trace").unwrap());
        for source in [invalid_type, out_of_range, escaped] {
            let error = FrameError(source);
            dispatcher::with_default(&dispatch, || {
                tracing::warn!(error = %crate::ErrorChain(&error), "relay frame rejected");
            });
        }

        let bundle = stored(dir.path());
        assert!(bundle.contains(
            "error=relay frame could not be decoded: invalid type: string \"[redacted]\", expected u64"
        ));
        assert!(bundle.contains("invalid value: integer `[redacted]`, expected u8"));
        assert!(!bundle.contains("esWWbPq4"));
        assert!(!bundle.contains("300431"));
        let exported = LogRecord {
            level: LogLevel::Info,
            target: String::new(),
            message: bundle,
            spans: Vec::new(),
            fields: Vec::new(),
        };
        assert_eq!(
            assert_no_secrets(&[exported], &[ADDRESS.as_bytes()]),
            Ok(())
        );
    }

    #[test]
    fn quoted_text_in_a_message_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let ring = Arc::new(open(dir.path(), 64 * 1024));
        let dispatch = host_dispatch(ring.clone(), LogFilter::parse("trace").unwrap());
        let message = format!("send to \"{ADDRESS}\" refused");
        dispatcher::with_default(&dispatch, || {
            tracing::warn!(target: "dart", tag = "send", "{message}");
        });

        let bundle = stored(dir.path());
        assert!(
            bundle.contains("send to \"[redacted]\" refused"),
            "{bundle}"
        );
        assert!(!bundle.contains("esWWbPq4"));
    }

    #[test]
    fn unclosed_quote_redacts_the_rest() {
        assert_eq!(redact_quoted("bad `esWW at line 1"), "bad `[redacted]");
        assert_eq!(redact_quoted("no quotes here"), "no quotes here");
    }

    #[test]
    fn host_fields_are_redacted_but_named() {
        let line = ring_line(
            &record(
                "relay connected",
                vec![
                    ("relay", "epicbox.example".to_owned()),
                    ("peer_relay", "relay.example:443".to_owned()),
                    ("node", "https://node.example:3413".to_owned()),
                ],
            ),
            fixed_clock(),
            4096,
        );
        assert!(
            line.ends_with(
                ": relay connected relay=[redacted] peer_relay=[redacted] node=[redacted]\n"
            ),
            "{line}"
        );
    }

    #[test]
    fn kept_values_are_redacted_as_text() {
        let line = ring_line(
            &record(
                "slate received",
                vec![
                    ("slate_id", SLATE_ID.to_owned()),
                    ("account", "paid 192.0.2.4".to_owned()),
                    ("tx_id", "17".to_owned()),
                ],
            ),
            fixed_clock(),
            4096,
        );
        assert!(
            line.ends_with(" slate_id=0f3b2a1c… account=paid [ip] tx_id=17\n"),
            "{line}"
        );
    }

    #[test]
    fn amounts_are_removed() {
        assert_eq!(
            redact_text("sent 1.5 EPIC to a contact"),
            "sent [amount] to a contact"
        );
        assert_eq!(redact_text("sent 1,000.25 EPIC"), "sent [amount]");
        assert_eq!(
            redact_text("bucket [<10 EPIC] then [≥100k EPIC]"),
            "bucket [amount] then [amount]"
        );
        assert_eq!(
            redact_text("amount=100000000 fee: 0.007 balance 42"),
            "amount=[amount] fee: [amount] balance [amount]"
        );
        assert_eq!(
            redact_text(r#"{"amount_credited":700000}"#),
            r#"{"[redacted]":[amount]}"#
        );
        assert_eq!(redact_text("spendable: unknown"), "spendable: unknown");
    }

    #[test]
    fn addresses_keep_only_a_fingerprint() {
        assert_eq!(
            redact_text(&format!("send to {ADDRESS} failed")),
            "send to esWW…K3oa@[host] failed"
        );
        assert_eq!(
            redact_text("from esWWbPq4mFMqGXZ2nN1P9P2uGFZnTtM4axHwHrrcmVdTbixBK3oa."),
            "from esWW…K3oa."
        );
        assert_eq!(
            redact_text("app wrote esWn9r…K3oa@relay.example"),
            "app wrote esWn…K3oa@[host]"
        );
        assert_eq!(
            redact_text(&format!("listening on {ONION}.onion")),
            "listening on abcd…uvwx.onion"
        );
        assert_eq!(
            redact_text(&format!("http://{ONION}.onion/v2/foreign")),
            "http://abcd…uvwx.onion"
        );
        assert_eq!(
            redact_text(&format!("tor at {ONION}.onion:9050")),
            "tor at [host]"
        );
        assert_eq!(
            redact_text(&format!("pay {SLATEPACK_ADDRESS} now")),
            "pay epic1qpzr…4khc now"
        );
    }

    #[test]
    fn urls_keep_only_their_scheme() {
        assert_eq!(
            redact_text("GET https://user:pw@node.example:3413/v2/foreign?id=1 failed"),
            "GET https://[host] failed"
        );
        assert_eq!(
            redact_text("relay wss://[2001:db8::7]:443/ws"),
            "relay wss://[host]"
        );
        assert_eq!(
            redact_text("node http://127.0.0.1:3413/v2/owner up"),
            "node http://127.0.0.1:3413 up"
        );
        assert_eq!(
            redact_text("mail alice@example.com now"),
            "mail [email] now"
        );
    }

    #[test]
    fn ip_addresses_and_host_names_are_removed() {
        assert_eq!(
            redact_text("connect to 192.0.2.7:3415 refused"),
            "connect to [ip] refused"
        );
        assert_eq!(
            redact_text("address = 192.0.2.5, port = 50322"),
            "address = [ip], port = [redacted]"
        );
        assert_eq!(
            redact_text("peers 2001:db8::1, [2001:db8::2]:443 and ::ffff:192.0.2.9"),
            "peers [ip], [ip] and [ip]"
        );
        assert_eq!(
            redact_text("lookup of relay.example failed: 'epicbox.example'"),
            "lookup of [host] failed: '[host]'"
        );
        for kept in [
            "proxy 127.0.0.1:9050 and localhost:3413",
            "opened wallet.db and lepic.0.log in /data/app/files at 12:34:56 on v4.1.0",
        ] {
            assert_eq!(redact_text(kept), kept);
        }
    }

    #[test]
    fn home_folders_lose_the_user_name() {
        assert_eq!(
            redact_text("wallet in /home/alice/.local/share/lepic"),
            "wallet in ~/.local/share/lepic"
        );
        assert_eq!(
            redact_text("profile C:\\Users\\Alice Smith\\AppData\\Local"),
            "profile ~\\AppData\\Local"
        );
        assert_eq!(
            redact_text("config /root/.lepic and /Users/alice"),
            "config ~/.lepic and ~"
        );
        assert_eq!(
            redact_text("share \\\\fileserver\\wallets\\w1"),
            "share \\\\[host]\\wallets\\w1"
        );
    }

    #[test]
    fn values_after_key_like_names_are_removed() {
        assert_eq!(
            redact_text("password=hunter2 pin: 1234"),
            "password=[redacted] pin: [redacted]"
        );
        assert_eq!(
            redact_text("PIN 123456 rejected, pin 12 too short"),
            "PIN [redacted] rejected, pin 12 too short"
        );
        assert_eq!(
            redact_text(r#"{"token":"abc123"}"#),
            r#"{"[redacted]":"[redacted]"}"#
        );
        assert_eq!(
            redact_text("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln"),
            "Authorization: Bearer [redacted]"
        );
        assert_eq!(redact_text("basic check failed"), "basic check failed");
        assert_eq!(
            redact_text("run --password s3cret --verbose"),
            "run --password [redacted] --verbose"
        );
        assert_eq!(
            redact_text("wallet_password: 'correct horse'"),
            "wallet_password: '[redacted]'"
        );
        assert_eq!(
            redact_text(
                "seed: [140, 1, 254] blinding_factor=08ab keychain_mask=f00d apiKey=xyz123"
            ),
            "seed: [redacted] blinding_factor=[redacted] keychain_mask=[redacted] \
             apiKey=[redacted]"
        );
        assert_eq!(
            redact_text(&format!(
                "password: none, token=[redacted] mnemonic_len=24 slate_id: {SLATE_ID}"
            )),
            "password: none, token=[redacted] mnemonic_len=24 slate_id: 0f3b2a1c…"
        );
    }

    #[test]
    fn recovery_phrases_are_removed() {
        assert_eq!(
            redact_text(&format!("restored from {MNEMONIC} ok")),
            "restored from [words] ok"
        );
        assert_eq!(
            redact_text(
                "1. abandon 2. ability 3. able 4. about 5. above 6. absent 7. absorb 8. abstract"
            ),
            "1. [words]"
        );
        assert_eq!(
            redact_text(
                r#"words ["abandon","ability","able","about","above","absent","absorb","abstract"]"#
            ),
            r#"words ["[redacted]"]"#
        );
        assert_eq!(
            redact_text("abandon ability able abuot above absent absorb abstract"),
            "[words]"
        );
        let sentence = "wallet opened after the node answered";
        assert_eq!(redact_text(sentence), sentence);
    }

    #[test]
    fn slates_and_slatepacks_are_removed() {
        assert_eq!(
            redact_text(&format!(
                r#"slate received {{"id":"{SLATE_ID}","sta":"S1","participant_data":[]}}"#
            )),
            "slate received [slate]"
        );
        assert_eq!(
            redact_text(r#"payload "{\"sta\":\"S2\",\"coms\":[]}""#),
            r#"payload "[redacted]"#
        );
        assert_eq!(
            redact_text("got BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv. ENDSLATEPACK. ok"),
            "got [slatepack] ok"
        );
        assert_eq!(
            redact_text("cut BEGINSLATEPACK. 4H1qx1wHe668tFW"),
            "cut [slatepack]"
        );
    }

    #[test]
    fn hex_uuids_and_long_tokens_are_removed() {
        let commitment = format!("08{}", "9f".repeat(32));
        assert_eq!(
            redact_text(&format!("output {commitment} spent")),
            "output [hex] spent"
        );
        assert_eq!(
            redact_text(&format!("tx {SLATE_ID} done")),
            "tx 0f3b2a1c… done"
        );
        assert_eq!(
            redact_text("got k1Zq8vB3nR5tY7uW9xA2cD4eF6gH8jK0mN2pQ4rS6tU= back"),
            "got [redacted] back"
        );
        assert_eq!(
            redact_text(
                "push with eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
                 dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            ),
            "push with [redacted]"
        );
    }

    #[test]
    fn app_lines_are_redacted_like_lepic_ones() {
        let dir = tempfile::tempdir().unwrap();
        let ring = Arc::new(open(dir.path(), 64 * 1024));
        let dispatch = host_dispatch(ring.clone(), LogFilter::parse("trace").unwrap());
        let message = format!("sent 2.5 EPIC to {ADDRESS} via 192.0.2.8:443 pin 4321");
        dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "dart", tag = "send", "{message}");
        });

        let bundle = stored(dir.path());
        assert!(
            bundle.contains(
                " dart: sent [amount] to esWW…K3oa@[host] via [ip] pin [redacted] tag=send\n"
            ),
            "{bundle}"
        );
    }

    #[derive(Debug, Error)]
    #[error("node at 192.0.2.10:3413 refused the wallet in /home/alice/.lepic")]
    struct NodeError;

    #[test]
    fn error_text_is_redacted_like_messages() {
        let dir = tempfile::tempdir().unwrap();
        let ring = Arc::new(open(dir.path(), 64 * 1024));
        let dispatch = host_dispatch(ring.clone(), LogFilter::parse("trace").unwrap());
        dispatcher::with_default(&dispatch, || {
            tracing::warn!(error = %crate::ErrorChain(&NodeError), "node call failed");
        });

        let bundle = stored(dir.path());
        assert!(
            bundle
                .contains(": node call failed error=node at [ip] refused the wallet in ~/.lepic\n"),
            "{bundle}"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
