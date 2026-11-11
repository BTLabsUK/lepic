// SPDX-License-Identifier: Apache-2.0
//! Secrets come from the password file or `LEPIC_PASSWORD` (the wallet password only), a prompt
//! with echo off when standard input is a terminal, or one line of standard input each. Never from arguments, which
//! other users can read from the process table and shells write to history.

use std::io::{self, BufRead, Read as _, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use tokio::sync::oneshot;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::settings::Env;

pub const PASSWORD_ENV: &str = "LEPIC_PASSWORD";
pub const NEW_PASSWORD_ENV: &str = "LEPIC_NEW_PASSWORD";
pub const NEW_PASSWORD_FILE_ENV: &str = "LEPIC_NEW_PASSWORD_FILE";

/// Longer than any password or recovery phrase a person types.
pub const MAX_SECRET_LEN: usize = 4096;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretError {
    #[error("standard input ended before the {what} was given")]
    Missing { what: &'static str },
    #[error("the {what} is longer than {MAX_SECRET_LEN} bytes")]
    TooLong { what: &'static str },
    #[error("the {what} is not valid utf-8")]
    NotUtf8 { what: &'static str },
    #[error("the {what} prompt was cancelled")]
    Cancelled { what: &'static str },
    #[error("the two passwords differ")]
    Mismatch,
    #[error("a new wallet password cannot be empty")]
    EmptyNew,
    #[error("a hidden prompt is not available here; pipe the {what} to standard input")]
    NoHiddenPrompt { what: &'static str },
    #[error("the password file {} can be read by other users; make it owner-only (chmod 600)", path.display())]
    PasswordFileOpen { path: PathBuf },
    #[error("the password file {} holds no password", path.display())]
    PasswordFileEmpty { path: PathBuf },
    #[error("reading the password file {} failed", path.display())]
    PasswordFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("reading the {what} failed")]
    Io {
        what: &'static str,
        #[source]
        source: io::Error,
    },
}

/// Where secrets are read from.
///
/// Each line is read on its own thread, so the command's runtime keeps running while the user
/// types and an interrupt can end the command at a prompt. The echo guard lives in the read's
/// future, so dropping that future turns echo back on.
pub struct SecretInput {
    reader: Arc<Mutex<Box<dyn BufRead + Send>>>,
    terminal: bool,
    prompt: Box<dyn Write + Send>,
}

impl SecretInput {
    /// `terminal` says whether `reader` is an interactive terminal, in which case each secret
    /// is prompted for on `prompt` with echo turned off.
    pub fn new(
        reader: Box<dyn BufRead + Send>,
        terminal: bool,
        prompt: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader)),
            terminal,
            prompt,
        }
    }

    /// The wallet password: the first line of `file`, else `LEPIC_PASSWORD`, else the prompt or
    /// a line of input. `LEPIC_PASSWORD` is removed from `env` either way. A new password must
    /// be non-empty and is asked for twice at a terminal; the CLI sets no other rule.
    pub async fn wallet_password(
        &mut self,
        env: &mut Env,
        file: Option<&Path>,
        new: bool,
    ) -> Result<Zeroizing<String>, SecretError> {
        let prompts = ("Wallet password: ", "Repeat the wallet password: ");
        self.password(env, PASSWORD_ENV, file, new, prompts).await
    }

    /// The password `wallet password` changes to: the first line of `file`, else
    /// `LEPIC_NEW_PASSWORD`, else the prompt (asked twice at a terminal) or a line of input. It
    /// must be non-empty.
    pub async fn changed_wallet_password(
        &mut self,
        env: &mut Env,
        file: Option<&Path>,
    ) -> Result<Zeroizing<String>, SecretError> {
        let prompts = ("New wallet password: ", "Repeat the new wallet password: ");
        self.password(env, NEW_PASSWORD_ENV, file, true, prompts)
            .await
    }

    async fn password(
        &mut self,
        env: &mut Env,
        variable: &str,
        file: Option<&Path>,
        new: bool,
        (prompt, repeat): (&str, &str),
    ) -> Result<Zeroizing<String>, SecretError> {
        let non_empty = |password: Zeroizing<String>| {
            if new && password.is_empty() {
                return Err(SecretError::EmptyNew);
            }
            Ok(password)
        };
        let from_env = env.take(variable);
        if let Some(path) = file {
            return non_empty(read_password_file(path)?);
        }
        if let Some(password) = from_env {
            return non_empty(password);
        }
        let password = non_empty(self.read("wallet password", prompt).await?)?;
        if new && self.terminal {
            let again = self.read("wallet password", repeat).await?;
            if *again != *password {
                return Err(SecretError::Mismatch);
            }
        }
        Ok(password)
    }

    /// Reads one secret, without its line ending.
    pub async fn read(
        &mut self,
        what: &'static str,
        prompt: &str,
    ) -> Result<Zeroizing<String>, SecretError> {
        #[cfg(not(unix))]
        if self.terminal {
            return self.read_typed(what, prompt).await;
        }
        let _echo = if self.terminal {
            let io_error = |source| SecretError::Io { what, source };
            let guard = EchoGuard::off().ok_or(SecretError::NoHiddenPrompt { what })?;
            self.prompt.write_all(prompt.as_bytes()).map_err(io_error)?;
            self.prompt.flush().map_err(io_error)?;
            Some(guard)
        } else {
            None
        };
        let line = self.next_line(what).await;
        if self.terminal {
            // The newline the user typed was not echoed.
            let _ = self.prompt.write_all(b"\n");
        }
        line
    }

    /// Reads a key at a time on a thread of its own, where the terminal has no echo to turn off.
    #[cfg(not(unix))]
    async fn read_typed(
        &mut self,
        what: &'static str,
        prompt: &str,
    ) -> Result<Zeroizing<String>, SecretError> {
        let io_error = |source| SecretError::Io { what, source };
        self.prompt.write_all(prompt.as_bytes()).map_err(io_error)?;
        self.prompt.flush().map_err(io_error)?;
        let (sender, receiver) = oneshot::channel();
        std::thread::Builder::new()
            .name("lepic-secret-input".to_owned())
            .spawn(move || {
                let _ = sender.send(read_keys(what));
            })
            .map_err(io_error)?;
        let line = receiver.await.map_err(|_| SecretError::Missing { what })?;
        let _ = self.prompt.write_all(b"\n");
        line
    }

    async fn next_line(&self, what: &'static str) -> Result<Zeroizing<String>, SecretError> {
        let (sender, receiver) = oneshot::channel();
        let reader = Arc::clone(&self.reader);
        std::thread::Builder::new()
            .name("lepic-secret-input".to_owned())
            .spawn(move || {
                let mut reader = reader.lock().unwrap_or_else(PoisonError::into_inner);
                // Nobody waits any more when the command was interrupted.
                let _ = sender.send(read_line(&mut **reader, what));
            })
            .map_err(|source| SecretError::Io { what, source })?;
        receiver.await.map_err(|_| SecretError::Missing { what })?
    }
}

fn read_line(
    reader: &mut dyn BufRead,
    what: &'static str,
) -> Result<Zeroizing<String>, SecretError> {
    let limit = u64::try_from(MAX_SECRET_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = line_buffer();
    let read = reader
        .take(limit)
        .read_until(b'\n', &mut bytes)
        .map_err(|source| SecretError::Io { what, source })?;
    if read == 0 {
        return Err(SecretError::Missing { what });
    }
    first_line(&bytes, what)
}

/// The first line of `bytes`, without its line ending.
fn first_line(bytes: &[u8], what: &'static str) -> Result<Zeroizing<String>, SecretError> {
    let line = bytes.split(|byte| *byte == b'\n').next().unwrap_or(bytes);
    let content = line.strip_suffix(b"\r").unwrap_or(line);
    if content.len() > MAX_SECRET_LEN {
        return Err(SecretError::TooLong { what });
    }
    let text = std::str::from_utf8(content).map_err(|_| SecretError::NotUtf8 { what })?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// The wallet password from the first line of a file only its owner can read, the way a service
/// manager hands a secret to a service without putting it in the environment. See
/// [`readable_by_others`] for the modes taken.
fn read_password_file(path: &Path) -> Result<Zeroizing<String>, SecretError> {
    let failed = |source| SecretError::PasswordFile {
        path: path.to_owned(),
        source,
    };
    let file = std::fs::File::open(path).map_err(failed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata().map_err(failed)?;
        if readable_by_others(metadata.mode(), metadata.uid()) {
            return Err(SecretError::PasswordFileOpen {
                path: path.to_owned(),
            });
        }
    }
    let limit = u64::try_from(MAX_SECRET_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = line_buffer();
    file.take(limit).read_to_end(&mut bytes).map_err(failed)?;
    let password = first_line(&bytes, "wallet password")?;
    if password.is_empty() {
        return Err(SecretError::PasswordFileEmpty {
            path: path.to_owned(),
        });
    }
    Ok(password)
}

/// Whether a file of `mode` owned by `owner` may be read by users the owner did not choose. A file
/// root owns may be readable by its group, or by users an access list names, as a systemd
/// credential is: only root granted that. A file anyone else owns must be owner-only.
#[cfg(unix)]
const fn readable_by_others(mode: u32, owner: u32) -> bool {
    let by_group = mode & 0o070 != 0 && owner != 0;
    let by_anyone = mode & 0o007 != 0;
    by_group || by_anyone
}

/// Holds the most a read takes, the longest secret and one byte more, from the start: a growing
/// `Vec` leaves the bytes it moved out of in freed memory, where `Zeroizing` cannot wipe them.
fn line_buffer() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(MAX_SECRET_LEN.saturating_add(1)))
}

/// Reads one secret from the terminal key by key with nothing echoed, whatever the platform:
/// `prompt` goes to standard error and a newline follows the Enter. For the shell's `unlock`.
pub(crate) fn read_hidden_line(prompt: &str) -> Result<Zeroizing<String>, SecretError> {
    const WHAT: &str = "password";
    let io_error = |source| SecretError::Io { what: WHAT, source };
    let mut stderr = io::stderr();
    stderr.write_all(prompt.as_bytes()).map_err(io_error)?;
    stderr.flush().map_err(io_error)?;
    let line = read_keys(WHAT);
    let _ = stderr.write_all(b"\n");
    line
}

/// Raw mode until dropped, on error and panic too.
struct RawMode;

impl RawMode {
    fn enable() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn read_keys(what: &'static str) -> Result<Zeroizing<String>, SecretError> {
    let _raw = RawMode::enable().map_err(|source| SecretError::Io { what, source })?;
    let mut line = TypedLine::new();
    loop {
        let event = event::read().map_err(|source| SecretError::Io { what, source })?;
        match line.apply(event) {
            Typed::More => {}
            Typed::Done => return Ok(line.text),
            Typed::Cancelled => return Err(SecretError::Cancelled { what }),
            Typed::Ended => return Err(SecretError::Missing { what }),
            Typed::TooLong => return Err(SecretError::TooLong { what }),
        }
    }
}

/// What a terminal event did to the line being typed.
#[derive(Debug, PartialEq, Eq)]
enum Typed {
    More,
    Done,
    Cancelled,
    /// Ctrl-D on an empty line: no input, as the end of a stream.
    Ended,
    TooLong,
}

/// The line typed so far. The text is reserved at its longest from the start, so it never
/// moves and leaves no copy for `Zeroizing` to miss.
struct TypedLine {
    text: Zeroizing<String>,
}

impl TypedLine {
    fn new() -> Self {
        Self {
            text: Zeroizing::new(String::with_capacity(MAX_SECRET_LEN.saturating_add(1))),
        }
    }

    fn apply(&mut self, event: Event) -> Typed {
        match event {
            Event::Key(key) => self.key(key),
            Event::Paste(pasted) => self.paste(&Zeroizing::new(pasted)),
            _ => Typed::More,
        }
    }

    fn key(&mut self, key: KeyEvent) -> Typed {
        // Windows reports the release of every key as well.
        if key.kind == KeyEventKind::Release {
            return Typed::More;
        }
        // AltGr arrives as Ctrl and Alt together and types a character.
        let control = key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Char('c') if control => Typed::Cancelled,
            KeyCode::Char('d') if control => {
                if self.text.is_empty() {
                    Typed::Ended
                } else {
                    Typed::More
                }
            }
            KeyCode::Esc => Typed::Cancelled,
            KeyCode::Enter => Typed::Done,
            KeyCode::Backspace => {
                self.text.pop();
                Typed::More
            }
            KeyCode::Char(typed) if !control => self.push(typed),
            _ => Typed::More,
        }
    }

    /// Takes the text up to its first line ending, which ends the line.
    fn paste(&mut self, pasted: &str) -> Typed {
        for typed in pasted.chars() {
            if matches!(typed, '\r' | '\n') {
                return Typed::Done;
            }
            if self.push(typed) == Typed::TooLong {
                return Typed::TooLong;
            }
        }
        Typed::More
    }

    fn push(&mut self, typed: char) -> Typed {
        let length = self.text.len().saturating_add(typed.len_utf8());
        if length > MAX_SECRET_LEN {
            return Typed::TooLong;
        }
        self.text.push(typed);
        Typed::More
    }
}

/// Turns terminal echo off until dropped. `unsafe` is denied, so this asks `stty`, which every
/// Unix has, instead of calling `tcsetattr`. Elsewhere the prompt reads keys itself.
struct EchoGuard;

impl EchoGuard {
    #[cfg(unix)]
    fn off() -> Option<Self> {
        stty("-echo").then_some(Self)
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        stty("echo");
    }
}

#[cfg(unix)]
fn stty(setting: &str) -> bool {
    std::process::Command::new("stty")
        .arg(setting)
        .env_remove(PASSWORD_ENV)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(text: &str) -> SecretInput {
        SecretInput::new(
            Box::new(io::Cursor::new(text.as_bytes().to_vec())),
            false,
            Box::new(io::sink()),
        )
    }

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// Input that never arrives, as from a user who has not pressed Enter yet.
    struct Silent(std::sync::mpsc::Receiver<()>);

    impl io::Read for Silent {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    #[test]
    fn reads_one_secret_per_line_without_the_line_ending() {
        let mut input = input("first\r\nsecond\nthird");
        block_on(async {
            assert_eq!(*input.read("a", "").await.unwrap(), "first");
            assert_eq!(*input.read("b", "").await.unwrap(), "second");
            assert_eq!(*input.read("c", "").await.unwrap(), "third");
            assert!(matches!(
                input.read("d", "").await,
                Err(SecretError::Missing { what: "d" })
            ));
        });
    }

    #[test]
    fn the_password_variable_wins_over_standard_input() {
        let mut env = Env::new([(PASSWORD_ENV.to_owned(), "from env".to_owned())]);
        let mut input = input("from stdin\n");
        block_on(async {
            assert_eq!(
                *input.wallet_password(&mut env, None, true).await.unwrap(),
                "from env"
            );
            assert_eq!(*input.read("next", "").await.unwrap(), "from stdin");
        });
    }

    #[test]
    fn an_empty_new_password_is_refused_from_every_source() {
        // An empty variable counts as unset, so the empty line on standard input is read.
        let vars: [Vec<(String, String)>; 2] =
            [vec![(PASSWORD_ENV.to_owned(), String::new())], vec![]];
        for vars in vars {
            let mut env = Env::new(vars);
            let mut input = input("\n");
            block_on(async {
                assert!(matches!(
                    input.wallet_password(&mut env, None, true).await,
                    Err(SecretError::EmptyNew)
                ));
            });
        }
    }

    /// A short password is read as it is, for a new wallet or an existing one.
    #[test]
    fn a_short_password_is_read_as_it_is() {
        let mut env = Env::new([(PASSWORD_ENV.to_owned(), "pw".to_owned())]);
        let mut input = input("pw\n");
        block_on(async {
            assert_eq!(
                *input.wallet_password(&mut env, None, false).await.unwrap(),
                "pw"
            );
            assert_eq!(
                *input.wallet_password(&mut env, None, false).await.unwrap(),
                "pw"
            );
        });
    }

    #[test]
    fn the_password_variable_is_removed_once_read() {
        let mut env = Env::new([(PASSWORD_ENV.to_owned(), "from env".to_owned())]);
        let mut input = input("from stdin\n");
        block_on(async {
            input.wallet_password(&mut env, None, false).await.unwrap();
            assert_eq!(env.get(PASSWORD_ENV), None);
            assert_eq!(
                *input.wallet_password(&mut env, None, false).await.unwrap(),
                "from stdin"
            );
        });
    }

    fn password_file(text: &str, mode: u32) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(text.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        file
    }

    #[test]
    fn the_password_file_wins_and_the_variable_is_still_removed() {
        let file = password_file("from file\nignored\n", 0o600);
        let mut env = Env::new([(PASSWORD_ENV.to_owned(), "from env".to_owned())]);
        let mut input = input("from stdin\n");
        block_on(async {
            assert_eq!(
                *input
                    .wallet_password(&mut env, Some(file.path()), true)
                    .await
                    .unwrap(),
                "from file"
            );
            assert_eq!(env.get(PASSWORD_ENV), None);
            assert_eq!(*input.read("next", "").await.unwrap(), "from stdin");
        });
    }

    #[test]
    fn an_empty_or_missing_password_file_is_refused() {
        let empty = password_file("\n", 0o600);
        let mut input = input("");
        block_on(async {
            assert!(matches!(
                input
                    .wallet_password(&mut Env::default(), Some(empty.path()), false)
                    .await,
                Err(SecretError::PasswordFileEmpty { .. })
            ));
            assert!(matches!(
                input
                    .wallet_password(
                        &mut Env::default(),
                        Some(Path::new("/nonexistent/pw")),
                        false
                    )
                    .await,
                Err(SecretError::PasswordFile { .. })
            ));
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_password_file_other_users_can_read_is_refused() {
        let file = password_file("secret\n", 0o640);
        let mut input = input("");
        block_on(async {
            assert!(matches!(
                input
                    .wallet_password(&mut Env::default(), Some(file.path()), false)
                    .await,
                Err(SecretError::PasswordFileOpen { .. })
            ));
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_root_owned_file_may_be_read_by_its_group_but_never_by_anyone() {
        assert!(!readable_by_others(0o100_600, 1000));
        assert!(readable_by_others(0o100_640, 1000));
        assert!(!readable_by_others(0o100_440, 0));
        assert!(readable_by_others(0o100_444, 0));
        assert!(readable_by_others(0o100_604, 1000));
    }

    #[test]
    fn the_longest_line_is_read_without_moving_the_buffer() {
        let mut bytes = line_buffer();
        let start = bytes.as_ptr();
        let line = format!("{}\n", "x".repeat(MAX_SECRET_LEN));
        io::Cursor::new(line.as_bytes())
            .take(u64::try_from(MAX_SECRET_LEN + 1).unwrap())
            .read_until(b'\n', &mut bytes)
            .unwrap();
        assert_eq!(bytes.len(), MAX_SECRET_LEN + 1);
        assert_eq!(bytes.as_ptr(), start);
    }

    #[test]
    fn rejects_overlong_and_non_utf8_secrets() {
        let long = "x".repeat(MAX_SECRET_LEN + 1);
        let exact = "x".repeat(MAX_SECRET_LEN);
        block_on(async {
            assert!(matches!(
                input(&long).read("p", "").await,
                Err(SecretError::TooLong { .. })
            ));
            assert!(matches!(
                input(&format!("{long}\n")).read("p", "").await,
                Err(SecretError::TooLong { .. })
            ));
            assert_eq!(
                input(&format!("{exact}\n"))
                    .read("p", "")
                    .await
                    .unwrap()
                    .len(),
                MAX_SECRET_LEN
            );
            let mut bad = SecretInput::new(
                Box::new(io::Cursor::new(vec![0xff, b'\n'])),
                false,
                Box::new(io::sink()),
            );
            assert!(matches!(
                bad.read("p", "").await,
                Err(SecretError::NotUtf8 { .. })
            ));
        });
    }

    #[test]
    fn a_pending_read_leaves_the_runtime_free_to_end_it() {
        let (_keep_open, receiver) = std::sync::mpsc::channel();
        let mut input = SecretInput::new(
            Box::new(io::BufReader::new(Silent(receiver))),
            false,
            Box::new(io::sink()),
        );
        let outcome = block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(50), input.read("p", "")).await
        });
        assert!(outcome.is_err(), "the read finished: {outcome:?}");
    }

    fn key(code: KeyCode, modifiers: KeyModifiers, kind: KeyEventKind) -> Event {
        let mut key = KeyEvent::new(code, modifiers);
        key.kind = kind;
        Event::Key(key)
    }

    fn typed(text: &str) -> Vec<Event> {
        text.chars()
            .map(|c| key(KeyCode::Char(c), KeyModifiers::NONE, KeyEventKind::Press))
            .collect()
    }

    fn press(code: KeyCode) -> Event {
        key(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    fn run(events: Vec<Event>) -> (TypedLine, Typed) {
        let mut line = TypedLine::new();
        for event in events {
            let step = line.apply(event);
            if step != Typed::More {
                return (line, step);
            }
        }
        (line, Typed::More)
    }

    #[test]
    fn typed_keys_build_the_line_until_enter() {
        let mut events = typed("abc");
        events.push(press(KeyCode::Enter));
        events.extend(typed("ignored"));
        let (line, step) = run(events);
        assert_eq!(step, Typed::Done);
        assert_eq!(*line.text, "abc");
    }

    #[test]
    fn backspace_removes_one_character_and_is_harmless_on_an_empty_line() {
        let mut events = vec![press(KeyCode::Backspace)];
        events.extend(typed("a\u{e9}x"));
        events.extend([press(KeyCode::Backspace), press(KeyCode::Backspace)]);
        events.extend(typed("b"));
        events.push(press(KeyCode::Enter));
        let (line, step) = run(events);
        assert_eq!(step, Typed::Done);
        assert_eq!(*line.text, "ab");
    }

    #[test]
    fn release_events_are_ignored() {
        let release = key(
            KeyCode::Char('x'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        let enter = key(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        let (line, step) = run(vec![press(KeyCode::Char('a')), release, enter]);
        assert_eq!(step, Typed::More);
        assert_eq!(*line.text, "a");
    }

    #[test]
    fn control_c_and_escape_cancel() {
        let ctrl = |c| key(KeyCode::Char(c), KeyModifiers::CONTROL, KeyEventKind::Press);
        assert_eq!(run(vec![ctrl('c')]).1, Typed::Cancelled);
        assert_eq!(run(vec![press(KeyCode::Esc)]).1, Typed::Cancelled);
        let mut events = typed("abc");
        events.push(ctrl('c'));
        assert_eq!(run(events).1, Typed::Cancelled);
    }

    #[test]
    fn control_d_ends_only_an_empty_line() {
        let ctrl_d = || {
            key(
                KeyCode::Char('d'),
                KeyModifiers::CONTROL,
                KeyEventKind::Press,
            )
        };
        assert_eq!(run(vec![ctrl_d()]).1, Typed::Ended);
        let mut events = typed("ab");
        events.push(ctrl_d());
        events.push(press(KeyCode::Enter));
        let (line, step) = run(events);
        assert_eq!(step, Typed::Done);
        assert_eq!(*line.text, "ab");
    }

    #[test]
    fn other_control_keys_and_altgr_characters() {
        let ctrl_a = key(
            KeyCode::Char('a'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        let altgr = key(
            KeyCode::Char('@'),
            KeyModifiers::CONTROL | KeyModifiers::ALT,
            KeyEventKind::Press,
        );
        let (line, _) = run(vec![
            ctrl_a,
            altgr,
            press(KeyCode::Tab),
            press(KeyCode::Left),
        ]);
        assert_eq!(*line.text, "@");
    }

    #[test]
    fn a_paste_is_appended_and_a_line_ending_in_it_ends_the_line() {
        let (line, step) = run(vec![
            Event::Paste("ab".to_owned()),
            Event::Paste("cd\r\nrest".to_owned()),
        ]);
        assert_eq!(step, Typed::Done);
        assert_eq!(*line.text, "abcd");
    }

    #[test]
    fn the_limit_is_kept_by_keys_and_by_pastes_without_moving_the_text() {
        let exact = "x".repeat(MAX_SECRET_LEN);
        let mut line = TypedLine::new();
        let start = line.text.as_ptr();
        assert_eq!(line.apply(Event::Paste(exact)), Typed::More);
        assert_eq!(line.text.len(), MAX_SECRET_LEN);
        assert_eq!(line.apply(press(KeyCode::Char('y'))), Typed::TooLong);
        assert_eq!(line.apply(Event::Paste("z".to_owned())), Typed::TooLong);
        assert_eq!(line.text.len(), MAX_SECRET_LEN);
        assert_eq!(line.text.as_ptr(), start);

        let (_, step) = run(vec![Event::Paste("x".repeat(MAX_SECRET_LEN + 1))]);
        assert_eq!(step, Typed::TooLong);
        // A two-byte character that would cross the limit is refused whole.
        let mut line = TypedLine::new();
        line.apply(Event::Paste("x".repeat(MAX_SECRET_LEN - 1)));
        assert_eq!(line.apply(press(KeyCode::Char('\u{e9}'))), Typed::TooLong);
    }
}
