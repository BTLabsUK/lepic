//! Secrets come from `LEPIC_PASSWORD` (the wallet password only), a prompt with echo off when
//! standard input is a terminal, or one line of standard input each. Never from arguments, which
//! other users can read from the process table and shells write to history.

use std::io::{self, BufRead, Read as _, Write};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::settings::Env;

pub const PASSWORD_ENV: &str = "LEPIC_PASSWORD";

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
    #[error("the two passwords differ")]
    Mismatch,
    #[error("a hidden prompt is not available here; pipe the {what} to standard input")]
    NoHiddenPrompt { what: &'static str },
    #[error("reading the {what} failed")]
    Io {
        what: &'static str,
        #[source]
        source: io::Error,
    },
}

/// Where secrets are read from.
pub struct SecretInput {
    reader: Box<dyn BufRead + Send>,
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
            reader,
            terminal,
            prompt,
        }
    }

    /// The wallet password: `LEPIC_PASSWORD`, else the prompt or a line of input. A new
    /// password is asked for twice at a terminal.
    pub fn wallet_password(
        &mut self,
        env: &Env,
        new: bool,
    ) -> Result<Zeroizing<String>, SecretError> {
        if let Some(password) = env.get(PASSWORD_ENV) {
            return Ok(Zeroizing::new(password.to_owned()));
        }
        let password = self.read("wallet password", "Wallet password: ")?;
        if new && self.terminal {
            let again = self.read("wallet password", "Repeat the wallet password: ")?;
            if *again != *password {
                return Err(SecretError::Mismatch);
            }
        }
        Ok(password)
    }

    /// Reads one secret, without its line ending.
    pub fn read(
        &mut self,
        what: &'static str,
        prompt: &str,
    ) -> Result<Zeroizing<String>, SecretError> {
        let _echo = if self.terminal {
            let io_error = |source| SecretError::Io { what, source };
            let guard = EchoGuard::off().ok_or(SecretError::NoHiddenPrompt { what })?;
            self.prompt.write_all(prompt.as_bytes()).map_err(io_error)?;
            self.prompt.flush().map_err(io_error)?;
            Some(guard)
        } else {
            None
        };
        let line = self.read_line(what);
        if self.terminal {
            // The newline the user typed was not echoed.
            let _ = self.prompt.write_all(b"\n");
        }
        line
    }

    fn read_line(&mut self, what: &'static str) -> Result<Zeroizing<String>, SecretError> {
        let limit = u64::try_from(MAX_SECRET_LEN)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut bytes = Zeroizing::new(Vec::new());
        let read = (&mut self.reader)
            .take(limit)
            .read_until(b'\n', &mut bytes)
            .map_err(|source| SecretError::Io { what, source })?;
        if read == 0 {
            return Err(SecretError::Missing { what });
        }
        let content = bytes
            .strip_suffix(b"\n")
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .unwrap_or(&bytes);
        if content.len() > MAX_SECRET_LEN {
            return Err(SecretError::TooLong { what });
        }
        let text = std::str::from_utf8(content).map_err(|_| SecretError::NotUtf8 { what })?;
        Ok(Zeroizing::new(text.to_owned()))
    }
}

/// Turns terminal echo off until dropped. `unsafe` is denied, so this asks `stty`, which every
/// Unix has, instead of calling `tcsetattr`.
struct EchoGuard;

impl EchoGuard {
    #[cfg(unix)]
    fn off() -> Option<Self> {
        stty("-echo").then_some(Self)
    }

    #[cfg(not(unix))]
    fn off() -> Option<Self> {
        None
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        stty("echo");
    }
}

#[cfg(unix)]
fn stty(setting: &str) -> bool {
    std::process::Command::new("stty")
        .arg(setting)
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

    #[test]
    fn reads_one_secret_per_line_without_the_line_ending() {
        let mut input = input("first\r\nsecond\nthird");
        assert_eq!(*input.read("a", "").unwrap(), "first");
        assert_eq!(*input.read("b", "").unwrap(), "second");
        assert_eq!(*input.read("c", "").unwrap(), "third");
        assert!(matches!(
            input.read("d", ""),
            Err(SecretError::Missing { what: "d" })
        ));
    }

    #[test]
    fn the_password_variable_wins_over_standard_input() {
        let env = Env::new([(PASSWORD_ENV.to_owned(), "from env".to_owned())]);
        let mut input = input("from stdin\n");
        assert_eq!(*input.wallet_password(&env, true).unwrap(), "from env");
        assert_eq!(*input.read("next", "").unwrap(), "from stdin");
    }

    #[test]
    fn rejects_overlong_and_non_utf8_secrets() {
        let long = "x".repeat(MAX_SECRET_LEN + 1);
        assert!(matches!(
            input(&long).read("p", ""),
            Err(SecretError::TooLong { .. })
        ));
        assert!(matches!(
            input(&format!("{long}\n")).read("p", ""),
            Err(SecretError::TooLong { .. })
        ));
        let exact = "x".repeat(MAX_SECRET_LEN);
        assert_eq!(
            input(&format!("{exact}\n")).read("p", "").unwrap().len(),
            MAX_SECRET_LEN
        );
        let mut bad = SecretInput::new(
            Box::new(io::Cursor::new(vec![0xff, b'\n'])),
            false,
            Box::new(io::sink()),
        );
        assert!(matches!(
            bad.read("p", ""),
            Err(SecretError::NotUtf8 { .. })
        ));
    }
}
