// SPDX-License-Identifier: Apache-2.0
//! The protocol between `lepic --service` and `lepic serve`, and the socket they share. It is
//! local to the CLI: the app does not speak it.
//!
//! One request per connection. The client sends one line of JSON, a [`Request`], and the server
//! answers with one JSON object, a [`Reply`], and closes the connection.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::exit::CliError;
use crate::settings::OutputFormat;

/// The socket's name inside the data directory.
const SOCKET_FILE: &str = "lepic.sock";

/// The longest request line the server reads.
#[cfg(unix)]
pub(crate) const MAX_REQUEST_LEN: usize = 64 * 1024;

/// The longest reply the client reads.
#[cfg(unix)]
const MAX_REPLY_LEN: u64 = 64 * 1024 * 1024;

/// The most bytes `sun_path` holds, without its terminating zero.
#[cfg(unix)]
const SOCKET_PATH_MAX: usize = if cfg!(any(target_os = "linux", target_os = "android")) {
    107
} else {
    103
};

/// The command line after the program name, without the client's `--service` option.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Request {
    pub args: Vec<String>,
}

/// What the command would have printed and exited with in a process of its own.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Reply {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
}

pub(crate) fn default_socket(data_dir: &Path) -> PathBuf {
    data_dir.join(SOCKET_FILE)
}

/// Refuses a path a unix socket cannot be bound to or connected at.
#[cfg(unix)]
pub(crate) fn check_socket_path(path: &Path) -> Result<(), CliError> {
    if path.as_os_str().len() > SOCKET_PATH_MAX {
        return Err(CliError::SocketPathTooLong {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// The arguments to send for the command line `args`, whose first item is the program name: the
/// rest without the `--service` option, led by the output format when `output` gives one.
pub(crate) fn request_args(
    args: &[std::ffi::OsString],
    output: Option<OutputFormat>,
) -> Result<Vec<String>, CliError> {
    let mut sent = Vec::new();
    if let Some(format) = output {
        sent.push("--output".to_owned());
        sent.push(
            match format {
                OutputFormat::Human => "human",
                OutputFormat::Json => "json",
            }
            .to_owned(),
        );
    }
    let mut options = true;
    for arg in args.iter().skip(1) {
        let arg = arg.to_str().ok_or(CliError::ServiceRequest {
            reason: "an argument is not valid unicode",
        })?;
        if options && arg == "--" {
            options = false;
        }
        if options && (arg == "--service" || arg.starts_with("--service=")) {
            continue;
        }
        sent.push(arg.to_owned());
    }
    Ok(sent)
}

/// The request line for `args`, newline included.
#[cfg(unix)]
fn encode_request(args: Vec<String>) -> Result<Vec<u8>, CliError> {
    let mut line = serde_json::to_vec(&Request { args }).map_err(|_| CliError::ServiceRequest {
        reason: "the arguments cannot be encoded",
    })?;
    line.push(b'\n');
    if line.len() > MAX_REQUEST_LEN {
        return Err(CliError::ServiceRequest {
            reason: "the request is longer than 64 KiB",
        });
    }
    Ok(line)
}

#[cfg(unix)]
pub(crate) fn decode_request(line: &[u8]) -> Result<Request, CliError> {
    if line.len() > MAX_REQUEST_LEN {
        return Err(CliError::ServiceRequest {
            reason: "the request is longer than 64 KiB",
        });
    }
    serde_json::from_slice(line.trim_ascii()).map_err(|_| CliError::ServiceRequest {
        reason: "the request is not one json object with an args list",
    })
}

/// Sends `args` to the server at `path` and waits for its reply. Blocks until the command ends,
/// however long that takes.
#[cfg(unix)]
pub(crate) fn call(path: &Path, args: Vec<String>) -> Result<Reply, CliError> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;

    check_socket_path(path)?;
    let line = encode_request(args)?;
    let mut stream = UnixStream::connect(path).map_err(|source| match source.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            CliError::ServiceUnavailable {
                path: path.to_owned(),
            }
        }
        _ => CliError::io("connect to the service")(source),
    })?;
    stream
        .write_all(&line)
        .and_then(|()| stream.flush())
        .map_err(CliError::io("send the request to the service"))?;
    let mut text = Vec::new();
    (&stream)
        .take(MAX_REPLY_LEN.saturating_add(1))
        .read_to_end(&mut text)
        .map_err(CliError::io("read the reply of the service"))?;
    if u64::try_from(text.len()).map_or(true, |len| len > MAX_REPLY_LEN) {
        return Err(CliError::ServiceRequest {
            reason: "the reply is longer than 64 MiB",
        });
    }
    serde_json::from_slice(&text).map_err(|source| {
        CliError::io("read the reply of the service")(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            source,
        ))
    })
}

#[cfg(not(unix))]
pub(crate) fn call(_: &Path, _: Vec<String>) -> Result<Reply, CliError> {
    Err(CliError::ServiceUnsupported)
}

#[cfg(unix)]
pub(crate) use server::{Listening, bind, read_request, write_reply};

#[cfg(unix)]
mod server {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    use super::{MAX_REQUEST_LEN, Reply, Request, check_socket_path, decode_request};
    use crate::exit::CliError;

    /// The socket `lepic serve` listens on. The socket file is removed when this is dropped.
    pub(crate) struct Listening {
        listener: UnixListener,
        path: PathBuf,
        owner: u32,
    }

    impl Listening {
        pub(crate) async fn accept(&self) -> std::io::Result<UnixStream> {
            self.listener.accept().await.map(|(stream, _)| stream)
        }

        /// Whether the process on the other end of `stream` runs as the user that runs serve.
        pub(crate) fn is_this_user(&self, stream: &UnixStream) -> bool {
            stream
                .peer_cred()
                .is_ok_and(|credentials| credentials.uid() == self.owner)
        }
    }

    impl Drop for Listening {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Binds `path`, owner-only. The caller holds the data directory lock, so no other serve
    /// owns a socket file left at `path`; only a socket is replaced.
    pub(crate) fn bind(path: &Path) -> Result<Listening, CliError> {
        check_socket_path(path)?;
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => {
                std::fs::remove_file(path).map_err(CliError::io("remove the old socket"))?;
            }
            Ok(_) => {
                return Err(CliError::SocketPathTaken {
                    path: path.to_owned(),
                });
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(CliError::io("check the socket path")(source)),
        }
        let listener = UnixListener::bind(path).map_err(CliError::io("bind the socket"))?;
        let listening = |owner| Listening {
            listener,
            path: path.to_owned(),
            owner,
        };
        // Removes the file again if the next steps fail.
        let bound = std::fs::symlink_metadata(path).map_err(CliError::io("check the socket"));
        let listening = match bound {
            Ok(meta) => listening(meta.uid()),
            Err(error) => {
                let _ = std::fs::remove_file(path);
                return Err(error);
            }
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(CliError::io("restrict the socket to its owner"))?;
        Ok(listening)
    }

    /// Reads the request line from `stream`, at most [`MAX_REQUEST_LEN`] bytes.
    pub(crate) async fn read_request(stream: &mut UnixStream) -> Result<Request, CliError> {
        let limit = u64::try_from(MAX_REQUEST_LEN)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut line = Vec::new();
        BufReader::new(stream.take(limit))
            .read_until(b'\n', &mut line)
            .await
            .map_err(CliError::io("read the request"))?;
        decode_request(&line)
    }

    pub(crate) async fn write_reply(
        stream: &mut UnixStream,
        reply: &Reply,
    ) -> Result<(), CliError> {
        let text = serde_json::to_vec(reply).map_err(|source| {
            CliError::io("encode the reply")(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                source,
            ))
        })?;
        stream
            .write_all(&text)
            .await
            .map_err(CliError::io("send the reply"))?;
        stream
            .shutdown()
            .await
            .map_err(CliError::io("send the reply"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_request_round_trips_and_is_bounded() {
        let line = encode_request(vec!["tx".to_owned(), "list".to_owned()]).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(decode_request(&line).unwrap().args, ["tx", "list"]);
        let long = vec!["x".repeat(MAX_REQUEST_LEN)];
        assert!(matches!(
            encode_request(long),
            Err(CliError::ServiceRequest { .. })
        ));
        assert!(decode_request(b"[1]").is_err());
    }

    #[test]
    fn a_socket_path_is_limited_to_what_sun_path_holds() {
        assert!(check_socket_path(Path::new("/tmp/lepic.sock")).is_ok());
        let long = Path::new("/tmp").join("x".repeat(200));
        assert!(matches!(
            check_socket_path(&long),
            Err(CliError::SocketPathTooLong { .. })
        ));
    }
}
