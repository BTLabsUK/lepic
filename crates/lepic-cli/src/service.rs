// SPDX-License-Identifier: Apache-2.0
//! The socket `lepic serve` answers the wallet API on, and its file rules.

use std::path::{Path, PathBuf};

use crate::exit::CliError;

/// The socket's name inside the data directory.
const SOCKET_FILE: &str = "lepic.sock";

/// The most bytes `sun_path` holds, without its terminating zero.
#[cfg(unix)]
const SOCKET_PATH_MAX: usize = if cfg!(any(target_os = "linux", target_os = "android")) {
    107
} else {
    103
};

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

#[cfg(unix)]
pub(crate) use server::{Listening, bind};

#[cfg(unix)]
mod server {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use tokio::net::{UnixListener, UnixStream};

    use super::check_socket_path;
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
        let listening = Listening {
            listener,
            path: path.to_owned(),
            owner: rustix::process::geteuid().as_raw(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(CliError::io("restrict the socket to its owner"))?;
        Ok(listening)
    }

    #[cfg(test)]
    mod tests {
        // Tests may unwrap (docs/rules.md).
        #![allow(clippy::unwrap_used)]

        use super::*;

        /// The peer's uid against serve's: a second account to connect from is not at hand in a
        /// test, so serve's uid is changed instead.
        #[tokio::test]
        async fn a_peer_of_another_user_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("s.sock");
            let mut listening = bind(&path).unwrap();
            let _client = UnixStream::connect(&path).await.unwrap();
            let stream = listening.accept().await.unwrap();
            assert!(listening.is_this_user(&stream));
            listening.owner = listening.owner.wrapping_add(1);
            assert!(!listening.is_this_user(&stream));
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

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
