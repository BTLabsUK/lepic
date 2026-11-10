// SPDX-License-Identifier: Apache-2.0
//! The socket `lepic serve` answers the wallet API on, and its file rules.

use std::path::{Path, PathBuf};

use crate::exit::CliError;

/// The socket's name inside the data directory.
const SOCKET_FILE: &str = "lepic.sock";

/// The file in the data directory that names the socket serve answers on, for a serve started
/// with `--socket`. It holds the socket's absolute path, as the bytes of the path.
const POINTER_FILE: &str = "serve-socket";

/// The longest pointer file read: a socket path plus slack.
#[cfg(unix)]
const POINTER_MAX: u64 = 4096;

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

/// Where serve in `data_dir` names its socket: the file `bind` writes.
pub(crate) fn pointer_file(data_dir: &Path) -> PathBuf {
    data_dir.join(POINTER_FILE)
}

/// The sockets a serve that holds `data_dir` may answer on, in the order to try them: the one
/// its pointer file names, then the default. A pointer that is empty, too long or not an
/// absolute path names nothing.
#[cfg(unix)]
pub(crate) fn candidate_sockets(data_dir: &Path) -> Vec<PathBuf> {
    use std::io::Read as _;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    let mut candidates = Vec::with_capacity(2);
    let pointed = std::fs::File::open(pointer_file(data_dir))
        .ok()
        .and_then(|file| {
            let mut bytes = Vec::new();
            file.take(POINTER_MAX + 1).read_to_end(&mut bytes).ok()?;
            (bytes.len() as u64 <= POINTER_MAX).then_some(bytes)
        });
    if let Some(bytes) = pointed {
        let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        if path.is_absolute()
            && !path.as_os_str().as_bytes().contains(&0)
            && check_socket_path(&path).is_ok()
        {
            candidates.push(path);
        }
    }
    let default = default_socket(data_dir);
    if !candidates.contains(&default) {
        candidates.push(default);
    }
    candidates
}

/// Connects to the serve that answers in `data_dir` and returns the stream with the socket it
/// reached. Only a socket served by this user is used. `None` when no serve answers.
#[cfg(unix)]
pub(crate) async fn connect(data_dir: &Path) -> Option<(tokio::net::UnixStream, PathBuf)> {
    connect_as(data_dir, rustix::process::geteuid().as_raw()).await
}

/// [`connect`] for the user `me`.
#[cfg(unix)]
async fn connect_as(data_dir: &Path, me: u32) -> Option<(tokio::net::UnixStream, PathBuf)> {
    for socket in candidate_sockets(data_dir) {
        let Ok(stream) = tokio::net::UnixStream::connect(&socket).await else {
            continue;
        };
        if stream.peer_cred().is_ok_and(|peer| peer.uid() == me) {
            return Some((stream, socket));
        }
    }
    None
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
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use tokio::net::{UnixListener, UnixStream};

    use super::{check_socket_path, pointer_file};
    use crate::exit::CliError;

    /// The socket `lepic serve` listens on. The socket file and the pointer file that names it
    /// are removed when this is dropped, the socket file only while it is still the one bound.
    pub(crate) struct Listening {
        listener: UnixListener,
        path: PathBuf,
        /// The device and inode of the socket file bound.
        file: (u64, u64),
        pointer: PathBuf,
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
            let _ = std::fs::remove_file(&self.pointer);
            if std::fs::symlink_metadata(&self.path)
                .is_ok_and(|meta| (meta.dev(), meta.ino()) == self.file)
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    /// Binds `path`, owner-only, and names it in the pointer file of `data_dir`, so commands
    /// find a socket that is not the default one. The caller holds the data directory lock, so
    /// no other serve owns a pointer file left in `data_dir`. A serve of another data directory
    /// can listen at `path`: a socket that answers is refused, and only one that does not is
    /// replaced.
    pub(crate) fn bind(path: &Path, data_dir: &Path) -> Result<Listening, CliError> {
        check_socket_path(path)?;
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => {
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(CliError::SocketInUse {
                        path: path.to_owned(),
                    });
                }
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
        let meta = std::fs::symlink_metadata(path).map_err(CliError::io("check the socket"))?;
        let pointer = pointer_file(data_dir);
        let listening = Listening {
            listener,
            path: path.to_owned(),
            file: (meta.dev(), meta.ino()),
            pointer: pointer.clone(),
            owner: rustix::process::geteuid().as_raw(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(CliError::io("restrict the socket to its owner"))?;
        let absolute =
            std::path::absolute(path).map_err(CliError::io("resolve the socket path"))?;
        lepic_store::file::write_owner_only_atomic(&pointer, absolute.as_os_str().as_bytes())
            .map_err(CliError::io("write the socket pointer"))?;
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
            let mut listening = bind(&path, dir.path()).unwrap();
            let _client = UnixStream::connect(&path).await.unwrap();
            let stream = listening.accept().await.unwrap();
            assert!(listening.is_this_user(&stream));
            listening.owner = listening.owner.wrapping_add(1);
            assert!(!listening.is_this_user(&stream));
        }

        #[tokio::test]
        async fn a_socket_another_serve_answers_on_is_left_alone() {
            let (first_dir, second_dir) =
                (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let path = first_dir.path().join("s.sock");
            let first = bind(&path, first_dir.path()).unwrap();
            assert!(matches!(
                bind(&path, second_dir.path()),
                Err(CliError::SocketInUse { .. })
            ));
            assert!(UnixStream::connect(&path).await.is_ok());
            drop(first);
            assert!(!path.exists());
        }

        #[tokio::test]
        async fn a_socket_nobody_answers_on_is_replaced() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("s.sock");
            drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
            assert!(path.exists());
            let _listening = bind(&path, dir.path()).unwrap();
            assert!(UnixStream::connect(&path).await.is_ok());
        }

        #[tokio::test]
        async fn a_socket_file_bound_again_since_is_not_removed() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("s.sock");
            let listening = bind(&path, dir.path()).unwrap();
            std::fs::remove_file(&path).unwrap();
            let _other = std::os::unix::net::UnixListener::bind(&path).unwrap();
            drop(listening);
            assert!(path.exists());
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

    #[test]
    fn a_pointer_names_a_socket_to_try_before_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let default = default_socket(dir.path());
        assert_eq!(
            candidate_sockets(dir.path()),
            std::slice::from_ref(&default)
        );

        let named = dir.path().join("other.sock");
        std::fs::write(
            pointer_file(dir.path()),
            named.as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(candidate_sockets(dir.path()), [named, default.clone()]);

        std::fs::write(
            pointer_file(dir.path()),
            default.as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(
            candidate_sockets(dir.path()),
            std::slice::from_ref(&default)
        );
    }

    #[test]
    fn a_pointer_that_names_no_usable_path_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let default = default_socket(dir.path());
        let long = format!("/{}", "x".repeat(200));
        for content in ["", "relative.sock", long.as_str(), "/tmp/a\u{0}b"] {
            std::fs::write(pointer_file(dir.path()), content).unwrap();
            assert_eq!(
                candidate_sockets(dir.path()),
                std::slice::from_ref(&default),
                "{content:?}"
            );
        }
        std::fs::write(pointer_file(dir.path()), vec![b'/'; 10_000]).unwrap();
        assert_eq!(candidate_sockets(dir.path()), [default]);
    }

    /// The serve's uid against the caller's: a second account to serve from is not at hand in
    /// a test, so the caller's uid is changed instead.
    #[tokio::test]
    async fn a_socket_served_by_another_user_is_not_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_socket(dir.path());
        let _listening = bind(&path, dir.path()).unwrap();
        let me = rustix::process::geteuid().as_raw();
        assert!(connect_as(dir.path(), me).await.is_some());
        assert!(connect_as(dir.path(), me.wrapping_add(1)).await.is_none());
    }
}
