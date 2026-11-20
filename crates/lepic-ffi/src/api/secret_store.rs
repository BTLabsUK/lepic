//! The storage the app provides for the wallet's sealed secrets, such as `flutter_secure_storage`
//! over the Android Keystore and the iOS Keychain.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use flutter_rust_bridge::DartFnFuture;
use flutter_rust_bridge::frb;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::boundary::guard;

/// The answer of one store call. The Dart wrapper in `package:lepic` builds it, so an exception
/// in the app's store becomes `ok: false` instead of an unanswered call. A read's value is the
/// PIN key or the sealed vault, so `Debug` shows only whether there is one (ADR 0014).
#[derive(Clone)]
pub struct SecretReply {
    pub ok: bool,
    /// The value read, for `read` only. `None` when nothing is stored under the key.
    pub value: Option<String>,
}

impl std::fmt::Debug for SecretReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretReply")
            .field("ok", &self.ok)
            .field("value", &self.value.as_ref().map_or("<none>", |_| "<set>"))
            .finish()
    }
}

/// How long a read or a delete may wait for the app's store, so a store call that never answers
/// (a dismissed keystore prompt, an isolate torn down) fails the wallet call instead of hanging
/// it.
const STORE_TIMEOUT: Duration = Duration::from_secs(30);

type ReadFn = dyn Fn(String) -> DartFnFuture<SecretReply> + Send + Sync;
type WriteFn = dyn Fn(String, String) -> DartFnFuture<SecretReply> + Send + Sync;
type DeleteFn = dyn Fn(String) -> DartFnFuture<SecretReply> + Send + Sync;

/// Key-value storage implemented by the app. LEPIC keeps a wallet's vault in it, which holds the
/// seed encrypted under the wallet password with Argon2id and XChaCha20-Poly1305, and for a PIN
/// wallet also the PIN key and the count of PIN failures. The plain seed never reaches the store
/// or Dart.
///
/// One store holds the secrets of one wallet: the keys have fixed names. Give each wallet its own
/// store, for example by prefixing keys on the Dart side.
#[frb(opaque)]
#[derive(Clone)]
pub struct AppSecretStore {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Dart {
        read: Arc<ReadFn>,
        write: Arc<WriteFn>,
        delete: Arc<DeleteFn>,
    },
    #[cfg(feature = "mock")]
    Memory(Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>),
}

impl AppSecretStore {
    /// Wraps the app's store. Use `LepicSecretStore` from `package:lepic` rather than calling
    /// this directly; it turns exceptions into failed replies.
    #[frb(sync)]
    pub fn new(
        read: impl Fn(String) -> DartFnFuture<SecretReply> + Send + Sync + 'static,
        write: impl Fn(String, String) -> DartFnFuture<SecretReply> + Send + Sync + 'static,
        delete: impl Fn(String) -> DartFnFuture<SecretReply> + Send + Sync + 'static,
    ) -> Result<Self, WalletError> {
        guard("secret_store", || {
            Ok(Self {
                backend: Backend::Dart {
                    read: Arc::new(read),
                    write: Arc::new(write),
                    delete: Arc::new(delete),
                },
            })
        })
    }

    /// A store in memory, for Rust tests.
    #[cfg(feature = "mock")]
    #[frb(ignore)]
    pub fn in_memory() -> Self {
        Self {
            backend: Backend::Memory(Arc::default()),
        }
    }

    pub(crate) async fn read(&self, key: &str) -> Result<Option<String>, WalletError> {
        match &self.backend {
            Backend::Dart { read, .. } => {
                checked(bounded(read(key.to_owned())).await?).map(|r| r.value)
            }
            #[cfg(feature = "mock")]
            Backend::Memory(map) => Ok(lock(map).get(key).cloned()),
        }
    }

    pub(crate) async fn write(&self, key: &str, value: String) -> Result<(), WalletError> {
        match &self.backend {
            // Not bounded like a read: a write given up on may still land, so trusting the
            // vault after it would take a read-back. A hung write is ended by a lock.
            Backend::Dart { write, .. } => checked(write(key.to_owned(), value).await).map(drop),
            #[cfg(feature = "mock")]
            Backend::Memory(map) => {
                lock(map).insert(key.to_owned(), value);
                Ok(())
            }
        }
    }

    pub(crate) async fn delete(&self, key: &str) -> Result<(), WalletError> {
        match &self.backend {
            Backend::Dart { delete, .. } => {
                checked(bounded(delete(key.to_owned())).await?).map(drop)
            }
            #[cfg(feature = "mock")]
            Backend::Memory(map) => {
                lock(map).remove(key);
                Ok(())
            }
        }
    }
}

/// The reply of a store call, or a `SecretStore` error once [`STORE_TIMEOUT`] has passed.
async fn bounded(reply: impl Future<Output = SecretReply>) -> Result<SecretReply, WalletError> {
    tokio::time::timeout(STORE_TIMEOUT, reply)
        .await
        .map_err(|_| {
            WalletError::new(
                WalletErrorKind::SecretStore,
                "app secret store did not answer in time",
            )
        })
}

fn checked(reply: SecretReply) -> Result<SecretReply, WalletError> {
    if reply.ok {
        Ok(reply)
    } else {
        Err(WalletError::new(
            WalletErrorKind::SecretStore,
            "app secret store failed",
        ))
    }
}

#[cfg(feature = "mock")]
fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reply_debug_hides_the_value() {
        let read = SecretReply {
            ok: true,
            value: Some("sealed-vault-text".to_owned()),
        };
        let printed = format!("{read:?}");
        assert!(!printed.contains("sealed-vault-text"));
        assert!(printed.contains("<set>"));
        let empty = SecretReply {
            ok: true,
            value: None,
        };
        assert!(format!("{empty:?}").contains("<none>"));
    }
}
