//! The storage the app provides for the wallet's sealed secrets, such as `flutter_secure_storage`
//! over the Android Keystore and the iOS Keychain.

use std::sync::Arc;

use flutter_rust_bridge::DartFnFuture;
use flutter_rust_bridge::frb;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::boundary::guard;

/// The answer of one store call. The Dart wrapper in `package:lepic` builds it, so an exception
/// in the app's store becomes `ok: false` instead of an unanswered call.
#[derive(Debug, Clone)]
pub struct SecretReply {
    pub ok: bool,
    /// The value read, for `read` only. `None` when nothing is stored under the key.
    pub value: Option<String>,
}

type ReadFn = dyn Fn(String) -> DartFnFuture<SecretReply> + Send + Sync;
type WriteFn = dyn Fn(String, String) -> DartFnFuture<SecretReply> + Send + Sync;
type DeleteFn = dyn Fn(String) -> DartFnFuture<SecretReply> + Send + Sync;

/// Key-value storage implemented by the app. LEPIC keeps one entry in it per wallet: the vault
/// that holds the seed, encrypted under the wallet password with Argon2id and
/// XChaCha20-Poly1305. The plain seed never reaches the store or Dart.
///
/// One store holds the secrets of one wallet. Give each wallet its own store, for example by
/// prefixing keys on the Dart side.
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
            Backend::Dart { read, .. } => checked(read(key.to_owned()).await).map(|r| r.value),
            #[cfg(feature = "mock")]
            Backend::Memory(map) => Ok(lock(map).get(key).cloned()),
        }
    }

    pub(crate) async fn write(&self, key: &str, value: String) -> Result<(), WalletError> {
        match &self.backend {
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
            Backend::Dart { delete, .. } => checked(delete(key.to_owned()).await).map(drop),
            #[cfg(feature = "mock")]
            Backend::Memory(map) => {
                lock(map).remove(key);
                Ok(())
            }
        }
    }
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
