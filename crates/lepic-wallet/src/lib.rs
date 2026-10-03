//! The LEPIC wallet engine.
//!
//! A [`Wallet`] is built from a [`WalletConfig`] and the [`Ports`] it runs on: the node, the
//! database, the secret storage, the transports, a clock, a random number generator and a Tokio
//! runtime handle. The engine owns none of them and keeps no global state, so several wallets,
//! on different networks, can run in one process.
//!
//! Every public operation runs in a `tracing` span named after it, with the field vocabulary of
//! `docs/logging.md`. Secrets never appear in spans, events or errors.

pub mod account;
mod cancel;
pub mod config;
pub mod error;
pub mod event;
pub mod finalize;
pub mod inbox;
pub mod invoice;
pub mod lifecycle;
pub mod ports;
pub mod receive;
pub mod refresh;
pub mod scan;
pub mod selection;
pub mod send;
pub mod state;
mod wallet;

pub use account::{Account, AccountError, AccountLabel, DEFAULT_ACCOUNT_LABEL};
pub use config::{ConfigError, NodeEndpoint, WalletConfig, WalletName};
pub use error::WalletError;
pub use event::{Event, SessionState};
pub use finalize::{FinalizeError, Finalized};
pub use lifecycle::{Password, RecoveryPhrase, WordCount};
pub use ports::{Clock, Ports, SecretVault, SecretVaultError, SharedRng, StoreOpener};
#[cfg(feature = "sqlite")]
pub use ports::{DATABASE_FILE, SqliteStores};
pub use receive::{ReceiveError, ReceiveRequest, Received};
pub use wallet::Wallet;
