// SPDX-License-Identifier: Apache-2.0
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
mod app_data;
mod cancel;
pub mod chain;
pub mod coinbase;
mod codecs;
pub mod config;
pub mod contact_link;
pub mod details;
pub mod epicbox_invoice;
mod epicbox_notice;
pub mod error;
pub mod error_text;
mod estimate;
pub mod event;
pub mod extension;
pub mod finalize;
mod finished;
pub mod inbox;
pub mod invoice;
pub mod legacy_history;
pub mod lifecycle;
pub mod namespace;
pub mod notice;
mod onion_key;
mod other_wallet;
pub mod peer_compat;
pub mod ports;
mod process;
mod receipt_cap;
pub mod receive;
pub mod refresh;
pub mod release;
pub mod scan;
pub mod selection;
pub mod self_send;
pub mod send;
mod send_limit;
mod slate_cache;
pub mod state;
mod twin_answer;
mod wallet;

pub use account::{Account, AccountError, AccountLabel, DEFAULT_ACCOUNT_LABEL};
pub use config::{ConfigError, NodeEndpoint, WalletConfig, WalletName, WalletPolicy};
pub use error::WalletError;
pub use event::{Event, SessionState};
pub use finalize::{FinalizeError, Finalized};
pub use lifecycle::{Password, RecoveryPhrase, WordCount, store_key};
pub use onion_key::OnionKey;
pub use ports::{Clock, Ports, SecretVault, SecretVaultError, SharedRng, StoreOpener};
#[cfg(feature = "sqlite")]
pub use ports::{
    DATABASE_FILE, ENCRYPTED_DATABASE_FILE, EncryptedSqliteStores, EncryptingSqliteStores,
    SqliteStores,
};
pub use process::{crypto_context_is_randomized, randomize_crypto_context};
pub use receive::{ProofKey, ReceiveError, ReceiveRequest, Received};
pub use wallet::Wallet;

/// What a host needs to decode a slate without a wallet, for example to show it to the user
/// before receiving or finalizing it.
pub mod slate {
    pub use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
    pub use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
    pub use lepic_slate::codec::{MediaType, WireSlate};
    pub use lepic_slate::error::DecodeError;
    pub use lepic_slate::model::Slate;
    pub use lepic_slate::origin::WireOrigin;
    pub use lepic_slate::registry::CodecRegistry;
    pub use lepic_slate::role::Role;
    pub use lepic_slate::stage::Stage;
    pub use lepic_slate::ur_slate;
}
