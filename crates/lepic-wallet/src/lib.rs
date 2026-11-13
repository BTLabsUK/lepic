// SPDX-License-Identifier: Apache-2.0
//! The LEPIC wallet engine.
//!
//! A [`Wallet`] is built from a [`WalletConfig`] and the [`Ports`] it runs on: the node, the
//! database, the secret storage, a clock, a random number generator and a Tokio runtime handle.
//! The engine owns none of them and keeps no global state, so several wallets, on different
//! networks, can run in one process. It sends, receives, finalizes, posts, cancels and releases
//! transactions, refreshes and scans against the node, and reports through [`Event`]s.
//!
//! Every public operation runs in a `tracing` span named after it, with the field vocabulary of
//! `docs/logging.md`. Spans, events and errors carry no secrets.
//!
//! The crate's `README.md` describes the transaction states, the ports, the hooks and the events.

pub mod account;
pub mod api_log;
mod api_tls_key;
mod app_data;
pub mod boost;
mod cancel;
pub mod chain;
pub(crate) use lepic_transport::codecs;
pub mod coinbase;
pub mod config;
pub mod contact_link;
pub mod details;
mod early_notice;
pub mod epic1_index;
mod epic1_keys;
pub mod epicbox_invoice;
pub mod error;
pub mod error_text;
mod estimate;
pub mod event;
pub mod extension;
pub mod finalize;
mod finished;
mod in_person_keys;
pub mod inbox;
pub mod invoice;
pub mod legacy_history;
pub mod lifecycle;
pub mod namespace;
mod native_epicbox;
pub mod notice;
mod notices;
mod onion_key;
mod other_wallet;
pub mod peer_compat;
pub mod peer_pin;
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
pub use api_tls_key::ApiTlsKey;
pub use config::{ConfigError, NodeEndpoint, WalletConfig, WalletName, WalletPolicy};
pub use error::WalletError;
pub use event::{Event, SessionState};
pub use finalize::{FinalizeError, Finalized};
pub use in_person_keys::{Epic1AccountKeys, IN_PERSON_REPLY_PREFIX};
pub use lifecycle::{Password, RecoveryPhrase, WordCount, store_key};
pub use native_epicbox::{NativeRefusal, SlateFormat};
pub use notices::ContactNotice;
pub use onion_key::OnionKey;
pub use peer_pin::PinOutcome;
pub use ports::{Clock, Ports, SecretVault, SecretVaultError, SharedRng, StoreOpener};
#[cfg(feature = "sqlite")]
pub use ports::{
    DATABASE_FILE, ENCRYPTED_DATABASE_FILE, EncryptedSqliteStores, EncryptingSqliteStores,
    SqliteStores,
};
pub use process::{crypto_context_is_randomized, randomize_crypto_context};
pub use receive::{ProofKey, ReceiveError, ReceiveRequest, Received};
pub use wallet::Wallet;

/// The method port the engine sends, receives and finalizes over (ADR 0051).
pub mod method {
    pub use lepic_transport::method::*;
}

/// What a host needs to decode a slate without a wallet, for example to show it to the user
/// before receiving or finalizing it.
pub mod slate {
    pub use lepic_legacy_slate::v2_json::V2JsonCodec;
    pub use lepic_legacy_slate::v3_json::V3JsonCodec;
    pub use lepic_slate::codec::{MediaType, WireSlate};
    pub use lepic_slate::error::DecodeError;
    pub use lepic_slate::model::Slate;
    pub use lepic_slate::origin::WireOrigin;
    pub use lepic_slate::registry::CodecRegistry;
    pub use lepic_slate::role::Role;
    pub use lepic_slate::stage::Stage;
    pub use lepic_slate::ur_slate;
}
