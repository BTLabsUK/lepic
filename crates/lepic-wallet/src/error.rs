// SPDX-License-Identifier: Apache-2.0
use lepic_keychain::vault::SecretNameError;
use lepic_keychain::{
    AppDataError, IdentifierError, KeychainError, MnemonicError, SecretStoreError, WalletSeedError,
};
use lepic_node::NodeError;
use lepic_primitives::amount::ArithmeticError;
use lepic_primitives::params::Network;
use lepic_store::{StoreError, TxId};
use thiserror::Error;

use crate::account::AccountError;
use crate::chain::ImplausibleNodeData;
use crate::config::ConfigError;
use crate::ports::SecretVaultError;
use crate::release::ReleaseRefusal;
use crate::state::InvalidTransition;

/// Every failure of an engine operation. Variants never carry secrets.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletError {
    #[error("wallet configuration is invalid")]
    Config(#[from] ConfigError),
    #[error("a wallet already exists in this secret storage")]
    WalletExists,
    #[error("no wallet exists in this secret storage")]
    NoWallet,
    /// The password is wrong or the stored secrets were altered; the two cannot be told apart.
    #[error("password did not unlock the wallet")]
    WrongPassword,
    #[error("wallet is locked")]
    Locked,
    #[error("wallet is already open")]
    AlreadyOpen,
    #[error("wallet database belongs to a {stored} wallet, the configuration says {configured}")]
    NetworkMismatch { stored: String, configured: Network },
    #[error("wallet database belongs to a wallet with another seed")]
    ForeignDatabase,
    #[error("recovery phrase rejected")]
    Mnemonic(#[source] MnemonicError),
    #[error("stored seed is malformed")]
    StoredSeed(#[source] MnemonicError),
    #[error("wallet.seed file rejected")]
    WalletSeedFile(#[source] WalletSeedError),
    #[error("key derivation failed")]
    Keychain(#[from] KeychainError),
    #[error("key identifier rejected")]
    Identifier(#[from] IdentifierError),
    #[error("secret storage failed")]
    SecretVault(#[source] SecretVaultError),
    #[error("secret storage failed")]
    SecretStore(#[from] SecretStoreError),
    #[error("secret name rejected")]
    SecretName(#[from] SecretNameError),
    #[error("wallet database operation failed")]
    Store(#[from] StoreError),
    #[error("account rejected")]
    Account(#[from] AccountError),
    #[error("transaction {0} does not exist")]
    UnknownTransaction(TxId),
    #[error("transaction state change rejected")]
    Transition(#[from] InvalidTransition),
    /// The other entry of a send to the wallet itself is posted, so the chain may still spend
    /// the inputs; neither entry is cancelled.
    #[error(
        "transaction {tx_id} cannot be cancelled while its self-send partner {partner} is posted"
    )]
    PartnerPosted { tx_id: TxId, partner: TxId },
    /// The node holds the transaction's kernel, so it can no longer be cancelled; the next
    /// refresh confirms it.
    #[error("transaction {0} is already on chain")]
    OnChain(TxId),
    /// The node's transaction pool holds the transaction's kernel, so it may still be mined
    /// and is not released.
    #[error("transaction {0} is in the node's pool")]
    InPool(TxId),
    #[error("transaction {tx_id} cannot be released")]
    NotReleasable {
        tx_id: TxId,
        #[source]
        reason: ReleaseRefusal,
    },
    /// Another operation, for example the inbox finalizing it, changed the transaction while
    /// it was being cancelled or released. Nothing was changed.
    #[error("transaction {0} changed while it was being cancelled")]
    ChangedDuringCancel(TxId),
    /// The database was rebuilt from the seed and no scan from genesis has completed since, so
    /// the next unused output key is not known yet.
    #[error("a restore scan must complete before new outputs are created")]
    RestoreScanRequired,
    #[error("node request failed")]
    Node(#[source] NodeError),
    /// The node's tip is not plausible for what the wallet stored about the chain. Nothing was
    /// stored.
    #[error("node data rejected")]
    Implausible(#[from] ImplausibleNodeData),
    #[error("app data file rejected")]
    AppData(#[from] AppDataError),
    #[error("blocking wallet task did not complete")]
    Task(#[source] tokio::task::JoinError),
    #[error("minimum confirmations must be at least 1")]
    MinimumConfirmationsOutOfRange { count: u64 },
    #[error("balance out of range")]
    Balance(#[source] ArithmeticError),
    /// A listing's directory key is not a compressed secp256k1 key.
    #[error("listing rejected")]
    InvalidListing,
}

impl From<SecretVaultError> for WalletError {
    fn from(error: SecretVaultError) -> Self {
        match error {
            SecretVaultError::NotFound => Self::NoWallet,
            SecretVaultError::AlreadyExists => Self::WalletExists,
            SecretVaultError::WrongPassword => Self::WrongPassword,
            other @ SecretVaultError::Backend(_) => Self::SecretVault(other),
        }
    }
}
