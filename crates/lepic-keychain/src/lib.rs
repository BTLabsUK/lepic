//! Mnemonics, key derivation, switch commitments, proof builders and seed vaults.

pub mod address_key;
pub mod app_data;
pub mod bip32;
pub mod contact_key;
pub mod identifier;
pub mod keychain;
pub mod mnemonic;
pub mod proof;
pub mod vault;

pub use address_key::{PaymentProofKey, address_key_id};
pub use app_data::AppDataError;
pub use bip32::{Bip32Error, ChainCode, ChildNumber, ExtKeyVersion, ExtendedPrivKey, Fingerprint};
pub use contact_key::{
    ContactKeyError, ContactKeys, ContactRoot, ReplyKey, contact_identity_key_id,
    pairing_mailbox_keys,
};
pub use identifier::{Identifier, IdentifierError};
pub use keychain::{Keychain, KeychainError, SwitchCommitment};
pub use mnemonic::{MnemonicError, Seed};
pub use proof::{
    LegacyProofBuilder, OutputRewinder, ProofBuild, ProofBuilder, ProofError, RewoundOutput,
};
pub use vault::{
    KdfParams, MemoryVaultStorage, SecretBytes, SecretName, SecretStore, SecretStoreError, Vault,
    VaultError, VaultStorage, WalletSeedError, WalletSeedFile,
};
