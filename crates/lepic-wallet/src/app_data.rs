// SPDX-License-Identifier: Apache-2.0
//! Sealing and opening the host app's own data files under a key only this wallet's seed
//! gives, so the app keeps its backups readable without ever holding a key.

use lepic_keychain::app_data::{self, NONCE_LEN, SALT_LEN};
use lepic_node::NodeApi;
use tracing::{debug, instrument};
use zeroize::Zeroizing;

use crate::error::WalletError;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Encrypts `payload` as an app data file (`docs/compat/wfeh.md`) with a fresh salt and
    /// nonce from the wallet's random number generator, so two seals of one payload differ.
    /// Any wallet restored from the same recovery phrase opens it. Runs on the blocking pool.
    ///
    /// Fails with [`WalletError::Locked`], and with [`WalletError::AppData`] for a payload
    /// above [`app_data::MAX_PAYLOAD_LEN`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn seal_app_data(&self, payload: Vec<u8>) -> Result<Vec<u8>, WalletError> {
        let session = self.session()?;
        let payload = Zeroizing::new(payload);
        self.blocking(move |ports, _| {
            let mut salt = [0u8; SALT_LEN];
            let mut nonce = [0u8; NONCE_LEN];
            {
                let mut rng = ports.rng.lock();
                rng.fill_bytes(&mut salt);
                rng.fill_bytes(&mut nonce);
            }
            let file = app_data::seal(&session.keychain, salt, nonce, &payload)?;
            debug!("app data sealed");
            Ok(file)
        })
        .await
    }

    /// Decrypts an app data file this wallet, or one restored from the same phrase, sealed.
    /// Runs on the blocking pool.
    ///
    /// Fails with [`WalletError::Locked`], or [`WalletError::AppData`] with
    /// [`app_data::AppDataError::ForeignWallet`] for an intact file of another wallet,
    /// [`app_data::AppDataError::Damaged`] for a changed or truncated file of this wallet,
    /// `NotAppData` or `UnsupportedVersion` for other files, and `TooLong` above
    /// [`app_data::MAX_FILE_LEN`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn open_app_data(&self, file: Vec<u8>) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        let session = self.session()?;
        self.blocking(move |_, _| {
            let payload = app_data::open(&session.keychain, &file)?;
            debug!("app data opened");
            Ok(payload)
        })
        .await
    }
}
