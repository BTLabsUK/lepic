//! The app's own data files, such as its history backups, encrypted under a key derived from
//! the wallet's seed. The key never leaves Rust; Dart passes the payload in and gets the sealed
//! file, and the other way round.

use crate::api::error::WalletError;
use crate::api::wallet::EpicWallet;

impl EpicWallet {
    /// Encrypts `payload` as a `WFEH` version 1 file, the format of the app's `.wfeh` history
    /// backups. Every call draws a fresh salt and nonce, so two files of one payload differ.
    /// Only this wallet, or one restored from the same recovery phrase, opens the file.
    ///
    /// Fails with `Locked`, and with `InvalidArgument` for a payload above 32 MiB.
    pub async fn seal_app_data(&self, payload: Vec<u8>) -> Result<Vec<u8>, WalletError> {
        self.run("seal_app_data", |session| async move {
            session.seal_app_data(payload).await
        })
        .await
    }

    /// Decrypts a file from [`EpicWallet::seal_app_data`], or a `.wfeh` backup the app wrote
    /// before it used LEPIC, and returns its payload.
    ///
    /// Fails with `ForeignAppData` for an intact file of another wallet, `DamagedAppData` for a
    /// file of this wallet that was changed or cut short, `Unsupported` for a later format
    /// version, `InvalidArgument` for anything that is not such a file or is larger than
    /// 32 MiB, and `Locked`.
    pub async fn open_app_data(&self, file: Vec<u8>) -> Result<Vec<u8>, WalletError> {
        self.run("open_app_data", |session| async move {
            session
                .open_app_data(file)
                .await
                .map(|payload| payload.to_vec())
        })
        .await
    }
}
