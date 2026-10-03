//! The host app's data files, sealed and opened by the engine under the wallet's root secret.

use zeroize::Zeroizing;

use super::Session;
use crate::api::error::WalletError;

impl Session {
    pub(crate) fn seal_app_data(&self, payload: &[u8]) -> Result<Vec<u8>, WalletError> {
        Ok(self.engine.seal_app_data(payload)?)
    }

    pub(crate) fn open_app_data(&self, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        Ok(self.engine.open_app_data(file)?)
    }
}
