// SPDX-License-Identifier: Apache-2.0
//! Whether a wallet database file is encrypted at rest, and the key it is encrypted under.

use zeroize::Zeroizing;

pub const STORE_KEY_LEN: usize = 32;

/// The key a whole database file, with its write-ahead log, is encrypted under. It has no
/// `Debug`, so it cannot reach a log by accident.
pub struct StoreKey(Zeroizing<[u8; STORE_KEY_LEN]>);

impl StoreKey {
    pub fn from_bytes(bytes: [u8; STORE_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A key that `fill` writes straight into its own wiped buffer, so a key derived here
    /// leaves no copy behind. Fails with the error of `fill`.
    pub fn filled_by<E>(
        fill: impl FnOnce(&mut [u8; STORE_KEY_LEN]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut key = Self(Zeroizing::new([0; STORE_KEY_LEN]));
        fill(&mut key.0)?;
        Ok(key)
    }

    #[cfg(feature = "sqlite")]
    pub(crate) fn expose(&self) -> &[u8; STORE_KEY_LEN] {
        &self.0
    }
}

/// How a database file is kept on disk.
#[derive(Clone, Copy)]
pub enum AtRest<'k> {
    /// A plain SQLite file.
    Plain,
    /// Every page of the file and its write-ahead log sealed with ChaCha20-Poly1305 under the
    /// key (SQLite3 Multiple Ciphers), with a key check file beside it.
    Encrypted(&'k StoreKey),
}
