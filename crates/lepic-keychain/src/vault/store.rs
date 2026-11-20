// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/lifecycle/seed.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! The `SecretStore` port: named secrets kept by the vault on desktop and by the platform
//! keystore, through the host app, on mobile.

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

/// An error from the backend behind a [`SecretStore`] or a [`super::VaultStorage`], such as the
/// filesystem or the platform keystore.
pub type BackendError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub const MAX_SECRET_NAME_LEN: usize = 64;

/// Why a secret name was rejected. Names are not secret, so the error may carry the length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SecretNameError {
    #[error("secret name has {actual} bytes, expected 1 to {MAX_SECRET_NAME_LEN}")]
    Length { actual: usize },
    #[error("secret name byte {position} is not a lowercase letter, digit, '-', '_', '.' or '/'")]
    Character { position: usize },
}

/// The name a secret is stored under, for example `wallet/default/seed`. Restricted to
/// lowercase ASCII letters, digits, `-`, `_`, `.` and `/`, so every platform keystore can use it
/// as a key unchanged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretName(String);

impl SecretName {
    pub fn new(name: &str) -> Result<Self, SecretNameError> {
        if name.is_empty() || name.len() > MAX_SECRET_NAME_LEN {
            return Err(SecretNameError::Length { actual: name.len() });
        }
        let allowed = |byte: &u8| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_./".contains(byte)
        };
        match name.bytes().position(|byte| !allowed(&byte)) {
            Some(position) => Err(SecretNameError::Character { position }),
            None => Ok(Self(name.to_owned())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A secret value. Wiped on drop and never printed. Deliberately not `PartialEq`: comparing
/// secrets that way would take variable time.
#[derive(Clone)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    /// The secret. Callers must not log it or copy it into memory that is not wiped.
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretStoreError {
    #[error("secret store is locked or unavailable")]
    Unavailable,
    #[error("secret has {actual} bytes, the store accepts at most {max}")]
    SecretTooLarge { actual: usize, max: usize },
    #[error("secret store holds {max} secrets, the most it can")]
    Full { max: usize },
    #[error("secret store backend failed")]
    Backend(#[source] BackendError),
}

/// Keeps secrets by name. Implementations persist a change before they return `Ok`, so a secret
/// that was put is still there after the process restarts.
pub trait SecretStore {
    /// Stores `secret` under `name`, replacing any secret already stored there.
    fn put(&mut self, name: &SecretName, secret: &SecretBytes) -> Result<(), SecretStoreError>;

    fn get(&self, name: &SecretName) -> Result<Option<SecretBytes>, SecretStoreError>;

    /// Removes the secret. Returns whether one was stored under `name`.
    fn delete(&mut self, name: &SecretName) -> Result<bool, SecretStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_keystore_safe_names() {
        for name in [
            "seed",
            "wallet/default/seed",
            "a-b_c.d",
            "0",
            &"x".repeat(64),
        ] {
            assert_eq!(SecretName::new(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_empty_and_long_names() {
        assert_eq!(
            SecretName::new(""),
            Err(SecretNameError::Length { actual: 0 })
        );
        assert_eq!(
            SecretName::new(&"x".repeat(65)),
            Err(SecretNameError::Length { actual: 65 })
        );
    }

    #[test]
    fn rejects_names_with_other_characters() {
        for (name, position) in [("Seed", 0), ("a b", 1), ("seé", 2), ("a\0", 1), ("x:y", 1)] {
            assert_eq!(
                SecretName::new(name),
                Err(SecretNameError::Character { position })
            );
        }
    }

    #[test]
    fn redacts_secret_bytes_in_debug() {
        let secret = SecretBytes::from_slice(b"hunter2");
        assert_eq!(format!("{secret:?}"), "SecretBytes([redacted])");
    }
}
