// SPDX-License-Identifier: Apache-2.0
//! The certificate key of `serve`'s owner TLS listener (ADR 0050): a key of the LEPIC namespace,
//! so a restore from the phrase gives the same certificate key and clients keep their pin.

use std::fmt;

use ed25519_dalek::SigningKey;

use lepic_node::NodeApi;
use zeroize::Zeroizing;

use crate::error::WalletError;
use crate::namespace;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// The PKCS#8 v1 (RFC 8410) encoding of an Ed25519 private key, before its 32-byte seed.
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The Ed25519 key of the owner TLS certificate, as PKCS#8 for the TLS and certificate code,
/// and its public key. The private key is wiped on drop and never printed.
pub struct ApiTlsKey {
    pkcs8: Zeroizing<Vec<u8>>,
    public_key: [u8; 32],
}

impl ApiTlsKey {
    /// The private key in PKCS#8 v1 DER. Callers must not log it or copy it into memory that is
    /// not wiped.
    pub fn expose_pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The Ed25519 public key the certificate carries.
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl fmt::Debug for ApiTlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiTlsKey([redacted])")
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The certificate key of the owner TLS listener: the namespace key labelled
    /// [`namespace::API_TLS_KEY_LABEL`], on no BIP32 path.
    ///
    /// Fails with [`WalletError::Locked`] while the wallet is locked.
    pub fn api_tls_key(&self) -> Result<ApiTlsKey, WalletError> {
        let session = self.session()?;
        let seed = namespace::api_tls_seed(&session.seed)?;
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        // One allocation of the full length, so no unwiped copy is left behind by a regrowth.
        let pkcs8 = Zeroizing::new([PKCS8_PREFIX.as_slice(), seed.as_slice()].concat());
        Ok(ApiTlsKey { pkcs8, public_key })
    }
}
