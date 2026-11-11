// SPDX-License-Identifier: Apache-2.0
//! The owner TLS listener of `serve --owner-tls` (ADR 0050): TLS 1.3 on TCP, answering clients
//! whose certificate key `api-clients` lists. The server certificate is self-signed and does
//! not expire; a client trusts it by pinning it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use lepic_wallet::ApiTlsKey;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, ServerConfig};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName as Subject, PeerIncompatible,
    PeerMisbehaved, SignatureScheme,
};
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use zeroize::Zeroizing;

use super::{Api, Listener, Owner};
use crate::api_clients::{Clients, Fingerprint};
use crate::exit::CliError;

const CERTIFICATE_FILE: &str = "api-tls.pem";
/// The name the certificate is issued to, which clients check in place of a host name.
const SERVER_NAME: &str = "lepic-wallet";
/// 9999-12-31T23:59:59Z, the notAfter of a certificate with no expiry date (RFC 5280).
const NO_EXPIRY: i64 = 253_402_300_799;

pub(crate) struct OwnerTls {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    pub(crate) address: SocketAddr,
    pub(crate) fingerprint: Fingerprint,
}

impl OwnerTls {
    /// Writes the certificate of `key` to `data_dir` and listens on `address`.
    pub(crate) async fn bind(
        address: SocketAddr,
        key: &ApiTlsKey,
        data_dir: &Path,
    ) -> Result<Self, CliError> {
        let certificate = certificate(key).map_err(CliError::OwnerTlsCertificate)?;
        lepic_store::file::write_owner_only_atomic(
            &data_dir.join(CERTIFICATE_FILE),
            certificate.pem().as_bytes(),
        )
        .map_err(CliError::io("write api-tls.pem"))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(ListedClients {
            data_dir: data_dir.to_owned(),
            algorithms: provider.signature_verification_algorithms,
        });
        let private_key = PrivatePkcs8KeyDer::from(key.expose_pkcs8().to_vec());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .and_then(|config| {
                config.with_client_cert_verifier(verifier).with_single_cert(
                    vec![certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(private_key),
                )
            })
            .map_err(CliError::OwnerTlsConfig)?;
        // A resumed session skips the client check, which would let a removed client back in.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        let listen_error = |source| CliError::OwnerTlsListen { address, source };
        let listener = TcpListener::bind(address).await.map_err(listen_error)?;
        Ok(Self {
            address: listener.local_addr().map_err(listen_error)?,
            listener,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            fingerprint: Fingerprint::of_ed25519_key(key.public_key()),
        })
    }

    pub(crate) async fn accept(&self) -> std::io::Result<TcpStream> {
        self.listener.accept().await.map(|(stream, _)| stream)
    }
}

/// The longest a TLS handshake may take, or the header deadline when that is shorter.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// A connection to the owner TLS listener whose handshake ended, with its listed client.
pub(crate) struct Shaken {
    stream: TlsStream<TcpStream>,
    client: Fingerprint,
}

impl<O: Owner> Api<'_, O> {
    /// The handshake of `stream`, within [`HANDSHAKE_TIMEOUT`] and the header deadline. A
    /// failed handshake counts as a refused connection.
    pub(crate) async fn tls_handshake(&self, tls: &OwnerTls, stream: TcpStream) -> Option<Shaken> {
        let handshake = tls.acceptor.accept(stream);
        let deadline = HANDSHAKE_TIMEOUT.min(self.limits().header_timeout);
        match tokio::time::timeout(deadline, handshake).await {
            Ok(Ok(stream)) => {
                // The verifier took only an Ed25519 certificate, so a client has a key here.
                let client = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(<[_]>::first)
                    .and_then(Fingerprint::of_ed25519);
                if client.is_none() {
                    self.refuse();
                }
                client.map(|client| Shaken { stream, client })
            }
            Ok(Err(error)) => {
                tracing::debug!(error = %error, "owner tls handshake failed");
                self.refuse();
                None
            }
            Err(_) => {
                self.refuse();
                None
            }
        }
    }

    /// Answers the requests of a client whose handshake ended.
    pub(crate) async fn tls_connection(&self, shaken: Shaken) {
        self.connection(shaken.stream, Listener::Tls, Some(shaken.client))
            .await;
    }
}

/// The certificate of `key`: self-signed, issued to [`SERVER_NAME`], with fixed dates, so one
/// key always gives the same certificate.
fn certificate(key: &ApiTlsKey) -> Result<Certificate, rcgen::Error> {
    let key_pair = Zeroizing::new(KeyPair::try_from(key.expose_pkcs8())?);
    let mut params = CertificateParams::new(vec![SERVER_NAME.to_owned()])?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, SERVER_NAME);
    params.not_before = OffsetDateTime::UNIX_EPOCH;
    params.not_after =
        OffsetDateTime::from_unix_timestamp(NO_EXPIRY).map_err(|_| rcgen::Error::Time)?;
    params.self_signed(&*key_pair)
}

/// Accepts a client whose Ed25519 certificate key `api-clients` lists. The file is read at each
/// handshake, so an edit applies from the next connection. Dates and issuer are not checked:
/// the listed key is the trust.
#[derive(Debug)]
struct ListedClients {
    data_dir: PathBuf,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for ListedClients {
    fn root_hint_subjects(&self) -> &[Subject] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let refused =
            || rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
        let fingerprint = Fingerprint::of_ed25519(end_entity).ok_or_else(refused)?;
        match Clients::read(&self.data_dir) {
            Ok(clients) if clients.lists(fingerprint) => Ok(ClientCertVerified::assertion()),
            Ok(_) => Err(refused()),
            Err(error) => {
                tracing::warn!(
                    error = %lepic_telemetry::ErrorChain(&error),
                    "api-clients is unreadable, so every client is refused"
                );
                Err(refused())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(PeerIncompatible::Tls12NotOfferedOrEnabled.into())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if signature.scheme != SignatureScheme::ED25519 {
            return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
        }
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
