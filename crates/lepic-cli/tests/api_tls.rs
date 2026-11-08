// SPDX-License-Identifier: Apache-2.0
//! The owner TLS listener of `lepic serve --owner-tls`: which clients it lets in and what it
//! answers them, in one process with a mock node and a mock relay.

// Tests may unwrap, index and panic (docs/rules.md).
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{AlertDescription, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::Value;
use support::{FUNDING, Instance, PATIENCE, Reply, SENDER_MNEMONIC, TestHost, http, parse_reply};

/// The shipped settings with the TLS listener on a free local port.
fn settings_with_owner_tls(wallet: &Instance) -> PathBuf {
    let path = wallet.path("settings.toml");
    let settings = include_str!("../settings.default.toml")
        .replace("# owner_tls = \"ip:port\"", "owner_tls = \"127.0.0.1:0\"");
    std::fs::write(&path, settings).unwrap();
    path
}

/// A running `serve --owner-tls`.
struct Serving<'a> {
    socket: &'a Path,
    host: &'a TestHost,
    wallet: &'a Instance,
    address: SocketAddr,
    fingerprint: String,
    /// The certificate serve wrote, which clients trust.
    certificate: CertificateDer<'static>,
}

/// Runs `test` against a `lepic serve --owner-tls` of `wallet`, then stops serve.
fn serving<T: Send>(
    mut host: TestHost,
    wallet: &Instance,
    test: impl FnOnce(&Serving<'_>) -> T + Send,
) -> T {
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let client = host.without_interrupt();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();
    let mut env = wallet.env();
    let settings = settings_with_owner_tls(wallet);
    env.push(("LEPIC_SETTINGS".to_owned(), settings.display().to_string()));
    std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            wallet.run_with(
                &host,
                &["serve", "--socket", socket_arg, "--owner-tls"],
                env,
                "",
            )
        });
        let stopping = Stop(&stop);
        support::wait_for_socket(&socket);
        let status = http(&socket, "GET", "/v1/status", None).ok();
        let pem = std::fs::read(wallet.data_dir().join("api-tls.pem")).unwrap();
        let serving = Serving {
            socket: &socket,
            host: &client,
            wallet,
            address: status["owner_tls"]["address"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            fingerprint: status["owner_tls"]["fingerprint"]
                .as_str()
                .unwrap()
                .to_owned(),
            certificate: CertificateDer::from_pem_slice(&pem).unwrap(),
        };
        let result = test(&serving);
        drop(stopping);
        server.join().unwrap().ok();
        result
    })
}

struct Stop<'a>(&'a AtomicBool);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A client certificate with a new Ed25519 key, and the PEM file `lepic api client add` reads.
struct ClientKey {
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    pem: PathBuf,
}

fn client_key(wallet: &Instance, name: &str) -> ClientKey {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let certificate = CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = wallet.path(&format!("{name}.pem"));
    std::fs::write(&pem, certificate.pem()).unwrap();
    ClientKey {
        certificate: certificate.der().clone(),
        key: PrivatePkcs8KeyDer::from(key.serialize_der()),
        pem,
    }
}

impl Serving<'_> {
    fn client(&self, args: &[&str]) -> Value {
        let args: Vec<&str> = ["api", "client"]
            .into_iter()
            .chain(args.iter().copied())
            .collect();
        self.wallet.run(self.host, &args).ok().json()
    }

    /// One request over TLS as `client`, or with no client certificate; the connection
    /// closes after the answer.
    fn request(
        &self,
        client: Option<&ClientKey>,
        method: &str,
        path: &str,
        body: &str,
    ) -> std::io::Result<Reply> {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);
        let config = match client {
            Some(client) => builder
                .with_client_auth_cert(
                    vec![client.certificate.clone()],
                    PrivateKeyDer::Pkcs8(client.key.clone_key()),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        let name = ServerName::try_from("lepic-wallet").unwrap();
        let connection = ClientConnection::new(Arc::new(config), name).unwrap();
        let tcp = TcpStream::connect(self.address)?;
        tcp.set_read_timeout(Some(PATIENCE))?;
        let mut stream = StreamOwned::new(connection, tcp);
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: lepic\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        let mut answer = String::new();
        stream.read_to_string(&mut answer)?;
        Ok(parse_reply(&answer))
    }

    fn get(&self, client: Option<&ClientKey>, path: &str) -> std::io::Result<Reply> {
        self.request(client, "GET", path, "")
    }
}

/// Checks that serve ended the handshake with `alert`.
fn refused(result: std::io::Result<Reply>, alert: AlertDescription) {
    let error = result.unwrap_err();
    let tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    assert_eq!(tls, Some(&rustls::Error::AlertReceived(alert)), "{error}");
}

fn funded_wallet(host: &TestHost) -> Instance {
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("tls password");
    wallet.restore(host, SENDER_MNEMONIC);
    wallet
}

#[test]
fn a_listed_client_is_answered_until_it_is_removed() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let info = wallet.run(&host, &["wallet", "info"]).ok().json();
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        let added = serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        assert_eq!(added["name"], "laptop", "{added}");
        let listed = serve.client(&["list"]);
        assert_eq!(listed["clients"], serde_json::json!([added]), "{listed}");
        // The fingerprint status shows is the one a client pins in api-clients.
        let pem = serve.wallet.data_dir().join("api-tls.pem");
        let server = serve.client(&["add", "server", pem.to_str().unwrap()]);
        assert_eq!(
            server["fingerprint"],
            serve.fingerprint.as_str(),
            "{server}"
        );
        serve.client(&["remove", "server"]);

        assert_eq!(serve.get(Some(&laptop), "/v1/wallet").unwrap().ok(), info);

        let removed = serve.client(&["remove", "laptop"]);
        assert_eq!(removed, added);
        refused(
            serve.get(Some(&laptop), "/v1/wallet"),
            AlertDescription::AccessDenied,
        );
        let status = http(serve.socket, "GET", "/v1/status", None).ok();
        assert_eq!(status["requests"]["refused"], 1, "{status}");
    });
}

#[test]
fn an_unlisted_client_or_one_without_a_certificate_is_refused_at_the_handshake() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");
    let stranger = client_key(&wallet, "stranger");

    serving(host, &wallet, |serve| {
        // No api-clients file lists no client.
        refused(
            serve.get(Some(&laptop), "/v1/wallet"),
            AlertDescription::AccessDenied,
        );
        serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        refused(
            serve.get(Some(&stranger), "/v1/wallet"),
            AlertDescription::AccessDenied,
        );
        refused(
            serve.get(None, "/v1/wallet"),
            AlertDescription::CertificateRequired,
        );
        assert_eq!(serve.get(Some(&laptop), "/v1/status").unwrap().status, 200);
    });
}

#[test]
fn the_password_route_is_refused_over_tls() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        let body = r#"{"current":"tls password","new":"other password"}"#;
        let reply = serve
            .request(Some(&laptop), "PUT", "/v1/wallet/password", body)
            .unwrap();
        assert_eq!(reply.status, 403, "{reply:?}");
        assert_eq!(reply.json()["code"], "usage", "{reply:?}");
    });
    // The password is unchanged.
    wallet.run(&TestHost::new(), &["wallet", "address"]).ok();
}

#[test]
fn one_seed_serves_the_same_certificate_every_time() {
    let fingerprint = |wallet: &Instance, host: TestHost| {
        serving(host, wallet, |serve| {
            (serve.fingerprint.clone(), serve.certificate.clone())
        })
    };
    let host = TestHost::new();
    let first = funded_wallet(&host);
    let (fingerprint_first, certificate_first) = fingerprint(&first, host);
    let host = TestHost::new();
    let second = funded_wallet(&host);
    let (fingerprint_second, certificate_second) = fingerprint(&second, host);
    assert_eq!(fingerprint_first, fingerprint_second);
    assert_eq!(certificate_first, certificate_second);
    assert_eq!(fingerprint_first.len(), 64);
}

#[test]
fn owner_tls_needs_an_address_in_the_settings() {
    let host = TestHost::new();
    let wallet = Instance::new("tls password");
    let outcome = wallet.run(&host, &["serve", "--owner-tls"]);
    assert_eq!(outcome.code, 3, "{outcome:?}");
    assert!(outcome.stdout.contains("owner_tls"), "{outcome:?}");
}
