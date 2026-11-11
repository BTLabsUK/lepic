// SPDX-License-Identifier: Apache-2.0
//! The owner TLS listener of `lepic serve --owner-tls`: which clients it lets in, what each
//! client's role reaches, and what it answers, in one process with a mock node and a mock relay.
//! Every `/api/v1` answer read here is checked against `docs/api/openapi.json`.

// Tests may unwrap, index and panic (docs/rules.md).
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod support;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use lepic_cli::app_config::ApiLimits;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ED25519, SignatureAlgorithm};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{AlertDescription, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};
use support::{
    FUNDING, Instance, PATIENCE, Reply, SENDER_MNEMONIC, TestHost, contract, http, parse_reply,
    problem, wait_until,
};

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
        let status = http(&socket, "GET", "/api/v1/status", None).ok();
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
    client_key_of(wallet, name, &PKCS_ED25519)
}

fn client_key_of(
    wallet: &Instance,
    name: &str,
    algorithm: &'static SignatureAlgorithm,
) -> ClientKey {
    let key = KeyPair::generate_for(algorithm).unwrap();
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

    /// Lists `client` in api-clients under `name` with `role`.
    fn add(&self, name: &str, client: &ClientKey, role: &str) -> Value {
        self.client(&["add", name, client.pem.to_str().unwrap(), "--role", role])
    }

    /// A TLS connection as `client`, or with no client certificate.
    fn connect(&self, client: Option<&ClientKey>) -> std::io::Result<Tls> {
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
        Ok(BufReader::new(StreamOwned::new(connection, tcp)))
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
        let mut stream = self.connect(client)?;
        write!(
            stream.get_mut(),
            "{method} {path} HTTP/1.1\r\nHost: lepic\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        let mut answer = String::new();
        stream.read_to_string(&mut answer)?;
        Ok(checked(method, path, parse_reply(&answer)))
    }

    fn post(&self, client: &ClientKey, path: &str, body: &Value) -> Reply {
        self.request(Some(client), "POST", path, &body.to_string())
            .unwrap()
    }

    fn get(&self, client: Option<&ClientKey>, path: &str) -> std::io::Result<Reply> {
        self.request(client, "GET", path, "")
    }

    fn status(&self) -> Value {
        http(self.socket, "GET", "/api/v1/status", None).ok()
    }
}

/// `reply`, checked against the API's contract when `path` is one of its calls.
fn checked(method: &str, path: &str, reply: Reply) -> Reply {
    if let Some(below) = path.strip_prefix("/api/v1") {
        contract::check(method, below, &reply);
    }
    reply
}

type Tls = BufReader<StreamOwned<ClientConnection, TcpStream>>;

/// A GET on `stream`, which stays open for the next request.
fn keep_alive_get(stream: &mut Tls, path: &str) -> std::io::Result<Reply> {
    write!(
        stream.get_mut(),
        "GET {path} HTTP/1.1\r\nHost: lepic\r\n\r\n"
    )?;
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    let reply = parse_reply(&format!("{head}{}", String::from_utf8(body).unwrap()));
    Ok(checked("GET", path, reply))
}

/// Checks that serve closed `stream`: a read ends, cleanly or with the TCP connection's end,
/// before [`PATIENCE`].
fn closed(stream: &mut Tls) {
    let mut rest = Vec::new();
    match stream.read_to_end(&mut rest) {
        Ok(_) => assert!(rest.is_empty(), "{rest:?}"),
        Err(error) => assert!(
            !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{error}"
        ),
    }
}

fn limits(max_connections: usize, header_timeout: Duration, tls_max_age: Duration) -> ApiLimits {
    ApiLimits {
        max_connections,
        header_timeout,
        body_timeout: PATIENCE,
        max_body: 64 * 1024,
        tls_max_age,
    }
}

/// Checks that serve ended the handshake with `alert`. In TLS 1.3 the client may still be
/// writing its request when serve closes, so the write can fail before the alert is read.
fn refused(result: std::io::Result<Reply>, alert: AlertDescription) {
    let error = result.unwrap_err();
    let tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    let closed = matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
    );
    assert!(
        tls == Some(&rustls::Error::AlertReceived(alert)) || (tls.is_none() && closed),
        "{error}"
    );
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

        let info = http(serve.socket, "GET", "/api/v1/wallet", None).ok();
        assert_eq!(
            serve.get(Some(&laptop), "/api/v1/wallet").unwrap().ok(),
            info
        );

        let removed = serve.client(&["remove", "laptop"]);
        assert_eq!(removed, added);
        refused(
            serve.get(Some(&laptop), "/api/v1/wallet"),
            AlertDescription::AccessDenied,
        );
        let status = http(serve.socket, "GET", "/api/v1/status", None).ok();
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
            serve.get(Some(&laptop), "/api/v1/wallet"),
            AlertDescription::AccessDenied,
        );
        serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        refused(
            serve.get(Some(&stranger), "/api/v1/wallet"),
            AlertDescription::AccessDenied,
        );
        refused(
            serve.get(None, "/api/v1/wallet"),
            AlertDescription::CertificateRequired,
        );
        assert_eq!(
            serve.get(Some(&laptop), "/api/v1/status").unwrap().status,
            200
        );
    });
}

#[test]
fn the_password_route_is_refused_over_tls() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        // Even a client with every role: the password is the socket's alone.
        serve.add("laptop", &laptop, "full");
        let body = r#"{"current":"tls password","new":"other password"}"#;
        let reply = serve
            .request(Some(&laptop), "PUT", "/api/v1/wallet/password", body)
            .unwrap();
        problem(&reply, 403, "socket_only");
    });
    // The password is unchanged.
    let host = TestHost::new();
    wallet.run(&host, &["wallet", "address"]).ok();
    let mut env = wallet.env();
    env.retain(|(key, _)| key != "LEPIC_PASSWORD");
    env.push(("LEPIC_PASSWORD".to_owned(), "other password".to_owned()));
    let other = wallet.run_with(&host, &["wallet", "address"], env, "");
    assert_eq!(other.code, 4, "{other:?}");
}

#[test]
fn a_removed_client_is_refused_on_its_open_connection() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        let mut stream = serve.connect(Some(&laptop)).unwrap();
        assert_eq!(
            keep_alive_get(&mut stream, "/api/v1/wallet")
                .unwrap()
                .status,
            200
        );

        serve.client(&["remove", "laptop"]);
        let reply = keep_alive_get(&mut stream, "/api/v1/wallet").unwrap();
        let refused = problem(&reply, 403, "client_not_listed");
        assert_eq!(
            refused["detail"], "this client is no longer listed in api-clients",
            "{reply:?}"
        );
        assert_eq!(reply.header("connection"), Some("close"), "{reply:?}");
        closed(&mut stream);
    });
}

#[test]
fn only_the_socket_compares_a_request_with_the_run_of_serve() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        let request = "GET /api/v1/status HTTP/1.1\r\nHost: lepic\r\nx-lepic-data-dir: /elsewhere\r\n\
                       Connection: close\r\n\r\n";

        // On the socket, a request naming another data directory is refused, naming it.
        let mut socket = std::os::unix::net::UnixStream::connect(serve.socket).unwrap();
        socket.set_read_timeout(Some(PATIENCE)).unwrap();
        socket.write_all(request.as_bytes()).unwrap();
        let mut answer = String::new();
        socket.read_to_string(&mut answer).unwrap();
        let refused = parse_reply(&answer);
        let settings = problem(&refused, 409, "serve_settings_differ");
        assert!(
            settings["detail"].as_str().unwrap().contains("/elsewhere"),
            "{settings}"
        );

        // On the TLS listener the same request is answered: no refusal tells a remote client
        // serve's settings.
        let mut tls = serve.connect(Some(&laptop)).unwrap();
        tls.get_mut().write_all(request.as_bytes()).unwrap();
        let mut answer = String::new();
        tls.read_to_string(&mut answer).unwrap();
        let answered = checked("GET", "/api/v1/status", parse_reply(&answer));
        assert_eq!(answered.status, 200, "{}", answered.body);
        assert!(
            !answered.body.contains("data directory"),
            "{}",
            answered.body
        );
    });
}

#[test]
fn the_tls_listener_has_its_own_connection_cap() {
    let deadline = Duration::from_secs(2);
    let mut host = TestHost::new();
    host.api_limits = Some(limits(2, deadline, PATIENCE));
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        let started = Instant::now();
        let mut idle: Vec<TcpStream> = (0..2)
            .map(|_| TcpStream::connect(serve.address).unwrap())
            .collect();
        // Both TLS slots are taken, so a third connection is closed unanswered; the socket
        // still answers.
        assert!(serve.get(Some(&laptop), "/api/v1/status").is_err());
        let status = serve.status();
        assert!(started.elapsed() < deadline, "{:?}", started.elapsed());
        assert_eq!(status["requests"]["refused"], 1, "{status}");

        for stream in &mut idle {
            stream.set_read_timeout(Some(PATIENCE)).unwrap();
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest);
        }
        assert!(started.elapsed() >= deadline, "{:?}", started.elapsed());
        wait_until("both idle connections count as refused", || {
            serve.status()["requests"]["refused"] == 3
        });
        assert_eq!(
            serve.get(Some(&laptop), "/api/v1/status").unwrap().status,
            200
        );
    });
}

#[test]
fn a_handshake_has_its_own_deadline_and_takes_no_connection_slot() {
    let mut host = TestHost::new();
    host.api_limits = Some(limits(1, PATIENCE, PATIENCE));
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        // A listed client holds the only connection slot.
        let mut held = serve.connect(Some(&laptop)).unwrap();
        assert_eq!(
            keep_alive_get(&mut held, "/api/v1/status").unwrap().status,
            200
        );
        // A connection that never starts its handshake is not refused for want of a slot: it
        // waits for its handshake, and is closed when the handshake deadline, shorter than
        // the header time, passes.
        let started = Instant::now();
        let mut idle = TcpStream::connect(serve.address).unwrap();
        idle.set_read_timeout(Some(PATIENCE)).unwrap();
        let mut rest = Vec::new();
        let _ = idle.read_to_end(&mut rest);
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(4), "{waited:?}");
        assert!(waited < PATIENCE - Duration::from_secs(5), "{waited:?}");
        assert_eq!(
            keep_alive_get(&mut held, "/api/v1/status").unwrap().status,
            200
        );
    });
}

#[test]
fn a_tls_connection_closes_at_its_age_limit() {
    let age = Duration::from_secs(1);
    let mut host = TestHost::new();
    host.api_limits = Some(limits(4, PATIENCE, age));
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        let started = Instant::now();
        let mut stream = serve.connect(Some(&laptop)).unwrap();
        assert_eq!(
            keep_alive_get(&mut stream, "/api/v1/status")
                .unwrap()
                .status,
            200
        );
        closed(&mut stream);
        assert!(started.elapsed() >= age, "{:?}", started.elapsed());
        assert_eq!(
            serve.get(Some(&laptop), "/api/v1/status").unwrap().status,
            200
        );
    });
}

#[test]
fn a_client_key_that_is_not_ed25519_is_refused_at_the_handshake() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key_of(&wallet, "laptop", &PKCS_ECDSA_P256_SHA256);

    serving(host, &wallet, |serve| {
        refused(
            serve.get(Some(&laptop), "/api/v1/wallet"),
            AlertDescription::CertificateRequired,
        );
    });
}

fn receiver_address(host: &TestHost) -> String {
    let receiver = Instance::new("receiver password");
    receiver.run(host, &["wallet", "init"]).ok();
    let address = receiver.run(host, &["wallet", "address"]).ok().json();
    support::text(&address, "address").to_owned()
}

#[test]
fn a_payment_over_tls_needs_an_id() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");
    let address = receiver_address(&host);

    serving(host, &wallet, |serve| {
        serve.add("laptop", &laptop, "full");
        let without = serve.post(
            &laptop,
            "/api/v1/payments",
            &json!({"amount": "1", "to": address}),
        );
        let refused = problem(&without, 400, "invalid_argument");
        assert_eq!(refused["param"], "/id", "{refused}");
        assert_eq!(sends(serve), Vec::<Value>::new());

        let id = "6b2d4f8a-1c3e-4a5b-9d7f-0e2c4a6b8d1f";
        let with = serve.post(
            &laptop,
            "/api/v1/payments",
            &json!({"amount": "1", "to": address, "id": id}),
        );
        assert_eq!(with.status, 201, "{with:?}");
        assert_eq!(with.json()["id"], id, "{with:?}");
        assert_eq!(with.json()["direction"], "out", "{with:?}");
    });
}

/// The sends of `serve`'s wallet, read over the socket.
fn sends(serve: &Serving<'_>) -> Vec<Value> {
    let list = http(serve.socket, "GET", "/api/v1/payments", None).ok();
    let all = list["items"].as_array().unwrap();
    all.iter()
        .filter(|payment| payment["direction"] == "out")
        .cloned()
        .collect()
}

#[test]
fn an_http_send_over_tls_does_not_reach_this_computer() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");
    // Stands for a wallet on this computer; nothing may connect to it.
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let port = target.local_addr().unwrap().port();

    serving(host, &wallet, |serve| {
        serve.add("laptop", &laptop, "full");
        for (to, id) in [
            (
                format!("http://127.0.0.1:{port}"),
                "0b6c1f3e-5a2d-4e8b-9c7a-1d3f5b7e9a20",
            ),
            (
                format!("http://localhost:{port}"),
                "0b6c1f3e-5a2d-4e8b-9c7a-1d3f5b7e9a21",
            ),
            (
                format!("https://[::1]:{port}"),
                "0b6c1f3e-5a2d-4e8b-9c7a-1d3f5b7e9a22",
            ),
        ] {
            let body = json!({"amount": "1", "to": to, "via": "http", "id": id});
            let reply = serve.post(&laptop, "/api/v1/payments", &body);
            assert_eq!(reply.status, 400, "{to}: {reply:?}");
            let detail = reply.json()["detail"].as_str().unwrap().to_owned();
            assert!(
                detail.contains("does not send to this computer's own addresses"),
                "{to}: {reply:?}"
            );
        }
        assert_eq!(sends(serve), Vec::<Value>::new());
    });
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "a send connected to this computer"
    );
}

#[test]
fn an_http_send_over_the_socket_may_reach_this_computer() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let port = target.local_addr().unwrap().port();

    serving(host, &wallet, |serve| {
        std::thread::scope(|scope| {
            let body = json!({
                "amount": "1",
                "to": format!("http://127.0.0.1:{port}"),
                "via": "http",
                "id": "0b6c1f3e-5a2d-4e8b-9c7a-1d3f5b7e9a24",
            })
            .to_string();
            let sending =
                scope.spawn(move || http(serve.socket, "POST", "/api/v1/payments", Some(&body)));
            // Takes the connection and closes it unanswered, so the delivery fails at once.
            wait_until("the send connects", || target.accept().map(drop).is_ok());
            let sent = sending.join().unwrap();
            assert_ne!(sent.status, 400, "{sent:?}");
            assert!(!sent.body.contains("this computer's own"), "{sent:?}");
        });
    });
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

#[test]
fn a_client_listed_without_a_role_reads_only() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let laptop = client_key(&wallet, "laptop");

    serving(host, &wallet, |serve| {
        let added = serve.client(&["add", "laptop", laptop.pem.to_str().unwrap()]);
        assert_eq!(added["role"], "read", "{added}");
        assert_eq!(
            serve.get(Some(&laptop), "/api/v1/wallet").unwrap().status,
            200
        );
        assert_eq!(
            serve.get(Some(&laptop), "/api/v1/payments").unwrap().status,
            200
        );
        let sync = serve.post(&laptop, "/api/v1/sync", &json!({}));
        let refused = problem(&sync, 403, "role_required");
        assert_eq!(
            refused["detail"], "this call needs the receive role",
            "{refused}"
        );
        // The role is checked before the body is read: a body that is not even JSON is
        // refused for the role, not for its shape.
        let garbage = serve
            .request(Some(&laptop), "POST", "/api/v1/payments", "not json")
            .unwrap();
        problem(&garbage, 403, "role_required");
    });
}

#[test]
fn each_role_reaches_the_calls_it_names() {
    let host = TestHost::new();
    let wallet = funded_wallet(&host);
    let till = client_key(&wallet, "till");
    let owner = client_key(&wallet, "owner");
    let address = receiver_address(&host);

    serving(host, &wallet, |serve| {
        serve.add("till", &till, "receive");
        serve.add("owner", &owner, "full");

        // receive: syncs and issues invoices, never spends or changes the wallet.
        assert_eq!(serve.post(&till, "/api/v1/sync", &json!({})).status, 200);
        let invoice = serve.post(
            &till,
            "/api/v1/payments",
            &json!({
                "kind": "invoice",
                "amount": "1",
                "via": "file",
                "id": "3f1c2b4a-7d6e-4f80-9a1b-2c3d4e5f6a70",
            }),
        );
        assert_eq!(invoice.status, 201, "{invoice:?}");
        assert_eq!(invoice.json()["kind"], "invoice", "{invoice:?}");
        let send = serve.post(
            &till,
            "/api/v1/payments",
            &json!({"amount": "1", "to": address, "id": "3f1c2b4a-7d6e-4f80-9a1b-2c3d4e5f6a71"}),
        );
        let refused = problem(&send, 403, "role_required");
        assert_eq!(
            refused["detail"], "this call needs the full role",
            "{refused}"
        );
        assert_eq!(sends(serve), Vec::<Value>::new());
        let account = serve.post(&till, "/api/v1/accounts", &json!({"label": "savings"}));
        problem(&account, 403, "role_required");

        // full: everything the TLS listener answers, and nothing marked for the socket.
        let account = serve.post(&owner, "/api/v1/accounts", &json!({"label": "savings"}));
        assert_eq!(account.status, 201, "{account:?}");
        let export = serve.post(&owner, "/api/v1/contacts/export", &json!({}));
        problem(&export, 403, "socket_only");
    });
}
