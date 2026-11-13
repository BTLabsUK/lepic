// SPDX-License-Identifier: Apache-2.0
//! One webhook request: the secrets, the signature, the address check and the POST (ADR 0058).

use std::io::Read as _;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac as _};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::secret::MAX_SECRET_LEN;

/// The most a secret file holds.
const MAX_SECRET_FILE: u64 = 64 * 1024;

/// The secrets of the file `path`: the base64-decoded part after `whsec_` of each line. The
/// file is read at each call, so a new secret needs no restart. Blank lines are skipped.
pub(super) fn secrets(path: &Path) -> Result<Vec<Zeroizing<Vec<u8>>>, String> {
    let failed = |what: &str| format!("the secret file {what}");
    let file = std::fs::File::open(path).map_err(|_| failed("could not be opened"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata().map_err(|_| failed("could not be read"))?;
        if crate::secret::readable_by_others(metadata.mode(), metadata.uid()) {
            return Err(failed("can be read by others"));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_SECRET_FILE.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| failed("could not be read"))?;
    if bytes.len() as u64 > MAX_SECRET_FILE {
        return Err(failed("is too large"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| failed("is not text"))?;
    let mut found = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let key = line
            .strip_prefix("whsec_")
            .filter(|key| key.len() <= MAX_SECRET_LEN)
            .and_then(|key| STANDARD.decode(key).ok())
            .filter(|key| !key.is_empty())
            .ok_or_else(|| failed("has a line that is not a whsec_ secret"))?;
        found.push(Zeroizing::new(key));
    }
    if found.is_empty() {
        return Err(failed("has no secret"));
    }
    Ok(found)
}

/// The `webhook-signature` value: `v1,<signature>` for each of `secrets`, space-separated.
pub(super) fn signature(
    secrets: &[Zeroizing<Vec<u8>>],
    id: &str,
    timestamp: i64,
    body: &[u8],
) -> String {
    let mut out = Vec::with_capacity(secrets.len());
    for key in secrets {
        // HMAC takes a key of any length.
        let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) else {
            continue;
        };
        mac.update(id.as_bytes());
        mac.update(b".");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        out.push(format!(
            "v1,{}",
            STANDARD.encode(mac.finalize().into_bytes())
        ));
    }
    out.join(" ")
}

/// Whether `ip` is public unicast: not loopback, private, link-local, CGNAT, multicast,
/// unspecified, documentation or broadcast. An IPv4-mapped IPv6 address counts as its IPv4.
pub(super) fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [first, second, ..] = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || first == 0
                || (first == 100 && second & 0xc0 == 64))
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            let second = ip.segments()[1];
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
                || (first == 0x2001 && second == 0x0db8))
        }
    }
}

/// How long a request waits.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    /// Resolving, connecting and the TLS handshake.
    pub connect: Duration,
    /// The whole request.
    pub total: Duration,
}

/// POSTs `body` with `headers` to `url`. Ok on a 2xx answer; the error says why not, without
/// the URL. Unless `allow_private`, every address the host resolves to must be public, and the
/// connection goes to one of those, with the URL's host for SNI and `Host`.
pub(super) async fn post(
    url: &str,
    allow_private: bool,
    headers: &[(&'static str, String)],
    body: Vec<u8>,
    limits: Limits,
) -> Result<(), String> {
    let uri: Uri = url.parse().map_err(|_| "the url is not valid".to_owned())?;
    let tls = match uri.scheme_str() {
        Some("https") => true,
        Some("http") if allow_private => false,
        _ => return Err("the url is not https".to_owned()),
    };
    let host = uri
        .host()
        .map(|host| host.trim_matches(['[', ']']).to_owned())
        .ok_or_else(|| "the url has no host".to_owned())?;
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let authority = uri
        .authority()
        .map_or_else(String::new, ToString::to_string);
    let path = uri.path_and_query().map_or("/", |path| path.as_str());
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, authority)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        let value = HeaderValue::from_str(value).map_err(|_| "a header is not valid".to_owned())?;
        request = request.header(*name, value);
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| "the request is not valid".to_owned())?;
    let work = async {
        let stream = tokio::time::timeout(limits.connect, async {
            let tcp = connect(&host, port, allow_private).await?;
            if tls {
                let name = ServerName::try_from(host.clone())
                    .map_err(|_| "the host is not a valid name".to_owned())?;
                let config = lepic_methods::http::webpki_tls_config()
                    .map_err(|_| "the tls configuration failed".to_owned())?;
                let stream = tokio_rustls::TlsConnector::from(config)
                    .connect(name, tcp)
                    .await
                    .map_err(|error| format!("the tls handshake failed: {}", error.kind()))?;
                Ok::<_, String>(Stream::Tls(Box::new(stream)))
            } else {
                Ok(Stream::Plain(tcp))
            }
        })
        .await
        .map_err(|_| "connecting timed out".to_owned())??;
        exchange(stream, request).await
    };
    tokio::time::timeout(limits.total, work)
        .await
        .map_err(|_| "the receiver did not answer in time".to_owned())?
}

/// Resolves `host`, refuses it when an address is not public, and connects to the first
/// address that takes the connection.
async fn connect(host: &str, port: u16, allow_private: bool) -> Result<TcpStream, String> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "the host did not resolve".to_owned())?
        .collect();
    if addresses.is_empty() {
        return Err("the host did not resolve".to_owned());
    }
    if !allow_private && let Some(address) = addresses.iter().find(|a| !is_public(a.ip())) {
        return Err(format!("{} is not a public address", address.ip()));
    }
    let mut last = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error.kind()),
        }
    }
    Err(format!(
        "the connection failed: {}",
        last.map_or_else(String::new, |kind| kind.to_string())
    ))
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Sends `request` over `stream` and judges the status; the answer's body is not read.
async fn exchange(stream: Stream, request: Request<Full<Bytes>>) -> Result<(), String> {
    match stream {
        Stream::Plain(stream) => run(stream, request).await,
        Stream::Tls(stream) => run(*stream, request).await,
    }
}

async fn run<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    request: Request<Full<Bytes>>,
) -> Result<(), String> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| "the connection failed".to_owned())?;
    let connection = tokio::spawn(connection);
    let answer = sender.send_request(request).await;
    connection.abort();
    let status = answer
        .map_err(|_| "the connection dropped before an answer".to_owned())?
        .status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("the receiver answered {status}"))
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::IpAddr;

    use super::*;

    const LIMITS: Limits = Limits {
        connect: Duration::from_secs(2),
        total: Duration::from_secs(2),
    };

    /// The test vector of the Standard Webhooks specification.
    #[test]
    fn the_signature_matches_the_standard_webhooks_vector() {
        let secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        let key = STANDARD
            .decode(secret.strip_prefix("whsec_").unwrap())
            .unwrap();
        let signature = signature(
            &[Zeroizing::new(key)],
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            1_614_265_330,
            br#"{"test": 2432232314}"#,
        );
        assert_eq!(signature, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
    }

    #[test]
    fn each_secret_gets_its_own_signature() {
        let one = Zeroizing::new(b"one".to_vec());
        let two = Zeroizing::new(b"two".to_vec());
        let both = signature(&[one.clone(), two.clone()], "1", 5, b"{}");
        let parts: Vec<&str> = both.split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], signature(&[one], "1", 5, b"{}"));
        assert_eq!(parts[1], signature(&[two], "1", 5, b"{}"));
        assert_ne!(parts[0], parts[1]);
    }

    #[test]
    fn only_public_unicast_addresses_pass() {
        for ip in [
            "93.184.216.34",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn a_private_target_is_refused_before_any_connection() {
        for url in [
            "https://127.0.0.1/",
            "https://[::1]:8443/hook",
            "https://10.0.0.5/",
            "https://169.254.169.254/latest",
            "https://[::ffff:192.168.0.1]/",
            "https://localhost/",
        ] {
            let error = post(url, false, &[], b"{}".to_vec(), LIMITS)
                .await
                .unwrap_err();
            assert!(
                error.contains("not a public address") || error.contains("resolve"),
                "{url}: {error}"
            );
            assert!(!error.contains(url), "{error}");
        }
    }

    #[tokio::test]
    async fn http_needs_allow_private() {
        let error = post("http://example.com/", false, &[], b"{}".to_vec(), LIMITS)
            .await
            .unwrap_err();
        assert_eq!(error, "the url is not https");
        let error = post("ftp://example.com/", true, &[], b"{}".to_vec(), LIMITS)
            .await
            .unwrap_err();
        assert_eq!(error, "the url is not https");
    }

    #[cfg(unix)]
    #[test]
    fn the_secret_file_is_read_each_time_and_must_be_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets");
        let mode =
            |mode| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::write(&path, "whsec_b25l\n\n  whsec_dHdv  \n").unwrap();
        mode(0o644);
        assert_eq!(
            secrets(&path).unwrap_err(),
            "the secret file can be read by others"
        );
        mode(0o600);
        let found = secrets(&path).unwrap();
        assert_eq!(
            found.iter().map(|key| key.as_slice()).collect::<Vec<_>>(),
            [b"one", b"two"]
        );
        std::fs::write(&path, "whsec_dGhyZWU=\n").unwrap();
        assert_eq!(secrets(&path).unwrap()[0].as_slice(), b"three");
        for bad in ["", "\n\n", "plain\n", "whsec_!!!\n", "whsec_\n"] {
            std::fs::write(&path, bad).unwrap();
            assert!(secrets(&path).is_err(), "{bad:?}");
        }
        assert_eq!(
            secrets(&dir.path().join("none")).unwrap_err(),
            "the secret file could not be opened"
        );
    }
}
