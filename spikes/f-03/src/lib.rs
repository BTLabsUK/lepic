//! Throwaway spike for task F-03: proves the mobile cross-build of the native pieces LEPIC needs
//! (secp256k1-zkp, bundled SQLite, rustls with ring) and one HTTPS request plus one WSS
//! round trip per candidate TLS stack from ADR 0006. Deleted before the branch merges.

use std::fmt::Debug;

pub struct Check {
    pub name: &'static str,
    pub outcome: Result<String, String>,
}

fn err<E: Debug>(e: E) -> String {
    format!("{e:?}")
}

pub fn stack_name() -> &'static str {
    if cfg!(feature = "stack-reqwest") {
        "reqwest+rustls-platform-verifier"
    } else if cfg!(feature = "stack-hyper") {
        "hyper+hyper-rustls+webpki-roots"
    } else {
        "core-only"
    }
}

/// Runs every check compiled into this build. `https_host` and `wss_host` are only used when a
/// network stack is enabled.
pub fn run(https_host: &str, wss_host: &str, db_dir: &std::path::Path) -> Vec<Check> {
    let checks = vec![
        Check {
            name: "pedersen+bulletproof",
            outcome: crypto(),
        },
        Check {
            name: "sqlite",
            outcome: sqlite(db_dir),
        },
    ];
    #[cfg(feature = "net")]
    let checks = checks
        .into_iter()
        .chain(net::run(https_host, wss_host))
        .collect();
    #[cfg(not(feature = "net"))]
    let _ = (https_host, wss_host);
    checks
}

fn crypto() -> Result<String, String> {
    use secp256k1zkp::{ContextFlag, Secp256k1, key::SecretKey};

    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let blind = SecretKey::from_slice(&secp, &[0x11; 32]).map_err(err)?;
    let rewind = SecretKey::from_slice(&secp, &[0x22; 32]).map_err(err)?;
    let private = SecretKey::from_slice(&secp, &[0x33; 32]).map_err(err)?;
    let value = 5_000_u64;
    let commit = secp.commit(value, blind.clone()).map_err(err)?;
    let proof = secp.bullet_proof(value, blind, rewind, private, None, None);
    let range = secp.verify_bullet_proof(commit, proof, None).map_err(err)?;
    let prefix: String = commit
        .0
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(format!(
        "commit {prefix}.. proof {} bytes, verified range {}..{}",
        proof.plen, range.min, range.max
    ))
}

fn sqlite(db_dir: &std::path::Path) -> Result<String, String> {
    let path = db_dir.join("f03-spike.sqlite");
    let result = (|| {
        let conn = rusqlite::Connection::open(&path).map_err(err)?;
        let mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(err)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS t(k INTEGER PRIMARY KEY, v BLOB);
             INSERT INTO t(v) VALUES (x'00ff');",
        )
        .map_err(err)?;
        let (version, rows): (String, i64) = conn
            .query_row("SELECT sqlite_version(), count(*) FROM t", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .map_err(err)?;
        Ok(format!("sqlite {version}, journal {mode}, rows {rows}"))
    })();
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    result
}

#[cfg(feature = "net")]
mod net {
    use super::{Check, err};
    use futures_util::{SinkExt, StreamExt};
    use rustls::ClientConfig;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;

    const TIMEOUT: Duration = Duration::from_secs(20);

    pub fn run(https_host: &str, wss_host: &str) -> Vec<Check> {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return vec![Check {
                    name: "runtime",
                    outcome: Err(err(e)),
                }];
            }
        };
        let guarded =
            |name, fut: std::pin::Pin<Box<dyn Future<Output = Result<String, String>>>>| {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rt.block_on(async {
                        tokio::time::timeout(TIMEOUT, fut)
                            .await
                            .unwrap_or(Err("timeout".into()))
                    })
                }))
                .unwrap_or_else(|p| {
                    let msg = p
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_owned())
                        .or_else(|| p.downcast_ref::<String>().cloned())
                        .unwrap_or_default();
                    Err(format!("panicked: {msg}"))
                });
                Check { name, outcome }
            };
        vec![
            guarded("https", Box::pin(https(https_host.to_owned()))),
            guarded("wss", Box::pin(wss(wss_host.to_owned()))),
        ]
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[cfg(feature = "stack-reqwest")]
    fn client_config() -> Result<ClientConfig, String> {
        use rustls_platform_verifier::BuilderVerifierExt;
        Ok(ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(err)?
            .with_platform_verifier()
            .map_err(err)?
            .with_no_client_auth())
    }

    #[cfg(feature = "stack-hyper")]
    fn client_config() -> Result<ClientConfig, String> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(err)?
            .with_root_certificates(roots)
            .with_no_client_auth())
    }

    #[cfg(feature = "stack-reqwest")]
    async fn https(host: String) -> Result<String, String> {
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(client_config()?)
            .build()
            .map_err(err)?;
        let resp = client
            .get(format!("https://{host}/"))
            .send()
            .await
            .map_err(err)?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(err)?;
        Ok(format!(
            "GET https://{host}/ -> {status}, {} bytes",
            body.len()
        ))
    }

    #[cfg(feature = "stack-hyper")]
    async fn https(host: String) -> Result<String, String> {
        use http_body_util::{BodyExt, Empty};
        use hyper::body::Bytes;
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(client_config()?)
            .https_only()
            .enable_http1()
            .build();
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build::<_, Empty<Bytes>>(connector);
        let uri: hyper::Uri = format!("https://{host}/").parse().map_err(err)?;
        let resp = client.get(uri).await.map_err(err)?;
        let status = resp.status();
        let body = resp.into_body().collect().await.map_err(err)?.to_bytes();
        Ok(format!(
            "GET https://{host}/ -> {status}, {} bytes",
            body.len()
        ))
    }

    async fn wss(host: String) -> Result<String, String> {
        let tcp = tokio::net::TcpStream::connect((host.as_str(), 443))
            .await
            .map_err(err)?;
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(err)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client_config()?))
            .connect(name, tcp)
            .await
            .map_err(err)?;
        let (mut ws, resp) = tokio_tungstenite::client_async(format!("wss://{host}/"), tls)
            .await
            .map_err(err)?;
        let payload = "lepic-f03-spike";
        ws.send(Message::text(payload)).await.map_err(err)?;
        for _ in 0..4 {
            match ws.next().await {
                Some(Ok(Message::Text(t))) if t.as_str() == payload => {
                    let _ = ws.close(None).await;
                    return Ok(format!(
                        "wss://{host}/ upgrade {}, echo received",
                        resp.status()
                    ));
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(err(e)),
                None => break,
            }
        }
        Err("no echo".into())
    }
}

/// C entry point so the static and dynamic libraries keep every code path after LTO, which makes
/// their size representative. Returns a bitmask of passed checks.
#[unsafe(no_mangle)]
pub extern "C" fn f03_spike_run() -> u32 {
    run("example.com", "echo.websocket.org", &std::env::temp_dir())
        .iter()
        .enumerate()
        .filter(|(_, c)| c.outcome.is_ok())
        .fold(0, |mask, (i, _)| mask | (1 << i))
}
