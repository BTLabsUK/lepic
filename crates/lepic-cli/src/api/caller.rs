// SPDX-License-Identifier: Apache-2.0
//! What a command forwarded to serve shares with serve: the version of `lepic`, the data
//! directory, the network and the settings that change how money moves. The CLI sends each as a
//! header; serve refuses a request that names any of them otherwise than its own run, so a
//! forwarded command never runs on another wallet or with other transport choices. A client
//! that sends none of the headers, such as `curl`, is not checked.

use hyper::HeaderMap;
use hyper::StatusCode;

use super::problem::{Category, Problem};
use crate::settings::{RelayTor, Settings};

/// The version of this `lepic`.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The header that names the version, sent by the CLI and on every answer of serve.
pub(crate) const VERSION_HEADER: &str = "x-lepic-version";

/// One fact of a run: its header, what it is called in a refusal, and its value.
struct Fact {
    header: &'static str,
    name: &'static str,
    value: String,
}

/// The facts of one run, as the CLI sends them and serve compares them.
pub(crate) struct Caller(Vec<Fact>);

impl Caller {
    pub(crate) fn of(settings: &Settings) -> Self {
        let data_dir =
            std::fs::canonicalize(&settings.data_dir).unwrap_or_else(|_| settings.data_dir.clone());
        let on = |on: bool| if on { "on" } else { "off" }.to_owned();
        let relay_tor = match &settings.relay_tor {
            RelayTor::Off => "off".to_owned(),
            RelayTor::Socks(address) => format!("socks {address}"),
            RelayTor::Binary { binary, lib_dir } => {
                let mut text = format!("binary {}", binary.display());
                if let Some(lib_dir) = lib_dir {
                    text.push_str(&format!(" lib {}", lib_dir.display()));
                }
                text
            }
        };
        Self(vec![
            Fact {
                header: VERSION_HEADER,
                name: "version",
                value: VERSION.to_owned(),
            },
            Fact {
                header: "x-lepic-data-dir",
                name: "data directory",
                value: encode(data_dir.as_os_str().as_encoded_bytes()),
            },
            Fact {
                header: "x-lepic-network",
                name: "network",
                value: settings.network.to_string(),
            },
            Fact {
                header: "x-lepic-native-direct",
                name: "native_direct",
                value: on(settings.native_direct),
            },
            Fact {
                header: "x-lepic-relay-tor",
                name: "relay_tor",
                value: encode(relay_tor.as_bytes()),
            },
            Fact {
                header: "x-lepic-node-over-tor",
                name: "node_over_tor",
                value: on(settings.node_over_tor),
            },
        ])
    }

    /// The headers a forwarded command sends.
    pub(crate) fn headers(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.0.iter().map(|fact| (fact.header, fact.value.as_str()))
    }

    /// Refuses a request that names a fact otherwise than this run. A fact it does not name is
    /// not checked.
    pub(crate) fn check(&self, headers: &HeaderMap) -> Result<(), Problem> {
        for fact in &self.0 {
            let Some(given) = headers.get(fact.header) else {
                continue;
            };
            if given.as_bytes() == fact.value.as_bytes() {
                continue;
            }
            let given = String::from_utf8_lossy(given.as_bytes());
            let detail = if fact.header == VERSION_HEADER {
                format!(
                    "lepic serve runs version {}, and this lepic is version {given}; restart \
                     serve with this lepic",
                    fact.value
                )
            } else {
                format!(
                    "lepic serve runs with {} {}, and this command with {given}; run it with \
                     the settings serve runs with, or stop serve",
                    fact.name, fact.value
                )
            };
            let code = if fact.header == VERSION_HEADER {
                "serve_version_differs"
            } else {
                "serve_settings_differ"
            };
            return Err(Problem::new(
                StatusCode::CONFLICT,
                Category::Config,
                code,
                detail,
            ));
        }
        Ok(())
    }
}

/// Percent-encodes every byte that is not visible ASCII, and `%`, so any path is a header value.
fn encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_graphic() && byte != b'%' || byte == b' ' {
            text.push(char::from(byte));
        } else {
            text.push_str(&format!("%{byte:02X}"));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use hyper::header::{HeaderName, HeaderValue};

    use super::*;

    fn headers(caller: &Caller) -> HeaderMap {
        caller
            .headers()
            .map(|(name, value)| {
                (
                    HeaderName::from_static(name),
                    HeaderValue::from_str(value).unwrap(),
                )
            })
            .collect()
    }

    fn settings(data_dir: &std::path::Path) -> Settings {
        let env = crate::settings::Env::new([
            ("HOME".to_owned(), "/home/u".to_owned()),
            ("LEPIC_NETWORK".to_owned(), "floonet".to_owned()),
            ("LEPIC_DATA_DIR".to_owned(), data_dir.display().to_string()),
        ]);
        Settings::resolve(&crate::cli::GlobalArgs::default(), &env).unwrap()
    }

    fn detail(problem: &Problem) -> String {
        serde_json::to_value(problem).unwrap()["detail"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn a_request_of_the_same_run_or_without_facts_passes() {
        let dir = tempfile::tempdir().unwrap();
        let caller = Caller::of(&settings(dir.path()));
        assert!(caller.check(&headers(&caller)).is_ok());
        assert!(caller.check(&HeaderMap::new()).is_ok());
    }

    #[test]
    fn a_request_of_another_run_is_refused_naming_what_differs() {
        let (dir, other) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let serve = Caller::of(&settings(dir.path()));
        let mut changes: Vec<(&str, Settings)> = Vec::new();
        changes.push(("data directory", settings(other.path())));
        let mut native = settings(dir.path());
        native.native_direct = !native.native_direct;
        changes.push(("native_direct", native));
        let mut node = settings(dir.path());
        node.node_over_tor = !node.node_over_tor;
        changes.push(("node_over_tor", node));
        let mut tor = settings(dir.path());
        tor.relay_tor = RelayTor::Socks("127.0.0.1:9050".parse().unwrap());
        changes.push(("relay_tor", tor));
        for (name, changed) in changes {
            let problem = serve.check(&headers(&Caller::of(&changed))).unwrap_err();
            assert_eq!(problem.status(), StatusCode::CONFLICT, "{name}");
            assert!(detail(&problem).contains(name), "{name}");
        }
        let mut older = headers(&serve);
        older.insert(VERSION_HEADER, HeaderValue::from_static("0.0.1"));
        let problem = serve.check(&older).unwrap_err();
        assert!(detail(&problem).contains("0.0.1"));
    }

    #[test]
    fn any_path_is_a_header_value() {
        assert_eq!(encode(b"/a b/%\n\xff"), "/a b/%25%0A%FF");
        assert!(HeaderValue::from_str(&encode(b"/a b/%\n\xff")).is_ok());
    }
}
