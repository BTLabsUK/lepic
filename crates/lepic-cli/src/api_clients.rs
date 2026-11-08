// SPDX-License-Identifier: Apache-2.0
//! The clients `serve --owner-tls` accepts (ADR 0050): the data directory's `api-clients` file,
//! one `<name> <fingerprint>` per line, where `#` starts a comment. A fingerprint is the SHA-256
//! of a certificate's SubjectPublicKeyInfo, in hex, so a client keeps its pin when it renews its
//! certificate with the same key.

use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use rustls::pki_types::CertificateDer;
use rustls::server::ParsedCertificate;
use sha2::{Digest as _, Sha256};

use crate::exit::CliError;

pub(crate) const FILE: &str = "api-clients";
const MAX_LEN: u64 = 64 * 1024;
const MAX_NAME_LEN: usize = 64;
/// The DER of an Ed25519 SubjectPublicKeyInfo (RFC 8410), before its 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub(crate) fn of_ed25519_key(key: &[u8; 32]) -> Self {
        let spki = Sha256::new()
            .chain_update(ED25519_SPKI_PREFIX)
            .chain_update(key);
        Self(spki.finalize().into())
    }

    /// The fingerprint of `certificate`'s key, when it is an Ed25519 key.
    pub(crate) fn of_ed25519(certificate: &CertificateDer<'_>) -> Option<Self> {
        let spki = ParsedCertificate::try_from(certificate)
            .ok()?
            .subject_public_key_info();
        let key = spki.as_ref().strip_prefix(&ED25519_SPKI_PREFIX)?;
        Some(Self::of_ed25519_key(key.try_into().ok()?))
    }

    fn parse(text: &str) -> Option<Self> {
        if text.len() != 64 || !text.is_ascii() {
            return None;
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// A client name: letters, digits, `.`, `-` and `_`.
pub(crate) fn check_name(name: &str) -> Result<(), CliError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    valid.then_some(()).ok_or(CliError::ApiClientName)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Client {
    pub(crate) name: String,
    pub(crate) fingerprint: Fingerprint,
}

/// A line of the file, kept as written so comments survive an edit.
struct Line {
    text: String,
    client: Option<Client>,
}

/// The `api-clients` file of a data directory.
pub(crate) struct Clients {
    path: PathBuf,
    lines: Vec<Line>,
}

impl Clients {
    /// The file in `data_dir`; a missing file lists no client.
    pub(crate) fn read(data_dir: &Path) -> Result<Self, CliError> {
        let path = data_dir.join(FILE);
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    lines: Vec::new(),
                });
            }
            Err(error) => return Err(CliError::io("read api-clients")(error)),
        };
        let mut text = String::new();
        file.take(MAX_LEN.saturating_add(1))
            .read_to_string(&mut text)
            .map_err(CliError::io("read api-clients"))?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_LEN {
            return Err(CliError::ApiClientsTooLarge { path });
        }
        let lines = text
            .lines()
            .enumerate()
            .map(|(index, line)| {
                let client = parse_line(line).map_err(|()| CliError::ApiClientsInvalid {
                    path: path.clone(),
                    line: index.saturating_add(1),
                })?;
                Ok(Line {
                    text: line.to_owned(),
                    client,
                })
            })
            .collect::<Result<_, CliError>>()?;
        Ok(Self { path, lines })
    }

    pub(crate) fn clients(&self) -> impl Iterator<Item = &Client> {
        self.lines.iter().filter_map(|line| line.client.as_ref())
    }

    pub(crate) fn lists(&self, fingerprint: Fingerprint) -> bool {
        self.clients()
            .any(|client| client.fingerprint == fingerprint)
    }

    /// Adds `client`, whose name and key must both be new.
    pub(crate) fn add(&mut self, client: Client) -> Result<(), CliError> {
        if let Some(listed) = self
            .clients()
            .find(|listed| listed.name == client.name || listed.fingerprint == client.fingerprint)
        {
            return Err(CliError::ApiClientListed {
                name: listed.name.clone(),
            });
        }
        self.lines.push(Line {
            text: format!("{} {}", client.name, client.fingerprint),
            client: Some(client),
        });
        Ok(())
    }

    /// Removes the client named `name`.
    pub(crate) fn remove(&mut self, name: &str) -> Result<Client, CliError> {
        let not_found = || CliError::ApiClientNotFound {
            name: name.to_owned(),
        };
        let index = self
            .lines
            .iter()
            .position(|line| {
                line.client
                    .as_ref()
                    .is_some_and(|client| client.name == name)
            })
            .ok_or_else(not_found)?;
        self.lines.remove(index).client.ok_or_else(not_found)
    }

    /// Replaces the file, owner-only, so a running serve reads the old list or the new.
    pub(crate) fn write(&self) -> Result<(), CliError> {
        let mut text = String::new();
        for line in &self.lines {
            text.push_str(&line.text);
            text.push('\n');
        }
        lepic_store::file::write_owner_only_atomic(&self.path, text.as_bytes())
            .map_err(CliError::io("write api-clients"))
    }
}

/// The client on `line`, `None` for a blank or comment line.
fn parse_line(line: &str) -> Result<Option<Client>, ()> {
    let content = line.split_once('#').map_or(line, |(content, _)| content);
    let mut fields = content.split_whitespace();
    let Some(name) = fields.next() else {
        return Ok(None);
    };
    let fingerprint = fields.next().and_then(Fingerprint::parse).ok_or(())?;
    if fields.next().is_some() || check_name(name).is_err() {
        return Err(());
    }
    Ok(Some(Client {
        name: name.to_owned(),
        fingerprint,
    }))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn a_line_is_a_name_and_a_fingerprint_with_an_optional_comment() {
        let client = parse_line(&format!("laptop {KEY} # kitchen"))
            .unwrap()
            .unwrap();
        assert_eq!(client.name, "laptop");
        assert_eq!(client.fingerprint.to_string(), KEY);
        assert_eq!(parse_line("  # a comment").unwrap(), None);
        assert_eq!(parse_line("").unwrap(), None);
        let uppercase = parse_line(&format!("laptop {}", KEY.to_uppercase())).unwrap();
        assert_eq!(uppercase.unwrap().fingerprint.to_string(), KEY);
    }

    #[test]
    fn a_malformed_line_is_refused() {
        for line in [
            "laptop".to_owned(),
            format!("laptop {}", &KEY[1..]),
            format!("laptop {KEY} extra"),
            format!("lap/top {KEY}"),
            format!("laptop {}g", &KEY[1..]),
            format!("{} {KEY}", "a".repeat(MAX_NAME_LEN + 1)),
        ] {
            assert_eq!(parse_line(&line), Err(()), "{line}");
        }
    }

    #[test]
    fn an_edit_keeps_the_comments_and_refuses_a_listed_name_or_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), format!("# phones\nold {KEY}\n")).unwrap();
        let mut clients = Clients::read(dir.path()).unwrap();
        let fingerprint = Fingerprint([7; 32]);
        let listed = |name: &str, fingerprint| Client {
            name: name.to_owned(),
            fingerprint,
        };
        assert!(matches!(
            clients.add(listed("old", fingerprint)),
            Err(CliError::ApiClientListed { name }) if name == "old"
        ));
        assert!(matches!(
            clients.add(listed("new", Fingerprint::parse(KEY).unwrap())),
            Err(CliError::ApiClientListed { name }) if name == "old"
        ));
        clients.add(listed("new", fingerprint)).unwrap();
        clients.remove("old").unwrap();
        assert!(matches!(
            clients.remove("old"),
            Err(CliError::ApiClientNotFound { .. })
        ));
        clients.write().unwrap();
        let text = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert_eq!(text, format!("# phones\nnew {fingerprint}\n"));
        assert!(Clients::read(dir.path()).unwrap().lists(fingerprint));
    }

    #[test]
    fn a_missing_file_lists_no_client() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Clients::read(dir.path()).unwrap().clients().count(), 0);
    }

    #[test]
    fn the_fingerprint_of_a_vector_key_is_its_spki_sha256() {
        let vectors = [
            include_str!("../../../testdata/vectors/keys/api_tls_key_seed16.json"),
            include_str!("../../../testdata/vectors/keys/api_tls_key_seed32.json"),
        ];
        for vector in vectors {
            let vector: serde_json::Value = serde_json::from_str(vector).unwrap();
            let expected = &vector["expected"];
            let key = Fingerprint::parse(expected["public_key"].as_str().unwrap()).unwrap();
            assert_eq!(
                Fingerprint::of_ed25519_key(&key.0).to_string(),
                expected["spki_sha256"].as_str().unwrap(),
                "{}",
                vector["name"]
            );
        }
    }
}
