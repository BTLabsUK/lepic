// SPDX-License-Identifier: Apache-2.0
//! Message cases: a plaintext encrypted by upstream's `EncryptedMessage` from a sender to a
//! receiver, the `str` the sender posts, and the sender's signature over it.
//!
//! Upstream draws the salt and nonce inside `EncryptedMessage::new`, so a fresh message differs on
//! every run. The generator keeps a committed message while it still matches its case and opens,
//! and draws a new one otherwise. The plaintext, keys and addresses are fixed, and before a vector
//! is written upstream decrypts it again, on the receive path the Epicbox listener uses when the
//! plaintext is a slate.

use epic_util::secp::{Secp256k1, Signature};
use epic_wallet_libwallet::crypto::{Hex, verify_signature};
use epic_wallet_libwallet::message::EncryptedMessage;
use epic_wallet_libwallet::{EpicboxAddress, Slate, SlateVersion, TxProof, VersionedSlate};
use serde::Serialize;

use super::{
    ALICE, BOB, CAROL, CheckFailed, Network, TestKey, address, committed_path, on_network, render,
    signature, upstream_outcome,
};
use crate::{Error, Rendered, Upstream, hex};

#[derive(Serialize)]
struct Inputs<'a> {
    network: Network,
    sender_secret_key: String,
    receiver_secret_key: String,
    to: &'a str,
    plaintext: &'a str,
}

/// `str` is the exact text posted and signed. `salt`, `nonce` and `encrypted_message` are copied
/// out of it; `key` is the PBKDF2 output both sides derive. `random` names the values upstream drew.
#[derive(Serialize)]
struct Expected<'a> {
    random: [&'static str; 2],
    sender_public_key_hex: String,
    receiver_public_key_hex: String,
    from: String,
    to: String,
    key: String,
    salt: String,
    nonce: String,
    encrypted_message: String,
    str: &'a str,
    signature: &'a str,
}

#[derive(Clone, Copy)]
enum Version {
    V2,
    V3,
}

#[derive(Clone, Copy)]
enum Plaintext {
    Slate(Version),
    Text(&'static str),
}

pub(super) struct Case {
    pub(super) name: &'static str,
    network: Network,
    sender: [u8; 32],
    receiver: [u8; 32],
    to_suffix: &'static str,
    plaintext: Plaintext,
}

pub(super) fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "v3_slate_mainnet_default_domain",
            network: Network::Mainnet,
            sender: ALICE,
            receiver: BOB,
            to_suffix: "",
            plaintext: Plaintext::Slate(Version::V3),
        },
        Case {
            name: "v3_slate_mainnet_explicit_port_443",
            network: Network::Mainnet,
            sender: BOB,
            receiver: ALICE,
            to_suffix: "@epicbox.epiccash.com:443",
            plaintext: Plaintext::Slate(Version::V3),
        },
        Case {
            name: "v2_slate_floonet_custom_port",
            network: Network::Floonet,
            sender: ALICE,
            receiver: CAROL,
            to_suffix: "@relay.example.org:13420",
            plaintext: Plaintext::Slate(Version::V2),
        },
        Case {
            name: "empty_plaintext",
            network: Network::Mainnet,
            sender: CAROL,
            receiver: BOB,
            to_suffix: "",
            plaintext: Plaintext::Text(""),
        },
        Case {
            name: "multibyte_plaintext",
            network: Network::Floonet,
            sender: BOB,
            receiver: CAROL,
            to_suffix: "@relay.example.org",
            plaintext: Plaintext::Text("épic ✓ 💸"),
        },
    ]
}

/// A slate as upstream builds a blank one, with the random id replaced by a fixed one.
fn slate_json(version: Version) -> Result<String, Error> {
    let version = match version {
        Version::V2 => SlateVersion::V2,
        Version::V3 => SlateVersion::V3,
    };
    let mut slate = Slate::blank(2);
    slate.id = serde_json::from_str("\"0436430c-2b02-624c-2032-570501212b00\"")?;
    slate.amount = 1_000_000_000;
    slate.fee = 8_000_000;
    slate.height = 5_000;
    slate.lock_height = 0;
    slate.ttl_cutoff_height = Some(5_060);
    Ok(serde_json::to_string(&VersionedSlate::into_version(
        slate, version,
    ))?)
}

/// Everything about a case that does not depend on upstream's random draw.
pub(super) struct Prepared {
    network: Network,
    sender: TestKey,
    receiver: TestKey,
    to_text: String,
    to: EpicboxAddress,
    from: EpicboxAddress,
    plaintext: String,
    is_slate: bool,
}

pub(super) fn prepare(case: &Case) -> Result<Prepared, Error> {
    let sender = TestKey::new(case.sender)?;
    let receiver = TestKey::new(case.receiver)?;
    let to_text = format!("{}{}", receiver.address_key(case.network), case.to_suffix);
    let parse = |text: &str| {
        address::parse(case.network, text)
            .ok_or(CheckFailed::Address)
            .map_err(Error::reference("message address"))
    };
    let to = parse(&to_text)?;
    let from = parse(&sender.address_key(case.network))?;
    let (plaintext, is_slate) = match case.plaintext {
        Plaintext::Slate(version) => (slate_json(version)?, true),
        Plaintext::Text(text) => (text.to_owned(), false),
    };
    Ok(Prepared {
        network: case.network,
        sender,
        receiver,
        to_text,
        to,
        from,
        plaintext,
        is_slate,
    })
}

impl Prepared {
    fn inputs(&self) -> Inputs<'_> {
        Inputs {
            network: self.network,
            sender_secret_key: hex(self.sender.secret_bytes),
            receiver_secret_key: hex(self.receiver.secret_bytes),
            to: &self.to_text,
            plaintext: &self.plaintext,
        }
    }
}

fn check(condition: bool, failure: CheckFailed) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::reference("message check")(failure))
    }
}

/// The recorded fields of a posted message, as upstream reads them back out of `str`.
pub(super) struct Opened {
    key: [u8; 32],
    salt: String,
    nonce: String,
    encrypted_message: String,
}

fn field(fields: &serde_json::Value, name: &'static str) -> Result<String, Error> {
    fields
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(CheckFailed::Plaintext)
        .map_err(Error::reference("message field"))
}

/// Decrypts a posted message with upstream code as the receiver, and checks every property the
/// vector relies on.
pub(super) fn open(prepared: &Prepared, posted: &str, signature: &str) -> Result<Opened, Error> {
    let signed_by_sender = upstream_outcome(|| {
        Signature::from_hex(signature)
            .and_then(|parsed| verify_signature(posted, &parsed, &prepared.sender.public))
    });
    check(signed_by_sender.is_some(), CheckFailed::Signature)?;
    let message: EncryptedMessage = serde_json::from_str(posted)?;
    let key = message
        .key(&prepared.sender.public, &prepared.receiver.secret)
        .map_err(Error::reference("receiver key"))?;
    let sender_key = message
        .key(&prepared.receiver.public, &prepared.sender.secret)
        .map_err(Error::reference("sender key"))?;
    check(key == sender_key, CheckFailed::SharedKey)?;
    let decrypted = message
        .decrypt_with_key(&key)
        .map_err(Error::reference("decryption"))?;
    check(decrypted == prepared.plaintext, CheckFailed::Plaintext)?;

    let fields: serde_json::Value = serde_json::from_str(posted)?;
    let encrypted_message = field(&fields, "encrypted_message")?;
    let mut tampered = fields.clone();
    if let Some(slot) = tampered.get_mut("encrypted_message") {
        *slot = serde_json::Value::String(flip_first_hex_digit(&encrypted_message));
    }
    let tampered: EncryptedMessage = serde_json::from_value(tampered)?;
    check(
        tampered.decrypt_with_key(&key).is_err(),
        CheckFailed::Tampered,
    )?;

    if prepared.is_slate {
        let (slate, _proof) = on_network(prepared.network, || {
            upstream_outcome(|| {
                TxProof::from_response(
                    prepared.from.to_string(),
                    posted.to_owned(),
                    signature.to_owned(),
                    &prepared.receiver.secret,
                    Some(&prepared.to),
                )
            })
        })
        .ok_or(CheckFailed::ReceivePath)
        .map_err(Error::reference("epicbox receive path"))?;
        check(
            serde_json::to_string(&slate)? == prepared.plaintext,
            CheckFailed::Plaintext,
        )?;
    }

    Ok(Opened {
        key,
        salt: field(&fields, "salt")?,
        nonce: field(&fields, "nonce")?,
        encrypted_message,
    })
}

fn flip_first_hex_digit(text: &str) -> String {
    let mut chars = text.chars();
    let first = match chars.next() {
        Some('0') => '1',
        Some(_) | None => '0',
    };
    std::iter::once(first).chain(chars).collect()
}

fn seal(prepared: &Prepared) -> Result<(String, String), Error> {
    let message = EncryptedMessage::new(
        prepared.plaintext.clone(),
        &prepared.to,
        &prepared.receiver.public,
        &prepared.sender.secret,
    )
    .map_err(Error::reference("encryption"))?;
    let posted = serde_json::to_string(&message)?;
    let signature = signature::sign(&prepared.sender, &posted)?;
    Ok((posted, signature))
}

/// The posted `str` and signature of the committed vector for this case, when that vector is still
/// one this generator would accept: same inputs, same upstream commit, and upstream opens it.
fn committed(
    name: &str,
    prepared: &Prepared,
    upstream: &Upstream,
) -> Result<Option<(String, String)>, Error> {
    let Ok(bytes) = std::fs::read(committed_path(name)) else {
        return Ok(None);
    };
    let Ok(vector) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(None);
    };
    let same_case = vector.get("inputs") == Some(&serde_json::to_value(prepared.inputs())?)
        && vector.get("upstream") == Some(&serde_json::to_value(upstream)?);
    let expected = vector.get("expected");
    let text = |key: &str| {
        expected
            .and_then(|e| e.get(key))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    Ok(match (same_case, text("str"), text("signature")) {
        (true, Some(posted), Some(signature)) => open(prepared, &posted, &signature)
            .is_ok()
            .then_some((posted, signature)),
        _ => None,
    })
}

/// Reuses a committed message that is still valid, so regenerating the area changes the random
/// values only when a case or the pin changed.
pub(super) fn generate(upstream: &Upstream) -> Result<Vec<Rendered>, Error> {
    let secp = Secp256k1::new();
    cases()
        .iter()
        .map(|case| {
            let name = format!("message_{}", case.name);
            let prepared = prepare(case)?;
            let (posted, signature) = match committed(&name, &prepared, upstream)? {
                Some(kept) => kept,
                None => seal(&prepared)?,
            };
            let opened = open(&prepared, &posted, &signature)?;
            let expected = Expected {
                random: ["salt", "nonce"],
                sender_public_key_hex: hex(prepared.sender.public.serialize_vec(&secp, true)),
                receiver_public_key_hex: hex(prepared.receiver.public.serialize_vec(&secp, true)),
                from: prepared.from.to_string(),
                to: prepared.to.to_string(),
                key: hex(opened.key),
                salt: opened.salt,
                nonce: opened.nonce,
                encrypted_message: opened.encrypted_message,
                str: &posted,
                signature: &signature,
            };
            render(&name, upstream, prepared.inputs(), expected)
        })
        .collect()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Checks a committed message vector against upstream: its inputs are the case's, upstream
    /// decrypts its `str` to the plaintext, and the copied fields agree with `str`.
    pub(in crate::epicbox) fn verify_committed(
        case: &Case,
        committed: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let prepared = prepare(case)?;
        assert_eq!(
            committed["inputs"],
            serde_json::to_value(prepared.inputs())?,
            "{}",
            case.name
        );
        let expected = &committed["expected"];
        let posted = expected["str"].as_str().ok_or("str")?;
        let signature = expected["signature"].as_str().ok_or("signature")?;
        let opened = open(&prepared, posted, signature)?;
        assert_eq!(expected["key"], hex(opened.key), "{}", case.name);
        assert_eq!(expected["salt"], opened.salt, "{}", case.name);
        assert_eq!(expected["nonce"], opened.nonce, "{}", case.name);
        assert_eq!(
            expected["encrypted_message"], opened.encrypted_message,
            "{}",
            case.name
        );
        assert_eq!(expected["from"], prepared.from.to_string(), "{}", case.name);
        assert_eq!(expected["to"], prepared.to.to_string(), "{}", case.name);
        Ok(())
    }

    #[test]
    fn a_fresh_message_differs_but_opens_the_same() -> Result<(), Error> {
        for case in cases() {
            let prepared = prepare(&case)?;
            let (first, first_signature) = seal(&prepared)?;
            let (second, second_signature) = seal(&prepared)?;
            assert_ne!(first, second, "{}", case.name);
            open(&prepared, &first, &first_signature)?;
            open(&prepared, &second, &second_signature)?;
        }
        Ok(())
    }

    #[test]
    fn a_signature_over_another_str_fails_the_receive_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let case = cases()
            .into_iter()
            .find(|case| matches!(case.plaintext, Plaintext::Slate(_)))
            .ok_or("no slate case")?;
        let prepared = prepare(&case)?;
        let (posted, _) = seal(&prepared)?;
        let (_, other_signature) = seal(&prepared)?;
        assert!(open(&prepared, &posted, &other_signature).is_err());
        Ok(())
    }
}
