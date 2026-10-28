// SPDX-License-Identifier: Apache-2.0
//! Signature cases: ECDSA over SHA-256 of the exact text, DER-encoded as hex, as `Subscribe` signs
//! a challenge, `PostSlate` signs `str` and `Made` signs the relay message id.

use epic_wallet_libwallet::crypto::{Hex, sign_challenge, verify_signature};
use epic_wallet_libwallet::message::EncryptedMessage;
use serde::Serialize;

use super::{ALICE, BOB, CAROL, CheckFailed, Network, TestKey, render, upstream_outcome};
use crate::{Error, Rendered, Upstream, hex};

// The relay sends this fixed challenge first, to clients that have not reported a protocol
// version, and a fresh 32-character one after that.
const STATIC_CHALLENGE: &str = "7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc";
const DYNAMIC_CHALLENGE: &str = "q8VfZ2mXc4Lr7TbN1kHs9WdJ3yPg6EuA";
const MESSAGE_ID: &str = "Rk4pW7nZ2cT9sLb3XyQ6vH1mJ8dG5fUa";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Signed {
    Challenge,
    Str,
    Epicboxmsgid,
}

#[derive(Serialize)]
struct Inputs<'a> {
    secret_key: String,
    signed: Signed,
    text: &'a str,
}

#[derive(Serialize)]
struct Expected {
    public_key_hex: String,
    signature: String,
}

struct Case {
    name: &'static str,
    key: [u8; 32],
    signed: Signed,
    text: String,
}

/// A `str` as upstream serializes an encrypted message, with fixed salt, nonce and ciphertext.
fn post_slate_str() -> Result<String, Error> {
    let destination = TestKey::new(BOB)?.address_key(Network::Mainnet);
    let text = format!(
        concat!(
            r#"{{"destination":{{"public_key":"{}","domain":"epicbox.epiccash.com","port":null}},"#,
            r#""encrypted_message":"{}","salt":"0102030405060708","nonce":"0102030405060708090a0b0c"}}"#
        ),
        destination,
        hex([0xab; 48]),
    );
    let message: EncryptedMessage = serde_json::from_str(&text)?;
    Ok(serde_json::to_string(&message)?)
}

fn cases() -> Result<Vec<Case>, Error> {
    Ok(vec![
        Case {
            name: "subscribe_static_challenge",
            key: ALICE,
            signed: Signed::Challenge,
            text: STATIC_CHALLENGE.to_owned(),
        },
        Case {
            name: "subscribe_dynamic_challenge",
            key: ALICE,
            signed: Signed::Challenge,
            text: DYNAMIC_CHALLENGE.to_owned(),
        },
        Case {
            name: "post_slate_str",
            key: ALICE,
            signed: Signed::Str,
            text: post_slate_str()?,
        },
        Case {
            name: "made_message_id",
            key: BOB,
            signed: Signed::Epicboxmsgid,
            text: MESSAGE_ID.to_owned(),
        },
        Case {
            name: "empty_text",
            key: CAROL,
            signed: Signed::Challenge,
            text: String::new(),
        },
    ])
}

/// Signs with upstream and checks that upstream accepts the signature only for this text and key.
pub(super) fn sign(key: &TestKey, text: &str) -> Result<String, Error> {
    let signature = sign_challenge(text, &key.secret).map_err(Error::reference("signature"))?;
    let signature_hex = signature.to_hex();
    let parsed = <epic_util::secp::Signature as Hex<_>>::from_hex(&signature_hex)
        .map_err(Error::reference("signature parse"))?;
    verify_signature(text, &parsed, &key.public)
        .map_err(Error::reference("signature verification"))?;
    let other = TestKey::new(if key.secret_bytes == CAROL {
        ALICE
    } else {
        CAROL
    })?;
    if upstream_outcome(|| verify_signature(text, &parsed, &other.public)).is_some() {
        return Err(Error::reference("signature check")(CheckFailed::OtherKey));
    }
    let other_text = format!("{text}.");
    if upstream_outcome(|| verify_signature(&other_text, &parsed, &key.public)).is_some() {
        return Err(Error::reference("signature check")(CheckFailed::OtherText));
    }
    Ok(signature_hex)
}

pub(super) fn generate(upstream: &Upstream) -> Result<Vec<Rendered>, Error> {
    cases()?
        .iter()
        .map(|case| {
            let key = TestKey::new(case.key)?;
            let expected = Expected {
                public_key_hex: key.public_hex(),
                signature: sign(&key, &case.text)?,
            };
            let inputs = Inputs {
                secret_key: hex(key.secret_bytes),
                signed: case.signed,
                text: &case.text,
            };
            render(
                &format!("signature_{}", case.name),
                upstream,
                inputs,
                expected,
            )
        })
        .collect()
}
